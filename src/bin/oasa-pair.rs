//! `oasa-pair`: pair a ground station with a drone and set up MAVLink signing.
//!
//! Prototype for OASA tech tree node R-SEC1. Do not fly with it.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use mavlink::dialects::common::{COMMAND_LONG_DATA, MavCmd, MavMessage};
use mavlink::{MavConnection, MavHeader};
use oasa_sec::code::PairingCode;
use oasa_sec::identity::Identity;
use oasa_sec::pairing::{check_name, pair_as_drone, pair_as_ground};
use oasa_sec::signing::SigningKey;
use oasa_sec::store::{self, Peer};

const USAGE: &str = "\
oasa-pair: OASA-SEC v0 pairing prototype (R-SEC1). Do not fly with it.

USAGE:
  oasa-pair init     --dir DIR
  oasa-pair drone    --dir DIR --name NAME --listen HOST:PORT
                     [--autopilot MAVLINK_ADDR] [--target SYS:COMP] [--wait SECONDS]
  oasa-pair ground   --dir DIR --name NAME --connect HOST:PORT --code CODE
  oasa-pair peers    --dir DIR
  oasa-pair remove   --dir DIR FINGERPRINT
  oasa-pair command  --dir DIR --to MAVLINK_ADDR [--target SYS:COMP]

  init      Make this device's identity (once per device) and print its fingerprint.
  drone     Show a one-time pairing code (text and QR), wait for one ground station
            to pair, save it as trusted, and save the signing key it sends. With
            --autopilot, load the key into the autopilot with SETUP_SIGNING.
            Use a wired or local link for --autopilot (e.g. udpout:127.0.0.1:14540).
  ground    Pair with the drone that showed CODE. Makes a fresh signing key,
            sends it inside the encrypted channel, and saves it.
  peers     List trusted devices.
  remove    Stop trusting a device. To lock it out fully, also re-pair to rotate
            the signing key.
  command   Send one signed test command (request AUTOPILOT_VERSION) and wait for
            a signed acknowledgment. Proves signing works end to end.

MAVLINK_ADDR uses the rust-mavlink format: udpout:HOST:PORT, udpin:HOST:PORT,
tcpout:HOST:PORT, serial:PORT:BAUD.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

type R = Result<(), Box<dyn std::error::Error>>;

fn run(args: &[String]) -> R {
    let Some(cmd) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };
    let opts = Opts::parse(&args[1..])?;
    match cmd.as_str() {
        "init" => init(&opts),
        "drone" => drone(&opts),
        "ground" => ground(&opts),
        "peers" => peers(&opts),
        "remove" => remove(&opts),
        "command" => command(&opts),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}; run oasa-pair --help").into()),
    }
}

fn init(o: &Opts) -> R {
    let dir = o.dir()?;
    let (id, created) = Identity::load_or_create(&dir)?;
    println!(
        "{} identity {}",
        if created { "Created" } else { "Existing" },
        id.fingerprint()
    );
    Ok(())
}

fn drone(o: &Opts) -> R {
    let dir = o.dir()?;
    let name = o.name()?;
    let listen = o.req("listen")?;
    let wait = Duration::from_secs(o.get("wait").map(|s| s.parse()).transpose()?.unwrap_or(300));
    let (me, _) = Identity::load_or_create(&dir)?;

    let code = PairingCode::new(*me.public_key())?;
    println!(
        "Drone {name} ({}) is in pairing mode for {}s.",
        me.fingerprint(),
        wait.as_secs()
    );
    println!("Scan this with the ground station, or copy the code below.\n");
    println!("{}", code.qr_text());
    println!("{}\n", code.encode());
    println!("Anyone who sees this code can pair once. Close pairing mode when done.");

    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + wait;
    let mut failures = 0;
    let result = loop {
        if Instant::now() > deadline {
            return Err("pairing window closed with no ground station".into());
        }
        let stream = match listener.accept() {
            Ok((s, addr)) => {
                eprintln!("Pairing attempt from {addr}");
                s
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let mut stream = prepare(stream)?;
        match pair_as_drone(&mut stream, &me, &name, &code) {
            Ok(r) => break r,
            Err(e) => {
                failures += 1;
                eprintln!("Pairing attempt failed: {e}");
                if failures >= 5 {
                    return Err(
                        "too many failed pairing attempts; start pairing mode again for a new code"
                            .into(),
                    );
                }
            }
        }
    };
    drop(code); // one-time: this code can't be used again

    store::add(&dir, &result.ground)?;
    let old_key = SigningKey::load(&dir).ok();
    result.signing_key.save(&dir)?;
    println!(
        "Paired with ground station {} ({}).",
        result.ground.name,
        result.ground.fingerprint()
    );

    if let Some(addr) = o.get("autopilot") {
        let (sys, comp) = o.target()?;
        let mut conn = mavlink::connect::<MavMessage>(addr)?;
        conn.set_protocol_version(mavlink::MavlinkVersion::V2);
        if let Some(old) = &old_key {
            // Changing a key the autopilot already has: PX4 and ArduPilot
            // only accept it if signed with the current key.
            conn.setup_signing(Some(old.mavlink_config(0)));
        }
        let msg = result.signing_key.setup_signing_message(sys, comp);
        conn.send(&companion_header(sys), &msg)?;
        println!("Sent SETUP_SIGNING to autopilot {sys}:{comp} at {addr}.");
    }
    Ok(())
}

fn ground(o: &Opts) -> R {
    let dir = o.dir()?;
    let name = o.name()?;
    let addr = o.req("connect")?;
    let code = PairingCode::decode(o.req("code")?)?;
    let (me, _) = Identity::load_or_create(&dir)?;
    let key = SigningKey::generate()?;

    println!(
        "Pairing with drone {} at {addr}...",
        oasa_sec::identity::fingerprint(&code.responder_public)
    );
    let mut stream = prepare(TcpStream::connect(addr)?)?;
    let r = pair_as_ground(&mut stream, &me, &name, &code, &key)?;
    store::add(&dir, &r.drone)?;
    key.save(&dir)?;
    println!(
        "Paired with drone {} ({}). Signing key saved.",
        r.drone.name,
        r.drone.fingerprint()
    );
    Ok(())
}

fn peers(o: &Opts) -> R {
    let list: Vec<Peer> = store::load(&o.dir()?)?;
    if list.is_empty() {
        println!("No trusted devices yet.");
    }
    for p in list {
        println!("{}  {}", p.fingerprint(), p.name);
    }
    Ok(())
}

fn remove(o: &Opts) -> R {
    let fp = o
        .positional
        .first()
        .ok_or("give the fingerprint to remove")?;
    if store::remove(&o.dir()?, fp)? {
        println!("Removed {fp}. Re-pair to rotate the signing key.");
        Ok(())
    } else {
        Err(format!("no trusted device {fp}").into())
    }
}

fn command(o: &Opts) -> R {
    let dir = o.dir()?;
    let key = SigningKey::load(&dir)?;
    let addr = o.req("to")?;
    let (sys, comp) = o.target()?;
    let mut conn = mavlink::connect::<MavMessage>(addr)?;
    conn.set_protocol_version(mavlink::MavlinkVersion::V2);
    conn.setup_signing(Some(key.mavlink_config(0)));

    let req = MavMessage::COMMAND_LONG(COMMAND_LONG_DATA {
        param1: 148.0, // AUTOPILOT_VERSION message id
        param2: 0.0,
        param3: 0.0,
        param4: 0.0,
        param5: 0.0,
        param6: 0.0,
        param7: 0.0,
        command: MavCmd::MAV_CMD_REQUEST_MESSAGE,
        target_system: sys,
        target_component: comp,
        confirmation: 0,
    });
    // recv() blocks; run it on a thread so we can give up after a timeout.
    let conn = std::sync::Arc::new(conn);
    let reader = conn.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        loop {
            match reader.recv() {
                Ok((_, MavMessage::COMMAND_ACK(ack))) => {
                    let _ = tx.send(Ok(ack));
                    return;
                }
                Ok(_) => {}
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    return;
                }
            }
        }
    });
    for _ in 0..5 {
        conn.send(&gcs_header(), &req)?;
        if let Ok(r) = rx.recv_timeout(Duration::from_secs(1)) {
            let ack = r?;
            println!(
                "Signed acknowledgment received: {:?} {:?}",
                ack.command, ack.result
            );
            return Ok(());
        }
    }
    Err("no signed acknowledgment (wrong key, or autopilot not listening)".into())
}

fn gcs_header() -> MavHeader {
    // 255 is the usual system id for a ground station; 190 is MAV_COMP_ID_MISSIONPLANNER.
    MavHeader {
        system_id: 255,
        component_id: 190,
        sequence: 0,
    }
}

fn companion_header(system_id: u8) -> MavHeader {
    // The drone's companion computer: same system as its autopilot,
    // component 191 (MAV_COMP_ID_ONBOARD_COMPUTER).
    MavHeader {
        system_id,
        component_id: 191,
        sequence: 0,
    }
}

fn prepare(s: TcpStream) -> std::io::Result<TcpStream> {
    s.set_nonblocking(false)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    s.set_nodelay(true)?;
    Ok(s)
}

struct Opts {
    named: Vec<(String, String)>,
    positional: Vec<String>,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut named = Vec::new();
        let mut positional = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if let Some(k) = a.strip_prefix("--") {
                let v = it.next().ok_or(format!("--{k} needs a value"))?;
                named.push((k.to_string(), v.clone()));
            } else {
                positional.push(a.clone());
            }
        }
        Ok(Self { named, positional })
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.named
            .iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
    fn req(&self, k: &str) -> Result<&str, String> {
        self.get(k).ok_or(format!("missing --{k}"))
    }
    fn dir(&self) -> Result<PathBuf, String> {
        self.req("dir").map(PathBuf::from)
    }
    fn name(&self) -> Result<String, String> {
        let n = self.req("name")?;
        check_name(n).map_err(|e| e.to_string())?;
        Ok(n.to_string())
    }
    fn target(&self) -> Result<(u8, u8), String> {
        let t = self.get("target").unwrap_or("1:1");
        let (s, c) = t.split_once(':').ok_or("--target is SYS:COMP, e.g. 1:1")?;
        Ok((
            s.parse().map_err(|_| "bad system id")?,
            c.parse().map_err(|_| "bad component id")?,
        ))
    }
}
