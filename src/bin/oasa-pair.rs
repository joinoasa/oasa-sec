//! `oasa-pair`: pair a ground station with a drone and set up MAVLink signing.
//!
//! Prototype for OASA tech tree node R-SEC1. Do not fly with it.

use std::io::{BufRead, IsTerminal};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use mavlink::dialects::common::{COMMAND_LONG_DATA, MavCmd, MavMessage, MavResult};
use mavlink::{MavConnection, MavHeader};
use oasa_sec::code::PairingCode;
use oasa_sec::identity::{self, Identity, fingerprint};
use oasa_sec::pairing::{DeadlineStream, check_name, pair_as_drone, pair_as_ground};
use oasa_sec::signing::{AUTOPILOT_KEY_FILE, SigningKey, peer_key_path};
use oasa_sec::store;

const USAGE: &str = "\
oasa-pair: OASA-SEC v0 pairing prototype (R-SEC1). Do not fly with it.

USAGE:
  oasa-pair init     --dir DIR [--name NAME]
  oasa-pair drone    --dir DIR --name NAME --listen HOST:PORT
                     [--autopilot MAVLINK_ADDR] [--target SYS:COMP] [--wait SECONDS]
  oasa-pair ground   --dir DIR --name NAME --connect HOST:PORT
                     [--code-file FILE | --code -] [--expect-drone FINGERPRINT]
  oasa-pair show     --dir DIR
  oasa-pair trust    --dir DIR --name PEERNAME --key HEX64
  oasa-pair peers    --dir DIR
  oasa-pair remove   --dir DIR FINGERPRINT
  oasa-pair command  --dir DIR --to MAVLINK_ADDR [--peer NAME|FINGERPRINT]
                     [--target SYS:COMP] [--link-id N] [--wait SECONDS]

  init      Make this device's identity (once per device) and print its fingerprint.
            --name saves the name this device calls itself (also saved the first
            time it pairs).
  show      Print this device's name, public key (64 hex characters) and fingerprint
            as one line of JSON. Public information only; never the private key.
  trust     Trust a device without pairing, like adding a WireGuard peer: give its
            name and public key (from its `show`), and compare the printed fingerprint
            with the one on that device, out loud, before using the link. For relays and
            test nodes that have no autopilot to pair with.
  drone     Show a one-time pairing code (text and QR) and wait for a ground station
            to pair. The first ground station sends a new signing key; with
            --autopilot the drone loads it into the autopilot, checks that it works,
            and only then saves it. Later ground stations receive the existing key.
            Use a wired or local link for --autopilot (e.g. udpout:127.0.0.1:14540).
  ground    Pair with the drone that showed the code. Reads the code from
            --code-file, or from standard input (the default, or --code -), so it
            doesn't show up in the process list or shell history. --expect-drone
            refuses to pair unless the code names that drone (compare with the
            fingerprint printed on the drone).
  peers     List paired devices.
  remove    Remove a device from the list. This does not lock it out: that needs
            key rotation, which is the next node (R-SEC2).
  command   Send one signed test command (request AUTOPILOT_VERSION) and wait for
            a signed, matching acknowledgment. On a ground station, --peer picks
            which drone's key to use (optional if only one is paired).
            Retries every second for up to --wait seconds (default 75). That long
            because ArduPilot refuses new signed streams for up to a minute after
            it reboots; PX4 answers at once.

MAVLINK_ADDR uses the rust-mavlink format: udpout:HOST:PORT, udpin:HOST:PORT,
tcpout:HOST:PORT, serial:PORT:BAUD.
";

/// Link IDs keep signed streams from different links apart (MAVLink spec).
const COMPANION_LINK_ID: u8 = 1;

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

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
        "show" => show(&opts),
        "trust" => trust(&opts),
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
    let name = o.get("name").map(check_given_name).transpose()?;
    let (id, created) = Identity::load_or_create(&dir)?;
    if let Some(name) = name {
        identity::save_device_name(&dir, name)?;
    }
    let word = if created { "Created" } else { "Existing" };
    println!("{word} identity {}", id.fingerprint());
    Ok(())
}

/// A name given on the command line, checked against the name rules.
fn check_given_name(n: &str) -> R<&str> {
    check_name(n)?;
    Ok(n)
}

/// Print this device's public details as JSON. The name is only letters,
/// digits and `-_.`, so it needs no escaping.
fn show(o: &Opts) -> R {
    let dir = o.dir()?;
    let id = Identity::load(&dir)
        .map_err(|e| format!("{e} (run `oasa-pair init --dir {}` first)", dir.display()))?;
    let name = identity::device_name(&dir)?
        .unwrap_or_else(|| identity::default_device_name(id.public_key()));
    println!(
        "{{\"name\":\"{name}\",\"public_key\":\"{}\",\"fingerprint\":\"{}\"}}",
        data_encoding::HEXLOWER.encode(id.public_key()),
        id.fingerprint()
    );
    Ok(())
}

/// Add a trusted peer by name and public key.
fn trust(o: &Opts) -> R {
    let dir = o.dir()?;
    let name = o.name()?;
    let hex = o.req("key")?.trim().to_ascii_lowercase();
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(
            "--key must be 64 hexadecimal characters (the public_key from `oasa-pair show`)".into(),
        );
    }
    let bytes = data_encoding::HEXLOWER.decode(hex.as_bytes())?;
    let public: [u8; 32] = bytes.try_into().map_err(|_| "--key must be 32 bytes")?;
    let me = Identity::load(&dir)
        .map_err(|e| format!("{e} (run `oasa-pair init --dir {}` first)", dir.display()))?;
    if &public == me.public_key() {
        return Err("that is this device's own key; a device cannot trust itself".into());
    }
    let peer = store::Peer { public, name };
    for p in store::load(&dir)? {
        if p == peer {
            println!("Already trusted: {} {}", peer.name, peer.fingerprint());
            return Ok(());
        }
        if p.public == peer.public {
            return Err(format!(
                "that key is already trusted as {}; remove it first (oasa-pair remove {})",
                p.name,
                p.fingerprint()
            )
            .into());
        }
        if p.name == peer.name {
            return Err(format!(
                "the name {} is already used by {}; pick another name or remove that device first",
                p.name,
                p.fingerprint()
            )
            .into());
        }
    }
    store::add(&dir, &peer)?;
    println!(
        "Trusted {} {}\nCheck that this fingerprint matches the one shown on that device.",
        peer.name,
        peer.fingerprint()
    );
    Ok(())
}

fn drone(o: &Opts) -> R {
    let dir = o.dir()?;
    let name = o.name()?;
    let window = Duration::from_secs(o.get("wait").map(str::parse).transpose()?.unwrap_or(300));
    let (me, _) = Identity::load_or_create(&dir)?;
    remember_name(&dir, &name);
    let key_path = dir.join(AUTOPILOT_KEY_FILE);
    let current_key = if key_path.exists() {
        Some(SigningKey::load(&key_path)?)
    } else {
        None
    };
    if current_key.is_none() && o.get("autopilot").is_none() {
        eprintln!(
            "warning: no --autopilot given; the new key will be saved but not loaded into an autopilot"
        );
    }

    // Listen before showing the code, so nobody can race to the port.
    let listener = TcpListener::bind(o.req("listen")?)?;
    listener.set_nonblocking(true)?;
    let code = PairingCode::new(*me.public_key())?;
    println!(
        "Drone {name} ({}) is in pairing mode for {}s.",
        me.fingerprint(),
        window.as_secs()
    );
    println!("Scan this with the ground station, or copy the code below.\n");
    println!("{}", code.qr_text());
    println!("{}\n", *zeroize::Zeroizing::new(code.encode()));
    println!("Anyone who sees this code can pair once. Close pairing mode when done.");

    let deadline = Instant::now() + window;
    let result = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("pairing window closed with no ground station".into());
        }
        let (stream, addr) = match listener.accept() {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        eprintln!("Pairing attempt from {addr}");
        // Each attempt gets at most 15 s, and never past the window.
        let mut stream = DeadlineStream::new(stream, left.min(Duration::from_secs(15)))?;
        let install = |key: &SigningKey| install_key(o, key, &key_path);
        match pair_as_drone(
            &mut stream,
            &me,
            &name,
            &code,
            current_key.as_ref(),
            install,
        ) {
            Ok(r) => break r,
            Err(e) => {
                eprintln!("Pairing attempt failed: {e}");
                // Failed attempts can't guess a 256-bit secret, so there's no
                // lockout; just slow repeated attempts down.
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    };
    drop(code); // one-time: this code can't be used again

    store::add(&dir, &result.ground)?;
    let how = if result.new_key {
        "new signing key loaded"
    } else {
        "shared the existing signing key"
    };
    println!(
        "Paired with ground station {} ({}); {how}.",
        result.ground.name,
        result.ground.fingerprint()
    );
    Ok(())
}

/// The first name a device pairs under becomes its saved name, so `show` and
/// the peers it later pairs with agree. An existing name is never changed.
fn remember_name(dir: &Path, name: &str) {
    if let Ok(None) = identity::device_name(dir)
        && let Err(e) = identity::save_device_name(dir, name)
    {
        eprintln!("note: could not save the device name: {e}");
    }
}

/// Load a brand-new key into the autopilot, prove it works with a signed
/// round trip, and only then save it. If anything fails, nothing is saved.
fn install_key(o: &Opts, key: &SigningKey, key_path: &Path) -> oasa_sec::Result<()> {
    let to_err = |e: Box<dyn std::error::Error>| {
        eprintln!("Loading the key into the autopilot failed: {e}");
        oasa_sec::Error::Protocol("autopilot did not accept the new key")
    };
    if let Some(addr) = o.get("autopilot") {
        let (sys, comp) = o.target().map_err(|e| to_err(e.into()))?;
        (|| -> R {
            let mut conn = mavlink::connect::<MavMessage>(addr)?;
            conn.set_protocol_version(mavlink::MavlinkVersion::V2);
            let msg = key.setup_signing_message(sys, comp);
            conn.send(&companion_header(sys), &msg)?;
            conn.setup_signing(Some(key.mavlink_config(COMPANION_LINK_ID)));
            // The autopilot needs a moment to switch; then prove the key works.
            std::thread::sleep(Duration::from_millis(200));
            // Right after SETUP_SIGNING ArduPilot's restart window doesn't apply,
            // so a short wait is enough.
            signed_round_trip(conn, companion_header(sys), sys, comp, INSTALL_WAIT, false)?;
            Ok(())
        })()
        .map_err(to_err)?;
        println!(
            "Autopilot {sys}:{comp} at {addr} accepted the new key (checked with a signed command)."
        );
    }
    key.save(key_path)
}

fn ground(o: &Opts) -> R {
    let dir = o.dir()?;
    let name = o.name()?;
    let addr = o.req("connect")?;
    let code = PairingCode::decode(&read_code(o)?)?;
    let drone_fp = fingerprint(&code.responder_public);
    if let Some(expected) = o.get("expect-drone")
        && expected != drone_fp
    {
        return Err(
            format!("code is for drone {drone_fp}, not {expected}; refusing to pair").into(),
        );
    }
    let (me, _) = Identity::load_or_create(&dir)?;
    remember_name(&dir, &name);

    println!(
        "Pairing with drone {drone_fp} at {addr}. Check this matches the drone's screen or label."
    );
    let stream = std::net::TcpStream::connect(addr)?;
    let mut stream = DeadlineStream::new(stream, Duration::from_secs(30))?;
    let r = pair_as_ground(&mut stream, &me, &name, &code, SigningKey::generate)?;
    r.signing_key
        .save(&peer_key_path(&dir, &r.drone.fingerprint()))?;
    store::add(&dir, &r.drone)?;
    let how = if r.new_key {
        "made a new signing key"
    } else {
        "received the drone's signing key"
    };
    println!(
        "Paired with drone {} ({}); {how}.",
        r.drone.name,
        r.drone.fingerprint()
    );
    Ok(())
}

/// The pairing code is a secret, so don't take it on the command line.
fn read_code(o: &Opts) -> R<zeroize::Zeroizing<String>> {
    if let Some(path) = o.get("code-file") {
        return Ok(zeroize::Zeroizing::new(std::fs::read_to_string(path)?));
    }
    match o.get("code") {
        None | Some("-") => {}
        Some(_) => {
            return Err(
                "don't put the pairing code on the command line (other users can see it); \
                        use --code-file FILE or pipe it in with --code -"
                    .into(),
            );
        }
    }
    if std::io::stdin().is_terminal() {
        eprintln!("Paste or scan the pairing code, then press Enter:");
    }
    let mut line = zeroize::Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line)
}

fn peers(o: &Opts) -> R {
    let list = store::load(&o.dir()?)?;
    if list.is_empty() {
        println!("No paired devices yet.");
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
        println!(
            "Removed {fp} from the list. It is not locked out until keys are rotated (R-SEC2)."
        );
        Ok(())
    } else {
        Err(format!("no paired device {fp}").into())
    }
}

fn command(o: &Opts) -> R {
    let dir = o.dir()?;
    let key = command_key(o, &dir)?;
    let (sys, comp) = o.target()?;
    let link_id: u8 = o.get("link-id").map(str::parse).transpose()?.unwrap_or(0);
    let mut conn = mavlink::connect::<MavMessage>(o.req("to")?)?;
    conn.set_protocol_version(mavlink::MavlinkVersion::V2);
    conn.setup_signing(Some(key.mavlink_config(link_id)));
    let wait = o.get("wait").map(str::parse).transpose()?.unwrap_or(75);
    signed_round_trip(
        conn,
        gcs_header(),
        sys,
        comp,
        Duration::from_secs(wait),
        true,
    )?;
    println!("Signed acknowledgment received from {sys}:{comp}: MAV_CMD_REQUEST_MESSAGE accepted.");
    Ok(())
}

/// Which key `command` uses: a drone's own autopilot key, or on a ground
/// station the key for `--peer` (or the only paired drone).
fn command_key(o: &Opts, dir: &Path) -> R<SigningKey> {
    if let Some(p) = o.get("peer") {
        let peer = store::find(dir, p)?.ok_or(format!("no paired device {p}"))?;
        return Ok(SigningKey::load(&peer_key_path(dir, &peer.fingerprint()))?);
    }
    let autopilot = dir.join(AUTOPILOT_KEY_FILE);
    if autopilot.exists() {
        return Ok(SigningKey::load(&autopilot)?);
    }
    let with_keys: Vec<_> = store::load(dir)?
        .into_iter()
        .filter(|p| peer_key_path(dir, &p.fingerprint()).exists())
        .collect();
    match with_keys.as_slice() {
        [only] => Ok(SigningKey::load(&peer_key_path(dir, &only.fingerprint()))?),
        [] => Err("no signing key here; pair first".into()),
        _ => Err("more than one drone is paired; choose one with --peer".into()),
    }
}

/// How long to wait for the check right after loading a key.
const INSTALL_WAIT: Duration = Duration::from_secs(5);

/// After this long with no reply, `command` tells the person it is still trying.
const QUIET_HINT_AFTER: Duration = Duration::from_secs(5);

/// Say why a signed command may get no reply. Never includes a key.
fn no_ack_message(wait: Duration) -> String {
    format!(
        "no signed acknowledgment after {}s. Likely causes: \
         (1) the autopilot already has a different signing key, from an earlier pairing; \
         (2) the autopilot is armed (PX4 and ArduPilot refuse a new key while armed); \
         (3) ArduPilot just rebooted and refuses signed commands for up to a minute; \
         (4) the wrong link or address, or the autopilot is not listening",
        wait.as_secs()
    )
}

/// Send a signed REQUEST_MESSAGE once a second for up to `wait`, and stop at
/// a signed COMMAND_ACK that matches it: same command, ACCEPTED, from the
/// target. With `hint`, say once after a few quiet seconds that we are still trying.
fn signed_round_trip(
    conn: impl MavConnection<MavMessage> + 'static,
    header: MavHeader,
    sys: u8,
    comp: u8,
    wait: Duration,
    hint: bool,
) -> R {
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
    // Only signed messages reach us: the connection drops anything else.
    let conn = Arc::new(conn);
    let reader = conn.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        loop {
            match reader.recv() {
                Ok((h, MavMessage::COMMAND_ACK(ack)))
                    if h.system_id == sys
                        && h.component_id == comp
                        && ack.command == MavCmd::MAV_CMD_REQUEST_MESSAGE =>
                {
                    let _ = tx.send(Ok(ack.result));
                    return;
                }
                Ok(_) => {}
                // TCP links time out reads when idle; that is not a failure.
                Err(mavlink::error::MessageReadError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    return;
                }
            }
        }
    });
    let start = Instant::now();
    let mut hinted = false;
    loop {
        conn.send(&header, &req)?;
        if let Ok(r) = rx.recv_timeout(Duration::from_secs(1)) {
            return match r? {
                MavResult::MAV_RESULT_ACCEPTED => Ok(()),
                other => Err(format!("command was refused: {other:?}").into()),
            };
        }
        let spent = start.elapsed();
        if spent >= wait {
            return Err(no_ack_message(wait).into());
        }
        if hint && !hinted && spent >= QUIET_HINT_AFTER {
            hinted = true;
            eprintln!(
                "no reply yet; if the autopilot just rebooted, ArduPilot refuses signed commands for up to a minute. Still trying..."
            );
        }
    }
}

fn gcs_header() -> MavHeader {
    // 255 is the usual ground station system id; 190 is MAV_COMP_ID_MISSIONPLANNER.
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
