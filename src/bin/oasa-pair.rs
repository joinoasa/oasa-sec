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
use oasa_sec::pairing::{DeadlineStream, check_name, pair_as_drone_checked, pair_as_ground};
use oasa_sec::removal;
use oasa_sec::signing::{AUTOPILOT_KEY_FILE, SigningKey, peer_key_path};
use oasa_sec::store::{self, Role};

const USAGE: &str = "\
oasa-pair: OASA-SEC pairing, roles and device removal (R-SEC1, R-SEC2). Do not fly with it.

USAGE:
  oasa-pair init     --dir DIR [--name NAME]
  oasa-pair drone    --dir DIR --name NAME --listen HOST:PORT
                     [--autopilot MAVLINK_ADDR] [--target SYS:COMP] [--wait SECONDS]
  oasa-pair ground   --dir DIR --name NAME --connect HOST:PORT
                     [--code-file FILE | --code -] [--expect-drone FINGERPRINT]
  oasa-pair show     --dir DIR
  oasa-pair trust    --dir DIR --name PEERNAME --key HEX64 [--role admin|operator|peer]
  oasa-pair reset-stamp --dir DIR --peer NAME|FINGERPRINT [--which sent|seen|both]
  oasa-pair peers    --dir DIR
  oasa-pair remove   --dir DIR PEER
  oasa-pair revoke   --dir DIR PEER
  oasa-pair restore  --dir DIR KEY
  oasa-pair removed  --dir DIR
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
            test nodes that have no autopilot to pair with. --role sets what the peer may
            do here (default peer). admin: its removal log is obeyed (1 to 3 owner devices,
            ideally kept at base). operator: a ground station that flies this drone. peer:
            link traffic only. Roles are set only here, never by a message. Running it again
            for a trusted key with the same name changes its role.
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
  reset-stamp
            Forget the handshake timestamps saved for one peer (default both). Use it
            when a peer's clock was set far ahead and its handshakes are now refused,
            or after fixing this device's own clock. Fix the clock first. Forgetting
            `seen` lets one recorded old handshake from that peer be accepted again
            until a newer one arrives; do it only for a peer you trust. Restart
            oasa-link afterwards.
  peers     List paired devices with their roles.
  remove    Remove a device on this device (PEER: fingerprint, name or 64-hex key). It
            goes into the permanent `removed` file (a tombstone: it is never trusted
            again, even if an old trusted-peers comes back), out of the list, and its
            handshake timestamps are deleted. A running oasa-link notices within a
            second; the one talking to the removed device exits with code 3. On a drone,
            removing an operator marks its signing key for rotation (the rotation itself
            is not built yet). On a ground station, removing a drone deletes its signing
            key files.
  revoke    Like remove, and also add the device to this device's removal log, which
            devices that list this one as admin pick up over the link. Cannot revoke itself.
  restore   Undo a removal on this device (KEY: fingerprint of a removed device, or
            64-hex key). It is not trusted again until you pair or trust it again.
            Entries already received for it are not applied again; a new one removes
            it again.
  removed   List removed devices (the tombstones).
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
    if let Some(d) = opts.get("dir") {
        report_migration(Path::new(d))?;
    }
    match cmd.as_str() {
        "init" => init(&opts),
        "drone" => drone(&opts),
        "ground" => ground(&opts),
        "show" => show(&opts),
        "trust" => trust(&opts),
        "reset-stamp" => reset_stamp(&opts),
        "peers" => peers(&opts),
        "remove" => remove(&opts),
        "revoke" => revoke(&opts),
        "restore" => restore(&opts),
        "removed" => removed(&opts),
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
    let role = match o.get("role") {
        None => Role::Peer,
        Some(r) => Role::parse(r).ok_or("--role must be admin, operator or peer")?,
    };
    let hex = o.req("key")?.trim().to_ascii_lowercase();
    let public = parse_hex_key(&hex)
        .ok_or("--key must be 64 hexadecimal characters (the public_key from `oasa-pair show`)")?;
    let me = Identity::load(&dir)
        .map_err(|e| format!("{e} (run `oasa-pair init --dir {}` first)", dir.display()))?;
    if &public == me.public_key() {
        return Err("that is this device's own key; a device cannot trust itself".into());
    }
    let peer = store::Peer { public, name, role };
    let mut changed_from = None;
    for p in store::load(&dir)? {
        if p == peer {
            println!(
                "Already trusted: {} {} ({})",
                peer.name,
                peer.fingerprint(),
                peer.role
            );
            return Ok(());
        }
        if p.public == peer.public {
            if p.name != peer.name {
                return Err(format!(
                    "that key is already trusted as {}; use that name to change its role, or remove it first (oasa-pair remove {})",
                    p.name,
                    p.fingerprint()
                )
                .into());
            }
            changed_from = Some(p.role);
            continue;
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
    store::add(&dir, &peer).map_err(|e| match e {
        oasa_sec::Error::Removed => {
            "that device was removed here; a removed device must make a new identity and pair again (or undo it with `oasa-pair restore`)".to_string()
        }
        other => other.to_string(),
    })?;
    match changed_from {
        Some(old) => println!(
            "Changed the role of {} {} from {old} to {}.",
            peer.name,
            peer.fingerprint(),
            peer.role
        ),
        None => println!(
            "Trusted {} {} as {}\nCheck that this fingerprint matches the one shown on that device.",
            peer.name,
            peer.fingerprint(),
            peer.role
        ),
    }
    Ok(())
}

fn parse_hex_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

/// If this folder still has an old `trusted-peers`, convert it and say what
/// came out, so a person can fix the roles (spec R-SEC2 section 3).
fn report_migration(dir: &Path) -> R {
    if let Some(peers) = store::migrate_if_needed(dir)? {
        eprintln!(
            "Converted the old trusted-peers to {} (the old file is now {}).",
            store::TRUST_FILE,
            store::MIGRATED_FILE
        );
        let on_drone = dir.join(AUTOPILOT_KEY_FILE).exists();
        for p in &peers {
            eprintln!("  {}  {}  {}", p.fingerprint(), p.role, p.name);
        }
        eprintln!(
            "Every device became {} ({}). Fix any role with `oasa-pair trust --role admin|operator|peer` (same name).",
            peers.first().map_or(Role::Peer, |p| p.role),
            if on_drone {
                "this device holds an autopilot key, so it is a drone"
            } else {
                "this device holds no autopilot key"
            }
        );
    }
    if dir.join(store::OLD_TRUST_FILE).exists() && dir.join(store::TRUST_FILE).exists() {
        eprintln!(
            "note: an old {} file is still here and is ignored; {} is the list in use.",
            store::OLD_TRUST_FILE,
            store::TRUST_FILE
        );
    }
    Ok(())
}

/// Forget the saved handshake timestamps for one peer.
fn reset_stamp(o: &Opts) -> R {
    use oasa_sec::link::FileTimestampStore;
    let dir = o.dir()?;
    let which = o.get("which").unwrap_or("both");
    let (sent, seen) = match which {
        "sent" => (true, false),
        "seen" => (false, true),
        "both" => (true, true),
        _ => return Err("--which must be sent, seen or both".into()),
    };
    let who = o.req("peer")?;
    let peer = store::find(&dir, who)?.ok_or(format!("no trusted peer {who}"))?;
    let mut st = FileTimestampStore::new(&dir, &peer.public);
    let old = st.reset(sent, seen)?;
    let show = |t: Option<oasa_sec::link::Timestamp>| {
        t.map_or("none".to_string(), |t| format!("{} s", t.secs))
    };
    println!(
        "Reset {which} for {} {} (was sent {}, seen {}).\nFix the clock first if it was wrong, then restart oasa-link.",
        peer.name,
        peer.fingerprint(),
        show(old.sent),
        show(old.seen)
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
        // A removed key gets nothing: no reply, no signing key.
        let accept = |ground: &store::Peer| store::check_not_removed(&dir, &ground.public);
        match pair_as_drone_checked(
            &mut stream,
            &me,
            &name,
            &code,
            current_key.as_ref(),
            accept,
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
        "Paired with ground station {} ({}) as {}; {how}.",
        result.ground.name,
        result.ground.fingerprint(),
        result.ground.role
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
    if store::check_not_removed(&dir, &code.responder_public).is_err() {
        return Err(format!(
            "drone {drone_fp} was removed on this device; a removed device must make a new identity and pair again (or undo it with `oasa-pair restore {drone_fp}`)"
        )
        .into());
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
        "Paired with drone {} ({}) as {}; {how}.",
        r.drone.name,
        r.drone.fingerprint(),
        r.drone.role
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
        println!("{}  {:<8}  {}", p.fingerprint(), p.role, p.name);
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The key a person means: a trusted peer's fingerprint or name, a device
/// already removed (by fingerprint), or 64 hex characters.
fn resolve_target(dir: &Path, text: &str) -> R<[u8; 32]> {
    if let Some(p) = store::find(dir, text)? {
        return Ok(p.public);
    }
    if let Some(k) = parse_hex_key(&text.to_ascii_lowercase()) {
        return Ok(k);
    }
    let removed = removal::load_removed(dir)?;
    if let Some(k) = removed
        .removed_keys()
        .into_iter()
        .find(|k| fingerprint(k) == text)
    {
        return Ok(k);
    }
    Err(format!("no device {text} (use its fingerprint, its name, or its 64-hex key)").into())
}

fn own_key(dir: &Path) -> R<[u8; 32]> {
    let me = Identity::load(dir)
        .map_err(|e| format!("{e} (run `oasa-pair init --dir {}` first)", dir.display()))?;
    Ok(*me.public_key())
}

fn describe_removal(dir: &Path, key: &[u8; 32], out: &removal::RemoveOutcome) {
    let fp = fingerprint(key);
    match &out.peer {
        Some(p) => println!("Removed {} {fp} ({}).", p.name, p.role),
        None if out.already_removed => println!("{fp} was already removed; noted again."),
        None => println!("Removed {fp} (it was not in the list; it can never be trusted here)."),
    }
    if dir.join(removal::ROTATION_PENDING_FILE).exists()
        && out.peer.as_ref().is_some_and(|p| p.role == Role::Operator)
    {
        println!(
            "The drone's MAVLink signing key is still the old one: a rotation is marked pending, but signing-key rotation is not built yet."
        );
    }
    println!("A running oasa-link notices within a second (or at once on SIGHUP).");
}

fn remove(o: &Opts) -> R {
    let dir = o.dir()?;
    let who = o
        .positional
        .first()
        .ok_or("give the fingerprint, name or key to remove")?;
    let key = resolve_target(&dir, who)?;
    let out = removal::remove_local(&dir, &own_key(&dir)?, &key, now_unix())?;
    describe_removal(&dir, &key, &out);
    Ok(())
}

fn revoke(o: &Opts) -> R {
    let dir = o.dir()?;
    let who = o
        .positional
        .first()
        .ok_or("give the fingerprint, name or key to revoke")?;
    let key = resolve_target(&dir, who)?;
    let r = removal::revoke(&dir, &own_key(&dir)?, &key, now_unix())?;
    describe_removal(&dir, &key, &r.outcome);
    println!(
        "Added to this device's removal log as entry {} of log {}{}. Devices that list this one as admin get it when their link is up.",
        r.seq,
        removal::log_id_text(&r.log_id),
        if r.was_in_log {
            " (it was already there)"
        } else {
            ""
        }
    );
    Ok(())
}

fn restore(o: &Opts) -> R {
    let dir = o.dir()?;
    let who = o
        .positional
        .first()
        .ok_or("give the fingerprint (or 64-hex key) of the removed device")?;
    let key = resolve_target(&dir, who)?;
    if removal::restore(&dir, &key, now_unix())? {
        println!(
            "Restored {}. It is not trusted yet: pair it or `oasa-pair trust` it again. Entries already received for it are not applied again; a new one removes it again.",
            fingerprint(&key)
        );
        Ok(())
    } else {
        Err(format!("{} is not removed here", fingerprint(&key)).into())
    }
}

fn removed(o: &Opts) -> R {
    let r = removal::load_removed(&o.dir()?)?;
    let keys = r.removed_keys();
    if keys.is_empty() {
        println!("Nothing removed.");
    }
    for k in keys {
        let by = r
            .records()
            .iter()
            .rev()
            .find_map(|rec| match (&rec.key == &k, &rec.kind) {
                (true, removal::RecordKind::Removed(removal::Source::Local)) => {
                    Some("by hand".to_string())
                }
                (
                    true,
                    removal::RecordKind::Removed(removal::Source::Admin { fingerprint, .. }),
                ) => Some(format!("by admin {fingerprint}")),
                _ => None,
            })
            .unwrap_or_default();
        println!("{}  {by}", fingerprint(&k));
    }
    Ok(())
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
