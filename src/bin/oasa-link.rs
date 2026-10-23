//! `oasa-link`: carry local UDP packets over the OASA-SEC v0 encrypted link.
//!
//! Prototype for OASA tech tree node R-COM2. Do not fly with it.
//!
//! Plaintext from local programs arrives on `--plain-listen`, goes out
//! encrypted over UDP from `--bind`, and what the peer sends comes out
//! decrypted at `--plain-send`. One JSON line per event goes to standard
//! output; the lab reads it. The link logic is `oasa_sec::link` (sans-IO);
//! this file only moves bytes and reads the clock.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oasa_sec::control::{Action, Control, Note};
use oasa_sec::identity::{Identity, fingerprint};
use oasa_sec::link::{
    Config, CounterLen, Dest, DropReason, Event, FileTimestampStore, Link, MIN_MTU, OsEntropy,
    SendError, SourceLimiter, looks_like_handshake1,
};
use oasa_sec::mavguard::{Block, Guard};
use oasa_sec::removal::{LOG_FILE, REMOVED_FILE};
use oasa_sec::signing::AUTOPILOT_KEY_FILE;
use oasa_sec::store::{self, TRUST_FILE};

const USAGE: &str = "\
oasa-link: OASA-SEC encrypted link (wire version 1) over UDP (R-COM2). Do not fly with it.

USAGE:
  oasa-link --dir DIR --peer PEERNAME --bind HOST:PORT
            --plain-listen HOST:PORT --plain-send HOST:PORT
            [--remote HOST:PORT] [--initiate] [--allow-remote-plain] [--trusted-clock]
            [--counter-bytes 2|4] [--rekey-secs N] [--keepalive-secs N]
            [--mtu BYTES] [--duration SECS]
            [--mavlink-guard | --no-mavlink-guard] [--allow-mavlink-ftp]
            [--allow-rtk] [--allow-fence-rally]
            [--allow-msg ID]... [--allow-command ID]... [--allow-param NAME]...

  --dir            Device folder made by `oasa-pair init`.
  --peer           Name of a trusted peer (see `oasa-pair peers`, `oasa-pair trust`).
  --bind           UDP address for the encrypted link.
  --remote         Where the peer is. Give it whenever you know it: without it a device
                   cannot start a handshake itself (after a restart it must wait for the
                   peer to notice, up to 90 s). A device without it learns the address from
                   the first packet that authenticates, and follows the peer if it moves.
  --trusted-clock  Only if this device has a trusted clock (RTC or NTP, set before start):
                   refuse a handshake whose timestamp is over 10 minutes ahead of it.
                   Off by default, so a drone with a slow or unset clock still connects.
  --initiate       Start the handshake (needs --remote). Without it, wait for the peer.
  --plain-listen   Local programs send plaintext packets here. Must be a loopback
                   address (127.0.0.1 or ::1) unless --allow-remote-plain is given.
  --plain-send     Decrypted packets from the peer go here. Plaintext is accepted only
                   from this host unless --allow-remote-plain is given.
  --allow-remote-plain
                   Let --plain-listen be a non-loopback address and accept plaintext from
                   any host. Anyone who can reach that port can then inject packets into
                   the link; only use it on a wired, trusted network.
  --counter-bytes  2 (default) or 4: how much of the packet counter goes on the wire.
  --rekey-secs     New handshake after this many seconds (default 600).
  --keepalive-secs Send an empty packet after this many idle seconds (default 25, 0 = off).
  --mtu            Largest encrypted packet in bytes (default 128, the smallest radio the
                   link supports). Plaintext must fit in MTU minus 22 bytes (24 with 4).
  --mavlink-guard  Check every packet from the link before it goes to --plain-send. Only
                   whole, CRC-valid frames of allowed messages and commands pass; the rest
                   of the datagram is dropped. Parameter writes, FTP and SETUP_SIGNING are
                   off. On by default when --dir holds mavlink-signing-key.bin (a drone);
                   this forces it on. The allowlist is in docs/oasa-sec-v0-link.md.
  --no-mavlink-guard
                   Turn the guard off (prints a warning). Not for flight.
  --allow-mavlink-ftp
                   Let FILE_TRANSFER_PROTOCOL through the guard (log download needs it).
  --allow-rtk      Allow GPS_INJECT_DATA and GPS_RTCM_DATA (RTK corrections). Logs a warning.
  --allow-fence-rally
                   Allow geofence and rally mission messages (mission types 1 and 2) and the
                   fence and rally commands (5000 to 5004, 5100). Logs a warning.
  --allow-msg ID   Also allow this MAVLink message id (repeatable). Logs a warning.
  --allow-command ID
                   Also allow this command id in COMMAND_LONG, COMMAND_INT and mission
                   items (repeatable). Logs a warning.
  --allow-param NAME
                   Allow PARAM_SET / PARAM_EXT_SET for this one parameter (repeatable).
                   Signing parameters can never be allowed. Logs a warning.
  --duration       Stop after this many seconds. Stops on SIGINT or SIGTERM too.

Prints one JSON line per event: handshake_sent, session_established, rekey, drop, hint,
mavlink_guard (at start), warning. A datagram stopped by the guard is a drop with reason
mavlink_blocked, a why word, the message id and (for commands) the command id
(never contents). The widening flags each print a warning at start.
At most 10 drop lines a second are printed; a drops_suppressed line counts the rest.

Removal (R-SEC2): oasa-link watches trusted-peers.v1, removed and removal-log and reloads
within a second (at once on SIGHUP). If its own --peer has been removed it prints
{\"event\":\"peer_removed\",...}, then the stats, and exits with code 3. If those files
cannot be read it exits with code 1 (it fails closed). Control messages (removal sync
between admins and devices) are handled here and never reach --plain-send; their drops
count as bad_role, bad_control and peer_removed. Lines: removal_entry, not_admin_here,
trust_reloaded, trust_migrated.

On exit prints {\"event\":\"stats\",...} and exits 0 (3 after peer_removed). Packet contents
and keys are never printed.
";

/// Handshake 1 packets let through per second from one source address.
const SOURCE_HANDSHAKES_PER_SECOND: u32 = 3;

static STOP: AtomicBool = AtomicBool::new(false);
/// Set by SIGHUP: reload the trust files now.
static RELOAD: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
mod signals {
    use super::{RELOAD, STOP};
    use std::sync::atomic::Ordering;

    extern "C" fn on_signal(_: i32) {
        STOP.store(true, Ordering::SeqCst);
    }

    extern "C" fn on_hup(_: i32) {
        RELOAD.store(true, Ordering::SeqCst);
    }

    unsafe extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }

    /// Ask for SIGINT and SIGTERM to set the stop flag, and SIGHUP the
    /// reload flag. The handlers only touch an atomic, which is safe in a
    /// signal handler.
    pub fn install() {
        const SIGHUP: i32 = 1;
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        // SAFETY: `signal` is the C library function; the handlers are
        // async-signal-safe (one atomic store).
        unsafe {
            signal(SIGINT, on_signal);
            signal(SIGTERM, on_signal);
            signal(SIGHUP, on_hup);
        }
    }
}

#[cfg(not(unix))]
mod signals {
    pub fn install() {}
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

type R<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Args {
    dir: PathBuf,
    peer: String,
    bind: SocketAddr,
    remote: Option<SocketAddr>,
    initiate: bool,
    allow_remote_plain: bool,
    trusted_clock: bool,
    guard: Option<bool>,
    allow_ftp: bool,
    allow_rtk: bool,
    allow_fence_rally: bool,
    allow_msgs: Vec<u32>,
    allow_commands: Vec<u32>,
    allow_params: Vec<String>,
    plain_listen: SocketAddr,
    plain_send: SocketAddr,
    counter: CounterLen,
    rekey_secs: Option<u64>,
    keepalive_secs: Option<u64>,
    mtu: usize,
    duration: Option<Duration>,
}

/// About ten years, in seconds.
const MAX_SECS: u64 = 10 * 365 * 86_400;

fn parse_args(args: &[String]) -> R<Option<Args>> {
    let mut named: BTreeMap<String, String> = BTreeMap::new();
    let mut initiate = false;
    let mut allow_remote_plain = false;
    let mut trusted_clock = false;
    let mut guard_on = false;
    let mut guard_off = false;
    let mut allow_ftp = false;
    let mut allow_rtk = false;
    let mut allow_fence_rally = false;
    let mut allow_msgs: Vec<u32> = Vec::new();
    let mut allow_commands: Vec<u32> = Vec::new();
    let mut allow_params: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" | "help" => return Ok(None),
            "--initiate" => initiate = true,
            "--allow-remote-plain" => allow_remote_plain = true,
            "--trusted-clock" => trusted_clock = true,
            "--mavlink-guard" => guard_on = true,
            "--no-mavlink-guard" => guard_off = true,
            "--allow-mavlink-ftp" => allow_ftp = true,
            "--allow-rtk" => allow_rtk = true,
            "--allow-fence-rally" => allow_fence_rally = true,
            "--allow-msg" | "--allow-command" => {
                let v = it.next().ok_or(format!("{a} needs a value"))?;
                let n: u32 = v
                    .parse()
                    .map_err(|_| format!("{a}: {v:?} is not a number"))?;
                if a == "--allow-msg" {
                    allow_msgs.push(n);
                } else {
                    allow_commands.push(n);
                }
            }
            "--allow-param" => {
                allow_params.push(it.next().ok_or("--allow-param needs a value")?.clone());
            }
            _ => {
                let k = a
                    .strip_prefix("--")
                    .ok_or(format!("unexpected argument {a:?}; run oasa-link --help"))?;
                let v = it.next().ok_or(format!("--{k} needs a value"))?;
                if named.insert(k.to_string(), v.clone()).is_some() {
                    return Err(format!("--{k} given twice").into());
                }
            }
        }
    }
    const KNOWN: [&str; 11] = [
        "dir",
        "peer",
        "bind",
        "remote",
        "plain-listen",
        "plain-send",
        "counter-bytes",
        "rekey-secs",
        "keepalive-secs",
        "mtu",
        "duration",
    ];
    if let Some(k) = named.keys().find(|k| !KNOWN.contains(&k.as_str())) {
        return Err(format!("unknown option --{k}; run oasa-link --help").into());
    }
    let req = |k: &str| named.get(k).ok_or(format!("missing --{k}"));
    let addr = |k: &str| -> R<SocketAddr> {
        let v = req(k)?;
        v.to_socket_addrs()
            .map_err(|e| format!("--{k} {v}: {e}"))?
            .next()
            .ok_or_else(|| format!("--{k} {v}: no address").into())
    };
    let num = |k: &str| -> R<Option<u64>> {
        named
            .get(k)
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| format!("--{k} must be a whole number"))
            })
            .transpose()
            .map_err(Into::into)
    };
    if guard_on && guard_off {
        return Err("--mavlink-guard and --no-mavlink-guard together make no sense".into());
    }
    if guard_off
        && (allow_ftp
            || allow_rtk
            || allow_fence_rally
            || !allow_msgs.is_empty()
            || !allow_commands.is_empty()
            || !allow_params.is_empty())
    {
        return Err("the --allow-* guard flags have no effect with --no-mavlink-guard".into());
    }
    let guard = match (guard_on, guard_off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    };
    let remote = match named.get("remote") {
        Some(_) => Some(addr("remote")?),
        None => None,
    };
    if initiate && remote.is_none() {
        return Err("--initiate needs --remote".into());
    }
    let counter = match num("counter-bytes")? {
        None => CounterLen::Short,
        Some(n) => usize::try_from(n)
            .ok()
            .and_then(CounterLen::from_bytes)
            .ok_or("--counter-bytes must be 2 or 4")?,
    };
    let mtu = match num("mtu")? {
        None => MIN_MTU,
        Some(n) => usize::try_from(n)
            .ok()
            .filter(|n| (MIN_MTU..=65_535).contains(n))
            .ok_or("--mtu must be 128 to 65535")?,
    };
    // The most we allow for a time option: about ten years.
    let secs = |k: &str, max: u64| -> R<Option<u64>> {
        match num(k)? {
            Some(n) if n > max => Err(format!("--{k} is too large (at most {max})").into()),
            other => Ok(other),
        }
    };
    let plain_listen = addr("plain-listen")?;
    if !plain_listen.ip().is_loopback() && !allow_remote_plain {
        return Err(
            "--plain-listen must be a loopback address (127.0.0.1 or ::1); anyone who can reach \
             it could inject packets into the link. Use --allow-remote-plain to override"
                .into(),
        );
    }
    Ok(Some(Args {
        dir: PathBuf::from(req("dir")?),
        peer: req("peer")?.clone(),
        bind: addr("bind")?,
        remote,
        initiate,
        allow_remote_plain,
        trusted_clock,
        guard,
        allow_ftp,
        allow_rtk,
        allow_fence_rally,
        allow_msgs,
        allow_commands,
        allow_params,
        plain_listen,
        plain_send: addr("plain-send")?,
        counter,
        rekey_secs: secs("rekey-secs", MAX_SECS / 2)?,
        keepalive_secs: secs("keepalive-secs", MAX_SECS)?,
        mtu,
        duration: secs("duration", MAX_SECS)?.map(Duration::from_secs),
    }))
}

/// The guard the flags ask for.
fn build_guard(a: &Args) -> Result<Guard, String> {
    let mut g = Guard::new();
    if a.allow_ftp {
        g = g.allow_ftp();
    }
    if a.allow_rtk {
        g = g.allow_rtk();
    }
    if a.allow_fence_rally {
        g = g.allow_fence_rally();
    }
    for &m in &a.allow_msgs {
        g = g.allow_msg(m)?;
    }
    for &c in &a.allow_commands {
        g = g.allow_command(c)?;
    }
    for p in &a.allow_params {
        g = g.allow_param(p)?;
    }
    Ok(g)
}

/// One line per thing the flags widened, for the start-up warnings.
fn widened(a: &Args) -> Vec<String> {
    let mut w = Vec::new();
    if a.allow_ftp {
        w.push("FILE_TRANSFER_PROTOCOL (110) is allowed".to_string());
    }
    if a.allow_rtk {
        w.push("GPS_INJECT_DATA (123) and GPS_RTCM_DATA (233) are allowed".to_string());
    }
    if a.allow_fence_rally {
        w.push("geofence and rally mission messages (types 1 and 2) and commands 5000-5004, 5100 are allowed".to_string());
    }
    w.extend(
        a.allow_msgs
            .iter()
            .map(|m| format!("message {m} is allowed")),
    );
    w.extend(
        a.allow_commands
            .iter()
            .map(|c| format!("command {c} is allowed")),
    );
    w.extend(
        a.allow_params
            .iter()
            .map(|p| format!("writes to parameter {} are allowed", p.to_ascii_uppercase())),
    );
    w
}

fn config_from(a: &Args) -> R<Config> {
    let mut c = Config {
        counter_len: a.counter,
        mtu: a.mtu,
        ..Config::default()
    };
    if let Some(n) = a.rekey_secs {
        c.rekey_after = Duration::from_secs(n);
        // Keep the usual margin of a half again, but never below 15 minutes.
        let margin = n
            .checked_add(n / 2)
            .and_then(|m| m.checked_add(1))
            .ok_or("--rekey-secs is too large")?;
        c.reject_after = c.reject_after.max(Duration::from_secs(margin));
    }
    if let Some(n) = a.keepalive_secs {
        c.keepalive = (n > 0).then(|| Duration::from_secs(n));
    }
    if a.trusted_clock {
        c.max_future = Some(Duration::from_secs(600));
    }
    c.validate()?;
    Ok(c)
}

/// Limits drop lines on standard output: 10 a second, then one summary line
/// a second. Counting is not affected; the statistics stay exact.
struct DropLog {
    window: Instant,
    printed: u32,
    suppressed: u64,
}

const DROP_LINES_PER_SECOND: u32 = 10;

impl DropLog {
    fn new(now: Instant) -> Self {
        Self {
            window: now,
            printed: 0,
            suppressed: 0,
        }
    }

    /// Start a new second if one has passed. Returns how many lines the
    /// second that ended held back.
    fn roll(&mut self, now: Instant) -> u64 {
        if now.saturating_duration_since(self.window) < Duration::from_secs(1) {
            return 0;
        }
        self.window = now;
        self.printed = 0;
        std::mem::take(&mut self.suppressed)
    }

    /// May one more drop line be printed now? (After `roll`.)
    fn allow(&mut self) -> bool {
        if self.printed < DROP_LINES_PER_SECOND {
            self.printed += 1;
            true
        } else {
            self.suppressed += 1;
            false
        }
    }
}

enum Msg {
    Encrypted(Vec<u8>, SocketAddr),
    Plain(Vec<u8>, SocketAddr),
}

/// Read datagrams from `sock` forever and pass them on.
fn spawn_reader(sock: UdpSocket, tx: mpsc::SyncSender<Msg>, encrypted: bool) {
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_536];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let data = buf[..n].to_vec();
                    let msg = if encrypted {
                        Msg::Encrypted(data, from)
                    } else {
                        Msg::Plain(data, from)
                    };
                    if tx.send(msg).is_err() {
                        return;
                    }
                }
                // ICMP "port unreachable" from an earlier send shows up here on
                // some systems; it says nothing about the packet we are waiting for.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    });
}

/// How the program sees a file change: modified time, size and inode
/// (an atomic replace gives a new inode even within one clock tick).
type FileSig = Option<(SystemTime, u64, u64)>;

fn file_sig(path: &std::path::Path) -> FileSig {
    let m = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    let ino = {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    };
    #[cfg(not(unix))]
    let ino = 0;
    Some((m.modified().ok()?, m.len(), ino))
}

/// Watches the files that decide who is trusted. Checked every 250 ms, so a
/// change is seen well inside a second.
struct Watch {
    dir: PathBuf,
    trust: [FileSig; 2],
    log: FileSig,
    next_check: Instant,
}

const WATCH_EVERY: Duration = Duration::from_millis(250);

impl Watch {
    fn new(dir: &std::path::Path, now: Instant) -> Self {
        let mut w = Self {
            dir: dir.to_path_buf(),
            trust: [None, None],
            log: None,
            next_check: now + WATCH_EVERY,
        };
        w.read();
        w
    }

    fn read(&mut self) -> (bool, bool) {
        let trust = [
            file_sig(&self.dir.join(TRUST_FILE)),
            file_sig(&self.dir.join(REMOVED_FILE)),
        ];
        let log = file_sig(&self.dir.join(LOG_FILE));
        let changed = (trust != self.trust, log != self.log);
        self.trust = trust;
        self.log = log;
        changed
    }

    /// `(trust files changed, removal log changed)`, or `None` if it is not
    /// time to look yet. `force` (SIGHUP) looks now and reports a reload.
    fn check(&mut self, now: Instant, force: bool) -> Option<(bool, bool)> {
        if !force && now < self.next_check {
            return None;
        }
        self.next_check = now + WATCH_EVERY;
        let (t, l) = self.read();
        Some((t || force, l))
    }
}

struct Tunnel {
    link: Link,
    control: Control,
    enc: UdpSocket,
    plain_out: UdpSocket,
    plain_send: SocketAddr,
    remote: Option<SocketAddr>,
    /// The MAVLink guard on what comes out of the link, if it is on.
    guard: Option<Guard>,
    /// Drops that happen before a packet is made (counted with the link's).
    local_drops: BTreeMap<&'static str, u64>,
    drop_log: DropLog,
    /// Handshakes in a row refused as old or too far ahead.
    stale_run: u32,
    hinted: bool,
}

impl Tunnel {
    fn local_drop(&mut self, reason: &'static str) {
        *self.local_drops.entry(reason).or_insert(0) += 1;
        if self.drop_log.allow() {
            println!(
                "{{\"ts\":\"{}\",\"event\":\"drop\",\"reason\":\"{reason}\"}}",
                rfc3339(SystemTime::now())
            );
        }
    }

    /// The guard stopped a datagram from the link. Counted as `mavlink_blocked`
    /// and logged like any drop; the line names the message id, never contents.
    fn guard_drop(&mut self, b: Block) {
        *self.local_drops.entry("mavlink_blocked").or_insert(0) += 1;
        if self.drop_log.allow() {
            let id = b.msgid.map_or(String::new(), |m| format!(",\"msgid\":{m}"));
            let cmd = b
                .command
                .map_or(String::new(), |c| format!(",\"command\":{c}"));
            let cmd = match b.mission_type {
                Some(t) => format!("{cmd},\"mission_type\":{t}"),
                None => cmd,
            };
            println!(
                "{{\"ts\":\"{}\",\"event\":\"drop\",\"reason\":\"mavlink_blocked\",\"why\":\"{}\"{id}{cmd}}}",
                rfc3339(SystemTime::now()),
                b.why.as_str()
            );
        }
    }

    /// Once a second, say how many drop lines were held back.
    fn flush_drop_summary(&mut self, force: bool) {
        let mut n = self.drop_log.roll(Instant::now());
        if force {
            n += std::mem::take(&mut self.drop_log.suppressed);
        }
        if n > 0 {
            println!(
                "{{\"ts\":\"{}\",\"event\":\"drops_suppressed\",\"count\":{n}}}",
                rfc3339(SystemTime::now())
            );
        }
    }

    /// Act on what the link asked for. `source` is where the packet being
    /// handled came from (None for timers and local packets).
    fn apply(&mut self, events: Vec<Event>, source: Option<SocketAddr>, now: Duration) {
        let ts = rfc3339(SystemTime::now());
        for e in events {
            match e {
                Event::Send { packet, to } => {
                    let dest = match to {
                        Dest::Remote => self.remote,
                        Dest::Source => source,
                    };
                    match dest {
                        Some(d) => {
                            let _ = self.enc.send_to(&packet, d);
                        }
                        None => self.local_drop("no_remote"),
                    }
                }
                Event::Deliver(p) => {
                    if let Some(Err(b)) = self.guard.as_ref().map(|g| g.check(&p)) {
                        self.guard_drop(b);
                        continue;
                    }
                    let _ = self.plain_out.send_to(&p, self.plain_send);
                }
                Event::Control(bytes) => {
                    let actions = self.control.handle(now, unix_now(), &bytes);
                    self.run_actions(actions, now);
                }
                Event::Authenticated => {
                    // Follow the peer if it moved, but only because a packet
                    // from the new address just passed every check.
                    if let Some(s) = source {
                        self.remote = Some(s);
                    }
                }
                Event::HandshakeSent { retry, rekey } => println!(
                    "{{\"ts\":\"{ts}\",\"event\":\"handshake_sent\",\"retry\":{retry},\"rekey\":{rekey}}}"
                ),
                Event::SessionEstablished { initiator, rekey } => {
                    // A new session: unfinished removal sync starts over.
                    let actions = self.control.session_started(now);
                    self.run_actions(actions, now);
                    self.stale_run = 0;
                    self.hinted = false;
                    let role = if initiator { "initiator" } else { "responder" };
                    println!(
                        "{{\"ts\":\"{ts}\",\"event\":\"session_established\",\"role\":\"{role}\"}}"
                    );
                    if rekey {
                        println!("{{\"ts\":\"{ts}\",\"event\":\"rekey\",\"role\":\"{role}\"}}");
                    }
                }
                Event::Dropped(reason) => {
                    if reason == DropReason::StaleHandshake {
                        self.stale_run += 1;
                        if self.stale_run >= 3 && !self.hinted {
                            self.hinted = true;
                            println!(
                                "{{\"ts\":\"{ts}\",\"event\":\"hint\",\"what\":\"handshakes from the peer keep being refused as old or too far ahead; check that both clocks are right, then run oasa-pair reset-stamp and restart\"}}"
                            );
                        }
                    }
                    if self.drop_log.allow() {
                        match source {
                            Some(s) => println!(
                                "{{\"ts\":\"{ts}\",\"event\":\"drop\",\"reason\":\"{}\",\"from\":\"{s}\"}}",
                                reason.as_str()
                            ),
                            None => println!(
                                "{{\"ts\":\"{ts}\",\"event\":\"drop\",\"reason\":\"{}\"}}",
                                reason.as_str()
                            ),
                        }
                    }
                }
                Event::Failure(what) => {
                    println!("{{\"ts\":\"{ts}\",\"event\":\"error\",\"what\":\"{what}\"}}")
                }
            }
        }
    }

    /// Do what the control layer asked: send its messages on the link, count
    /// its drops, log its notes. A message that cannot go now (no session
    /// yet) is not lost: the control layer resends on its own timers.
    fn run_actions(&mut self, actions: Vec<Action>, now: Duration) {
        for a in actions {
            match a {
                Action::Send(bytes) => {
                    if let Ok(packet) = self.link.send_control(now, &bytes) {
                        match self.remote {
                            Some(r) => {
                                let _ = self.enc.send_to(&packet, r);
                            }
                            None => self.local_drop("no_remote"),
                        }
                    }
                }
                Action::Drop(reason) => self.local_drop(reason),
                Action::Note(n) => print_note(&n),
            }
        }
    }

    fn print_stats(&self) {
        let st = self.link.stats();
        let mut drops: Vec<(String, u64)> = st
            .drops()
            .map(|(r, n)| (r.as_str().to_string(), n))
            .collect();
        for (k, n) in &self.local_drops {
            drops.push(((*k).to_string(), *n));
        }
        let drops = drops
            .iter()
            .map(|(k, n)| format!("\"{k}\":{n}"))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"ts\":\"{}\",\"event\":\"stats\",\"sent\":{},\"received\":{},\"delivered\":{},\"control_sent\":{},\"control_received\":{},\"drops\":{{{drops}}}}}",
            rfc3339(SystemTime::now()),
            st.sent,
            st.received,
            st.delivered,
            st.control_sent,
            st.control_received
        );
    }
}

/// Exit code when this process's own `--peer` was removed (R-SEC2).
const EXIT_PEER_REMOVED: u8 = 3;

fn run(args: &[String]) -> R<u8> {
    let Some(a) = parse_args(args)? else {
        print!("{USAGE}");
        return Ok(0);
    };
    let me = Identity::load(&a.dir).map_err(|e| {
        format!(
            "{e} (make one with `oasa-pair init --dir {}`)",
            a.dir.display()
        )
    })?;
    // An old trusted-peers file is converted once; say what came out.
    if let Some(peers) = store::migrate_if_needed(&a.dir)? {
        let ts = rfc3339(SystemTime::now());
        for p in &peers {
            println!(
                "{{\"ts\":\"{ts}\",\"event\":\"trust_migrated\",\"key\":\"{}\",\"role\":\"{}\"}}",
                p.fingerprint(),
                p.role
            );
        }
    }
    // Look at the files before reading them, so a change in between is seen.
    let mut watch = Watch::new(&a.dir, Instant::now());
    let peer = store::find(&a.dir, &a.peer)?.ok_or(format!(
        "no trusted peer named {}; pair first, or `oasa-pair trust`",
        a.peer
    ))?;
    let own_public = *me.public_key();
    let start = Instant::now();
    let wall_base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the clock is before 1970")?;
    let link = Link::new(
        &me,
        peer.public,
        config_from(&a)?,
        Box::new(OsEntropy),
        wall_base,
        Box::new(FileTimestampStore::new(&a.dir, &peer.public)),
    )?;
    drop(me);
    let mut link = link;
    if a.trusted_clock {
        // Read at each check, not once at startup.
        link.set_wall_clock(Box::new(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
        }));
    }

    let enc = UdpSocket::bind(a.bind)?;
    let plain_in = UdpSocket::bind(a.plain_listen)?;
    // Decrypted packets leave from the same socket that plaintext arrives on,
    // so a program that answers the sender (PX4 does) answers to --plain-listen.
    let plain_out = plain_in.try_clone()?;
    signals::install();

    // On by default for a drone (the device that holds the autopilot's key).
    let has_key = a.dir.join(AUTOPILOT_KEY_FILE).exists();
    let guard = match a.guard {
        Some(on) => on,
        None => has_key,
    }
    .then(|| build_guard(&a))
    .transpose()?;
    let now = rfc3339(SystemTime::now());
    match (&guard, a.guard) {
        (Some(g), _) => {
            println!(
                "{{\"ts\":\"{now}\",\"event\":\"mavlink_guard\",\"state\":\"on\",\"ftp\":{}}}",
                g.ftp_allowed()
            );
            for what in widened(&a) {
                println!(
                    "{{\"ts\":\"{now}\",\"event\":\"warning\",\"what\":\"the MAVLink guard is widened: {what}\"}}"
                );
            }
        }
        (None, Some(false)) => println!(
            "{{\"ts\":\"{now}\",\"event\":\"warning\",\"what\":\"the MAVLink guard is off: the link can carry any MAVLink to the autopilot, including SETUP_SIGNING, FTP and parameter writes\"}}"
        ),
        (None, _) => {
            println!(
                "{{\"ts\":\"{now}\",\"event\":\"mavlink_guard\",\"state\":\"off\",\"ftp\":false}}"
            );
            println!(
                "{{\"ts\":\"{now}\",\"event\":\"hint\",\"what\":\"the MAVLink guard is off because --dir has no mavlink-signing-key.bin; drones whose key lives elsewhere: use --mavlink-guard\"}}"
            );
        }
    }

    let (tx, rx) = mpsc::sync_channel::<Msg>(4096);
    spawn_reader(enc.try_clone()?, tx.clone(), true);
    spawn_reader(plain_in, tx, false);
    // Handshakes per source address (the port is free for an attacker to vary).
    let mut source_limit: SourceLimiter<IpAddr> = SourceLimiter::new(SOURCE_HANDSHAKES_PER_SECOND);

    let mut t = Tunnel {
        link,
        control: Control::new(&a.dir, own_public, peer.public, Box::new(OsEntropy)),
        enc,
        plain_out,
        plain_send: a.plain_send,
        remote: a.remote,
        guard,
        local_drops: BTreeMap::new(),
        drop_log: DropLog::new(Instant::now()),
        stale_run: 0,
        hinted: false,
    };

    if a.initiate {
        let now = start.elapsed();
        let ev = t.link.start_handshake(now)?;
        t.apply(ev, None, now);
    }
    let mut exit_code = 0u8;
    let deadline = match a.duration {
        Some(d) => Some(start.checked_add(d).ok_or("--duration is too large")?),
        None => None,
    };
    while !STOP.load(Ordering::SeqCst) && deadline.is_none_or(|d| Instant::now() < d) {
        // Wait briefly for a packet, then take whatever else is already
        // queued, then run the timers.
        let first = rx.recv_timeout(Duration::from_millis(10));
        let mut batch = Vec::new();
        match first {
            Ok(m) => batch.push(m),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err("a socket closed".into()),
        }
        while batch.len() < 512 {
            match rx.try_recv() {
                Ok(m) => batch.push(m),
                Err(_) => break,
            }
        }
        for m in batch {
            let now = start.elapsed();
            match m {
                Msg::Encrypted(bytes, from) => {
                    if looks_like_handshake1(&bytes) && !source_limit.allow(now, from.ip()) {
                        t.local_drop("source_limited");
                        continue;
                    }
                    let ev = t.link.handle_packet(now, &bytes);
                    t.apply(ev, Some(from), now);
                }
                Msg::Plain(bytes, from) => {
                    if !a.allow_remote_plain && from.ip() != a.plain_send.ip() {
                        t.local_drop("plain_source");
                        continue;
                    }
                    // Without a place to send to, nothing is encrypted: a
                    // packet is not counted as sent if it never leaves.
                    let Some(r) = t.remote else {
                        t.local_drop("no_remote");
                        continue;
                    };
                    match t.link.send(now, &bytes) {
                        Ok(packet) => {
                            let _ = t.enc.send_to(&packet, r);
                        }
                        Err(SendError::TooLarge) => t.local_drop("too_large"),
                        Err(e) => t.local_drop(e.as_str()),
                    }
                }
            }
        }
        let now = start.elapsed();
        let ev = t.link.poll_timers(now);
        t.apply(ev, None, now);
        let actions = t.control.poll(now);
        t.run_actions(actions, now);
        // The trust files: looked at four times a second, and at once on SIGHUP.
        let hup = RELOAD.swap(false, Ordering::SeqCst);
        if let Some((trust_changed, log_changed)) = watch.check(Instant::now(), hup) {
            if trust_changed {
                match reload(&a.dir, &peer, &mut t) {
                    Ok(true) => {}
                    Ok(false) => {
                        exit_code = EXIT_PEER_REMOVED;
                        break;
                    }
                    Err(e) => {
                        // Fail closed: if the files cannot be read, a removal
                        // might be in them. Stop rather than guess.
                        t.flush_drop_summary(true);
                        t.print_stats();
                        return Err(format!("cannot read the trust files: {e}").into());
                    }
                }
            }
            if log_changed {
                let actions = t.control.log_changed(now);
                t.run_actions(actions, now);
            }
        }
        t.flush_drop_summary(false);
    }
    t.flush_drop_summary(true);
    t.print_stats();
    Ok(exit_code)
}

/// Read the trust files again. `Ok(true)`: carry on. `Ok(false)`: our own
/// peer is gone (removed, or no longer listed); the link to it is over, which
/// the caller does by exiting. Unsent control messages for it are dropped.
fn reload(dir: &std::path::Path, peer: &store::Peer, t: &mut Tunnel) -> oasa_sec::Result<bool> {
    let snap = store::snapshot(dir)?;
    let ts = rfc3339(SystemTime::now());
    if snap.get(&peer.public).is_none() {
        t.control.peer_removed();
        let why = if snap.removed.is_removed(&peer.public) {
            "removed"
        } else {
            "not_listed"
        };
        println!(
            "{{\"ts\":\"{ts}\",\"event\":\"peer_removed\",\"peer\":\"{}\",\"why\":\"{why}\"}}",
            fingerprint(&peer.public)
        );
        return Ok(false);
    }
    println!(
        "{{\"ts\":\"{ts}\",\"event\":\"trust_reloaded\",\"peers\":{},\"removed\":{}}}",
        snap.peers.len(),
        snap.removed.removed_keys().len()
    );
    Ok(true)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One log line for a control-layer note. Fingerprints and numbers only.
fn print_note(n: &Note) {
    let mut line = format!(
        "{{\"ts\":\"{}\",\"event\":\"{}\"",
        rfc3339(SystemTime::now()),
        n.what
    );
    if let Some(k) = &n.key {
        line.push_str(&format!(",\"key\":\"{k}\""));
    }
    if let Some(s) = n.seq {
        line.push_str(&format!(",\"seq\":{s}"));
    }
    if let Some(d) = n.detail {
        line.push_str(&format!(",\"detail\":\"{d}\""));
    }
    line.push('}');
    println!("{line}");
}

/// `2026-10-23T12:34:56.789Z`
fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Days since 1970-01-01 to a calendar date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, ms: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, ms * 1_000_000)
    }

    #[test]
    fn timestamps_are_rfc3339_utc() {
        assert_eq!(rfc3339(at(0, 0)), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(at(951_782_400, 5)), "2000-02-29T00:00:00.005Z");
        assert_eq!(rfc3339(at(1_700_000_000, 999)), "2023-11-14T22:13:20.999Z");
        assert_eq!(rfc3339(at(1_793_000_000, 0)), "2026-10-26T07:33:20.000Z");
        assert_eq!(rfc3339(at(4_107_542_400, 0)), "2100-03-01T00:00:00.000Z");
    }

    fn v(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    const BASE: &str =
        "--dir d --peer p --bind 127.0.0.1:1 --plain-listen 127.0.0.1:2 --plain-send 127.0.0.1:3";

    #[test]
    fn arguments_are_checked() {
        assert!(parse_args(&v(BASE)).unwrap().is_some());
        assert!(parse_args(&v("--help")).unwrap().is_none());
        let a = parse_args(&v(&format!(
            "{BASE} --remote 127.0.0.1:4 --initiate --counter-bytes 4 --rekey-secs 9 --duration 5 --mtu 200"
        )))
        .unwrap()
        .unwrap();
        assert!(a.initiate && a.counter == CounterLen::Long && a.mtu == 200);
        assert_eq!(a.duration, Some(Duration::from_secs(5)));
        for bad in [
            format!("{BASE} --initiate"), // needs --remote
            format!("{BASE} --counter-bytes 3"),
            format!("{BASE} --rekey-secs x"),
            format!("{BASE} --nonsense 1"),
            format!("{BASE} --dir e"),      // twice
            "--dir d --peer p".to_string(), // missing options
            format!("{BASE} stray"),
        ] {
            assert!(parse_args(&v(&bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn plain_listen_must_be_loopback_unless_allowed() {
        let remote =
            "--dir d --peer p --bind 127.0.0.1:1 --plain-listen 0.0.0.0:2 --plain-send 127.0.0.1:3";
        let e = parse_args(&v(remote)).err().unwrap().to_string();
        assert!(e.contains("loopback"), "{e}");
        let lan = "--dir d --peer p --bind 127.0.0.1:1 --plain-listen 192.168.1.5:2 --plain-send 127.0.0.1:3";
        assert!(parse_args(&v(lan)).is_err());
        let a = parse_args(&v(&format!("{remote} --allow-remote-plain")))
            .unwrap()
            .unwrap();
        assert!(a.allow_remote_plain);
        let v6 = "--dir d --peer p --bind 127.0.0.1:1 --plain-listen [::1]:2 --plain-send [::1]:3";
        assert!(parse_args(&v(v6)).unwrap().is_some());
        assert!(!parse_args(&v(BASE)).unwrap().unwrap().allow_remote_plain);
    }

    #[test]
    fn guard_widening_flags_are_checked() {
        let a = parse_args(&v(&format!(
            "{BASE} --allow-msg 33 --allow-msg 24 --allow-command 185 --allow-param WP_SPD --allow-param MPC_X"
        )))
        .unwrap()
        .unwrap();
        assert_eq!(a.allow_msgs, [33, 24]);
        assert_eq!(a.allow_commands, [185]);
        assert_eq!(a.allow_params, ["WP_SPD", "MPC_X"]);
        let g = build_guard(&a).unwrap();
        assert_eq!(widened(&a).len(), 5);
        assert!(g.ftp_allowed() == a.allow_ftp);
        for bad in [
            "--allow-msg",
            "--allow-msg x",
            "--allow-command -1",
            "--allow-param",
            "--no-mavlink-guard --allow-msg 33",
            "--no-mavlink-guard --allow-param WP_SPD",
        ] {
            assert!(parse_args(&v(&format!("{BASE} {bad}"))).is_err(), "{bad}");
        }
        // Refused by the guard itself: reported when the guard is built.
        for bad in [
            "--allow-msg 256",
            "--allow-msg 110",
            "--allow-param MAV_SIGN_CFG",
            "--allow-command 70000",
        ] {
            let a = parse_args(&v(&format!("{BASE} {bad}"))).unwrap().unwrap();
            assert!(build_guard(&a).is_err(), "{bad}");
        }
    }

    #[test]
    fn rtk_and_fence_rally_flags_are_checked() {
        let a = parse_args(&v(&format!("{BASE} --allow-rtk --allow-fence-rally")))
            .unwrap()
            .unwrap();
        assert!(a.allow_rtk && a.allow_fence_rally);
        let g = build_guard(&a).unwrap();
        assert!(g.rtk_allowed() && g.fence_rally_allowed());
        assert_eq!(widened(&a).len(), 2);
        let a = parse_args(&v(BASE)).unwrap().unwrap();
        assert!(!a.allow_rtk && !a.allow_fence_rally);
        assert!(widened(&a).is_empty());
        for bad in [
            "--no-mavlink-guard --allow-rtk",
            "--no-mavlink-guard --allow-fence-rally",
        ] {
            assert!(parse_args(&v(&format!("{BASE} {bad}"))).is_err(), "{bad}");
        }
    }

    #[test]
    fn guard_flags_are_checked() {
        let a = parse_args(&v(BASE)).unwrap().unwrap();
        assert_eq!((a.guard, a.allow_ftp), (None, false));
        let a = parse_args(&v(&format!("{BASE} --mavlink-guard --allow-mavlink-ftp")))
            .unwrap()
            .unwrap();
        assert_eq!((a.guard, a.allow_ftp), (Some(true), true));
        let a = parse_args(&v(&format!("{BASE} --no-mavlink-guard")))
            .unwrap()
            .unwrap();
        assert_eq!(a.guard, Some(false));
        for bad in [
            "--mavlink-guard --no-mavlink-guard",
            "--no-mavlink-guard --allow-mavlink-ftp",
            "--mavlink-guard x",
        ] {
            assert!(parse_args(&v(&format!("{BASE} {bad}"))).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_future_check_is_off_unless_asked_for() {
        let off = parse_args(&v(BASE)).unwrap().unwrap();
        assert_eq!(config_from(&off).unwrap().max_future, None);
        let on = parse_args(&v(&format!("{BASE} --trusted-clock")))
            .unwrap()
            .unwrap();
        assert_eq!(
            config_from(&on).unwrap().max_future,
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn huge_numbers_are_refused_not_wrapped() {
        for bad in [
            "--duration 18446744073709551615",
            "--duration 99999999999",
            "--rekey-secs 18446744073709551615",
            "--rekey-secs 9999999999999",
            "--keepalive-secs 18446744073709551615",
            "--mtu 18446744073709551615",
            "--mtu 70000",
            "--mtu 127",
            "--counter-bytes 4294967298", // wraps to 2 on a 32-bit usize
        ] {
            assert!(parse_args(&v(&format!("{BASE} {bad}"))).is_err(), "{bad}");
        }
        // The largest allowed values still make a valid config.
        let a = parse_args(&v(&format!(
            "{BASE} --rekey-secs {} --keepalive-secs {} --duration {}",
            MAX_SECS / 2,
            MAX_SECS,
            MAX_SECS
        )))
        .unwrap()
        .unwrap();
        config_from(&a).unwrap();
    }

    #[test]
    fn drop_lines_are_limited_to_ten_a_second_with_a_summary() {
        let t0 = Instant::now();
        let mut log = DropLog::new(t0);
        let printed = (0..1000).filter(|_| log.allow()).count();
        assert_eq!(printed, 10);
        assert_eq!(log.suppressed, 990);
        // Nothing to report until the second is over, then exactly the rest.
        assert_eq!(log.roll(t0 + Duration::from_millis(900)), 0);
        assert_eq!(log.roll(t0 + Duration::from_millis(1000)), 990);
        assert_eq!(log.roll(t0 + Duration::from_millis(1100)), 0);
        // A new second starts with a new allowance.
        assert_eq!((0..50).filter(|_| log.allow()).count(), 10);
    }

    #[test]
    fn rekey_setting_keeps_the_config_valid() {
        for secs in [1u64, 3, 600, 899, 900, 5000] {
            let a = parse_args(&v(&format!("{BASE} --rekey-secs {secs}")))
                .unwrap()
                .unwrap();
            config_from(&a).unwrap();
        }
    }
}
