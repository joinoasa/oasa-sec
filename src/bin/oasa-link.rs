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
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oasa_sec::identity::Identity;
use oasa_sec::link::{
    Config, CounterLen, Dest, Event, FileTimestampStore, Link, MIN_MTU, OsEntropy, SendError,
};
use oasa_sec::store;

const USAGE: &str = "\
oasa-link: OASA-SEC v0 encrypted link over UDP (R-COM2). Do not fly with it.

USAGE:
  oasa-link --dir DIR --peer PEERNAME --bind HOST:PORT
            --plain-listen HOST:PORT --plain-send HOST:PORT
            [--remote HOST:PORT] [--initiate]
            [--counter-bytes 2|4] [--rekey-secs N] [--keepalive-secs N]
            [--mtu BYTES] [--duration SECS]

  --dir            Device folder made by `oasa-pair init`.
  --peer           Name of a trusted peer (see `oasa-pair peers`, `oasa-pair trust`).
  --bind           UDP address for the encrypted link.
  --remote         Where the peer is. A responder without it learns the address from
                   the first packet that authenticates, and follows the peer if it moves.
  --initiate       Start the handshake (needs --remote). Without it, wait for the peer.
  --plain-listen   Local programs send plaintext packets here.
  --plain-send     Decrypted packets from the peer go here.
  --counter-bytes  2 (default) or 4: how much of the packet counter goes on the wire.
  --rekey-secs     New handshake after this many seconds (default 600).
  --keepalive-secs Send an empty packet after this many idle seconds (default 25, 0 = off).
  --mtu            Largest encrypted packet in bytes (default 128, the smallest radio the
                   link supports). Plaintext must fit in MTU minus 21 bytes (23 with 4).
  --duration       Stop after this many seconds. Stops on SIGINT or SIGTERM too.

Prints one JSON line per event: handshake_sent, session_established, rekey, drop.
On exit prints {\"event\":\"stats\",...} and exits 0. Packet contents and keys are never printed.
";

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
mod signals {
    use super::STOP;
    use std::sync::atomic::Ordering;

    extern "C" fn on_signal(_: i32) {
        STOP.store(true, Ordering::SeqCst);
    }

    unsafe extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }

    /// Ask for SIGINT and SIGTERM to set the stop flag. The handler only
    /// touches an atomic, which is safe in a signal handler.
    pub fn install() {
        const SIGINT: i32 = 2;
        const SIGTERM: i32 = 15;
        // SAFETY: `signal` is the C library function; the handler is
        // async-signal-safe (one atomic store).
        unsafe {
            signal(SIGINT, on_signal);
            signal(SIGTERM, on_signal);
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
        Ok(()) => ExitCode::SUCCESS,
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
    plain_listen: SocketAddr,
    plain_send: SocketAddr,
    counter: CounterLen,
    rekey_secs: Option<u64>,
    keepalive_secs: Option<u64>,
    mtu: usize,
    duration: Option<Duration>,
}

fn parse_args(args: &[String]) -> R<Option<Args>> {
    let mut named: BTreeMap<String, String> = BTreeMap::new();
    let mut initiate = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" | "help" => return Ok(None),
            "--initiate" => initiate = true,
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
    let remote = match named.get("remote") {
        Some(_) => Some(addr("remote")?),
        None => None,
    };
    if initiate && remote.is_none() {
        return Err("--initiate needs --remote".into());
    }
    let counter = match num("counter-bytes")? {
        None => CounterLen::Short,
        Some(n) => CounterLen::from_bytes(n as usize).ok_or("--counter-bytes must be 2 or 4")?,
    };
    let mtu = num("mtu")?.map_or(MIN_MTU, |n| n as usize);
    Ok(Some(Args {
        dir: PathBuf::from(req("dir")?),
        peer: req("peer")?.clone(),
        bind: addr("bind")?,
        remote,
        initiate,
        plain_listen: addr("plain-listen")?,
        plain_send: addr("plain-send")?,
        counter,
        rekey_secs: num("rekey-secs")?,
        keepalive_secs: num("keepalive-secs")?,
        mtu,
        duration: num("duration")?.map(Duration::from_secs),
    }))
}

fn config_from(a: &Args) -> Config {
    let mut c = Config {
        counter_len: a.counter,
        mtu: a.mtu,
        ..Config::default()
    };
    if let Some(n) = a.rekey_secs {
        c.rekey_after = Duration::from_secs(n);
        // Keep the usual margin of a half again, but never below 15 minutes.
        c.reject_after = c.reject_after.max(Duration::from_secs(n + n / 2 + 1));
    }
    if let Some(n) = a.keepalive_secs {
        c.keepalive = (n > 0).then(|| Duration::from_secs(n));
    }
    c
}

enum Msg {
    Encrypted(Vec<u8>, SocketAddr),
    Plain(Vec<u8>),
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
                        Msg::Plain(data)
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

struct Tunnel {
    link: Link,
    enc: UdpSocket,
    plain_out: UdpSocket,
    plain_send: SocketAddr,
    remote: Option<SocketAddr>,
    /// Drops that happen before a packet is made (counted with the link's).
    local_drops: BTreeMap<&'static str, u64>,
}

impl Tunnel {
    fn local_drop(&mut self, reason: &'static str) {
        *self.local_drops.entry(reason).or_insert(0) += 1;
        println!(
            "{{\"ts\":\"{}\",\"event\":\"drop\",\"reason\":\"{reason}\"}}",
            rfc3339(SystemTime::now())
        );
    }

    /// Act on what the link asked for. `source` is where the packet being
    /// handled came from (None for timers and local packets).
    fn apply(&mut self, events: Vec<Event>, source: Option<SocketAddr>) {
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
                    let _ = self.plain_out.send_to(&p, self.plain_send);
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
                    let role = if initiator { "initiator" } else { "responder" };
                    println!(
                        "{{\"ts\":\"{ts}\",\"event\":\"session_established\",\"role\":\"{role}\"}}"
                    );
                    if rekey {
                        println!("{{\"ts\":\"{ts}\",\"event\":\"rekey\",\"role\":\"{role}\"}}");
                    }
                }
                Event::Dropped(reason) => match source {
                    Some(s) => println!(
                        "{{\"ts\":\"{ts}\",\"event\":\"drop\",\"reason\":\"{}\",\"from\":\"{s}\"}}",
                        reason.as_str()
                    ),
                    None => println!(
                        "{{\"ts\":\"{ts}\",\"event\":\"drop\",\"reason\":\"{}\"}}",
                        reason.as_str()
                    ),
                },
                Event::Failure(what) => {
                    println!("{{\"ts\":\"{ts}\",\"event\":\"error\",\"what\":\"{what}\"}}")
                }
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
            "{{\"ts\":\"{}\",\"event\":\"stats\",\"sent\":{},\"received\":{},\"delivered\":{},\"drops\":{{{drops}}}}}",
            rfc3339(SystemTime::now()),
            st.sent,
            st.received,
            st.delivered
        );
    }
}

fn run(args: &[String]) -> R {
    let Some(a) = parse_args(args)? else {
        print!("{USAGE}");
        return Ok(());
    };
    let me = Identity::load(&a.dir).map_err(|e| {
        format!(
            "{e} (make one with `oasa-pair init --dir {}`)",
            a.dir.display()
        )
    })?;
    let peer = store::find(&a.dir, &a.peer)?.ok_or(format!(
        "no trusted peer named {}; pair first, or `oasa-pair trust`",
        a.peer
    ))?;
    let start = Instant::now();
    let wall_base = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "the clock is before 1970")?;
    let link = Link::new(
        &me,
        peer.public,
        config_from(&a),
        Box::new(OsEntropy),
        wall_base,
        Box::new(FileTimestampStore::new(&a.dir, &peer.public)),
    )?;
    drop(me);

    let enc = UdpSocket::bind(a.bind)?;
    let plain_in = UdpSocket::bind(a.plain_listen)?;
    let plain_out = UdpSocket::bind(if a.plain_send.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    signals::install();

    let (tx, rx) = mpsc::sync_channel::<Msg>(4096);
    spawn_reader(enc.try_clone()?, tx.clone(), true);
    spawn_reader(plain_in, tx, false);

    let mut t = Tunnel {
        link,
        enc,
        plain_out,
        plain_send: a.plain_send,
        remote: a.remote,
        local_drops: BTreeMap::new(),
    };

    if a.initiate {
        let ev = t.link.start_handshake(start.elapsed())?;
        t.apply(ev, None);
    }
    let deadline = a.duration.map(|d| start + d);
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
                    let ev = t.link.handle_packet(now, &bytes);
                    t.apply(ev, Some(from));
                }
                Msg::Plain(bytes) => match t.link.send(now, &bytes) {
                    Ok(packet) => match t.remote {
                        Some(r) => {
                            let _ = t.enc.send_to(&packet, r);
                        }
                        None => t.local_drop("no_remote"),
                    },
                    Err(SendError::TooLarge) => t.local_drop("too_large"),
                    Err(e) => t.local_drop(e.as_str()),
                },
            }
        }
        let ev = t.link.poll_timers(start.elapsed());
        t.apply(ev, None);
    }
    t.print_stats();
    Ok(())
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
    fn rekey_setting_keeps_the_config_valid() {
        for secs in [1u64, 3, 600, 899, 900, 5000] {
            let a = parse_args(&v(&format!("{BASE} --rekey-secs {secs}")))
                .unwrap()
                .unwrap();
            config_from(&a).validate().unwrap();
        }
    }
}
