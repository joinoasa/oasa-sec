//! `oasa-pair show` and `oasa-pair trust`, run as the real program.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn tempdir(tag: &str) -> PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    std::env::temp_dir().join(format!(
        "oasa-pair-cli-{tag}-{}",
        data_encoding::HEXLOWER.encode(&r)
    ))
}

fn pair(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oasa-pair"))
        .args(args)
        .output()
        .unwrap()
}

fn ok(args: &[&str]) -> String {
    let o = pair(args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}

fn err(args: &[&str]) -> String {
    let o = pair(args);
    assert!(!o.status.success(), "{args:?} should fail");
    assert!(o.stdout.is_empty(), "nothing on stdout on failure");
    String::from_utf8(o.stderr).unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Pull `"key":"value"` out of the one-line JSON `show` prints.
fn field<'a>(json: &'a str, key: &str) -> &'a str {
    let tag = format!("\"{key}\":\"");
    let start = json.find(&tag).unwrap() + tag.len();
    let end = start + json[start..].find('"').unwrap();
    &json[start..end]
}

#[test]
fn show_prints_public_details_only() {
    let d = tempdir("show");
    let out = ok(&["init", "--dir", s(&d), "--name", "gcs-1"]);
    assert!(out.starts_with("Created identity "));
    let json = ok(&["show", "--dir", s(&d)]);
    assert_eq!(json.lines().count(), 1);
    assert_eq!(field(&json, "name"), "gcs-1");
    let key = field(&json, "public_key");
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
    let fp = field(&json, "fingerprint");
    assert_eq!(fp.len(), 19);
    assert!(out.contains(fp), "init and show agree on the fingerprint");
    // The private key never appears.
    let private = std::fs::read(d.join("identity.key")).unwrap();
    assert!(!json.contains(&data_encoding::HEXLOWER.encode(&private)));
    assert!(json.starts_with('{') && json.trim_end().ends_with('}'));
}

#[test]
fn show_without_a_saved_name_uses_a_name_from_the_key() {
    let d = tempdir("noname");
    ok(&["init", "--dir", s(&d)]);
    let json = ok(&["show", "--dir", s(&d)]);
    let name = field(&json, "name");
    let key = field(&json, "public_key");
    assert_eq!(name, format!("device-{}", &key[..8]));
    // A name given later (init again) sticks; a different one is refused.
    ok(&["init", "--dir", s(&d), "--name", "relay-1"]);
    assert_eq!(field(&ok(&["show", "--dir", s(&d)]), "name"), "relay-1");
    assert!(err(&["init", "--dir", s(&d), "--name", "other"]).contains("already named"));
    assert!(err(&["init", "--dir", s(&tempdir("x")), "--name", "bad name"]).contains("name"));
}

#[test]
fn show_needs_an_identity() {
    let d = tempdir("none");
    assert!(err(&["show", "--dir", s(&d)]).contains("init"));
}

#[test]
fn trust_adds_a_peer_and_prints_its_fingerprint() {
    let (a, b) = (tempdir("ta"), tempdir("tb"));
    ok(&["init", "--dir", s(&a), "--name", "gcs"]);
    ok(&["init", "--dir", s(&b), "--name", "relay"]);
    let jb = ok(&["show", "--dir", s(&b)]);
    let (key, fp) = (field(&jb, "public_key"), field(&jb, "fingerprint"));
    let out = ok(&["trust", "--dir", s(&a), "--name", "relay", "--key", key]);
    assert!(out.contains(fp), "{out}");
    let peers = ok(&["peers", "--dir", s(&a)]);
    assert!(peers.contains(fp) && peers.contains("relay"));
    // Upper case hex is fine, and trusting the same thing again is fine.
    let upper = key.to_ascii_uppercase();
    let again = ok(&["trust", "--dir", s(&a), "--name", "relay", "--key", &upper]);
    assert!(again.starts_with("Already trusted"));
    assert_eq!(ok(&["peers", "--dir", s(&a)]).lines().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(a.join("trusted-peers.v1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn trust_refuses_bad_input() {
    let (a, b, c) = (tempdir("ra"), tempdir("rb"), tempdir("rc"));
    for (d, n) in [(&a, "gcs"), (&b, "relay"), (&c, "other")] {
        ok(&["init", "--dir", s(d), "--name", n]);
    }
    let key_of = |d: &PathBuf| field(&ok(&["show", "--dir", s(d)]), "public_key").to_string();
    let (ka, kb, kc) = (key_of(&a), key_of(&b), key_of(&c));
    // Bad hex: wrong length, non-hex, empty, base32 form.
    for bad in [
        "",
        "abcd",
        &kb[..62],
        &format!("{kb}00"),
        &format!("zz{}", &kb[2..]),
        &format!("0x{}", &kb[2..]),
        "OASA",
    ] {
        let e = err(&["trust", "--dir", s(&a), "--name", "relay", "--key", bad]);
        assert!(e.contains("64 hexadecimal"), "{bad:?}: {e}");
    }
    // Bad name.
    assert!(err(&["trust", "--dir", s(&a), "--name", "re lay", "--key", &kb]).contains("name"));
    assert!(err(&["trust", "--dir", s(&a), "--name", "", "--key", &kb]).contains("name"));
    // Missing options.
    assert!(err(&["trust", "--dir", s(&a), "--key", &kb]).contains("--name"));
    assert!(err(&["trust", "--dir", s(&a), "--name", "relay"]).contains("--key"));
    // Its own key.
    assert!(err(&["trust", "--dir", s(&a), "--name", "me", "--key", &ka]).contains("own key"));
    // Nothing was written by any of the failures.
    assert!(!a.join("trusted-peers.v1").exists());
    // Clashes with an existing entry.
    ok(&["trust", "--dir", s(&a), "--name", "relay", "--key", &kb]);
    let same_name = err(&["trust", "--dir", s(&a), "--name", "relay", "--key", &kc]);
    assert!(same_name.contains("already used"), "{same_name}");
    let same_key = err(&["trust", "--dir", s(&a), "--name", "relay2", "--key", &kb]);
    assert!(same_key.contains("already trusted as relay"), "{same_key}");
    assert_eq!(ok(&["peers", "--dir", s(&a)]).lines().count(), 1);
    // No identity yet in the directory.
    assert!(
        err(&[
            "trust",
            "--dir",
            s(&tempdir("z")),
            "--name",
            "x",
            "--key",
            &kb
        ])
        .contains("init")
    );
}

#[test]
fn trust_refuses_small_order_keys_and_fingerprint_shaped_names() {
    let (a, b) = (tempdir("sa"), tempdir("sb"));
    ok(&["init", "--dir", s(&a), "--name", "gcs"]);
    ok(&["init", "--dir", s(&b), "--name", "relay"]);
    let kb = field(&ok(&["show", "--dir", s(&b)]), "public_key").to_string();
    for k in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ] {
        let e = err(&["trust", "--dir", s(&a), "--name", "evil", "--key", k]);
        assert!(e.contains("not a valid device key"), "{e}");
    }
    let fp = field(&ok(&["show", "--dir", s(&b)]), "fingerprint").to_string();
    let e = err(&["trust", "--dir", s(&a), "--name", &fp, "--key", &kb]);
    assert!(e.contains("fingerprint"), "{e}");
    assert!(!a.join("trusted-peers.v1").exists());
}

#[test]
fn reset_stamp_forgets_saved_timestamps() {
    let (a, b) = (tempdir("ta"), tempdir("tb"));
    ok(&["init", "--dir", s(&a), "--name", "gcs"]);
    ok(&["init", "--dir", s(&b), "--name", "relay"]);
    let kb = field(&ok(&["show", "--dir", s(&b)]), "public_key").to_string();
    let fp = field(&ok(&["show", "--dir", s(&b)]), "fingerprint").to_string();
    ok(&["trust", "--dir", s(&a), "--name", "relay", "--key", &kb]);
    // Save stamps the way the link does: 24 bytes, sent then seen.
    let file = a.join(format!("link-timestamp-{fp}"));
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&100u64.to_be_bytes());
    bytes[12..20].copy_from_slice(&4_000_000_000u64.to_be_bytes());
    std::fs::write(&file, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = ok(&[
        "reset-stamp",
        "--dir",
        s(&a),
        "--peer",
        "relay",
        "--which",
        "seen",
    ]);
    assert!(out.contains("seen 4000000000 s"), "{out}");
    let after = std::fs::read(&file).unwrap();
    assert_eq!(&after[..8], &100u64.to_be_bytes());
    assert!(after[12..].iter().all(|b| *b == 0));
    ok(&["reset-stamp", "--dir", s(&a), "--peer", &fp]);
    assert!(std::fs::read(&file).unwrap().iter().all(|b| *b == 0));
    assert!(err(&["reset-stamp", "--dir", s(&a), "--peer", "nobody"]).contains("no trusted peer"));
    assert!(
        err(&[
            "reset-stamp",
            "--dir",
            s(&a),
            "--peer",
            "relay",
            "--which",
            "x"
        ])
        .contains("--which")
    );
}

// ---- roles, removal and the lock (R-SEC2) -------------------------------------

fn make(tag: &str) -> (PathBuf, String, String) {
    let d = tempdir(tag);
    ok(&["init", "--dir", s(&d), "--name", tag]);
    let j = ok(&["show", "--dir", s(&d)]);
    (
        d,
        field(&j, "public_key").to_string(),
        field(&j, "fingerprint").to_string(),
    )
}

#[test]
fn trust_sets_roles_and_peers_shows_them() {
    let (a, _, _) = make("ra");
    let (_, kb, fb) = make("rb");
    ok(&["trust", "--dir", s(&a), "--name", "b", "--key", &kb]);
    assert!(ok(&["peers", "--dir", s(&a)]).contains("peer"));
    // Same key and name again with a role changes the role.
    ok(&[
        "trust",
        "--dir",
        s(&a),
        "--name",
        "b",
        "--key",
        &kb,
        "--role",
        "admin",
    ]);
    let peers = ok(&["peers", "--dir", s(&a)]);
    assert!(peers.contains("admin") && peers.contains(&fb), "{peers}");
    assert_eq!(peers.lines().count(), 1);
    err(&[
        "trust",
        "--dir",
        s(&a),
        "--name",
        "b",
        "--key",
        &kb,
        "--role",
        "root",
    ]);
}

#[test]
fn remove_is_permanent_until_restore_and_restore_does_not_trust() {
    let (a, _, _) = make("rma");
    let (_, kb, fb) = make("rmb");
    ok(&["trust", "--dir", s(&a), "--name", "b", "--key", &kb]);
    let out = ok(&["remove", "--dir", s(&a), "b"]);
    assert!(out.contains(&fb), "{out}");
    assert!(ok(&["peers", "--dir", s(&a)]).contains("No paired devices"));
    assert!(ok(&["removed", "--dir", s(&a)]).contains(&fb));
    // A removed key can not be trusted again, by name or by key.
    err(&["trust", "--dir", s(&a), "--name", "b", "--key", &kb]);
    // Restore lifts the tombstone but trusts nothing.
    ok(&["restore", "--dir", s(&a), &fb]);
    assert!(ok(&["peers", "--dir", s(&a)]).contains("No paired devices"));
    assert!(ok(&["removed", "--dir", s(&a)]).contains("Nothing removed"));
    err(&["restore", "--dir", s(&a), &fb]);
    ok(&["trust", "--dir", s(&a), "--name", "b", "--key", &kb]);
    assert!(ok(&["peers", "--dir", s(&a)]).contains(&fb));
}

#[test]
fn revoke_removes_and_writes_a_removal_log() {
    let (a, _, _) = make("rva");
    let (_, kb, fb) = make("rvb");
    ok(&["trust", "--dir", s(&a), "--name", "b", "--key", &kb]);
    let out = ok(&["revoke", "--dir", s(&a), &fb]);
    assert!(out.contains("entry 1"), "{out}");
    assert!(ok(&["removed", "--dir", s(&a)]).contains(&fb));
    // Again: still one entry.
    let again = ok(&["revoke", "--dir", s(&a), &fb]);
    assert!(again.contains("already"), "{again}");
    let log = std::fs::read_to_string(a.join("removal-log")).unwrap();
    assert_eq!(log.lines().count(), 2, "log id plus one entry: {log}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["removal-log", "removed"] {
            let m = std::fs::metadata(a.join(f)).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600, "{f}");
        }
    }
    err(&["remove", "--dir", s(&a), "nobody"]);
    err(&["remove", "--dir", s(&a)]);
}

#[test]
fn an_old_trusted_peers_file_is_converted_and_reported() {
    let a = tempdir("mig");
    ok(&["init", "--dir", s(&a), "--name", "old"]);
    let key = data_encoding::BASE32_NOPAD.encode(&[9u8; 32]);
    std::fs::write(
        a.join("trusted-peers"),
        format!("# OASA-SEC v0 trusted peers: <public key> <name>\n{key} friend\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            a.join("trusted-peers"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let o = pair(&["peers", "--dir", s(&a)]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let (so, se) = (
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
    );
    assert!(se.contains("Converted") && se.contains("friend"), "{se}");
    assert!(so.contains("friend") && so.contains("peer"), "{so}");
    assert!(a.join("trusted-peers.v0-migrated").exists());
    assert!(!a.join("trusted-peers").exists());
    // Second run: nothing to say.
    let o = pair(&["peers", "--dir", s(&a)]);
    assert!(o.stderr.is_empty());
}

#[test]
fn many_processes_changing_one_folder_lose_nothing() {
    let n = 24usize;
    let keys: Vec<String> = (0..n)
        .map(|i| data_encoding::HEXLOWER.encode(&[(i as u8) + 20; 32]))
        .collect();
    // Spawn them all first, then wait: they really overlap.
    let b = tempdir("lock2");
    ok(&["init", "--dir", s(&b), "--name", "b"]);
    let procs: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            Command::new(env!("CARGO_BIN_EXE_oasa-pair"))
                .args([
                    "trust",
                    "--dir",
                    s(&b),
                    "--name",
                    &format!("p{i}"),
                    "--key",
                    k,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for p in procs {
        let o = p.wait_with_output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    assert_eq!(ok(&["peers", "--dir", s(&b)]).lines().count(), n);
}

fn make_drone(tag: &str) -> PathBuf {
    let (d, _, _) = make(tag);
    oasa_sec::signing::SigningKey::generate()
        .unwrap()
        .save(&d.join("mavlink-signing-key.bin"))
        .unwrap();
    d
}

#[test]
fn demoting_an_operator_on_a_drone_asks_for_a_new_signing_key_and_says_so() {
    let drone = make_drone("demote");
    let (_, kb, _) = make("demote-b");
    let t = |role: &str| {
        pair(&[
            "trust",
            "--dir",
            s(&drone),
            "--name",
            "b",
            "--key",
            &kb,
            "--role",
            role,
        ])
    };
    for role in ["peer", "operator"] {
        assert!(t(role).status.success());
    }
    // peer -> operator asked for nothing; operator -> peer does.
    assert!(!drone.join("rotation-pending").exists());
    let out = t("peer");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("new key was requested"), "{text}");
    let pending = std::fs::read_to_string(drone.join("rotation-pending")).unwrap();
    assert!(pending.contains("operator-role-changed"), "{pending}");
}

#[test]
fn migrating_on_a_drone_makes_everyone_an_operator_and_says_so_loudly() {
    let a = make_drone("migdrone");
    let key = data_encoding::BASE32_NOPAD.encode(&[9u8; 32]);
    let old = a.join("trusted-peers");
    std::fs::write(
        &old,
        format!("# OASA-SEC v0 trusted peers: <public key> <name>\n{key} friend\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let o = pair(&["peers", "--dir", s(&a)]);
    assert!(o.status.success());
    let se = String::from_utf8_lossy(&o.stderr);
    assert!(se.contains("CHECK THIS") && se.contains("OPERATOR"), "{se}");
    assert!(se.contains("trust --role peer"), "{se}");
}

/// Kill `pid` after 30 s, so a regression (a signer that never stops, or
/// never prints) fails the test instead of hanging it.
fn watchdog(pid: u32) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    });
}

fn start_signer(d: &Path, port: u16) -> std::process::Child {
    use std::process::Stdio;
    let c = Command::new(env!("CARGO_BIN_EXE_oasa-pair"))
        .args([
            "signer",
            "--dir",
            s(d),
            "--autopilot",
            &format!("udpout:127.0.0.1:{port}"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    watchdog(c.id());
    c
}

#[test]
fn a_second_signer_on_one_folder_is_refused() {
    use std::io::{BufRead, BufReader};
    let d = make_drone("onesigner");
    let mut first = start_signer(&d, 14999);
    let mut line = String::new();
    BufReader::new(first.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("signer_started"), "{line}");
    let second = start_signer(&d, 14998).wait_with_output().unwrap();
    assert!(!second.status.success(), "the second signer must not run");
    let e = String::from_utf8_lossy(&second.stderr);
    assert!(e.contains("already running"), "{e}");
    first.kill().unwrap();
    first.wait().unwrap();
    // Once the first is gone, the folder is free again.
    let mut again = start_signer(&d, 14999);
    let mut line = String::new();
    BufReader::new(again.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("signer_started"), "{line}");
    again.kill().unwrap();
    again.wait().unwrap();
}

// --- Pairing under attack (review finding M1) -------------------------------

use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start `oasa-pair drone` on a free port; return it, its address and its code.
fn start_drone(d: &Path) -> (std::process::Child, String, String) {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let addr = format!("127.0.0.1:{}", free_port());
    let mut c = Command::new(env!("CARGO_BIN_EXE_oasa-pair"))
        .args(["drone", "--dir", s(d), "--name", "drone-1"])
        .args(["--listen", &addr, "--wait", "60"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    watchdog(c.id());
    let mut out = BufReader::new(c.stdout.take().unwrap());
    let code = loop {
        let mut line = String::new();
        assert!(
            out.read_line(&mut line).unwrap() > 0,
            "drone showed no code"
        );
        if line.starts_with("OASA1-") {
            break line.trim().to_string();
        }
    };
    // Keep reading so the drone never blocks on a full pipe.
    std::thread::spawn(move || std::io::copy(&mut out, &mut std::io::sink()));
    (c, addr, code)
}

fn run_ground(d: &Path, addr: &str, code: &str, extra: &[&str]) -> (Output, Duration) {
    use std::io::Write;
    use std::process::Stdio;
    let start = Instant::now();
    let mut g = Command::new(env!("CARGO_BIN_EXE_oasa-pair"))
        .args([
            "ground",
            "--dir",
            s(d),
            "--name",
            "gcs-1",
            "--connect",
            addr,
        ])
        .args(["--code", "-"])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    watchdog(g.id());
    writeln!(g.stdin.take().unwrap(), "{code}").unwrap();
    let o = g.wait_with_output().unwrap();
    (o, start.elapsed())
}

/// An attacker with no code keeps `n` connections open to the pairing port and
/// opens a new one shortly after the drone closes one. `trickle` sends a frame
/// header and then one byte every 200 ms; otherwise the connection stays idle.
fn jam(addr: &str, n: usize, trickle: bool) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    for _ in 0..n {
        let (addr, stop) = (addr.to_string(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut c) = TcpStream::connect(&addr) {
                    hold(&mut c, &stop, trickle);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
    }
    // Let the attacker's connections get there first.
    std::thread::sleep(Duration::from_millis(500));
    stop
}

fn hold(c: &mut TcpStream, stop: &AtomicBool, trickle: bool) {
    use std::io::{Read, Write};
    c.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    if trickle && c.write_all(&[0x00, 0x90]).is_err() {
        return;
    }
    let mut b = [0u8; 64];
    while !stop.load(Ordering::Relaxed) {
        match c.read(&mut b) {
            Ok(0) => return, // the drone closed it
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
        }
        if trickle && c.write_all(&[0x41]).is_err() {
            return;
        }
    }
}

fn pairs_despite(tag: &str, n: usize, trickle: bool) {
    let (dd, gd) = (tempdir(&format!("{tag}-d")), tempdir(&format!("{tag}-g")));
    let (mut drone, addr, code) = start_drone(&dd);
    let stop = jam(&addr, n, trickle);
    let (o, took) = run_ground(&gd, &addr, &code, &[]);
    stop.store(true, Ordering::Relaxed);
    let (out, e) = (
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr),
    );
    assert!(o.status.success(), "ground failed after {took:?}: {e}");
    assert!(out.contains("Paired with drone drone-1"), "{out}");
    assert!(took < Duration::from_secs(10), "pairing took {took:?}");
    assert!(drone.wait().unwrap().success(), "the drone did not finish");
    let peers = ok(&["peers", "--dir", s(&dd)]);
    assert_eq!(peers.lines().count(), 1, "{peers}");
    assert!(
        peers.contains("gcs-1") && peers.contains("operator"),
        "{peers}"
    );
}

#[test]
fn idle_connections_cannot_jam_pairing() {
    pairs_despite("jam-idle", 12, false);
}

#[test]
fn slow_senders_cannot_jam_pairing() {
    pairs_despite("jam-slow", 12, true);
}

/// Two ground stations with the right code at once: exactly one pairs, the
/// code is used once, and the drone saves exactly one ground station.
#[test]
fn one_code_pairs_once_even_in_parallel() {
    let dd = tempdir("par-d");
    let (mut drone, addr, code) = start_drone(&dd);
    let runs: Vec<_> = (0..3)
        .map(|i| {
            let (addr, code) = (addr.clone(), code.clone());
            std::thread::spawn(move || {
                let gd = tempdir(&format!("par-g{i}"));
                let (o, _) = run_ground(&gd, &addr, &code, &["--wait", "5"]);
                (o.status.success(), gd)
            })
        })
        .collect();
    let results: Vec<_> = runs.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|(won, _)| *won).count(), 1);
    assert!(drone.wait().unwrap().success());
    assert_eq!(ok(&["peers", "--dir", s(&dd)]).lines().count(), 1);
    for (won, gd) in &results {
        // Only the winner saved a key for the drone.
        let keys = std::fs::read_dir(gd.join("signing-keys")).map_or(0, |r| r.count());
        assert_eq!(keys, usize::from(*won));
    }
}

/// A ground station with a code for this drone but the wrong secret gets no
/// reply, gives up within seconds, and doesn't end the drone's window.
#[test]
fn a_wrong_code_gets_no_reply_and_gives_up_quickly() {
    let (dd, gd) = (tempdir("wrong-d"), tempdir("wrong-g"));
    ok(&["init", "--dir", s(&dd), "--name", "drone-1"]);
    let (mut drone, addr, code) = start_drone(&dd);
    let drone_pub = oasa_sec::code::PairingCode::decode(&code)
        .unwrap()
        .responder_public;
    let fake = oasa_sec::code::PairingCode::new(drone_pub)
        .unwrap()
        .encode();
    let (o, took) = run_ground(&gd, &addr, &fake, &[]);
    assert!(!o.status.success());
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(e.contains("without answering"), "{e}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    let (o, _) = run_ground(&gd, &addr, &code, &[]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(drone.wait().unwrap().success());
}
