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

#[test]
fn a_second_signer_on_one_folder_is_refused() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let d = make_drone("onesigner");
    let mut first = Command::new(env!("CARGO_BIN_EXE_oasa-pair"))
        .args([
            "signer",
            "--dir",
            s(&d),
            "--autopilot",
            "udpout:127.0.0.1:14999",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(first.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("signer_started"), "{line}");
    let e = err(&[
        "signer",
        "--dir",
        s(&d),
        "--autopilot",
        "udpout:127.0.0.1:14998",
    ]);
    assert!(e.contains("already running"), "{e}");
    first.kill().unwrap();
    first.wait().unwrap();
    // Once the first is gone, the folder is free again.
    let mut second = Command::new(env!("CARGO_BIN_EXE_oasa-pair"))
        .args([
            "signer",
            "--dir",
            s(&d),
            "--autopilot",
            "udpout:127.0.0.1:14999",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(second.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.contains("signer_started"), "{line}");
    second.kill().unwrap();
    second.wait().unwrap();
}
