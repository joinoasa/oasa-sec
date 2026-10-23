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
        let mode = std::fs::metadata(a.join("trusted-peers"))
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
    assert!(!a.join("trusted-peers").exists());
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
    assert!(!a.join("trusted-peers").exists());
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
