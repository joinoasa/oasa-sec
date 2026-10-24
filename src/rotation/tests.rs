use super::*;
use crate::files::tempdir;

const FP: &str = "ABCD-EFGH-JKLM-NPQR";

fn drone() -> (PathBuf, SigningKey) {
    let dir = tempdir("rot-drone");
    let k = SigningKey::generate().unwrap();
    k.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    (dir, k)
}

fn operator() -> (PathBuf, SigningKey) {
    let dir = tempdir("rot-op");
    let k = SigningKey::generate().unwrap();
    k.save(&peer_key_path(&dir, FP)).unwrap();
    (dir, k)
}

fn k(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn begin_saves_the_number_first_then_the_key_and_never_reuses_a_number() {
    let (dir, old) = drone();
    let a = begin(&dir).unwrap();
    assert_eq!(a.generation, 1);
    let keys = load_drone_keys(&dir).unwrap().unwrap();
    assert_eq!(keys.current, old);
    assert_eq!(keys.next.as_ref().map(|n| n.0), Some(1));
    // One at a time.
    assert!(begin(&dir).is_err());
    abandon(&dir).unwrap();
    let b = begin(&dir).unwrap();
    assert_eq!(b.generation, 2, "an abandoned number is burnt");
    assert_ne!(a.key, b.key);
    abandon(&dir).unwrap();
    // A number saved with no key (a crash between the two writes) is burnt too.
    write_gen(&dir.join(HIGHEST_GEN_FILE), 7).unwrap();
    assert_eq!(begin(&dir).unwrap().generation, 8);
    // And the highest never falls below the current key's generation.
    abandon(&dir).unwrap();
    std::fs::remove_file(dir.join(HIGHEST_GEN_FILE)).unwrap();
    write_gen(&dir.join(CURRENT_GEN_FILE), 5).unwrap();
    assert_eq!(begin(&dir).unwrap().generation, 6);
}

#[test]
fn commit_switches_the_key_and_the_generation_and_keeps_newer_requests() {
    let (dir, _) = drone();
    request(&dir, "requested", "-", 10).unwrap();
    request(&dir, "operator-removed", FP, 11).unwrap();
    let b = begin(&dir).unwrap();
    // Made after the rotation began: it needs a rotation of its own.
    request(&dir, "operator-removed", FP, 12).unwrap();
    assert_eq!(pending_lines(&dir).unwrap(), 3);
    commit(&dir, b.generation).unwrap();
    let keys = load_drone_keys(&dir).unwrap().unwrap();
    assert_eq!(keys.current, b.key);
    assert_eq!((keys.current_gen, keys.highest), (1, 1));
    assert!(keys.next.is_none());
    assert_eq!(pending_lines(&dir).unwrap(), 1);
    // Committing again (a restart that is not sure) is harmless.
    commit(&dir, 1).unwrap();
    assert_eq!(load_drone_keys(&dir).unwrap().unwrap().current, b.key);
    assert_eq!(pending_lines(&dir).unwrap(), 1);
    // The wrong generation is refused.
    let c = begin(&dir).unwrap();
    assert!(commit(&dir, c.generation + 1).is_err());
    assert!(commit(&dir, c.generation - 1).is_err());
}

#[test]
fn a_commit_that_stopped_part_way_can_be_finished() {
    let (dir, _) = drone();
    let b = begin(&dir).unwrap();
    // Crash after the key was replaced: .bin is new, the rest is not done.
    b.key.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    let keys = load_drone_keys(&dir).unwrap().unwrap();
    assert_eq!(keys.current, keys.next.as_ref().unwrap().1);
    commit(&dir, 1).unwrap();
    let keys = load_drone_keys(&dir).unwrap().unwrap();
    assert_eq!((keys.current_gen, keys.next.is_none()), (1, true));
}

/// A drone with one request made before a rotation began, and one made
/// while it ran. Returns the rotation, stopped before any commit step.
fn rotation_with_two_requests() -> (PathBuf, Begun) {
    let (dir, _) = drone();
    request(&dir, "requested", "-", 10).unwrap();
    let b = begin(&dir).unwrap();
    request(&dir, "operator-removed", FP, 11).unwrap();
    (dir, b)
}

/// Whatever step a crash stopped at, the folder loads, the key in use is the
/// new one once `.bin` was written, and nothing guesses: a restart (the
/// signer's tidy-up, or a repeat of the commit) ends in the same finished
/// state with only the later request left.
fn assert_finished(dir: &Path, b: &Begun) {
    tidy(dir).unwrap();
    let keys = load_drone_keys(dir).unwrap().unwrap();
    assert_eq!(keys.current, b.key);
    assert_eq!(
        (keys.current_gen, keys.highest),
        (b.generation, b.generation)
    );
    assert!(keys.next.is_none());
    assert!(!dir.join(NEXT_KEY_FILE).exists(), ".next is cleaned up");
    assert_eq!(pending_lines(dir).unwrap(), 1, "only the later request");
    // A new rotation can start.
    let c = begin(dir).unwrap();
    assert_eq!(c.generation, b.generation + 1);
}

#[test]
fn a_crash_at_every_step_of_commit_leaves_a_folder_that_loads_and_finishes() {
    // Step 1 done: .bin replaced. .gen, .next and requests untouched.
    let (dir, b) = rotation_with_two_requests();
    b.key.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    assert!(load_drone_keys(&dir).is_ok());
    commit(&dir, b.generation).unwrap();
    assert_finished(&dir, &b);

    // Step 2 done: .gen written too. (The reviewer's case: this used to be
    // refused for good.)
    let (dir, b) = rotation_with_two_requests();
    b.key.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    write_gen(&dir.join(CURRENT_GEN_FILE), b.generation).unwrap();
    let keys = load_drone_keys(&dir).unwrap().unwrap();
    assert!(keys.next.is_none(), "a finished commit, not a pending key");
    assert_eq!(pending_lines(&dir).unwrap(), 2);
    commit(&dir, b.generation).unwrap();
    assert_finished(&dir, &b);
    // ... and a restart without a commit call ends the same way.
    let (dir, b) = rotation_with_two_requests();
    b.key.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    write_gen(&dir.join(CURRENT_GEN_FILE), b.generation).unwrap();
    assert_finished(&dir, &b);

    // Step 3 done: .next deleted. Only the request clean-up is left.
    let (dir, b) = rotation_with_two_requests();
    b.key.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    write_gen(&dir.join(CURRENT_GEN_FILE), b.generation).unwrap();
    std::fs::remove_file(dir.join(NEXT_KEY_FILE)).unwrap();
    assert_eq!(pending_lines(&dir).unwrap(), 2);
    assert_finished(&dir, &b);
}

#[test]
fn a_leftover_next_that_is_not_the_current_key_is_still_refused() {
    let (dir, _) = drone();
    let b = begin(&dir).unwrap();
    // The generation says "finished" but the keys differ: not a commit.
    write_gen(&dir.join(CURRENT_GEN_FILE), b.generation).unwrap();
    assert!(load_drone_keys(&dir).is_err());
}

#[test]
fn a_commit_after_an_abandon_is_refused_and_changes_nothing() {
    let (dir, old) = drone();
    let b = begin(&dir).unwrap();
    abandon(&dir).unwrap();
    assert!(commit(&dir, b.generation).is_err());
    let keys = load_drone_keys(&dir).unwrap().unwrap();
    assert_eq!((keys.current_gen, keys.current == old), (0, true));
    // Nor does it clear a request.
    request(&dir, "requested", "-", 1).unwrap();
    assert!(commit(&dir, b.generation).is_err());
    assert_eq!(pending_lines(&dir).unwrap(), 1);
}

#[test]
fn requests_are_counted_and_validated() {
    let (dir, _) = drone();
    assert_eq!(pending_lines(&dir).unwrap(), 0);
    assert!(request(&dir, "two words", "-", 1).is_err());
    assert!(request(&dir, "", "-", 1).is_err());
    request(&dir, "requested", "-", 1).unwrap();
    assert_eq!(pending_lines(&dir).unwrap(), 1);
}

#[test]
fn requests_name_the_generation_that_was_highest_not_a_time() {
    let (dir, _) = drone();
    request(&dir, "requested", "-", u64::MAX / 2).unwrap(); // a wild clock
    let b = begin(&dir).unwrap();
    request(&dir, "requested", "-", 5).unwrap(); // an earlier "time"
    commit(&dir, b.generation).unwrap();
    // The first was made before the rotation began, whatever its time said.
    assert_eq!(pending_lines(&dir).unwrap(), 1);
    let text = std::fs::read_to_string(dir.join(PENDING_FILE)).unwrap();
    assert_eq!(text, "5 requested - 1\n");
    // Rotations since: that one is now answered by the next commit.
    let c = begin(&dir).unwrap();
    commit(&dir, c.generation).unwrap();
    assert_eq!(pending_lines(&dir).unwrap(), 0);
}

#[test]
fn a_second_signer_cannot_run_on_the_same_folder() {
    let (dir, _) = drone();
    let first = lock_signer(&dir).unwrap();
    assert!(lock_signer(&dir).is_err());
    drop(first);
    assert!(lock_signer(&dir).is_ok());
}

#[test]
fn a_bad_generation_file_is_an_error_not_a_guess() {
    let (dir, _) = drone();
    for bad in ["", "x\n", "-1\n", "99999999999\n", "1 2\n"] {
        crate::files::write_private_file(&dir.join(HIGHEST_GEN_FILE), bad.as_bytes()).unwrap();
        assert!(load_drone_keys(&dir).is_err(), "{bad:?}");
    }
}

#[test]
fn what_an_operator_is_owed() {
    let (dir, cur) = drone();
    let keys = |next: Option<u32>, gen_: u32| DroneKeys {
        current: cur.clone(),
        current_gen: gen_,
        next: next.map(|g| (g, SigningKey::generate().unwrap())),
        highest: next.unwrap_or(gen_).max(gen_),
    };
    let a = |n, c| Acked { next: n, commit: c };
    drop(dir);
    // The key from pairing needs nothing.
    assert_eq!(owed(&keys(None, 0), a(0, 0)), Owed::Nothing);
    // A pending key goes out at once, and then waits for the autopilot.
    assert_eq!(owed(&keys(Some(3), 2), a(2, 2)), Owed::Next(3));
    assert_eq!(owed(&keys(Some(3), 2), a(3, 2)), Owed::Nothing);
    // After the commit: the commit.
    assert_eq!(owed(&keys(None, 3), a(3, 2)), Owed::Commit(3));
    assert_eq!(owed(&keys(None, 3), a(3, 3)), Owed::Nothing);
    // One that was away: the current key first, then its commit.
    assert_eq!(owed(&keys(None, 3), a(0, 0)), Owed::Next(3));
    assert_eq!(owed(&keys(None, 3), a(1, 1)), Owed::Next(3));
    // One that holds a stale key from a failed rotation (next acked 5, now 3).
    assert_eq!(owed(&keys(None, 3), a(5, 2)), Owed::Next(3));
}

#[test]
fn acked_state_round_trips_and_rejects_nonsense() {
    let (dir, _) = drone();
    assert_eq!(read_acked(&dir, FP).unwrap(), Acked::default());
    write_acked(&dir, FP, Acked { next: 4, commit: 3 }).unwrap();
    assert_eq!(read_acked(&dir, FP).unwrap(), Acked { next: 4, commit: 3 });
    assert!(write_acked(&dir, "../etc/passwd", Acked::default()).is_err());
    crate::files::write_private_file(&dir.join(ACKED_DIR).join(FP), b"1\n").unwrap();
    assert!(read_acked(&dir, FP).is_err());
}

#[test]
fn an_operator_stores_a_pending_key_and_switches_only_on_commit() {
    let (dir, old) = operator();
    assert_eq!(
        operator_on_next(&dir, FP, 1, &k(9)).unwrap(),
        NextOutcome::Stored
    );
    // Not switched yet.
    assert_eq!(SigningKey::load(&peer_key_path(&dir, FP)).unwrap(), old);
    assert_eq!(operator_gen(&dir, FP).unwrap(), 0);
    assert_eq!(operator_pending(&dir, FP).unwrap().unwrap().0, 1);
    // A repeat is known; the same generation with another key is a conflict.
    assert_eq!(
        operator_on_next(&dir, FP, 1, &k(9)).unwrap(),
        NextOutcome::Known
    );
    assert_eq!(
        operator_on_next(&dir, FP, 1, &k(8)).unwrap(),
        NextOutcome::Conflict
    );
    assert_eq!(
        SigningKey::load(&op_path(&dir, FP, ".next"))
            .unwrap()
            .as_bytes(),
        &k(9),
        "a conflict changes nothing"
    );
    // Commit.
    assert_eq!(
        operator_on_commit(&dir, FP, 1).unwrap(),
        CommitOutcome::Switched
    );
    assert_eq!(
        SigningKey::load(&peer_key_path(&dir, FP))
            .unwrap()
            .as_bytes(),
        &k(9)
    );
    assert_eq!(operator_gen(&dir, FP).unwrap(), 1);
    assert!(operator_pending(&dir, FP).unwrap().is_none());
    assert!(!op_path(&dir, FP, ".next").exists() && !op_path(&dir, FP, ".next.gen").exists());
    // Repeats and old news.
    assert_eq!(
        operator_on_commit(&dir, FP, 1).unwrap(),
        CommitOutcome::AlreadyCurrent
    );
    assert_eq!(
        operator_on_next(&dir, FP, 1, &k(9)).unwrap(),
        NextOutcome::Old
    );
    assert_eq!(
        operator_on_next(&dir, FP, 0, &k(7)).unwrap(),
        NextOutcome::Old
    );
}

#[test]
fn a_newer_next_replaces_a_pending_one_and_a_commit_for_another_generation_does_nothing() {
    let (dir, old) = operator();
    operator_on_next(&dir, FP, 2, &k(2)).unwrap();
    assert_eq!(
        operator_on_commit(&dir, FP, 3).unwrap(),
        CommitOutcome::NoPending
    );
    assert_eq!(
        operator_on_commit(&dir, FP, 1).unwrap(),
        CommitOutcome::NoPending
    );
    assert_eq!(SigningKey::load(&peer_key_path(&dir, FP)).unwrap(), old);
    assert_eq!(
        operator_on_next(&dir, FP, 4, &k(4)).unwrap(),
        NextOutcome::Stored
    );
    let (g, key) = operator_pending(&dir, FP).unwrap().unwrap();
    assert_eq!((g, key.as_bytes()), (4, &k(4)));
    assert_eq!(
        operator_on_commit(&dir, FP, 2).unwrap(),
        CommitOutcome::NoPending
    );
    // A pending key from a failed rotation (5) gives way to the current one (3).
    operator_on_next(&dir, FP, 5, &k(5)).unwrap();
    assert_eq!(
        operator_on_next(&dir, FP, 3, &k(3)).unwrap(),
        NextOutcome::Stored
    );
    assert_eq!(
        operator_on_commit(&dir, FP, 3).unwrap(),
        CommitOutcome::Switched
    );
    assert_eq!(operator_gen(&dir, FP).unwrap(), 3);
    // ... and 5 cannot come back by repeating a commit.
    assert_eq!(
        operator_on_commit(&dir, FP, 5).unwrap(),
        CommitOutcome::NoPending
    );
}

#[test]
fn an_interrupted_switch_is_finished_by_the_repeat() {
    let (dir, _) = operator();
    operator_on_next(&dir, FP, 1, &k(9)).unwrap();
    // Crash after the key file was replaced, before the number.
    SigningKey::from_bytes(k(9))
        .unwrap()
        .save(&peer_key_path(&dir, FP))
        .unwrap();
    assert_eq!(operator_gen(&dir, FP).unwrap(), 0);
    assert_eq!(
        operator_on_commit(&dir, FP, 1).unwrap(),
        CommitOutcome::Switched
    );
    assert_eq!(operator_gen(&dir, FP).unwrap(), 1);
    // Crash after the number, before the clean-up.
    let (dir, _) = operator();
    operator_on_next(&dir, FP, 1, &k(9)).unwrap();
    SigningKey::from_bytes(k(9))
        .unwrap()
        .save(&peer_key_path(&dir, FP))
        .unwrap();
    write_gen(&op_path(&dir, FP, ".gen"), 1).unwrap();
    assert_eq!(
        operator_on_commit(&dir, FP, 1).unwrap(),
        CommitOutcome::Switched
    );
    assert!(operator_pending(&dir, FP).unwrap().is_none());
}

#[test]
fn a_next_with_no_key_held_for_that_drone_is_refused_and_a_zero_key_too() {
    let dir = tempdir("rot-op-none");
    assert!(operator_on_next(&dir, FP, 1, &k(9)).is_err());
    assert!(operator_on_commit(&dir, FP, 1).is_err());
    let (dir, _) = operator();
    assert!(
        operator_on_next(&dir, FP, 1, &[0u8; 32]).is_err(),
        "all-zero turns signing off"
    );
    assert!(operator_pending(&dir, FP).unwrap().is_none());
}

#[test]
fn a_symlinked_or_loose_key_file_is_refused() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let (dir, _) = operator();
        operator_on_next(&dir, FP, 1, &k(9)).unwrap();
        let p = op_path(&dir, FP, ".next");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(operator_on_commit(&dir, FP, 1).is_err());
    }
}

#[test]
fn seen_timestamps_only_go_up() {
    let (dir, _) = drone();
    assert_eq!(read_seen_ts(&dir).unwrap(), 0);
    write_seen_ts(&dir, 50).unwrap();
    write_seen_ts(&dir, 20).unwrap();
    assert_eq!(read_seen_ts(&dir).unwrap(), 50);
}
