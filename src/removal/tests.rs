//! Removal file tests: tombstones, the log, the two-admin rule, restore.

use super::*;
use crate::files::tempdir;
use crate::identity::fingerprint;

const OWN: [u8; 32] = [1; 32];
const A1: [u8; 32] = [11; 32];
const A2: [u8; 32] = [12; 32];
const A3: [u8; 32] = [13; 32];
const OP: [u8; 32] = [21; 32];
const PEER: [u8; 32] = [31; 32];
const STRANGER: [u8; 32] = [41; 32];

fn trust(dir: &Path, key: [u8; 32], name: &str, role: Role) {
    store::add(
        dir,
        &Peer {
            public: key,
            name: name.into(),
            role,
        },
    )
    .unwrap();
}

/// A device that lists admins A1 and A2, an operator and a peer.
fn device() -> PathBuf {
    let d = tempdir("removal");
    trust(&d, A1, "admin-1", Role::Admin);
    trust(&d, A2, "admin-2", Role::Admin);
    trust(&d, OP, "operator", Role::Operator);
    trust(&d, PEER, "peer", Role::Peer);
    d
}

fn entry(log: u8, seq: u32, target: [u8; 32]) -> Entry {
    Entry {
        log_id: [log; 4],
        seq,
        target,
        time: 1000 + u64::from(seq),
    }
}

fn listed(dir: &Path, key: &[u8; 32]) -> bool {
    store::get(dir, key).unwrap().is_some()
}

#[test]
fn a_tombstone_beats_a_stale_trusted_peers() {
    let d = device();
    let stale = std::fs::read(d.join(store::TRUST_FILE)).unwrap();
    let out = remove_local(&d, &OWN, &PEER, 50).unwrap();
    assert_eq!(out.peer.unwrap().role, Role::Peer);
    assert!(!out.already_removed);
    assert!(!listed(&d, &PEER));
    // A backup of the old list comes back: the tombstone still wins.
    write_private_file(&d.join(store::TRUST_FILE), &stale).unwrap();
    assert!(!listed(&d, &PEER));
    assert_eq!(store::load(&d).unwrap().len(), 3);
    assert!(store::find(&d, "peer").unwrap().is_none());
    // And a key can't be added, trusted or paired while removed.
    let again = Peer {
        public: PEER,
        name: "peer".into(),
        role: Role::Admin,
    };
    assert!(matches!(store::add(&d, &again), Err(Error::Removed)));
    assert!(matches!(
        store::check_not_removed(&d, &PEER),
        Err(Error::Removed)
    ));
    assert!(store::check_not_removed(&d, &STRANGER).is_ok());
}

#[test]
fn removing_a_key_that_was_never_listed_still_keeps_it_out() {
    let d = device();
    let out = remove_local(&d, &OWN, &STRANGER, 5).unwrap();
    assert_eq!(out.peer, None);
    assert!(load_removed(&d).unwrap().is_removed(&STRANGER));
    assert!(matches!(
        store::add(
            &d,
            &Peer {
                public: STRANGER,
                name: "late".into(),
                role: Role::Peer
            }
        ),
        Err(Error::Removed)
    ));
    // A device can't remove itself.
    assert!(remove_local(&d, &OWN, &OWN, 5).is_err());
}

#[test]
fn removal_deletes_timestamps_and_keeps_the_file_append_only() {
    let d = device();
    let stamp = FileTimestampStore::new(&d, &PEER).path().to_path_buf();
    write_private_file(&stamp, &[1u8; 24]).unwrap();
    let other = FileTimestampStore::new(&d, &OP).path().to_path_buf();
    write_private_file(&other, &[1u8; 24]).unwrap();
    remove_local(&d, &OWN, &PEER, 50).unwrap();
    assert!(!stamp.exists());
    assert!(other.exists(), "only the removed peer's file goes");
    let first = std::fs::read_to_string(d.join(REMOVED_FILE)).unwrap();
    assert_eq!(first, format!("{} removed local 50\n", key_to_text(&PEER)));
    remove_local(&d, &OWN, &OP, 60).unwrap();
    let second = std::fs::read_to_string(d.join(REMOVED_FILE)).unwrap();
    assert!(second.starts_with(&first), "earlier lines never change");
    assert_eq!(second.lines().count(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.join(REMOVED_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Removing again changes nothing but adds a record, and says so.
    let again = remove_local(&d, &OWN, &PEER, 70).unwrap();
    assert!(again.already_removed);
}

#[test]
fn a_drone_removing_an_operator_asks_for_a_rotation_and_a_peer_does_not() {
    let d = device();
    // Not a drone: nothing.
    remove_local(&d, &OWN, &OP, 1).unwrap();
    assert!(!d.join(ROTATION_PENDING_FILE).exists());
    // A drone (has the autopilot key).
    let d = device();
    write_private_file(&d.join(AUTOPILOT_KEY_FILE), &[7u8; 40]).unwrap();
    remove_local(&d, &OWN, &PEER, 2).unwrap();
    assert!(
        !d.join(ROTATION_PENDING_FILE).exists(),
        "a peer holds no key"
    );
    remove_local(&d, &OWN, &OP, 3).unwrap();
    let text = std::fs::read_to_string(d.join(ROTATION_PENDING_FILE)).unwrap();
    assert_eq!(text, format!("3 operator-removed {} 0\n", fingerprint(&OP)));
    // The same through an admin's entry.
    let d = device();
    write_private_file(&d.join(AUTOPILOT_KEY_FILE), &[7u8; 40]).unwrap();
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, OP), 9).unwrap(),
        Applied::Removed
    );
    assert!(d.join(ROTATION_PENDING_FILE).exists());
}

#[test]
fn a_ground_station_removing_a_drone_deletes_its_signing_keys() {
    let d = device();
    let fp = fingerprint(&PEER);
    let keys = d.join(PEER_KEYS_DIR);
    let other = fingerprint(&OP);
    for name in [
        format!("{fp}.bin"),
        format!("{fp}.next"),
        format!("{fp}.gen"),
        format!("{other}.bin"),
    ] {
        write_private_file(&keys.join(name), &[9u8; 40]).unwrap();
    }
    remove_local(&d, &OWN, &PEER, 1).unwrap();
    let left: Vec<String> = std::fs::read_dir(&keys)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec![format!("{other}.bin")]);
}

#[test]
fn restore_lifts_the_tombstone_but_trusts_nothing_by_itself() {
    let d = device();
    remove_local(&d, &OWN, &PEER, 1).unwrap();
    assert!(!restore(&d, &STRANGER, 2).unwrap(), "was not removed");
    assert!(restore(&d, &PEER, 3).unwrap());
    assert!(!restore(&d, &PEER, 4).unwrap(), "already restored");
    assert!(!load_removed(&d).unwrap().is_removed(&PEER));
    // Not listed any more: a person has to pair or trust it again.
    assert!(!listed(&d, &PEER));
    trust(&d, PEER, "peer-again", Role::Peer);
    assert!(listed(&d, &PEER));
    // The tombstone history stays in the file.
    assert_eq!(load_removed(&d).unwrap().records().len(), 2);
}

#[test]
fn restore_also_drops_a_stale_listing_so_it_never_trusts_by_itself() {
    let d = device();
    let stale = std::fs::read(d.join(store::TRUST_FILE)).unwrap();
    remove_local(&d, &OWN, &PEER, 1).unwrap();
    // A backup of the old list comes back, with the key in it again.
    write_private_file(&d.join(store::TRUST_FILE), &stale).unwrap();
    assert!(restore(&d, &PEER, 2).unwrap());
    assert!(!listed(&d, &PEER), "the stale listing is gone");
    assert!(
        listed(&d, &OP) && listed(&d, &A1),
        "the others are untouched"
    );
}

#[test]
fn restore_does_not_reapply_old_entries_but_a_new_entry_removes_again() {
    let d = device();
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, PEER), 10).unwrap(),
        Applied::Removed
    );
    restore(&d, &PEER, 11).unwrap();
    trust(&d, PEER, "peer", Role::Peer);
    // The same entry again (same admin, log and seq): known, not applied.
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, PEER), 12).unwrap(),
        Applied::Known
    );
    assert!(listed(&d, &PEER));
    // A new entry from the same admin removes it again.
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 2, PEER), 13).unwrap(),
        Applied::Removed
    );
    assert!(!listed(&d, &PEER));
    // A different admin's entry is also new.
    restore(&d, &PEER, 14).unwrap();
    trust(&d, PEER, "peer", Role::Peer);
    assert_eq!(
        apply_entry(&d, &OWN, &A2, &entry(7, 1, PEER), 15).unwrap(),
        Applied::Removed
    );
    // A new log id from the same admin (a reinstalled admin) is new too.
    restore(&d, &PEER, 16).unwrap();
    trust(&d, PEER, "peer", Role::Peer);
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(8, 1, PEER), 17).unwrap(),
        Applied::Removed
    );
}

#[test]
fn only_a_current_admin_may_send_entries() {
    let d = device();
    for sender in [OP, PEER, STRANGER] {
        assert_eq!(
            apply_entry(&d, &OWN, &sender, &entry(7, 1, A1), 1).unwrap(),
            Applied::NotAdmin
        );
    }
    // Nothing changed.
    assert!(listed(&d, &A1));
    assert!(!d.join(REMOVED_FILE).exists());
    // A removed admin is not an admin.
    remove_local(&d, &OWN, &A2, 2).unwrap();
    assert_eq!(
        apply_entry(&d, &OWN, &A2, &entry(7, 1, PEER), 3).unwrap(),
        Applied::NotAdmin
    );
    assert!(listed(&d, &PEER));
}

#[test]
fn entries_for_our_own_key_or_by_an_admin_about_itself_are_ignored() {
    let d = device();
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, OWN), 1).unwrap(),
        Applied::OwnKey
    );
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 2, A1), 2).unwrap(),
        Applied::SelfRevoke
    );
    assert!(listed(&d, &A1));
    assert!(!load_removed(&d).unwrap().is_removed(&OWN));
    // Both still count as dealt with for the sync number.
    on_head(&d, &fingerprint(&A1), &[7; 4], 2).unwrap();
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, OWN), 3).unwrap(),
        Applied::OwnKey
    );
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 2, A1), 4).unwrap(),
        Applied::SelfRevoke
    );
    assert_eq!(
        sync_state(&d, &fingerprint(&A1)).unwrap(),
        Some(([7; 4], 2))
    );
}

#[test]
fn small_order_targets_are_refused() {
    let d = device();
    assert!(apply_entry(&d, &OWN, &A1, &entry(7, 1, [0; 32]), 1).is_err());
    assert!(!d.join(REMOVED_FILE).exists());
}

#[test]
fn removing_an_admin_takes_two_different_admins() {
    let d = device();
    trust(&d, A3, "admin-3", Role::Admin);
    // One admin is not enough, however often it asks.
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, A3), 1).unwrap(),
        Applied::Voted
    );
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 2, A3), 2).unwrap(),
        Applied::Voted
    );
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, A3), 3).unwrap(),
        Applied::Voted
    );
    assert!(listed(&d, &A3));
    let votes = std::fs::read_to_string(d.join(VOTES_FILE)).unwrap();
    assert_eq!(votes.lines().count(), 1, "a single vote per admin: {votes}");
    // A second admin finishes it.
    assert_eq!(
        apply_entry(&d, &OWN, &A2, &entry(9, 1, A3), 4).unwrap(),
        Applied::Removed
    );
    assert!(!listed(&d, &A3));
    // The votes are gone with it.
    assert_eq!(std::fs::read_to_string(d.join(VOTES_FILE)).unwrap(), "");
    // The tombstone names the entry that completed it.
    let rec = load_removed(&d).unwrap().records().last().unwrap().clone();
    assert_eq!(
        rec.kind,
        RecordKind::Removed(Source::Admin {
            fingerprint: fingerprint(&A2),
            log_id: [9; 4],
            seq: 1
        })
    );
}

#[test]
fn the_two_admin_rule_depends_on_the_role_on_the_receiving_device() {
    // This device lists A3 as admin: two votes. Another lists it as a peer: one.
    let two = device();
    trust(&two, A3, "a3", Role::Admin);
    let one = device();
    trust(&one, A3, "a3", Role::Peer);
    assert_eq!(
        apply_entry(&two, &OWN, &A1, &entry(7, 1, A3), 1).unwrap(),
        Applied::Voted
    );
    assert_eq!(
        apply_entry(&one, &OWN, &A1, &entry(7, 1, A3), 1).unwrap(),
        Applied::Removed
    );
}

#[test]
fn a_removed_admins_votes_are_dropped() {
    let d = device();
    trust(&d, A3, "admin-3", Role::Admin);
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, A3), 1).unwrap(),
        Applied::Voted
    );
    // A1 is the stolen one: removed by hand here. Its vote must not count.
    remove_local(&d, &OWN, &A1, 2).unwrap();
    assert_eq!(std::fs::read_to_string(d.join(VOTES_FILE)).unwrap(), "");
    assert_eq!(
        apply_entry(&d, &OWN, &A2, &entry(7, 1, A3), 3).unwrap(),
        Applied::Voted,
        "A2 alone is one vote"
    );
    assert!(listed(&d, &A3));
    // The removed admin can't add another.
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 5, A3), 4).unwrap(),
        Applied::NotAdmin
    );
    assert!(listed(&d, &A3));
}

#[test]
fn a_vote_from_an_admin_demoted_by_hand_is_dropped_when_the_next_vote_arrives() {
    let d = device();
    trust(&d, A3, "admin-3", Role::Admin);
    apply_entry(&d, &OWN, &A1, &entry(7, 1, A3), 1).unwrap();
    // A person at this device turns A1 into a plain peer.
    trust(&d, A1, "admin-1", Role::Peer);
    assert_eq!(
        apply_entry(&d, &OWN, &A2, &entry(7, 1, A3), 2).unwrap(),
        Applied::Voted
    );
    assert!(listed(&d, &A3));
}

#[test]
fn the_target_cannot_vote_for_itself_and_our_own_key_is_never_a_vote() {
    let d = device();
    trust(&d, A3, "admin-3", Role::Admin);
    // A3 sends an entry naming A1 (ordinary), then one about itself: ignored.
    assert_eq!(
        apply_entry(&d, &OWN, &A3, &entry(7, 1, A3), 1).unwrap(),
        Applied::SelfRevoke
    );
    assert!(!d.join(VOTES_FILE).exists());
    // Votes against A3 from A3's own fingerprint can't exist; and a vote file
    // line naming our own fingerprint does not count either.
    let line = format!(
        "{} {} {} 1\n",
        key_to_text(&A3),
        fingerprint(&OWN),
        log_id_text(&[7; 4])
    );
    write_private_file(&d.join(VOTES_FILE), line.as_bytes()).unwrap();
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(7, 1, A3), 2).unwrap(),
        Applied::Voted
    );
}

#[test]
fn union_in_any_order_and_the_held_number_catches_up() {
    let d = device();
    let a1 = fingerprint(&A1);
    assert_eq!(on_head(&d, &a1, &[7; 4], 4).unwrap(), 0);
    let targets = [[51u8; 32], [52; 32], [53; 32], [54; 32]];
    // Entries 3 and 4 arrive first, then 2, then 1.
    for seq in [3u32, 4, 2] {
        apply_entry(&d, &OWN, &A1, &entry(7, seq, targets[seq as usize - 1]), 1).unwrap();
        assert_eq!(
            sync_state(&d, &a1).unwrap(),
            Some(([7; 4], 0)),
            "after {seq}"
        );
    }
    // They were all applied anyway: removal is a union.
    for seq in [2usize, 3, 4] {
        assert!(load_removed(&d).unwrap().is_removed(&targets[seq - 1]));
    }
    assert!(!load_removed(&d).unwrap().is_removed(&targets[0]));
    apply_entry(&d, &OWN, &A1, &entry(7, 1, targets[0]), 1).unwrap();
    assert_eq!(sync_state(&d, &a1).unwrap(), Some(([7; 4], 4)));
    // Resent entries change nothing.
    for seq in 1..=4u32 {
        assert_eq!(
            apply_entry(&d, &OWN, &A1, &entry(7, seq, targets[seq as usize - 1]), 9).unwrap(),
            Applied::Known
        );
    }
    assert_eq!(sync_state(&d, &a1).unwrap(), Some(([7; 4], 4)));
    assert_eq!(load_removed(&d).unwrap().records().len(), 4);
}

#[test]
fn heads_answer_what_we_hold_and_reset_on_a_new_log_or_a_lower_head() {
    let d = device();
    let a1 = fingerprint(&A1);
    assert_eq!(on_head(&d, &a1, &[7; 4], 3).unwrap(), 0, "nothing held yet");
    for seq in 1..=3u32 {
        apply_entry(&d, &OWN, &A1, &entry(7, seq, [60 + seq as u8; 32]), 1).unwrap();
    }
    assert_eq!(on_head(&d, &a1, &[7; 4], 3).unwrap(), 3, "in step");
    assert_eq!(on_head(&d, &a1, &[7; 4], 5).unwrap(), 3, "admin is ahead");
    // The admin was reinstalled: a new log id. Take the whole log again.
    assert_eq!(on_head(&d, &a1, &[8; 4], 3).unwrap(), 0);
    assert_eq!(sync_state(&d, &a1).unwrap(), Some(([8; 4], 0)));
    // Its entries (same seqs, new id) are new entries; nothing was undone.
    for seq in 1..=3u32 {
        assert!(load_removed(&d).unwrap().is_removed(&[60 + seq as u8; 32]));
    }
    // A head below what we hold (an old backup of the admin): start over.
    apply_entry(&d, &OWN, &A1, &entry(8, 1, [70; 32]), 1).unwrap();
    apply_entry(&d, &OWN, &A1, &entry(8, 2, [71; 32]), 1).unwrap();
    assert_eq!(on_head(&d, &a1, &[8; 4], 2).unwrap(), 2);
    assert_eq!(on_head(&d, &a1, &[8; 4], 1).unwrap(), 0);
    // Different admins keep separate state.
    assert_eq!(on_head(&d, &fingerprint(&A2), &[8; 4], 1).unwrap(), 0);
    assert_eq!(
        sync_state(&d, &fingerprint(&A2)).unwrap(),
        Some(([8; 4], 0))
    );
}

#[test]
fn an_entry_with_a_different_log_id_than_the_synced_one_applies_but_does_not_advance() {
    let d = device();
    let a1 = fingerprint(&A1);
    on_head(&d, &a1, &[7; 4], 1).unwrap();
    apply_entry(&d, &OWN, &A1, &entry(9, 1, [80; 32]), 1).unwrap();
    assert!(load_removed(&d).unwrap().is_removed(&[80; 32]));
    assert_eq!(sync_state(&d, &a1).unwrap(), Some(([7; 4], 0)));
    // And without any head at all there is no state to move.
    let d = device();
    apply_entry(&d, &OWN, &A1, &entry(9, 1, [80; 32]), 1).unwrap();
    assert_eq!(sync_state(&d, &a1).unwrap(), None);
}

#[test]
fn revoke_keeps_a_numbered_log_and_removes_locally() {
    let d = device();
    let r = revoke(&d, &OWN, &PEER, 100).unwrap();
    assert_eq!((r.seq, r.was_in_log), (1, false));
    assert!(!listed(&d, &PEER));
    let log = load_log(&d).unwrap().unwrap();
    assert_eq!(log.id, r.log_id);
    assert_eq!(log.entries.len(), 1);
    assert_eq!(log.entry(1).unwrap().key, PEER);
    let r2 = revoke(&d, &OWN, &OP, 101).unwrap();
    assert_eq!((r2.seq, r2.log_id), (2, r.log_id), "same log, next number");
    // The same key again: no new entry.
    let r3 = revoke(&d, &OWN, &PEER, 102).unwrap();
    assert_eq!((r3.seq, r3.was_in_log), (1, true));
    let log = load_log(&d).unwrap().unwrap();
    assert_eq!((log.highest(), log.entries.len()), (2, 2));
    assert!(log.entry(0).is_none() && log.entry(3).is_none());
    // An admin can't revoke itself, nor a bad key.
    assert!(revoke(&d, &OWN, &OWN, 1).is_err());
    assert!(revoke(&d, &OWN, &[0; 32], 1).is_err());
    // Another log id for another device.
    let other = device();
    assert_ne!(revoke(&other, &OWN, &PEER, 1).unwrap().log_id, r.log_id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.join(LOG_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn revoking_a_key_that_is_already_removed_still_reaches_the_log() {
    let d = device();
    remove_local(&d, &OWN, &PEER, 1).unwrap();
    let r = revoke(&d, &OWN, &PEER, 2).unwrap();
    assert!(r.outcome.already_removed);
    assert_eq!(load_log(&d).unwrap().unwrap().entries.len(), 1);
}

#[test]
fn hostile_files_are_errors_never_skipped() {
    let d = tempdir("removal-hostile");
    let k = key_to_text(&PEER);
    let fp = fingerprint(&A1);
    for bad in [
        format!("{k} removed\n"),
        format!("{k} banned local 5\n"),
        format!("{k} restored {fp}:{}:1 5\n", log_id_text(&[1; 4])),
        format!("{k} removed local +5\n"),
        format!("{k} removed local -5\n"),
        format!("{k} removed local 5 extra\n"),
        format!("{k} removed nobody:00000000:1 5\n"),
        format!("{k} removed {fp}:0000000:1 5\n"),
        format!("{k} removed {fp}:00000000:99999999999 5\n"),
        "nonsense local\n".to_string(),
        format!("{k}  removed local 5\n"),
    ] {
        write_private_file(&d.join(REMOVED_FILE), bad.as_bytes()).unwrap();
        assert!(load_removed(&d).is_err(), "{bad:?}");
        // A damaged `removed` stops loading the trust list too.
        assert!(store::load(&d).is_err(), "{bad:?}");
    }
    let good = format!(
        "{k} removed local 5\n{k} restored local 6\n{k} removed {fp}:{}:3 7\n",
        log_id_text(&[1, 2, 3, 4])
    );
    write_private_file(&d.join(REMOVED_FILE), good.as_bytes()).unwrap();
    let r = load_removed(&d).unwrap();
    assert!(r.is_removed(&PEER));
    assert!(r.knows_entry(&PEER, &fp, &[1, 2, 3, 4], 3));
    assert!(!r.knows_entry(&PEER, &fp, &[1, 2, 3, 4], 4));
    assert_eq!(r.removed_keys(), vec![PEER]);
    // Log files: gaps, repeats and bad ids are errors.
    for bad in [
        "",
        "zz\n",
        "0102030\n",
        "01020304\n2 AAAA 5\n",
        &format!("01020304\n1 {k} 5\n1 {k} 6\n"),
        &format!("01020304\n1 {k}\n"),
        &format!("01020304\n0 {k} 5\n"),
    ] {
        write_private_file(&d.join(LOG_FILE), bad.as_bytes()).unwrap();
        assert!(load_log(&d).is_err(), "{bad:?}");
    }
    write_private_file(&d.join(SYNC_DIR).join(&fp), b"01020304\n").unwrap();
    assert!(sync_state(&d, &fp).is_err());
    write_private_file(&d.join(VOTES_FILE), b"junk\n").unwrap();
    assert!(read_votes(&d).is_err());
}

#[test]
fn many_threads_removing_and_adding_lose_nothing() {
    let d = tempdir("removal-threads");
    std::thread::scope(|s| {
        for t in 0..6u8 {
            let d = &d;
            s.spawn(move || {
                for i in 0..10u8 {
                    let key = [100 + t * 10 + i; 32];
                    store::add(
                        d,
                        &Peer {
                            public: key,
                            name: format!("p-{t}-{i}"),
                            role: Role::Peer,
                        },
                    )
                    .unwrap();
                    if i % 2 == 0 {
                        remove_local(d, &OWN, &key, 1).unwrap();
                    }
                }
            });
        }
    });
    // 60 added, every even one removed: 30 left, 30 tombstones, nothing lost.
    assert_eq!(store::load(&d).unwrap().len(), 30);
    assert_eq!(load_removed(&d).unwrap().removed_keys().len(), 30);
}

fn fresh_key(i: u32) -> [u8; 32] {
    let mut k = [0x55u8; 32];
    k[..4].copy_from_slice(&i.to_be_bytes());
    k[31] = 0x40;
    k
}

/// Write tombstones straight into the removed file (fast set-up for caps).
fn seed_removed(d: &Path, recs: impl Iterator<Item = Record>) {
    use std::os::unix::fs::PermissionsExt;
    let path = d.join(REMOVED_FILE);
    let mut bytes = std::fs::read(&path).unwrap_or_default();
    for r in recs {
        bytes.extend_from_slice(r.to_line().as_bytes());
    }
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn one_admin_cannot_fill_the_removed_file() {
    let d = device();
    let fp = fingerprint(&A1);
    let n = MAX_ENTRIES_PER_ADMIN as u32;
    seed_removed(
        &d,
        (1..n - 2).map(|i| Record {
            key: fresh_key(i),
            kind: RecordKind::Removed(Source::Admin {
                fingerprint: fp.clone(),
                log_id: [9; 4],
                seq: i,
            }),
            time: 1,
        }),
    );
    let mut results = Vec::new();
    for i in n - 2..n + 3 {
        results.push(apply_entry(&d, &OWN, &A1, &entry(9, i, fresh_key(i)), 5).unwrap());
    }
    assert_eq!(
        results.iter().filter(|r| **r == Applied::Removed).count(),
        3,
        "{results:?}"
    );
    assert!(results[3..].iter().all(|r| *r == Applied::Limit));
    // The refused entries are not on record and sync did not advance past them.
    assert!(!load_removed(&d).unwrap().is_removed(&fresh_key(n + 2)));
    assert!(store::load(&d).is_ok());
    // The other admin is unaffected, and an entry already held is still Known.
    assert_eq!(
        apply_entry(&d, &OWN, &A2, &entry(8, 1, PEER), 5).unwrap(),
        Applied::Removed
    );
    assert_eq!(
        apply_entry(&d, &OWN, &A1, &entry(9, 1, fresh_key(1)), 5).unwrap(),
        Applied::Known
    );
    // No new removals while the caller's budget is spent.
    assert_eq!(
        apply_entry_limited(&d, &OWN, &A2, &entry(8, 2, OP), 5, false).unwrap(),
        Applied::Limit
    );
}

#[test]
fn a_removed_file_over_one_mib_still_loads_and_appends() {
    let d = device();
    seed_removed(
        &d,
        (1..=20000u32).map(|i| Record {
            key: fresh_key(i),
            kind: RecordKind::Removed(Source::Local),
            time: 1,
        }),
    );
    assert!(std::fs::metadata(d.join(REMOVED_FILE)).unwrap().len() > 1 << 20);
    let r = load_removed(&d).unwrap();
    assert!(r.is_removed(&fresh_key(1)) && r.is_removed(&fresh_key(20000)));
    assert!(store::load(&d).is_ok());
    remove_local(&d, &OWN, &PEER, 9).unwrap();
    assert!(load_removed(&d).unwrap().is_removed(&PEER));
}
