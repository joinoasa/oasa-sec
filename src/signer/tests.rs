//! The signer against a simulated autopilot in virtual time.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use mavlink::dialects::common::{
    COMMAND_ACK_DATA, HEARTBEAT_DATA, MavAutopilot, MavCmd, MavModeFlag, MavResult, MavState,
    MavType,
};

use super::*;
use crate::files::tempdir;
use crate::rotation;
use crate::signing::AUTOPILOT_KEY_FILE;

const SYS: u8 = 1;
const COMP: u8 = 1;

fn cfg() -> Config {
    Config {
        sys: SYS,
        comp: COMP,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Sent {
    Setup {
        signed_with: Option<[u8; 32]>,
        initial: u64,
        key: [u8; 32],
    },
    Request {
        signed_with: Option<[u8; 32]>,
    },
}

struct Frame {
    at: Duration,
    msg: MavMessage,
    /// The key the frame is signed with, and its timestamp.
    signed: Option<([u8; 32], u64)>,
}

/// The autopilot. Signing rules as PX4 and ArduPilot have them: keyless, it
/// takes a first `SETUP_SIGNING`; keyed, it wants everything signed.
#[derive(Default)]
struct Ap {
    t: Duration,
    key: Option<[u8; 32]>,
    armed: bool,
    /// It signs its own frames once keyed (ArduPilot does).
    sign_own: bool,
    /// No frames at all, and no answers.
    silent: bool,
    /// Go silent as soon as a `SETUP_SIGNING` was applied.
    mute_after_setup: bool,
    /// Throw away this many answers.
    drop_acks: u32,
    /// Ignore a `SETUP_SIGNING` (keeps the old key) without saying so.
    ignore_setup: bool,
    /// Ignore signed commands until this time (a reboot).
    deaf_until: Duration,
    /// The signer's port fails on this send (power loss).
    crash_at_send: Option<usize>,
    sends: Vec<Sent>,
    send_count: usize,
    queue: VecDeque<Frame>,
    next_hb: Duration,
    hb_ts: u64,
    /// After a `SETUP_SIGNING` is applied it ignores signed commands this long.
    deaf_after_setup: Duration,
    /// Called when a `SETUP_SIGNING` is applied.
    on_setup: Option<Box<dyn FnMut()>>,
}

#[derive(Clone)]
struct FakePort(Rc<RefCell<Ap>>);

fn heartbeat(armed: bool) -> MavMessage {
    MavMessage::HEARTBEAT(HEARTBEAT_DATA {
        custom_mode: 0,
        mavtype: MavType::MAV_TYPE_QUADROTOR,
        autopilot: MavAutopilot::MAV_AUTOPILOT_PX4,
        base_mode: if armed {
            MavModeFlag::MAV_MODE_FLAG_SAFETY_ARMED
        } else {
            MavModeFlag::empty()
        },
        system_status: MavState::MAV_STATE_STANDBY,
        mavlink_version: 3,
    })
}

impl Port for FakePort {
    fn now(&mut self) -> Duration {
        self.0.borrow().t
    }

    fn send(&mut self, key: Option<&SigningKey>, msg: &MavMessage, _min_ts: u64) -> Result<u64> {
        let mut ap = self.0.borrow_mut();
        ap.send_count += 1;
        if ap.crash_at_send == Some(ap.send_count) {
            return Err(Error::Link("power loss"));
        }
        let signed_with = key.map(|k| *k.as_bytes());
        let ok = ap.key.is_none() || signed_with == ap.key;
        match msg {
            MavMessage::SETUP_SIGNING(s) => {
                ap.sends.push(Sent::Setup {
                    signed_with,
                    initial: s.initial_timestamp,
                    key: s.secret_key,
                });
                if ok && !ap.armed && !ap.silent && !ap.ignore_setup {
                    ap.key = Some(s.secret_key);
                    ap.deaf_until = ap.t + ap.deaf_after_setup;
                    if let Some(mut f) = ap.on_setup.take() {
                        f();
                    }
                    if ap.mute_after_setup {
                        ap.silent = true;
                    }
                }
            }
            MavMessage::COMMAND_LONG(c) if c.command == MavCmd::MAV_CMD_REQUEST_MESSAGE => {
                ap.sends.push(Sent::Request { signed_with });
                let deaf = ap.t < ap.deaf_until && ap.key.is_some();
                if ok && !ap.silent && !deaf {
                    if ap.drop_acks > 0 {
                        ap.drop_acks -= 1;
                    } else {
                        let at = ap.t + Duration::from_millis(50);
                        let signed = ap.key.map(|k| (k, 5_000));
                        ap.queue.push_back(Frame {
                            at,
                            msg: MavMessage::COMMAND_ACK(COMMAND_ACK_DATA {
                                command: MavCmd::MAV_CMD_REQUEST_MESSAGE,
                                result: MavResult::MAV_RESULT_ACCEPTED,
                            }),
                            signed,
                        });
                    }
                }
            }
            _ => {}
        }
        Ok(if key.is_some() { 7 } else { 0 })
    }

    fn recv(&mut self, wait: Duration, keys: &[&SigningKey]) -> Result<Option<Inbound>> {
        let mut ap = self.0.borrow_mut();
        let until = ap.t + wait;
        if ap.silent {
            ap.t = until;
            return Ok(None);
        }
        let hb_due = ap.next_hb;
        let q_due = ap.queue.front().map(|f| f.at);
        let next = q_due.map_or(hb_due, |q| q.min(hb_due));
        if next > until {
            ap.t = until;
            return Ok(None);
        }
        ap.t = ap.t.max(next);
        let frame = if q_due == Some(next) {
            ap.queue.pop_front().unwrap()
        } else {
            ap.next_hb = ap.t + Duration::from_secs(1);
            let ts = ap.hb_ts;
            Frame {
                at: ap.t,
                msg: heartbeat(ap.armed),
                signed: ap.sign_own.then_some(()).and(ap.key).map(|k| (k, ts)),
            }
        };
        let sig = frame.signed.map(|(k, ts)| Sig {
            timestamp: ts,
            verified_by: keys.iter().position(|c| *c.as_bytes() == k),
        });
        Ok(Some(Inbound {
            header: MavHeader {
                system_id: SYS,
                component_id: COMP,
                sequence: 0,
            },
            msg: frame.msg,
            sig,
        }))
    }
}

struct Rig {
    dir: PathBuf,
    ap: Rc<RefCell<Ap>>,
    old: SigningKey,
    signer: Signer<FakePort>,
}

fn rig(tag: &str) -> Rig {
    let dir = tempdir(tag);
    let old = SigningKey::generate().unwrap();
    old.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    let ap = Rc::new(RefCell::new(Ap {
        key: Some(*old.as_bytes()),
        ..Ap::default()
    }));
    let signer = Signer::new(&dir, FakePort(ap.clone()), cfg());
    Rig {
        dir,
        ap,
        old,
        signer,
    }
}

impl Rig {
    fn want(&self) {
        rotation::request(&self.dir, "requested", "-", 1000).unwrap();
    }

    /// Run ticks until nothing happens for a while; collect the events.
    fn run(&mut self, ticks: usize) -> Vec<Event> {
        let mut all = Vec::new();
        for _ in 0..ticks {
            all.extend(self.signer.tick().unwrap());
        }
        all
    }

    fn restart(&mut self) {
        self.signer = Signer::new(&self.dir, FakePort(self.ap.clone()), cfg());
    }

    fn keys(&self) -> rotation::DroneKeys {
        rotation::load_drone_keys(&self.dir).unwrap().unwrap()
    }

    fn files(&self, name: &str) -> bool {
        self.dir.join(name).exists()
    }
}

#[test]
fn a_rotation_issues_a_generation_proves_the_key_and_commits() {
    let mut r = rig("sg-happy");
    r.want();
    let ev = r.run(3);
    assert_eq!(ev, vec![Event::Issued(1), Event::Rotated(1)]);
    let keys = r.keys();
    assert_eq!(Some(*keys.current.as_bytes()), r.ap.borrow().key);
    assert_ne!(keys.current, r.old);
    assert_eq!((keys.current_gen, keys.highest), (1, 1));
    assert!(keys.next.is_none());
    assert!(!r.files(rotation::NEXT_KEY_FILE));
    assert!(!r.files(rotation::PENDING_FILE), "request cleared");
    // SETUP_SIGNING was signed with the OLD key and carried the new one.
    let ap = r.ap.borrow();
    match &ap.sends[0] {
        Sent::Setup {
            signed_with, key, ..
        } => {
            assert_eq!(*signed_with, Some(*r.old.as_bytes()));
            assert_eq!(key, keys.current.as_bytes());
        }
        other => panic!("{other:?}"),
    }
    // The proof was signed with the new key.
    assert!(ap.sends[1..].iter().all(|s| matches!(s,
        Sent::Request { signed_with } if *signed_with == Some(*keys.current.as_bytes()))));
}

#[test]
fn nothing_happens_without_a_request() {
    let mut r = rig("sg-idle");
    assert!(r.run(5).is_empty());
    assert!(r.ap.borrow().sends.is_empty());
}

#[test]
fn an_armed_autopilot_is_left_alone_until_it_is_disarmed() {
    let mut r = rig("sg-armed");
    r.want();
    r.ap.borrow_mut().armed = true;
    let ev = r.run(15);
    assert_eq!(ev, vec![Event::WaitingArmed], "said once, not every second");
    assert!(r.ap.borrow().sends.is_empty(), "nothing sent while armed");
    assert!(!r.files(rotation::NEXT_KEY_FILE) && !r.files(rotation::HIGHEST_GEN_FILE));
    r.ap.borrow_mut().armed = false;
    let ev = r.run(3);
    assert_eq!(ev, vec![Event::Issued(1), Event::Rotated(1)]);
}

#[test]
fn without_a_heartbeat_it_does_not_assume_disarmed() {
    let mut r = rig("sg-nohb");
    r.want();
    r.ap.borrow_mut().silent = true;
    assert_eq!(r.run(15), vec![Event::WaitingHeartbeat]);
    assert!(r.ap.borrow().sends.is_empty());
}

#[test]
fn arming_during_the_change_is_refused_and_rolled_back_with_a_new_generation_next_time() {
    let mut r = rig("sg-refused");
    r.want();
    // It arms between the heartbeat and the key change: SETUP is refused.
    r.ap.borrow_mut().ignore_setup = true;
    let ev = r.run(3);
    assert_eq!(ev, vec![Event::Issued(1), Event::RolledBack(1)]);
    assert_eq!(r.keys().current, r.old, "the old key is still the key");
    assert!(!r.files(rotation::NEXT_KEY_FILE));
    assert!(r.files(rotation::PENDING_FILE), "the request stays");
    assert_eq!(r.keys().highest, 1);
    // Right away it does not try again (it waits), then it does, with 2.
    r.ap.borrow_mut().ignore_setup = false;
    assert!(r.run(10).is_empty());
    let ev = r.run(40);
    assert_eq!(ev, vec![Event::Issued(2), Event::Rotated(2)]);
    assert_eq!(r.keys().highest, 2);
}

#[test]
fn a_lost_ack_is_recovered_by_probing() {
    let mut r = rig("sg-lostack");
    r.want();
    // The autopilot takes the key, but five answers get lost (the whole
    // proof window), and one more at the start of the probe.
    r.ap.borrow_mut().drop_acks = 6;
    let ev = r.run(3);
    assert_eq!(ev, vec![Event::Issued(1), Event::Rotated(1)]);
    assert_eq!(Some(*r.keys().current.as_bytes()), r.ap.borrow().key);
    assert!(!r.files(rotation::NEXT_KEY_FILE));
}

#[test]
fn a_reboot_window_is_waited_out_by_the_probe() {
    let mut r = rig("sg-reboot");
    r.want();
    // After applying the key the autopilot ignores signed commands for 60 s.
    r.ap.borrow_mut().deaf_after_setup = Duration::from_secs(60);
    let ev = r.run(3);
    assert_eq!(ev, vec![Event::Issued(1), Event::Rotated(1)]);
    assert!(r.ap.borrow().t >= Duration::from_secs(60));
}

#[test]
fn a_silent_autopilot_leaves_both_keys_and_reports_stuck_until_asked_again() {
    let mut r = rig("sg-stuck");
    r.want();
    r.ap.borrow_mut().mute_after_setup = true;
    let ev = r.run(2);
    assert_eq!(ev, vec![Event::Issued(1), Event::Stuck]);
    let keys = r.keys();
    assert_eq!(keys.current, r.old, "never deleted or replaced");
    assert!(keys.next.is_some(), "and the new one is kept too");
    // Nothing changes while it stays silent and nobody asks.
    r.ap.borrow_mut().silent = false;
    assert!(r.run(5).is_empty());
    // Asked again: it looks, and the autopilot has the new key.
    rotation::request(&r.dir, "requested", "-", 1000).unwrap();
    let ev = r.run(2);
    assert_eq!(ev, vec![Event::Rotated(1)]);
    assert!(!r.files(rotation::PENDING_FILE));
}

#[test]
fn a_restart_while_a_new_key_is_pending_works_out_which_key_is_in_use() {
    // Power lost after SETUP_SIGNING, before the proof: the autopilot has the
    // new key.
    let mut r = rig("sg-power-new");
    r.want();
    r.ap.borrow_mut().crash_at_send = Some(2);
    assert!(r.signer.tick().is_err());
    assert!(r.files(rotation::NEXT_KEY_FILE));
    r.restart();
    let ev = r.run(2);
    assert_eq!(ev, vec![Event::Rotated(1)]);
    assert_eq!(Some(*r.keys().current.as_bytes()), r.ap.borrow().key);

    // Power lost before SETUP_SIGNING got there: the autopilot kept the old key.
    let mut r = rig("sg-power-old");
    r.want();
    r.ap.borrow_mut().ignore_setup = true;
    r.ap.borrow_mut().crash_at_send = Some(2);
    assert!(r.signer.tick().is_err());
    r.restart();
    let ev = r.run(2);
    assert_eq!(ev, vec![Event::RolledBack(1)]);
    assert_eq!(r.keys().current, r.old);
    assert!(r.files(rotation::PENDING_FILE));
}

#[test]
fn a_keyed_autopilot_that_signs_its_frames_settles_it_by_listening() {
    let mut r = rig("sg-listen");
    r.want();
    r.ap.borrow_mut().sign_own = true;
    r.ap.borrow_mut().crash_at_send = Some(2);
    assert!(r.signer.tick().is_err());
    r.restart();
    let sent = r.ap.borrow().sends.len();
    let ev = r.run(2);
    assert_eq!(ev, vec![Event::Rotated(1)]);
    assert_eq!(
        r.ap.borrow().sends.len(),
        sent,
        "it asked nothing: it listened"
    );

    // Same for the old key.
    let mut r = rig("sg-listen-old");
    r.want();
    {
        let mut a = r.ap.borrow_mut();
        a.sign_own = true;
        a.ignore_setup = true;
        a.crash_at_send = Some(2);
    }
    assert!(r.signer.tick().is_err());
    r.restart();
    let sent = r.ap.borrow().sends.len();
    assert_eq!(r.run(2), vec![Event::RolledBack(1)]);
    assert_eq!(r.ap.borrow().sends.len(), sent);
}

#[test]
fn generations_are_never_reused_across_failures() {
    let mut r = rig("sg-gens");
    r.want();
    let mut seen = Vec::new();
    let mut collect = |ev: Vec<Event>| {
        for e in ev {
            if let Event::Issued(g) = e {
                seen.push(g);
            }
        }
    };
    // Several refused tries, then one that works.
    r.ap.borrow_mut().ignore_setup = true;
    collect(r.run(100));
    r.ap.borrow_mut().ignore_setup = false;
    collect(r.run(100));
    assert!(seen.len() >= 3, "{seen:?}");
    let n = seen.len() as u32;
    assert_eq!(
        seen,
        (1..=n).collect::<Vec<_>>(),
        "each number once, in order"
    );
    let k = r.keys();
    assert_eq!((k.current_gen, k.highest), (n, n));
    // A crash after the number was saved but before the key: the number is burnt.
    std::fs::write(r.dir.join(rotation::HIGHEST_GEN_FILE), b"9\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            r.dir.join(rotation::HIGHEST_GEN_FILE),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    r.want();
    r.ap.borrow_mut().ignore_setup = false;
    let ev = r.run(60);
    assert!(ev.contains(&Event::Issued(10)), "{ev:?}");
}

#[test]
fn a_request_that_arrives_during_a_rotation_gets_its_own_rotation() {
    let mut r = rig("sg-midreq");
    r.want();
    let dir = r.dir.clone();
    r.ap.borrow_mut().on_setup = Some(Box::new(move || {
        // An operator is removed while the key is being changed. It may have
        // been sent the new key, so this rotation does not answer it.
        rotation::request(
            &dir,
            "operator-removed",
            "AAAA-BBBB-CCCC-DDDD",
            2_000_000_000,
        )
        .unwrap();
    }));
    let ev = r.run(1);
    assert_eq!(ev, vec![Event::Issued(1), Event::Rotated(1)]);
    assert_eq!(rotation::pending_lines(&r.dir).unwrap(), 1);
    let ev = r.run(1);
    assert_eq!(ev, vec![Event::Issued(2), Event::Rotated(2)]);
    assert!(!r.files(rotation::PENDING_FILE));
}

#[test]
fn the_initial_timestamp_is_above_everything_seen() {
    let mut r = rig("sg-ts");
    r.want();
    let far = crate::signing::mavlink_timestamp_now() + 50_000_000_000;
    {
        let mut a = r.ap.borrow_mut();
        a.sign_own = true;
        a.hb_ts = far;
    }
    // The autopilot signs its heartbeats under the key in use, which is the
    // current one; the signer reads their timestamps while it watches.
    r.run(3);
    let ap = r.ap.borrow();
    let Sent::Setup { initial, .. } = ap.sends[0] else {
        panic!()
    };
    assert!(initial > far, "{initial} must be above {far}");
    drop(ap);
    // And a floor left by oasa-link (timestamps seen through the tunnel) counts.
    let mut r = rig("sg-ts2");
    r.want();
    let floor = crate::signing::mavlink_timestamp_now() + 90_000_000_000;
    rotation::write_seen_ts(&r.dir, floor).unwrap();
    r.run(3);
    let Sent::Setup { initial, .. } = r.ap.borrow().sends[0] else {
        panic!()
    };
    assert!(initial > floor);
}

#[test]
fn a_folder_without_an_autopilot_key_is_not_a_drone() {
    let dir = tempdir("sg-nodrone");
    let ap = Rc::new(RefCell::new(Ap::default()));
    let mut s = Signer::new(&dir, FakePort(ap), cfg());
    assert!(s.tick().is_err());
}

#[test]
fn a_pending_key_with_no_saved_generation_is_not_guessed() {
    let r = rig("sg-nogen");
    SigningKey::generate()
        .unwrap()
        .save(&r.dir.join(rotation::NEXT_KEY_FILE))
        .unwrap();
    assert!(rotation::load_drone_keys(&r.dir).is_err());
}
