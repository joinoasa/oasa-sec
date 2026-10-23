//! The signer: rotates the MAVLink signing key in a drone's autopilot (spec
//! R-SEC2 section 4).
//!
//! It runs on the drone and owns a dedicated link to the autopilot (its own
//! UDP port, never a router endpoint), so `SETUP_SIGNING` never reaches
//! routers or logs. The state machine ([`Signer`]) does its I/O through the
//! [`Port`] trait and takes its time from it, so tests drive it against a
//! simulated autopilot in virtual time. [`port::UdpPort`] is the real one.
//!
//! One [`Signer::tick`] watches the autopilot for about a second, and then:
//! 1. If a `.next` key exists (a crash, a lost reply, or a stuck rotation):
//!    **work out which key the autopilot has** ([`Signer::resolve`]).
//! 2. Otherwise, if `rotation-pending` has lines: wait until the autopilot is
//!    **disarmed**, then rotate: issue a generation, save `.next`, send
//!    `SETUP_SIGNING` signed with the current key, prove the new key with a
//!    signed `MAV_CMD_REQUEST_MESSAGE` and a signed matching `COMMAND_ACK`,
//!    and commit.
//!
//! Which key the autopilot has is never guessed. A keyed autopilot signs what
//! it sends: if its frames verify under one key, that key is in use. Else we
//! ask under each key, for 75 s. If neither answers, both files stay and the
//! rotation is reported `rotation_stuck`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use mavlink::MavHeader;
use mavlink::dialects::common::{
    COMMAND_LONG_DATA, HEARTBEAT_DATA, MavAutopilot, MavCmd, MavMessage, MavModeFlag, MavState,
    MavType, SETUP_SIGNING_DATA,
};

use crate::rotation;
use crate::signing::{SigningKey, mavlink_timestamp_now};
use crate::{Error, Result};

pub mod port;

/// How long a heartbeat counts as news about the arming state.
pub const HEARTBEAT_FRESH: Duration = Duration::from_secs(10);
/// How long to wait for the proof under the new key (step 5).
pub const PROVE_WAIT: Duration = Duration::from_secs(5);
/// How long a probe only listens, before it asks.
pub const LISTEN: Duration = Duration::from_secs(4);
/// How long a probe asks under each key (ArduPilot refuses new signed
/// streams for up to a minute after a reboot).
pub const PROBE_TOTAL: Duration = Duration::from_secs(75);
/// After a rotation fails, wait this long before the next try.
pub const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30);
/// How long one tick watches the autopilot.
pub const TICK: Duration = Duration::from_secs(1);

/// A signature on a frame we received.
#[derive(Clone, Copy, Debug)]
pub struct Sig {
    pub timestamp: u64,
    /// Which of the keys we were given it verifies under.
    pub verified_by: Option<usize>,
}

/// A frame from the autopilot link.
#[derive(Debug)]
pub struct Inbound {
    pub header: MavHeader,
    pub msg: MavMessage,
    /// `None`: not signed.
    pub sig: Option<Sig>,
}

/// The dedicated autopilot link.
pub trait Port {
    /// A monotonic clock.
    fn now(&mut self) -> Duration;
    /// Send `msg` signed with `key` (unsigned for `None`). The signature
    /// timestamp is at least `min_ts`; the one used comes back (0 if unsigned).
    fn send(&mut self, key: Option<&SigningKey>, msg: &MavMessage, min_ts: u64) -> Result<u64>;
    /// Wait up to `wait` for a frame. `keys` are the candidates a signature is
    /// checked against.
    fn recv(&mut self, wait: Duration, keys: &[&SigningKey]) -> Result<Option<Inbound>>;
}

fn companion_heartbeat() -> MavMessage {
    MavMessage::HEARTBEAT(HEARTBEAT_DATA {
        custom_mode: 0,
        mavtype: MavType::MAV_TYPE_ONBOARD_CONTROLLER,
        autopilot: MavAutopilot::MAV_AUTOPILOT_INVALID,
        base_mode: MavModeFlag::empty(),
        system_status: MavState::MAV_STATE_ACTIVE,
        mavlink_version: 3,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The autopilot's system and component id.
    pub sys: u8,
    pub comp: u8,
}

/// What a tick tells the person. `name` is the log event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A rotation is wanted and the autopilot is armed.
    WaitingArmed,
    /// A rotation is wanted but there is no recent heartbeat to say it is disarmed.
    WaitingHeartbeat,
    /// A new key was issued (generation).
    Issued(u32),
    /// The autopilot answered under the new key; it is now the current key.
    Rotated(u32),
    /// The autopilot kept the old key; the new one was dropped. A new try
    /// will use a new generation.
    RolledBack(u32),
    /// Neither key answered. Both files are kept.
    Stuck,
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Event::WaitingArmed => "rotation_waiting_armed",
            Event::WaitingHeartbeat => "rotation_waiting_heartbeat",
            Event::Issued(_) => "rotation_started",
            Event::Rotated(_) => "rotation_done",
            Event::RolledBack(_) => "rotation_rolled_back",
            Event::Stuck => "rotation_stuck",
        }
    }

    pub fn generation(&self) -> Option<u32> {
        match self {
            Event::Issued(g) | Event::Rotated(g) | Event::RolledBack(g) => Some(*g),
            _ => None,
        }
    }
}

type EventHook = Box<dyn FnMut(&Event)>;

pub struct Signer<P: Port> {
    dir: PathBuf,
    port: P,
    cfg: Config,
    /// Last heartbeat from the autopilot: when, and armed or not.
    heartbeat: Option<(Duration, bool)>,
    /// Highest signature timestamp seen from the autopilot link.
    max_ts: u64,
    /// The next signature timestamp we may use.
    next_ts: u64,
    /// Work out the key at the first tick (every start).
    probe_due: bool,
    /// Requests waiting when the last probe got no answer.
    stuck_with: Option<usize>,
    retry_at: Duration,
    last_wait: Option<Event>,
    /// Told of each event as it happens (a tick can take 80 s).
    on_event: Option<EventHook>,
}

impl<P: Port> Signer<P> {
    pub fn new(dir: &Path, port: P, cfg: Config) -> Self {
        Self {
            dir: dir.to_path_buf(),
            port,
            cfg,
            heartbeat: None,
            max_ts: 0,
            next_ts: 0,
            probe_due: true,
            stuck_with: None,
            retry_at: Duration::ZERO,
            last_wait: None,
            on_event: None,
        }
    }

    /// Call `f` for each event the moment it happens, not when the tick ends.
    pub fn on_event(&mut self, f: impl FnMut(&Event) + 'static) {
        self.on_event = Some(Box::new(f));
    }

    fn emit(&mut self, e: Event) -> Event {
        if let Some(f) = self.on_event.as_mut() {
            f(&e);
        }
        e
    }

    pub fn port(&mut self) -> &mut P {
        &mut self.port
    }

    /// Watch the autopilot for `wait`: note heartbeats and signature times.
    fn observe(&mut self, wait: Duration) -> Result<()> {
        let end = self.port.now() + wait;
        loop {
            let left = end.saturating_sub(self.port.now());
            if left.is_zero() {
                return Ok(());
            }
            match self.port.recv(left, &[])? {
                Some(f) => self.note(&f),
                None => return Ok(()),
            }
        }
    }

    fn note(&mut self, f: &Inbound) {
        if f.header.system_id != self.cfg.sys {
            return;
        }
        if let Some(s) = f.sig {
            self.max_ts = self.max_ts.max(s.timestamp);
        }
        if f.header.component_id == self.cfg.comp
            && let MavMessage::HEARTBEAT(h) = &f.msg
        {
            let armed = h.base_mode.bits() & MavModeFlag::MAV_MODE_FLAG_SAFETY_ARMED.bits() != 0;
            let now = self.port.now();
            self.heartbeat = Some((now, armed));
        }
    }

    fn request(&self) -> MavMessage {
        MavMessage::COMMAND_LONG(COMMAND_LONG_DATA {
            param1: 148.0, // AUTOPILOT_VERSION
            param2: 0.0,
            param3: 0.0,
            param4: 0.0,
            param5: 0.0,
            param6: 0.0,
            param7: 0.0,
            command: MavCmd::MAV_CMD_REQUEST_MESSAGE,
            target_system: self.cfg.sys,
            target_component: self.cfg.comp,
            confirmation: 0,
        })
    }

    fn send(&mut self, key: &SigningKey, msg: &MavMessage) -> Result<()> {
        let used = self.port.send(Some(key), msg, self.next_ts)?;
        self.next_ts = self.next_ts.max(used.saturating_add(1));
        Ok(())
    }

    /// Is this frame the autopilot's answer to our request?
    fn is_answer(&self, f: &Inbound) -> bool {
        f.header.system_id == self.cfg.sys
            && f.header.component_id == self.cfg.comp
            && matches!(&f.msg, MavMessage::COMMAND_ACK(a) if a.command == MavCmd::MAV_CMD_REQUEST_MESSAGE)
    }

    /// Step 5: ask under `key` once a second for up to `wait`; true when a
    /// signed, matching `COMMAND_ACK` verifies under it.
    fn prove(&mut self, key: &SigningKey, wait: Duration) -> Result<bool> {
        let end = self.port.now() + wait;
        let req = self.request();
        while self.port.now() < end {
            self.send(key, &req)?;
            let second = (self.port.now() + Duration::from_secs(1)).min(end);
            while self.port.now() < second {
                let left = second.saturating_sub(self.port.now());
                let Some(f) = self.port.recv(left, &[key])? else {
                    break;
                };
                self.note(&f);
                if self.is_answer(&f) && f.sig.is_some_and(|s| s.verified_by == Some(0)) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// One round: watch, then probe or rotate if there is work. After an
    /// error (a lost link, a full disk) the next round works out which key
    /// the autopilot has before it does anything else.
    pub fn tick(&mut self) -> Result<Vec<Event>> {
        let r = self.tick_inner();
        if r.is_err() {
            self.probe_due = true;
        }
        r
    }

    fn tick_inner(&mut self) -> Result<Vec<Event>> {
        let Some(keys) = rotation::load_drone_keys(&self.dir)? else {
            return Err(Error::Link("this folder holds no autopilot key"));
        };
        // A companion computer says hello once a second, signed with the
        // current key: the autopilot learns where to send its frames (some only
        // answer the last address that spoke), and we hear its heartbeats.
        self.send(&keys.current, &companion_heartbeat())?;
        self.observe(TICK)?;
        let lines = rotation::pending_lines(&self.dir)?;
        if keys.next.is_some() {
            let again = self.stuck_with.is_some_and(|n| n != lines);
            if self.probe_due || again {
                self.probe_due = false;
                self.stuck_with = None;
                return self.resolve();
            }
            return Ok(Vec::new());
        }
        self.probe_due = false;
        self.stuck_with = None;
        if lines == 0 {
            self.last_wait = None;
            return Ok(Vec::new());
        }
        if self.port.now() < self.retry_at {
            return Ok(Vec::new());
        }
        // Step 1: wait until disarmed.
        let now = self.port.now();
        let wait = match self.heartbeat {
            Some((t, false)) if now.saturating_sub(t) <= HEARTBEAT_FRESH => None,
            Some((t, true)) if now.saturating_sub(t) <= HEARTBEAT_FRESH => {
                Some(Event::WaitingArmed)
            }
            _ => Some(Event::WaitingHeartbeat),
        };
        if let Some(e) = wait {
            // Say it once, not every second.
            if self.last_wait.as_ref() != Some(&e) {
                self.last_wait = Some(e.clone());
                return Ok(vec![self.emit(e)]);
            }
            return Ok(Vec::new());
        }
        self.last_wait = None;
        self.rotate(keys.current)
    }

    /// Steps 2 to 6.
    fn rotate(&mut self, current: SigningKey) -> Result<Vec<Event>> {
        let begun = rotation::begin(&self.dir)?;
        let g = begun.generation;
        let mut events = vec![self.emit(Event::Issued(g))];
        // Step 4: the initial timestamp is one more than the latest of our
        // clock and every signed timestamp we have seen.
        let seen = rotation::read_seen_ts(&self.dir).unwrap_or(0);
        let initial = mavlink_timestamp_now()
            .max(self.max_ts)
            .max(self.next_ts)
            .max(seen)
            .saturating_add(1);
        let setup = MavMessage::SETUP_SIGNING(SETUP_SIGNING_DATA {
            initial_timestamp: initial,
            target_system: self.cfg.sys,
            target_component: self.cfg.comp,
            secret_key: *begun.key.as_bytes(),
        });
        self.next_ts = self.next_ts.max(initial);
        self.send(&current, &setup)?;
        // Step 5: the autopilot needs a moment to switch.
        self.observe(Duration::from_millis(200))?;
        if self.prove(&begun.key, PROVE_WAIT)? {
            rotation::commit(&self.dir, g, begun.consumed)?;
            events.push(self.emit(Event::Rotated(g)));
            return Ok(events);
        }
        events.extend(self.resolve()?);
        Ok(events)
    }

    /// "When unsure": a `.next` key exists and we do not know which key the
    /// autopilot has. Listen, then ask, and keep the key that answered.
    pub fn resolve(&mut self) -> Result<Vec<Event>> {
        let keys = rotation::load_drone_keys(&self.dir)?
            .ok_or(Error::Link("this folder holds no autopilot key"))?;
        let Some((g, next)) = keys.next else {
            return Ok(Vec::new());
        };
        let current = keys.current;
        if current == next {
            // Switched on disk already; only the clean-up is left.
            self.finish(g)?;
            return Ok(vec![self.emit(Event::Rotated(g))]);
        }
        match self.which_key(&current, &next)? {
            Some(1) => {
                self.finish(g)?;
                Ok(vec![self.emit(Event::Rotated(g))])
            }
            Some(_) => {
                rotation::abandon(&self.dir)?;
                self.retry_at = self.port.now() + RETRY_AFTER_FAILURE;
                Ok(vec![self.emit(Event::RolledBack(g))])
            }
            None => {
                self.stuck_with = Some(rotation::pending_lines(&self.dir)?);
                Ok(vec![self.emit(Event::Stuck)])
            }
        }
    }

    /// Commit after the fact (a restart found the new key in use). Requests
    /// older than the pending key are answered by it; newer ones stay.
    fn finish(&mut self, g: u32) -> Result<()> {
        let consumed = rotation::lines_before_next(&self.dir)?;
        rotation::commit(&self.dir, g, consumed)
    }

    /// Which key (index into `[current, next]`) does the autopilot use?
    /// `None`: neither answered. Never deletes anything.
    fn which_key(&mut self, current: &SigningKey, next: &SigningKey) -> Result<Option<usize>> {
        let both = [current, next];
        // 1. Listen: a keyed autopilot signs what it sends.
        let end = self.port.now() + LISTEN;
        while self.port.now() < end {
            let left = end.saturating_sub(self.port.now());
            let Some(f) = self.port.recv(left, &both)? else {
                break;
            };
            self.note(&f);
            if f.header.system_id == self.cfg.sys
                && let Some(i) = f.sig.and_then(|s| s.verified_by)
            {
                return Ok(Some(i));
            }
        }
        // 2. Ask under each key, once a second, for 75 s.
        let end = self.port.now() + PROBE_TOTAL;
        let req = self.request();
        while self.port.now() < end {
            self.send(next, &req)?;
            self.send(current, &req)?;
            let second = self.port.now() + Duration::from_secs(1);
            while self.port.now() < second {
                let left = second.saturating_sub(self.port.now());
                let Some(f) = self.port.recv(left, &both)? else {
                    break;
                };
                self.note(&f);
                if f.header.system_id == self.cfg.sys
                    && let Some(i) = f.sig.and_then(|s| s.verified_by)
                {
                    return Ok(Some(i));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
