//! One session: the two keys from a handshake, our send counter and the
//! replay window for what we receive.

use std::time::Duration;

use snow::StatelessTransportState;

use super::counter::{ReplayWindow, rebuild_counter};
use super::packet::{CounterLen, TAG_LEN, data_header, data_overhead};
use super::{Config, DropReason, SendError};

pub(crate) struct Session {
    pub local_index: u16,
    pub remote_index: u16,
    /// We started the handshake that made this session.
    pub initiator: bool,
    /// The peer has proved it holds the session: a valid data packet arrived
    /// on it. Until then an initiator cannot tell a working session from one
    /// whose handshake 2 was changed on the way (the indexes in it are not
    /// covered by the Noise tags).
    pub confirmed: bool,
    pub created: Duration,
    transport: StatelessTransportState,
    send_counter: u64,
    recv: ReplayWindow,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub last_sent: Duration,
}

impl Session {
    pub fn new(
        transport: StatelessTransportState,
        local_index: u16,
        remote_index: u16,
        initiator: bool,
        now: Duration,
    ) -> Self {
        Self {
            local_index,
            remote_index,
            initiator,
            confirmed: false,
            created: now,
            transport,
            send_counter: 0,
            recv: ReplayWindow::new(),
            packets_sent: 0,
            packets_received: 0,
            last_sent: now,
        }
    }

    /// Past 15 minutes or 2^60 packets: no sending, no accepting.
    pub fn expired(&self, now: Duration, cfg: &Config) -> bool {
        now.saturating_sub(self.created) >= cfg.reject_after
            || self.send_counter >= cfg.reject_after_packets
    }

    /// The initiator should start a new handshake.
    pub fn wants_rekey(&self, now: Duration, cfg: &Config) -> bool {
        now.saturating_sub(self.created) >= cfg.rekey_after
            || self.send_counter >= cfg.rekey_after_packets
    }

    /// Encrypt `plaintext` (empty for a keepalive) into a data packet.
    pub fn encrypt(
        &mut self,
        now: Duration,
        cfg: &Config,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SendError> {
        if data_overhead(cfg.counter_len) + plaintext.len() > cfg.mtu {
            return Err(SendError::TooLarge);
        }
        if self.expired(now, cfg) {
            return Err(SendError::NoSession);
        }
        let counter = self.send_counter;
        let mut packet = data_header(self.remote_index, cfg.counter_len, counter);
        let head = packet.len();
        packet.resize(head + plaintext.len() + TAG_LEN, 0);
        self.transport
            .write_message(counter, plaintext, &mut packet[head..])
            .map_err(|_| SendError::NoSession)?;
        // Only after the packet exists: a counter is never reused.
        self.send_counter += 1;
        self.packets_sent += 1;
        self.last_sent = now;
        Ok(packet)
    }

    /// Receive steps 3 to 5 of spec section 4: rebuild the counter, refuse
    /// what is too old, verify the tag, and only then check and update the
    /// replay window.
    pub fn decrypt(
        &mut self,
        now: Duration,
        cfg: &Config,
        counter_len: CounterLen,
        low: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DropReason> {
        if self.expired(now, cfg) {
            return Err(DropReason::UnknownIndex);
        }
        let counter = rebuild_counter(self.recv.expected(), low, counter_len.bits());
        if counter >= cfg.reject_after_packets {
            // A real peer never gets here, so it is a forgery.
            return Err(DropReason::BadTag);
        }
        if self.recv.is_too_old(counter) {
            return Err(DropReason::TooOld);
        }
        let mut out = vec![0u8; ciphertext.len().saturating_sub(TAG_LEN)];
        let n = self
            .transport
            .read_message(counter, ciphertext, &mut out)
            .map_err(|_| DropReason::BadTag)?;
        out.truncate(n);
        if !self.recv.mark(counter) {
            return Err(DropReason::Replay);
        }
        self.packets_received += 1;
        Ok(out)
    }
}
