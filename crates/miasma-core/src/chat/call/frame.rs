//! Media frame seal/open, replay window and epoch advance (PR1).
//!
//! Design: design-call-security-v7e.md chapter 4 (4.1-4.3) and chapter 2
//! (2.4-2.5). This is pure library code: it takes a message key plus the
//! `(direction, key_epoch, packet_seq, media_type)` tuple and the active
//! call_id, and produces or verifies an authenticated frame. It holds no
//! socket and no transport.
//!
//! Privacy: no key, nonce, call id, peer id or media sample is ever logged or
//! put in an error. Secret buffers live in `Zeroizing`; the AEAD tag is the
//! only thing that decides authenticity, in constant time inside the AEAD.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use super::media::{
    chain_step, init_chain_key, media_aad, media_nonce, Direction, MediaError, EPOCH_MAX_PACKETS,
    FRAME_PLAINTEXT_LEN, KEY_EPOCH_MAX, MEDIA_REKEY_SECONDS, MEDIA_REPLAY_WINDOW, TAG_LEN,
};

/// Seal one media frame body under `msg_key`, returning `ciphertext || tag`.
/// The AAD binds `call_id || direction || key_epoch || packet_seq ||
/// media_type` (§2.5). The nonce is the deterministic §2.4 construction. The
/// plaintext must be exactly `FRAME_PLAINTEXT_LEN` bytes (§4.4.2 CBR).
pub fn seal_frame(
    msg_key: &[u8; 32],
    call_id: &[u8; 16],
    direction: Direction,
    key_epoch: u32,
    packet_seq: u64,
    media_type: u8,
    plaintext: &[u8],
) -> Result<Vec<u8>, MediaError> {
    if plaintext.len() != FRAME_PLAINTEXT_LEN {
        return Err(MediaError::Malformed);
    }
    let nonce = media_nonce(direction, key_epoch, packet_seq);
    let aad = media_aad(call_id, direction, key_epoch, packet_seq, media_type);
    let mut buf = plaintext.to_vec();
    let cipher = XChaCha20Poly1305::new(msg_key.into());
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, buf.as_mut_slice())
        .map_err(|_| MediaError::KeySchedule)?;
    buf.extend_from_slice(&tag);
    Ok(buf)
}

/// Open one media frame (`ciphertext || tag`) under `msg_key`. The receiver
/// rebuilds the AAD from the active call's id and the header fields; if any of
/// them differs from what the sender bound, the tag check fails. Returns the
/// plaintext (zeroized on drop). This checks neither sequence nor replay; that
/// is the window's job (see `ReplayWindow`).
pub fn open_frame(
    msg_key: &[u8; 32],
    call_id: &[u8; 16],
    direction: Direction,
    key_epoch: u32,
    packet_seq: u64,
    media_type: u8,
    frame: &[u8],
) -> Result<Zeroizing<Vec<u8>>, MediaError> {
    if frame.len() < TAG_LEN {
        return Err(MediaError::Authentication);
    }
    let (body, tag) = frame.split_at(frame.len() - TAG_LEN);
    let nonce = media_nonce(direction, key_epoch, packet_seq);
    let aad = media_aad(call_id, direction, key_epoch, packet_seq, media_type);
    let mut buf = Zeroizing::new(body.to_vec());
    let cipher = XChaCha20Poly1305::new(msg_key.into());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &aad,
            buf.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| MediaError::Authentication)?;
    Ok(buf)
}

/// A sliding replay window over `packet_seq` for one `(direction, key_epoch)`,
/// §4.2.1-4.2.2. The bitmap holds the `MEDIA_REPLAY_WINDOW` sequence numbers
/// just below `max_seq`. The window is updated only after the AEAD tag passed,
/// so a forged seq can never mark a slot received.
pub struct ReplayWindow {
    max_seq: u64,
    /// Whether any packet was accepted yet (so seq 0 is distinguishable).
    seen_any: bool,
    bits: Vec<u64>,
}

impl ReplayWindow {
    pub fn new() -> Self {
        let words = (MEDIA_REPLAY_WINDOW as usize).div_ceil(64);
        ReplayWindow {
            max_seq: 0,
            seen_any: false,
            bits: vec![0u64; words],
        }
    }

    fn slot(&self, seq: u64) -> (usize, u64) {
        let idx = (seq % MEDIA_REPLAY_WINDOW) as usize;
        (idx / 64, 1u64 << (idx % 64))
    }

    fn is_set(&self, seq: u64) -> bool {
        let (w, b) = self.slot(seq);
        self.bits[w] & b != 0
    }

    fn set(&mut self, seq: u64) {
        let (w, b) = self.slot(seq);
        self.bits[w] |= b;
    }

    fn clear_range(&mut self, from_excl: u64, to_incl: u64) {
        // Clear slots for (from_excl, to_incl], used when sliding forward.
        let span = to_incl.saturating_sub(from_excl);
        let span = span.min(MEDIA_REPLAY_WINDOW);
        let mut s = to_incl;
        for _ in 0..span {
            let (w, b) = self.slot(s);
            self.bits[w] &= !b;
            if s == 0 {
                break;
            }
            s -= 1;
        }
    }

    /// Decide whether `seq` may be accepted. Does not mutate on rejection.
    /// Use `open_frame_and_accept` to authenticate and record a frame.
    pub fn check(&self, seq: u64) -> Result<(), MediaError> {
        if !self.seen_any {
            return Ok(());
        }
        if seq > self.max_seq {
            return Ok(());
        }
        // seq <= max_seq
        if self.max_seq.saturating_sub(seq) >= MEDIA_REPLAY_WINDOW {
            return Err(MediaError::OutsideWindow);
        }
        if self.is_set(seq) {
            return Err(MediaError::Replay);
        }
        Ok(())
    }

    /// Reject replays, authenticate the frame, and only then update the window.
    /// Use a separate window for each direction and key epoch.
    #[allow(clippy::too_many_arguments)]
    pub fn open_frame_and_accept(
        &mut self,
        msg_key: &[u8; 32],
        call_id: &[u8; 16],
        direction: Direction,
        key_epoch: u32,
        packet_seq: u64,
        media_type: u8,
        frame: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, MediaError> {
        self.check(packet_seq)?;
        let plaintext = open_frame(
            msg_key, call_id, direction, key_epoch, packet_seq, media_type, frame,
        )?;
        self.accept(packet_seq);
        Ok(plaintext)
    }

    /// Record a sequence after replay checking and authentication succeed.
    fn accept(&mut self, seq: u64) {
        if !self.seen_any {
            self.seen_any = true;
            self.max_seq = seq;
            self.set(seq);
            return;
        }
        if seq > self.max_seq {
            self.clear_range(self.max_seq, seq);
            self.max_seq = seq;
            self.set(seq);
        } else {
            self.set(seq);
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Reason an epoch advance was triggered (§4.3.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdvanceReason {
    None,
    PacketCount,
    Time,
}

/// The send-side chain for one direction: the current chain key, epoch, the
/// monotonic packet counter and the time of the last advance. Advancing drops
/// the old chain key (zeroized) and moves to the next epoch.
pub struct SendChain {
    direction: Direction,
    chain_key: Zeroizing<[u8; 32]>,
    msg_key: Zeroizing<[u8; 32]>,
    key_epoch: u32,
    next_seq: u64,
    last_advance_ms: u64,
    ended: bool,
}

impl SendChain {
    // The packet sender owns a call-wide sequence; next_seq remains the
    // per-epoch packet count used by the existing advance trigger.
    pub(super) fn seal_packet(
        &mut self,
        call_id: &[u8; 16],
        packet_seq: u64,
        media_type: u8,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<(u32, Vec<u8>), MediaError> {
        if self.ended {
            return Err(MediaError::EpochExhausted);
        }
        if self.advance_due(now_ms) != AdvanceReason::None {
            self.advance(now_ms)?;
        }
        let frame = seal_frame(
            &self.msg_key,
            call_id,
            self.direction,
            self.key_epoch,
            packet_seq,
            media_type,
            plaintext,
        )?;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(MediaError::EpochExhausted)?;
        Ok((self.key_epoch, frame))
    }

    /// Start a send chain from `MK_root` at epoch 0, time `now_ms`.
    pub fn start(
        mk_root: &[u8; 32],
        direction: Direction,
        now_ms: u64,
    ) -> Result<Self, MediaError> {
        let chain_key = init_chain_key(mk_root)?;
        let (msg_key, next) = chain_step(&chain_key)?;
        Ok(SendChain {
            direction,
            chain_key: next,
            msg_key,
            key_epoch: 0,
            next_seq: 0,
            last_advance_ms: now_ms,
            ended: false,
        })
    }

    pub fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Decide whether an epoch advance is due at `now_ms`, given how many
    /// packets have been sent in this epoch (§4.3.3): either the packet count
    /// reached `EPOCH_MAX_PACKETS` or `MEDIA_REKEY_SECONDS` elapsed.
    pub fn advance_due(&self, now_ms: u64) -> AdvanceReason {
        if self.next_seq >= EPOCH_MAX_PACKETS {
            return AdvanceReason::PacketCount;
        }
        if now_ms.saturating_sub(self.last_advance_ms) >= MEDIA_REKEY_SECONDS * 1000 {
            return AdvanceReason::Time;
        }
        AdvanceReason::None
    }

    /// Advance to the next epoch: derive the next message key, drop the old
    /// chain/message key (zeroized), reset the packet counter, bump the epoch.
    /// On reaching `KEY_EPOCH_MAX` the chain refuses to wrap and marks the call
    /// ended (§4.3.3): callers end the call and reconnect with a new call_id.
    pub fn advance(&mut self, now_ms: u64) -> Result<(), MediaError> {
        if self.key_epoch >= KEY_EPOCH_MAX {
            self.ended = true;
            return Err(MediaError::EpochExhausted);
        }
        let (msg_key, next) = chain_step(&self.chain_key)?;
        // Old self.msg_key and self.chain_key are zeroized when overwritten
        // (Zeroizing's Drop runs on the replaced value).
        self.msg_key = msg_key;
        self.chain_key = next;
        self.key_epoch += 1;
        self.next_seq = 0;
        self.last_advance_ms = now_ms;
        Ok(())
    }

    /// If an advance is due, perform it first; then seal the next frame and
    /// return `(key_epoch, packet_seq, frame)`. The counter is monotonic and
    /// never rewinds or is restored from disk (§2.4).
    pub fn seal_next(
        &mut self,
        call_id: &[u8; 16],
        media_type: u8,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<(u32, u64, Vec<u8>), MediaError> {
        if self.ended {
            return Err(MediaError::EpochExhausted);
        }
        if self.advance_due(now_ms) != AdvanceReason::None {
            self.advance(now_ms)?;
        }
        let seq = self.next_seq;
        let frame = seal_frame(
            &self.msg_key,
            call_id,
            self.direction,
            self.key_epoch,
            seq,
            media_type,
            plaintext,
        )?;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(MediaError::EpochExhausted)?;
        Ok((self.key_epoch, seq, frame))
    }
}

#[cfg(test)]
mod tests {
    use super::super::media::{derive_mk_root, FRAME_PLAINTEXT_LEN, FRAME_WIRE_LEN, KEY_EPOCH_MAX};
    use super::*;

    // All tests use run-time random key material (no fixed keys), per the
    // chapter-7 rule for PR1.
    fn rand32() -> [u8; 32] {
        std::array::from_fn(|_| rand::random::<u8>())
    }
    fn rand16() -> [u8; 16] {
        std::array::from_fn(|_| rand::random::<u8>())
    }
    fn rand_plaintext() -> [u8; FRAME_PLAINTEXT_LEN] {
        std::array::from_fn(|_| rand::random::<u8>())
    }

    // A fresh message key for the seal/open tests.
    fn fresh_msg_key() -> [u8; 32] {
        let ck = rand32();
        let hk = rand32();
        let mk = derive_mk_root(&ck, &hk, &rand16(), &rand16(), Direction::Caller).unwrap();
        let ck0 = init_chain_key(&mk).unwrap();
        let (m, _next) = chain_step(&ck0).unwrap();
        *m
    }

    // §4.1.1 / §7.1: a frame seals and opens round-trip and the wire length is
    // the single CBR total (header is added by the transport; this is the
    // ciphertext+tag part plus the fixed plaintext length check).
    #[test]
    fn seal_open_round_trip() {
        let key = fresh_msg_key();
        let call_id = rand16();
        let pt = rand_plaintext();
        let frame = seal_frame(&key, &call_id, Direction::Caller, 0, 0, 0x00, &pt).unwrap();
        // ciphertext + tag only (no 14-byte wire header in the library)
        assert_eq!(frame.len(), FRAME_PLAINTEXT_LEN + TAG_LEN);
        assert_eq!(frame.len(), FRAME_WIRE_LEN - 14);
        let opened = open_frame(&key, &call_id, Direction::Caller, 0, 0, 0x00, &frame).unwrap();
        assert_eq!(opened.as_slice(), &pt[..]);
    }

    // §7.1 tamper: flipping any bit of the ciphertext or the tag makes open
    // fail with Authentication and yields no plaintext.
    #[test]
    fn tamper_ciphertext_or_tag_fails() {
        let key = fresh_msg_key();
        let call_id = rand16();
        let pt = rand_plaintext();
        let frame = seal_frame(&key, &call_id, Direction::Caller, 0, 0, 0x00, &pt).unwrap();
        for i in 0..frame.len() {
            let mut bad = frame.clone();
            bad[i] ^= 0x01;
            let r = open_frame(&key, &call_id, Direction::Caller, 0, 0, 0x00, &bad);
            assert_eq!(r.unwrap_err(), MediaError::Authentication);
        }
    }

    // §7.1 tamper: changing any AAD field the receiver rebuilds (call_id,
    // direction, key_epoch, packet_seq, media_type) makes the tag check fail.
    #[test]
    fn aad_mismatch_fails() {
        let key = fresh_msg_key();
        let call_id = rand16();
        let pt = rand_plaintext();
        let frame = seal_frame(&key, &call_id, Direction::Caller, 5, 9, 0x00, &pt).unwrap();
        // wrong call_id
        let mut other_id = call_id;
        other_id[0] ^= 0x01;
        assert_eq!(
            open_frame(&key, &other_id, Direction::Caller, 5, 9, 0x00, &frame).unwrap_err(),
            MediaError::Authentication
        );
        // wrong direction
        assert_eq!(
            open_frame(&key, &call_id, Direction::Callee, 5, 9, 0x00, &frame).unwrap_err(),
            MediaError::Authentication
        );
        // wrong key_epoch
        assert_eq!(
            open_frame(&key, &call_id, Direction::Caller, 6, 9, 0x00, &frame).unwrap_err(),
            MediaError::Authentication
        );
        // wrong packet_seq
        assert_eq!(
            open_frame(&key, &call_id, Direction::Caller, 5, 10, 0x00, &frame).unwrap_err(),
            MediaError::Authentication
        );
        // wrong media_type
        assert_eq!(
            open_frame(&key, &call_id, Direction::Caller, 5, 9, 0x01, &frame).unwrap_err(),
            MediaError::Authentication
        );
    }

    // §7.1: a too-short frame (shorter than the tag) is rejected, not a panic.
    #[test]
    fn short_frame_rejected() {
        let key = fresh_msg_key();
        let call_id = rand16();
        let r = open_frame(&key, &call_id, Direction::Caller, 0, 0, 0x00, &[0u8; 4]);
        assert_eq!(r.unwrap_err(), MediaError::Authentication);
    }

    // §7.1: the plaintext must be exactly FRAME_PLAINTEXT_LEN; other lengths
    // are rejected (CBR, §4.4.2).
    #[test]
    fn wrong_plaintext_length_rejected() {
        let key = fresh_msg_key();
        let call_id = rand16();
        assert_eq!(
            seal_frame(&key, &call_id, Direction::Caller, 0, 0, 0x00, &[0u8; 59]).unwrap_err(),
            MediaError::Malformed
        );
        assert_eq!(
            seal_frame(&key, &call_id, Direction::Caller, 0, 0, 0x00, &[0u8; 61]).unwrap_err(),
            MediaError::Malformed
        );
    }

    // §7.2 replay: a sequence number that was already accepted is rejected as a
    // replay; it is never re-accepted.
    #[test]
    fn replay_window_rejects_duplicate() {
        let mut w = ReplayWindow::new();
        for seq in 0u64..10 {
            assert!(w.check(seq).is_ok());
            w.accept(seq);
        }
        // re-injecting an already-seen seq is a replay
        assert_eq!(w.check(5).unwrap_err(), MediaError::Replay);
        assert_eq!(w.check(0).unwrap_err(), MediaError::Replay);
    }

    // §7.2 replay: a sequence number older than the window is rejected as
    // outside the window.
    #[test]
    fn replay_window_rejects_too_old() {
        let mut w = ReplayWindow::new();
        w.accept(0);
        let newest = MEDIA_REPLAY_WINDOW + 100;
        w.accept(newest);
        assert_eq!(
            w.check(newest - MEDIA_REPLAY_WINDOW).unwrap_err(),
            MediaError::OutsideWindow
        );
    }

    // §7.3 reorder: out-of-order delivery inside the window is accepted; the
    // window does not require strictly increasing arrival.
    #[test]
    fn reorder_inside_window_accepted() {
        let mut w = ReplayWindow::new();
        let order: Vec<u64> = (0u64..100).map(|i| (i * 37) % 100).collect();
        for &seq in &order {
            assert!(w.check(seq).is_ok(), "seq {seq} should be accepted");
            w.accept(seq);
        }
        for seq in 0u64..100 {
            assert_eq!(w.check(seq).unwrap_err(), MediaError::Replay);
        }
    }

    // §7.3: an end-to-end reorder with real frames: seal three frames, open
    // them out of order, each opens once and the window then flags replays.
    #[test]
    fn reorder_end_to_end() {
        let key = fresh_msg_key();
        let call_id = rand16();
        let mut frames = Vec::new();
        for seq in 0u64..3 {
            let pt = rand_plaintext();
            let f = seal_frame(&key, &call_id, Direction::Caller, 0, seq, 0x00, &pt).unwrap();
            frames.push((seq, pt, f));
        }
        let mut w = ReplayWindow::new();
        for &i in &[2usize, 0, 1] {
            let (seq, ref pt, ref f) = frames[i];
            assert!(w.check(seq).is_ok());
            let opened = w
                .open_frame_and_accept(&key, &call_id, Direction::Caller, 0, seq, 0x00, f)
                .unwrap();
            assert_eq!(opened.as_slice(), &pt[..]);
        }
        assert_eq!(w.check(0).unwrap_err(), MediaError::Replay);
    }

    #[test]
    fn failed_open_does_not_advance_or_poison_window() {
        let key = Zeroizing::new(fresh_msg_key());
        let call_id = rand16();
        let pt = Zeroizing::new(rand_plaintext());
        let frame = seal_frame(&key, &call_id, Direction::Caller, 0, 1, 0x00, &pt[..]).unwrap();
        let mut window = ReplayWindow::new();
        let mut bad = frame.clone();
        bad[0] ^= 1;

        assert!(matches!(
            window.open_frame_and_accept(&key, &call_id, Direction::Caller, 0, 1, 0x00, &bad),
            Err(MediaError::Authentication)
        ));
        assert!(window.check(1).is_ok());
        assert!(matches!(
            window.open_frame_and_accept(
                &key,
                &call_id,
                Direction::Caller,
                0,
                u64::MAX,
                0x00,
                &frame,
            ),
            Err(MediaError::Authentication)
        ));
        assert!(window.check(1).is_ok());
        let opened = window
            .open_frame_and_accept(&key, &call_id, Direction::Caller, 0, 1, 0x00, &frame)
            .unwrap();
        assert!(opened.as_slice() == &pt[..]);
        assert!(matches!(
            window.open_frame_and_accept(&key, &call_id, Direction::Caller, 0, 1, 0x00, &frame),
            Err(MediaError::Replay)
        ));
    }

    // §7.4 epoch time trigger: advancing the injected clock by
    // MEDIA_REKEY_SECONDS bumps the epoch even though the packet count is far
    // below EPOCH_MAX_PACKETS, and the previous epoch's frame no longer opens
    // under the new epoch's key.
    #[test]
    fn epoch_time_trigger_advances_and_rotates_key() {
        let ck = rand32();
        let hk = rand32();
        let call_id = rand16();
        let call_nonce = rand16();
        let mk = derive_mk_root(&ck, &hk, &call_id, &call_nonce, Direction::Caller).unwrap();
        let t0 = 1_000_000u64;
        let mut chain = SendChain::start(&mk, Direction::Caller, t0).unwrap();
        assert_eq!(chain.key_epoch(), 0);
        assert_eq!(chain.advance_due(t0), AdvanceReason::None);

        let pt0 = rand_plaintext();
        let (e0, s0, f0) = chain.seal_next(&call_id, 0x00, &pt0, t0).unwrap();
        assert_eq!(e0, 0);
        assert_eq!(s0, 0);

        let t1 = t0 + MEDIA_REKEY_SECONDS * 1000;
        assert_eq!(chain.advance_due(t1), AdvanceReason::Time);
        let pt1 = rand_plaintext();
        let (e1, s1, _f1) = chain.seal_next(&call_id, 0x00, &pt1, t1).unwrap();
        assert_eq!(e1, 1, "epoch advanced on the time trigger");
        assert_eq!(s1, 0, "packet counter reset at the new epoch");

        // Rebuild the epoch-1 message key independently and confirm it cannot
        // open the epoch-0 frame (the key rotated).
        let ck0 = init_chain_key(&mk).unwrap();
        let (_m0, ck1) = chain_step(&ck0).unwrap();
        let (m1, _ck2) = chain_step(&ck1).unwrap();
        assert_eq!(
            open_frame(&m1, &call_id, Direction::Caller, 0, s0, 0x00, &f0).unwrap_err(),
            MediaError::Authentication
        );
    }

    // §7.4 / §4.3.3: a normal advance bumps the epoch and does not end the
    // call, and KEY_EPOCH_MAX is the 24-bit ceiling that the chain refuses to
    // wrap past.
    #[test]
    fn epoch_advance_and_ceiling_constant() {
        let mk = rand32();
        let mut chain = SendChain::start(&mk, Direction::Caller, 0).unwrap();
        chain.advance(1000).unwrap();
        assert_eq!(chain.key_epoch(), 1);
        assert!(!chain.ended());
        assert_eq!(KEY_EPOCH_MAX, (1u32 << 24) - 1);
    }

    // §7.4: the send counter is monotonic within an epoch (0, 1, 2, ...).
    #[test]
    fn send_counter_is_monotonic() {
        let mk = rand32();
        let call_id = rand16();
        let mut chain = SendChain::start(&mk, Direction::Caller, 0).unwrap();
        let pt = rand_plaintext();
        let (_e, s0, _f) = chain.seal_next(&call_id, 0x00, &pt, 0).unwrap();
        let (_e, s1, _f) = chain.seal_next(&call_id, 0x00, &pt, 1).unwrap();
        let (_e, s2, _f) = chain.seal_next(&call_id, 0x00, &pt, 2).unwrap();
        assert_eq!((s0, s1, s2), (0, 1, 2));
    }
}
