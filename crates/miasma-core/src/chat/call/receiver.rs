//! Authenticated media receiver without transport or device I/O.
use super::frame::ReplayWindow;
use super::media::{
    chain_step, init_chain_key, Direction, MediaError, FRAME_PLAINTEXT_LEN, MAX_EPOCH_JUMP,
};
use super::packet::split_packet;
use zeroize::Zeroizing;

// Provisional: ten 20 ms frames allow jitter while limiting key retention.
pub const PREV_EPOCH_RETAIN_MS: u64 = 200;
// Provisional: 50 frames represent about one second at 50 frames/s.
pub const MAX_CONSECUTIVE_DROP: u32 = 50;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DropReason {
    Malformed,
    WrongDirection,
    StaleEpoch,
    FutureEpoch,
    Replay,
    OutsideWindow,
    AuthFailed,
}
pub enum RecvOutcome {
    Audio(Zeroizing<[u8; FRAME_PLAINTEXT_LEN]>),
    /// Camera video stream, media_type 0x01.
    Video(Zeroizing<[u8; FRAME_PLAINTEXT_LEN]>),
    /// Screen share stream, media_type 0x02. Routed to a separate video
    /// driver by the caller so camera and screen frames never mix, even when
    /// their frame numbers coincide.
    Screen(Zeroizing<[u8; FRAME_PLAINTEXT_LEN]>),
    Dropped(DropReason),
    Fatal,
}

struct Epoch {
    number: u32,
    key: Zeroizing<[u8; 32]>,
    next: Zeroizing<[u8; 32]>,
    window: ReplayWindow,
}
pub struct MediaReceiver {
    current: Epoch,
    previous: Option<(Epoch, u64)>,
    call_id: [u8; 16],
    direction: Direction,
    failures: u32,
    fatal: bool,
}
impl MediaReceiver {
    pub fn new(
        mk_root: &[u8; 32],
        call_id: [u8; 16],
        peer_direction: Direction,
        _now_ms: u64,
    ) -> Result<Self, MediaError> {
        let initial = init_chain_key(mk_root)?;
        let (key, next) = chain_step(&initial)?;
        Ok(Self {
            current: Epoch {
                number: 0,
                key,
                next,
                window: ReplayWindow::new(),
            },
            previous: None,
            call_id,
            direction: peer_direction,
            failures: 0,
            fatal: false,
        })
    }

    /// `now_ms` must be monotonic. Expiry is enforced on receive; drop an idle
    /// receiver when the call ends, since this pure type has no timer.
    pub fn receive(&mut self, packet: &[u8], now_ms: u64) -> RecvOutcome {
        if self.fatal {
            return RecvOutcome::Fatal;
        }
        let (header, body) = match split_packet(packet) {
            Ok(v) => v,
            Err(_) => return RecvOutcome::Dropped(DropReason::Malformed),
        };
        if header.direction != self.direction {
            return RecvOutcome::Dropped(DropReason::WrongDirection);
        }
        // Accept audio (0x00), camera video (0x01) and screen share (0x02);
        // screen rides the same media AEAD and key labels as camera and is
        // separated after authentication by its media_type.
        if header.media_type > 2 {
            return RecvOutcome::Dropped(DropReason::Malformed);
        }
        if header.key_epoch > self.current.number.saturating_add(MAX_EPOCH_JUMP) {
            return RecvOutcome::Dropped(DropReason::FutureEpoch);
        }
        if header.key_epoch < self.current.number
            && !self
                .previous
                .as_ref()
                .map_or(false, |(epoch, _)| epoch.number == header.key_epoch)
        {
            return RecvOutcome::Dropped(DropReason::StaleEpoch);
        }
        if self.previous.as_ref().map_or(false, |(_, since)| {
            now_ms.saturating_sub(*since) >= PREV_EPOCH_RETAIN_MS
        }) {
            self.previous = None;
        }
        let result = if header.key_epoch == self.current.number {
            self.current.window.open_frame_and_accept(
                &self.current.key,
                &self.call_id,
                self.direction,
                header.key_epoch,
                header.packet_seq,
                header.media_type,
                body,
            )
        } else if header.key_epoch < self.current.number {
            match self.previous.as_mut() {
                Some((epoch, _)) if epoch.number == header.key_epoch => {
                    epoch.window.open_frame_and_accept(
                        &epoch.key,
                        &self.call_id,
                        self.direction,
                        header.key_epoch,
                        header.packet_seq,
                        header.media_type,
                        body,
                    )
                }
                _ => return RecvOutcome::Dropped(DropReason::StaleEpoch),
            }
        } else {
            let jump = header.key_epoch - self.current.number;
            let (mut key, mut next) = match chain_step(&self.current.next) {
                Ok(v) => v,
                Err(_) => {
                    self.fatal = true;
                    return RecvOutcome::Fatal;
                }
            };
            if jump == 2 {
                // Resolve the conflicting design rules by never accepting the skipped
                // epoch: it has no installed replay window.
                (key, next) = match chain_step(&next) {
                    Ok(v) => v,
                    Err(_) => {
                        self.fatal = true;
                        return RecvOutcome::Fatal;
                    }
                };
            }
            let mut candidate = Epoch {
                number: header.key_epoch,
                key,
                next,
                window: ReplayWindow::new(),
            };
            // Fuse authentication and replay acceptance before installing the
            // candidate: a forged future packet cannot advance the real chain.
            let opened = candidate.window.open_frame_and_accept(
                &candidate.key,
                &self.call_id,
                self.direction,
                header.key_epoch,
                header.packet_seq,
                header.media_type,
                body,
            );
            if opened.is_ok() {
                let old = std::mem::replace(&mut self.current, candidate);
                // Retain E only after an authenticated E+1, for late packets;
                // after E+2 neither E nor the skipped epoch remains accepting.
                self.previous = if jump == 1 { Some((old, now_ms)) } else { None };
            }
            opened
        };
        match result {
            Ok(plain) => {
                if plain.len() != FRAME_PLAINTEXT_LEN {
                    self.fatal = true;
                    return RecvOutcome::Fatal;
                }
                let mut out = Zeroizing::new([0u8; FRAME_PLAINTEXT_LEN]);
                out.copy_from_slice(&plain);
                self.failures = 0;
                // Route by stream kind so camera and screen frames never mix,
                // even with equal frame numbers.
                match header.media_type {
                    1 => RecvOutcome::Video(out),
                    2 => RecvOutcome::Screen(out),
                    _ => RecvOutcome::Audio(out),
                }
            }
            Err(MediaError::Authentication) => {
                self.failures = self.failures.saturating_add(1);
                if self.failures >= MAX_CONSECUTIVE_DROP {
                    self.fatal = true;
                    RecvOutcome::Fatal
                } else {
                    RecvOutcome::Dropped(DropReason::AuthFailed)
                }
            }
            Err(MediaError::Replay) => RecvOutcome::Dropped(DropReason::Replay),
            Err(MediaError::OutsideWindow) => RecvOutcome::Dropped(DropReason::OutsideWindow),
            Err(_) => {
                self.fatal = true;
                RecvOutcome::Fatal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::media::MEDIA_REKEY_SECONDS;
    use super::super::sender::MediaSender;
    use super::*;

    fn setup() -> (MediaSender, MediaReceiver) {
        let root = Zeroizing::new(std::array::from_fn(|_| rand::random::<u8>()));
        let id = std::array::from_fn(|_| rand::random::<u8>());
        (
            MediaSender::new(&root, id, Direction::Caller, 0).unwrap(),
            MediaReceiver::new(&root, id, Direction::Caller, 0).unwrap(),
        )
    }
    fn audio(out: RecvOutcome) -> bool {
        matches!(out, RecvOutcome::Audio(_))
    }
    fn dropped(out: RecvOutcome, reason: DropReason) -> bool {
        matches!(out, RecvOutcome::Dropped(r) if r == reason)
    }

    #[test]
    fn screen_stream_round_trips_and_separates_from_camera() {
        let (mut sender, mut receiver) = setup();
        // A camera frame (0x01) and a screen frame (0x02) on consecutive
        // sequence numbers: both authenticate and surface as distinct kinds,
        // so the caller can route them to separate video drivers.
        let camera = sender.next_packet_type(0, Some(&[0xAA]), 1).unwrap();
        let screen = sender.next_packet_type(0, Some(&[0xBB]), 2).unwrap();
        match receiver.receive(&camera, 0) {
            RecvOutcome::Video(frame) => assert_eq!(frame[0], 0xAA),
            _ => panic!("expected camera video"),
        }
        match receiver.receive(&screen, 0) {
            RecvOutcome::Screen(frame) => assert_eq!(frame[0], 0xBB),
            _ => panic!("expected screen"),
        }
        // A screen packet is distinct bytes from a camera packet even if the
        // stream kind byte is the only visible difference pre-auth: flipping
        // media_type breaks authentication (it is bound in the AAD). Forge a
        // fresh, not-yet-received screen packet (its own sequence number) so
        // the replay window lets it through to authentication; the AAD-bound
        // media_type then fails the tag check and the frame is AuthFailed.
        let fresh_screen = sender.next_packet_type(0, Some(&[0xCC]), 2).unwrap();
        let mut forged = fresh_screen.clone();
        forged[13] = 1;
        assert!(dropped(
            receiver.receive(&forged, 0),
            DropReason::AuthFailed
        ));
    }

    #[test]
    fn screen_and_camera_interleave_without_replay_confusion() {
        // Camera and screen share one sequence space (one nonce per seq), so a
        // long interleaved run never trips the replay window: each seq is used
        // once, by exactly one stream kind.
        let (mut sender, mut receiver) = setup();
        for i in 0..200u16 {
            let kind = if i % 2 == 0 { 1 } else { 2 };
            let packet = sender.next_packet_type(0, Some(&[i as u8]), kind).unwrap();
            match (kind, receiver.receive(&packet, 0)) {
                (1, RecvOutcome::Video(frame)) => assert_eq!(frame[0], i as u8),
                (2, RecvOutcome::Screen(frame)) => assert_eq!(frame[0], i as u8),
                _ => panic!("stream kind mismatch at {i}"),
            }
        }
    }

    #[test]
    fn ordered_shuffled_replay_and_forgery() {
        let (mut sender, mut receiver) = setup();
        for i in 0..300 {
            let packet = sender.next_packet(0, Some(&[i as u8])).unwrap();
            match receiver.receive(&packet, 0) {
                RecvOutcome::Audio(frame) => assert_eq!(frame[0], i as u8),
                _ => panic!("expected audio"),
            }
            if i == 0 {
                assert!(dropped(receiver.receive(&packet, 0), DropReason::Replay));
            }
        }
        let mut packets = Vec::new();
        for _ in 0..100 {
            packets.push(sender.next_packet(0, None).unwrap());
        }
        let mut forged = packets[0].clone();
        forged[5..13].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(dropped(
            receiver.receive(&forged, 0),
            DropReason::AuthFailed
        ));
        for packet in packets.iter().rev() {
            assert!(audio(receiver.receive(packet, 0)));
        }
    }

    #[test]
    fn adjacent_and_skipped_epochs() {
        let (mut sender, mut receiver) = setup();
        let late = sender.next_packet(0, None).unwrap();
        let expired = sender.next_packet(0, None).unwrap();
        let first = sender
            .next_packet(MEDIA_REKEY_SECONDS * 1000, None)
            .unwrap();
        assert!(audio(receiver.receive(&first, 30000)));
        assert!(audio(receiver.receive(&late, 30199)));
        assert!(dropped(
            receiver.receive(&expired, 30200),
            DropReason::StaleEpoch
        ));

        let (mut sender, mut receiver) = setup();
        let old = sender.next_packet(0, None).unwrap();
        let skipped = sender.next_packet(30000, None).unwrap();
        let future = sender.next_packet(60000, None).unwrap();
        let mut forged = future.clone();
        forged[14] ^= 1;
        assert!(dropped(
            receiver.receive(&forged, 60000),
            DropReason::AuthFailed
        ));
        assert!(audio(receiver.receive(&old, 60000)));
        assert!(audio(receiver.receive(&future, 60000)));
        assert!(dropped(
            receiver.receive(&skipped, 60000),
            DropReason::StaleEpoch
        ));
        let (mut sender, mut receiver) = setup();
        let _ = sender.next_packet(30000, None).unwrap();
        let _ = sender.next_packet(60000, None).unwrap();
        let third = sender.next_packet(90000, None).unwrap();
        assert!(dropped(
            receiver.receive(&third, 90000),
            DropReason::FutureEpoch
        ));
    }

    #[test]
    fn direction_failures_and_reset() {
        let (mut sender, mut receiver) = setup();
        let packet = sender.next_packet(0, None).unwrap();
        let mut wrong = packet.clone();
        wrong[1] = 1;
        assert!(dropped(
            receiver.receive(&wrong, 0),
            DropReason::WrongDirection
        ));
        let mut forged = packet.clone();
        forged[14] ^= 1;
        for _ in 0..49 {
            assert!(dropped(
                receiver.receive(&forged, 0),
                DropReason::AuthFailed
            ));
        }
        assert!(audio(receiver.receive(&packet, 0)));
        let packet = sender.next_packet(0, None).unwrap();
        let mut forged = packet.clone();
        forged[14] ^= 1;
        for _ in 0..49 {
            assert!(dropped(
                receiver.receive(&forged, 0),
                DropReason::AuthFailed
            ));
        }
        assert!(matches!(receiver.receive(&forged, 0), RecvOutcome::Fatal));
    }
}
