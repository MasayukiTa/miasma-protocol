//! Synchronous media glue. Construct one session per call and drop it at
//! hangup: dropping the sender and receiver zeroizes their key chains.
//! The caller drives one tick per 20 ms using a monotonic clock.
use super::device::{AudioSink, AudioSource};
use super::jitter::JitterBuffer;
use super::media::{Direction, FRAME_WIRE_LEN};
use super::packet::split_packet;
use super::receiver::{MediaReceiver, RecvOutcome};
use super::sender::MediaSender;
use zeroize::Zeroizing;

// Bound receive work per tick across all media types, including malformed packets.
const MAX_RECEIVE_PACKETS_PER_TICK: usize = 64;

// The caller drives one tick per 20 ms, so the constant packet rate is
// 1000 / 20 = 50 packets per second. Audio uses one of those packets per tick;
// the remaining budget is shared by the camera and screen video streams.
const TICK_INTERVAL_MS: u64 = 20;
const PACKET_RATE_PER_SECOND: u64 = 1000 / TICK_INTERVAL_MS;

// The screen-share stream is paced far below the camera: a named low rate of
// 5 whole frames per second. Derivation: at PACKET_RATE_PER_SECOND (50) ticks
// per second, serving the screen once every PACKET_RATE_PER_SECOND / 5 = 10
// ticks yields 5 screen frames per second. A screen frame is still fragmented
// across ticks like any video frame; this constant bounds how often a *new*
// screen frame may begin, not how many fragments ride per tick.
const SCREEN_FRAMES_PER_SECOND: u64 = 5;
const TICKS_PER_SCREEN_FRAME: u64 = PACKET_RATE_PER_SECOND / SCREEN_FRAMES_PER_SECOND;

// media_type bytes on the wire: 0x00 audio, 0x01 camera video, 0x02 screen
// share. Screen uses the same media AEAD and key labels as camera; only the
// stream kind differs so the two never mix.
const MEDIA_TYPE_CAMERA: u8 = 1;
const MEDIA_TYPE_SCREEN: u8 = 2;

pub trait DatagramLink: Send {
    fn max_len(&self) -> usize;
    fn send(&mut self, packet: &[u8]) -> bool;
    fn try_recv(&mut self) -> Option<Vec<u8>>;
}

impl DatagramLink for Box<dyn DatagramLink> {
    fn max_len(&self) -> usize {
        (**self).max_len()
    }
    fn send(&mut self, packet: &[u8]) -> bool {
        (**self).send(packet)
    }
    fn try_recv(&mut self) -> Option<Vec<u8>> {
        (**self).try_recv()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    DatagramTooSmall,
    Media,
}
impl core::fmt::Debug for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::DatagramTooSmall => "DatagramTooSmall",
            Self::Media => "Media",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickStatus {
    Running,
    Fatal,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub sent: u64,
    pub send_failed: u64,
    pub received_ok: u64,
    pub dropped: u64,
    pub played: u64,
    pub late_dropped: u64,
    /// Whole video frames fully fragmented and handed to the sender.
    pub video_frames_sent: u64,
    /// Whole video frames reassembled and handed to the sink.
    pub video_frames_played: u64,
}

pub struct MediaSession<S: AudioSource, K: AudioSink, L: DatagramLink> {
    sender: Option<MediaSender>,
    receiver: Option<MediaReceiver>,
    jitter: JitterBuffer,
    source: S,
    sink: K,
    link: L,
    stats: SessionStats,
}
impl<S: AudioSource, K: AudioSink, L: DatagramLink> MediaSession<S, K, L> {
    pub fn new(
        root: &Zeroizing<[u8; 32]>,
        call_id: [u8; 16],
        direction: Direction,
        now_ms: u64,
        source: S,
        sink: K,
        link: L,
    ) -> Result<Self, SessionError> {
        Self::with_roots(root, root, call_id, direction, now_ms, source, sink, link)
    }
    pub fn with_roots(
        send_root: &Zeroizing<[u8; 32]>,
        recv_root: &Zeroizing<[u8; 32]>,
        call_id: [u8; 16],
        direction: Direction,
        now_ms: u64,
        source: S,
        sink: K,
        link: L,
    ) -> Result<Self, SessionError> {
        if link.max_len() < FRAME_WIRE_LEN {
            return Err(SessionError::DatagramTooSmall);
        }
        let peer_direction = match direction {
            Direction::Caller => Direction::Callee,
            Direction::Callee => Direction::Caller,
        };
        let sender = MediaSender::new(send_root, call_id, direction, now_ms)
            .map_err(|_| SessionError::Media)?;
        let receiver = MediaReceiver::new(recv_root, call_id, peer_direction, now_ms)
            .map_err(|_| SessionError::Media)?;
        Ok(Self {
            sender: Some(sender),
            receiver: Some(receiver),
            jitter: JitterBuffer::new(),
            source,
            sink,
            link,
            stats: SessionStats::default(),
        })
    }
    fn fatal(&mut self) -> TickStatus {
        self.stats.late_dropped = self.jitter.late_dropped;
        self.sender = None;
        self.receiver = None;
        self.jitter = JitterBuffer::new();
        TickStatus::Fatal
    }
    pub fn tick(&mut self, now_ms: u64) -> TickStatus {
        self.tick_with_media(now_ms, &[], &[], |_, _| {}, |_, _| {})
    }

    /// Serve audio plus a single camera video stream (media_type 0x01). Kept
    /// for callers that do not share a screen; it forwards to
    /// [`Self::tick_with_media`] with an empty screen stream.
    pub fn tick_with_video(
        &mut self,
        now_ms: u64,
        video: &[[u8; super::media::FRAME_PLAINTEXT_LEN]],
        receive_video: impl FnMut(&[u8], u64),
    ) -> TickStatus {
        self.tick_with_media(now_ms, video, &[], receive_video, |_, _| {})
    }

    /// Serve audio, the camera video stream (media_type 0x01) and the screen
    /// share stream (media_type 0x02) within one constant-rate tick.
    ///
    /// Pacing: audio always takes one packet. The remaining per-tick video
    /// budget is [`super::video::MAX_VIDEO_FRAGMENTS_PER_TICK`] fragments,
    /// shared by the two video streams so the combined packet rate never
    /// exceeds the constant rate (1 audio + at most that many video packets).
    /// Camera fragments are served first, up to the full budget. Whatever the
    /// camera leaves unused is offered to the screen stream, so when the
    /// camera is off (no camera fragments this tick) the screen stream may use
    /// the camera's entire share. The screen stream is itself paced to a low
    /// rate upstream (see [`SCREEN_FRAMES_PER_SECOND`] and
    /// [`TICKS_PER_SCREEN_FRAME`]); this method only enforces the shared
    /// per-tick ceiling.
    ///
    /// Received camera bodies are handed to `receive_video` and received
    /// screen bodies to `receive_screen`, split by their wire media_type so
    /// camera and screen frames never mix even with equal frame numbers.
    pub fn tick_with_media(
        &mut self,
        now_ms: u64,
        video: &[[u8; super::media::FRAME_PLAINTEXT_LEN]],
        screen: &[[u8; super::media::FRAME_PLAINTEXT_LEN]],
        mut receive_video: impl FnMut(&[u8], u64),
        mut receive_screen: impl FnMut(&[u8], u64),
    ) -> TickStatus {
        let sender = match self.sender.as_mut() {
            Some(sender) => sender,
            None => return TickStatus::Fatal,
        };
        let frame = self.source.next_frame().map(Zeroizing::new);
        let packet = match sender.next_packet(now_ms, frame.as_ref().map(|f| &f[..])) {
            Ok(packet) => packet,
            Err(_) => return self.fatal(),
        };
        if self.link.send(&packet) {
            self.stats.sent = self.stats.sent.saturating_add(1);
        } else {
            self.stats.send_failed = self.stats.send_failed.saturating_add(1);
        }
        // Camera first, up to the whole per-tick video budget.
        let budget = super::video::MAX_VIDEO_FRAGMENTS_PER_TICK;
        let camera_sent = video.len().min(budget);
        for body in video.iter().take(camera_sent) {
            let packet = match sender.next_packet_type(now_ms, Some(body), MEDIA_TYPE_CAMERA) {
                Ok(packet) => packet,
                Err(_) => return self.fatal(),
            };
            if !self.link.send(&packet) {
                self.stats.send_failed = self.stats.send_failed.saturating_add(1);
            }
        }
        // Screen uses only the budget the camera left unused this tick, so the
        // combined video fragment count is at most `budget`. With the camera
        // off, camera_sent is 0 and the screen may use the full budget.
        let screen_room = budget.saturating_sub(camera_sent);
        for body in screen.iter().take(screen_room) {
            let packet = match sender.next_packet_type(now_ms, Some(body), MEDIA_TYPE_SCREEN) {
                Ok(packet) => packet,
                Err(_) => return self.fatal(),
            };
            if !self.link.send(&packet) {
                self.stats.send_failed = self.stats.send_failed.saturating_add(1);
            }
        }
        for _ in 0..MAX_RECEIVE_PACKETS_PER_TICK {
            let packet = match self.link.try_recv() {
                Some(packet) => packet,
                None => break,
            };
            let outcome = match self.receiver.as_mut() {
                Some(receiver) => receiver.receive(&packet, now_ms),
                None => return self.fatal(),
            };
            match outcome {
                RecvOutcome::Audio(frame) => {
                    self.stats.received_ok = self.stats.received_ok.saturating_add(1);
                    if let Ok((header, _)) = split_packet(&packet) {
                        self.jitter.push(header.packet_seq, frame);
                    }
                }
                // The receiver has already separated the streams by their
                // authenticated media_type, so camera (0x01) and screen (0x02)
                // bodies arrive as distinct outcomes and reach separate
                // drivers; they never mix even with equal frame numbers.
                RecvOutcome::Video(body) => receive_video(&body[..], now_ms),
                RecvOutcome::Screen(body) => receive_screen(&body[..], now_ms),
                RecvOutcome::Dropped(_) => {
                    self.stats.dropped = self.stats.dropped.saturating_add(1)
                }
                RecvOutcome::Fatal => {
                    self.stats.dropped = self.stats.dropped.saturating_add(1);
                    return self.fatal();
                }
            }
        }
        self.stats.late_dropped = self.jitter.late_dropped;
        if let Some((gap, frame)) = self.jitter.pop_ready_gap() {
            // Each skipped sequence is a lost frame; let the sink conceal it
            // before the next real frame. A byte-level sink ignores this; a
            // decoding sink runs packet-loss concealment. Bound the run so a
            // huge gap cannot stall the tick.
            for _ in 0..gap.min(8) {
                self.sink.conceal();
            }
            self.sink.play(&frame);
            self.stats.played = self.stats.played.saturating_add(1);
        }
        TickStatus::Running
    }
    pub fn stats(&self) -> SessionStats {
        self.stats
    }
    pub fn sink(&self) -> &K {
        &self.sink
    }
    /// Record that one whole video frame was fragmented and handed to the
    /// sender. The video fragments ride in the same fixed-size packets as
    /// audio (media_type 0x01); a video driver built on
    /// [`super::video::SendScheduler`] calls this once per source frame.
    pub fn note_video_frame_sent(&mut self) {
        self.stats.video_frames_sent = self.stats.video_frames_sent.saturating_add(1);
    }
    /// Record that one whole video frame was reassembled and handed to the
    /// sink. A video driver built on [`super::video::ReassemblyBuffer`] calls
    /// this once per completed frame.
    pub fn note_video_frame_played(&mut self) {
        self.stats.video_frames_played = self.stats.video_frames_played.saturating_add(1);
    }
    /// Access the source between ticks, for example to apply a mute change.
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }
}

#[cfg(test)]
mod tests {
    use super::super::device::{RecordingSink, ToneSource};
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    // The video counters start at zero and advance only when a video driver
    // reports a whole frame sent or played; audio ticks never touch them.
    #[test]
    fn video_counters_advance_independently() {
        let root = root();
        let id = id();
        let (link, _) = LoopLink::pair();
        let mut session = make(&root, id, Direction::Caller, link);
        assert_eq!(session.stats().video_frames_sent, 0);
        assert_eq!(session.stats().video_frames_played, 0);
        session.tick(0);
        assert_eq!(session.stats().video_frames_sent, 0);
        assert_eq!(session.stats().video_frames_played, 0);
        session.note_video_frame_sent();
        session.note_video_frame_sent();
        session.note_video_frame_played();
        assert_eq!(session.stats().video_frames_sent, 2);
        assert_eq!(session.stats().video_frames_played, 1);
    }

    #[test]
    fn video_drivers_exchange_over_link() {
        use super::super::video::{
            PassthroughCodec, RecordingVideoSink, TestPatternSource, VideoDriver,
        };
        let root = root();
        let id = id();
        let (left, right) = LoopLink::pair();
        let mut a = make(&root, id, Direction::Caller, left);
        let mut b = make(&root, id, Direction::Callee, right);
        let driver = || {
            VideoDriver::new(
                TestPatternSource::new(8, 8, 100),
                RecordingVideoSink::new(),
                PassthroughCodec::new(),
                PassthroughCodec::new(),
                20,
            )
        };
        let mut av = driver();
        let mut bv = driver();
        for n in 0..5 {
            let now = n * 20;
            let packets = av.tick(now);
            a.tick_with_video(now, &packets, |body, time| av.receive(body, time));
            let packets = bv.tick(now);
            b.tick_with_video(now, &packets, |body, time| bv.receive(body, time));
        }
        assert!(av.frames_sent >= 3 && bv.frames_sent >= 3);
        assert!(av.frames_played >= 3 && bv.frames_played >= 3);
    }

    // Camera (0x01) and screen (0x02) run as two independent video drivers
    // over one session link. Each side pumps both a camera driver and a screen
    // driver through tick_with_media; the receive callbacks route by stream
    // kind to the matching driver. Both streams complete frames, and neither
    // driver ever receives the other's bodies, so their buffers stay separate
    // even though both number frames from zero.
    #[test]
    fn camera_and_screen_drivers_round_trip_without_mixing() {
        use super::super::video::{
            PassthroughCodec, RecordingVideoSink, TestPatternSource, VideoDriver,
        };
        let root = root();
        let id = id();
        let (left, right) = LoopLink::pair();
        let mut a = make(&root, id, Direction::Caller, left);
        let mut b = make(&root, id, Direction::Callee, right);
        // Distinct picture sizes per stream so a body delivered to the wrong
        // driver would decode to the wrong geometry and fail the assertions.
        let camera_driver = || {
            VideoDriver::new(
                TestPatternSource::new(8, 8, 100),
                RecordingVideoSink::new(),
                PassthroughCodec::new(),
                PassthroughCodec::new(),
                20,
            )
        };
        let screen_driver = || {
            VideoDriver::new(
                TestPatternSource::new(16, 12, 120),
                RecordingVideoSink::new(),
                PassthroughCodec::new(),
                PassthroughCodec::new(),
                20,
            )
        };
        let mut a_cam = camera_driver();
        let mut a_scr = screen_driver();
        let mut b_cam = camera_driver();
        let mut b_scr = screen_driver();
        for n in 0..8 {
            let now = n * 20;
            let cam = a_cam.tick(now);
            let scr = a_scr.tick(now);
            a.tick_with_media(
                now,
                &cam,
                &scr,
                |body, time| a_cam.receive(body, time),
                |body, time| a_scr.receive(body, time),
            );
            let cam = b_cam.tick(now);
            let scr = b_scr.tick(now);
            b.tick_with_media(
                now,
                &cam,
                &scr,
                |body, time| b_cam.receive(body, time),
                |body, time| b_scr.receive(body, time),
            );
        }
        // Both kinds completed frames on both peers.
        assert!(a_cam.frames_played >= 3 && b_cam.frames_played >= 3);
        assert!(a_scr.frames_played >= 3 && b_scr.frames_played >= 3);
        // The streams never mixed: each sink only ever saw its own geometry.
        for sink in [a_cam.sink(), b_cam.sink()] {
            assert!(sink
                .pictures()
                .iter()
                .all(|p| p.width == 8 && p.height == 8));
        }
        for sink in [a_scr.sink(), b_scr.sink()] {
            assert!(sink
                .pictures()
                .iter()
                .all(|p| p.width == 16 && p.height == 12));
        }
    }
    struct LoopLink {
        incoming: Arc<Mutex<VecDeque<Vec<u8>>>>,
        outgoing: Arc<Mutex<VecDeque<Vec<u8>>>>,
        max: usize,
        sends: u64,
        drop_every: u64,
        flood: usize,
    }
    impl LoopLink {
        fn pair() -> (Self, Self) {
            let a = Arc::new(Mutex::new(VecDeque::new()));
            let b = Arc::new(Mutex::new(VecDeque::new()));
            let make = |incoming, outgoing| Self {
                incoming,
                outgoing,
                max: 90,
                sends: 0,
                drop_every: 0,
                flood: 0,
            };
            (make(a.clone(), b.clone()), make(b, a))
        }
    }
    impl DatagramLink for LoopLink {
        fn max_len(&self) -> usize {
            self.max
        }
        fn send(&mut self, packet: &[u8]) -> bool {
            self.sends = self.sends.saturating_add(1);
            if self.drop_every != 0 && self.sends % self.drop_every == 0 {
                return false;
            }
            let mut queue = self.outgoing.lock().unwrap();
            if queue.len() >= 4096 {
                return false;
            }
            queue.push_back(packet.to_vec());
            true
        }
        fn try_recv(&mut self) -> Option<Vec<u8>> {
            if self.flood > 0 {
                self.flood -= 1;
                return Some(vec![0; 90]);
            }
            self.incoming.lock().unwrap().pop_front()
        }
    }
    fn root() -> Zeroizing<[u8; 32]> {
        Zeroizing::new(std::array::from_fn(|_| rand::random()))
    }
    fn id() -> [u8; 16] {
        std::array::from_fn(|_| rand::random())
    }
    fn make(
        root: &Zeroizing<[u8; 32]>,
        id: [u8; 16],
        direction: Direction,
        link: LoopLink,
    ) -> MediaSession<ToneSource, RecordingSink, LoopLink> {
        MediaSession::new(
            root,
            id,
            direction,
            0,
            ToneSource::new(),
            RecordingSink::new(),
            link,
        )
        .unwrap()
    }
    #[test]
    fn ordered_both_ways() {
        let root = root();
        let id = id();
        let (a, b) = LoopLink::pair();
        let mut a = make(&root, id, Direction::Caller, a);
        let mut b = make(&root, id, Direction::Callee, b);
        for n in 0..300 {
            assert_eq!(a.tick(n * 20), TickStatus::Running);
            assert_eq!(b.tick(n * 20), TickStatus::Running);
        }
        for frames in [a.sink().frames(), b.sink().frames()] {
            assert!(frames.len() >= 299);
            for (i, frame) in frames.iter().enumerate().skip(1) {
                assert!(frame.iter().all(|byte| *byte == i as u8));
            }
        }
        assert_eq!(a.stats().sent, 300);
        assert_eq!(b.stats().sent, 300);
        assert_eq!(a.stats().received_ok, 299);
        assert_eq!(b.stats().received_ok, 300);
        assert_eq!(a.stats().played, 299);
        assert_eq!(b.stats().played, 300);
        assert_eq!(a.stats().dropped, 0);
        assert_eq!(b.stats().late_dropped, 0);
    }
    #[test]
    fn directional_roots_and_authentication() {
        let first = Zeroizing::new([1; 32]);
        let second = Zeroizing::new([2; 32]);
        let id = id();
        let (a, b) = LoopLink::pair();
        let mut a = MediaSession::with_roots(
            &first,
            &second,
            id,
            Direction::Caller,
            0,
            ToneSource::new(),
            RecordingSink::new(),
            a,
        )
        .unwrap();
        let mut b = MediaSession::with_roots(
            &second,
            &first,
            id,
            Direction::Callee,
            0,
            ToneSource::new(),
            RecordingSink::new(),
            b,
        )
        .unwrap();
        for n in 0..100 {
            assert_eq!(a.tick(n * 20), TickStatus::Running);
            assert_eq!(b.tick(n * 20), TickStatus::Running);
        }
        assert!(a.stats().played > 0 && b.stats().played > 0);
        let (a, b) = LoopLink::pair();
        let mut a = MediaSession::with_roots(
            &first,
            &second,
            id,
            Direction::Caller,
            0,
            ToneSource::new(),
            RecordingSink::new(),
            a,
        )
        .unwrap();
        let mut b = MediaSession::with_roots(
            &first,
            &second,
            id,
            Direction::Callee,
            0,
            ToneSource::new(),
            RecordingSink::new(),
            b,
        )
        .unwrap();
        let mut fatal = false;
        for n in 0..100 {
            let x = a.tick(n * 20);
            let y = b.tick(n * 20);
            if x == TickStatus::Fatal || y == TickStatus::Fatal {
                fatal = true;
                break;
            }
        }
        assert!(fatal);
        assert_eq!(a.stats().played, 0);
        assert_eq!(b.stats().played, 0);
    }
    #[test]
    fn too_small_and_losses() {
        let root = root();
        let id = id();
        let (mut a, b) = LoopLink::pair();
        a.max = 89;
        assert!(matches!(
            MediaSession::new(
                &root,
                id,
                Direction::Caller,
                0,
                ToneSource::new(),
                RecordingSink::new(),
                a
            ),
            Err(SessionError::DatagramTooSmall)
        ));
        let (mut a, _) = LoopLink::pair();
        a.drop_every = 3;
        // Connect the lossy sender to the original receiver.
        a.outgoing = b.incoming.clone();
        let mut a = make(&root, id, Direction::Caller, a);
        let mut b = make(&root, id, Direction::Callee, b);
        for n in 0..300 {
            a.tick(n * 20);
            b.tick(n * 20);
        }
        assert_eq!(a.stats().sent, 200);
        assert_eq!(a.stats().send_failed, 100);
        assert_eq!(b.stats().received_ok, 200);
        assert_eq!(b.stats().played, 200);
        for (i, frame) in b.sink().frames().iter().enumerate() {
            let expected = (i + i / 2) as u8;
            assert!(frame.iter().all(|byte| *byte == expected));
        }
    }
    #[test]
    fn flood_is_bounded() {
        let root = root();
        let id = id();
        let (mut link, _) = LoopLink::pair();
        link.flood = 100_000;
        let mut session = make(&root, id, Direction::Caller, link);
        assert_eq!(session.tick(0), TickStatus::Running);
        assert_eq!(session.stats().dropped, 64);
        assert_eq!(session.link.flood, 99_936);
    }
    #[test]
    fn mixed_media_flood_shares_receive_budget() {
        let root = root();
        let id = id();
        let (link, _) = LoopLink::pair();
        let incoming = link.incoming.clone();
        let mut sender = MediaSender::new(&root, id, Direction::Callee, 0).unwrap();
        for i in 0..80 {
            let packet = sender.next_packet_type(0, None, (i % 2) as u8).unwrap();
            incoming.lock().unwrap().push_back(packet);
        }
        let mut session = make(&root, id, Direction::Caller, link);
        let mut videos = 0;
        assert_eq!(
            session.tick_with_video(0, &[], |_, _| videos += 1),
            TickStatus::Running
        );
        assert_eq!(session.stats().received_ok, 32);
        assert_eq!(videos, 32);
        assert_eq!(incoming.lock().unwrap().len(), 16);
    }
    #[test]
    fn authentication_failure_stops_and_drops_chains() {
        let root = root();
        let id = id();
        let (link, _) = LoopLink::pair();
        let incoming = link.incoming.clone();
        let mut sender = MediaSender::new(&root, id, Direction::Callee, 0).unwrap();
        for _ in 0..50 {
            let mut packet = sender.next_packet(0, None).unwrap();
            for byte in &mut packet[14..] {
                *byte = rand::random();
            }
            incoming.lock().unwrap().push_back(packet);
        }
        let mut session = make(&root, id, Direction::Caller, link);
        assert_eq!(session.tick(0), TickStatus::Fatal);
        assert_eq!(session.stats().dropped, 50);
        assert_eq!(session.stats().sent, 1);
        assert!(session.sender.is_none() && session.receiver.is_none());
        assert_eq!(session.tick(20), TickStatus::Fatal);
        assert_eq!(session.stats().sent, 1);
        assert_eq!(session.stats().played, 0);
    }

    // The pacing constants stay a sane, bounded derivation of the 20 ms tick.
    #[test]
    fn pacing_constants_derive_from_packet_rate() {
        assert_eq!(TICK_INTERVAL_MS, 20);
        assert_eq!(PACKET_RATE_PER_SECOND, 50);
        assert_eq!(SCREEN_FRAMES_PER_SECOND, 5);
        assert_eq!(TICKS_PER_SCREEN_FRAME, 10);
        assert_eq!(MEDIA_TYPE_CAMERA, 1);
        assert_eq!(MEDIA_TYPE_SCREEN, 2);
    }

    // Count the media_type byte of every packet queued on `outgoing` and drain
    // it. Header byte 13 is the media_type (see packet.rs encode_header).
    fn drain_media_types(outgoing: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> (usize, usize, usize) {
        let mut queue = outgoing.lock().unwrap();
        let (mut audio, mut camera, mut screen) = (0, 0, 0);
        while let Some(packet) = queue.pop_front() {
            let (header, _) = split_packet(&packet).unwrap();
            match header.media_type {
                0 => audio += 1,
                1 => camera += 1,
                2 => screen += 1,
                other => panic!("unexpected media_type {other}"),
            }
        }
        (audio, camera, screen)
    }

    // Screen fragments go out as media_type 0x02, distinct from camera's 0x01,
    // so the two streams never mix on the wire.
    #[test]
    fn screen_fragments_use_media_type_two() {
        let root = root();
        let id = id();
        let (link, _peer) = LoopLink::pair();
        let outgoing = link.outgoing.clone();
        let mut session = make(&root, id, Direction::Caller, link);
        let camera = [[1u8; super::super::media::FRAME_PLAINTEXT_LEN]; 2];
        let screen = [[2u8; super::super::media::FRAME_PLAINTEXT_LEN]; 3];
        assert_eq!(
            session.tick_with_media(0, &camera, &screen, |_, _| {}, |_, _| {}),
            TickStatus::Running
        );
        let (audio, camera_n, screen_n) = drain_media_types(&outgoing);
        assert_eq!(audio, 1);
        assert_eq!(camera_n, 2);
        assert_eq!(screen_n, 3);
    }

    // Camera and screen share one per-tick video budget: their combined
    // fragment count never exceeds MAX_VIDEO_FRAGMENTS_PER_TICK, and the
    // camera is served first so the screen gets only the remainder.
    #[test]
    fn camera_and_screen_share_tick_budget() {
        let budget = super::super::video::MAX_VIDEO_FRAGMENTS_PER_TICK;
        let root = root();
        let id = id();
        let (link, _peer) = LoopLink::pair();
        let outgoing = link.outgoing.clone();
        let mut session = make(&root, id, Direction::Caller, link);
        // Offer more of each than the budget; camera takes most of it.
        let camera = vec![[1u8; super::super::media::FRAME_PLAINTEXT_LEN]; budget - 3];
        let screen = vec![[2u8; super::super::media::FRAME_PLAINTEXT_LEN]; budget];
        assert_eq!(
            session.tick_with_media(0, &camera, &screen, |_, _| {}, |_, _| {}),
            TickStatus::Running
        );
        let (audio, camera_n, screen_n) = drain_media_types(&outgoing);
        assert_eq!(audio, 1);
        assert_eq!(camera_n, budget - 3);
        // Only the 3 leftover slots go to the screen this tick.
        assert_eq!(screen_n, 3);
        assert!(camera_n + screen_n <= budget);
    }

    // When the camera is off (no camera fragments this tick), the screen
    // stream may use the camera's entire share, up to the full budget.
    #[test]
    fn screen_uses_full_budget_when_camera_off() {
        let budget = super::super::video::MAX_VIDEO_FRAGMENTS_PER_TICK;
        let root = root();
        let id = id();
        let (link, _peer) = LoopLink::pair();
        let outgoing = link.outgoing.clone();
        let mut session = make(&root, id, Direction::Caller, link);
        let screen = vec![[2u8; super::super::media::FRAME_PLAINTEXT_LEN]; budget + 5];
        assert_eq!(
            session.tick_with_media(0, &[], &screen, |_, _| {}, |_, _| {}),
            TickStatus::Running
        );
        let (audio, camera_n, screen_n) = drain_media_types(&outgoing);
        assert_eq!(audio, 1);
        assert_eq!(camera_n, 0);
        assert_eq!(screen_n, budget);
        assert!(screen_n <= budget);
    }

    // tick_with_video stays camera-only: it never emits a 0x02 screen packet,
    // preserving the existing single-stream behaviour.
    #[test]
    fn tick_with_video_emits_no_screen() {
        let root = root();
        let id = id();
        let (link, _peer) = LoopLink::pair();
        let outgoing = link.outgoing.clone();
        let mut session = make(&root, id, Direction::Caller, link);
        let camera = [[1u8; super::super::media::FRAME_PLAINTEXT_LEN]; 4];
        assert_eq!(
            session.tick_with_video(0, &camera, |_, _| {}),
            TickStatus::Running
        );
        let (audio, camera_n, screen_n) = drain_media_types(&outgoing);
        assert_eq!(audio, 1);
        assert_eq!(camera_n, 4);
        assert_eq!(screen_n, 0);
    }
}
