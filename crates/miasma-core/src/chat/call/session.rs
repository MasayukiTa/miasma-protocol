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
        for _ in 0..64 {
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
        if let Some(frame) = self.jitter.pop_ready() {
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
}
