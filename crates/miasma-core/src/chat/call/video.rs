//! Video path for calls: source/sink/encoder/decoder traits, a bounded
//! reassembly buffer, and an audio+video pacing scheduler.
//!
//! Design: design-call-security-v7e.md chapter 4 (the media_type 0x01 video
//! path) and the constant-bit-rate pacing of 繝ｻ繧托ｽｽ・ｧ4.4. This is pure library code:
//! it holds no socket, no device and no key material. It turns encoded video
//! frames into fixed 60-byte plaintext bodies (see [`super::video_frame`]) and
//! back, and decides how many video fragments ride alongside each audio packet
//! so the packet rate stays constant.
//!
//! Privacy: these types hold opaque bitstream bytes and counters only; no key,
//! nonce, call id or peer id is stored, logged or formatted here.

use std::collections::BTreeMap;

use super::media::FRAME_PLAINTEXT_LEN;
use super::video_frame::{
    fragment_frame, parse_fragment, FragmentHeader, VideoFrameError, FRAGMENT_PAYLOAD_LEN,
    MAX_FRAGMENTS_PER_FRAME,
};

/// An encoded video frame handed to or from a codec: opaque bitstream bytes
/// plus whether it is a keyframe. No codec is chosen in this slice.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct EncodedVideoFrame {
    pub keyframe: bool,
    pub data: Vec<u8>,
}

impl core::fmt::Debug for EncodedVideoFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EncodedVideoFrame")
    }
}

/// A raw (unencoded) video picture. In this slice it is an opaque byte buffer
/// with a size, so the test source/sink can move pictures without a codec.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct RawPicture {
    pub width: u16,
    pub height: u16,
    pub pixels: Vec<u8>,
}

impl core::fmt::Debug for RawPicture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RawPicture")
    }
}

/// Captures raw pictures. A real implementation wraps a camera; the test
/// implementation is a moving pattern.
pub trait VideoSource {
    fn is_open(&self) -> bool {
        false
    }

    fn next_picture(&mut self) -> Option<RawPicture>;
}

/// Builds the screen-share [`VideoSource`] on demand. The call runtime holds
/// one of these and asks it for a source only when the user starts sharing the
/// screen inside a connected, video-negotiated call; tests inject a fake
/// factory to drive the screen stream without touching a real display.
///
/// Returns `None` when no source can be opened (no display, denied, or the
/// capture backend is unavailable); the runtime then simply does not start the
/// screen stream.
pub trait ScreenSourceFactory: Send + Sync {
    fn create(&self) -> Option<Box<dyn VideoSource + Send>>;
}

/// Receives decoded raw pictures for display. A real implementation draws to a
/// surface; the test implementation records what it received.
pub trait VideoSink {
    fn put_picture(&mut self, picture: &RawPicture);
}

/// Encodes a raw picture into an encoded video frame. A real implementation
/// wraps a video encoder; the pseudo implementation copies bytes through.
pub trait VideoEncoder {
    fn encode(&mut self, picture: &RawPicture) -> Option<EncodedVideoFrame>;
    /// Ask the encoder to emit a keyframe on its next encode (after loss).
    fn request_keyframe(&mut self);
}

/// Decodes an encoded video frame into a raw picture. A real implementation
/// wraps a video decoder; the pseudo implementation reverses the pseudo
/// encoder.
pub trait VideoDecoder {
    fn decode(&mut self, frame: &EncodedVideoFrame) -> Option<RawPicture>;
}

impl<T: VideoSource + ?Sized> VideoSource for Box<T> {
    fn is_open(&self) -> bool {
        (**self).is_open()
    }
    fn next_picture(&mut self) -> Option<RawPicture> {
        (**self).next_picture()
    }
}
impl<T: VideoSink + ?Sized> VideoSink for Box<T> {
    fn put_picture(&mut self, picture: &RawPicture) {
        (**self).put_picture(picture)
    }
}
impl<T: VideoEncoder + ?Sized> VideoEncoder for Box<T> {
    fn encode(&mut self, picture: &RawPicture) -> Option<EncodedVideoFrame> {
        (**self).encode(picture)
    }
    fn request_keyframe(&mut self) {
        (**self).request_keyframe()
    }
}
impl<T: VideoDecoder + ?Sized> VideoDecoder for Box<T> {
    fn decode(&mut self, frame: &EncodedVideoFrame) -> Option<RawPicture> {
        (**self).decode(frame)
    }
}
/// At most this many video fragments ride alongside one audio packet per tick.
///
/// Derivation: audio paces one 90-byte packet per 20 ms tick (50 packets/s).
/// A reasonable call video target is about 1.5 Mbps peak. At 50 ticks/s that
/// is 1_500_000 / 8 / 50 = 3750 bytes per tick of video; each fragment carries
/// `FRAGMENT_PAYLOAD_LEN` (51) bitstream bytes, so 3750 / 51 驕ｶ霈斐・70 fragments.
/// We round to a named ceiling that keeps the combined rate bounded and
/// constant: audio (1) + video (`MAX_VIDEO_FRAGMENTS_PER_TICK`) packets per
/// tick, never more. Raising it raises the peak bit-rate linearly.
pub const MAX_VIDEO_FRAGMENTS_PER_TICK: usize = 70;

/// Default memory budget for the reassembly buffer, in bytes. It bounds how
/// much partially-received video the receiver holds at once. Chosen so a
/// handful of in-flight frames at the per-frame ceiling fit, and no more:
/// `MAX_FRAGMENTS_PER_FRAME` * `FRAGMENT_PAYLOAD_LEN` is one full frame's
/// payload; this budget holds a few of those.
pub const DEFAULT_REASSEMBLY_BUDGET_BYTES: usize =
    4 * MAX_FRAGMENTS_PER_FRAME as usize * FRAGMENT_PAYLOAD_LEN;

/// The outcome of offering one fragment to the reassembly buffer.
#[derive(Clone, PartialEq, Eq)]
pub enum Reassembled {
    /// The fragment was accepted; the frame is still incomplete.
    Pending,
    /// This fragment completed a frame; here are its reassembled bytes and
    /// whether it was a keyframe.
    Complete(EncodedVideoFrame),
    /// The fragment was dropped (malformed body, inconsistent header, or it
    /// belonged to a frame already evicted). No state changed.
    Dropped,
}

impl core::fmt::Debug for Reassembled {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let len = match self {
            Self::Complete(frame) => frame.data.len(),
            Self::Pending | Self::Dropped => 0,
        };
        f.debug_struct("Reassembled").field("len", &len).finish()
    }
}

/// One frame being reassembled: the fragments received so far, keyed by index.
struct PartialFrame {
    fragment_count: u16,
    keyframe: bool,
    first_seen_ms: u64,
    encoded_length: Option<usize>,
    fragments: BTreeMap<u16, [u8; FRAGMENT_PAYLOAD_LEN]>,
}

impl PartialFrame {
    fn bytes_held(&self) -> usize {
        self.fragments.len() * FRAGMENT_PAYLOAD_LEN
    }
}

/// Reassembles video frames from 60-byte fragment bodies with a bounded memory
/// budget and a per-frame timeout. When an incomplete frame times out or must
/// be evicted to stay within budget, it is dropped and the buffer records that
/// a keyframe should be requested.
pub struct ReassemblyBuffer {
    partials: BTreeMap<u16, PartialFrame>,
    budget_bytes: usize,
    held_bytes: usize,
    timeout_ms: u64,
    keyframe_requested: bool,
}

impl ReassemblyBuffer {
    /// A buffer with an explicit memory budget and per-frame timeout.
    pub fn new(budget_bytes: usize, timeout_ms: u64) -> Self {
        ReassemblyBuffer {
            partials: BTreeMap::new(),
            budget_bytes,
            held_bytes: 0,
            timeout_ms,
            keyframe_requested: false,
        }
    }

    /// How many bytes of partial frames are currently held.
    pub fn held_bytes(&self) -> usize {
        self.held_bytes
    }

    /// Whether a keyframe is owed (a frame was dropped). Reading clears it.
    pub fn take_keyframe_request(&mut self) -> bool {
        let owed = self.keyframe_requested;
        self.keyframe_requested = false;
        owed
    }

    /// Drop any frame first seen more than `timeout_ms` before `now_ms`.
    pub fn expire(&mut self, now_ms: u64) {
        let timeout = self.timeout_ms;
        let stale: Vec<u16> = self
            .partials
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.first_seen_ms) >= timeout)
            .map(|(&n, _)| n)
            .collect();
        for n in stale {
            self.evict(n);
        }
    }

    fn evict(&mut self, frame_number: u16) {
        if let Some(p) = self.partials.remove(&frame_number) {
            self.held_bytes -= p.bytes_held();
            self.keyframe_requested = true;
        }
    }

    /// Evict oldest partial frames until one more fragment fits in the budget.
    fn make_room_for_one(&mut self) {
        while self.held_bytes + FRAGMENT_PAYLOAD_LEN > self.budget_bytes {
            let oldest = match self.partials.keys().next().copied() {
                Some(n) => n,
                None => break,
            };
            self.evict(oldest);
        }
    }

    /// Offer one 60-byte fragment body to the buffer at time `now_ms`.
    ///
    /// Returns [`Reassembled::Complete`] with the frame bytes when the last
    /// missing fragment arrives, [`Reassembled::Pending`] while incomplete,
    /// or [`Reassembled::Dropped`] for a malformed body or one belonging to a
    /// frame that cannot be held. Never panics on hostile input.
    pub fn offer(&mut self, body: &[u8], now_ms: u64) -> Reassembled {
        let (header, payload) = match parse_fragment(body) {
            Ok(v) => v,
            Err(_) => return Reassembled::Dropped,
        };
        self.offer_parsed(&header, payload, now_ms)
    }

    fn offer_parsed(
        &mut self,
        header: &FragmentHeader,
        payload: &[u8],
        now_ms: u64,
    ) -> Reassembled {
        if payload.len() != FRAGMENT_PAYLOAD_LEN {
            return Reassembled::Dropped;
        }
        // Drop a late fragment for a frame we no longer hold only if its index
        // is out of range; otherwise start/append to the partial frame.
        if header.fragment_count == 0 || header.fragment_count > MAX_FRAGMENTS_PER_FRAME {
            return Reassembled::Dropped;
        }
        if header.fragment_index >= header.fragment_count {
            return Reassembled::Dropped;
        }

        let mut chunk = [0u8; FRAGMENT_PAYLOAD_LEN];
        chunk.copy_from_slice(payload);

        if self.budget_bytes < FRAGMENT_PAYLOAD_LEN {
            self.keyframe_requested = true;
            return Reassembled::Dropped;
        }
        // Ensure room for one more fragment before inserting.
        let is_new_fragment = match self.partials.get(&header.frame_number) {
            Some(p) => !p.fragments.contains_key(&header.fragment_index),
            None => true,
        };
        if is_new_fragment {
            self.make_room_for_one();
            // If making room evicted the very frame we are adding to, it will
            // simply be recreated below as a fresh partial.
        }

        let entry = self
            .partials
            .entry(header.frame_number)
            .or_insert_with(|| PartialFrame {
                fragment_count: header.fragment_count,
                keyframe: header.keyframe,
                first_seen_ms: now_ms,
                encoded_length: None,
                fragments: BTreeMap::new(),
            });
        // A fragment_count that disagrees with the frame we are building is
        // hostile or corrupt: drop the whole frame.
        if entry.fragment_count != header.fragment_count || entry.keyframe != header.keyframe {
            self.evict(header.frame_number);
            return Reassembled::Dropped;
        }
        if header.fragment_index == 0 {
            if entry
                .encoded_length
                .is_some_and(|length| length != header.encoded_length as usize)
            {
                self.evict(header.frame_number);
                return Reassembled::Dropped;
            }
            entry.encoded_length = Some(header.encoded_length as usize);
        }
        if entry
            .fragments
            .insert(header.fragment_index, chunk)
            .is_none()
        {
            self.held_bytes += FRAGMENT_PAYLOAD_LEN;
        }

        let complete = {
            let entry = &self.partials[&header.frame_number];
            entry.fragments.len() == entry.fragment_count as usize
        };
        if !complete {
            return Reassembled::Pending;
        }

        // Assemble in index order and remove the final fragment padding.
        let partial = self.partials.remove(&header.frame_number).unwrap();
        self.held_bytes -= partial.bytes_held();
        let mut data = Vec::with_capacity(partial.fragments.len() * FRAGMENT_PAYLOAD_LEN);
        for (_, chunk) in partial.fragments.iter() {
            data.extend_from_slice(chunk);
        }
        if let Some(length) = partial.encoded_length {
            data.truncate(length);
        } else {
            return Reassembled::Dropped;
        }
        Reassembled::Complete(EncodedVideoFrame {
            keyframe: partial.keyframe,
            data,
        })
    }
}

/// What one scheduler tick produced: one audio body plus zero or more video
/// fragment bodies, in send order. Each body is a fixed 60-byte plaintext.
pub struct TickFill {
    pub audio: [u8; FRAME_PLAINTEXT_LEN],
    pub video: Vec<[u8; FRAME_PLAINTEXT_LEN]>,
}

/// Fills each constant-rate tick with exactly one audio packet and at most
/// [`MAX_VIDEO_FRAGMENTS_PER_TICK`] video fragments drawn from a queue of
/// pending fragments. The scheduler never emits more than that per tick, so
/// audio + video together keep the packet rate bounded.
pub struct SendScheduler {
    pending: std::collections::VecDeque<[u8; FRAME_PLAINTEXT_LEN]>,
    max_video_per_tick: usize,
}

impl SendScheduler {
    pub fn new() -> Self {
        SendScheduler {
            pending: std::collections::VecDeque::new(),
            max_video_per_tick: MAX_VIDEO_FRAGMENTS_PER_TICK,
        }
    }

    /// A scheduler with an explicit per-tick video ceiling (for tests).
    pub fn with_ceiling(max_video_per_tick: usize) -> Self {
        SendScheduler {
            pending: std::collections::VecDeque::new(),
            max_video_per_tick,
        }
    }

    /// Queue an encoded video frame's fragments for later ticks. Returns the
    /// number of fragments queued, or an error if the frame cannot be split.
    pub fn enqueue_frame(
        &mut self,
        frame_number: u16,
        frame: &EncodedVideoFrame,
    ) -> Result<usize, VideoFrameError> {
        let bodies = fragment_frame(frame_number, frame.keyframe, &frame.data)?;
        let n = bodies.len();
        for body in bodies {
            self.pending.push_back(body);
        }
        Ok(n)
    }

    /// How many video fragments are waiting to be sent.
    pub fn pending_fragments(&self) -> usize {
        self.pending.len()
    }

    /// Produce one tick: the given audio body plus up to the ceiling of video
    /// fragments. Total packets this tick = 1 + video.len(), always within
    /// 1 + `max_video_per_tick`.
    pub fn tick(&mut self, audio: [u8; FRAME_PLAINTEXT_LEN]) -> TickFill {
        let take = self.max_video_per_tick.min(self.pending.len());
        let mut video = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(body) = self.pending.pop_front() {
                video.push(body);
            }
        }
        TickFill { audio, video }
    }
}

impl Default for SendScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// --- Pseudo implementations for tests -----------------------------------

/// A moving test-pattern source: each picture is a solid ramp whose value
/// advances per frame, so a sink can assert the exact bytes and their order.
pub struct TestPatternSource {
    counter: u8,
    width: u16,
    height: u16,
    size: usize,
}

impl TestPatternSource {
    pub fn new(width: u16, height: u16, size: usize) -> Self {
        TestPatternSource {
            counter: 0,
            width,
            height,
            size,
        }
    }
}

impl VideoSource for TestPatternSource {
    fn next_picture(&mut self) -> Option<RawPicture> {
        let pixels = vec![self.counter; self.size];
        self.counter = self.counter.wrapping_add(1);
        Some(RawPicture {
            width: self.width,
            height: self.height,
            pixels,
        })
    }
}

/// A recording sink that keeps every picture it was given, in order.
pub struct RecordingVideoSink {
    pictures: Vec<RawPicture>,
}

impl RecordingVideoSink {
    pub fn new() -> Self {
        RecordingVideoSink {
            pictures: Vec::new(),
        }
    }
    pub fn pictures(&self) -> &[RawPicture] {
        &self.pictures
    }
}

impl Default for RecordingVideoSink {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoSink for RecordingVideoSink {
    fn put_picture(&mut self, picture: &RawPicture) {
        self.pictures.push(picture.clone());
    }
}

/// A [`VideoSink`] that drops every received picture. Used as the receive end
/// of the local screen-share driver: outgoing screen frames are what matter,
/// and nothing locally renders the loopback of our own screen stream.
#[derive(Default)]
pub struct DiscardVideoSink;

impl VideoSink for DiscardVideoSink {
    fn put_picture(&mut self, _picture: &RawPicture) {}
}

/// A pseudo encoder/decoder pair that carries the raw pixels through as the
/// "bitstream", with a one-byte size-independent tag so the decoder can
/// reproduce the picture geometry. No real compression; this exists only so
/// the fragmentation and reassembly path can be exercised end to end.
pub struct PassthroughCodec {
    want_keyframe: bool,
    frames_since_keyframe: u32,
}

impl PassthroughCodec {
    pub fn new() -> Self {
        PassthroughCodec {
            want_keyframe: true,
            frames_since_keyframe: 0,
        }
    }
}

impl Default for PassthroughCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl VideoEncoder for PassthroughCodec {
    fn encode(&mut self, picture: &RawPicture) -> Option<EncodedVideoFrame> {
        // Encode geometry as a 4-byte prefix so the decoder can rebuild it.
        let mut data = Vec::with_capacity(4 + picture.pixels.len());
        data.extend_from_slice(&picture.width.to_be_bytes());
        data.extend_from_slice(&picture.height.to_be_bytes());
        data.extend_from_slice(&picture.pixels);
        let keyframe = self.want_keyframe || self.frames_since_keyframe >= 50;
        if keyframe {
            self.want_keyframe = false;
            self.frames_since_keyframe = 0;
        } else {
            self.frames_since_keyframe = self.frames_since_keyframe.saturating_add(1);
        }
        Some(EncodedVideoFrame { keyframe, data })
    }
    fn request_keyframe(&mut self) {
        self.want_keyframe = true;
    }
}

impl VideoDecoder for PassthroughCodec {
    fn decode(&mut self, frame: &EncodedVideoFrame) -> Option<RawPicture> {
        if frame.data.len() < 4 {
            return None;
        }
        let width = u16::from_be_bytes([frame.data[0], frame.data[1]]);
        let height = u16::from_be_bytes([frame.data[2], frame.data[3]]);
        Some(RawPicture {
            width,
            height,
            pixels: frame.data[4..].to_vec(),
        })
    }
}

/// Drives pseudo or injected video components once per media tick.
/// Control packets use fragment_count zero and body byte 6 equal to 1 to
/// request a keyframe; all remaining bytes in the fixed body are zero.
pub struct VideoDriver<S, K, E, D> {
    source: S,
    sink: K,
    encoder: E,
    decoder: D,
    scheduler: SendScheduler,
    reassembly: ReassemblyBuffer,
    frame_interval_ms: u64,
    next_frame_ms: u64,
    frame_number: u16,
    last_completed: Option<u16>,
    last_gap_request_ms: Option<u64>,
    gap_request_pending: bool,
    /// The most recently decoded remote picture, waiting to be taken by the
    /// media task so it can be published for the UI. Replaced each time a
    /// frame decodes; taking it clears the slot. Holds pixel bytes only, no
    /// key, nonce, call id or peer id.
    last_decoded: Option<RawPicture>,
    pub frames_sent: u64,
    pub frames_played: u64,
}

impl<S: VideoSource, K: VideoSink, E: VideoEncoder, D: VideoDecoder> VideoDriver<S, K, E, D> {
    pub fn new(source: S, sink: K, encoder: E, decoder: D, frame_interval_ms: u64) -> Self {
        Self {
            source,
            sink,
            encoder,
            decoder,
            scheduler: SendScheduler::new(),
            reassembly: ReassemblyBuffer::new(DEFAULT_REASSEMBLY_BUDGET_BYTES, 500),
            frame_interval_ms: frame_interval_ms.max(20),
            next_frame_ms: 0,
            frame_number: 0,
            last_completed: None,
            last_gap_request_ms: None,
            gap_request_pending: false,
            last_decoded: None,
            frames_sent: 0,
            frames_played: 0,
        }
    }

    pub fn tick(&mut self, now_ms: u64) -> Vec<[u8; FRAME_PLAINTEXT_LEN]> {
        self.tick_with_budget(now_ms, MAX_VIDEO_FRAGMENTS_PER_TICK)
    }

    pub fn tick_with_budget(
        &mut self,
        now_ms: u64,
        budget: usize,
    ) -> Vec<[u8; FRAME_PLAINTEXT_LEN]> {
        self.reassembly.expire(now_ms);
        let request = self.reassembly.take_keyframe_request() || self.gap_request_pending;
        self.gap_request_pending = false;
        if now_ms >= self.next_frame_ms && self.scheduler.pending_fragments() == 0 {
            self.next_frame_ms = now_ms.saturating_add(self.frame_interval_ms);
            if let Some(frame) = self
                .source
                .next_picture()
                .and_then(|picture| self.encoder.encode(&picture))
            {
                if self
                    .scheduler
                    .enqueue_frame(self.frame_number, &frame)
                    .is_ok()
                {
                    self.frame_number = self.frame_number.wrapping_add(1);
                    self.frames_sent = self.frames_sent.saturating_add(1);
                }
            }
        }

        if request {
            let mut control = [0; FRAME_PLAINTEXT_LEN];
            control[6] = 1;
            self.scheduler.pending.push_front(control);
        }
        let take = budget
            .min(self.scheduler.max_video_per_tick)
            .min(self.scheduler.pending.len());
        self.scheduler.pending.drain(..take).collect()
    }

    pub fn receive(&mut self, body: &[u8], now_ms: u64) {
        if body.len() != FRAME_PLAINTEXT_LEN {
            return;
        }
        if body[4] == 0 && body[5] == 0 {
            if body[6] == 1
                && body[..6].iter().all(|&b| b == 0)
                && body[7..].iter().all(|&b| b == 0)
            {
                self.encoder.request_keyframe();
            }
            return;
        }
        if let Reassembled::Complete(frame) = self.reassembly.offer(body, now_ms) {
            if let Ok((header, _)) = parse_fragment(body) {
                let number = header.frame_number;
                if let Some(previous) = self.last_completed {
                    let distance = number.wrapping_sub(previous);
                    if distance > 0 && distance < 0x8000 {
                        if distance > 1
                            && self
                                .last_gap_request_ms
                                .map_or(true, |last| now_ms >= last && now_ms - last >= 1_000)
                        {
                            self.gap_request_pending = true;
                            self.last_gap_request_ms = Some(now_ms);
                        }
                        self.last_completed = Some(number);
                    }
                } else {
                    self.last_completed = Some(number);
                }
            }
            if let Some(picture) = self.decoder.decode(&frame) {
                self.sink.put_picture(&picture);
                self.last_decoded = Some(picture);
                self.frames_played = self.frames_played.saturating_add(1);
            }
        }
    }

    pub fn source_is_open(&self) -> bool {
        self.source.is_open()
    }

    pub fn sink(&self) -> &K {
        &self.sink
    }

    /// Take the most recently decoded remote picture, if one arrived since the
    /// last take, clearing the slot. The media task calls this each tick to
    /// publish the latest frame for the UI without cloning on every tick.
    pub fn take_decoded_picture(&mut self) -> Option<RawPicture> {
        self.last_decoded.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drivers_exchange_frames_over_memory_link() {
        let driver = || {
            VideoDriver::new(
                TestPatternSource::new(8, 8, 100),
                RecordingVideoSink::new(),
                PassthroughCodec::new(),
                PassthroughCodec::new(),
                20,
            )
        };
        let mut a = driver();
        let mut b = driver();
        let mut a_to_b = std::collections::VecDeque::new();
        let mut b_to_a = std::collections::VecDeque::new();
        for time in (0..100).step_by(20) {
            a_to_b.extend(a.tick(time));
            b_to_a.extend(b.tick(time));
            while let Some(packet) = a_to_b.pop_front() {
                b.receive(&packet, time);
            }
            while let Some(packet) = b_to_a.pop_front() {
                a.receive(&packet, time);
            }
        }
        assert!(a.frames_sent >= 3 && b.frames_sent >= 3);
        assert!(a.frames_played >= 3 && b.frames_played >= 3);
        assert!(a.sink().pictures().len() >= 3 && b.sink().pictures().len() >= 3);
    }
    #[test]
    fn drivers_exchange_and_request_keyframe_after_loss() {
        fn driver(
        ) -> VideoDriver<TestPatternSource, RecordingVideoSink, PassthroughCodec, PassthroughCodec>
        {
            VideoDriver::new(
                TestPatternSource::new(8, 8, 100),
                RecordingVideoSink::new(),
                PassthroughCodec::new(),
                PassthroughCodec::new(),
                20,
            )
        }
        let mut a = driver();
        let mut b = driver();
        let a_first = a.tick(0);
        let b_first = b.tick(0);
        for packet in &a_first {
            b.receive(packet, 0);
        }
        for packet in &b_first {
            a.receive(packet, 0);
        }
        assert_eq!(a.frames_played, 1);
        assert_eq!(b.frames_played, 1);
        assert_eq!(a.sink().pictures()[0].pixels.len(), 100);
        let lost = a.tick(20);
        for packet in lost.iter().skip(1) {
            b.receive(packet, 20);
        }
        for packet in b.tick(520) {
            a.receive(&packet, 520);
        }
        let next = a.tick(520);
        assert!(!next.is_empty());
        assert!(parse_fragment(&next[0]).unwrap().0.keyframe);
        for packet in &next {
            b.receive(packet, 520);
        }
        assert_eq!(a.frames_sent, 3);
        assert_eq!(b.frames_played, 2);
    }
    #[test]
    fn whole_frame_loss_requests_keyframe_with_rate_limit() {
        let mut receiver = VideoDriver::new(
            TestPatternSource::new(8, 8, 100),
            RecordingVideoSink::new(),
            PassthroughCodec::new(),
            PassthroughCodec::new(),
            20,
        );
        let frame = encoded(100, false);
        for (number, time) in [(0, 0), (2, 20), (4, 40), (6, 1020)] {
            for body in fragment_frame(number, false, &frame.data).unwrap() {
                receiver.receive(&body, time);
            }
            let packets = receiver.tick(time);
            let requests = packets
                .iter()
                .filter(|body| body[4] == 0 && body[5] == 0 && body[6] == 1)
                .count();
            assert_eq!(requests, usize::from(number == 2 || number == 6));
        }
    }
    fn encoded(len: usize, keyframe: bool) -> EncodedVideoFrame {
        EncodedVideoFrame {
            keyframe,
            data: (0..len).map(|i| (i % 251) as u8).collect(),
        }
    }

    // Fragment then reassemble a frame of many sizes, in order and shuffled.
    #[test]
    fn reassembly_round_trip_many_sizes() {
        for len in [1usize, 53, 54, 106, 500, 2000, 8192] {
            let frame = encoded(len, true);
            let bodies = fragment_frame(1, true, &frame.data).unwrap();
            let mut buf = ReassemblyBuffer::new(DEFAULT_REASSEMBLY_BUDGET_BYTES, 1000);
            let mut done = None;
            // shuffle: offer odd indices then even indices
            let order: Vec<usize> = (0..bodies.len())
                .filter(|i| i % 2 == 1)
                .chain((0..bodies.len()).filter(|i| i % 2 == 0))
                .collect();
            for &i in &order {
                if let Reassembled::Complete(f) = buf.offer(&bodies[i], 0) {
                    done = Some(f);
                }
            }
            let got = done.expect("frame should complete");
            // The reassembled bitstream is the fragments concatenated, with the
            // final fragment zero-padded; the original is its prefix.
            assert_eq!(got.data.len(), frame.data.len());
            assert_eq!(&got.data[..frame.data.len()], &frame.data[..]);
            assert!(got.keyframe);
            assert_eq!(buf.held_bytes(), 0);
        }
    }

    // Losing exactly one fragment drops exactly that frame and asks for a
    // keyframe; a later complete frame still assembles.
    #[test]
    fn one_lost_fragment_drops_that_frame() {
        let frame = encoded(500, false);
        let bodies = fragment_frame(5, false, &frame.data).unwrap();
        assert!(bodies.len() >= 3);
        let mut buf = ReassemblyBuffer::new(DEFAULT_REASSEMBLY_BUDGET_BYTES, 100);
        // offer all but the last fragment
        for body in &bodies[..bodies.len() - 1] {
            assert_eq!(buf.offer(body, 0), Reassembled::Pending);
        }
        // time passes beyond the timeout; the incomplete frame is dropped
        buf.expire(100);
        assert_eq!(buf.held_bytes(), 0);
        assert!(buf.take_keyframe_request());
        // a fresh, complete frame still assembles
        let frame2 = encoded(120, true);
        let bodies2 = fragment_frame(6, true, &frame2.data).unwrap();
        let mut done = None;
        for body in &bodies2 {
            if let Reassembled::Complete(f) = buf.offer(body, 200) {
                done = Some(f);
            }
        }
        assert!(done.is_some());
    }

    // The memory budget is never exceeded, even under a flood of partial
    // frames that never complete.
    #[test]
    fn memory_budget_never_exceeded() {
        let budget = 10 * FRAGMENT_PAYLOAD_LEN;
        let mut buf = ReassemblyBuffer::new(budget, 10_000);
        // Many distinct frames, each contributing one fragment of a 3-fragment
        // frame, so none ever completes and all stay partial.
        for frame_number in 0..1000u16 {
            let frame = encoded(3 * FRAGMENT_PAYLOAD_LEN, false);
            let bodies = fragment_frame(frame_number, false, &frame.data).unwrap();
            buf.offer(&bodies[0], frame_number as u64);
            assert!(
                buf.held_bytes() <= budget,
                "held {} > budget {}",
                buf.held_bytes(),
                budget
            );
        }
    }

    // The scheduler never emits more than 1 + ceiling packets per tick, so the
    // combined audio+video packet rate stays bounded.
    #[test]
    fn pacing_never_exceeds_packet_rate() {
        let ceiling = 4;
        let mut sched = SendScheduler::with_ceiling(ceiling);
        // enqueue a large frame: many more fragments than one tick can carry
        let frame = encoded(ceiling * FRAGMENT_PAYLOAD_LEN * 10, true);
        let total = sched.enqueue_frame(0, &frame).unwrap();
        assert!(total > ceiling);
        let audio = [0u8; FRAME_PLAINTEXT_LEN];
        let mut drained = 0;
        for _ in 0..1000 {
            let fill = sched.tick(audio);
            assert!(
                fill.video.len() <= ceiling,
                "tick emitted too many video fragments"
            );
            // total packets this tick = 1 audio + video
            assert!(1 + fill.video.len() <= 1 + ceiling);
            drained += fill.video.len();
            if sched.pending_fragments() == 0 {
                break;
            }
        }
        assert_eq!(drained, total, "all fragments eventually sent");
    }

    // Default ceiling derivation stays a sane, bounded constant.
    #[test]
    fn default_ceiling_is_bounded() {
        assert_eq!(MAX_VIDEO_FRAGMENTS_PER_TICK, 70);
    }

    // The pseudo codec + fragmentation form an end-to-end moving-pattern path:
    // source -> encode -> fragment -> reassemble -> decode -> sink, and the
    // sink sees the same moving pattern the source produced.
    #[test]
    fn end_to_end_test_pattern() {
        let mut source = TestPatternSource::new(16, 16, 100);
        let mut sink = RecordingVideoSink::new();
        let mut codec = PassthroughCodec::new();
        let mut buf = ReassemblyBuffer::new(DEFAULT_REASSEMBLY_BUDGET_BYTES, 10_000);
        for frame_number in 0..5u16 {
            let picture = source.next_picture().unwrap();
            let encoded = codec.encode(&picture).unwrap();
            let bodies = fragment_frame(frame_number, encoded.keyframe, &encoded.data).unwrap();
            for body in &bodies {
                if let Reassembled::Complete(f) = buf.offer(body, frame_number as u64) {
                    // trim the padding back to the original encoded length
                    let mut trimmed = f.clone();
                    trimmed.data.truncate(encoded.data.len());
                    if let Some(pic) = codec.decode(&trimmed) {
                        sink.put_picture(&pic);
                    }
                }
            }
        }
        assert_eq!(sink.pictures().len(), 5);
        for (i, pic) in sink.pictures().iter().enumerate() {
            assert_eq!(pic.width, 16);
            assert_eq!(pic.height, 16);
            assert!(pic.pixels.iter().all(|&b| b == i as u8));
        }
    }
}
