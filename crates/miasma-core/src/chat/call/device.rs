//! Audio device ports and deterministic fakes used by CI. A future audio device
//! only needs to implement these traits; no real device is used here.
use super::media::FRAME_PLAINTEXT_LEN;

pub trait AudioSource: Send {
    /// None means no frame is ready for this tick.
    fn next_frame(&mut self) -> Option<[u8; FRAME_PLAINTEXT_LEN]>;
}
pub trait AudioSink: Send {
    fn play(&mut self, frame: &[u8; FRAME_PLAINTEXT_LEN]);
}

/// Repeating counter pattern, with one counter value per frame.
#[derive(Default)]
pub struct ToneSource {
    counter: u8,
}
impl ToneSource {
    pub fn new() -> Self {
        Self::default()
    }
}
impl AudioSource for ToneSource {
    fn next_frame(&mut self) -> Option<[u8; FRAME_PLAINTEXT_LEN]> {
        let frame = [self.counter; FRAME_PLAINTEXT_LEN];
        self.counter = self.counter.wrapping_add(1);
        Some(frame)
    }
}

/// Stores up to 4096 frames and counts further frames.
#[derive(Default)]
pub struct RecordingSink {
    frames: Vec<[u8; FRAME_PLAINTEXT_LEN]>,
    overflow: u64,
}
impl RecordingSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn frames(&self) -> &[[u8; FRAME_PLAINTEXT_LEN]] {
        &self.frames
    }
    pub fn overflow(&self) -> u64 {
        self.overflow
    }
}
impl AudioSink for RecordingSink {
    fn play(&mut self, frame: &[u8; FRAME_PLAINTEXT_LEN]) {
        if self.frames.len() < 4096 {
            self.frames.push(*frame);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }
}
