//! Fixed-size audio jitter queue, ordered by packet sequence.
use super::media::FRAME_PLAINTEXT_LEN;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const JITTER_MAX: usize = 100;
pub const INFLIGHT_BYTES_MAX: usize = 256 * 1024;
pub struct JitterBuffer {
    frames: BTreeMap<u64, Zeroizing<[u8; FRAME_PLAINTEXT_LEN]>>,
    played: Option<u64>,
    pub late_dropped: u64,
}
impl JitterBuffer {
    pub fn new() -> Self {
        Self {
            frames: BTreeMap::new(),
            played: None,
            late_dropped: 0,
        }
    }
    /// Drop new arrivals at capacity; duplicates do not replace buffered audio.
    pub fn push(&mut self, seq: u64, frame: Zeroizing<[u8; FRAME_PLAINTEXT_LEN]>) {
        if self.played.map_or(false, |played| seq <= played) {
            self.late_dropped = self.late_dropped.saturating_add(1);
            return;
        }
        if self.frames.len() >= JITTER_MAX
            || (self.frames.len() + 1) * FRAME_PLAINTEXT_LEN > INFLIGHT_BYTES_MAX
        {
            return;
        }
        self.frames.entry(seq).or_insert(frame);
    }
    /// Play the lowest currently buffered sequence, skipping missing frames.
    pub fn pop_ready(&mut self) -> Option<Zeroizing<[u8; FRAME_PLAINTEXT_LEN]>> {
        let (seq, frame) = self.frames.pop_first()?;
        self.played = Some(seq);
        Some(frame)
    }
    pub fn len(&self) -> usize {
        self.frames.len()
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}
impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(value: u8) -> Zeroizing<[u8; FRAME_PLAINTEXT_LEN]> {
        Zeroizing::new([value; FRAME_PLAINTEXT_LEN])
    }
    #[test]
    fn ordering_capacity_and_late() {
        let mut buffer = JitterBuffer::new();
        for seq in (0..100).rev() {
            buffer.push(seq, frame(seq as u8));
        }
        for seq in 100..100_000 {
            buffer.push(seq, frame(0));
        }
        assert_eq!(buffer.len(), 100);
        for seq in 0..100 {
            assert_eq!(buffer.pop_ready().unwrap()[0], seq as u8);
        }
        buffer.push(99, frame(0));
        assert_eq!(buffer.late_dropped, 1);
        assert!(buffer.is_empty());
    }
}
