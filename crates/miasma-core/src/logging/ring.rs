//! Bounded in-memory log buffer.
//!
//! One `Box<[u8]>` of fixed size holds the newest lines as `[len: u16][bytes]`
//! records laid end to end in a circle. A new line that does not fit makes the
//! oldest lines drop until it does. Nothing is allocated after construction,
//! so the buffer's memory use is its capacity no matter how much is logged.

/// Default capacity: 2 MiB.
pub const DEFAULT_CAPACITY: usize = 2 * 1024 * 1024;
/// Smallest and largest capacity a caller may ask for.
pub const MIN_CAPACITY: usize = 1024 * 1024;
pub const MAX_CAPACITY: usize = 8 * 1024 * 1024;
/// A line longer than this is cut (at a character boundary).
pub const MAX_LINE: usize = 512;

const HDR: usize = 2;

#[derive(Debug)]
pub struct RingBuffer {
    buf: Box<[u8]>,
    /// Where the next record is written.
    head: usize,
    /// Where the oldest record starts.
    tail: usize,
    /// Bytes in use (headers included).
    used: usize,
    /// Records currently held.
    lines: u64,
    /// Sequence number the next pushed line gets. The oldest held line has
    /// number `next_seq - lines`.
    next_seq: u64,
}

/// Lines read from the buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Slice {
    pub lines: Vec<String>,
    /// Pass this as `from` to continue after the last returned line.
    pub next_seq: u64,
}

impl RingBuffer {
    /// A buffer of `capacity` bytes (clamped to 1-8 MiB).
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.clamp(MIN_CAPACITY, MAX_CAPACITY);
        Self::with_exact_capacity(cap)
    }

    /// As [`new`](Self::new) without the clamp. Only for tests that want a
    /// tiny buffer.
    pub fn with_exact_capacity(cap: usize) -> Self {
        assert!(cap >= MAX_LINE + HDR + 1, "ring too small");
        Self {
            buf: vec![0u8; cap].into_boxed_slice(),
            head: 0,
            tail: 0,
            used: 0,
            lines: 0,
            next_seq: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn used_bytes(&self) -> usize {
        self.used
    }

    pub fn len(&self) -> usize {
        self.lines as usize
    }

    pub fn is_empty(&self) -> bool {
        self.lines == 0
    }

    /// Sequence number of the next line to be pushed.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    fn first_seq(&self) -> u64 {
        self.next_seq - self.lines
    }

    fn wrap(&self, pos: usize) -> usize {
        if pos >= self.buf.len() {
            pos - self.buf.len()
        } else {
            pos
        }
    }

    fn read_len(&self, pos: usize) -> usize {
        let hi = self.buf[pos] as usize;
        let lo = self.buf[self.wrap(pos + 1)] as usize;
        (hi << 8) | lo
    }

    fn drop_oldest(&mut self) {
        debug_assert!(self.lines > 0);
        let len = self.read_len(self.tail);
        let rec = HDR + len;
        self.tail = self.wrap(self.tail + rec);
        self.used -= rec;
        self.lines -= 1;
    }

    fn write_bytes(&mut self, mut pos: usize, data: &[u8]) -> usize {
        let cap = self.buf.len();
        let first = (cap - pos).min(data.len());
        self.buf[pos..pos + first].copy_from_slice(&data[..first]);
        pos += first;
        if first < data.len() {
            let rest = data.len() - first;
            self.buf[..rest].copy_from_slice(&data[first..]);
            pos = rest;
        }
        self.wrap(pos)
    }

    /// Append one line (a trailing newline is not stored). Returns its
    /// sequence number.
    pub fn push(&mut self, line: &str) -> u64 {
        let line = line.trim_end_matches(['\n', '\r']);
        let mut n = line.len().min(MAX_LINE);
        while !line.is_char_boundary(n) {
            n -= 1;
        }
        let rec = HDR + n;
        while self.buf.len() - self.used < rec {
            self.drop_oldest();
        }
        let hdr = [(n >> 8) as u8, (n & 0xff) as u8];
        let mut pos = self.write_bytes(self.head, &hdr);
        pos = self.write_bytes(pos, &line.as_bytes()[..n]);
        self.head = pos;
        self.used += rec;
        self.lines += 1;
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    fn copy_out(&self, pos: usize, len: usize) -> String {
        let cap = self.buf.len();
        let mut out = Vec::with_capacity(len);
        let first = (cap - pos).min(len);
        out.extend_from_slice(&self.buf[pos..pos + first]);
        if first < len {
            out.extend_from_slice(&self.buf[..len - first]);
        }
        // Lines were cut at a character boundary, so this never substitutes;
        // a lossy conversion keeps a corrupted buffer from panicking a reader.
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Read lines.
    ///
    /// * `from`: first sequence number wanted (`None` = the newest `max_lines`).
    ///   A number older than the oldest held line starts at the oldest.
    /// * `max_lines`: at most this many lines.
    /// * `max_bytes`: at most this many bytes of line text in total (the reply
    ///   to a client is bounded by it). With `from == None` the newest lines
    ///   win; otherwise the oldest wanted lines do.
    pub fn read(&self, from: Option<u64>, max_lines: usize, max_bytes: usize) -> Slice {
        let first = self.first_seq();
        let skipped = match from {
            Some(s) => s.saturating_sub(first).min(self.lines),
            None => self.lines.saturating_sub(max_lines as u64),
        };
        let mut pos = self.tail;
        for _ in 0..skipped {
            pos = self.wrap(pos + HDR + self.read_len(pos));
        }
        let mut seq = first + skipped;
        let end = self.next_seq;
        let mut lines: Vec<String> = Vec::new();
        let mut bytes = 0usize;
        while seq < end && lines.len() < max_lines {
            let len = self.read_len(pos);
            if bytes + len > max_bytes && from.is_some() {
                break;
            }
            let s = self.copy_out(self.wrap(pos + HDR), len);
            bytes += len;
            lines.push(s);
            pos = self.wrap(pos + HDR + len);
            seq += 1;
        }
        if from.is_none() && bytes > max_bytes {
            // Newest lines win: drop from the front until it fits.
            let mut over = bytes - max_bytes;
            let mut drop_n = 0;
            for l in &lines {
                if over == 0 {
                    break;
                }
                over = over.saturating_sub(l.len());
                drop_n += 1;
            }
            lines.drain(..drop_n);
        }
        Slice {
            lines,
            next_seq: seq,
        }
    }

    /// Forget every line and overwrite the memory with zeros.
    pub fn clear(&mut self) {
        self.buf.fill(0);
        self.head = 0;
        self.tail = 0;
        self.used = 0;
        self.lines = 0;
        // `next_seq` keeps counting so a follower does not see numbers repeat.
    }
}
