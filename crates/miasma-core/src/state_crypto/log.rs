//! Record-log shape: append-only, streamed, tolerant of a torn tail.
//!
//! ```text
//! header (22 bytes)
//!      0     4  magic "MSL1"
//!      4     1  format version (1)
//!      5     1  label id
//!      6    16  random file salt
//! then, repeated:
//!      0     4  body length, little endian (40 ..= 40 + 64 KiB)
//!      4    24  nonce = 16 random bytes | record number (u64, big endian)
//!     28     n  ciphertext
//!   28+n    16  Poly1305 tag
//! ```
//!
//! The file key is derived from the class key and the file salt, so no two
//! files share a key. Associated data = `magic | version | label id | file
//! salt | record number`: a record moved to another position, another file or
//! another class fails to open. A record holds at most 64 KiB of plaintext.
//!
//! **Torn tail.** A crash can leave the last record partly written. Such a
//! record (incomplete, or complete but failing authentication at the very end
//! of the file, or a run of zero bytes where a record would start) is dropped:
//! readers stop before it and the writer cuts the file back to the last good
//! record before it appends. A bad record *before* the end is damage, not a
//! torn write, and is reported as an error.
//!
//! Memory is bounded: a reader holds one record and a 64 KiB read buffer;
//! it never loads the file.

use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use super::{
    fsync_path, open_detached, seal_detached, sync_parent_dir, Label, StateError, StateKeys,
    LOG_MAGIC, NONCE_LEN, TAG_LEN,
};
use crate::crypto::keyderive;

pub const LOG_VERSION: u8 = 1;
pub const LOG_HEADER_LEN: usize = 4 + 1 + 1 + 16;

const MIN_BODY: usize = NONCE_LEN + TAG_LEN;

const IO_BUF: usize = 64 * 1024;

/// Key and identity of one open log file.
struct Core {
    key: Zeroizing<[u8; 32]>,
    label: Label,
    salt: [u8; 16],
}

impl Core {
    fn new(keys: &StateKeys, label: Label, salt: [u8; 16]) -> Self {
        let doc_key = keys.doc_key(label);
        let key = keyderive::derive_state_log_key(doc_key.as_ref(), &salt)
            .expect("HKDF expand of 32 bytes cannot fail");
        Self { key, label, salt }
    }

    fn max_body(&self) -> usize {
        NONCE_LEN + self.label.max_record_bytes() + TAG_LEN
    }

    fn header(&self) -> [u8; LOG_HEADER_LEN] {
        let mut h = [0u8; LOG_HEADER_LEN];
        h[..4].copy_from_slice(LOG_MAGIC);
        h[4] = LOG_VERSION;
        h[5] = self.label.id();
        h[6..].copy_from_slice(&self.salt);
        h
    }

    fn aad(&self, seq: u64) -> [u8; 30] {
        let mut a = [0u8; 30];
        a[..4].copy_from_slice(LOG_MAGIC);
        a[4] = LOG_VERSION;
        a[5] = self.label.id();
        a[6..22].copy_from_slice(&self.salt);
        a[22..].copy_from_slice(&seq.to_be_bytes());
        a
    }

    /// Decrypt a record body (`nonce | ciphertext | tag`) in place and return
    /// the plaintext. The body buffer is left holding plaintext: callers wipe it.
    fn open_body(&self, seq: u64, body: &mut [u8]) -> Result<Zeroizing<Vec<u8>>, StateError> {
        let nonce: [u8; NONCE_LEN] = body[..NONCE_LEN].try_into().expect("slice length");
        if nonce[16..] != seq.to_be_bytes() {
            return Err(StateError::Authentication);
        }
        let tag_at = body.len() - TAG_LEN;
        let (head, tag) = body.split_at_mut(tag_at);
        open_detached(
            &self.key,
            &nonce,
            &self.aad(seq),
            &mut head[NONCE_LEN..],
            tag,
        )?;
        Ok(Zeroizing::new(head[NONCE_LEN..].to_vec()))
    }
}

fn parse_header(h: &[u8; LOG_HEADER_LEN], label: Label) -> Result<[u8; 16], StateError> {
    if &h[..4] != LOG_MAGIC {
        return Err(StateError::NotProtected);
    }
    if h[4] != LOG_VERSION {
        return Err(StateError::UnsupportedVersion(h[4]));
    }
    if h[5] != label.id() {
        return Err(StateError::WrongLabel {
            expected: label.id(),
            found: h[5],
        });
    }
    Ok(h[6..].try_into().expect("slice length"))
}

fn is_unexpected_eof(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof
}

/// Read exactly `n` bytes.
fn read_vec<R: Read>(r: &mut R, n: usize) -> std::io::Result<Vec<u8>> {
    let mut v = Vec::with_capacity(n);
    r.by_ref().take(n as u64).read_to_end(&mut v)?;
    if v.len() != n {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(v)
}

/// Read exactly `N` bytes into an array.
fn read_array<const N: usize, R: Read>(r: &mut R) -> std::io::Result<[u8; N]> {
    read_vec(r, N)?
        .try_into()
        .map_err(|_| std::io::ErrorKind::UnexpectedEof.into())
}

/// True when the next `count` bytes of `r` are all zero. (Only inspects file
/// layout; nothing here is key material.)
fn rest_is_zero<R: Read>(r: &mut R, mut count: u64) -> std::io::Result<bool> {
    while count > 0 {
        let n = count.min(4096);
        let chunk = read_vec(r, n as usize)?;
        if chunk.iter().any(|b| *b != 0) {
            return Ok(false);
        }
        count -= n;
    }
    Ok(true)
}

// ─── Reader ─────────────────────────────────────────────────────────────────

/// Streams the records of one log, oldest first.
pub struct LogReader {
    r: BufReader<File>,
    /// `None` for an empty file: there is no salt, so no key is derived.
    core: Option<Core>,
    seq: u64,
    offset: u64,
    file_len: u64,
    torn: Option<u64>,
    done: bool,
    scratch: Zeroizing<Vec<u8>>,
}

impl LogReader {
    /// Open `path`. `Ok(None)` when the file does not exist. A zero-length
    /// file reads as an empty log.
    pub fn open(keys: &StateKeys, label: Label, path: &Path) -> Result<Option<Self>, StateError> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let file_len = file.metadata()?.len();
        let mut r = BufReader::with_capacity(IO_BUF, file);
        let (core, offset, done) = if file_len == 0 {
            (None, 0, true)
        } else {
            if file_len < LOG_HEADER_LEN as u64 {
                let head = read_vec(&mut r, file_len as usize)?;
                let n = head.len().min(4);
                return Err(if head[..n] == LOG_MAGIC[..n] {
                    StateError::Truncated
                } else {
                    StateError::NotProtected
                });
            }
            let h: [u8; LOG_HEADER_LEN] = read_array(&mut r)?;
            let salt = parse_header(&h, label)?;
            (
                Some(Core::new(keys, label, salt)),
                LOG_HEADER_LEN as u64,
                false,
            )
        };
        Ok(Some(Self {
            r,
            core,
            seq: 0,
            offset,
            file_len,
            torn: None,
            done,
            scratch: Zeroizing::new(Vec::new()),
        }))
    }

    fn tear(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.torn = Some(self.offset);
        self.done = true;
        None
    }

    fn fail(&mut self, e: StateError) -> Result<Option<Zeroizing<Vec<u8>>>, StateError> {
        self.done = true;
        Err(e)
    }

    /// The next record, `Ok(None)` at the end (clean or torn: see
    /// [`torn_at`](Self::torn_at)). After an error the reader is finished.
    pub fn next_record(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, StateError> {
        let Some(core) = &self.core else {
            self.done = true;
            return Ok(None);
        };
        if self.done {
            return Ok(None);
        }
        let max_body = core.max_body();
        let remaining = self.file_len - self.offset;
        if remaining == 0 {
            self.done = true;
            return Ok(None);
        }
        if remaining < 4 {
            return Ok(self.tear());
        }
        let lenb: [u8; 4] = match read_array(&mut self.r) {
            Ok(b) => b,
            Err(e) if is_unexpected_eof(&e) => return Ok(self.tear()),
            Err(e) => return self.fail(e.into()),
        };
        let body_len = u32::from_le_bytes(lenb) as usize;
        if !(MIN_BODY..=max_body).contains(&body_len) {
            let zeros = u32::from_le_bytes(lenb) == 0
                && matches!(rest_is_zero(&mut self.r, remaining - 4), Ok(true));
            return if zeros {
                Ok(self.tear())
            } else {
                self.fail(StateError::Corrupt(self.offset))
            };
        }
        if (4 + body_len) as u64 > remaining {
            return Ok(self.tear());
        }
        match read_vec(&mut self.r, body_len) {
            Ok(body) => self.scratch = Zeroizing::new(body),
            Err(e) if is_unexpected_eof(&e) => return Ok(self.tear()),
            Err(e) => return self.fail(e.into()),
        }
        let end = self.offset + 4 + body_len as u64;
        let opened = self
            .core
            .as_ref()
            .map(|c| c.open_body(self.seq, &mut self.scratch));
        match opened.unwrap_or(Err(StateError::Authentication)) {
            Ok(plain) => {
                self.seq += 1;
                self.offset = end;
                if self.scratch.capacity() > 256 * 1024 {
                    self.scratch = Zeroizing::new(Vec::new());
                }
                Ok(Some(plain))
            }
            // A final record that fails is a torn write only when an earlier
            // record of this file opened: that proves the key is the right one.
            // Otherwise it may be a wrong key, and nothing is cut away.
            Err(_) if end == self.file_len && self.seq > 0 => Ok(self.tear()),
            Err(e) => self.fail(e),
        }
    }

    /// `Some(valid_length)` when the log ended in a torn record that was
    /// dropped (known once `next_record` has returned `Ok(None)`).
    pub fn torn_at(&self) -> Option<u64> {
        self.torn
    }

    /// Records returned so far.
    pub fn records_read(&self) -> u64 {
        self.seq
    }
}

// ─── Writer ─────────────────────────────────────────────────────────────────

/// Appends records to one log. One writer per file at a time.
pub struct LogWriter {
    file: File,
    core: Core,
    seq: u64,
    end: u64,
    scratch: Zeroizing<Vec<u8>>,
}

struct Scan {
    count: u64,
    valid_len: u64,
}

impl LogWriter {
    /// Open `path` for appending, creating it (with a fresh header) when it is
    /// missing or empty. A torn last record is cut off first.
    pub fn open_append(keys: &StateKeys, label: Label, path: &Path) -> Result<Self, StateError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let len = match std::fs::metadata(path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        if len < LOG_HEADER_LEN as u64 {
            if len > 0 {
                // A prefix of our own header is a creation that never finished;
                // anything else is somebody's data and is left alone.
                let head = read_vec(&mut File::open(path)?, len as usize)?;
                let n = head.len().min(4);
                if head[..n] != LOG_MAGIC[..n] {
                    return Err(StateError::NotProtected);
                }
            }
            return Self::create_file(keys, label, path);
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let h: [u8; LOG_HEADER_LEN] = read_array(&mut file)?;
        let salt = parse_header(&h, label)?;
        let core = Core::new(keys, label, salt);
        let scan = Self::scan(path, &core, len)?;
        if scan.valid_len < len {
            file.set_len(scan.valid_len)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::Start(scan.valid_len))?;
        Ok(Self {
            file,
            core,
            seq: scan.count,
            end: scan.valid_len,
            scratch: Zeroizing::new(Vec::new()),
        })
    }

    /// Start a new log at `path`, replacing whatever is there.
    pub(crate) fn create_file(
        keys: &StateKeys,
        label: Label,
        path: &Path,
    ) -> Result<Self, StateError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let salt: [u8; 16] = rand::random();
        let core = Core::new(keys, label, salt);
        let header = core.header();
        crate::secure_file::write_restricted(path, &header)?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        file.seek(SeekFrom::End(0))?;
        Ok(Self {
            file,
            core,
            seq: 0,
            end: LOG_HEADER_LEN as u64,
            scratch: Zeroizing::new(Vec::new()),
        })
    }

    /// Walk the record lengths (no decryption except for the last record) to
    /// find where the good part of the file ends.
    fn scan(path: &Path, core: &Core, file_len: u64) -> Result<Scan, StateError> {
        let mut r = BufReader::with_capacity(IO_BUF, File::open(path)?);
        r.seek(SeekFrom::Start(LOG_HEADER_LEN as u64))?;
        let mut offset = LOG_HEADER_LEN as u64;
        let mut count = 0u64;
        let mut last: Option<(u64, usize)> = None;
        let mut prev: Option<(u64, usize)> = None;
        loop {
            let remaining = file_len - offset;
            if remaining == 0 || remaining < 4 {
                break;
            }
            let lenb: [u8; 4] = read_array(&mut r)?;
            let body_len = u32::from_le_bytes(lenb) as usize;
            if !(MIN_BODY..=core.max_body()).contains(&body_len) {
                if u32::from_le_bytes(lenb) == 0 && rest_is_zero(&mut r, remaining - 4)? {
                    break;
                }
                return Err(StateError::Corrupt(offset));
            }
            if (4 + body_len) as u64 > remaining {
                break;
            }
            prev = last;
            last = Some((offset, body_len));
            count += 1;
            offset += 4 + body_len as u64;
            r.seek_relative(body_len as i64)?;
        }
        if let Some((off, body_len)) = last {
            r.seek(SeekFrom::Start(off + 4))?;
            let mut body = Zeroizing::new(read_vec(&mut r, body_len)?);
            if core.open_body(count - 1, &mut body).is_err() {
                // Cut the final record away only if it was not written
                // completely, which an earlier record opening proves: with the
                // wrong key nothing opens, and then nothing may be cut.
                let Some((poff, plen)) = prev else {
                    return Err(StateError::Authentication);
                };
                r.seek(SeekFrom::Start(poff + 4))?;
                let mut pbody = Zeroizing::new(read_vec(&mut r, plen)?);
                if core.open_body(count - 2, &mut pbody).is_err() {
                    return Err(StateError::Authentication);
                }
                return Ok(Scan {
                    count: count - 1,
                    valid_len: off,
                });
            }
        }
        Ok(Scan {
            count,
            valid_len: offset,
        })
    }

    /// Append one record (at most [`Label::max_record_bytes`] bytes).
    pub fn append(&mut self, record: &[u8]) -> Result<(), StateError> {
        if record.len() > self.core.label.max_record_bytes() {
            return Err(StateError::TooLarge {
                size: record.len() as u64,
                limit: self.core.label.max_record_bytes() as u64,
            });
        }
        let body_len = NONCE_LEN + record.len() + TAG_LEN;
        let mut nonce: [u8; NONCE_LEN] = rand::random();
        nonce[16..].copy_from_slice(&self.seq.to_be_bytes());
        self.scratch.clear();
        self.scratch
            .extend_from_slice(&(body_len as u32).to_le_bytes());
        self.scratch.extend_from_slice(&nonce);
        self.scratch.extend_from_slice(record);
        let tag = seal_detached(
            &self.core.key,
            &nonce,
            &self.core.aad(self.seq),
            &mut self.scratch[4 + NONCE_LEN..],
        )?;
        self.scratch.extend_from_slice(&tag);
        if let Err(e) = self.file.write_all(&self.scratch) {
            // Do not leave half a record in front of the next one.
            let _ = self.file.set_len(self.end);
            let _ = self.file.seek(SeekFrom::Start(self.end));
            return Err(e.into());
        }
        self.end += self.scratch.len() as u64;
        self.seq += 1;
        if self.scratch.capacity() > 256 * 1024 {
            // Do not keep a large buffer for the life of the process.
            self.scratch = Zeroizing::new(Vec::new());
        }
        Ok(())
    }

    /// Append one record and make it durable before returning.
    pub fn append_durable(&mut self, record: &[u8]) -> Result<(), StateError> {
        self.append(record)?;
        self.sync()
    }

    /// Flush appended records to disk.
    pub fn sync(&mut self) -> Result<(), StateError> {
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Records in the file.
    pub fn record_count(&self) -> u64 {
        self.seq
    }

    /// Bytes in the file.
    pub fn len(&self) -> u64 {
        self.end
    }

    pub fn is_empty(&self) -> bool {
        self.seq == 0
    }
}

// ─── Rewrite (compaction, trim, migration) ──────────────────────────────────

/// Builds a replacement log in a temp file, then swaps it in. Dropping it
/// without [`commit`](Self::commit) removes the temp file and leaves the
/// original untouched.
pub struct LogRewrite {
    writer: Option<LogWriter>,
    tmp: PathBuf,
    dest: PathBuf,
    armed: bool,
}

impl LogRewrite {
    /// Start a replacement for `dest`, staged at `tmp` (any leftover at `tmp`
    /// is overwritten).
    pub fn begin(
        keys: &StateKeys,
        label: Label,
        dest: &Path,
        tmp: &Path,
    ) -> Result<Self, StateError> {
        let writer = LogWriter::create_file(keys, label, tmp)?;
        Ok(Self {
            writer: Some(writer),
            tmp: tmp.to_path_buf(),
            dest: dest.to_path_buf(),
            armed: true,
        })
    }

    pub fn append(&mut self, record: &[u8]) -> Result<(), StateError> {
        self.writer
            .as_mut()
            .expect("writer present until finish")
            .append(record)
    }

    /// Flush the staged log to disk and hand back its path; the caller moves
    /// it into place.
    pub fn finish(mut self) -> Result<PathBuf, StateError> {
        let mut w = self.writer.take().expect("writer present until finish");
        w.sync()?;
        drop(w);
        self.armed = false;
        Ok(self.tmp.clone())
    }

    /// Flush and rename over the destination.
    pub fn commit(self) -> Result<(), StateError> {
        let dest = self.dest.clone();
        let tmp = self.finish()?;
        fsync_path(&tmp)?;
        std::fs::rename(&tmp, &dest).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
        sync_parent_dir(&dest);
        Ok(())
    }
}

impl Drop for LogRewrite {
    fn drop(&mut self) {
        if self.armed {
            drop(self.writer.take());
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(b: u8) -> StateKeys {
        StateKeys::from_master_key(&[b; 32]).unwrap()
    }

    fn read_all(
        k: &StateKeys,
        label: Label,
        p: &Path,
    ) -> Result<(Vec<Vec<u8>>, Option<u64>), StateError> {
        let mut r = LogReader::open(k, label, p)?.expect("exists");
        let mut out = Vec::new();
        while let Some(rec) = r.next_record()? {
            out.push(rec.to_vec());
        }
        Ok((out, r.torn_at()))
    }

    fn write_n(k: &StateKeys, label: Label, p: &Path, n: usize) {
        let mut w = LogWriter::open_append(k, label, p).unwrap();
        for i in 0..n {
            w.append(format!("record number {i}").as_bytes()).unwrap();
        }
        w.sync().unwrap();
    }

    #[test]
    fn round_trip_for_every_label_and_reopen_continues() {
        let k = keys(1);
        let dir = tempfile::tempdir().unwrap();
        for label in Label::ALL {
            let p = dir.path().join(format!("{}.log", label.name()));
            write_n(&k, label, &p, 3);
            // Reopen and append more: numbering continues.
            let mut w = LogWriter::open_append(&k, label, &p).unwrap();
            assert_eq!(w.record_count(), 3);
            w.append(b"").unwrap();
            w.append(&vec![7u8; label.max_record_bytes()]).unwrap();
            drop(w);
            let (recs, torn) = read_all(&k, label, &p).unwrap();
            assert_eq!(torn, None);
            assert_eq!(recs.len(), 5);
            assert_eq!(recs[0], b"record number 0");
            assert!(recs[3].is_empty());
            assert_eq!(recs[4].len(), label.max_record_bytes());
        }
    }

    #[test]
    fn plaintext_never_appears_in_the_file() {
        let k = keys(1);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.log");
        write_n(&k, Label::PushHistory, &p, 50);
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"record"));
        assert_eq!(&raw[..4], b"MSL1");
    }

    #[test]
    fn oversized_record_is_refused() {
        let k = keys(1);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.log");
        let mut w = LogWriter::open_append(&k, Label::PushHistory, &p).unwrap();
        assert!(matches!(
            w.append(&vec![0u8; Label::PushHistory.max_record_bytes() + 1]),
            Err(StateError::TooLarge { .. })
        ));
        w.append(b"still works").unwrap();
    }

    #[test]
    fn every_torn_prefix_of_the_last_record_is_dropped_and_repaired() {
        let k = keys(2);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.log");
        write_n(&k, Label::ReplicationWal, &p, 4);
        let full = std::fs::read(&p).unwrap();
        let last_len = 4 + NONCE_LEN + b"record number 3".len() + TAG_LEN;
        let good = full.len() - last_len;
        for cut in good..full.len() {
            std::fs::write(&p, &full[..cut]).unwrap();
            let (recs, torn) = read_all(&k, Label::ReplicationWal, &p).unwrap();
            assert_eq!(recs.len(), 3, "cut {cut}");
            assert_eq!(torn, if cut == good { None } else { Some(good as u64) });
            // The writer repairs the tail and carries on at the right number.
            let mut w = LogWriter::open_append(&k, Label::ReplicationWal, &p).unwrap();
            assert_eq!(w.record_count(), 3);
            w.append(b"after the tear").unwrap();
            drop(w);
            let (recs, torn) = read_all(&k, Label::ReplicationWal, &p).unwrap();
            assert_eq!((recs.len(), torn), (4, None));
            assert_eq!(recs[3], b"after the tear");
        }
    }

    #[test]
    fn zero_filled_or_garbage_tail_of_the_last_record_is_a_torn_write() {
        let k = keys(2);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.log");
        write_n(&k, Label::ReplicationWal, &p, 3);
        let full = std::fs::read(&p).unwrap();
        // Zeros appended (file grew, data never landed).
        let mut z = full.clone();
        z.extend_from_slice(&[0u8; 300]);
        std::fs::write(&p, &z).unwrap();
        let (recs, torn) = read_all(&k, Label::ReplicationWal, &p).unwrap();
        assert_eq!((recs.len(), torn), (3, Some(full.len() as u64)));
        // Last record complete in length but its body is unwritten (zeros).
        let last_len = 4 + NONCE_LEN + b"record number 2".len() + TAG_LEN;
        let mut g = full.clone();
        let n = g.len();
        for b in &mut g[n - last_len + 4..] {
            *b = 0;
        }
        std::fs::write(&p, &g).unwrap();
        let (recs, torn) = read_all(&k, Label::ReplicationWal, &p).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(torn, Some((n - last_len) as u64));
        let w = LogWriter::open_append(&k, Label::ReplicationWal, &p).unwrap();
        assert_eq!(w.record_count(), 2);
    }

    #[test]
    fn damage_before_the_end_is_an_error_not_a_silent_truncation() {
        let k = keys(3);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.log");
        write_n(&k, Label::PushHistory, &p, 5);
        let mut raw = std::fs::read(&p).unwrap();
        // Flip a ciphertext byte of the second record.
        let first = 4 + NONCE_LEN + b"record number 0".len() + TAG_LEN;
        raw[LOG_HEADER_LEN + first + 4 + NONCE_LEN + 2] ^= 0x40;
        std::fs::write(&p, &raw).unwrap();
        let mut r = LogReader::open(&k, Label::PushHistory, &p)
            .unwrap()
            .unwrap();
        assert!(r.next_record().unwrap().is_some());
        assert!(matches!(r.next_record(), Err(StateError::Authentication)));
        assert!(r.next_record().unwrap().is_none(), "reader stays finished");
        // The writer refuses to append behind damage? It keeps the damaged
        // body (only the tail is verified); the reader still reports it.
        let (res,) = (read_all(&k, Label::PushHistory, &p),);
        assert!(res.is_err());
    }

    #[test]
    fn a_single_unreadable_record_is_never_cut_away() {
        // With one record there is no proof that the key is right, so a record
        // that does not open (wrong key, damage) is kept, not treated as torn.
        let k = keys(3);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.log");
        write_n(&k, Label::PushHistory, &p, 1);
        let right = std::fs::read(&p).unwrap();
        assert!(matches!(
            read_all(&keys(4), Label::PushHistory, &p),
            Err(StateError::Authentication)
        ));
        assert!(matches!(
            LogWriter::open_append(&keys(4), Label::PushHistory, &p),
            Err(StateError::Authentication)
        ));
        assert_eq!(std::fs::read(&p).unwrap(), right, "file untouched");
        // A log of several records under the wrong key fails as well, and also
        // stays as it is.
        write_n(&k, Label::PushHistory, &p, 3);
        let three = std::fs::read(&p).unwrap();
        assert!(LogWriter::open_append(&keys(4), Label::PushHistory, &p).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), three);
    }

    #[test]
    fn a_flipped_length_prefix_is_corruption() {
        let k = keys(3);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.log");
        write_n(&k, Label::PushHistory, &p, 3);
        let mut raw = std::fs::read(&p).unwrap();
        raw[LOG_HEADER_LEN + 3] = 0x7f; // absurd length on record 0
        std::fs::write(&p, &raw).unwrap();
        assert!(matches!(
            read_all(&k, Label::PushHistory, &p),
            Err(StateError::Corrupt(_))
        ));
        assert!(matches!(
            LogWriter::open_append(&k, Label::PushHistory, &p),
            Err(StateError::Corrupt(_))
        ));
    }

    #[test]
    fn reordered_spliced_and_replayed_records_are_rejected() {
        let k = keys(4);
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.log");
        let b = dir.path().join("b.log");
        write_n(&k, Label::PushHistory, &a, 4);
        write_n(&k, Label::PushHistory, &b, 4);
        let ra = std::fs::read(&a).unwrap();
        let rb = std::fs::read(&b).unwrap();
        let rec = 4 + NONCE_LEN + b"record number 0".len() + TAG_LEN;
        let at = |i: usize| LOG_HEADER_LEN + i * rec..LOG_HEADER_LEN + (i + 1) * rec;

        // Records 1 and 2 swapped.
        let mut swapped = ra.clone();
        swapped[at(1)].copy_from_slice(&ra[at(2)]);
        swapped[at(2)].copy_from_slice(&ra[at(1)]);
        std::fs::write(&a, &swapped).unwrap();
        assert!(read_all(&k, Label::PushHistory, &a).is_err());

        // A record of another file spliced in.
        let mut spliced = ra.clone();
        spliced[at(1)].copy_from_slice(&rb[at(1)]);
        std::fs::write(&a, &spliced).unwrap();
        assert!(read_all(&k, Label::PushHistory, &a).is_err());

        // An old record replayed at a later position.
        let mut replay = ra.clone();
        replay[at(2)].copy_from_slice(&ra[at(0)]);
        std::fs::write(&a, &replay).unwrap();
        assert!(read_all(&k, Label::PushHistory, &a).is_err());

        // The whole header (salt) of another file put in front.
        let mut hdr = ra.clone();
        hdr[..LOG_HEADER_LEN].copy_from_slice(&rb[..LOG_HEADER_LEN]);
        std::fs::write(&a, &hdr).unwrap();
        assert!(read_all(&k, Label::PushHistory, &a).is_err());
    }

    #[test]
    fn wrong_key_label_header_and_junk_are_refused_without_panic() {
        let k = keys(5);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.log");
        write_n(&k, Label::PushHistory, &p, 3);
        assert!(read_all(&keys(6), Label::PushHistory, &p).is_err());
        assert!(matches!(
            LogReader::open(&k, Label::ReplicationWal, &p),
            Err(StateError::WrongLabel { .. })
        ));
        let raw = std::fs::read(&p).unwrap();
        // A forged label byte: the key differs, nothing opens.
        let mut forged = raw.clone();
        forged[5] = Label::ReplicationWal.id();
        std::fs::write(&p, &forged).unwrap();
        assert!(read_all(&k, Label::ReplicationWal, &p).is_err());
        // Every header bit flip is detected or harmless-by-rejection.
        for i in 0..LOG_HEADER_LEN {
            let mut bad = raw.clone();
            bad[i] ^= 0x10;
            std::fs::write(&p, &bad).unwrap();
            assert!(
                read_all(&k, Label::PushHistory, &p).is_err(),
                "header byte {i}"
            );
        }
        // Plaintext JSON lines are not a log.
        std::fs::write(&p, b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n").unwrap();
        assert!(matches!(
            read_all(&k, Label::PushHistory, &p),
            Err(StateError::NotProtected)
        ));
        assert!(matches!(
            LogWriter::open_append(&k, Label::PushHistory, &p),
            Err(StateError::NotProtected)
        ));
        // Short junk.
        std::fs::write(&p, b"{}").unwrap();
        assert!(matches!(
            LogWriter::open_append(&k, Label::PushHistory, &p),
            Err(StateError::NotProtected)
        ));
        assert_eq!(std::fs::read(&p).unwrap(), b"{}", "foreign data untouched");
    }

    #[test]
    fn zero_length_and_header_only_and_missing_files() {
        let k = keys(7);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.log");
        assert!(LogReader::open(&k, Label::PushHistory, &p)
            .unwrap()
            .is_none());
        std::fs::write(&p, b"").unwrap();
        let (recs, torn) = read_all(&k, Label::PushHistory, &p).unwrap();
        assert!(recs.is_empty() && torn.is_none());
        let mut w = LogWriter::open_append(&k, Label::PushHistory, &p).unwrap();
        assert!(w.is_empty());
        w.append(b"first").unwrap();
        drop(w);
        let raw = std::fs::read(&p).unwrap();
        std::fs::write(&p, &raw[..LOG_HEADER_LEN]).unwrap();
        assert!(read_all(&k, Label::PushHistory, &p).unwrap().0.is_empty());
        // Cut inside the header: truncated for readers, rebuilt by the writer.
        std::fs::write(&p, &raw[..10]).unwrap();
        assert!(matches!(
            read_all(&k, Label::PushHistory, &p),
            Err(StateError::Truncated)
        ));
        let mut w = LogWriter::open_append(&k, Label::PushHistory, &p).unwrap();
        w.append(b"again").unwrap();
        drop(w);
        assert_eq!(read_all(&k, Label::PushHistory, &p).unwrap().0.len(), 1);
    }

    #[test]
    fn rewrite_commits_atomically_and_drop_discards() {
        let k = keys(8);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.log");
        let tmp = dir.path().join("w.sec.tmp");
        write_n(&k, Label::ReplicationWal, &p, 5);
        {
            let mut rw = LogRewrite::begin(&k, Label::ReplicationWal, &p, &tmp).unwrap();
            rw.append(b"new").unwrap();
        } // dropped
        assert!(!tmp.exists());
        assert_eq!(read_all(&k, Label::ReplicationWal, &p).unwrap().0.len(), 5);
        let mut rw = LogRewrite::begin(&k, Label::ReplicationWal, &p, &tmp).unwrap();
        rw.append(b"x").unwrap();
        rw.append(b"y").unwrap();
        rw.commit().unwrap();
        assert!(!tmp.exists());
        assert_eq!(
            read_all(&k, Label::ReplicationWal, &p).unwrap().0,
            vec![b"x".to_vec(), b"y".to_vec()]
        );
    }

    #[test]
    fn appending_to_an_empty_file_uses_a_fresh_random_salt() {
        let k = keys(5);
        let dir = tempfile::tempdir().unwrap();
        let mut salts = Vec::new();
        for i in 0..3 {
            let p = dir.path().join(format!("e{i}.log"));
            std::fs::write(&p, b"").unwrap();
            let mut w = LogWriter::open_append(&k, Label::PushHistory, &p).unwrap();
            w.append(b"x").unwrap();
            drop(w);
            let raw = std::fs::read(&p).unwrap();
            salts.push(raw[6..22].to_vec());
            assert_eq!(read_all(&k, Label::PushHistory, &p).unwrap().0.len(), 1);
        }
        assert!(salts.iter().all(|s| s.iter().any(|b| *b != 0)));
        assert!(salts[0] != salts[1] && salts[1] != salts[2]);
    }
    #[test]
    fn two_files_with_the_same_content_look_different() {
        let k = keys(9);
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.log");
        let b = dir.path().join("b.log");
        write_n(&k, Label::PushHistory, &a, 3);
        write_n(&k, Label::PushHistory, &b, 3);
        let (ra, rb) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert_eq!(ra.len(), rb.len());
        assert_ne!(ra[6..22], rb[6..22], "salt differs");
        assert_ne!(ra[LOG_HEADER_LEN..], rb[LOG_HEADER_LEN..]);
    }
}
