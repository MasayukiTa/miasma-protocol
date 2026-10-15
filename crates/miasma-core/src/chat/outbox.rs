//! The outbox: messages that have been accepted from the user and not yet
//! delivered or failed for good.
//!
//! Entries are kept in an encrypted record log (`state_crypto`, label
//! `ChatOutbox`): a `Put` record when a message is queued and a `Done` record
//! when it leaves the outbox. On start the log is folded into the list of
//! pending entries and rewritten if it holds mostly finished ones.
//!
//! Bounds: a number of entries, a number per contact and a total of text bytes
//! (so the in-memory copy, which holds the text, stays small). When one is
//! reached the message is refused with an error; nothing is ever dropped
//! silently.
//!
//! A sealed envelope is kept only in memory, for the retries of the running
//! process: a restart seals again with a fresh message key (the receiver keeps
//! keys for messages it has not seen, up to a bound).

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use tracing::warn;

use super::{
    crypto::Rd,
    proto::MAX_TEXT_BYTES,
    store::{StoreError, StoreSettings},
};
use crate::state_crypto::{Label, LogReader, LogRewrite, LogWriter, StateKeys};

const REC_PUT: u8 = 1;
const REC_DONE: u8 = 2;

#[derive(Debug, Clone)]
pub struct OutEntry {
    pub id: [u8; 16],
    pub peer: [u8; 32],
    pub seq: u64,
    pub sent_ms: u64,
    pub created_ms: u64,
    pub text: String,
    /// Delivery attempts made by this process (not persisted).
    pub attempts: u32,
    /// Sealed bytes of the last attempt, kept for a retry (not persisted).
    pub sealed: Option<Vec<u8>>,
    pub sending: bool,
    pub last_error: Option<String>,
}

impl OutEntry {
    fn put_record(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 16 + 32 + 24 + 2 + self.text.len());
        v.push(REC_PUT);
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.peer);
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.extend_from_slice(&self.sent_ms.to_be_bytes());
        v.extend_from_slice(&self.created_ms.to_be_bytes());
        v.extend_from_slice(&(self.text.len() as u16).to_be_bytes());
        v.extend_from_slice(self.text.as_bytes());
        v
    }

    fn parse_put(b: &[u8]) -> Option<Self> {
        let mut r = Rd::new(b);
        if r.u8().ok()? != REC_PUT {
            return None;
        }
        let id = r.arr::<16>().ok()?;
        let peer = r.arr::<32>().ok()?;
        let seq = r.u64().ok()?;
        let sent_ms = r.u64().ok()?;
        let created_ms = r.u64().ok()?;
        let n = r.u16().ok()? as usize;
        if n == 0 || n > MAX_TEXT_BYTES {
            return None;
        }
        let text = std::str::from_utf8(r.bytes(n).ok()?).ok()?.to_owned();
        if !r.done() {
            return None;
        }
        Some(Self {
            id,
            peer,
            seq,
            sent_ms,
            created_ms,
            text,
            attempts: 0,
            sealed: None,
            sending: false,
            last_error: None,
        })
    }
}

struct Inner {
    entries: VecDeque<OutEntry>,
    text_bytes: usize,
    writer: Option<LogWriter>,
    /// Records in the log that no longer matter (finished entries).
    garbage: usize,
}

pub struct Outbox {
    path: PathBuf,
    keys: Arc<StateKeys>,
    settings: StoreSettings,
    inner: Mutex<Inner>,
}

impl Outbox {
    /// Open the outbox at `path`. Entries older than the expiry are returned
    /// so the caller can record them as failed.
    pub fn open(
        path: &Path,
        keys: Arc<StateKeys>,
        settings: StoreSettings,
        now_ms: u64,
    ) -> (Self, Vec<OutEntry>) {
        let mut entries: VecDeque<OutEntry> = VecDeque::new();
        let mut garbage = 0usize;
        let mut damaged = false;
        match LogReader::open(&keys, Label::ChatOutbox, path) {
            Ok(Some(mut r)) => loop {
                match r.next_record() {
                    Ok(Some(rec)) => match rec.first() {
                        Some(&REC_PUT) => match OutEntry::parse_put(&rec) {
                            Some(e) => entries.push_back(e),
                            None => garbage += 1,
                        },
                        Some(&REC_DONE) if rec.len() == 17 => {
                            let id: [u8; 16] = rec[1..17].try_into().unwrap_or_default();
                            if let Some(i) = entries.iter().position(|e| e.id == id) {
                                entries.remove(i);
                                garbage += 2;
                            } else {
                                garbage += 1;
                            }
                        }
                        _ => garbage += 1,
                    },
                    Ok(None) => break,
                    Err(_) => {
                        damaged = true;
                        break;
                    }
                }
            },
            Ok(None) => {}
            Err(_) => damaged = true,
        }
        if damaged {
            match crate::state_crypto::set_aside(path) {
                Ok(p) => warn!("the chat outbox cannot be opened; it was moved to {p:?}"),
                Err(e) => warn!("the chat outbox cannot be opened: {e}"),
            }
            entries.clear();
        }
        let expiry_ms = settings.outbox_expiry_days.saturating_mul(86_400_000);
        let mut expired = Vec::new();
        if expiry_ms > 0 {
            let (old, keep): (Vec<_>, Vec<_>) = entries
                .into_iter()
                .partition(|e| now_ms.saturating_sub(e.created_ms) > expiry_ms);
            expired = old;
            entries = keep.into();
        }
        let text_bytes = entries.iter().map(|e| e.text.len()).sum();
        let ob = Self {
            path: path.to_path_buf(),
            keys,
            settings,
            inner: Mutex::new(Inner {
                entries,
                text_bytes,
                writer: None,
                garbage: garbage + expired.len(),
            }),
        };
        ob.compact_if_needed(true);
        (ob, expired)
    }

    fn with_writer<R>(
        &self,
        g: &mut Inner,
        f: impl FnOnce(&mut LogWriter) -> Result<R, crate::state_crypto::StateError>,
    ) -> Result<R, StoreError> {
        if g.writer.is_none() {
            g.writer = Some(LogWriter::open_append(
                &self.keys,
                Label::ChatOutbox,
                &self.path,
            )?);
        }
        let w = g.writer.as_mut().expect("just set");
        match f(w) {
            Ok(r) => Ok(r),
            Err(e) => {
                g.writer = None;
                Err(e.into())
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue a message. Durable before it returns.
    pub fn push(&self, e: OutEntry) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        if g.entries.len() >= self.settings.outbox_max {
            return Err(StoreError::OutboxFull);
        }
        if g.entries.iter().filter(|x| x.peer == e.peer).count()
            >= self.settings.outbox_max_per_contact
        {
            return Err(StoreError::OutboxFull);
        }
        if g.text_bytes + e.text.len() > self.settings.outbox_bytes {
            return Err(StoreError::OutboxFull);
        }
        let rec = e.put_record();
        let durable = !self.settings.defer_flush;
        self.with_writer(&mut g, |w| {
            if durable {
                w.append_durable(&rec)
            } else {
                w.append(&rec)
            }
        })?;
        g.text_bytes += e.text.len();
        g.entries.push_back(e);
        Ok(())
    }

    /// Remove an entry (delivered, failed for good, or cancelled).
    pub fn remove(&self, id: &[u8; 16]) -> Option<OutEntry> {
        let mut g = self.inner.lock().unwrap();
        let i = g.entries.iter().position(|e| &e.id == id)?;
        let e = g.entries.remove(i)?;
        g.text_bytes = g.text_bytes.saturating_sub(e.text.len());
        let mut rec = Vec::with_capacity(17);
        rec.push(REC_DONE);
        rec.extend_from_slice(id);
        // A lost `Done` only means one more (deduplicated) delivery attempt.
        let _ = self.with_writer(&mut g, |w| w.append(&rec));
        g.garbage += 2;
        drop(g);
        self.compact_if_needed(false);
        Some(e)
    }

    /// The oldest pending entry of `peer`.
    pub fn first_for(&self, peer: &[u8; 32]) -> Option<OutEntry> {
        let g = self.inner.lock().unwrap();
        g.entries.iter().find(|e| &e.peer == peer).cloned()
    }

    pub fn pending_for(&self, peer: &[u8; 32]) -> Vec<OutEntry> {
        let g = self.inner.lock().unwrap();
        g.entries
            .iter()
            .filter(|e| &e.peer == peer)
            .cloned()
            .collect()
    }

    pub fn count_for(&self, peer: &[u8; 32]) -> usize {
        let g = self.inner.lock().unwrap();
        g.entries.iter().filter(|e| &e.peer == peer).count()
    }

    /// Contacts that have something waiting (each once, oldest first).
    pub fn peers(&self) -> Vec<[u8; 32]> {
        let g = self.inner.lock().unwrap();
        let mut out: Vec<[u8; 32]> = Vec::new();
        for e in &g.entries {
            if !out.contains(&e.peer) {
                out.push(e.peer);
            }
        }
        out
    }

    /// Change the in-memory part of an entry.
    pub fn update(&self, id: &[u8; 16], f: impl FnOnce(&mut OutEntry)) {
        let mut g = self.inner.lock().unwrap();
        if let Some(e) = g.entries.iter_mut().find(|e| &e.id == id) {
            f(e);
        }
    }

    pub fn get(&self, id: &[u8; 16]) -> Option<OutEntry> {
        let g = self.inner.lock().unwrap();
        g.entries.iter().find(|e| &e.id == id).cloned()
    }

    /// Remove every entry of `peer`; returns them.
    pub fn remove_peer(&self, peer: &[u8; 32]) -> Vec<OutEntry> {
        let ids: Vec<[u8; 16]> = self.pending_for(peer).iter().map(|e| e.id).collect();
        ids.iter().filter_map(|id| self.remove(id)).collect()
    }

    /// Rewrite the log with only the pending entries when it has grown mostly
    /// out of finished ones.
    fn compact_if_needed(&self, force_when_garbage: bool) {
        let mut g = self.inner.lock().unwrap();
        let limit = g.entries.len() * 2 + 1024;
        let due = g.garbage > limit || (force_when_garbage && g.garbage > 0);
        if !due {
            return;
        }
        g.writer = None;
        let tmp = self.path.with_extension("log.tmp");
        let Ok(mut out) = LogRewrite::begin(&self.keys, Label::ChatOutbox, &self.path, &tmp) else {
            return;
        };
        for e in &g.entries {
            if out.append(&e.put_record()).is_err() {
                return;
            }
        }
        if out.commit().is_ok() {
            g.garbage = 0;
        }
    }
}

/// Convenience for tests and the service: build an entry for a new message.
pub fn new_entry(id: [u8; 16], peer: [u8; 32], seq: u64, sent_ms: u64, text: String) -> OutEntry {
    OutEntry {
        id,
        peer,
        seq,
        sent_ms,
        created_ms: sent_ms,
        text,
        attempts: 0,
        sealed: None,
        sending: false,
        last_error: None,
    }
}
