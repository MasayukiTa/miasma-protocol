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
//! The sealed envelope of a message is written to the same log (a `Sealed`
//! record) before it is first sent, so that a resend after a restart puts the
//! identical bytes on the wire and the ratchet is not advanced a second time
//! for the same message. An `Unseal` record voids it when the session it
//! belongs to is replaced. The delivery worker only ever tries the oldest
//! message of a contact, so at most one sealed envelope per contact exists;
//! the total is bounded by [`SEALED_BUDGET`] as well.

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
const REC_PUT_READ: u8 = 3;

/// What an outbox entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutKind {
    /// A message the person wrote.
    Text,
    /// A read receipt; `seq` holds the number it reports up to and `text` is
    /// empty. It never reaches the history, and it is dropped (not failed)
    /// when it expires.
    Read,
}

const REC_SEALED: u8 = 4;
const REC_UNSEAL: u8 = 5;

/// Bytes of sealed envelopes the outbox keeps (memory and log).
pub const SEALED_BUDGET: usize = 2 * 1024 * 1024;
/// Longest sealed envelope kept (the largest a frame can carry).
const MAX_SEALED: usize = super::proto::MAX_FRAME_BODY;

#[derive(Debug, Clone)]
pub struct OutEntry {
    pub id: [u8; 16],
    pub kind: OutKind,
    pub peer: [u8; 32],
    pub seq: u64,
    pub sent_ms: u64,
    pub created_ms: u64,
    pub text: String,
    /// Delivery attempts made by this process (not persisted).
    pub attempts: u32,
    /// The sealed envelope of this message, kept (and persisted) for retries.
    pub sealed: Option<Vec<u8>>,
    pub sending: bool,
    pub last_error: Option<String>,
    /// When the last delivery attempt started (ms since the epoch; 0 = none
    /// yet in this process). Not persisted.
    pub last_try_ms: u64,
}

impl OutEntry {
    fn put_record(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 16 + 32 + 24 + 2 + self.text.len());
        if self.kind == OutKind::Read {
            v.push(REC_PUT_READ);
            v.extend_from_slice(&self.id);
            v.extend_from_slice(&self.peer);
            v.extend_from_slice(&self.seq.to_be_bytes());
            v.extend_from_slice(&self.sent_ms.to_be_bytes());
            v.extend_from_slice(&self.created_ms.to_be_bytes());
            return v;
        }
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

    fn parse_put_read(b: &[u8]) -> Option<Self> {
        let mut r = Rd::new(b);
        if r.u8().ok()? != REC_PUT_READ {
            return None;
        }
        let id = r.arr::<16>().ok()?;
        let peer = r.arr::<32>().ok()?;
        let seq = r.u64().ok()?;
        let sent_ms = r.u64().ok()?;
        let created_ms = r.u64().ok()?;
        if !r.done() || seq == 0 {
            return None;
        }
        Some(Self {
            id,
            kind: OutKind::Read,
            peer,
            seq,
            sent_ms,
            created_ms,
            text: String::new(),
            attempts: 0,
            sealed: None,
            sending: false,
            last_error: None,
            last_try_ms: 0,
        })
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
            kind: OutKind::Text,
            peer,
            seq,
            sent_ms,
            created_ms,
            text,
            attempts: 0,
            sealed: None,
            sending: false,
            last_error: None,
            last_try_ms: 0,
        })
    }
}

struct Inner {
    entries: VecDeque<OutEntry>,
    text_bytes: usize,
    sealed_bytes: usize,
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
                        Some(&REC_PUT_READ) => match OutEntry::parse_put_read(&rec) {
                            Some(e) => entries.push_back(e),
                            None => garbage += 1,
                        },
                        Some(&REC_DONE) if rec.len() == 17 => {
                            let id: [u8; 16] = rec[1..17].try_into().unwrap_or_default();
                            if let Some(i) = entries.iter().position(|e| e.id == id) {
                                if let Some(e) = entries.remove(i) {
                                    if e.sealed.is_some() {
                                        garbage += 1;
                                    }
                                }
                                garbage += 2;
                            } else {
                                garbage += 1;
                            }
                        }
                        Some(&REC_SEALED) if rec.len() > 17 && rec.len() <= 17 + MAX_SEALED => {
                            let id: [u8; 16] = rec[1..17].try_into().unwrap_or_default();
                            match entries.iter_mut().find(|e| e.id == id) {
                                Some(e) => {
                                    if e.sealed.is_some() {
                                        garbage += 1;
                                    }
                                    e.sealed = Some(rec[17..].to_vec());
                                }
                                None => garbage += 1,
                            }
                        }
                        Some(&REC_UNSEAL) if rec.len() == 17 => {
                            let id: [u8; 16] = rec[1..17].try_into().unwrap_or_default();
                            if let Some(e) = entries.iter_mut().find(|e| e.id == id) {
                                e.sealed = None;
                            }
                            garbage += 2;
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
            let (old, keep): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| {
                e.kind == OutKind::Text && now_ms.saturating_sub(e.created_ms) > expiry_ms
            });
            expired = old;
            entries = keep.into();
        }
        // Receipts are not worth a late delivery: past their own, shorter
        // expiry they are dropped without a trace in the history.
        let before = entries.len();
        entries.retain(|e| {
            e.kind != OutKind::Read
                || now_ms.saturating_sub(e.created_ms) <= settings.receipt_expiry_ms
        });
        garbage += before - entries.len();
        let text_bytes = entries.iter().map(|e| e.text.len()).sum();
        // More sealed bytes than the budget (a log written under another
        // setting): the surplus is dropped and those messages are sealed again
        // when they are tried.
        let mut sealed_bytes = 0usize;
        for e in entries.iter_mut() {
            if let Some(s) = &e.sealed {
                if sealed_bytes + s.len() > SEALED_BUDGET {
                    e.sealed = None;
                } else {
                    sealed_bytes += s.len();
                }
            }
        }
        let ob = Self {
            path: path.to_path_buf(),
            keys,
            settings,
            inner: Mutex::new(Inner {
                entries,
                text_bytes,
                sealed_bytes,
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

    /// Every entry, receipts included.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Messages waiting (receipts are not counted: they have a bound of their
    /// own, one per contact).
    pub fn text_len(&self) -> usize {
        let g = self.inner.lock().unwrap();
        g.entries.iter().filter(|e| e.kind == OutKind::Text).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue a read receipt for its contact, replacing the one that is still
    /// waiting (a newer receipt reports at least as much). At most one receipt
    /// per contact is ever held, so this needs no limit of its own. Durable
    /// before it returns.
    pub fn push_receipt(&self, e: OutEntry) -> Result<(), StoreError> {
        debug_assert_eq!(e.kind, OutKind::Read);
        let old: Vec<[u8; 16]> = {
            let g = self.inner.lock().unwrap();
            g.entries
                .iter()
                .filter(|x| x.kind == OutKind::Read && x.peer == e.peer)
                .map(|x| x.id)
                .collect()
        };
        for id in old {
            self.remove(&id);
        }
        let mut g = self.inner.lock().unwrap();
        let rec = e.put_record();
        let durable = !self.settings.defer_flush;
        self.with_writer(&mut g, |w| {
            if durable {
                w.append_durable(&rec)
            } else {
                w.append(&rec)
            }
        })?;
        g.entries.push_back(e);
        Ok(())
    }

    /// The receipt waiting for `peer`, if any.
    pub fn receipt_for(&self, peer: &[u8; 32]) -> Option<OutEntry> {
        let g = self.inner.lock().unwrap();
        g.entries
            .iter()
            .find(|e| e.kind == OutKind::Read && &e.peer == peer)
            .cloned()
    }

    /// Queue a message. Durable before it returns.
    pub fn push(&self, e: OutEntry) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let texts = g.entries.iter().filter(|x| x.kind == OutKind::Text);
        if texts.count() >= self.settings.outbox_max {
            return Err(StoreError::OutboxFull);
        }
        if g.entries
            .iter()
            .filter(|x| x.kind == OutKind::Text && x.peer == e.peer)
            .count()
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
        if let Some(s) = &e.sealed {
            g.sealed_bytes = g.sealed_bytes.saturating_sub(s.len());
            g.garbage += 1;
        }
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

    /// Messages (not receipts) waiting for `peer`.
    pub fn count_for(&self, peer: &[u8; 32]) -> usize {
        let g = self.inner.lock().unwrap();
        g.entries
            .iter()
            .filter(|e| e.kind == OutKind::Text && &e.peer == peer)
            .count()
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

    /// Change the in-memory part of an entry. Not for the sealed envelope: use
    /// [`set_sealed`](Self::set_sealed) and [`clear_sealed`](Self::clear_sealed),
    /// which write it down.
    pub fn update(&self, id: &[u8; 16], f: impl FnOnce(&mut OutEntry)) {
        let mut g = self.inner.lock().unwrap();
        if let Some(e) = g.entries.iter_mut().find(|e| &e.id == id) {
            let before = e.sealed.as_ref().map_or(0, |s| s.len());
            f(e);
            let after = e.sealed.as_ref().map_or(0, |s| s.len());
            g.sealed_bytes = (g.sealed_bytes + after).saturating_sub(before);
        }
    }

    /// Keep the sealed envelope of entry `id`. Durable before it returns, so
    /// the bytes can be sent knowing that a restart sends the same ones.
    pub fn set_sealed(&self, id: &[u8; 16], bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.is_empty() || bytes.len() > MAX_SEALED {
            return Err(StoreError::OutboxFull);
        }
        let mut g = self.inner.lock().unwrap();
        let Some(i) = g.entries.iter().position(|e| &e.id == id) else {
            return Ok(());
        };
        let old = g.entries[i].sealed.as_ref().map_or(0, |s| s.len());
        if g.sealed_bytes - old + bytes.len() > SEALED_BUDGET {
            return Err(StoreError::OutboxFull);
        }
        let mut rec = Vec::with_capacity(17 + bytes.len());
        rec.push(REC_SEALED);
        rec.extend_from_slice(id);
        rec.extend_from_slice(bytes);
        let durable = !self.settings.defer_flush;
        self.with_writer(&mut g, |w| {
            if durable {
                w.append_durable(&rec)
            } else {
                w.append(&rec)
            }
        })?;
        g.sealed_bytes = g.sealed_bytes - old + bytes.len();
        if old > 0 {
            g.garbage += 1;
        }
        g.entries[i].sealed = Some(bytes.to_vec());
        Ok(())
    }

    /// Void the sealed envelope of entry `id` (its session was replaced).
    pub fn clear_sealed(&self, id: &[u8; 16]) {
        let mut g = self.inner.lock().unwrap();
        let Some(i) = g.entries.iter().position(|e| &e.id == id) else {
            return;
        };
        let Some(old) = g.entries[i].sealed.take() else {
            return;
        };
        g.sealed_bytes = g.sealed_bytes.saturating_sub(old.len());
        let mut rec = Vec::with_capacity(17);
        rec.push(REC_UNSEAL);
        rec.extend_from_slice(id);
        // A lost `Unseal` only brings back an envelope the receiver answers
        // with "no session"; the next attempt voids it again.
        let _ = self.with_writer(&mut g, |w| w.append(&rec));
        g.garbage += 2;
    }

    /// True when one more envelope of the largest size still fits the budget.
    /// Checked before sealing, so that no key is used for a message whose
    /// envelope could not be kept.
    pub fn has_sealed_room(&self) -> bool {
        self.inner.lock().unwrap().sealed_bytes + MAX_SEALED <= SEALED_BUDGET
    }

    /// Bytes of sealed envelopes currently held.
    pub fn sealed_bytes(&self) -> usize {
        self.inner.lock().unwrap().sealed_bytes
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
            if let Some(s) = &e.sealed {
                let mut rec = Vec::with_capacity(17 + s.len());
                rec.push(REC_SEALED);
                rec.extend_from_slice(&e.id);
                rec.extend_from_slice(s);
                if out.append(&rec).is_err() {
                    return;
                }
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
        kind: OutKind::Text,
        peer,
        seq,
        sent_ms,
        created_ms: sent_ms,
        text,
        attempts: 0,
        sealed: None,
        sending: false,
        last_error: None,
        last_try_ms: 0,
    }
}

/// An entry for a read receipt that reports up to `up_to_seq`.
pub fn new_receipt(id: [u8; 16], peer: [u8; 32], up_to_seq: u64, now_ms: u64) -> OutEntry {
    OutEntry {
        id,
        kind: OutKind::Read,
        peer,
        seq: up_to_seq,
        sent_ms: now_ms,
        created_ms: now_ms,
        text: String::new(),
        attempts: 0,
        sealed: None,
        sending: false,
        last_error: None,
        last_try_ms: 0,
    }
}
