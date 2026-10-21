//! A small record, kept outside the data folder, that says which version of a
//! contact's session file was written last.
//!
//! The session file holds the keys the next message is sealed with. If the
//! data folder is put back to an earlier copy (a restored backup, a sync
//! conflict), the next message would be sealed with keys that were already
//! used. The record lets the program notice that before anything is sent:
//!
//! * Before a session file is replaced, the record is written with the
//!   fingerprint of the file now on disk (`cur`) and of the file about to be
//!   written (`next`). After the replacement it is written again with both
//!   set to the new file. A crash between the steps leaves a record that
//!   accepts the file that is on disk; the window closes at the next start.
//! * When a session file is loaded, its fingerprint must be the one in the
//!   record. If it is not, the file is older (or newer, or foreign): the
//!   session is dropped, so a new one with fresh keys starts, and the send
//!   counter continues above the highest value the record has seen.
//! * No record (first start, another machine, the record was removed) is
//!   accepted and the record is created from the file found.
//!
//! The record holds fingerprints of the encrypted file (a hash of bytes that
//! carry a fresh random nonce at every write) and a counter. It holds no key
//! and nothing of the content, is sealed itself, and lives under a name that
//! is a keyed hash. The session file format is not touched.
//!
//! What it cannot do: when the data folder and the record are both put back,
//! or the folder is copied to a second machine that keeps its own record,
//! the old file looks genuine. That limit is by design (see the tests).
//!
//! Nothing here writes to a log: stealth mode keeps the programs from leaving
//! lines about what they did and where.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use crate::state_crypto::{doc, Label, StateKeys};

pub type Fingerprint = [u8; 16];

/// The "fingerprint" of a session file that does not exist.
pub const NO_FILE: Fingerprint = [0; 16];

const RECORD_VERSION: u8 = 1;
const RECORD_LEN: usize = 1 + 16 + 16 + 8;

/// What the record holds about one contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The session file that was on disk before the last write began.
    pub cur: Fingerprint,
    /// The session file that the last write put (or was about to put) there.
    pub next: Fingerprint,
    /// The highest send counter seen so far.
    pub send_seq_hwm: u64,
}

impl Record {
    fn encode(&self) -> [u8; RECORD_LEN] {
        let mut b = [0u8; RECORD_LEN];
        b[0] = RECORD_VERSION;
        b[1..17].copy_from_slice(&self.cur);
        b[17..33].copy_from_slice(&self.next);
        b[33..].copy_from_slice(&self.send_seq_hwm.to_be_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != RECORD_LEN || b[0] != RECORD_VERSION {
            return None;
        }
        Some(Self {
            cur: b[1..17].try_into().ok()?,
            next: b[17..33].try_into().ok()?,
            send_seq_hwm: u64::from_be_bytes(b[33..].try_into().ok()?),
        })
    }
}

/// The verdict on a session file that was just loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// It is the one written last (or there is nothing to compare with).
    Fine,
    /// It is not the latest version. The session must not be used; the send
    /// counter must continue at `send_seq_floor` or above.
    Behind { send_seq_floor: u64 },
}

#[derive(Clone, Copy)]
struct Seen {
    on_disk: Fingerprint,
    seq_hwm: u64,
}

pub struct Anchor {
    /// Where the records live; `None` keeps only the in-memory marks.
    dir: Option<PathBuf>,
    keys: Arc<StateKeys>,
    own_id: [u8; 32],
    seen: Mutex<HashMap<[u8; 32], Seen>>,
    /// Set after a record could not be written: the records are left alone
    /// for the rest of the run (and the stale one is removed if possible).
    off: AtomicBool,
}

impl Anchor {
    pub fn new(dir: Option<PathBuf>, keys: Arc<StateKeys>, own_id: [u8; 32]) -> Self {
        Self {
            dir,
            keys,
            own_id,
            seen: Mutex::new(HashMap::new()),
            off: AtomicBool::new(false),
        }
    }

    /// The record file of `peer`: a keyed hash, so the name says nothing.
    pub fn path_of(&self, peer: &[u8; 32]) -> Option<PathBuf> {
        let dir = self.dir.as_ref()?;
        let key = self.keys.doc_key(Label::ChatAnchor).ok()?;
        let mut h = blake3::Hasher::new_keyed(&key);
        h.update(&self.own_id);
        h.update(peer);
        Some(dir.join(hex::encode(&h.finalize().as_bytes()[..16])))
    }

    fn read(&self, peer: &[u8; 32]) -> Option<Record> {
        let path = self.path_of(peer)?;
        if !path.exists() {
            return None;
        }
        let plain = doc::read_document(&self.keys, Label::ChatAnchor, &path).ok()?;
        Record::decode(&plain)
    }

    fn write(&self, peer: &[u8; 32], rec: Record, durable: bool) -> bool {
        let Some(path) = self.path_of(peer) else {
            return false;
        };
        let Ok(sealed) = doc::seal(
            &self.keys,
            Label::ChatAnchor,
            &doc::context_of(&path),
            &rec.encode(),
        ) else {
            return false;
        };
        doc::write_sealed(&path, &sealed, durable).is_ok()
    }

    fn switch_off(&self, peer: &[u8; 32]) {
        self.off.store(true, Ordering::Relaxed);
        if let Some(p) = self.path_of(peer) {
            let _ = std::fs::remove_file(p);
        }
    }

    fn is_off(&self) -> bool {
        self.off.load(Ordering::Relaxed)
    }

    /// Judge the session file just loaded for `peer`. `disk` is the
    /// fingerprint of the file as read ([`NO_FILE`] when there is none) and
    /// `send_seq` the counter it holds.
    pub fn check(&self, peer: &[u8; 32], disk: Fingerprint, send_seq: u64) -> Check {
        if self.is_off() {
            return Check::Fine;
        }
        let record = self.read(peer);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let hwm_of_record = record.map_or(0, |r| r.send_seq_hwm);
        // Known from earlier in this run: the file must be the one we wrote
        // (or found) last. This also catches a copy put back while running.
        if let Some(s) = seen.get(peer).copied() {
            if s.on_disk == disk {
                return Check::Fine;
            }
            let floor = s.seq_hwm.max(hwm_of_record);
            seen.insert(
                *peer,
                Seen {
                    on_disk: disk,
                    seq_hwm: floor,
                },
            );
            return Check::Behind {
                send_seq_floor: floor,
            };
        }
        match record {
            Some(rec) if disk == rec.cur || disk == rec.next => {
                seen.insert(
                    *peer,
                    Seen {
                        on_disk: disk,
                        seq_hwm: rec.send_seq_hwm.max(send_seq),
                    },
                );
                if rec.cur != rec.next || disk != rec.next {
                    // A write was cut short: settle the record on what is there.
                    self.write(
                        peer,
                        Record {
                            cur: disk,
                            next: disk,
                            send_seq_hwm: rec.send_seq_hwm.max(send_seq),
                        },
                        false,
                    );
                }
                Check::Fine
            }
            Some(rec) => {
                seen.insert(
                    *peer,
                    Seen {
                        on_disk: disk,
                        seq_hwm: rec.send_seq_hwm,
                    },
                );
                Check::Behind {
                    send_seq_floor: rec.send_seq_hwm,
                }
            }
            None => {
                // Nothing to compare with: accept, and start the record.
                seen.insert(
                    *peer,
                    Seen {
                        on_disk: disk,
                        seq_hwm: send_seq,
                    },
                );
                if disk != NO_FILE {
                    self.write(
                        peer,
                        Record {
                            cur: disk,
                            next: disk,
                            send_seq_hwm: send_seq,
                        },
                        false,
                    );
                }
                Check::Fine
            }
        }
    }

    /// Called before the session file of `peer` is replaced by the one with
    /// fingerprint `next`. Returns `false` if the record could not be written
    /// (the caller goes on without it; the record is then switched off).
    pub fn before_write(&self, peer: &[u8; 32], next: Fingerprint, send_seq: u64) -> bool {
        if self.is_off() {
            return false;
        }
        let (cur, hwm) = {
            let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.get(peer)
                .map_or((NO_FILE, send_seq), |s| (s.on_disk, s.seq_hwm.max(send_seq)))
        };
        if self.dir.is_some()
            && !self.write(
                peer,
                Record {
                    cur,
                    next,
                    send_seq_hwm: hwm,
                },
                true,
            )
        {
            self.switch_off(peer);
            return false;
        }
        true
    }

    /// Called after the session file with fingerprint `next` was put in place.
    pub fn after_write(&self, peer: &[u8; 32], next: Fingerprint, send_seq: u64) {
        let hwm = {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            let hwm = seen
                .get(peer)
                .map_or(send_seq, |s| s.seq_hwm.max(send_seq));
            seen.insert(
                *peer,
                Seen {
                    on_disk: next,
                    seq_hwm: hwm,
                },
            );
            hwm
        };
        if !self.is_off()
            && self.dir.is_some()
            && !self.write(
                peer,
                Record {
                    cur: next,
                    next,
                    send_seq_hwm: hwm,
                },
                false,
            )
        {
            // The earlier record still accepts the file just written.
            self.switch_off(peer);
        }
    }

    /// Test hook: put an exact record on disk.
    #[cfg(test)]
    pub(crate) fn force_record(&self, peer: &[u8; 32], rec: Record) {
        assert!(self.write(peer, rec, true));
    }

    /// The highest send counter this run has seen for `peer`.
    pub fn send_seq_hwm(&self, peer: &[u8; 32]) -> u64 {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer)
            .map_or(0, |s| s.seq_hwm)
    }
}

/// Remove an anchor folder with everything in it (the emergency wipe): each
/// file is overwritten, then removed. Missing is fine.
pub fn wipe_dir(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let _ = crate::state_crypto::overwrite_and_remove(&e.path());
        }
    }
    let _ = std::fs::remove_dir(dir);
    // The `ms` folder above it, once the last data directory is gone.
    if let Some(parent) = dir.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

/// Wipe the anchor folder of `data_dir` in the default place.
pub fn wipe_for(data_dir: &Path) {
    if let Some(d) = crate::paths::anchor_dir(data_dir) {
        wipe_dir(&d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(dir: &Path) -> Anchor {
        let keys = Arc::new(StateKeys::from_master_key(&[7u8; 32]).unwrap());
        Anchor::new(Some(dir.to_path_buf()), keys, [1u8; 32])
    }

    const PEER: [u8; 32] = [2u8; 32];
    fn fp(n: u8) -> Fingerprint {
        [n; 16]
    }

    /// Write the record the way the store does.
    fn put(a: &Anchor, n: u8, seq: u64) {
        assert!(a.before_write(&PEER, fp(n), seq));
        a.after_write(&PEER, fp(n), seq);
    }

    #[test]
    fn record_round_trips_and_rejects_other_shapes() {
        let r = Record {
            cur: fp(1),
            next: fp(2),
            send_seq_hwm: 77,
        };
        assert_eq!(Record::decode(&r.encode()), Some(r));
        assert_eq!(Record::decode(&r.encode()[..RECORD_LEN - 1]), None);
        let mut bad = r.encode();
        bad[0] = 9;
        assert_eq!(Record::decode(&bad), None);
    }

    #[test]
    fn no_record_is_accepted_and_the_record_is_created() {
        let d = tempfile::tempdir().unwrap();
        let a = anchor(d.path());
        assert_eq!(a.check(&PEER, fp(5), 3), Check::Fine);
        // A second run sees the record, which now names fp(5).
        let b = anchor(d.path());
        assert_eq!(b.check(&PEER, fp(5), 3), Check::Fine);
        assert_eq!(
            b.check(&PEER, fp(4), 3),
            Check::Behind { send_seq_floor: 3 }
        );
    }

    #[test]
    fn an_older_file_is_behind_and_the_counter_floor_is_the_highest_seen() {
        let d = tempfile::tempdir().unwrap();
        let a = anchor(d.path());
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        put(&a, 1, 1);
        put(&a, 2, 5);
        put(&a, 3, 9);
        let b = anchor(d.path());
        // The file from two writes ago, and the one from one write ago.
        assert_eq!(
            b.check(&PEER, fp(1), 1),
            Check::Behind { send_seq_floor: 9 }
        );
        let c = anchor(d.path());
        assert_eq!(
            c.check(&PEER, fp(2), 5),
            Check::Behind { send_seq_floor: 9 }
        );
        let e = anchor(d.path());
        assert_eq!(e.check(&PEER, fp(3), 9), Check::Fine);
    }

    #[test]
    fn a_crash_inside_a_write_is_not_a_rollback_in_either_order() {
        let d = tempfile::tempdir().unwrap();
        let a = anchor(d.path());
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        put(&a, 1, 1);
        // The record was written, the file was not: the old file is on disk.
        assert!(a.before_write(&PEER, fp(2), 2));
        let b = anchor(d.path());
        assert_eq!(b.check(&PEER, fp(1), 1), Check::Fine);
        // After that start the old file is the settled one: putting back the
        // very same old file later is accepted (it is the latest), and the
        // never-written one is not.
        let c = anchor(d.path());
        assert_eq!(c.check(&PEER, fp(1), 1), Check::Fine);
        let c2 = anchor(d.path());
        assert_eq!(
            c2.check(&PEER, fp(2), 2),
            Check::Behind { send_seq_floor: 2 }
        );
        // The file was written, the closing record was not.
        put(&c, 1, 1);
        assert!(c.before_write(&PEER, fp(3), 4));
        let f = anchor(d.path());
        assert_eq!(f.check(&PEER, fp(3), 4), Check::Fine);
        // Settled again: the previous file is now behind.
        let g = anchor(d.path());
        assert_eq!(
            g.check(&PEER, fp(1), 1),
            Check::Behind { send_seq_floor: 4 }
        );
    }

    #[test]
    fn a_file_the_record_never_heard_of_is_behind() {
        let d = tempfile::tempdir().unwrap();
        let a = anchor(d.path());
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        put(&a, 1, 1);
        let b = anchor(d.path());
        // Newer than the record (written by something that does not keep it).
        assert_eq!(
            b.check(&PEER, fp(9), 50),
            Check::Behind { send_seq_floor: 1 }
        );
        // The file is gone while the record says there was one.
        let c = anchor(d.path());
        assert_eq!(
            c.check(&PEER, NO_FILE, 0),
            Check::Behind { send_seq_floor: 1 }
        );
    }

    #[test]
    fn an_unreadable_record_counts_as_missing() {
        let d = tempfile::tempdir().unwrap();
        let a = anchor(d.path());
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        put(&a, 1, 1);
        let path = a.path_of(&PEER).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let b = anchor(d.path());
        assert_eq!(b.check(&PEER, fp(8), 2), Check::Fine);
        // It was recreated from what was found.
        let c = anchor(d.path());
        assert_eq!(c.check(&PEER, fp(8), 2), Check::Fine);
    }

    #[test]
    fn a_copy_put_back_while_running_is_caught_by_the_marks_in_memory() {
        let d = tempfile::tempdir().unwrap();
        // No folder at all: only the marks in memory.
        let keys = Arc::new(StateKeys::from_master_key(&[7u8; 32]).unwrap());
        let a = Anchor::new(None, keys, [1u8; 32]);
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        put(&a, 1, 1);
        put(&a, 2, 6);
        assert_eq!(a.check(&PEER, fp(2), 6), Check::Fine);
        assert_eq!(
            a.check(&PEER, fp(1), 1),
            Check::Behind { send_seq_floor: 6 }
        );
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn the_record_holds_fingerprints_and_a_counter_only() {
        let d = tempfile::tempdir().unwrap();
        let a = anchor(d.path());
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        put(&a, 4, 12);
        let path = a.path_of(&PEER).unwrap();
        // Opened with the right key the content is exactly the record.
        let plain = doc::read_document(&a.keys, Label::ChatAnchor, &path).unwrap();
        assert_eq!(plain.len(), RECORD_LEN);
        assert_eq!(
            Record::decode(&plain),
            Some(Record {
                cur: fp(4),
                next: fp(4),
                send_seq_hwm: 12
            })
        );
        // The file on disk shows neither the counter nor the peer.
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(32).any(|w| w == PEER));
        assert!(!raw.windows(16).any(|w| w == fp(4)));
        // The name is not the plain hash of the two ids.
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), 32);
        assert!(!name.contains("chat") && !name.to_lowercase().contains("miasma"));
    }

    #[test]
    fn a_record_that_cannot_be_written_switches_the_records_off() {
        let d = tempfile::tempdir().unwrap();
        // A file where the folder should be: no record can be created.
        let blocked = d.path().join("blocked");
        std::fs::write(&blocked, b"x").unwrap();
        let a = anchor(&blocked.join("inner"));
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        assert!(!a.before_write(&PEER, fp(1), 1));
        // From now on nothing is compared or written.
        assert!(!a.before_write(&PEER, fp(2), 2));
        assert_eq!(a.check(&PEER, fp(7), 1), Check::Fine);
    }

    #[test]
    fn wipe_removes_the_files_and_the_folder() {
        let base = tempfile::tempdir().unwrap();
        let data = base.path().join("data");
        let dir = crate::paths::anchor_dir_in(&base.path().join("state"), &data);
        let a = anchor(&dir);
        assert_eq!(a.check(&PEER, NO_FILE, 0), Check::Fine);
        put(&a, 1, 1);
        assert!(a.path_of(&PEER).unwrap().exists());
        wipe_dir(&dir);
        assert!(!dir.exists());
        // The shared folder above went too, as it was empty.
        assert!(!dir.parent().unwrap().exists());
    }
}
