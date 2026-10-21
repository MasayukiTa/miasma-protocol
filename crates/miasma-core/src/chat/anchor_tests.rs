//! Tests of the record kept outside the data folder at the level of the store:
//! how a session file is judged when it is loaded, in which orders a write
//! can be cut short, and what the record holds.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{
    anchor::{Anchor, Record},
    crypto::{file_stem, Identity, Session},
    store::{ChatStore, StoreSettings},
};
use crate::state_crypto::{doc, StateKeys};

const OWN: [u8; 32] = [9u8; 32];

struct Fx {
    root: tempfile::TempDir,
    master: [u8; 32],
    peer: [u8; 32],
    me: Identity,
}

impl Fx {
    fn new() -> Self {
        let peer = Identity::from_seed(&rand::random()).id();
        Self {
            root: tempfile::tempdir().unwrap(),
            master: rand::random(),
            peer,
            me: Identity::from_seed(&rand::random()),
        }
    }

    fn keys(&self) -> Arc<StateKeys> {
        Arc::new(StateKeys::from_master_key(&self.master).unwrap())
    }

    fn chat(&self) -> PathBuf {
        self.root.path().join("data").join("chat")
    }

    fn anchor_dir(&self) -> PathBuf {
        self.root.path().join("elsewhere")
    }

    fn anchor(&self) -> Anchor {
        Anchor::new(Some(self.anchor_dir()), self.keys(), OWN)
    }

    fn store(&self) -> ChatStore {
        ChatStore::open(&self.chat(), self.keys(), OWN, StoreSettings::default())
            .unwrap()
            .with_anchor(self.anchor())
    }

    fn sess(&self) -> PathBuf {
        crate::paths::chat_session_file(&self.chat(), &file_stem(&OWN, &self.peer))
    }

    /// Give the contact a session and this send counter, and write it.
    fn write(&self, st: &ChatStore, seq: u64) {
        let session = Session::new_initiator(&self.me, &self.peer).unwrap();
        st.with_peer(&self.peer, |p| {
            p.send_seq = seq;
            p.session = Some(session);
        });
        st.flush_peer(&self.peer).unwrap();
    }

    fn fp(&self) -> [u8; 16] {
        doc::fingerprint(&fs::read(self.sess()).unwrap())
    }

    fn state(&self, st: &ChatStore) -> (bool, u64) {
        st.peek_peer(&self.peer, |p| (p.session.is_some(), p.send_seq))
    }
}

#[test]
fn a_file_that_is_the_latest_written_is_loaded_as_it_is() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    st.close();
    let st = f.store();
    assert_eq!(f.state(&st), (true, 4));
    assert!(!st.take_rollback(&f.peer));
}

#[test]
fn an_older_file_is_dropped_and_the_counter_is_kept_above_what_was_used() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    let older = fs::read(f.sess()).unwrap();
    f.write(&st, 9);
    st.close();
    fs::write(f.sess(), older).unwrap();
    let st = f.store();
    // No session, and the counter did not go back to 4.
    assert_eq!(f.state(&st), (false, 9));
    assert!(st.take_rollback(&f.peer));
    // Reported once.
    assert!(!st.take_rollback(&f.peer));
}

#[test]
fn a_session_file_put_back_while_the_program_runs_is_noticed_when_read_again() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    let older = fs::read(f.sess()).unwrap();
    f.write(&st, 9);
    st.evict_for_test(&f.peer);
    fs::write(f.sess(), older).unwrap();
    assert_eq!(f.state(&st), (false, 9));
    assert!(st.take_rollback(&f.peer));
}

#[test]
fn a_missing_record_is_accepted_and_made_again() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    st.close();
    fs::remove_dir_all(f.anchor_dir()).unwrap();
    let st = f.store();
    assert_eq!(f.state(&st), (true, 4));
    assert!(!st.take_rollback(&f.peer));
    assert!(fs::read_dir(f.anchor_dir()).unwrap().count() > 0);
    // And it now guards the file: an older one is caught.
    let older = fs::read(f.sess()).unwrap();
    f.write(&st, 6);
    st.close();
    fs::write(f.sess(), older).unwrap();
    let st = f.store();
    assert_eq!(f.state(&st), (false, 6));
}

#[test]
fn a_damaged_record_is_treated_as_missing() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    st.close();
    for e in fs::read_dir(f.anchor_dir()).unwrap().flatten() {
        fs::write(e.path(), b"not a record").unwrap();
    }
    let st = f.store();
    assert_eq!(f.state(&st), (true, 4));
}

#[test]
fn a_record_that_names_a_file_never_written_means_the_file_is_behind() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    st.close();
    // The record is ahead of every file there is.
    f.anchor().force_record(
        &f.peer,
        Record {
            cur: [0xAA; 16],
            next: [0xBB; 16],
            send_seq_hwm: 30,
        },
    );
    let st = f.store();
    assert_eq!(f.state(&st), (false, 30));
}

#[test]
fn a_write_cut_short_after_the_record_and_before_the_file_is_not_a_rollback() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    st.close();
    let on_disk = f.fp();
    // The record says: from this file to one that was never put in place.
    f.anchor().force_record(
        &f.peer,
        Record {
            cur: on_disk,
            next: [0xCC; 16],
            send_seq_hwm: 5,
        },
    );
    let st = f.store();
    assert_eq!(f.state(&st), (true, 4));
    assert!(!st.take_rollback(&f.peer));
    // Settled on the file that is there: the unwritten one is not welcome.
    st.close();
    let st = f.store();
    assert_eq!(f.state(&st), (true, 4));
}

#[test]
fn a_write_cut_short_after_the_file_and_before_the_closing_record_is_not_a_rollback() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    let first = f.fp();
    f.write(&st, 9);
    let second = f.fp();
    st.close();
    // The record as it stands between the two steps of the second write.
    f.anchor().force_record(
        &f.peer,
        Record {
            cur: first,
            next: second,
            send_seq_hwm: 9,
        },
    );
    let st = f.store();
    assert_eq!(f.state(&st), (true, 9));
    assert!(!st.take_rollback(&f.peer));
}

#[test]
fn once_a_write_is_complete_the_file_before_it_is_no_longer_accepted() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    let first = fs::read(f.sess()).unwrap();
    f.write(&st, 9);
    st.close();
    fs::write(f.sess(), first).unwrap();
    let st = f.store();
    assert_eq!(f.state(&st), (false, 9));
}

#[test]
fn the_records_hold_no_key_material() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    let session = st.peek_peer(&f.peer, |p| p.session.as_ref().unwrap().to_bytes().to_vec());
    st.close();
    let mut files = 0;
    for e in fs::read_dir(f.anchor_dir()).unwrap().flatten() {
        files += 1;
        let raw = fs::read(e.path()).unwrap();
        // Header, 41 bytes of record, tag: nothing that could hold a key.
        assert_eq!(raw.len(), doc::DOC_HEADER_LEN + 41 + 16);
        assert!(!raw.windows(8).any(|w| session.windows(8).any(|s| s == w)));
        assert!(!raw.windows(32).any(|w| w == f.peer || w == OWN));
        // The name is a hash: it does not contain the contact's ID or "chat".
        let name = e.file_name().to_string_lossy().into_owned();
        assert!(name.len() == 32 && name.chars().all(|c| c.is_ascii_hexdigit()));
    }
    assert_eq!(files, 1);
}

#[test]
fn nothing_but_the_chat_and_the_record_folders_is_written() {
    let f = Fx::new();
    let st = f.store();
    f.write(&st, 4);
    st.close();
    let mut tops: Vec<String> = fs::read_dir(f.root.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    tops.sort();
    assert_eq!(tops, ["data", "elsewhere"]);
    // No leftover temp file in either folder.
    for dir in [f.chat(), f.anchor_dir()] {
        assert!(fs::read_dir(dir)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().ends_with(".tmp")));
    }
}

#[test]
fn the_emergency_wipe_removes_the_record_folder() {
    let base = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    crate::paths::ANCHOR_BASE_OVERRIDE.with(|o| *o.borrow_mut() = Some(base.path().to_path_buf()));
    let store = crate::store::LocalShareStore::open(data.path(), 100).unwrap();
    let dir = crate::paths::anchor_dir(data.path()).unwrap();
    let keys = Arc::new(StateKeys::from_master_key(&[5u8; 32]).unwrap());
    let a = Anchor::new(Some(dir.clone()), keys, OWN);
    let peer = [3u8; 32];
    a.check(&peer, [0; 16], 0);
    assert!(a.before_write(&peer, [1; 16], 1));
    a.after_write(&peer, [1; 16], 1);
    assert!(fs::read_dir(&dir).unwrap().count() > 0);
    // The folder sits under the base, in the shared folder with the neutral name.
    assert!(dir.starts_with(base.path().join(crate::paths::CHAT_ANCHOR_DIR.name)));
    store.distress_wipe().unwrap();
    assert!(!dir.exists());
    crate::paths::ANCHOR_BASE_OVERRIDE.with(|o| *o.borrow_mut() = None);
}

#[test]
fn the_location_is_not_inside_the_data_folder_and_says_nothing() {
    let data = Path::new("some").join("data");
    let dir = crate::paths::anchor_dir_in(Path::new("state"), &data);
    assert!(!dir.starts_with(&data));
    let shown = dir.to_string_lossy().to_lowercase();
    for word in ["miasma", "chat", "anchor", "session"] {
        assert!(!shown.contains(word), "{word}");
    }
    // Two data folders do not share a record folder.
    let other = crate::paths::anchor_dir_in(Path::new("state"), &Path::new("some").join("other"));
    assert_ne!(dir, other);
}
