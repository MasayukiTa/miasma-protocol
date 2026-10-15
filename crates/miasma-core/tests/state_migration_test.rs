//! Conversion of the plaintext state files written by earlier versions, and
//! behaviour of the stores when the key is missing, wrong or the files are
//! damaged.
//!
//! The data directory is built the way an earlier version leaves it: real
//! shapes, a damaged contacts file set aside earlier, leftover temp copies.

use std::path::{Path, PathBuf};

use miasma_core::{
    daemon::replication::{PendingReplication, ReplicationQueue},
    directed::{DirectedEnvelope, DirectedInbox, EnvelopeState},
    network::types::DhtRecord,
    paths,
    push::{
        state::{History, HistoryEntry},
        ContactCode, ContactStore, Direction, PushState,
    },
    state_crypto::{
        self,
        migrate::{migrate_data_dir, needs_migration},
        Label, LogReader, Sniffed, StateError, StateKeys,
    },
    transfer::{
        journal::ReceiveJournal,
        manifest::SegmentEntry,
        protection::Protection,
        publish_journal::{PublishHeader, PublishJournal, PublishSegmentRecord},
    },
};

const MARK: &str = "ZEBRA-MARKER";

fn endpoint(seed: u8) -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn contact_code(seed: u8) -> ContactCode {
    ContactCode::new(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn history_entry(i: usize) -> HistoryEntry {
    HistoryEntry {
        id: format!("{i:04}"),
        direction: Direction::In,
        contact_id: "c".into(),
        contact_label: format!("{MARK}-label"),
        name: format!("{MARK}-file-{i}.bin"),
        size: i as u64,
        state: PushState::Done,
        error: None,
        reject_reason: None,
        error_kind: None,
        source_path: None,
        saved_as: Some(format!("C:/Users/x/{MARK}/{i}.bin")),
        finished_at_ms: i as u64,
    }
}

fn dht_record(id: u8) -> DhtRecord {
    let mut digest = [0u8; 32];
    digest[0] = id;
    DhtRecord {
        mid_digest: digest,
        data_shards: 2,
        total_shards: 3,
        version: 1,
        locations: vec![],
        published_at: 100,
    }
}

fn envelope(id: u8) -> DirectedEnvelope {
    DirectedEnvelope {
        envelope_id: [id; 32],
        version: 1,
        sender_pubkey: [0x01; 32],
        recipient_pubkey: [0x02; 32],
        ephemeral_pubkey: [0x03; 32],
        encrypted_payload: vec![0x04; 64],
        payload_nonce: [0x05; 24],
        password_salt: [0x06; 32],
        expires_at: u64::MAX,
        created_at: 1000 + id as u64,
        state: EnvelopeState::Pending,
        challenge_hash: None,
        password_attempts_remaining: 3,
        challenge_attempts_remaining: 3,
        challenge_expires_at: 0,
        retention_secs: 86400,
    }
}

fn receive_journal() -> ReceiveJournal {
    ReceiveJournal {
        version: 1,
        mid: format!("miasma:{MARK}"),
        output_path: format!("C:/out/{MARK}.bin"),
        part_path: format!("C:/out/{MARK}.bin.part"),
        data_shards: 10,
        total_shards: 12,
        segment_count: 20,
        total_bytes: 1 << 30,
        manifest_hash: Some("ab".repeat(32)),
        next_segment: 7,
        bytes_done: 7 << 20,
        started_at: 1,
        updated_at: 2,
        last_error: None,
        share_id: None,
    }
}

fn publish_header() -> PublishHeader {
    PublishHeader {
        version: 2,
        path: format!("C:/data/{MARK}.bin"),
        file_len: 1 << 30,
        mtime_secs: 1_700_000_000,
        mtime_nanos: 5,
        data_shards: 10,
        total_shards: 12,
        segment_size: 64 << 20,
        mid: "miasma:abc".into(),
        protection: Protection::None,
        started_at: 1,
    }
}

fn publish_record(i: u32) -> PublishSegmentRecord {
    PublishSegmentRecord {
        entry: SegmentEntry {
            index: i,
            plaintext_len: 64,
            plain_hash: [i as u8; 32],
            piece_ids: vec![[i as u8; 32]; 12],
        },
        remote: vec![],
    }
}

/// What the seeded directory holds, for comparison after the conversion.
struct Seed {
    /// (path, original bytes) of every plaintext file.
    files: Vec<(PathBuf, Vec<u8>)>,
    /// Plaintext leftovers that no version ever read.
    leftovers: Vec<PathBuf>,
}

fn put(files: &mut Vec<(PathBuf, Vec<u8>)>, path: PathBuf, bytes: Vec<u8>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    files.push((path, bytes));
}

/// A data directory as the previous release leaves it.
fn seed(dir: &Path) -> Seed {
    state_crypto::provision_master_key(dir).unwrap();
    let mut files = Vec::new();
    let mut leftovers = Vec::new();

    // contacts.json, in the shape the loader wrote.
    let contacts = serde_json::json!({
        "version": 1,
        "contacts": [
            {"id": &endpoint(1)[..16], "label": format!("{MARK} Taro"), "endpoint_id": endpoint(1),
             "added_at": 1_700_000_000u64, "allow_receive": true, "allow_send": true, "max_file_size": null},
            {"id": &endpoint(2)[..16], "label": "Hanako", "endpoint_id": endpoint(2),
             "added_at": 1_700_000_100u64, "allow_receive": false, "allow_send": true, "max_file_size": 1000},
        ]
    });
    put(
        &mut files,
        dir.join(paths::CONTACTS.name),
        serde_json::to_vec_pretty(&contacts).unwrap(),
    );
    // A contacts file an earlier start had set aside as unreadable.
    put(
        &mut files,
        dir.join("contacts.json.corrupt-1700000000"),
        b"{ \"contacts\": [ {\"label\": \"ZEBRA-MARKER half".to_vec(),
    );

    // push_history.jsonl with one damaged line in the middle.
    let mut hist = String::new();
    for i in 0..40 {
        hist.push_str(&serde_json::to_string(&history_entry(i)).unwrap());
        hist.push('\n');
        if i == 20 {
            hist.push_str("{garbage that was never valid\n");
        }
    }
    put(
        &mut files,
        dir.join(paths::PUSH_HISTORY.name),
        hist.into_bytes(),
    );

    // replication_wal.jsonl: snapshots, then an ack, then a torn last line.
    let mut wal = String::new();
    for id in 1..=5u8 {
        let item = PendingReplication::new(format!("mid-{MARK}-{id}"), dht_record(id));
        wal.push_str(
            &serde_json::json!({ "Snapshot": serde_json::to_value(&item).unwrap() }).to_string(),
        );
        wal.push('\n');
    }
    wal.push_str(&serde_json::json!({"Ack": {"mid_digest": dht_record(1).mid_digest}}).to_string());
    wal.push('\n');
    wal.push_str("{\"Snapshot\":{\"mid_str\":\"torn");
    put(
        &mut files,
        dir.join(paths::REPLICATION_WAL.name),
        wal.into_bytes(),
    );
    // A compaction that never finished.
    let tmp = dir.join(paths::REPLICATION_WAL_TMP.name);
    std::fs::write(&tmp, format!("{MARK} partial compaction")).unwrap();
    leftovers.push(tmp);

    // store_index.json
    put(
        &mut files,
        dir.join(paths::STORE_INDEX.name),
        serde_json::to_vec(&serde_json::json!({
            "aa11": {"size_bytes": 10, "last_accessed_secs": 5},
            "bb22": {"size_bytes": 20, "last_accessed_secs": 6, "origin": "Hosted"}
        }))
        .unwrap(),
    );

    // desktop-prefs.toml
    put(
        &mut files,
        dir.join(paths::DESKTOP_PREFS.name),
        b"mode = \"technical\"\nlocale = \"ja\"\n".to_vec(),
    );

    // transfers/: a receive journal and a publish journal.
    let tdir = paths::transfers_dir(dir);
    put(
        &mut files,
        tdir.join("recv-3xAmpleMid.json"),
        serde_json::to_vec_pretty(&receive_journal()).unwrap(),
    );
    let mut send = serde_json::to_string(&publish_header()).unwrap();
    send.push('\n');
    for i in 0..3 {
        send.push_str(&serde_json::to_string(&publish_record(i)).unwrap());
        send.push('\n');
    }
    put(
        &mut files,
        tdir.join("send-00112233445566778899aabbccddeeff.jsonl"),
        send.into_bytes(),
    );
    let stale = tdir.join("recv-3xAmpleMid.json.tmp");
    std::fs::write(&stale, format!("{MARK} half written journal")).unwrap();
    leftovers.push(stale);

    // directed/: envelopes and sidecars.
    let incoming = paths::directed_incoming_dir(dir);
    let outgoing = paths::directed_outgoing_dir(dir);
    let e1 = envelope(0x11);
    let e2 = envelope(0x22);
    put(
        &mut files,
        incoming.join(format!("{}.json", e1.id_hex())),
        serde_json::to_vec_pretty(&e1).unwrap(),
    );
    put(
        &mut files,
        incoming.join(format!("{}.challenge", e1.id_hex())),
        format!("CODE-{MARK}").into_bytes(),
    );
    put(
        &mut files,
        incoming.join(format!("{}.peer", e1.id_hex())),
        format!("12D3Koo{MARK}").into_bytes(),
    );
    put(
        &mut files,
        outgoing.join(format!("{}.json", e2.id_hex())),
        serde_json::to_vec_pretty(&e2).unwrap(),
    );
    put(
        &mut files,
        outgoing.join(format!("{}.peer", e2.id_hex())),
        format!("12D3Koo{MARK}-out").into_bytes(),
    );

    Seed { files, leftovers }
}

fn everything_under(dir: &Path) -> Vec<PathBuf> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut v = Vec::new();
    walk(dir, &mut v);
    v.sort();
    v
}

/// Decrypt a converted file back to the bytes it had.
fn decrypted(keys: &StateKeys, path: &Path) -> Vec<u8> {
    match state_crypto::sniff(path) {
        Sniffed::Document(id) => {
            let label = Label::from_id(id).unwrap();
            state_crypto::read_document(keys, label, path)
                .unwrap()
                .to_vec()
        }
        Sniffed::Log(id) => {
            let label = Label::from_id(id).unwrap();
            let mut r = LogReader::open(keys, label, path).unwrap().unwrap();
            let mut out = Vec::new();
            while let Some(rec) = r.next_record().unwrap() {
                out.extend_from_slice(&rec);
                out.push(b'\n');
            }
            assert!(r.torn_at().is_none());
            out
        }
        other => panic!("{path:?} is not converted: {other:?}"),
    }
}

/// The non-blank lines of a plaintext JSONL file, newline-terminated.
fn jsonl_lines(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in raw.split(|b| *b == b'\n') {
        let t = line.trim_ascii();
        if !t.is_empty() {
            out.extend_from_slice(line.strip_suffix(b"\r").unwrap_or(line));
            out.push(b'\n');
        }
    }
    out
}

fn is_log_name(p: &Path) -> bool {
    p.extension().is_some_and(|e| e == "jsonl")
}

#[test]
fn conversion_keeps_every_byte_removes_plaintext_and_a_second_run_is_a_noop() {
    let dir = tempfile::tempdir().unwrap();
    let seed = seed(dir.path());
    assert!(needs_migration(dir.path()));

    let report = migrate_data_dir(dir.path()).unwrap();
    assert!(report.is_clean(), "{:?}", report.failures);
    assert_eq!(report.migrated, seed.files.len());
    assert_eq!(report.discarded_leftovers, seed.leftovers.len());
    assert_eq!(report.skipped_lines, 0);

    let keys = StateKeys::load(dir.path()).unwrap();
    for (path, original) in &seed.files {
        // Same content once decrypted.
        let back = decrypted(&keys, path);
        let want = if is_log_name(path) {
            jsonl_lines(original)
        } else {
            original.clone()
        };
        assert_eq!(back, want, "{path:?}");
        // No plaintext left in the file.
        let raw = std::fs::read(path).unwrap();
        assert!(
            !raw.windows(MARK.len()).any(|w| w == MARK.as_bytes()),
            "{path:?} still shows plaintext"
        );
        assert!(!raw.starts_with(b"{") && !raw.starts_with(b"mode"));
    }
    for gone in &seed.leftovers {
        assert!(!gone.exists(), "{gone:?}");
    }
    // Nothing but the converted files, the key and the lock remain.
    for p in everything_under(dir.path()) {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!name.ends_with(".premigrate"), "{name}");
        assert!(!name.ends_with(".tmp"), "{name}");
    }

    // Second run: nothing to do, nothing changes.
    let before: Vec<_> = everything_under(dir.path())
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    assert!(!needs_migration(dir.path()));
    let again = migrate_data_dir(dir.path()).unwrap();
    assert!(!again.changed_anything() && again.is_clean());
    let after: Vec<_> = everything_under(dir.path())
        .into_iter()
        .map(|p| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect();
    assert_eq!(before, after, "a second run must not touch a single byte");
}

#[test]
fn stores_see_exactly_the_old_data_with_or_without_the_bulk_conversion() {
    for bulk in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        if bulk {
            migrate_data_dir(dir.path()).unwrap();
        }

        let contacts = ContactStore::open(dir.path());
        let list = contacts.list();
        assert_eq!(list.len(), 2, "bulk={bulk}");
        assert_eq!(list[0].label, format!("{MARK} Taro"));
        assert!(!list[1].allow_receive && list[1].max_file_size == Some(1000));
        assert!(contacts
            .by_endpoint(contact_code(1).endpoint_id())
            .is_some());
        // Still writable after the conversion.
        contacts.add(&contact_code(3), Some("Jiro"), None).unwrap();
        assert_eq!(ContactStore::open(dir.path()).list().len(), 3);

        let h = History::open(dir.path());
        let l = h.list(1000);
        assert_eq!(l.len(), 40, "the damaged line is dropped, the rest kept");
        assert_eq!(l[0].id, "0039");
        h.append(&history_entry(40));
        assert_eq!(History::open(dir.path()).list(1)[0].id, "0040");

        let q = ReplicationQueue::load_or_create(dir.path()).unwrap();
        assert_eq!(q.pending_count(), 4, "five items, one acknowledged");
        assert!(q.get(&dht_record(3).mid_digest).is_some());

        let tdir = paths::transfers_dir(dir.path());
        let j = ReceiveJournal::load(&tdir.join("recv-3xAmpleMid.json")).unwrap();
        assert_eq!(j, receive_journal());
        let p = PublishJournal::load(&tdir.join("send-00112233445566778899aabbccddeeff.jsonl"))
            .unwrap();
        assert_eq!(p.header, publish_header());
        assert_eq!(p.segments.len(), 3);
        PublishJournal::append(
            &tdir.join("send-00112233445566778899aabbccddeeff.jsonl"),
            &publish_record(3),
        )
        .unwrap();

        let inbox = DirectedInbox::open(dir.path()).unwrap();
        let incoming = inbox.list_incoming();
        assert_eq!(incoming.len(), 1);
        assert_eq!(
            incoming[0].challenge_code.as_deref(),
            Some(&*format!("CODE-{MARK}"))
        );
        assert_eq!(
            incoming[0].sender_peer_id.as_deref(),
            Some(&*format!("12D3Koo{MARK}"))
        );
        assert_eq!(inbox.list_outgoing().len(), 1);
        let id_in = envelope(0x11).id_hex();
        assert_eq!(inbox.load_incoming(&id_in).unwrap().created_at, 1000 + 0x11);
        assert!(inbox.incoming_peer_is_bound(&id_in, &format!("12D3Koo{MARK}")));
        assert!(inbox.bind_incoming_peer_id(&id_in, "someone-else").is_err());

        // Whatever the route, nothing readable is left on disk.
        let _ = migrate_data_dir(dir.path()).unwrap();
        for p in everything_under(dir.path()) {
            let raw = std::fs::read(&p).unwrap();
            assert!(
                !raw.windows(MARK.len()).any(|w| w == MARK.as_bytes()),
                "bulk={bulk}: {p:?} still shows plaintext"
            );
        }
    }
}

/// A crash can stop the conversion of a file at any step. Each state a
/// restart can find must finish without losing the data.
#[test]
fn an_interrupted_conversion_resumes_from_every_state() {
    let name = paths::CONTACTS.name;

    // 1. Stopped before anything was renamed: a staged copy lies next to the
    //    untouched plaintext (here: a half-written one).
    {
        let dir = tempfile::tempdir().unwrap();
        let s = seed(dir.path());
        let orig = s.files[0].1.clone();
        let staged = paths::staged_tmp(&dir.path().join(name));
        std::fs::write(&staged, b"MSD1\x01\x01 half a document").unwrap();
        let r = migrate_data_dir(dir.path()).unwrap();
        assert!(r.is_clean(), "{:?}", r.failures);
        let keys = StateKeys::load(dir.path()).unwrap();
        assert_eq!(decrypted(&keys, &dir.path().join(name)), orig);
        assert!(!staged.exists());
    }

    // 2. Stopped between the two renames: the plaintext waits under its
    //    .premigrate name, the real name is missing.
    {
        let dir = tempfile::tempdir().unwrap();
        let s = seed(dir.path());
        let orig = s.files[0].1.clone();
        let real = dir.path().join(name);
        let old = paths::premigrate_copy(&real);
        std::fs::rename(&real, &old).unwrap();
        assert!(needs_migration(dir.path()));
        let r = migrate_data_dir(dir.path()).unwrap();
        assert!(r.is_clean() && r.recovered == 1, "{r:?}");
        let keys = StateKeys::load(dir.path()).unwrap();
        assert_eq!(decrypted(&keys, &real), orig);
        assert!(!old.exists());
    }

    // 3. Stopped before the plaintext was wiped: the protected file is in
    //    place and a plaintext copy is still lying beside it.
    {
        let dir = tempfile::tempdir().unwrap();
        let s = seed(dir.path());
        let orig = s.files[0].1.clone();
        migrate_data_dir(dir.path()).unwrap();
        let real = dir.path().join(name);
        let protected = std::fs::read(&real).unwrap();
        let old = paths::premigrate_copy(&real);
        std::fs::write(&old, &orig).unwrap();
        let r = migrate_data_dir(dir.path()).unwrap();
        assert!(r.is_clean() && r.recovered == 1, "{r:?}");
        assert!(!old.exists());
        assert_eq!(std::fs::read(&real).unwrap(), protected, "kept as it was");
    }

    // 4. The same for a log: the plaintext waits under .premigrate and a
    //    complete protected log is staged but was never moved in.
    {
        let dir = tempfile::tempdir().unwrap();
        let s = seed(dir.path());
        let (hist_path, hist_orig) = s
            .files
            .iter()
            .find(|(p, _)| p.ends_with(paths::PUSH_HISTORY.name))
            .cloned()
            .unwrap();
        let old = paths::premigrate_copy(&hist_path);
        std::fs::rename(&hist_path, &old).unwrap();
        let r = migrate_data_dir(dir.path()).unwrap();
        assert!(r.is_clean(), "{:?}", r.failures);
        let keys = StateKeys::load(dir.path()).unwrap();
        assert_eq!(decrypted(&keys, &hist_path), jsonl_lines(&hist_orig));
        assert!(!old.exists());
    }
}

#[test]
fn an_oversized_plaintext_line_is_skipped_and_counted_not_fatal() {
    let dir = tempfile::tempdir().unwrap();
    state_crypto::provision_master_key(dir.path()).unwrap();
    let mut text = serde_json::to_string(&history_entry(1)).unwrap();
    text.push('\n');
    text.push_str(&"x".repeat(200_000));
    text.push('\n');
    text.push_str(&serde_json::to_string(&history_entry(2)).unwrap());
    text.push('\n');
    std::fs::write(dir.path().join(paths::PUSH_HISTORY.name), text).unwrap();
    let r = migrate_data_dir(dir.path()).unwrap();
    assert_eq!(r.skipped_lines, 1);
    assert_eq!(History::open(dir.path()).list(10).len(), 2);
}

#[test]
fn without_a_master_key_nothing_is_read_written_or_created() {
    let dir = tempfile::tempdir().unwrap();
    let s = seed(dir.path());
    std::fs::remove_file(paths::master_key(dir.path())).unwrap();

    assert!(matches!(
        migrate_data_dir(dir.path()),
        Err(StateError::KeyMissing)
    ));
    assert!(!paths::master_key(dir.path()).exists(), "no key invented");
    for (p, original) in &s.files {
        assert_eq!(&std::fs::read(p).unwrap(), original, "{p:?} untouched");
    }
    assert!(!paths::state_migration_lock(dir.path()).exists());
}

#[test]
fn encrypted_state_fails_closed_when_the_master_key_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    migrate_data_dir(dir.path()).unwrap();
    // Put something in via the stores too.
    ContactStore::open(dir.path())
        .add(&contact_code(9), Some("Late"), None)
        .unwrap();
    let snapshot = |dir: &Path| -> Vec<(PathBuf, Vec<u8>)> {
        everything_under(dir)
            .into_iter()
            .filter(|p| {
                !p.ends_with(paths::MASTER_KEY.name)
                    && !p.ends_with(paths::STATE_MIGRATION_LOCK.name)
            })
            .map(|p| {
                let b = std::fs::read(&p).unwrap();
                (p, b)
            })
            .collect()
    };
    let before = snapshot(dir.path());

    // Delete the root of the key hierarchy.
    std::fs::remove_file(paths::master_key(dir.path())).unwrap();

    // Contacts: closed, empty, refuses changes.
    let c = ContactStore::open(dir.path());
    assert!(c.list().is_empty());
    assert!(c.add(&contact_code(5), Some("New"), None).is_err());
    // History: closed, empty, ignores appends.
    let h = History::open(dir.path());
    assert!(h.list(10).is_empty());
    h.append(&history_entry(1));
    // Queue and directed inbox refuse to start.
    assert!(ReplicationQueue::load_or_create(dir.path()).is_err());
    assert!(DirectedInbox::open(dir.path()).is_err());
    // Journals read as absent and cannot be saved.
    let tdir = paths::transfers_dir(dir.path());
    assert!(ReceiveJournal::load(&tdir.join("recv-3xAmpleMid.json")).is_none());
    assert!(receive_journal()
        .save(&tdir.join("recv-3xAmpleMid.json"))
        .is_err());
    assert!(StateKeys::open_or_init(dir.path()).is_err());
    assert!(matches!(
        migrate_data_dir(dir.path()),
        Err(StateError::KeyMissing)
    ));

    assert!(!paths::master_key(dir.path()).exists(), "no key invented");
    let after = snapshot(dir.path());
    assert_eq!(before, after, "not one byte of protected state changed");
}

#[test]
fn a_different_master_key_sets_files_aside_and_never_overwrites_them() {
    let dir = tempfile::tempdir().unwrap();
    seed(dir.path());
    migrate_data_dir(dir.path()).unwrap();
    let contacts_path = dir.path().join(paths::CONTACTS.name);
    let hist_path = dir.path().join(paths::PUSH_HISTORY.name);
    let contacts_bytes = std::fs::read(&contacts_path).unwrap();
    let hist_bytes = std::fs::read(&hist_path).unwrap();

    // The key file is replaced by another valid key.
    std::fs::write(paths::master_key(dir.path()), [0x42u8; 32]).unwrap();

    assert!(ContactStore::open(dir.path()).list().is_empty());
    assert!(History::open(dir.path()).list(10).is_empty());
    let asides: Vec<_> = everything_under(dir.path())
        .into_iter()
        .filter(|p| p.to_string_lossy().contains(".corrupt-"))
        .collect();
    let find = |bytes: &Vec<u8>| asides.iter().any(|p| &std::fs::read(p).unwrap() == bytes);
    assert!(find(&contacts_bytes), "the contacts file was kept");
    assert!(find(&hist_bytes), "the history was kept");
}

#[test]
fn damaged_files_are_handled_without_a_panic() {
    let flip = |p: &Path, at: usize| {
        let mut b = std::fs::read(p).unwrap();
        let i = at.min(b.len() - 1);
        b[i] ^= 0x55;
        std::fs::write(p, b).unwrap();
    };
    let setup = || {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        migrate_data_dir(dir.path()).unwrap();
        dir
    };

    // Contacts: a flipped byte anywhere, a cut file, a zero-length file.
    for at in [0usize, 4, 5, 10, 35, 100, 10_000] {
        let dir = setup();
        flip(&dir.path().join(paths::CONTACTS.name), at);
        assert!(
            ContactStore::open(dir.path()).list().is_empty(),
            "flip {at}"
        );
    }
    {
        let dir = setup();
        let p = dir.path().join(paths::CONTACTS.name);
        let b = std::fs::read(&p).unwrap();
        std::fs::write(&p, &b[..b.len() / 2]).unwrap();
        assert!(ContactStore::open(dir.path()).list().is_empty());
        std::fs::write(&p, b"").unwrap();
        assert!(ContactStore::open(dir.path()).list().is_empty());
    }
    // One protected file put where another class is expected.
    {
        let dir = setup();
        let wal = std::fs::read(dir.path().join(paths::REPLICATION_WAL.name)).unwrap();
        std::fs::write(dir.path().join(paths::PUSH_HISTORY.name), wal).unwrap();
        assert!(History::open(dir.path()).list(10).is_empty(), "label swap");
        let contacts = std::fs::read(dir.path().join(paths::CONTACTS.name)).unwrap();
        std::fs::write(dir.path().join(paths::DESKTOP_PREFS.name), &contacts).unwrap();
        let keys = StateKeys::load(dir.path()).unwrap();
        assert!(matches!(
            state_crypto::read_document(
                &keys,
                Label::DesktopPrefs,
                &dir.path().join(paths::DESKTOP_PREFS.name)
            ),
            Err(StateError::WrongLabel { .. })
        ));
    }
    // Directed envelope: damaged files are skipped by the listing.
    {
        let dir = setup();
        let inbox_dir = paths::directed_incoming_dir(dir.path());
        let f = inbox_dir.join(format!("{}.json", envelope(0x11).id_hex()));
        flip(&f, 40);
        let inbox = DirectedInbox::open(dir.path()).unwrap();
        assert!(inbox.list_incoming().is_empty());
        assert!(inbox.load_incoming(&envelope(0x11).id_hex()).is_err());
    }
    // Journals: damaged receive journal reads as none; publish journal keeps
    // the records before the damage.
    {
        let dir = setup();
        let tdir = paths::transfers_dir(dir.path());
        flip(&tdir.join("recv-3xAmpleMid.json"), 50);
        assert!(ReceiveJournal::load(&tdir.join("recv-3xAmpleMid.json")).is_none());
        let send = tdir.join("send-00112233445566778899aabbccddeeff.jsonl");
        let n = std::fs::metadata(&send).unwrap().len();
        // Cut inside the last record: the earlier ones survive.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&send)
            .unwrap()
            .set_len(n - 7)
            .unwrap();
        assert_eq!(PublishJournal::load(&send).unwrap().segments.len(), 2);
        // Damage in the first record (the header) means no journal.
        flip(&send, 30);
        assert!(PublishJournal::load(&send).is_none());
    }
    // Queue: a flipped byte in the middle keeps what came before and sets the
    // damaged file aside.
    {
        let dir = setup();
        let wal = dir.path().join(paths::REPLICATION_WAL.name);
        let len = std::fs::metadata(&wal).unwrap().len() as usize;
        flip(&wal, len / 3);
        let q = ReplicationQueue::load_or_create(dir.path()).unwrap();
        assert!(q.pending_count() < 5);
        assert!(everything_under(dir.path())
            .iter()
            .any(|p| p.to_string_lossy().contains(".corrupt-")));
    }
}
