//! Tests of the sealed form: start-up rules, the automatic move, and what a
//! stopped program leaves behind. Every key is generated when the test runs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::sealed::{self, ALL_STEPS, STOP_AFTER};
use super::stub::{Stub, STUB_LEN};
use super::*;
use crate::secure_memory::SecureBytes;

fn rnd<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

/// A wrap that works like the file wrap and can be switched off and counted.
struct TestWrap {
    id: ProviderId,
    state: Mutex<Availability>,
    unwraps: AtomicUsize,
}

impl TestWrap {
    fn new(id: ProviderId) -> Arc<Self> {
        Arc::new(Self {
            id,
            state: Mutex::new(Availability::Ready),
            unwraps: AtomicUsize::new(0),
        })
    }
    fn set(&self, a: Availability) {
        *self.state.lock().unwrap() = a;
    }
}

impl DeviceWrap for TestWrap {
    fn id(&self) -> ProviderId {
        self.id
    }
    fn available(&self) -> Availability {
        *self.state.lock().unwrap()
    }
    fn wrap(&self, dir: &Path, aad: &[u8], root: &[u8; 32]) -> Result<Vec<u8>, WrapError> {
        FileWrap.wrap(dir, aad, root)
    }
    fn unwrap(&self, dir: &Path, aad: &[u8], wrapped: &[u8]) -> Result<SecureBytes<32>, WrapError> {
        self.unwraps.fetch_add(1, Ordering::SeqCst);
        FileWrap.unwrap(dir, aad, wrapped)
    }
    fn destroy(&self, _dir: &Path) -> Result<DestroyOutcome, WrapError> {
        Ok(DestroyOutcome::NothingToDestroy)
    }
}

fn sealing() -> (Arc<TestWrap>, SealedProvider) {
    let w = TestWrap::new(ProviderId::File);
    let p = SealedProvider::new(w.clone());
    (w, p)
}

fn master(dir: &Path) -> PathBuf {
    crate::paths::master_key(dir)
}

fn sealed_file(dir: &Path) -> PathBuf {
    crate::paths::ROOT_SEALED.in_dir(dir)
}

fn plain_dir() -> (tempfile::TempDir, [u8; 32]) {
    let d = tempfile::tempdir().unwrap();
    let key = rnd::<32>();
    std::fs::write(master(d.path()), key).unwrap();
    (d, key)
}

/// A directory whose key `key` is already sealed.
fn sealed_dir() -> (tempfile::TempDir, [u8; 32]) {
    let (d, key) = plain_dir();
    let (_, p) = sealing();
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
        key
    );
    assert_eq!(std::fs::read(master(d.path())).unwrap().len(), STUB_LEN);
    (d, key)
}

fn read_key(r: &RootKey) -> [u8; 32] {
    r.with(|k| *k).unwrap()
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn expected(files: &[&crate::paths::PathSpec]) -> Vec<String> {
    let mut v: Vec<String> = files.iter().map(|s| s.name.to_string()).collect();
    v.sort();
    v
}

fn sealed_names_with_lock() -> Vec<String> {
    expected(&[
        &crate::paths::MASTER_KEY,
        &crate::paths::ROOT_SEALED,
        &crate::paths::WRAP_SECRET,
        &crate::paths::STATE_MIGRATION_LOCK,
    ])
}

/// Every file with its bytes, except the advisory lock (its creation is not a
/// change to the key).
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = names(dir)
        .into_iter()
        .filter(|n| n != crate::paths::STATE_MIGRATION_LOCK.name)
        .filter(|n| dir.join(n).is_file())
        .map(|n| {
            let bytes = std::fs::read(dir.join(&n)).unwrap();
            (n, bytes)
        })
        .collect();
    out.sort();
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn no_file_holds(dir: &Path, secret: &[u8]) {
    for n in names(dir) {
        if n == crate::paths::WRAP_SECRET.name {
            continue;
        }
        let bytes = std::fs::read(dir.join(&n)).unwrap();
        assert!(!contains(&bytes, secret), "{n} holds the plain key");
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── Sealing a plain key ─────────────────────────────────────────────────────

#[test]
fn a_plain_key_is_sealed_at_start_up_without_asking_anything() {
    let (d, key) = plain_dir();
    let (_, p) = sealing();
    let root = get_with(d.path(), CreatePolicy::Never, &p).unwrap();
    assert_eq!(read_key(&root), key);

    // The key file is now the marker; the key itself is nowhere in the clear.
    let marker = std::fs::read(master(d.path())).unwrap();
    assert_eq!(marker.len(), STUB_LEN);
    Stub::parse(&marker).unwrap();
    assert_eq!(names(d.path()), sealed_names_with_lock());
    no_file_holds(d.path(), &key);
    assert_eq!(status(d.path()), RootKeyState::Sealed);

    // Any program, with or without a sealing provider, reads the same key.
    for again in [
        get_with(d.path(), CreatePolicy::Never, &p).unwrap(),
        get_with(d.path(), CreatePolicy::Never, &FileProvider).unwrap(),
    ] {
        assert_eq!(read_key(&again), key);
    }
}

#[test]
fn sealing_twice_changes_nothing() {
    let (d, key) = plain_dir();
    let (wrap, p) = sealing();
    get_with(d.path(), CreatePolicy::Never, &p).unwrap();
    let after_first = snapshot(d.path());

    for _ in 0..3 {
        assert_eq!(
            read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
            key
        );
    }
    // Asking for the move again, directly, finds nothing to do.
    let secure = SecureBytes::from_slice(&key);
    assert_eq!(
        sealed::migrate(d.path(), &*wrap, &secure).unwrap(),
        sealed::Moved::Skipped
    );
    assert!(!seal_with(d.path(), &*wrap).unwrap());
    assert_eq!(snapshot(d.path()), after_first);
}

#[test]
fn without_a_sealing_provider_nothing_is_ever_written() {
    let (d, key) = plain_dir();
    let before = snapshot(d.path());
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &FileProvider).unwrap()),
        key
    );
    assert_eq!(snapshot(d.path()), before);
    assert_eq!(names(d.path()).len(), 1);
}

#[test]
fn an_unavailable_key_store_leaves_the_plain_key_in_use() {
    let (d, key) = plain_dir();
    let (wrap, p) = sealing();
    wrap.set(Availability::Unavailable("key store locked"));
    let before = snapshot(d.path());
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
        key
    );
    assert_eq!(snapshot(d.path()), before);
    assert_eq!(names(d.path()), vec![crate::paths::MASTER_KEY.name]);

    // Once it is back, the key is sealed on the next start.
    wrap.set(Availability::Ready);
    get_with(d.path(), CreatePolicy::Never, &p).unwrap();
    assert_eq!(status(d.path()), RootKeyState::Sealed);
}

#[test]
fn killed_after_every_step_the_next_start_converges_and_the_key_never_changes() {
    for step in ALL_STEPS {
        let (d, key) = plain_dir();
        let (wrap, p) = sealing();
        let secure = SecureBytes::from_slice(&key);

        STOP_AFTER.with(|c| c.set(Some(step)));
        let stopped = sealed::migrate(d.path(), &*wrap, &secure);
        STOP_AFTER.with(|c| c.set(None));
        assert!(stopped.is_err(), "{step:?} did not stop");

        // At the moment of the kill: master.key exists (a program that only
        // knows the plain file never sees it missing), and it is the plain key
        // or a valid marker.
        let on_disk = std::fs::read(master(d.path()))
            .unwrap_or_else(|e| panic!("master.key missing after {step:?}: {e}"));
        match on_disk.len() {
            32 => assert_eq!(on_disk, key, "{step:?}"),
            STUB_LEN => {
                Stub::parse(&on_disk).unwrap();
            }
            n => panic!("{step:?}: master.key has {n} bytes"),
        }

        // With the key store down, a key that is still plain keeps working.
        if on_disk.len() == 32 {
            wrap.set(Availability::Unavailable("key store locked"));
            let r = get_with(d.path(), CreatePolicy::Never, &p).unwrap();
            assert_eq!(read_key(&r), key, "{step:?}");
            wrap.set(Availability::Ready);
        }

        // Restart: the same key, and the directory has settled.
        let r = get_with(d.path(), CreatePolicy::Never, &p).unwrap();
        assert_eq!(read_key(&r), key, "{step:?}");
        assert_eq!(names(d.path()), sealed_names_with_lock(), "{step:?}");
        Stub::parse(&std::fs::read(master(d.path())).unwrap()).unwrap();
        no_file_holds(d.path(), &key);

        // A further start changes nothing; a program without the provider
        // reads the same key.
        let settled = snapshot(d.path());
        assert_eq!(
            read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
            key
        );
        assert_eq!(
            read_key(&get_with(d.path(), CreatePolicy::Never, &FileProvider).unwrap()),
            key
        );
        assert_eq!(snapshot(d.path()), settled, "{step:?}");
    }
}

#[test]
fn a_move_whose_sealed_file_was_damaged_in_the_gap_goes_back_to_the_plain_key() {
    let (d, key) = plain_dir();
    let (wrap, p) = sealing();
    let secure = SecureBytes::from_slice(&key);
    // Stopped right after the marker replaced the plain file; the old key is
    // still there under its second name.
    STOP_AFTER.with(|c| c.set(Some(sealed::Step::StubInPlace)));
    assert!(sealed::migrate(d.path(), &*wrap, &secure).is_err());
    STOP_AFTER.with(|c| c.set(None));
    assert_eq!(std::fs::read(master(d.path())).unwrap().len(), STUB_LEN);

    let mut b = std::fs::read(sealed_file(d.path())).unwrap();
    let last = b.len() - 1;
    b[last] ^= 1;
    std::fs::write(sealed_file(d.path()), &b).unwrap();

    let r = get_with(d.path(), CreatePolicy::Never, &p).unwrap();
    assert_eq!(read_key(&r), key);
    // The plain key is back in place and the damaged file is kept aside.
    assert_eq!(std::fs::read(master(d.path())).unwrap(), key);
    assert!(!sealed_file(d.path()).exists());
    assert!(names(d.path())
        .iter()
        .any(|n| n.starts_with("root.sealed.corrupt-")));
    // And the next start seals it again.
    get_with(d.path(), CreatePolicy::Never, &p).unwrap();
    assert_eq!(status(d.path()), RootKeyState::Sealed);
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
        key
    );
}

#[test]
fn two_starts_at_once_agree_on_one_key() {
    let (d, key) = plain_dir();
    let (_, p) = sealing();
    let p = Arc::new(p);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let p = p.clone();
            let dir = d.path().to_path_buf();
            std::thread::spawn(move || read_key(&get_with(&dir, CreatePolicy::Never, &*p).unwrap()))
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), key);
    }
    assert_eq!(status(d.path()), RootKeyState::Sealed);
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &*p).unwrap()),
        key
    );
}

// ── A new key, sealed from the start ────────────────────────────────────────

#[test]
fn a_new_key_is_created_sealed_and_never_appears_in_the_clear() {
    let d = tempfile::tempdir().unwrap();
    let (_, p) = sealing();
    let root = get_with(d.path(), CreatePolicy::FirstUse, &p).unwrap();
    let key = read_key(&root);
    assert_ne!(key, [0u8; 32]);
    assert_eq!(
        names(d.path()),
        expected(&[
            &crate::paths::MASTER_KEY,
            &crate::paths::ROOT_SEALED,
            &crate::paths::WRAP_SECRET
        ])
    );
    assert_eq!(std::fs::read(master(d.path())).unwrap().len(), STUB_LEN);
    no_file_holds(d.path(), &key);
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &FileProvider).unwrap()),
        key
    );
}

#[test]
fn several_creators_at_once_end_with_one_key() {
    let d = tempfile::tempdir().unwrap();
    let (_, p) = sealing();
    let p = Arc::new(p);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let p = p.clone();
            let dir = d.path().to_path_buf();
            std::thread::spawn(move || {
                read_key(&get_with(&dir, CreatePolicy::FirstUse, &*p).unwrap())
            })
        })
        .collect();
    let keys: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(keys.iter().all(|k| *k == keys[0]));
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &*p).unwrap()),
        keys[0]
    );
}

#[test]
fn the_store_and_state_keys_open_a_sealed_directory_through_the_default_provider() {
    let (d, _) = plain_dir();
    let (_, p) = sealing();
    get_with(d.path(), CreatePolicy::Never, &p).unwrap();
    let key_files = |d: &Path| {
        [
            master(d),
            sealed_file(d),
            crate::paths::WRAP_SECRET.in_dir(d),
        ]
        .map(|f| std::fs::read(f).unwrap())
    };
    let before = key_files(d.path());
    crate::store::LocalShareStore::open(d.path(), 10).unwrap();
    crate::state_crypto::StateKeys::load(d.path()).unwrap();
    assert_eq!(key_files(d.path()), before);
}

// ── The start-up rules, one row per combination ─────────────────────────────

enum Expect {
    Key,
    Err(fn(&RootKeyError) -> bool),
}

struct Row {
    label: &'static str,
    policy: CreatePolicy,
    /// Builds the directory; returns the key that is meant to open (if any).
    setup: fn(&Path) -> Option<[u8; 32]>,
    expect: Expect,
    /// `true` when the call may change the directory (the move, a marker
    /// restored); error rows must leave it byte-identical.
    changes: bool,
}

fn seal_into(dir: &Path) -> [u8; 32] {
    let key = rnd::<32>();
    std::fs::write(master(dir), key).unwrap();
    let (_, p) = sealing();
    get_with(dir, CreatePolicy::Never, &p).unwrap();
    key
}

fn flip(path: &Path, at: usize) {
    let mut b = std::fs::read(path).unwrap();
    let i = if at == usize::MAX { b.len() - 1 } else { at };
    b[i] ^= 1;
    std::fs::write(path, b).unwrap();
}

#[test]
fn start_up_rules_table() {
    let rows: Vec<Row> = vec![
        Row {
            label: "nothing, creation not allowed",
            policy: CreatePolicy::Never,
            setup: |_| None,
            expect: Expect::Err(|e| matches!(e, RootKeyError::Missing)),
            changes: false,
        },
        Row {
            label: "plain key",
            policy: CreatePolicy::Never,
            setup: |d| {
                let k = rnd::<32>();
                std::fs::write(master(d), k).unwrap();
                Some(k)
            },
            expect: Expect::Key,
            changes: true,
        },
        Row {
            label: "marker + sealed file",
            policy: CreatePolicy::Never,
            setup: |d| Some(seal_into(d)),
            expect: Expect::Key,
            changes: false,
        },
        Row {
            label: "marker only",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                std::fs::remove_file(sealed_file(d)).unwrap();
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::SealedFileMissing)),
            changes: false,
        },
        Row {
            label: "sealed file only (marker lost)",
            policy: CreatePolicy::Never,
            setup: |d| {
                let k = seal_into(d);
                std::fs::remove_file(master(d)).unwrap();
                Some(k)
            },
            expect: Expect::Key,
            changes: true,
        },
        Row {
            label: "damaged marker",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                flip(&master(d), 30);
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::DamagedMarker)),
            changes: false,
        },
        Row {
            label: "marker of a newer version",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                let mut b = std::fs::read(master(d)).unwrap();
                b[8] = 2;
                std::fs::write(master(d), b).unwrap();
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::FutureVersion { found: 2, .. })),
            changes: false,
        },
        Row {
            label: "sealed file of a newer version",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                let mut b = std::fs::read(sealed_file(d)).unwrap();
                b[4] = 2;
                std::fs::write(sealed_file(d), b).unwrap();
                None
            },
            expect: Expect::Err(|e| {
                matches!(
                    e,
                    RootKeyError::FutureVersion {
                        file: "the sealed key file",
                        found: 2
                    }
                ) && e.to_string().contains("update the program")
            }),
            changes: false,
        },
        Row {
            label: "sealed file cut short",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                let b = std::fs::read(sealed_file(d)).unwrap();
                std::fs::write(sealed_file(d), &b[..b.len() - 5]).unwrap();
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::SealedCorrupt(_))),
            changes: false,
        },
        Row {
            label: "wrapped key altered",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                flip(&sealed_file(d), usize::MAX);
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::SealedCorrupt(_))),
            changes: false,
        },
        Row {
            label: "header altered (record no longer authenticates)",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                // The creation time is part of the authenticated header.
                flip(&sealed_file(d), 41);
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::SealedCorrupt(_))),
            changes: false,
        },
        Row {
            label: "sealed file of another install",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                let other = tempfile::tempdir().unwrap();
                seal_into(other.path());
                std::fs::copy(sealed_file(other.path()), sealed_file(d)).unwrap();
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::SealedMismatch)),
            changes: false,
        },
        Row {
            label: "wrapping secret deleted",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                seal_into(d);
                std::fs::remove_file(crate::paths::WRAP_SECRET.in_dir(d)).unwrap();
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::SealedKeyGone)),
            changes: false,
        },
        Row {
            label: "plain key + sealed file of a newer version",
            policy: CreatePolicy::Never,
            setup: |d| {
                let other = tempfile::tempdir().unwrap();
                seal_into(other.path());
                let mut b = std::fs::read(sealed_file(other.path())).unwrap();
                b[4] = 2;
                std::fs::write(sealed_file(d), b).unwrap();
                let k = rnd::<32>();
                std::fs::write(master(d), k).unwrap();
                Some(k)
            },
            // The plain key is used and the newer file is left untouched.
            expect: Expect::Key,
            changes: false,
        },
        Row {
            label: "erased plain key",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                std::fs::write(master(d), [0u8; 32]).unwrap();
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::Erased)),
            changes: false,
        },
        Row {
            label: "master.key of a wrong length",
            policy: CreatePolicy::FirstUse,
            setup: |d| {
                std::fs::write(master(d), [7u8; 63]).unwrap();
                None
            },
            expect: Expect::Err(|e| matches!(e, RootKeyError::WrongLength)),
            changes: false,
        },
    ];

    for row in rows {
        let d = tempfile::tempdir().unwrap();
        let wanted = (row.setup)(d.path());
        let before = snapshot(d.path());
        let (_, p) = sealing();
        let result = get_with(d.path(), row.policy, &p);
        match (&row.expect, result) {
            (Expect::Key, Ok(root)) => {
                assert_eq!(Some(read_key(&root)), wanted, "{}", row.label);
            }
            (Expect::Err(pred), Err(e)) => {
                assert!(pred(&e), "{}: unexpected error {e:?}", row.label);
                // Errors say what is wrong without showing key material.
                let shown = format!("{e} {e:?}");
                if let Some(k) = wanted {
                    assert!(!shown.contains(&hex(&k)), "{}", row.label);
                }
            }
            (Expect::Key, Err(e)) => panic!("{}: expected the key, got {e:?}", row.label),
            (Expect::Err(_), Ok(_)) => panic!("{}: expected an error", row.label),
        }
        if !row.changes {
            assert_eq!(
                snapshot(d.path()),
                before,
                "{} changed the directory",
                row.label
            );
        }
    }
}

#[test]
fn a_damaged_sealed_file_next_to_a_plain_key_is_set_aside_and_replaced() {
    let (d, key) = plain_dir();
    std::fs::write(sealed_file(d.path()), rnd::<90>()).unwrap();
    let (_, p) = sealing();
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
        key
    );
    assert_eq!(status(d.path()), RootKeyState::Sealed);
    assert!(names(d.path())
        .iter()
        .any(|n| n.starts_with("root.sealed.corrupt-")));
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
        key
    );
}

#[test]
fn a_pending_wipe_wins_over_every_other_file() {
    let (d, _) = sealed_dir();
    std::fs::write(crate::paths::WIPE_PENDING.in_dir(d.path()), b"wipe\n").unwrap();
    let (_, p) = sealing();
    assert!(matches!(
        get_with(d.path(), CreatePolicy::FirstUse, &p),
        Err(RootKeyError::Wiped)
    ));
    assert!(!master(d.path()).exists() && !sealed_file(d.path()).exists());
}

// ── Providers and versions ──────────────────────────────────────────────────

#[test]
fn a_key_sealed_by_another_provider_needs_that_provider() {
    let d = tempfile::tempdir().unwrap();
    let keystore = TestWrap::new(ProviderId::Keystore);
    let p = SealedProvider::new(keystore.clone());
    let key = read_key(&get_with(d.path(), CreatePolicy::FirstUse, &p).unwrap());
    let before = snapshot(d.path());

    // The marker names the provider.
    let stub = Stub::parse(&std::fs::read(master(d.path())).unwrap()).unwrap();
    assert_eq!(stub.provider, ProviderId::Keystore as u8);

    // The file provider and the file wrap cannot open it, and change nothing.
    let (_, file_sealing) = sealing();
    for prov in [&FileProvider as &dyn RootKeyProvider, &file_sealing] {
        assert!(matches!(
            get_with(d.path(), CreatePolicy::FirstUse, prov),
            Err(RootKeyError::SealedUnavailable)
        ));
    }
    assert_eq!(snapshot(d.path()), before);
    // The right provider opens it, and a provider that is down reports that.
    assert_eq!(
        read_key(&get_with(d.path(), CreatePolicy::Never, &p).unwrap()),
        key
    );
    keystore.set(Availability::Unavailable("key store locked"));
    assert!(matches!(
        get_with(d.path(), CreatePolicy::Never, &p),
        Err(RootKeyError::KeyStoreUnavailable(m)) if m.contains("locked")
    ));
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn the_wrap_is_bound_to_the_header_and_the_record() {
    let (d, _) = sealed_dir();
    let bytes = std::fs::read(sealed_file(d.path())).unwrap();
    let blob = format::Blob::parse(&bytes).unwrap();
    let rec = blob.device_record();
    // The right aad opens; any other header or record head does not.
    FileWrap
        .unwrap(d.path(), &rec.aad(&blob.header), &rec.wrapped)
        .unwrap();
    let mut other_header = blob.header;
    other_header.install_id[0] ^= 1;
    assert!(matches!(
        FileWrap.unwrap(d.path(), &rec.aad(&other_header), &rec.wrapped),
        Err(WrapError::Corrupt)
    ));
    let mut other_record = rec.clone();
    other_record.kdf_id = format::KDF_NONE;
    assert!(matches!(
        FileWrap.unwrap(d.path(), &other_record.aad(&blob.header), &rec.wrapped),
        Err(WrapError::Corrupt)
    ));
    // Two wraps of the same key are not equal (fresh nonce).
    let key = rnd::<32>();
    let a = FileWrap.wrap(d.path(), b"aad", &key).unwrap();
    let b = FileWrap.wrap(d.path(), b"aad", &key).unwrap();
    assert_ne!(a, b);
    assert!(!contains(&a, &key));
}

#[test]
fn nothing_secret_is_printed() {
    let d = tempfile::tempdir().unwrap();
    let (_, p) = sealing();
    let root = get_with(d.path(), CreatePolicy::FirstUse, &p).unwrap();
    let key = read_key(&root);
    let secret = std::fs::read(crate::paths::WRAP_SECRET.in_dir(d.path())).unwrap();
    let bytes = std::fs::read(sealed_file(d.path())).unwrap();
    let blob = format::Blob::parse(&bytes).unwrap();
    let stub = Stub::parse(&std::fs::read(master(d.path())).unwrap()).unwrap();

    let shown = [
        format!("{root:?}"),
        format!("{p:?}"),
        format!("{:?}", FileWrap),
        format!("{blob:?}"),
        format!("{:?}", blob.header),
        format!("{stub:?}"),
        format!("{:?}", WrapError::Corrupt),
    ]
    .join(" ");
    for secret_bytes in [&key[..], &secret[..]] {
        assert!(!shown.contains(&hex(secret_bytes)));
        assert!(!shown.contains(&format!("{:?}", secret_bytes)));
        assert!(!shown.contains(&format!("{:?}", secret_bytes.to_vec())));
    }
    assert_eq!(format!("{root:?}"), "RootKey(<redacted>)");
}

// ── Wipe ────────────────────────────────────────────────────────────────────

#[test]
fn a_wipe_removes_the_sealed_file_the_marker_and_every_leftover_without_opening_the_key() {
    let (d, _) = sealed_dir();
    // What a stopped move can leave beside the key files.
    let leftovers = [
        crate::paths::premigrate_copy(&master(d.path())),
        crate::paths::staged_tmp(&sealed_file(d.path())),
        crate::paths::corrupt_aside(&sealed_file(d.path()), 1_700_000_000),
        d.path().join("master.key.0123456789ab.sec.tmp"),
    ];
    for l in &leftovers {
        std::fs::write(l, rnd::<40>()).unwrap();
    }
    // Opening the key would fail: the secret that wraps it is gone.
    std::fs::remove_file(crate::paths::WRAP_SECRET.in_dir(d.path())).unwrap();
    assert!(get_with(d.path(), CreatePolicy::Never, &FileProvider).is_err());
    std::fs::write(crate::paths::WRAP_SECRET.in_dir(d.path()), rnd::<32>()).unwrap();

    let report = wipe_data_dir(d.path());
    assert!(report.is_complete(), "{:?}", report.errors);
    assert!(report.key_files_removed >= 3 + leftovers.len());
    for l in &leftovers {
        assert!(!l.exists(), "{} survived", l.display());
    }
    let left: Vec<String> = names(d.path())
        .into_iter()
        .filter(|n| n != crate::paths::STATE_MIGRATION_LOCK.name)
        .collect();
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(status(d.path()), RootKeyState::Absent);
}

#[test]
fn a_wipe_interrupted_before_the_sealed_file_went_is_finished_without_opening() {
    let (d, _) = sealed_dir();
    std::fs::write(crate::paths::WIPE_PENDING.in_dir(d.path()), b"wipe\n").unwrap();
    let wrap = TestWrap::new(ProviderId::File);
    let p = SealedProvider::new(wrap.clone());
    assert!(matches!(
        get_with(d.path(), CreatePolicy::Never, &p),
        Err(RootKeyError::Wiped)
    ));
    assert_eq!(wrap.unwraps.load(Ordering::SeqCst), 0);
    assert_eq!(status(d.path()), RootKeyState::Absent);
}
