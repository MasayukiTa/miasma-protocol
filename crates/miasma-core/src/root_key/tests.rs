use super::stub::{Stub, STUB_LEN};
use super::*;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

fn dir_with_plain_key() -> (tempfile::TempDir, [u8; 32]) {
    let d = tempfile::tempdir().unwrap();
    let key = random_bytes::<32>();
    std::fs::write(crate::paths::master_key(d.path()), key).unwrap();
    (d, key)
}

fn valid_stub() -> [u8; STUB_LEN] {
    Stub {
        provider: 1,
        flags: 0,
        install_id: random_bytes(),
        key_id: random_bytes(),
        created_epoch: 1_700_000_000,
    }
    .encode()
}

fn read_key(root: &RootKey) -> [u8; 32] {
    root.with(|k| *k).unwrap()
}

/// Every file below `dir` with its bytes, to prove nothing changed.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((p.clone(), std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn a_plain_key_is_read_without_changing_the_directory() {
    let (d, key) = dir_with_plain_key();
    let before = snapshot(d.path());
    for policy in [
        CreatePolicy::Never,
        CreatePolicy::IfFreshDataDir,
        CreatePolicy::FirstUse,
    ] {
        let root = get(d.path(), policy).unwrap();
        assert_eq!(read_key(&root), key);
    }
    assert_eq!(snapshot(d.path()), before);
    assert_eq!(status(d.path()), RootKeyState::File);
    assert!(is_initialized(d.path()));
}

#[test]
fn nothing_is_created_unless_the_policy_allows_it() {
    let d = tempfile::tempdir().unwrap();
    assert!(matches!(
        get(d.path(), CreatePolicy::Never),
        Err(RootKeyError::Missing)
    ));
    assert!(!is_initialized(d.path()));
    assert_eq!(status(d.path()), RootKeyState::Absent);
    assert!(snapshot(d.path()).is_empty());
}

#[test]
fn a_missing_key_is_created_once_and_reused() {
    let d = tempfile::tempdir().unwrap();
    let first = get(d.path(), CreatePolicy::FirstUse).unwrap();
    let on_disk = std::fs::read(crate::paths::master_key(d.path())).unwrap();
    assert_eq!(on_disk.len(), 32);
    assert_eq!(read_key(&first), on_disk.as_slice());
    let again = get(d.path(), CreatePolicy::IfFreshDataDir).unwrap();
    assert_eq!(read_key(&again), read_key(&first));
}

#[test]
fn a_fresh_directory_policy_refuses_next_to_protected_state() {
    let d = tempfile::tempdir().unwrap();
    // A key that existed once, state written under it, then the key lost.
    let keys = crate::state_crypto::StateKeys::open_or_init(d.path()).unwrap();
    crate::state_crypto::write_document(
        &keys,
        crate::state_crypto::Label::Contacts,
        &crate::paths::CONTACTS.in_dir(d.path()),
        b"{}",
    )
    .unwrap();
    std::fs::remove_file(crate::paths::master_key(d.path())).unwrap();
    assert!(matches!(
        get(d.path(), CreatePolicy::IfFreshDataDir),
        Err(RootKeyError::Missing)
    ));
    assert!(!crate::paths::master_key(d.path()).exists());
}

#[test]
fn unusable_key_files_are_errors_and_never_replaced() {
    let d = tempfile::tempdir().unwrap();
    let path = crate::paths::master_key(d.path());

    std::fs::write(&path, [0u8; 32]).unwrap();
    assert!(matches!(
        get(d.path(), CreatePolicy::FirstUse),
        Err(RootKeyError::Erased)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), vec![0u8; 32]);

    for len in [0usize, 16, 31, 33, 63, 65, 128] {
        std::fs::write(&path, vec![7u8; len]).unwrap();
        assert!(
            matches!(
                get(d.path(), CreatePolicy::FirstUse),
                Err(RootKeyError::WrongLength)
            ),
            "length {len}"
        );
        assert_eq!(std::fs::read(&path).unwrap().len(), len);
    }
}

#[test]
fn a_64_byte_marker_says_the_key_is_sealed_and_fails_closed() {
    let d = tempfile::tempdir().unwrap();
    let path = crate::paths::master_key(d.path());
    let marker = valid_stub();
    std::fs::write(&path, marker).unwrap();
    let before = snapshot(d.path());

    for policy in [
        CreatePolicy::Never,
        CreatePolicy::IfFreshDataDir,
        CreatePolicy::FirstUse,
    ] {
        let err = get(d.path(), policy).unwrap_err();
        assert!(matches!(err, RootKeyError::SealedFileMissing), "{err}");
        assert!(err.to_string().contains("sealed key unavailable"), "{err}");
    }
    // Every consumer reports the same clear error and creates nothing.
    let open_err = crate::store::LocalShareStore::open(d.path(), 10)
        .err()
        .expect("opening the store with a sealed key must fail");
    assert!(
        open_err.to_string().contains("sealed key unavailable"),
        "{open_err}"
    );
    assert!(matches!(
        crate::state_crypto::StateKeys::load(d.path()),
        Err(crate::state_crypto::StateError::KeyInvalid(m)) if m.contains("sealed key unavailable")
    ));
    assert!(crate::state_crypto::StateKeys::open_or_init(d.path()).is_err());
    crate::state_crypto::provision_master_key(d.path()).unwrap();

    assert_eq!(snapshot(d.path()), before);
    assert_eq!(status(d.path()), RootKeyState::Sealed);
    assert!(is_initialized(d.path()));
}

#[test]
fn a_damaged_64_byte_marker_is_refused_too() {
    let d = tempfile::tempdir().unwrap();
    let path = crate::paths::master_key(d.path());
    let mut marker = valid_stub();
    marker[30] ^= 1;
    std::fs::write(&path, marker).unwrap();
    assert!(matches!(
        get(d.path(), CreatePolicy::FirstUse),
        Err(RootKeyError::DamagedMarker)
    ));
    assert_eq!(status(d.path()), RootKeyState::Damaged);
    assert_eq!(std::fs::read(&path).unwrap(), marker);
}

#[test]
fn erasing_cached_handles_stops_holders_and_spares_other_directories() {
    let (a, key_a) = dir_with_plain_key();
    let (b, key_b) = dir_with_plain_key();
    let held = get(a.path(), CreatePolicy::Never).unwrap();
    let held_clone = held.clone();
    let other = get(b.path(), CreatePolicy::Never).unwrap();
    assert_eq!(read_key(&held), key_a);

    assert!(erase_cached(a.path()) >= 1);
    assert!(held.is_erased() && held_clone.is_erased());
    assert!(matches!(held.with(|k| *k), Err(RootKeyError::KeyErased)));
    assert!(!other.is_erased());
    assert_eq!(read_key(&other), key_b);
    // A file key can be read again afterwards (a new node may start in the
    // same process after a wipe).
    assert_eq!(
        read_key(&get(a.path(), CreatePolicy::Never).unwrap()),
        key_a
    );
}

#[test]
fn the_debug_output_never_shows_the_key() {
    let (d, key) = dir_with_plain_key();
    let root = get(d.path(), CreatePolicy::Never).unwrap();
    let shown = format!("{root:?}");
    assert_eq!(shown, "RootKey(<redacted>)");
    assert!(!shown.contains(&format!("{:?}", key)));
}

#[test]
fn wipe_removes_every_registered_key_file_without_opening_the_key() {
    let d = tempfile::tempdir().unwrap();
    let files = crate::paths::wipe_key_files(d.path());
    // The master key is damaged on purpose: opening it would fail.
    for (i, f) in files.iter().enumerate() {
        std::fs::write(f, vec![9u8; 5 + i]).unwrap();
    }
    assert!(get(d.path(), CreatePolicy::Never).is_err());

    let report = wipe_data_dir(d.path());
    assert!(report.is_complete(), "{:?}", report.errors);
    assert_eq!(report.key_files_removed, files.len());
    for f in &files {
        assert!(!f.exists(), "{} survived", f.display());
    }
    assert!(!crate::paths::WIPE_PENDING.in_dir(d.path()).exists());
    assert_eq!(status(d.path()), RootKeyState::Absent);
}

#[test]
fn wipe_removes_the_marker_of_a_sealed_key_too() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(crate::paths::master_key(d.path()), valid_stub()).unwrap();
    std::fs::write(crate::paths::ROOT_SEALED.in_dir(d.path()), b"placeholder").unwrap();
    let report = wipe_data_dir(d.path());
    assert!(report.is_complete(), "{:?}", report.errors);
    assert!(!crate::paths::master_key(d.path()).exists());
    assert!(!crate::paths::ROOT_SEALED.in_dir(d.path()).exists());
}

#[test]
fn wipe_of_a_missing_directory_creates_nothing() {
    let d = tempfile::tempdir().unwrap();
    let gone = d.path().join("never-created");
    let report = wipe_data_dir(&gone);
    assert!(report.is_complete());
    assert!(!gone.exists());
}

#[test]
fn an_interrupted_wipe_is_finished_without_opening_the_key() {
    let (d, _) = dir_with_plain_key();
    // The program stopped after writing the marker.
    std::fs::write(crate::paths::WIPE_PENDING.in_dir(d.path()), b"wipe\n").unwrap();
    assert_eq!(status(d.path()), RootKeyState::WipePending);

    assert!(matches!(
        get(d.path(), CreatePolicy::Never),
        Err(RootKeyError::Wiped)
    ));
    assert!(!crate::paths::master_key(d.path()).exists());
    assert!(!crate::paths::WIPE_PENDING.in_dir(d.path()).exists());
    // After that the directory is fresh again.
    assert!(get(d.path(), CreatePolicy::FirstUse).is_ok());
}

#[test]
fn a_wipe_in_this_process_owns_its_marker() {
    let (d, key) = dir_with_plain_key();
    std::fs::write(crate::paths::WIPE_PENDING.in_dir(d.path()), b"wipe\n").unwrap();
    let guard = wipe::Running::enter(d.path());
    assert!(matches!(
        get(d.path(), CreatePolicy::Never),
        Err(RootKeyError::WipePending)
    ));
    // The key is untouched while the running wipe has not removed it yet.
    assert_eq!(
        std::fs::read(crate::paths::master_key(d.path())).unwrap(),
        key
    );
    drop(guard);
}

#[test]
fn a_store_wipe_goes_through_the_same_path() {
    let d = tempfile::tempdir().unwrap();
    let store = crate::store::LocalShareStore::open(d.path(), 10).unwrap();
    assert!(crate::paths::master_key(d.path()).exists());
    let live = get(d.path(), CreatePolicy::Never).unwrap();
    store.distress_wipe().unwrap();
    assert!(!crate::paths::master_key(d.path()).exists());
    assert!(!crate::paths::WIPE_PENDING.in_dir(d.path()).exists());
    assert!(live.is_erased(), "live handles are erased by the wipe");
}
