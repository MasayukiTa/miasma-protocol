//! Older releases meeting a `master.key` that is not a plain 32-byte key.
//!
//! A `master.key` of 64 bytes means "the key is kept elsewhere". Every released
//! reader accepts exactly 32 bytes, so it must stop with a length error and
//! must neither create a key nor touch anything else in the data directory.
//! If it started over with a new key, the node would lose its identity and
//! every share and state file written under the old one.
//!
//! `old_v0_1_0` and `old_v0_3_2_beta_11` hold the readers of those releases,
//! copied from their tags (`crates/miasma-core/src/store.rs`,
//! `crates/miasma-cli/src/main.rs`, `crates/miasma-core/src/daemon/mod.rs`,
//! `crates/miasma-core/src/state_crypto/mod.rs`). The creation branch is kept so
//! that the control tests can show the fixtures really do start over when the
//! file is absent. Nothing here uses a fixed key: every key and marker is
//! generated when the test runs.
//!
//! The released command-line program is exercised against the same kind of
//! directory by the `old-release-stub` job in `.github/workflows/ci.yml`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use miasma_core::root_key::stub::{Stub, STUB_LEN};
use miasma_core::root_key::{self, CreatePolicy, RootKeyError};

// ─── Readers of the earlier releases (copied from their tags) ────────────────

/// `v0.1.0-beta.1` (first release). Read paths are unchanged up to
/// `v0.3.1-beta.1`: a file that exists must be exactly 32 bytes.
mod old_v0_1_0 {
    use std::path::Path;

    /// `store.rs`: `load_or_create_master_key`. The permission hardening after
    /// the write is left out; it only runs after a key was created.
    pub fn load_or_create_master_key(data_dir: &Path) -> Result<[u8; 32], String> {
        let key_path = data_dir.join("master.key");
        if key_path.exists() {
            let bytes = std::fs::read(&key_path).map_err(|e| e.to_string())?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "key derivation failed: master.key has wrong length".to_string())?;
            Ok(arr)
        } else {
            let mut arr = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut arr);
            std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
            atomic_write(&key_path, &arr)?;
            Ok(arr)
        }
    }

    fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    /// `main.rs`: the key read at the start of `cmd_daemon`.
    pub fn cli_daemon_read(data_dir: &Path) -> Result<[u8; 32], String> {
        let master_key_path = data_dir.join("master.key");
        if !master_key_path.exists() {
            return Err("Node not initialised. Run `miasma init` first.".into());
        }
        let master_bytes = std::fs::read(&master_key_path).map_err(|e| e.to_string())?;
        master_bytes
            .try_into()
            .map_err(|_| "master.key has wrong length".to_string())
    }
}

/// `v0.3.2-beta.11` (latest release when this was written). The same rule,
/// plus the all-zero refusal, and two more readers (`StateKeys::load`, the
/// daemon's directed-sharing key).
mod old_v0_3_2_beta_11 {
    use std::path::Path;

    /// `store.rs`: `load_or_create_master_key`.
    pub fn load_or_create_master_key(data_dir: &Path) -> Result<[u8; 32], String> {
        let key_path = data_dir.join("master.key");
        if key_path.exists() {
            let bytes = std::fs::read(&key_path).map_err(|e| e.to_string())?;
            if bytes.len() != 32 {
                return Err("key derivation failed: master.key has wrong length".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            if arr.iter().all(|byte| *byte == 0) {
                return Err(
                    "key derivation failed: master.key is erased/all-zero; refusing known key material"
                        .into(),
                );
            }
            Ok(arr)
        } else {
            let mut arr = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut arr);
            std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
            miasma_core::secure_file::atomic_write_restricted(&key_path, &arr)
                .map_err(|e| format!("failed to write master.key: {e}"))?;
            Ok(arr)
        }
    }

    /// `main.rs`: the key read in `cmd_daemon`.
    pub fn cli_daemon_read(data_dir: &Path) -> Result<[u8; 32], String> {
        let master_key_path = data_dir.join("master.key");
        if !master_key_path.exists() {
            return Err("Node not initialised. Run `miasma init` first.".into());
        }
        let master_bytes = std::fs::read(&master_key_path).map_err(|e| e.to_string())?;
        if master_bytes.len() != 32 {
            return Err("master.key has wrong length".into());
        }
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_bytes);
        if master_key.iter().all(|byte| *byte == 0) {
            return Err("master.key is erased/all-zero".into());
        }
        Ok(master_key)
    }

    /// `daemon/mod.rs`: the key read before the directed-sharing key is derived.
    pub fn daemon_sharing_read(data_dir: &Path) -> Result<[u8; 32], String> {
        let master_key_path = data_dir.join("master.key");
        let master_bytes = std::fs::read(&master_key_path).map_err(|e| e.to_string())?;
        if master_bytes.len() != 32 {
            return Err(format!("{} has wrong length", master_key_path.display()));
        }
        if master_bytes.iter().all(|byte| *byte == 0) {
            return Err(format!("{} is erased/all-zero", master_key_path.display()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&master_bytes);
        Ok(out)
    }

    /// `state_crypto/mod.rs`: `StateKeys::load` (key lookup part). A missing
    /// file is an error here, never a new key.
    pub fn state_keys_load(data_dir: &Path) -> Result<[u8; 32], String> {
        let path = data_dir.join("master.key");
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err("the master key is missing".into())
            }
            Err(e) => return Err(e.to_string()),
        };
        if bytes.len() != 32 {
            return Err("the master key is unusable: wrong length".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

fn marker_bytes() -> [u8; STUB_LEN] {
    Stub {
        provider: 1,
        flags: 0,
        install_id: random_bytes(),
        key_id: random_bytes(),
        created_epoch: 1_700_000_000,
    }
    .encode()
}

/// A data directory as a node leaves it: the key file, a configuration, a share
/// and a state file. All content is random.
fn data_dir_with(master_key_bytes: &[u8]) -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("master.key"), master_key_bytes).unwrap();
    std::fs::write(d.path().join("config.toml"), random_bytes::<48>()).unwrap();
    std::fs::create_dir_all(d.path().join("shares")).unwrap();
    std::fs::write(d.path().join("shares").join("a.ms"), random_bytes::<200>()).unwrap();
    std::fs::write(d.path().join("store_index.json"), random_bytes::<64>()).unwrap();
    d
}

/// Every file below `dir` and its bytes.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().to_path_buf();
                out.insert(rel, std::fs::read(&p).unwrap());
            }
        }
    }
    out
}

// ─── The marker stops every older reader ─────────────────────────────────────

#[test]
fn every_older_reader_stops_on_the_marker_and_leaves_the_directory_alone() {
    let marker = marker_bytes();
    assert_eq!(marker.len(), 64);
    let d = data_dir_with(&marker);
    let before = snapshot(d.path());

    let results: Vec<(&str, Result<[u8; 32], String>)> = vec![
        (
            "v0.1.0 store",
            old_v0_1_0::load_or_create_master_key(d.path()),
        ),
        ("v0.1.0 cli", old_v0_1_0::cli_daemon_read(d.path())),
        (
            "v0.3.2-beta.11 store",
            old_v0_3_2_beta_11::load_or_create_master_key(d.path()),
        ),
        (
            "v0.3.2-beta.11 cli",
            old_v0_3_2_beta_11::cli_daemon_read(d.path()),
        ),
        (
            "v0.3.2-beta.11 daemon",
            old_v0_3_2_beta_11::daemon_sharing_read(d.path()),
        ),
        (
            "v0.3.2-beta.11 state",
            old_v0_3_2_beta_11::state_keys_load(d.path()),
        ),
    ];
    for (name, result) in results {
        let err = result.expect_err(name);
        assert!(err.contains("wrong length"), "{name}: {err}");
    }

    // No key was created, nothing was rewritten, no temporary file was left.
    assert_eq!(snapshot(d.path()), before);
    assert_eq!(
        std::fs::read(d.path().join("master.key")).unwrap(),
        marker.to_vec()
    );
}

#[test]
fn the_fixtures_do_start_over_when_the_file_is_absent_and_read_a_plain_key() {
    // Controls: without them the test above could pass because the copied
    // readers never create anything.
    let absent = tempfile::tempdir().unwrap();
    let k1 = old_v0_1_0::load_or_create_master_key(absent.path()).unwrap();
    assert_eq!(std::fs::read(absent.path().join("master.key")).unwrap(), k1);

    let absent = tempfile::tempdir().unwrap();
    let k2 = old_v0_3_2_beta_11::load_or_create_master_key(absent.path()).unwrap();
    assert_eq!(std::fs::read(absent.path().join("master.key")).unwrap(), k2);

    let key = random_bytes::<32>();
    let plain = data_dir_with(&key);
    assert_eq!(
        old_v0_1_0::load_or_create_master_key(plain.path()).unwrap(),
        key
    );
    assert_eq!(old_v0_1_0::cli_daemon_read(plain.path()).unwrap(), key);
    assert_eq!(
        old_v0_3_2_beta_11::load_or_create_master_key(plain.path()).unwrap(),
        key
    );
    assert_eq!(
        old_v0_3_2_beta_11::cli_daemon_read(plain.path()).unwrap(),
        key
    );
    assert_eq!(
        old_v0_3_2_beta_11::daemon_sharing_read(plain.path()).unwrap(),
        key
    );
    assert_eq!(
        old_v0_3_2_beta_11::state_keys_load(plain.path()).unwrap(),
        key
    );
}

#[test]
fn an_older_reader_also_stops_on_a_marker_of_any_content() {
    // The older readers look at the length only, so a marker whose layout
    // changes later is still safe as long as it is not 32 bytes.
    let d = data_dir_with(&random_bytes::<64>());
    let before = snapshot(d.path());
    assert!(old_v0_3_2_beta_11::load_or_create_master_key(d.path()).is_err());
    assert!(old_v0_1_0::load_or_create_master_key(d.path()).is_err());
    assert_eq!(snapshot(d.path()), before);
}

// ─── This build ──────────────────────────────────────────────────────────────

#[test]
fn this_build_reports_a_sealed_key_clearly_and_creates_nothing() {
    let d = data_dir_with(&marker_bytes());
    let before = snapshot(d.path());

    for policy in [
        CreatePolicy::Never,
        CreatePolicy::IfFreshDataDir,
        CreatePolicy::FirstUse,
    ] {
        match root_key::get(d.path(), policy) {
            Err(RootKeyError::SealedFileMissing) => {}
            other => panic!("expected SealedFileMissing, got {other:?}"),
        }
    }
    let store_err = miasma_core::LocalShareStore::open(d.path(), 10)
        .err()
        .expect("the store must not open");
    assert!(
        store_err.to_string().contains("sealed key unavailable"),
        "{store_err}"
    );
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn a_plain_key_still_works_and_stays_byte_identical() {
    let key = random_bytes::<32>();
    let d = data_dir_with(&key);
    let before = snapshot(d.path());
    let root = root_key::get(d.path(), CreatePolicy::Never).unwrap();
    assert_eq!(root.with(|k| *k).unwrap(), key);
    drop(root);
    assert_eq!(snapshot(d.path()), before);
}

// ─── A directory this build sealed ───────────────────────────────────────────

/// Every copied reader, in one list.
fn older_readers(dir: &Path) -> Vec<(&'static str, Result<[u8; 32], String>)> {
    vec![
        ("v0.1.0 store", old_v0_1_0::load_or_create_master_key(dir)),
        ("v0.1.0 cli", old_v0_1_0::cli_daemon_read(dir)),
        (
            "v0.3.2-beta.11 store",
            old_v0_3_2_beta_11::load_or_create_master_key(dir),
        ),
        (
            "v0.3.2-beta.11 cli",
            old_v0_3_2_beta_11::cli_daemon_read(dir),
        ),
        (
            "v0.3.2-beta.11 daemon",
            old_v0_3_2_beta_11::daemon_sharing_read(dir),
        ),
        (
            "v0.3.2-beta.11 state",
            old_v0_3_2_beta_11::state_keys_load(dir),
        ),
    ]
}

fn sealing_provider() -> root_key::SealedProvider {
    root_key::SealedProvider::new(std::sync::Arc::new(root_key::FileWrap))
}

#[test]
fn a_plain_key_sealed_by_this_build_stops_every_older_reader_and_is_still_opened_here() {
    let key = random_bytes::<32>();
    let d = data_dir_with(&key);
    let root = root_key::get_with(d.path(), CreatePolicy::Never, &sealing_provider()).unwrap();
    assert_eq!(root.with(|k| *k).unwrap(), key);
    assert_eq!(
        std::fs::read(d.path().join("master.key")).unwrap().len(),
        STUB_LEN
    );
    assert!(d.path().join("root.sealed").exists());
    let before = snapshot(d.path());

    for (name, result) in older_readers(d.path()) {
        let err = result.expect_err(name);
        assert!(err.contains("wrong length"), "{name}: {err}");
    }
    // No older reader started a new key or rewrote anything.
    assert_eq!(snapshot(d.path()), before);

    // This build opens it with and without a sealing provider.
    let plain_provider = root_key::get(d.path(), CreatePolicy::Never).unwrap();
    assert_eq!(plain_provider.with(|k| *k).unwrap(), key);
    assert_eq!(snapshot(d.path()), before);
}

#[test]
fn a_key_created_sealed_by_this_build_stops_every_older_reader() {
    let d = tempfile::tempdir().unwrap();
    let root = root_key::get_with(d.path(), CreatePolicy::FirstUse, &sealing_provider()).unwrap();
    let key = root.with(|k| *k).unwrap();
    let before = snapshot(d.path());
    for (name, result) in older_readers(d.path()) {
        let err = result.expect_err(name);
        assert!(
            err.contains("wrong length") || err.contains("wrong"),
            "{name}: {err}"
        );
    }
    assert_eq!(snapshot(d.path()), before);
    assert_eq!(
        root_key::get(d.path(), CreatePolicy::Never)
            .unwrap()
            .with(|k| *k)
            .unwrap(),
        key
    );
}

#[test]
fn a_sealed_file_of_a_newer_version_is_named_not_misread() {
    let d = tempfile::tempdir().unwrap();
    root_key::get_with(d.path(), CreatePolicy::FirstUse, &sealing_provider()).unwrap();
    let path = d.path().join("root.sealed");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[4] = 9;
    std::fs::write(&path, &bytes).unwrap();
    let before = snapshot(d.path());
    match root_key::get(d.path(), CreatePolicy::FirstUse) {
        Err(RootKeyError::FutureVersion { found: 9, .. }) => {}
        other => panic!("expected FutureVersion, got {other:?}"),
    }
    assert_eq!(snapshot(d.path()), before);
}
