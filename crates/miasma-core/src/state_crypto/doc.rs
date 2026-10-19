//! Document shape: one small file, replaced whole.
//!
//! ```text
//! offset  size  field
//!      0     4  magic "MSD1"
//!      4     1  format version (1)
//!      5     1  label id
//!      6    24  random XChaCha20 nonce
//!     30     n  ciphertext
//!   30+n    16  Poly1305 tag
//! ```
//!
//! Associated data = `magic | version | label id | context`, where the
//! context is the file name. A document copied over another file of the same
//! class therefore fails to open, as does one whose label byte was changed.

use std::path::Path;

use zeroize::Zeroizing;

use super::{
    fsync_path, open_detached, seal_detached, sync_parent_dir, Label, StateError, StateKeys,
    DOC_MAGIC, NONCE_LEN, TAG_LEN,
};

pub const DOC_VERSION: u8 = 1;
/// Bytes before the ciphertext.
pub const DOC_HEADER_LEN: usize = 4 + 1 + 1 + NONCE_LEN;

fn aad(label: Label, ctx: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(6 + ctx.len());
    a.extend_from_slice(DOC_MAGIC);
    a.push(DOC_VERSION);
    a.push(label.id());
    a.extend_from_slice(ctx);
    a
}

/// The context bound to a document: the final file name.
pub(crate) fn context_of(path: &Path) -> Vec<u8> {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned().into_bytes())
        .unwrap_or_default()
}

/// Encrypt `plaintext` into the full on-disk bytes of a document.
pub fn seal(
    keys: &StateKeys,
    label: Label,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, StateError> {
    let limit = label.max_document_bytes();
    if plaintext.len() > limit {
        return Err(StateError::TooLarge {
            size: plaintext.len() as u64,
            limit: limit as u64,
        });
    }
    let nonce: [u8; NONCE_LEN] = rand::random();
    let mut out = Vec::with_capacity(DOC_HEADER_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(DOC_MAGIC);
    out.push(DOC_VERSION);
    out.push(label.id());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let key = keys.doc_key(label)?;
    let tag = seal_detached(
        &key,
        &nonce,
        &aad(label, context),
        &mut out[DOC_HEADER_LEN..],
    )?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypt the full on-disk bytes of a document (consumed; the returned buffer
/// is the plaintext and is wiped on drop).
pub fn open(
    keys: &StateKeys,
    label: Label,
    context: &[u8],
    mut file: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, StateError> {
    if file.len() < DOC_HEADER_LEN + TAG_LEN {
        // A short file that does not even start like ours is "not protected";
        // a prefix of our own header is a truncated document.
        let n = file.len().min(4);
        return Err(if file[..n] == DOC_MAGIC[..n] && n > 0 {
            StateError::Truncated
        } else if file.is_empty() {
            StateError::Truncated
        } else {
            StateError::NotProtected
        });
    }
    if &file[..4] != DOC_MAGIC {
        return Err(StateError::NotProtected);
    }
    if file[4] != DOC_VERSION {
        return Err(StateError::UnsupportedVersion(file[4]));
    }
    if file[5] != label.id() {
        return Err(StateError::WrongLabel {
            expected: label.id(),
            found: file[5],
        });
    }
    let nonce: [u8; NONCE_LEN] = file[6..DOC_HEADER_LEN].try_into().expect("slice length");
    let tag_at = file.len() - TAG_LEN;
    let tag: [u8; TAG_LEN] = file[tag_at..].try_into().expect("slice length");
    let key = keys.doc_key(label)?;
    let res = open_detached(
        &key,
        &nonce,
        &aad(label, context),
        &mut file[DOC_HEADER_LEN..tag_at],
        &tag,
    );
    let mut plain = Zeroizing::new(file);
    res?;
    plain.truncate(tag_at);
    plain.drain(..DOC_HEADER_LEN);
    Ok(plain)
}

/// Read and decrypt the document at `path`.
pub fn read_document(
    keys: &StateKeys,
    label: Label,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, StateError> {
    read_document_as(keys, label, path, &context_of(path))
}

/// Like [`read_document`] for a file that is read under another name than the
/// one it was sealed for (a staged copy).
pub(crate) fn read_document_as(
    keys: &StateKeys,
    label: Label,
    path: &Path,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, StateError> {
    let size = std::fs::metadata(path)?.len();
    let limit = (label.max_document_bytes() + DOC_HEADER_LEN + TAG_LEN) as u64;
    if size > limit {
        return Err(StateError::TooLarge { size, limit });
    }
    let bytes = std::fs::read(path)?;
    open(keys, label, context, bytes)
}

/// Write `plaintext` to `path`: sealed, written to a temp file next to it,
/// flushed to disk, then renamed into place.
pub fn write_document(
    keys: &StateKeys,
    label: Label,
    path: &Path,
    plaintext: &[u8],
) -> Result<(), StateError> {
    let tmp = stage_document(keys, label, path, plaintext)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    sync_parent_dir(path);
    Ok(())
}

/// Write a document only if `path` does not exist yet. `Ok(true)` when this
/// call created it, `Ok(false)` when it was already there (untouched).
pub fn write_document_new(
    keys: &StateKeys,
    label: Label,
    path: &Path,
    plaintext: &[u8],
) -> Result<bool, StateError> {
    if path.exists() {
        return Ok(false);
    }
    let tmp = stage_document(keys, label, path, plaintext)?;
    // A hard link fails when the target exists, so a competing writer cannot be replaced.
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            sync_parent_dir(path);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Write the sealed document for `path` to a durable temp file and return the
/// temp path (not yet renamed). Callers serialise writers of one file.
pub(crate) fn stage_document(
    keys: &StateKeys,
    label: Label,
    path: &Path,
    plaintext: &[u8],
) -> Result<std::path::PathBuf, StateError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sealed = seal(keys, label, &context_of(path), plaintext)?;
    let tmp = crate::paths::staged_tmp(path);
    crate::secure_file::write_restricted(&tmp, &sealed).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    fsync_path(&tmp)?;
    Ok(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(b: u8) -> StateKeys {
        StateKeys::from_master_key(&[b; 32]).unwrap()
    }

    #[test]
    fn round_trip_for_every_label() {
        let k = keys(7);
        for label in Label::ALL {
            let sealed = seal(&k, label, b"file.json", b"hello world").unwrap();
            assert_eq!(&sealed[..4], b"MSD1");
            assert_eq!(sealed[5], label.id());
            assert!(!sealed.windows(5).any(|w| w == b"hello"));
            let plain = open(&k, label, b"file.json", sealed).unwrap();
            assert_eq!(plain.as_slice(), b"hello world");
        }
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = keys(1);
        let sealed = seal(&k, Label::Contacts, b"c", b"").unwrap();
        assert_eq!(sealed.len(), DOC_HEADER_LEN + TAG_LEN);
        assert!(open(&k, Label::Contacts, b"c", sealed).unwrap().is_empty());
    }

    #[test]
    fn nonces_are_fresh() {
        let k = keys(2);
        let a = seal(&k, Label::Contacts, b"c", b"same").unwrap();
        let b = seal(&k, Label::Contacts, b"c", b"same").unwrap();
        assert_ne!(a[6..30], b[6..30]);
        assert_ne!(a[30..], b[30..]);
    }

    #[test]
    fn every_single_byte_flip_is_rejected() {
        let k = keys(3);
        let sealed = seal(&k, Label::Contacts, b"c", b"some contacts").unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x01;
            assert!(open(&k, Label::Contacts, b"c", bad).is_err(), "byte {i}");
        }
    }

    #[test]
    fn label_swap_and_context_swap_are_rejected() {
        let k = keys(4);
        let sealed = seal(&k, Label::Contacts, b"a.json", b"x").unwrap();
        assert!(matches!(
            open(&k, Label::DesktopPrefs, b"a.json", sealed.clone()),
            Err(StateError::WrongLabel { .. })
        ));
        // Header byte rewritten to the other label: the key differs, so it fails.
        let mut forged = sealed.clone();
        forged[5] = Label::DesktopPrefs.id();
        assert!(matches!(
            open(&k, Label::DesktopPrefs, b"a.json", forged),
            Err(StateError::Authentication)
        ));
        assert!(matches!(
            open(&k, Label::Contacts, b"b.json", sealed),
            Err(StateError::Authentication)
        ));
    }

    #[test]
    fn wrong_key_truncation_and_garbage_do_not_panic() {
        let k = keys(5);
        let sealed = seal(&k, Label::Contacts, b"c", b"payload").unwrap();
        assert!(matches!(
            open(&keys(6), Label::Contacts, b"c", sealed.clone()),
            Err(StateError::Authentication)
        ));
        for n in 0..sealed.len() {
            assert!(open(&k, Label::Contacts, b"c", sealed[..n].to_vec()).is_err());
        }
        assert!(matches!(
            open(&k, Label::Contacts, b"c", Vec::new()),
            Err(StateError::Truncated)
        ));
        assert!(matches!(
            open(&k, Label::Contacts, b"c", b"{\"contacts\":[]}".repeat(5)),
            Err(StateError::NotProtected)
        ));
        let mut v2 = sealed;
        v2[4] = 9;
        assert!(matches!(
            open(&k, Label::Contacts, b"c", v2),
            Err(StateError::UnsupportedVersion(9))
        ));
    }

    #[test]
    fn size_limit_is_enforced_both_ways() {
        let k = keys(8);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.dat");
        let huge = vec![0u8; Label::DesktopPrefs.max_document_bytes() + 1];
        assert!(matches!(
            seal(&k, Label::DesktopPrefs, b"big.dat", &huge),
            Err(StateError::TooLarge { .. })
        ));
        // A file longer than the limit is refused before it is read.
        let f = std::fs::File::create(&p).unwrap();
        f.set_len((Label::DesktopPrefs.max_document_bytes() + DOC_HEADER_LEN + TAG_LEN + 1) as u64)
            .unwrap();
        assert!(matches!(
            read_document(&k, Label::DesktopPrefs, &p),
            Err(StateError::TooLarge { .. })
        ));
    }

    #[test]
    fn write_then_read_replaces_atomically_and_leaves_no_temp() {
        let k = keys(9);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("prefs.toml");
        write_document(&k, Label::DesktopPrefs, &p, b"one").unwrap();
        write_document(&k, Label::DesktopPrefs, &p, b"two").unwrap();
        assert_eq!(
            read_document(&k, Label::DesktopPrefs, &p)
                .unwrap()
                .as_slice(),
            b"two"
        );
        let names: Vec<_> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        // The file name is part of what was sealed.
        let moved = dir.path().join("sub").join("other.toml");
        std::fs::rename(&p, &moved).unwrap();
        assert!(read_document(&k, Label::DesktopPrefs, &moved).is_err());
    }
}
