//! Offline file deposit: hand an end-to-end encrypted file to holders so the
//! recipient can fetch it later, after the sender has gone offline.
//!
//! The direct push path (`push::service`) needs both ends online at the same
//! time: it keeps only the source path in the sender's outbox and retries from
//! the sender. That cannot deliver once the sender leaves. This module adds the
//! missing path: the sender splits the file into small ciphertext chunks,
//! deposits each chunk plus a manifest with trusted holders bound to the
//! recipient, and once enough holders acknowledge the deposit the sender may go
//! offline. The recipient later fetches the manifest and the chunks, verifies
//! and decrypts them, and reassembles the file.
//!
//! ## What a holder learns
//!
//! Nothing a relay would not. Every chunk and the manifest are sealed under a
//! fresh random key K. K is delivered to the recipient inside an end-to-end
//! chat message (hybrid protected, custody-backed), so a holder never sees K.
//! Deposits are bound to the
//! recipient by [`RecipientTag`], exactly as a chat custody deposit is, and the
//! item IDs are opaque.
//!
//! ## Memory
//!
//! Bounded. The sender reads the source one chunk at a time and never holds
//! more than one chunk plus the manifest in memory, so a file far larger than
//! RAM deposits in constant memory. The receiver writes each decrypted chunk to
//! its sink before fetching the next, so reassembly is constant memory too.
//!
//! ## Reuse, not a new format
//!
//! The bytes reach a holder through the existing [`MailboxTransport`] custody
//! verbs (deposit/list/fetch/delete); this module only decides what to put in
//! an item and how to put a file across many items. It does not invent a new
//! wire frame.

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use tracing::warn;

use crate::chat::mailbox::{
    client::{MailboxError, MailboxTransport},
    holder::{CustodyError, DepositOutcome},
    ids::{ItemId, RecipientTag},
};

/// Largest plaintext carried in one chunk item. A chat custody item holds at
/// most `MAX_ITEM_BYTES` bytes; a deposited chunk item is `[nonce..] + [header]
/// + ciphertext`, so the plaintext per chunk is kept well under that ceiling.
/// 16 KiB matches the largest chat plaintext bucket and keeps a chunk small
/// enough that a single holder's per-item cap is never the limit.
pub const CHUNK_PLAINTEXT: usize = 16 * 1024;

/// Domain-separation label for the per-deposit file key.
const DEPOSIT_KDF_LABEL: &[u8] = b"miasma/push/deposit/v1/filekey";
/// Info string that binds a chunk's key/nonce to its index, so a chunk can
/// never be decrypted as another index even under the same file key.
const CHUNK_INFO: &[u8] = b"miasma/push/deposit/v1/chunk";
/// Info string for the manifest item's key/nonce.
const MANIFEST_INFO: &[u8] = b"miasma/push/deposit/v1/manifest";

/// Nonce length of XChaCha20-Poly1305.
const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
const TAG_LEN: usize = 16;

/// A key derived from the random per-deposit key and salt.
#[derive(Clone)]
struct FileKey([u8; 32]);

impl FileKey {
    fn derive(input: &[u8; 32], salt: &[u8; 16]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(salt), input);
        let mut key = [0u8; 32];
        hk.expand(DEPOSIT_KDF_LABEL, &mut key)
            .expect("32 is a valid HKDF-SHA256 output length");
        FileKey(key)
    }

    /// The XChaCha20-Poly1305 key and nonce for one item, bound to `info` and
    /// `index`. The nonce is derived (not random) so both ends agree without
    /// storing it; the key is unique per (file key, info, index) so no nonce is
    /// ever reused under the same key.
    fn item_key_nonce(&self, info: &[u8], index: u64) -> ([u8; 32], [u8; NONCE_LEN]) {
        let hk = Hkdf::<Sha256>::new(Some(&index.to_be_bytes()), &self.0);
        let mut out = [0u8; 32 + NONCE_LEN];
        hk.expand(info, &mut out)
            .expect("56 is a valid HKDF-SHA256 output length");
        let key = out[..32].try_into().expect("key length");
        let nonce = out[32..].try_into().expect("nonce length");
        (key, nonce)
    }
}

/// Seal `plaintext` for one item: returns `ciphertext || tag`. The item key and
/// nonce are derived, so only the ciphertext and tag are stored.
fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buf = plaintext.to_vec();
    let tag: Tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, &mut buf)
        .expect("XChaCha20-Poly1305 encryption does not fail for a valid key");
    buf.extend_from_slice(&tag);
    buf
}

/// Open an item sealed by [`seal`]. `blob` is `ciphertext || tag`.
fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>, DepositError> {
    if blob.len() < TAG_LEN {
        return Err(DepositError::Corrupt);
    }
    let (ct, tag) = blob.split_at(blob.len() - TAG_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            aad,
            &mut buf,
            Tag::from_slice(tag),
        )
        .map_err(|_| DepositError::Corrupt)?;
    Ok(buf)
}

/// A problem met while depositing or fetching.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DepositError {
    /// Not enough holders acknowledged the deposit; the file is NOT delivered.
    #[error("only {held} of {needed} holders took the deposit")]
    NotDeposited { held: usize, needed: usize },
    /// A fetched item did not decrypt or did not match its hash.
    #[error("a fetched item is corrupt or altered")]
    Corrupt,
    /// The manifest is not yet available from any reachable holder.
    #[error("no manifest is available yet")]
    NoManifest,
    /// A chunk named by the manifest is missing from every reachable holder.
    #[error("a chunk is missing from the holders")]
    MissingChunk,
    /// The sink could not take a decrypted chunk.
    #[error("the receiving sink failed")]
    Sink,
}

fn item_id(index: u64, kind: u8, salt: &[u8; 16]) -> ItemId {
    // A stable, opaque per-file-per-index id. blake3 keyed by the salt so two
    // files never collide and a holder cannot tell one file's chunk n from
    // another's by the id alone.
    let mut input = Vec::with_capacity(1 + 8);
    input.push(kind);
    input.extend_from_slice(&index.to_be_bytes());
    let h = blake3::keyed_hash(
        &{
            let mut k = [0u8; 32];
            k[..16].copy_from_slice(salt);
            k
        },
        &input,
    );
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.as_bytes()[..16]);
    ItemId(id)
}

const KIND_MANIFEST: u8 = 0;
const KIND_CHUNK: u8 = 1;

/// Return the manifest item ID derived from the deposit salt.
pub(crate) fn manifest_id(salt: &[u8; 16]) -> ItemId {
    item_id(0, KIND_MANIFEST, salt)
}

pub(crate) fn chunk_id(index: u64, salt: &[u8; 16]) -> ItemId {
    item_id(index, KIND_CHUNK, salt)
}

/// The manifest of a deposited file: enough to fetch, verify and reassemble it
/// without the source. Serialised, sealed and deposited as one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Per-file salt (also the key for the item ids and the KDF).
    pub salt: [u8; 16],
    /// Total plaintext length.
    pub size: u64,
    /// Number of chunks.
    pub chunks: u64,
    /// Plaintext bytes per chunk (the last may be shorter).
    pub chunk_plaintext: u32,
    /// BLAKE3 of the whole plaintext file (for the final check).
    pub file_hash: [u8; 32],
}

impl Manifest {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + 8 + 8 + 4 + 32);
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.size.to_be_bytes());
        v.extend_from_slice(&self.chunks.to_be_bytes());
        v.extend_from_slice(&self.chunk_plaintext.to_be_bytes());
        v.extend_from_slice(&self.file_hash);
        v
    }

    fn decode(b: &[u8]) -> Result<Self, DepositError> {
        if b.len() != 16 + 8 + 8 + 4 + 32 {
            return Err(DepositError::Corrupt);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[..16]);
        let size = u64::from_be_bytes(b[16..24].try_into().unwrap());
        let chunks = u64::from_be_bytes(b[24..32].try_into().unwrap());
        let chunk_plaintext = u32::from_be_bytes(b[32..36].try_into().unwrap());
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&b[36..68]);
        Ok(Manifest {
            salt,
            size,
            chunks,
            chunk_plaintext,
            file_hash,
        })
    }
}

/// What a deposit achieved.
#[derive(Clone, PartialEq, Eq)]
pub struct DepositReceipt {
    /// The manifest the recipient will fetch.
    pub manifest: Manifest,
    /// Opaque identifier of the deposited manifest.
    pub manifest_id: ItemId,
    /// Random key to deliver to the recipient over the protected chat.
    pub file_key: [u8; 32],
    /// Holders that acknowledged every item (manifest and all chunks).
    pub held_by: Vec<[u8; 32]>,
    pub sha256: [u8; 32],
}

impl DepositReceipt {
    pub(crate) fn into_notice(
        self,
        salt: [u8; 16],
        file_name: String,
    ) -> crate::chat::proto::FileDepositNotice {
        crate::chat::proto::FileDepositNotice {
            file_key: self.file_key,
            salt,
            manifest_id: self.manifest_id.0,
            holders: self.held_by,
            file_name,
            size: self.manifest.size,
            sha256: self.sha256,
        }
    }
}

impl std::fmt::Debug for DepositReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DepositReceipt")
            .field("manifest", &self.manifest)
            .field("manifest_id", &self.manifest_id)
            .field("file_key", &"[REDACTED]")
            .field("held_by", &self.held_by)
            .finish()
    }
}

/// Deposit the plaintext read from `src` as an end-to-end encrypted file for
/// `recipient`, using `holders` (in order) and requiring at least `threshold`
/// of them to acknowledge every item.
///
/// `salt` binds this deposit to this file; pass fresh random bytes per file.
/// The receipt contains the manifest ID and the random key for delivery to the
/// recipient through the protected chat.
///
/// Memory is bounded: at most one chunk (`CHUNK_PLAINTEXT` bytes) is held at a
/// time regardless of file size. On success every chunk and the manifest are
/// held by at least `threshold` holders, so the sender may go offline. On
/// failure the error says the deposit did not happen; it never reports a
/// partial deposit as success.
#[allow(clippy::too_many_arguments)]
pub fn deposit_file<R: std::io::Read>(
    transport: &dyn MailboxTransport,
    holders: &[[u8; 32]],
    recipient: &[u8; 32],
    salt: [u8; 16],
    src: R,
    now_ms: u64,
    threshold: usize,
) -> Result<DepositReceipt, DepositError> {
    let mut file_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut file_key);
    deposit_file_with_key(
        transport, holders, recipient, file_key, salt, src, now_ms, threshold,
    )
}

/// Deposit using a previously persisted key and salt, allowing identical retries.
#[allow(clippy::too_many_arguments)]
pub fn deposit_file_with_key<R: std::io::Read>(
    transport: &dyn MailboxTransport,
    holders: &[[u8; 32]],
    recipient: &[u8; 32],
    file_key: [u8; 32],
    salt: [u8; 16],
    mut src: R,
    now_ms: u64,
    threshold: usize,
) -> Result<DepositReceipt, DepositError> {
    let needed = threshold.max(1);
    let fk = FileKey::derive(&file_key, &salt);
    let tag = RecipientTag::for_recipient(recipient);

    // Holders that have acknowledged *every* item so far. Start with all the
    // offered holders; intersect after each item with the ones that took it.
    let mut surviving: Vec<[u8; 32]> = Vec::new();
    for holder in holders {
        if holder != recipient && !surviving.contains(holder) {
            surviving.push(*holder);
        }
    }

    use sha2::{Digest, Sha256};
    let mut sha256 = Sha256::new();
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK_PLAINTEXT];
    let mut index: u64 = 0;
    let mut total: u64 = 0;
    loop {
        let n = read_full(&mut src, &mut buf).map_err(|_| DepositError::Sink)?;
        if n == 0 {
            break;
        }
        let plain = &buf[..n];
        hasher.update(plain);
        sha256.update(plain);
        total += n as u64;
        let (key, nonce) = fk.item_key_nonce(CHUNK_INFO, index);
        let id = item_id(index, KIND_CHUNK, &salt);
        let aad = chunk_aad(&salt, index);
        let blob = seal(&key, &nonce, &aad, plain);
        deposit_one(transport, &mut surviving, tag, id, &blob, now_ms, needed)?;
        index += 1;
        // A short read means the source ended; a full read may still be the end.
        if n < CHUNK_PLAINTEXT {
            break;
        }
    }

    let manifest = Manifest {
        salt,
        size: total,
        chunks: index,
        chunk_plaintext: CHUNK_PLAINTEXT as u32,
        file_hash: *hasher.finalize().as_bytes(),
    };
    // The manifest is deposited last: its presence means every chunk is already
    // held, so a recipient that sees the manifest can fetch the whole file.
    let (mkey, mnonce) = fk.item_key_nonce(MANIFEST_INFO, 0);
    let mid = item_id(0, KIND_MANIFEST, &salt);
    let maad = manifest_aad(&salt);
    let mblob = seal(&mkey, &mnonce, &maad, &manifest.encode());
    deposit_one(transport, &mut surviving, tag, mid, &mblob, now_ms, needed)?;

    Ok(DepositReceipt {
        manifest,
        manifest_id: mid,
        file_key,
        held_by: surviving,
        sha256: sha256.finalize().into(),
    })
}

/// Deposit one item with the still-surviving holders and keep only those that
/// took it. Fails (without depositing the rest of the file) if fewer than
/// `needed` hold it.
fn deposit_one(
    transport: &dyn MailboxTransport,
    surviving: &mut Vec<[u8; 32]>,
    tag: RecipientTag,
    id: ItemId,
    blob: &[u8],
    now_ms: u64,
    needed: usize,
) -> Result<(), DepositError> {
    let mut kept: Vec<[u8; 32]> = Vec::with_capacity(surviving.len());
    // Keep why the last holder that refused did so. A deposit under the
    // threshold rolls up to `NotDeposited`, which cannot carry a per-holder
    // reason without changing its shape; recording the last refusal here means
    // the failure can still say *why* (capacity, trust, budget, ...) instead of
    // leaving the operator to guess.
    let mut last_refusal: Option<CustodyError> = None;
    for h in surviving.iter() {
        match transport.deposit(h, tag, id, blob, now_ms) {
            Ok(DepositOutcome::Stored) | Ok(DepositOutcome::Duplicate) => kept.push(*h),
            Err(MailboxError::Unreachable) => {}
            Err(MailboxError::Refused(e)) => last_refusal = Some(e),
        }
    }
    if kept.len() < needed {
        if let Some(e) = last_refusal {
            warn!(
                held = kept.len(),
                needed,
                reason = %e,
                "a file chunk could not be deposited with enough holders"
            );
        }
        return Err(DepositError::NotDeposited {
            held: kept.len(),
            needed,
        });
    }
    *surviving = kept;
    Ok(())
}

/// Fetch, verify, decrypt and reassemble a file deposited by [`deposit_file`]
/// into `sink`, writing each chunk before fetching the next (bounded memory).
///
/// `file_key` is the random key delivered by the sender; `recipient` is the
/// endpoint id and `salt` is the per-file salt. Returns the verified
/// [`Manifest`] on success.
#[allow(clippy::too_many_arguments)]
pub fn fetch_file<W: std::io::Write>(
    transport: &dyn MailboxTransport,
    holders: &[[u8; 32]],
    file_key: &[u8; 32],
    recipient: &[u8; 32],
    salt: [u8; 16],
    mut sink: W,
    now_ms: u64,
) -> Result<Manifest, DepositError> {
    let fk = FileKey::derive(file_key, &salt);
    let tag = RecipientTag::for_recipient(recipient);

    let mid = item_id(0, KIND_MANIFEST, &salt);
    let mblob = fetch_any(transport, holders, recipient, tag, mid, now_ms)
        .ok_or(DepositError::NoManifest)?;
    let (mkey, mnonce) = fk.item_key_nonce(MANIFEST_INFO, 0);
    let maad = manifest_aad(&salt);
    let manifest = Manifest::decode(&open(&mkey, &mnonce, &maad, &mblob)?)?;

    let mut hasher = blake3::Hasher::new();
    let mut written: u64 = 0;
    for index in 0..manifest.chunks {
        let id = item_id(index, KIND_CHUNK, &salt);
        let blob = fetch_any(transport, holders, recipient, tag, id, now_ms)
            .ok_or(DepositError::MissingChunk)?;
        let (key, nonce) = fk.item_key_nonce(CHUNK_INFO, index);
        let aad = chunk_aad(&salt, index);
        let plain = open(&key, &nonce, &aad, &blob)?;
        hasher.update(&plain);
        written += plain.len() as u64;
        sink.write_all(&plain).map_err(|_| DepositError::Sink)?;
    }
    if written != manifest.size || hasher.finalize().as_bytes() != &manifest.file_hash {
        return Err(DepositError::Corrupt);
    }
    sink.flush().map_err(|_| DepositError::Sink)?;
    Ok(manifest)
}

/// Ask holders in order for one item; return the first blob found. Skips
/// holders that cannot be reached or do not have it.
fn fetch_any(
    transport: &dyn MailboxTransport,
    holders: &[[u8; 32]],
    recipient: &[u8; 32],
    tag: RecipientTag,
    id: ItemId,
    now_ms: u64,
) -> Option<Vec<u8>> {
    // Keep the last refusal so that when no holder yields the item, the log
    // says why the reachable holders turned it down (not trusted, expired and
    // swept, ...) rather than silently returning `None`.
    let mut last_refusal: Option<CustodyError> = None;
    for h in holders {
        if h == recipient {
            continue;
        }
        match transport.fetch(h, tag, id, now_ms) {
            Ok(Some(blob)) => return Some(blob),
            Ok(None) => {}
            Err(MailboxError::Unreachable) => {}
            Err(MailboxError::Refused(e)) => last_refusal = Some(e),
        }
    }
    if let Some(e) = last_refusal {
        warn!(reason = %e, "an item could not be fetched from any reachable holder");
    }
    None
}

/// Fill `buf` from `src`, returning the number of bytes read; short only at
/// end of input. Keeps chunking aligned so both ends agree on chunk bounds.
fn read_full<R: std::io::Read>(src: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn chunk_aad(salt: &[u8; 16], index: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(16 + 8 + 1);
    a.extend_from_slice(salt);
    a.extend_from_slice(&index.to_be_bytes());
    a.push(KIND_CHUNK);
    a
}

fn manifest_aad(salt: &[u8; 16]) -> Vec<u8> {
    let mut a = Vec::with_capacity(16 + 1);
    a.extend_from_slice(salt);
    a.push(KIND_MANIFEST);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::chat::crypto::Identity;
    use crate::chat::mailbox::holder::{CustodyLimits, CustodyStore, MemoryCustody};

    /// An in-process transport over a set of trusting holders. Each holder is a
    /// `MemoryCustody` keyed by its endpoint id; a deposit/list/fetch/delete is
    /// answered directly, with no network. This is the two-node custody path
    /// collapsed into one process for the test.
    struct InProcess {
        holders: Vec<([u8; 32], Arc<MemoryCustody>)>,
        /// The id the depositor/collector authenticates as.
        who: [u8; 32],
    }

    impl InProcess {
        fn store(&self, holder: &[u8; 32]) -> Option<&Arc<MemoryCustody>> {
            self.holders
                .iter()
                .find(|(id, _)| id == holder)
                .map(|(_, s)| s)
        }
    }

    impl MailboxTransport for InProcess {
        fn deposit(
            &self,
            holder: &[u8; 32],
            tag: RecipientTag,
            item: ItemId,
            blob: &[u8],
            now_ms: u64,
        ) -> Result<DepositOutcome, MailboxError> {
            let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
            s.deposit(&self.who, tag, item, blob, now_ms)
                .map_err(MailboxError::Refused)
        }
        fn list(
            &self,
            holder: &[u8; 32],
            tag: RecipientTag,
            now_ms: u64,
        ) -> Result<Vec<ItemId>, MailboxError> {
            let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
            s.list(&self.who, tag, now_ms)
                .map_err(MailboxError::Refused)
        }
        fn fetch(
            &self,
            holder: &[u8; 32],
            tag: RecipientTag,
            item: ItemId,
            now_ms: u64,
        ) -> Result<Option<Vec<u8>>, MailboxError> {
            let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
            s.fetch(&self.who, tag, item, now_ms)
                .map_err(MailboxError::Refused)
        }
        fn delete(
            &self,
            holder: &[u8; 32],
            tag: RecipientTag,
            item: ItemId,
        ) -> Result<bool, MailboxError> {
            let s = self.store(holder).ok_or(MailboxError::Unreachable)?;
            s.delete(&self.who, tag, item)
                .map_err(MailboxError::Refused)
        }
    }

    /// A custody store with room for a whole small file (the chat defaults are
    /// sized for single messages, not files). The hard ceilings still apply.
    fn file_holder(depositor: [u8; 32], recipient: [u8; 32]) -> Arc<MemoryCustody> {
        let limits = CustodyLimits {
            enabled: true,
            max_items: 1024,
            max_items_per_depositor: 1024,
            max_bytes_per_depositor: 4 * 1024 * 1024,
            max_total_bytes: 4 * 1024 * 1024,
            ..CustodyLimits::default()
        };
        let s = Arc::new(MemoryCustody::new(limits));
        s.trust(depositor);
        s.trust(recipient);
        s
    }

    fn ids() -> (Identity, Identity) {
        (
            Identity::from_seed(&[11u8; 32]),
            Identity::from_seed(&[22u8; 32]),
        )
    }

    #[test]
    fn sender_deposits_then_goes_away_and_recipient_receives_later() {
        let (sender, recipient) = ids();
        let holder_id = [7u8; 32];
        let store = file_holder(sender.id(), recipient.id());
        let salt = rand::random();
        // A file of a few chunks plus a partial last chunk.
        let file: Vec<u8> = (0..(CHUNK_PLAINTEXT * 3 + 123))
            .map(|i| (i % 251) as u8)
            .collect();

        // The sender deposits with its own transport, then is dropped entirely.
        let receipt = {
            let tx = InProcess {
                holders: vec![(holder_id, store.clone())],
                who: sender.id(),
            };
            deposit_file(
                &tx,
                &[holder_id],
                &recipient.id(),
                salt,
                &file[..],
                1_000,
                1,
            )
            .expect("deposit succeeds with one holder")
            // tx is dropped here: the sender is gone.
        };
        assert_eq!(receipt.held_by, vec![holder_id]);
        assert_eq!(receipt.manifest_id, item_id(0, KIND_MANIFEST, &salt));
        assert_eq!(receipt.manifest.chunks, 4);
        assert_eq!(receipt.manifest.size as usize, file.len());
        use sha2::{Digest, Sha256};
        let notice = receipt.clone().into_notice(salt, "example.bin".into());
        let decoded =
            crate::chat::proto::FileDepositNotice::decode(&notice.encode().unwrap()).unwrap();
        assert!(decoded == notice);
        assert_eq!(decoded.sha256, <[u8; 32]>::from(Sha256::digest(&file)));
        assert_eq!(decoded.size, file.len() as u64);
        assert_eq!(decoded.holders, vec![holder_id]);

        // Later, the recipient connects (a fresh transport) and fetches.
        let rx = InProcess {
            holders: vec![(holder_id, store.clone())],
            who: recipient.id(),
        };
        let mut out = Vec::new();
        let m = fetch_file(
            &rx,
            &[holder_id],
            &receipt.file_key,
            &recipient.id(),
            salt,
            &mut out,
            2_000,
        )
        .expect("recipient fetches after the sender left");
        assert_eq!(out, file);
        assert_eq!(m.file_hash, receipt.manifest.file_hash);
    }

    #[cfg(feature = "iroh")]
    #[test]
    fn verified_receive_places_only_matching_file() {
        use crate::chat::proto::FileDepositNotice;
        use crate::push::receive_offline::fetch_verified;
        use sha2::{Digest, Sha256};

        let (sender, recipient) = ids();
        let holder = [7u8; 32];
        let store = file_holder(sender.id(), recipient.id());
        let tx = InProcess {
            holders: vec![(holder, store.clone())],
            who: sender.id(),
        };
        let data = vec![42; CHUNK_PLAINTEXT * 3 + 1];
        let salt = [9; 16];
        let receipt =
            deposit_file(&tx, &[holder], &recipient.id(), salt, &data[..], 1_000, 1).unwrap();
        let rx = InProcess {
            holders: vec![(holder, store)],
            who: recipient.id(),
        };
        let mut notice = FileDepositNotice {
            file_key: receipt.file_key,
            salt,
            manifest_id: receipt.manifest_id.0,
            holders: receipt.held_by,
            file_name: "test.bin".into(),
            size: data.len() as u64,
            sha256: Sha256::digest(&data).into(),
        };
        let dir = tempfile::tempdir().unwrap();
        notice.sha256[0] ^= 1;
        assert!(fetch_verified(&rx, &recipient.id(), &notice, dir.path(), 2_000).is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        notice.sha256[0] ^= 1;
        let path = fetch_verified(&rx, &recipient.id(), &notice, dir.path(), 2_000).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), data);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn retry_with_saved_key_and_salt_reuses_items() {
        let (sender, recipient) = ids();
        let holder = [7u8; 32];
        let store = file_holder(sender.id(), recipient.id());
        let tx = InProcess {
            holders: vec![(holder, store.clone())],
            who: sender.id(),
        };
        let mut key = [0u8; 32];
        let mut salt = [0u8; 16];
        {
            use rand::rngs::OsRng;
            use rand::RngCore;
            OsRng.fill_bytes(&mut key);
            OsRng.fill_bytes(&mut salt);
        }
        let first = deposit_file_with_key(
            &tx,
            &[holder],
            &recipient.id(),
            key,
            salt,
            &b"file"[..],
            0,
            1,
        )
        .unwrap();
        let second = deposit_file_with_key(
            &tx,
            &[holder],
            &recipient.id(),
            key,
            salt,
            &b"file"[..],
            1,
            1,
        )
        .unwrap();
        assert_eq!(first.file_key, second.file_key);
        assert_eq!(first.manifest_id, second.manifest_id);
        assert_eq!(store.stats().items, 2);
    }

    #[test]
    fn each_deposit_gets_a_fresh_key() {
        let (sender, recipient) = ids();
        let holder = [7u8; 32];
        let tx = InProcess {
            holders: vec![(holder, file_holder(sender.id(), recipient.id()))],
            who: sender.id(),
        };
        let first = deposit_file(
            &tx,
            &[holder],
            &recipient.id(),
            rand::random(),
            &b"file"[..],
            0,
            1,
        )
        .unwrap();
        let second = deposit_file(
            &tx,
            &[holder],
            &recipient.id(),
            rand::random(),
            &b"file"[..],
            0,
            1,
        )
        .unwrap();
        assert_ne!(first.file_key, second.file_key);
    }

    #[test]
    fn too_few_holders_is_reported_as_not_delivered() {
        let (sender, recipient) = ids();
        let holder_id = [7u8; 32];
        let store = file_holder(sender.id(), recipient.id());
        let tx = InProcess {
            holders: vec![(holder_id, store)],
            who: sender.id(),
        };
        let file = vec![9u8; CHUNK_PLAINTEXT + 10];
        // One holder offered, but two acknowledgements required.
        let err = deposit_file(
            &tx,
            &[holder_id],
            &recipient.id(),
            rand::random(),
            &file[..],
            0,
            2,
        )
        .unwrap_err();
        assert_eq!(err, DepositError::NotDeposited { held: 1, needed: 2 });
    }

    #[test]
    fn duplicate_holder_ids_do_not_satisfy_threshold() {
        let (sender, recipient) = ids();
        let a = [7u8; 32];
        let b = [8u8; 32];
        let tx = InProcess {
            holders: vec![
                (a, file_holder(sender.id(), recipient.id())),
                (b, file_holder(sender.id(), recipient.id())),
            ],
            who: sender.id(),
        };
        let err = deposit_file(
            &tx,
            &[a, b, a],
            &recipient.id(),
            rand::random(),
            &b"data"[..],
            0,
            3,
        )
        .unwrap_err();
        assert_eq!(err, DepositError::NotDeposited { held: 2, needed: 3 });
    }

    #[test]
    fn an_unreachable_holder_does_not_count_as_delivered() {
        let (sender, recipient) = ids();
        // The transport knows no holders at all: every deposit is unreachable.
        let tx = InProcess {
            holders: vec![],
            who: sender.id(),
        };
        let file = vec![1u8; 100];
        let err = deposit_file(
            &tx,
            &[[7u8; 32]],
            &recipient.id(),
            rand::random(),
            &file[..],
            0,
            1,
        )
        .unwrap_err();
        assert_eq!(err, DepositError::NotDeposited { held: 0, needed: 1 });
    }

    #[test]
    fn a_wrong_file_key_cannot_open_the_file() {
        let (sender, recipient) = ids();
        let holder_id = [7u8; 32];
        let store = file_holder(sender.id(), recipient.id());
        let salt = rand::random();
        let file = vec![2u8; CHUNK_PLAINTEXT + 1];
        let tx = InProcess {
            holders: vec![(holder_id, store.clone())],
            who: sender.id(),
        };
        let receipt =
            deposit_file(&tx, &[holder_id], &recipient.id(), salt, &file[..], 0, 1).unwrap();
        // A different key cannot open the manifest.
        let mut wrong_key = receipt.file_key;
        wrong_key[0] ^= 1;
        let rx = InProcess {
            holders: vec![(holder_id, store)],
            who: recipient.id(),
        };
        let mut out = Vec::new();
        let err = fetch_file(
            &rx,
            &[holder_id],
            &wrong_key,
            &recipient.id(),
            salt,
            &mut out,
            0,
        )
        .unwrap_err();
        assert_eq!(err, DepositError::Corrupt);
        assert!(out.is_empty());
    }

    #[test]
    fn the_manifest_round_trips_through_its_bytes() {
        let m = Manifest {
            salt: [1u8; 16],
            size: 123456,
            chunks: 8,
            chunk_plaintext: CHUNK_PLAINTEXT as u32,
            file_hash: [9u8; 32],
        };
        assert_eq!(Manifest::decode(&m.encode()).unwrap(), m);
        assert!(Manifest::decode(&[0u8; 10]).is_err());
    }
}
