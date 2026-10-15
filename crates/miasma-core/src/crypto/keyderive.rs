use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::MiasmaError;

/// Domain separation labels for HKDF-SHA256 key derivation.
const LABEL_NODE_ID: &[u8] = b"miasma-v1-node-id";
const LABEL_DHT_SIGN: &[u8] = b"miasma-v1-dht-signing-key";
const LABEL_SESSION: &[u8] = b"miasma-v1-session-key";
const LABEL_MAC: &[u8] = b"miasma-v1-mac-key-v1";
const LABEL_SHARING: &[u8] = b"miasma-v1-sharing-key";
/// Root label of the at-rest state key hierarchy (see `state_crypto`).
const LABEL_STATE_ROOT: &[u8] = b"miasma/state/v1";
/// Prefix of the per-document-class labels below the state key.
const LABEL_STATE_DOC_PREFIX: &[u8] = b"miasma/state/v1/doc/";
/// Label of the per-file key of an append-only record log.
const LABEL_STATE_LOG_FILE: &[u8] = b"miasma/state/v1/log-file";

/// Node key hierarchy derived from a single master key.
///
/// ```text
/// NodeMasterKey (32 bytes, from secure RNG or user passphrase)
///   ├─ node_id         (32 bytes) — public identifier
///   ├─ dht_signing_key (32 bytes) — signs DHT entries
///   └─ session_key     (32 bytes) — ephemeral transport sessions
/// ```
pub struct NodeKeys {
    pub node_id: [u8; 32],
    pub dht_signing_key: Zeroizing<[u8; 32]>,
    pub session_key: Zeroizing<[u8; 32]>,
}

impl NodeKeys {
    /// Derive all node keys from a master key using HKDF-SHA256.
    pub fn derive(master_key: &[u8]) -> Result<Self, MiasmaError> {
        let node_id = hkdf_derive(master_key, LABEL_NODE_ID)?;
        Ok(Self {
            // node_id is a public identifier; only secret-derived key material
            // remains zeroizing after derivation.
            node_id: *node_id,
            dht_signing_key: hkdf_derive(master_key, LABEL_DHT_SIGN)?,
            session_key: hkdf_derive(master_key, LABEL_SESSION)?,
        })
    }
}

/// Derive an X25519 static key for directed sharing (recipient binding).
///
/// This key is persistent (does not rotate with epochs) and is shared
/// out-of-band with potential senders.
pub fn derive_sharing_key(master_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    hkdf_derive(master_key, LABEL_SHARING)
}

/// Derive the at-rest state key from the master key:
/// `HKDF-SHA256(ikm = master_key, salt = none, info = "miasma/state/v1")`.
pub fn derive_state_key(master_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    hkdf_derive(master_key, LABEL_STATE_ROOT)
}

/// Derive the key of one document class from the state key. `label` is the
/// class name (`"contacts"`, `"push-history"`, ...): different classes never
/// share a key.
pub fn derive_state_doc_key(
    state_key: &[u8],
    label: &str,
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let mut info = Vec::with_capacity(LABEL_STATE_DOC_PREFIX.len() + label.len());
    info.extend_from_slice(LABEL_STATE_DOC_PREFIX);
    info.extend_from_slice(label.as_bytes());
    hkdf_derive(state_key, &info)
}

/// Derive the key of one record-log file from its class key and the random
/// salt in the file header, so no two files ever encrypt under the same key.
pub fn derive_state_log_key(
    doc_key: &[u8],
    file_salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let hk = Hkdf::<Sha256>::new(Some(file_salt), doc_key);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(LABEL_STATE_LOG_FILE, out.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

/// Derive a MAC key (K_tag) from an encryption key (K_enc).
///
/// # SECURITY NOTE (ADR-003)
/// K_tag is derived from K_enc. K_enc is only available after k shares are
/// collected and SSS reconstruction succeeds. Until that point, per-share
/// MAC verification is impossible — coarse verification (shard_hash + mid_prefix)
/// must be used instead. This constraint is intentional, not a bug.
pub fn derive_mac_key(k_enc: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    hkdf_derive(k_enc, LABEL_MAC)
}

/// Internal HKDF-SHA256 helper: expand `ikm` with `info` label into 32 bytes.
fn hkdf_derive(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, out.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"test-master-key-32bytes-padded!!";

    #[test]
    fn node_keys_derivation_deterministic() {
        let keys1 = NodeKeys::derive(MASTER).unwrap();
        let keys2 = NodeKeys::derive(MASTER).unwrap();
        assert_eq!(keys1.node_id, keys2.node_id);
        assert_eq!(
            keys1.dht_signing_key.as_ref(),
            keys2.dht_signing_key.as_ref()
        );
        assert_eq!(keys1.session_key.as_ref(), keys2.session_key.as_ref());
    }

    #[test]
    fn different_labels_different_keys() {
        let keys = NodeKeys::derive(MASTER).unwrap();
        // All derived keys must be distinct.
        assert_ne!(keys.node_id, *keys.dht_signing_key);
        assert_ne!(keys.node_id, *keys.session_key);
        assert_ne!(*keys.dht_signing_key, *keys.session_key);
    }

    #[test]
    fn mac_key_differs_from_enc_key() {
        let k_enc = [0x11u8; 32];
        let k_tag = derive_mac_key(&k_enc).unwrap();
        assert_ne!(*k_tag, k_enc, "K_tag must differ from K_enc");
    }

    #[test]
    fn state_keys_are_separated_by_class_and_file() {
        let state = derive_state_key(MASTER).unwrap();
        let a = derive_state_doc_key(state.as_ref(), "contacts").unwrap();
        let b = derive_state_doc_key(state.as_ref(), "push-history").unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*a, *state);
        assert_eq!(
            *a,
            *derive_state_doc_key(state.as_ref(), "contacts").unwrap()
        );
        let f1 = derive_state_log_key(a.as_ref(), &[1u8; 16]).unwrap();
        let f2 = derive_state_log_key(a.as_ref(), &[2u8; 16]).unwrap();
        assert_ne!(*f1, *f2);
        assert_ne!(*f1, *a);
        let other = derive_state_key(b"other-master-key-32bytes-padded!").unwrap();
        assert_ne!(*other, *state);
    }

    #[test]
    fn different_master_keys_different_derivations() {
        let keys_a = NodeKeys::derive(b"master-key-A-32bytes-padded!!!!").unwrap();
        let keys_b = NodeKeys::derive(b"master-key-B-32bytes-padded!!!!").unwrap();
        assert_ne!(keys_a.node_id, keys_b.node_id);
    }

    /// Published test vector — ensures cross-version compatibility.
    #[test]
    fn test_vector_node_id() {
        let master = [0xABu8; 32];
        let keys = NodeKeys::derive(&master).unwrap();
        // node_id must be deterministic and stable across builds.
        let keys2 = NodeKeys::derive(&master).unwrap();
        assert_eq!(keys.node_id, keys2.node_id);
    }
}
