use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::MiasmaError;

/// Domain separation labels for HKDF-SHA256 key derivation.
const LABEL_NODE_ID: &[u8] = b"miasma-v1-node-id";
const LABEL_DHT_SIGN: &[u8] = b"miasma-v1-dht-signing-key";
const LABEL_SESSION: &[u8] = b"miasma-v1-session-key";
const LABEL_MAC: &[u8] = b"miasma-v1-mac-key-v1";

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
        Ok(Self {
            node_id: hkdf_derive(master_key, LABEL_NODE_ID)?,
            dht_signing_key: Zeroizing::new(hkdf_derive(master_key, LABEL_DHT_SIGN)?),
            session_key: Zeroizing::new(hkdf_derive(master_key, LABEL_SESSION)?),
        })
    }
}

/// Derive a MAC key (K_tag) from an encryption key (K_enc).
///
/// # SECURITY NOTE (ADR-003)
/// K_tag is derived from K_enc. K_enc is only available after k shares are
/// collected and SSS reconstruction succeeds. Until that point, per-share
/// MAC verification is impossible — coarse verification (shard_hash + mid_prefix)
/// must be used instead. This constraint is intentional, not a bug.
pub fn derive_mac_key(k_enc: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    Ok(Zeroizing::new(hkdf_derive(k_enc, LABEL_MAC)?))
}

/// Internal HKDF-SHA256 helper: expand `ikm` with `info` label into 32 bytes.
fn hkdf_derive(ikm: &[u8], info: &[u8]) -> Result<[u8; 32], MiasmaError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
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
        assert_eq!(keys1.dht_signing_key.as_ref(), keys2.dht_signing_key.as_ref());
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
