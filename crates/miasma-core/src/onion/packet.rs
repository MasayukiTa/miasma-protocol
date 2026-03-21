/// Onion packet construction and layer processing.
///
/// # 2-hop circuit topology
/// ```text
/// Initiator ──layer1──▶ Relay1 ──layer2──▶ Relay2 ──payload──▶ Target
///           ◀──────────────────────────────────────────────────
///                     (response routed back via return path)
/// ```
///
/// # Cryptography per hop
/// - Key exchange : X25519 ECDH (initiator ephemeral key × relay static key)
/// - Key derivation: HKDF-SHA256(shared_secret, "miasma-onion-enc-v1")
/// - Encryption   : XChaCha20-Poly1305 (random 24-byte nonce, prepended to ciphertext)
use hkdf::Hkdf;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::MiasmaError;

pub const CIRCUIT_ID_LEN: usize = 16;
pub const X25519_KEY_LEN: usize = 32;
const ONION_ENC_LABEL: &[u8] = b"miasma-onion-enc-v1";

/// Fixed size (in bytes) that every onion `LayerPayload.data` field is padded
/// to before encryption.  This prevents packet-size correlation across hops.
///
/// 8 KiB is chosen because:
/// - Typical share data (4 KiB default segment) fits comfortably
/// - InnerPayload with ReturnPath + body serialises to ~200–4200 bytes
/// - The outer-layer data (inner OnionLayer ciphertext) is ~4300–4500 bytes
/// - 8 KiB provides comfortable headroom with constant wire size
///
/// After 3-layer encryption, overhead is ~200 bytes per layer, so the
/// final on-wire packet is roughly 8 KiB + 600 bytes — well within the
/// 64 KiB onion message limit.
pub const ONION_PAD_TARGET: usize = 8 * 1024;

// ─── CircuitId ────────────────────────────────────────────────────────────────

/// Ephemeral, unique-per-circuit identifier.
///
/// Never reused — a new CircuitId is generated for every DHT query and every
/// Share retrieval request to prevent correlation across requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CircuitId(pub [u8; CIRCUIT_ID_LEN]);

impl CircuitId {
    pub fn random() -> Self {
        let mut id = [0u8; CIRCUIT_ID_LEN];
        rand::rngs::OsRng.fill_bytes(&mut id);
        Self(id)
    }
}

// ─── Wire types ───────────────────────────────────────────────────────────────

/// One encrypted onion layer.
///
/// The recipient uses their static X25519 private key + `ephemeral_pubkey`
/// to derive the symmetric key, then decrypts `ciphertext` with the `nonce`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    /// Initiator's ephemeral X25519 public key for this hop.
    pub ephemeral_pubkey: [u8; X25519_KEY_LEN],
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// XChaCha20-Poly1305 ciphertext (includes 16-byte auth tag).
    pub ciphertext: Vec<u8>,
}

/// Plaintext content inside a decrypted onion layer.
#[derive(Debug, Serialize, Deserialize)]
pub struct LayerPayload {
    /// `Some(peer_id_bytes)` → forward the inner data to this peer.
    /// `None` → we are the final destination, `data` is the actual message.
    pub next_hop: Option<Vec<u8>>,
    /// The next onion layer bytes (if `next_hop` is `Some`),
    /// or the final query/response payload.
    pub data: Vec<u8>,
    /// Per-hop symmetric key for response encryption.
    /// Each relay stores this and encrypts the response with it before
    /// forwarding back to the previous hop. This ensures each relay adds
    /// a layer of encryption that only the initiator can remove.
    #[serde(default)]
    pub return_key: Option<[u8; 32]>,
}

/// A 2-hop onion-wrapped packet ready to send to Relay1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    /// Ephemeral circuit identifier (used for response routing).
    pub circuit_id: CircuitId,
    /// Outermost layer — only Relay1 can decrypt this.
    pub layer: OnionLayer,
}

/// A return-path token embedded in the innermost layer payload.
///
/// Allows Target to send a response back through R2→R1→Initiator without
/// knowing the initiator's address. Each circuit gets a unique token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnPath {
    /// Circuit ID that the response must carry.
    pub circuit_id: CircuitId,
    /// Relay2's address (Target sends response here).
    pub r2_addr: Vec<u8>,
    /// Re-encryption key for R2 → R1 leg (XChaCha20-Poly1305, 32 bytes).
    pub r2_r1_key: [u8; 32],
    /// Re-encryption key for R1 → Initiator leg (XChaCha20-Poly1305, 32 bytes).
    pub r1_init_key: [u8; 32],
}

/// Final destination payload (inner content of the innermost layer).
#[derive(Debug, Serialize, Deserialize)]
pub struct InnerPayload {
    /// Return path for the response.
    pub return_path: ReturnPath,
    /// Actual query or message data.
    pub body: Vec<u8>,
}

// ─── OnionPacketBuilder ───────────────────────────────────────────────────────

/// Builds 2-hop onion packets from scratch.
///
/// # Circuit layout
/// ```text
/// Initiator creates:
///   layer2 = encrypt(r2_key, LayerPayload { next_hop: target, data: InnerPayload })
///   layer1 = encrypt(r1_key, LayerPayload { next_hop: r2_id,  data: layer2_bytes })
///   packet = OnionPacket { circuit_id, layer: layer1 }
/// ```
pub struct OnionPacketBuilder;

impl OnionPacketBuilder {
    /// Build a 2-hop `OnionPacket`.
    ///
    /// - `r1_static_pubkey` / `r2_static_pubkey`: relay static X25519 public keys
    /// - `r2_peer_id`: Relay2's peer ID bytes (Relay1 uses this to forward)
    /// - `target_peer_id`: final destination peer ID bytes
    /// - `body`: actual query/message
    /// - Returns `(packet, return_path)` — keep `return_path` to decrypt the response.
    pub fn build(
        r1_static_pubkey: &[u8; X25519_KEY_LEN],
        r2_static_pubkey: &[u8; X25519_KEY_LEN],
        r2_peer_id: Vec<u8>,
        target_peer_id: Vec<u8>,
        r2_addr: Vec<u8>,
        body: Vec<u8>,
    ) -> Result<(OnionPacket, ReturnPath), MiasmaError> {
        let circuit_id = CircuitId::random();

        // Generate return-path symmetric keys (used for response re-encryption).
        let mut r2_r1_key = Zeroizing::new([0u8; 32]);
        let mut r1_init_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(r2_r1_key.as_mut());
        rand::rngs::OsRng.fill_bytes(r1_init_key.as_mut());

        let return_path = ReturnPath {
            circuit_id,
            r2_addr,
            r2_r1_key: *r2_r1_key,
            r1_init_key: *r1_init_key,
        };

        // ── Innermost layer (R2 → Target) ──────────────────────────────────
        let inner = InnerPayload {
            return_path: return_path.clone(),
            body,
        };
        let inner_bytes = bincode::serialize(&inner)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        let layer2 = Self::encrypt_layer(
            r2_static_pubkey,
            LayerPayload {
                next_hop: Some(target_peer_id),
                data: inner_bytes,
                return_key: Some(*r2_r1_key),
            },
        )?;

        // ── Outer layer (R1 → R2) ──────────────────────────────────────────
        let layer2_bytes = bincode::serialize(&layer2)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        let layer1 = Self::encrypt_layer(
            r1_static_pubkey,
            LayerPayload {
                next_hop: Some(r2_peer_id),
                data: layer2_bytes,
                return_key: Some(*r1_init_key),
            },
        )?;

        Ok((
            OnionPacket {
                circuit_id,
                layer: layer1,
            },
            return_path,
        ))
    }

    /// Build a 2-hop `OnionPacket` with end-to-end encryption to the target.
    ///
    /// Like `build()`, but additionally wraps `body` in a target-addressed
    /// encryption layer using `target_static_pubkey`. This ensures neither
    /// relay can read the payload, even though R2 peels the inner onion layer.
    ///
    /// Returns `(packet, return_path, e2e_session_key)`.
    /// The `e2e_session_key` is needed to decrypt the target's response.
    pub fn build_e2e(
        r1_static_pubkey: &[u8; X25519_KEY_LEN],
        r2_static_pubkey: &[u8; X25519_KEY_LEN],
        target_static_pubkey: &[u8; X25519_KEY_LEN],
        r2_peer_id: Vec<u8>,
        target_peer_id: Vec<u8>,
        r2_addr: Vec<u8>,
        body: Vec<u8>,
    ) -> Result<(OnionPacket, ReturnPath, Zeroizing<[u8; 32]>), MiasmaError> {
        // End-to-end encrypt the body for the target.
        let e2e_layer = Self::encrypt_layer(
            target_static_pubkey,
            LayerPayload {
                next_hop: None, // target is the final destination
                data: body,
                return_key: None,
            },
        )?;
        let e2e_bytes = bincode::serialize(&e2e_layer)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        // Derive the same session key the target will derive, for response decryption.
        // We need the shared secret from the e2e ECDH. Since encrypt_layer consumed
        // the ephemeral secret, we derive the session key from the e2e layer's
        // ephemeral pubkey and the target's static key. But the initiator doesn't
        // have the target's static secret. Instead, we derive a deterministic
        // session key from the e2e ephemeral pubkey bytes as a session identifier.
        //
        // For response decryption, we embed a session key in the e2e payload.
        // Generate a random session key and include it in the onion body.
        let mut session_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(session_key.as_mut());

        // Wrap: session_key || e2e_encrypted_body
        let mut wrapped_body = Vec::with_capacity(32 + e2e_bytes.len());
        wrapped_body.extend_from_slice(session_key.as_ref());
        wrapped_body.extend_from_slice(&e2e_bytes);

        // Build the standard 2-hop onion packet with the wrapped body.
        let (packet, return_path) = Self::build(
            r1_static_pubkey,
            r2_static_pubkey,
            r2_peer_id,
            target_peer_id,
            r2_addr,
            wrapped_body,
        )?;

        Ok((packet, return_path, session_key))
    }

    /// Encrypt one onion layer using ECDH + XChaCha20-Poly1305.
    ///
    /// The `data` field within the payload is padded to `ONION_PAD_TARGET`
    /// bytes before encryption so that all onion packets have a uniform
    /// ciphertext size, preventing packet-size correlation across hops.
    fn encrypt_layer(
        recipient_static_pubkey: &[u8; X25519_KEY_LEN],
        mut payload: LayerPayload,
    ) -> Result<OnionLayer, MiasmaError> {
        // Pad the data field to a fixed size to prevent traffic analysis.
        payload.data = pad_to_fixed_size(&payload.data, ONION_PAD_TARGET);

        // Generate ephemeral X25519 keypair for this hop.
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ephemeral_pubkey = PublicKey::from(&ephemeral_secret);

        // ECDH.
        let recipient_pubkey = PublicKey::from(*recipient_static_pubkey);
        let shared = ephemeral_secret.diffie_hellman(&recipient_pubkey);

        // Derive symmetric key.
        let enc_key = derive_enc_key(shared.as_bytes())?;

        // Encrypt.
        let plaintext = bincode::serialize(&payload)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        let (nonce, ciphertext) = xchacha20_encrypt(&enc_key, &plaintext)?;

        Ok(OnionLayer {
            ephemeral_pubkey: ephemeral_pubkey.to_bytes(),
            nonce,
            ciphertext,
        })
    }
}

// ─── OnionLayerProcessor ─────────────────────────────────────────────────────

/// Processes (peels) one onion layer using the relay's static X25519 private key.
///
/// Used by relay nodes to extract `LayerPayload` from an incoming `OnionLayer`.
pub struct OnionLayerProcessor;

impl OnionLayerProcessor {
    /// Peel one layer.
    ///
    /// `relay_static_secret`: relay's 32-byte static X25519 private key
    pub fn peel(
        relay_static_secret: &[u8; X25519_KEY_LEN],
        layer: &OnionLayer,
    ) -> Result<LayerPayload, MiasmaError> {
        // ECDH with initiator's ephemeral pubkey.
        let static_secret = StaticSecret::from(*relay_static_secret);
        let ephemeral_pubkey = PublicKey::from(layer.ephemeral_pubkey);
        let shared = static_secret.diffie_hellman(&ephemeral_pubkey);

        // Derive symmetric key.
        let enc_key = derive_enc_key(shared.as_bytes())?;

        // Decrypt.
        let plaintext = xchacha20_decrypt(&enc_key, &layer.nonce, &layer.ciphertext)?;

        let mut payload: LayerPayload = bincode::deserialize(&plaintext)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        // Remove padding added during encryption.
        payload.data = unpad_fixed_size(&payload.data)?;

        Ok(payload)
    }
}

// ─── Response encryption/decryption ──────────────────────────────────────────

/// Encrypt a response for the return path using a pre-shared symmetric key.
pub fn encrypt_response(key: &[u8; 32], response: &[u8]) -> Result<Vec<u8>, MiasmaError> {
    let (nonce, ct) = xchacha20_encrypt(key, response)?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a return-path response.
pub fn decrypt_response(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, MiasmaError> {
    if blob.len() < 24 {
        return Err(MiasmaError::Decryption("response blob too short".into()));
    }
    let (nonce_bytes, ct) = blob.split_at(24);
    let nonce: [u8; 24] = nonce_bytes.try_into().unwrap();
    xchacha20_decrypt(key, &nonce, ct)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Pad `data` to exactly `target_size` bytes using a 4-byte LE length prefix
/// followed by the original data and random padding bytes.
///
/// Format: `[4-byte LE original_len] [original data] [random padding]`
///
/// Total output is always `max(target_size, 4 + data.len())`.
fn pad_to_fixed_size(data: &[u8], target_size: usize) -> Vec<u8> {
    let header_len = 4; // 4-byte LE length prefix
    let min_size = header_len + data.len();
    let padded_size = min_size.max(target_size);
    let mut out = Vec::with_capacity(padded_size);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    // Fill remaining bytes with random padding.
    if out.len() < padded_size {
        let pad_len = padded_size - out.len();
        let mut pad = vec![0u8; pad_len];
        rand::rngs::OsRng.fill_bytes(&mut pad);
        out.extend_from_slice(&pad);
    }
    out
}

/// Remove padding added by `pad_to_fixed_size`.
///
/// Reads the 4-byte LE length prefix and returns only the original data.
pub fn unpad_fixed_size(padded: &[u8]) -> Result<Vec<u8>, MiasmaError> {
    if padded.len() < 4 {
        return Err(MiasmaError::Decryption("padded data too short for length prefix".into()));
    }
    let original_len = u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if 4 + original_len > padded.len() {
        return Err(MiasmaError::Decryption(format!(
            "padded data claims length {original_len} but buffer is only {} bytes",
            padded.len()
        )));
    }
    Ok(padded[4..4 + original_len].to_vec())
}

fn derive_enc_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(ONION_ENC_LABEL, key.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

fn xchacha20_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; 24], Vec<u8>), MiasmaError> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};

    let mut nonce_bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| MiasmaError::Encryption(e.to_string()))?;
    Ok((nonce_bytes, ct))
}

fn xchacha20_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MiasmaError> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| MiasmaError::Decryption(e.to_string()))
}

// ─── X25519 key derivation from master key ────────────────────────────────────

/// Derive a relay's static X25519 private key from its master key.
///
/// `label = "miasma-onion-x25519-v1"`
pub fn derive_onion_static_key(master_key: &[u8]) -> Result<Zeroizing<[u8; 32]>, MiasmaError> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(b"miasma-onion-x25519-v1", out.as_mut())
        .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
    Ok(out)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn make_relay_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pubkey = PublicKey::from(&secret);
        (secret.to_bytes(), pubkey.to_bytes())
    }

    #[test]
    fn build_and_peel_two_layers() {
        let (r1_sec, r1_pub) = make_relay_keypair();
        let (r2_sec, r2_pub) = make_relay_keypair();
        let body = b"DHT query: get MID abc123".to_vec();

        let (packet, _return_path) = OnionPacketBuilder::build(
            &r1_pub,
            &r2_pub,
            b"r2_peer_id".to_vec(),
            b"target_peer_id".to_vec(),
            b"r2_addr".to_vec(),
            body.clone(),
        )
        .unwrap();

        // R1 peels outer layer.
        let payload1 = OnionLayerProcessor::peel(&r1_sec, &packet.layer).unwrap();
        assert_eq!(payload1.next_hop, Some(b"r2_peer_id".to_vec()));

        // R2 deserialises inner layer and peels it.
        let inner_layer: OnionLayer = bincode::deserialize(&payload1.data).unwrap();
        let payload2 = OnionLayerProcessor::peel(&r2_sec, &inner_layer).unwrap();
        assert_eq!(payload2.next_hop, Some(b"target_peer_id".to_vec()));

        // Target decodes inner payload.
        let inner: InnerPayload = bincode::deserialize(&payload2.data).unwrap();
        assert_eq!(inner.body, body);
    }

    #[test]
    fn wrong_key_fails_to_peel() {
        let (_r1_sec, r1_pub) = make_relay_keypair();
        let (r2_sec, r2_pub) = make_relay_keypair();

        let (packet, _) = OnionPacketBuilder::build(
            &r1_pub,
            &r2_pub,
            b"r2".to_vec(),
            b"target".to_vec(),
            b"addr".to_vec(),
            b"payload".to_vec(),
        )
        .unwrap();

        // Try to peel outer layer with R2's key — must fail.
        assert!(OnionLayerProcessor::peel(&r2_sec, &packet.layer).is_err());
    }

    #[test]
    fn response_encrypt_decrypt() {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let response = b"DHT response data".to_vec();

        let encrypted = encrypt_response(&key, &response).unwrap();
        let decrypted = decrypt_response(&key, &encrypted).unwrap();
        assert_eq!(decrypted, response);
    }

    #[test]
    fn circuit_ids_are_unique() {
        let ids: Vec<CircuitId> = (0..100).map(|_| CircuitId::random()).collect();
        let unique: std::collections::HashSet<[u8; CIRCUIT_ID_LEN]> =
            ids.iter().map(|id| id.0).collect();
        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn derive_onion_key_is_deterministic() {
        let master = [0x42u8; 32];
        let k1 = derive_onion_static_key(&master).unwrap();
        let k2 = derive_onion_static_key(&master).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());
    }
}
