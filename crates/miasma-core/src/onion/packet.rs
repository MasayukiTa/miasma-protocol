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
use std::fmt;
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
#[derive(Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    /// Initiator's ephemeral X25519 public key for this hop.
    pub ephemeral_pubkey: [u8; X25519_KEY_LEN],
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// XChaCha20-Poly1305 ciphertext (includes 16-byte auth tag).
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for OnionLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnionLayer")
            .field("ephemeral_pubkey", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

/// Plaintext content inside a decrypted onion layer.
#[derive(Serialize, Deserialize)]
pub struct LayerPayload {
    /// `Some(peer_id_bytes)` → forward the inner data to this peer.
    /// `None` → we are the final destination, `data` is the actual message.
    pub next_hop: Option<Vec<u8>>,
    /// The next onion layer bytes (if `next_hop` is `Some`),
    /// or the final query/response payload.
    pub data: Vec<u8>,
    /// Response symmetric key carried inside this encrypted layer.
    /// Relays use it as their per-hop return key; the final target-encrypted
    /// layer uses it as the target?initiator response key. A node learns the key
    /// only after successfully peeling its own layer.
    #[serde(default)]
    pub return_key: Option<[u8; 32]>,
}

impl fmt::Debug for LayerPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayerPayload")
            .field("next_hop_len", &self.next_hop.as_ref().map(Vec::len))
            .field("data_len", &self.data.len())
            .field("return_key_configured", &self.return_key.is_some())
            .finish()
    }
}

/// A 2-hop onion-wrapped packet ready to send to Relay1.
#[derive(Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    /// Ephemeral circuit identifier (used for response routing).
    pub circuit_id: CircuitId,
    /// Outermost layer — only Relay1 can decrypt this.
    pub layer: OnionLayer,
}

impl fmt::Debug for OnionPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnionPacket")
            .field("circuit_id", &self.circuit_id)
            .field("layer", &self.layer)
            .finish()
    }
}

/// A return-path token embedded in the innermost layer payload.
///
/// Allows Target to send a response back through R2→R1→Initiator without
/// knowing the initiator's address. Each circuit gets a unique token.
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for ReturnPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReturnPath")
            .field("circuit_id", &self.circuit_id)
            .field("r2_addr_len", &self.r2_addr.len())
            .field("r2_r1_key", &"<redacted>")
            .field("r1_init_key", &"<redacted>")
            .finish()
    }
}

/// Final destination payload (inner content of the innermost layer).
#[derive(Serialize, Deserialize)]
pub struct InnerPayload {
    /// Return path for the response.
    pub return_path: ReturnPath,
    /// Actual query or message data.
    pub body: Vec<u8>,
}

impl fmt::Debug for InnerPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerPayload")
            .field("return_path", &self.return_path)
            .field("body_len", &self.body.len())
            .finish()
    }
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
        let inner_bytes =
            bincode::serialize(&inner).map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        let layer2 = Self::encrypt_layer(
            r2_static_pubkey,
            LayerPayload {
                next_hop: Some(target_peer_id),
                data: inner_bytes,
                return_key: Some(*r2_r1_key),
            },
        )?;

        // ── Outer layer (R1 → R2) ──────────────────────────────────────────
        let layer2_bytes =
            bincode::serialize(&layer2).map_err(|e| MiasmaError::Serialization(e.to_string()))?;

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
    /// The initiator retains `e2e_session_key`; the target receives the same key
    /// only after decrypting its end-to-end `LayerPayload`. Neither relay learns it.
    pub fn build_e2e(
        r1_static_pubkey: &[u8; X25519_KEY_LEN],
        r2_static_pubkey: &[u8; X25519_KEY_LEN],
        target_static_pubkey: &[u8; X25519_KEY_LEN],
        r2_peer_id: Vec<u8>,
        target_peer_id: Vec<u8>,
        r2_addr: Vec<u8>,
        body: Vec<u8>,
    ) -> Result<(OnionPacket, ReturnPath, Zeroizing<[u8; 32]>), MiasmaError> {
        // Generate a response session key known only to the initiator and target.
        // It is carried inside the target-addressed encrypted LayerPayload, never
        // outside that layer where R2 could read it.
        let mut session_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(session_key.as_mut());

        // End-to-end encrypt the request and response key for the target.
        let e2e_layer = Self::encrypt_layer(
            target_static_pubkey,
            LayerPayload {
                next_hop: None, // target is the final destination
                data: body,
                return_key: Some(*session_key),
            },
        )?;
        let e2e_bytes = bincode::serialize(&e2e_layer)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;

        // Build the standard 2-hop onion packet. R2 learns only the serialized
        // target-encrypted OnionLayer, not the request body or response session key.
        let (packet, return_path) = Self::build(
            r1_static_pubkey,
            r2_static_pubkey,
            r2_peer_id,
            target_peer_id,
            r2_addr,
            e2e_bytes,
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
        if !shared.was_contributory() {
            return Err(MiasmaError::Encryption(
                "non-contributory X25519 recipient public key".into(),
            ));
        }

        // Derive symmetric key.
        let enc_key = derive_enc_key(shared.as_bytes())?;

        // Encrypt.
        let plaintext =
            bincode::serialize(&payload).map_err(|e| MiasmaError::Serialization(e.to_string()))?;
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
        if !shared.was_contributory() {
            return Err(MiasmaError::Decryption(
                "non-contributory X25519 ephemeral public key".into(),
            ));
        }

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
        return Err(MiasmaError::Decryption(
            "padded data too short for length prefix".into(),
        ));
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

fn xchacha20_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 24], Vec<u8>), MiasmaError> {
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

    #[test]
    fn onion_debug_redacts_plaintext_and_return_keys() {
        let payload = LayerPayload {
            next_hop: Some(vec![1, 2, 3]),
            data: b"plaintext-sensitive".to_vec(),
            return_key: Some([0xAB; 32]),
        };
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains("plaintext-sensitive"));
        assert!(!rendered.contains("171, 171"));
        assert!(rendered.contains("data_len: 19"));
        assert!(rendered.contains("return_key_configured: true"));

        let path = ReturnPath {
            circuit_id: CircuitId([7; CIRCUIT_ID_LEN]),
            r2_addr: vec![4, 5, 6],
            r2_r1_key: [0xCD; 32],
            r1_init_key: [0xEF; 32],
        };
        let rendered = format!("{path:?}");
        assert!(!rendered.contains("205, 205"));
        assert!(!rendered.contains("239, 239"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn onion_layer_and_inner_payload_debug_emit_lengths_only() {
        let layer = OnionLayer {
            ephemeral_pubkey: [0x11; X25519_KEY_LEN],
            nonce: [0x22; 24],
            ciphertext: vec![9, 8, 7, 6],
        };
        let rendered = format!("{layer:?}");
        assert!(!rendered.contains("[9, 8, 7, 6]"));
        assert!(!rendered.contains("17, 17"));
        assert!(!rendered.contains("34, 34"));
        assert!(rendered.contains("ciphertext_len: 4"));

        let inner = InnerPayload {
            return_path: ReturnPath {
                circuit_id: CircuitId([1; CIRCUIT_ID_LEN]),
                r2_addr: vec![2, 3],
                r2_r1_key: [4; 32],
                r1_init_key: [5; 32],
            },
            body: b"private-query-body".to_vec(),
        };
        let rendered = format!("{inner:?}");
        assert!(!rendered.contains("private-query-body"));
        assert!(rendered.contains("body_len: 18"));
    }
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
    fn encrypt_layer_rejects_non_contributory_recipient_key() {
        let err = OnionPacketBuilder::encrypt_layer(
            &[0u8; 32],
            LayerPayload {
                next_hop: None,
                data: b"secret".to_vec(),
                return_key: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, MiasmaError::Encryption(_)));
    }

    #[test]
    fn peel_rejects_non_contributory_ephemeral_key() {
        let (relay_secret, _) = make_relay_keypair();
        let layer = OnionLayer {
            ephemeral_pubkey: [0u8; 32],
            nonce: rand::random::<[u8; 24]>(),
            ciphertext: rand::random::<[u8; 16]>().to_vec(),
        };
        let err = OnionLayerProcessor::peel(&relay_secret, &layer).unwrap_err();
        assert!(matches!(err, MiasmaError::Decryption(_)));
    }

    #[test]
    fn response_encrypt_decrypt() {
        let key = rand::random::<[u8; 32]>();
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
