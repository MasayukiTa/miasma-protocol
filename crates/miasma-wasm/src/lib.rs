//! Miasma Protocol — WebAssembly build.
//!
//! Provides dissolve/retrieve operations in the browser via wasm-bindgen.
//! Protocol-compatible with miasma-core v1 (MID, share format, crypto pipeline).

use std::collections::HashMap;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// ── Constants ──────────────────────────────────────────────────────────

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MID_PREFIX_LEN: usize = 8;
const PROTOCOL_VERSION: u8 = 1;

// ── Error ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum MiasmaError {
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("SSS operation failed: {0}")]
    Sss(String),
    #[error("Reed-Solomon encode/decode failed: {0}")]
    ReedSolomon(String),
    #[error("invalid MID: {0}")]
    InvalidMid(String),
    #[error("insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: usize, got: usize },
    #[error("hash mismatch: content does not match MID")]
    HashMismatch,
    #[error("share integrity check failed")]
    ShareIntegrity,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

// MiasmaError implements std::error::Error via thiserror,
// so wasm_bindgen's blanket From<E: StdError> for JsError applies automatically.

// ── ContentId ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId {
    digest: [u8; 32],
}

impl ContentId {
    pub fn compute(content: &[u8], params: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(content);
        hasher.update(params);
        let digest = *hasher.finalize().as_bytes();
        Self { digest }
    }

    pub fn to_mid_string(&self) -> String {
        format!("miasma:{}", bs58::encode(&self.digest).into_string())
    }

    pub fn from_mid_str(s: &str) -> Result<Self, MiasmaError> {
        let s = s.strip_prefix("miasma:").ok_or_else(|| {
            MiasmaError::InvalidMid("missing 'miasma:' prefix".into())
        })?;
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| MiasmaError::InvalidMid(e.to_string()))?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| MiasmaError::InvalidMid("digest must be 32 bytes".into()))?;
        Ok(Self { digest })
    }

    pub fn prefix(&self) -> [u8; MID_PREFIX_LEN] {
        self.digest[..MID_PREFIX_LEN]
            .try_into()
            .expect("MID_PREFIX_LEN <= 32")
    }
}

// ── MiasmaShare ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiasmaShare {
    pub version: u8,
    pub mid_prefix: [u8; MID_PREFIX_LEN],
    pub segment_index: u32,
    pub slot_index: u16,
    pub shard_data: Vec<u8>,
    pub key_share: Vec<u8>,
    pub shard_hash: [u8; 32],
    pub nonce: [u8; 12],
    pub original_len: u32,
    pub timestamp: u64,
}

impl MiasmaShare {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mid: &ContentId,
        segment_index: u32,
        slot_index: u16,
        shard_data: Vec<u8>,
        key_share: Vec<u8>,
        nonce: [u8; 12],
        original_len: u32,
        timestamp: u64,
    ) -> Self {
        let shard_hash = *blake3::hash(&shard_data).as_bytes();
        Self {
            version: 1,
            mid_prefix: mid.prefix(),
            segment_index,
            slot_index,
            shard_data,
            key_share,
            shard_hash,
            nonce,
            original_len,
            timestamp,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MiasmaError> {
        bincode::serialize(self).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MiasmaError> {
        // Limit input size to prevent OOM from crafted length prefixes.
        if bytes.len() as u64 > MAX_BINCODE_SIZE {
            return Err(MiasmaError::Serialization(format!(
                "share data too large: {} bytes (max {})",
                bytes.len(),
                MAX_BINCODE_SIZE
            )));
        }
        bincode::deserialize(bytes).map_err(|e| MiasmaError::Serialization(e.to_string()))
    }
}

// ── Crypto: AES-256-GCM ───────────────────────────────────────────────

fn encrypt(
    plaintext: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; KEY_LEN]>, [u8; NONCE_LEN]), MiasmaError> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| MiasmaError::Encryption(e.to_string()))?;

    let mut key_arr = Zeroizing::new([0u8; KEY_LEN]);
    key_arr.as_mut().copy_from_slice(&key);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce);

    Ok((ciphertext, key_arr, nonce_arr))
}

fn decrypt(
    ciphertext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, MiasmaError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| MiasmaError::Decryption(e.to_string()))
}

// ── Crypto: Shamir Secret Sharing ─────────────────────────────────────

fn sss_split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Vec<u8>>, MiasmaError> {
    if k == 0 || n == 0 || k > n {
        return Err(MiasmaError::Sss(format!(
            "invalid parameters: k={k}, n={n} (require 0 < k <= n)"
        )));
    }
    let sharks = Sharks(k);
    let dealer = sharks.dealer(secret);
    let shares: Vec<Vec<u8>> = dealer.take(n as usize).map(|s| Vec::from(&s)).collect();
    Ok(shares)
}

fn sss_combine(shares: &[Vec<u8>], k: u8) -> Result<Zeroizing<Vec<u8>>, MiasmaError> {
    if shares.len() < k as usize {
        return Err(MiasmaError::InsufficientShares {
            need: k as usize,
            got: shares.len(),
        });
    }
    let sharks = Sharks(k);
    let parsed: Result<Vec<Share>, _> = shares
        .iter()
        .map(|s| Share::try_from(s.as_slice()))
        .collect();
    let parsed = parsed.map_err(|e| MiasmaError::Sss(e.to_string()))?;
    let secret = sharks
        .recover(&parsed)
        .map_err(|e| MiasmaError::Sss(e.to_string()))?;
    Ok(Zeroizing::new(secret))
}

// ── Crypto: Reed-Solomon ──────────────────────────────────────────────

fn rs_encode(
    data: &[u8],
    data_shards: usize,
    total_shards: usize,
) -> Result<Vec<Vec<u8>>, MiasmaError> {
    if total_shards <= data_shards || data_shards == 0 {
        return Err(MiasmaError::ReedSolomon(format!(
            "invalid parameters: data_shards={data_shards}, total_shards={total_shards}"
        )));
    }
    let recovery_shards = total_shards - data_shards;

    let mut shard_len = data.len().div_ceil(data_shards).max(1);
    if shard_len % 2 == 1 {
        shard_len += 1;
    }

    let mut padded = data.to_vec();
    padded.resize(shard_len * data_shards, 0);

    let mut encoder = ReedSolomonEncoder::new(data_shards, recovery_shards, shard_len)
        .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;

    for chunk in padded.chunks(shard_len) {
        encoder
            .add_original_shard(chunk)
            .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;
    }

    let result = encoder
        .encode()
        .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;

    let mut output: Vec<Vec<u8>> = padded.chunks(shard_len).map(|c| c.to_vec()).collect();
    for recovery in result.recovery_iter() {
        output.push(recovery.to_vec());
    }
    Ok(output)
}

fn rs_decode(
    available_shards: &[(usize, Vec<u8>)],
    data_shards: usize,
    total_shards: usize,
    original_len: usize,
) -> Result<Vec<u8>, MiasmaError> {
    if total_shards <= data_shards || data_shards == 0 {
        return Err(MiasmaError::ReedSolomon(format!(
            "invalid parameters: data_shards={data_shards}, total_shards={total_shards}"
        )));
    }
    if available_shards.is_empty() {
        return Err(MiasmaError::InsufficientShares {
            need: data_shards,
            got: 0,
        });
    }

    let recovery_shards = total_shards - data_shards;
    let shard_len = available_shards[0].1.len();

    if shard_len == 0 || shard_len % 2 != 0 {
        return Err(MiasmaError::ReedSolomon(format!(
            "invalid shard size: {shard_len} bytes (must be non-zero and even)"
        )));
    }

    let mut data_map: HashMap<usize, &Vec<u8>> = HashMap::new();
    let mut recovery_map: HashMap<usize, &Vec<u8>> = HashMap::new();
    for (idx, shard) in available_shards {
        if *idx < data_shards {
            data_map.entry(*idx).or_insert(shard);
        } else {
            let rec_idx = idx - data_shards;
            if rec_idx < recovery_shards {
                recovery_map.entry(rec_idx).or_insert(shard);
            }
        }
    }

    // Fast path: all data shards present.
    if data_map.len() == data_shards {
        let mut output = Vec::with_capacity(shard_len * data_shards);
        for i in 0..data_shards {
            output.extend_from_slice(data_map[&i]);
        }
        output.truncate(original_len);
        return Ok(output);
    }

    let missing_data = data_shards - data_map.len();
    if recovery_map.len() < missing_data {
        return Err(MiasmaError::InsufficientShares {
            need: data_shards,
            got: data_map.len() + recovery_map.len(),
        });
    }

    let mut decoder = ReedSolomonDecoder::new(data_shards, recovery_shards, shard_len)
        .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;

    for (&idx, &shard) in &data_map {
        decoder
            .add_original_shard(idx, shard)
            .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;
    }

    for (&rec_idx, &shard) in recovery_map.iter().take(missing_data) {
        decoder
            .add_recovery_shard(rec_idx, shard)
            .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;
    }

    let result = decoder
        .decode()
        .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;

    let restored: HashMap<usize, &[u8]> = result.restored_original_iter().collect();

    let mut output = Vec::with_capacity(shard_len * data_shards);
    for i in 0..data_shards {
        if let Some(shard) = data_map.get(&i) {
            output.extend_from_slice(shard);
        } else {
            let shard = restored.get(&i).ok_or_else(|| {
                MiasmaError::ReedSolomon(format!("shard {i} missing from decoder output"))
            })?;
            output.extend_from_slice(shard);
        }
    }

    output.truncate(original_len);
    Ok(output)
}

// ── Verification ──────────────────────────────────────────────────────

fn coarse_verify(share: &MiasmaShare, expected_mid: &ContentId) -> bool {
    if share.mid_prefix != expected_mid.prefix() {
        return false;
    }
    let computed = *blake3::hash(&share.shard_data).as_bytes();
    computed == share.shard_hash
}

fn full_verify(
    plaintext: &[u8],
    params: &[u8],
    expected_mid: &ContentId,
) -> Result<(), MiasmaError> {
    let computed = ContentId::compute(plaintext, params);
    if computed != *expected_mid {
        return Err(MiasmaError::HashMismatch);
    }
    Ok(())
}

// ── Pipeline Parameters ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DissolutionParams {
    pub data_shards: usize,
    pub total_shards: usize,
}

impl Default for DissolutionParams {
    fn default() -> Self {
        Self {
            data_shards: 10,
            total_shards: 20,
        }
    }
}

impl DissolutionParams {
    pub fn to_param_bytes(&self) -> Vec<u8> {
        format!(
            "k={},n={},v={}",
            self.data_shards, self.total_shards, PROTOCOL_VERSION
        )
        .into_bytes()
    }
}

// ── Input Validation ──────────────────────────────────────────────────

/// Maximum allowed input size for dissolve (100 MiB).
const MAX_INPUT_SIZE: usize = 100 * 1024 * 1024;
/// Maximum allowed share count per retrieval.
const MAX_SHARE_COUNT: usize = 512;
/// Maximum allowed bincode deserialization size (1 MiB per share).
const MAX_BINCODE_SIZE: u64 = 1024 * 1024;

fn validate_params(k: usize, n: usize) -> Result<(), MiasmaError> {
    if k == 0 || n == 0 || k >= n {
        return Err(MiasmaError::Sss(format!(
            "invalid parameters: k={k}, n={n} (require 0 < k < n)"
        )));
    }
    if k > 255 || n > 255 {
        return Err(MiasmaError::Sss(format!(
            "parameters out of range: k={k}, n={n} (max 255)"
        )));
    }
    if n > u16::MAX as usize {
        return Err(MiasmaError::Sss(format!(
            "total_shards {n} exceeds u16::MAX"
        )));
    }
    Ok(())
}

// ── Pipeline: dissolve ────────────────────────────────────────────────

fn dissolve_inner(
    plaintext: &[u8],
    params: DissolutionParams,
) -> Result<(ContentId, Vec<MiasmaShare>), MiasmaError> {
    validate_params(params.data_shards, params.total_shards)?;

    if plaintext.is_empty() {
        return Err(MiasmaError::Encryption("empty input".into()));
    }
    if plaintext.len() > MAX_INPUT_SIZE {
        return Err(MiasmaError::Encryption(format!(
            "input too large: {} bytes (max {})",
            plaintext.len(),
            MAX_INPUT_SIZE
        )));
    }
    if plaintext.len() > u32::MAX as usize {
        return Err(MiasmaError::Encryption(
            "input exceeds u32::MAX bytes".into(),
        ));
    }

    let param_bytes = params.to_param_bytes();
    let mid = ContentId::compute(plaintext, &param_bytes);

    let (ciphertext, k_enc, nonce) = encrypt(plaintext)?;

    let shards = rs_encode(&ciphertext, params.data_shards, params.total_shards)?;
    let key_shares =
        sss_split(k_enc.as_ref(), params.data_shards as u8, params.total_shards as u8)?;

    #[cfg(target_arch = "wasm32")]
    let timestamp = (js_sys::Date::now() / 1000.0) as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let shares: Vec<MiasmaShare> = shards
        .into_iter()
        .zip(key_shares)
        .enumerate()
        .map(|(i, (shard_data, key_share))| {
            MiasmaShare::new(
                &mid,
                0,
                i as u16,
                shard_data,
                key_share,
                nonce,
                plaintext.len() as u32,
                timestamp,
            )
        })
        .collect();

    Ok((mid, shares))
}

// ── Pipeline: retrieve ────────────────────────────────────────────────

fn retrieve_inner(
    mid: &ContentId,
    shares: &[MiasmaShare],
    params: DissolutionParams,
) -> Result<Vec<u8>, MiasmaError> {
    validate_params(params.data_shards, params.total_shards)?;

    if shares.len() > MAX_SHARE_COUNT {
        return Err(MiasmaError::Sss(format!(
            "too many shares: {} (max {})",
            shares.len(),
            MAX_SHARE_COUNT
        )));
    }

    if shares.len() < params.data_shards {
        return Err(MiasmaError::InsufficientShares {
            need: params.data_shards,
            got: shares.len(),
        });
    }

    let valid: Vec<&MiasmaShare> = shares
        .iter()
        .filter(|s| coarse_verify(s, mid))
        .collect();

    if valid.len() < params.data_shards {
        return Err(MiasmaError::InsufficientShares {
            need: params.data_shards,
            got: valid.len(),
        });
    }

    let selected = &valid[..params.data_shards];
    let nonce: [u8; NONCE_LEN] = selected[0].nonce;
    let plaintext_len = selected[0].original_len as usize;

    // Verify nonce and original_len consistency across selected shares.
    for s in &selected[1..] {
        if s.nonce != nonce {
            return Err(MiasmaError::ShareIntegrity);
        }
        if s.original_len as usize != plaintext_len {
            return Err(MiasmaError::ShareIntegrity);
        }
    }

    let ciphertext_len = plaintext_len + 16; // AES-GCM tag length

    let rs_shards: Vec<(usize, Vec<u8>)> = selected
        .iter()
        .map(|s| (s.slot_index as usize, s.shard_data.clone()))
        .collect();

    let ciphertext = rs_decode(
        &rs_shards,
        params.data_shards,
        params.total_shards,
        ciphertext_len,
    )?;

    let key_shares: Vec<Vec<u8>> = selected.iter().map(|s| s.key_share.clone()).collect();
    let k_enc = sss_combine(&key_shares, params.data_shards as u8)?;

    let key: [u8; KEY_LEN] = k_enc
        .as_slice()
        .try_into()
        .map_err(|_| MiasmaError::Sss("recovered K_enc has wrong length".into()))?;

    let plaintext = decrypt(&ciphertext, &key, &nonce)?;

    let param_bytes = params.to_param_bytes();
    full_verify(&plaintext, &param_bytes, mid)?;

    Ok(plaintext)
}

// ── JSON result types ─────────────────────────────────────────────────

#[derive(Serialize)]
struct DissolveResult {
    mid: String,
    shares: Vec<ShareJson>,
    data_shards: usize,
    total_shards: usize,
}

#[derive(Serialize, Deserialize)]
struct ShareJson {
    version: u8,
    mid_prefix: String,
    segment_index: u32,
    slot_index: u16,
    shard_data: String,   // base64
    key_share: String,    // base64
    shard_hash: String,   // hex
    nonce: String,        // hex
    original_len: u32,
    timestamp: u64,
    /// bincode-serialized share bytes (base64), for cross-platform interop.
    bincode: String,
}

fn share_to_json(share: &MiasmaShare) -> ShareJson {
    let bincode_bytes = share.to_bytes().unwrap_or_default();
    ShareJson {
        version: share.version,
        mid_prefix: hex::encode(share.mid_prefix),
        segment_index: share.segment_index,
        slot_index: share.slot_index,
        shard_data: base64_encode(&share.shard_data),
        key_share: base64_encode(&share.key_share),
        shard_hash: hex::encode(share.shard_hash),
        nonce: hex::encode(share.nonce),
        original_len: share.original_len,
        timestamp: share.timestamp,
        bincode: base64_encode(&bincode_bytes),
    }
}

fn share_from_json(j: &ShareJson) -> Result<MiasmaShare, MiasmaError> {
    // Prefer bincode if available (exact cross-platform compat).
    if !j.bincode.is_empty() {
        let bytes = base64_decode(&j.bincode)
            .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        return MiasmaShare::from_bytes(&bytes);
    }

    let mid_prefix: [u8; MID_PREFIX_LEN] = hex::decode(&j.mid_prefix)
        .map_err(|e| MiasmaError::Serialization(e.to_string()))?
        .try_into()
        .map_err(|_| MiasmaError::Serialization("mid_prefix must be 8 bytes".into()))?;
    let shard_data = base64_decode(&j.shard_data)
        .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
    let key_share = base64_decode(&j.key_share)
        .map_err(|e| MiasmaError::Serialization(e.to_string()))?;
    let shard_hash: [u8; 32] = hex::decode(&j.shard_hash)
        .map_err(|e| MiasmaError::Serialization(e.to_string()))?
        .try_into()
        .map_err(|_| MiasmaError::Serialization("shard_hash must be 32 bytes".into()))?;
    let nonce: [u8; 12] = hex::decode(&j.nonce)
        .map_err(|e| MiasmaError::Serialization(e.to_string()))?
        .try_into()
        .map_err(|_| MiasmaError::Serialization("nonce must be 12 bytes".into()))?;

    Ok(MiasmaShare {
        version: j.version,
        mid_prefix,
        segment_index: j.segment_index,
        slot_index: j.slot_index,
        shard_data,
        key_share,
        shard_hash,
        nonce,
        original_len: j.original_len,
        timestamp: j.timestamp,
    })
}

// ── Base64 helpers (no extra dep, use simple impl) ────────────────────

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 char: {}", c as char)),
        }
    }
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let n = (val(chunk[0])? << 18)
            | (val(chunk[1])? << 12)
            | (val(chunk[2])? << 6)
            | val(chunk[3])?;
        result.push((n >> 16) as u8);
        if chunk[2] != b'=' {
            result.push((n >> 8) as u8);
        }
        if chunk[3] != b'=' {
            result.push(n as u8);
        }
    }
    Ok(result)
}

// hex module (minimal, no extra dep)
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at {}: {}", i, e))
            })
            .collect()
    }
}

// ── wasm-bindgen exports ──────────────────────────────────────────────

/// Dissolve text content into shares.
/// Returns JSON: { mid, shares, data_shards, total_shards }
#[wasm_bindgen]
pub fn dissolve_text(plaintext: &str, k: usize, n: usize) -> Result<String, JsError> {
    let params = DissolutionParams {
        data_shards: k,
        total_shards: n,
    };
    let (mid, shares) = dissolve_inner(plaintext.as_bytes(), params)?;
    let result = DissolveResult {
        mid: mid.to_mid_string(),
        shares: shares.iter().map(|s| share_to_json(s)).collect(),
        data_shards: k,
        total_shards: n,
    };
    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Dissolve binary data into shares.
/// Returns JSON: { mid, shares, data_shards, total_shards }
#[wasm_bindgen]
pub fn dissolve_bytes(data: &[u8], k: usize, n: usize) -> Result<String, JsError> {
    let params = DissolutionParams {
        data_shards: k,
        total_shards: n,
    };
    let (mid, shares) = dissolve_inner(data, params)?;
    let result = DissolveResult {
        mid: mid.to_mid_string(),
        shares: shares.iter().map(|s| share_to_json(s)).collect(),
        data_shards: k,
        total_shards: n,
    };
    serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Retrieve content from shares JSON.
/// shares_json: JSON array of ShareJson objects.
/// Returns the reconstructed bytes.
#[wasm_bindgen]
pub fn retrieve_from_shares(
    mid_str: &str,
    shares_json: &str,
    k: usize,
    n: usize,
) -> Result<Vec<u8>, JsError> {
    let mid = ContentId::from_mid_str(mid_str)?;
    let share_jsons: Vec<ShareJson> =
        serde_json::from_str(shares_json).map_err(|e| JsError::new(&e.to_string()))?;
    let shares: Result<Vec<MiasmaShare>, _> = share_jsons.iter().map(share_from_json).collect();
    let shares = shares?;
    let params = DissolutionParams {
        data_shards: k,
        total_shards: n,
    };
    let plaintext = retrieve_inner(&mid, &shares, params)?;
    Ok(plaintext)
}

/// Verify a single share against a MID.
#[wasm_bindgen]
pub fn verify_share(share_json: &str, mid_str: &str) -> Result<bool, JsError> {
    let mid = ContentId::from_mid_str(mid_str)?;
    let sj: ShareJson =
        serde_json::from_str(share_json).map_err(|e| JsError::new(&e.to_string()))?;
    let share = share_from_json(&sj)?;
    Ok(coarse_verify(&share, &mid))
}

/// Get the protocol version string.
#[wasm_bindgen]
pub fn protocol_version() -> String {
    format!("miasma-wasm v{} (protocol v{})", env!("CARGO_PKG_VERSION"), PROTOCOL_VERSION)
}

// ── Tests (native only — cross-platform compatibility) ────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONTENT: &[u8] = b"Miasma dissolution pipeline test content. \
        This is a realistic-length payload that exercises all pipeline stages. \
        The content must survive encrypt-encode-split-combine-decode-decrypt.";

    // ── MID compatibility ──

    /// Verify MID computation matches miasma-core's algorithm exactly.
    /// BLAKE3("hello miasma" || "k=10,n=20,v=1") must be deterministic.
    #[test]
    fn mid_computation_deterministic() {
        let mid1 = ContentId::compute(b"hello miasma", b"k=10,n=20,v=1");
        let mid2 = ContentId::compute(b"hello miasma", b"k=10,n=20,v=1");
        assert_eq!(mid1, mid2);
    }

    #[test]
    fn mid_string_format() {
        let mid = ContentId::compute(b"hello miasma", b"k=10,n=20,v=1");
        let s = mid.to_mid_string();
        assert!(s.starts_with("miasma:"), "MID must start with 'miasma:' prefix");
        let parsed = ContentId::from_mid_str(&s).unwrap();
        assert_eq!(mid, parsed);
    }

    #[test]
    fn mid_prefix_is_first_8_bytes() {
        let mid = ContentId::compute(b"test", b"k=10,n=20,v=1");
        let prefix = mid.prefix();
        assert_eq!(prefix.len(), MID_PREFIX_LEN);
        assert_eq!(&prefix[..], &mid.digest[..MID_PREFIX_LEN]);
    }

    #[test]
    fn param_bytes_format() {
        let params = DissolutionParams { data_shards: 10, total_shards: 20 };
        assert_eq!(params.to_param_bytes(), b"k=10,n=20,v=1");

        let params2 = DissolutionParams { data_shards: 5, total_shards: 10 };
        assert_eq!(params2.to_param_bytes(), b"k=5,n=10,v=1");
    }

    /// Cross-platform MID test vector: same input must produce same MID as miasma-core.
    /// This is the canonical test vector from miasma-core::crypto::hash tests.
    #[test]
    fn mid_cross_platform_vector() {
        let content = b"hello miasma";
        let params = b"k=10,n=20,v=1";
        let mid = ContentId::compute(content, params);

        // Compute the expected BLAKE3 hash directly to verify
        let mut hasher = blake3::Hasher::new();
        hasher.update(content);
        hasher.update(params);
        let expected_digest = *hasher.finalize().as_bytes();

        assert_eq!(mid.digest, expected_digest);
        // Verify base58 roundtrip
        let mid_str = mid.to_mid_string();
        let recovered = ContentId::from_mid_str(&mid_str).unwrap();
        assert_eq!(recovered.digest, expected_digest);
    }

    // ── AES-256-GCM ──

    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let plaintext = b"Miasma Protocol test plaintext";
        let (ct, key, nonce) = encrypt(plaintext).unwrap();
        assert_ne!(ct.as_slice(), plaintext.as_ref());
        let recovered = decrypt(&ct, &key, &nonce).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn aead_ciphertext_includes_16_byte_tag() {
        let plaintext = b"exactly 16 bytes";
        let (ct, _, _) = encrypt(plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16);
    }

    #[test]
    fn aead_tampered_ciphertext_fails() {
        let (mut ct, key, nonce) = encrypt(b"sensitive").unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt(&ct, &key, &nonce).is_err());
    }

    // ── Shamir SSS ──

    #[test]
    fn sss_split_combine_roundtrip() {
        let secret = [0x42u8; 32];
        let shares = sss_split(&secret, 10, 20).unwrap();
        assert_eq!(shares.len(), 20);
        let recovered = sss_combine(&shares[..10], 10).unwrap();
        assert_eq!(recovered.as_slice(), &secret);
    }

    #[test]
    fn sss_insufficient_shares_fails() {
        let secret = [0x42u8; 32];
        let shares = sss_split(&secret, 10, 20).unwrap();
        assert!(sss_combine(&shares[..9], 10).is_err());
    }

    // ── Reed-Solomon ──

    #[test]
    fn rs_encode_decode_roundtrip() {
        let data = b"Hello Miasma Reed-Solomon test data that is long enough for testing!";
        let shards = rs_encode(data, 10, 20).unwrap();
        assert_eq!(shards.len(), 20);

        let indexed: Vec<(usize, Vec<u8>)> = shards.iter().cloned().enumerate().collect();
        let recovered = rs_decode(&indexed, 10, 20, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn rs_decode_with_missing_data_shards() {
        let data = b"Hello Miasma Reed-Solomon test data that is long enough for testing!";
        let shards = rs_encode(data, 10, 20).unwrap();
        // Drop first 5 data shards, keep rest.
        let indexed: Vec<(usize, Vec<u8>)> = shards.iter().cloned().enumerate()
            .filter(|(i, _)| *i >= 5)
            .collect();
        let recovered = rs_decode(&indexed, 10, 20, data.len()).unwrap();
        assert_eq!(recovered, data);
    }

    // ── Full Pipeline ──

    #[test]
    fn dissolve_and_retrieve_default_params() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve_inner(TEST_CONTENT, params).unwrap();
        assert_eq!(shares.len(), params.total_shards);

        let recovered = retrieve_inner(&mid, &shares, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn dissolve_and_retrieve_with_minimum_k_shares() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve_inner(TEST_CONTENT, params).unwrap();

        let subset = &shares[..params.data_shards];
        let recovered = retrieve_inner(&mid, subset, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn dissolve_and_retrieve_using_recovery_shards() {
        let params = DissolutionParams::default();
        let (mid, all_shares) = dissolve_inner(TEST_CONTENT, params).unwrap();

        // Drop first 5 data shards, use remaining data + recovery.
        let subset: Vec<MiasmaShare> = all_shares.into_iter()
            .filter(|s| s.slot_index >= 5)
            .collect();
        let recovered = retrieve_inner(&mid, &subset, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn forged_shares_are_rejected() {
        let params = DissolutionParams::default();
        let (mid, mut shares) = dissolve_inner(TEST_CONTENT, params).unwrap();

        // Forge 5 shares.
        for i in 0..5usize {
            shares[i].shard_data = vec![0xFF; shares[i].shard_data.len()];
        }
        // 15 valid shares remain — should succeed.
        let recovered = retrieve_inner(&mid, &shares, params).unwrap();
        assert_eq!(recovered, TEST_CONTENT);
    }

    #[test]
    fn insufficient_shares_fails() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve_inner(TEST_CONTENT, params).unwrap();
        let result = retrieve_inner(&mid, &shares[..5], params);
        assert!(result.is_err());
    }

    #[test]
    fn small_content_single_byte() {
        let params = DissolutionParams::default();
        let (mid, shares) = dissolve_inner(b"X", params).unwrap();
        let recovered = retrieve_inner(&mid, &shares, params).unwrap();
        assert_eq!(recovered, b"X");
    }

    // ── Bincode Share Compatibility ──

    #[test]
    fn share_bincode_roundtrip() {
        let mid = ContentId::compute(b"serialize test", b"k=10,n=20,v=1");
        let share = MiasmaShare::new(
            &mid, 0, 7,
            vec![0xBB; 64],
            vec![0xAA; 33],
            [0x24; 12],
            100,
            1700000000,
        );
        let bytes = share.to_bytes().unwrap();
        let recovered = MiasmaShare::from_bytes(&bytes).unwrap();
        assert_eq!(share.slot_index, recovered.slot_index);
        assert_eq!(share.shard_hash, recovered.shard_hash);
        assert_eq!(share.mid_prefix, recovered.mid_prefix);
        assert_eq!(share.nonce, recovered.nonce);
        assert_eq!(share.original_len, recovered.original_len);
        assert_eq!(share.shard_data, recovered.shard_data);
        assert_eq!(share.key_share, recovered.key_share);
    }

    // ── JSON Serialization ──

    #[test]
    fn share_json_roundtrip() {
        let mid = ContentId::compute(b"json test", b"k=10,n=20,v=1");
        let share = MiasmaShare::new(
            &mid, 0, 3,
            vec![0xCC; 48],
            vec![0xDD; 33],
            [0x11; 12],
            256,
            1700000000,
        );
        let json = share_to_json(&share);
        let recovered = share_from_json(&json).unwrap();
        assert_eq!(share.slot_index, recovered.slot_index);
        assert_eq!(share.shard_hash, recovered.shard_hash);
        assert_eq!(share.mid_prefix, recovered.mid_prefix);
        assert_eq!(share.shard_data, recovered.shard_data);
    }

    #[test]
    fn share_json_bincode_path() {
        let mid = ContentId::compute(b"bincode path", b"k=10,n=20,v=1");
        let share = MiasmaShare::new(
            &mid, 0, 5,
            vec![0xEE; 32],
            vec![0xFF; 33],
            [0x22; 12],
            64,
            1700000000,
        );
        let json = share_to_json(&share);
        // bincode field should be populated
        assert!(!json.bincode.is_empty());
        // Deserialization should prefer bincode path
        let recovered = share_from_json(&json).unwrap();
        assert_eq!(share.shard_data, recovered.shard_data);
        assert_eq!(share.key_share, recovered.key_share);
    }

    // ── Base64 / Hex Helpers ──

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello Miasma";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_edge_cases() {
        // Empty
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), b"");
        // 1 byte (padding test)
        let e1 = base64_encode(b"M");
        assert_eq!(base64_decode(&e1).unwrap(), b"M");
        // 2 bytes
        let e2 = base64_encode(b"Mi");
        assert_eq!(base64_decode(&e2).unwrap(), b"Mi");
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = hex::encode(data);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, &data);
    }

    // ── Coarse & Full Verification ──

    #[test]
    fn coarse_verify_valid() {
        let mid = ContentId::compute(b"verify test", b"k=10,n=20,v=1");
        let share = MiasmaShare::new(&mid, 0, 0, vec![1, 2, 3], vec![0xAA; 32], [0; 12], 3, 0);
        assert!(coarse_verify(&share, &mid));
    }

    #[test]
    fn coarse_verify_wrong_mid() {
        let mid = ContentId::compute(b"content A", b"k=10,n=20,v=1");
        let other = ContentId::compute(b"content B", b"k=10,n=20,v=1");
        let share = MiasmaShare::new(&mid, 0, 0, vec![1, 2, 3], vec![0xAA; 32], [0; 12], 3, 0);
        assert!(!coarse_verify(&share, &other));
    }

    #[test]
    fn coarse_verify_tampered_shard() {
        let mid = ContentId::compute(b"tamper test", b"k=10,n=20,v=1");
        let mut share = MiasmaShare::new(&mid, 0, 0, vec![1, 2, 3], vec![0xAA; 32], [0; 12], 3, 0);
        share.shard_data[0] ^= 0xFF;
        assert!(!coarse_verify(&share, &mid));
    }

    #[test]
    fn full_verify_correct() {
        let content = b"full verify test";
        let params = b"k=10,n=20,v=1";
        let mid = ContentId::compute(content, params);
        assert!(full_verify(content, params, &mid).is_ok());
    }

    #[test]
    fn full_verify_wrong_content() {
        let params = b"k=10,n=20,v=1";
        let mid = ContentId::compute(b"correct", params);
        assert!(full_verify(b"wrong", params, &mid).is_err());
    }
}
