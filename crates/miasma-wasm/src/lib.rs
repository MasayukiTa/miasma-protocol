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
            MiasmaError::InvalidMid(format!("missing 'miasma:' prefix in '{}'", s))
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

// ── Pipeline: dissolve ────────────────────────────────────────────────

fn dissolve_inner(
    plaintext: &[u8],
    params: DissolutionParams,
) -> Result<(ContentId, Vec<MiasmaShare>), MiasmaError> {
    let param_bytes = params.to_param_bytes();
    let mid = ContentId::compute(plaintext, &param_bytes);

    let (ciphertext, k_enc, nonce) = encrypt(plaintext)?;

    let shards = rs_encode(&ciphertext, params.data_shards, params.total_shards)?;
    let key_shares =
        sss_split(k_enc.as_ref(), params.data_shards as u8, params.total_shards as u8)?;

    let timestamp = (js_sys::Date::now() / 1000.0) as u64;

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
    let ciphertext_len = plaintext_len + 16;

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
