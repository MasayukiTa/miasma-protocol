use std::collections::HashMap;

use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

use crate::MiasmaError;

/// Default Reed-Solomon parameters (10 data shards, 20 total = 10 recovery shards).
pub const DEFAULT_DATA_SHARDS: usize = 10;
pub const DEFAULT_TOTAL_SHARDS: usize = 20;
pub const DEFAULT_RECOVERY_SHARDS: usize = DEFAULT_TOTAL_SHARDS - DEFAULT_DATA_SHARDS;

/// Encode `data` into `total_shards` shards (k data + (total-k) parity).
///
/// Returns a `Vec` of `total_shards` shards, each of equal length.
/// Indices 0..data_shards are data shards; the rest are recovery shards.
///
/// `data` is zero-padded if not evenly divisible by `data_shards`.
///
/// IMPORTANT: `reed-solomon-simd` requires shard size to be non-zero and a multiple of 2 bytes
/// (even length). We therefore round shard_len up to the next even number. [2](https://users.rust-lang.org/t/cargo-use-windows-tls-ssl-ca-store/117029)
pub fn rs_encode(
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

    // Compute shard length, then round up to even length (required by reed-solomon-simd). [2](https://users.rust-lang.org/t/cargo-use-windows-tls-ssl-ca-store/117029)
    let mut shard_len = data.len().div_ceil(data_shards).max(1);
    if shard_len % 2 == 1 {
        shard_len += 1;
    }

    // Zero-pad so data divides evenly into data_shards.
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

/// Reconstruct original `data` from a subset of shards.
///
/// `available_shards` is a list of `(global_index, shard_bytes)` pairs where:
/// - `global_index` in `0..data_shards` → data shard
/// - `global_index` in `data_shards..total_shards` → recovery shard
///
/// At least `data_shards` shards (any combination of data+recovery) must be provided.
/// Returns the reconstructed data trimmed to `original_len`.
pub fn rs_decode(
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

    // Defensive checks: shard sizes must be non-zero, even, and equal.
    // `reed-solomon-simd` requires shard size even. [2](https://users.rust-lang.org/t/cargo-use-windows-tls-ssl-ca-store/117029)
    if shard_len == 0 || !shard_len.is_multiple_of(2) {
        return Err(MiasmaError::ReedSolomon(format!(
            "invalid shard size: {shard_len} bytes (must non-zero and multiple of 2)"
        )));
    }
    if !available_shards.iter().all(|(_, s)| s.len() == shard_len) {
        return Err(MiasmaError::ReedSolomon(
            "shards have different lengths".into(),
        ));
    }

    // Separate into data and recovery shard maps (deduplicated by index).
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

    // Fast path: all data shards present, no recovery needed.
    if data_map.len() == data_shards {
        let mut output = Vec::with_capacity(shard_len * data_shards);
        for i in 0..data_shards {
            output.extend_from_slice(data_map[&i]);
        }
        output.truncate(original_len);
        return Ok(output);
    }

    // Determine how many recovery shards we need.
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

    // Only add as many recovery shards as needed.
    for (&rec_idx, &shard) in recovery_map.iter().take(missing_data) {
        decoder
            .add_recovery_shard(rec_idx, shard)
            .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;
    }

    let result = decoder
        .decode()
        .map_err(|e| MiasmaError::ReedSolomon(e.to_string()))?;

    // Collect restored shards from the decoder result.
    let restored: HashMap<usize, &[u8]> = result.restored_original_iter().collect();

    // Build output in shard order.
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

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &[u8] = b"Hello Miasma Reed-Solomon test data that is long enough for testing!";

    fn make_indexed(shards: &[Vec<u8>]) -> Vec<(usize, Vec<u8>)> {
        shards.iter().cloned().enumerate().collect()
    }

    #[test]
    fn encode_decode_all_shards() {
        let shards = rs_encode(DATA, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap();
        assert_eq!(shards.len(), DEFAULT_TOTAL_SHARDS);
        let indexed = make_indexed(&shards);
        let recovered = rs_decode(
            &indexed,
            DEFAULT_DATA_SHARDS,
            DEFAULT_TOTAL_SHARDS,
            DATA.len(),
        )
        .unwrap();
        assert_eq!(recovered, DATA);
    }

    #[test]
    fn decode_fast_path_all_data_shards() {
        let shards = rs_encode(DATA, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap();
        // Only provide data shards (no recovery), should use fast path.
        let indexed: Vec<(usize, Vec<u8>)> = shards[..DEFAULT_DATA_SHARDS]
            .iter()
            .cloned()
            .enumerate()
            .collect();
        let recovered = rs_decode(
            &indexed,
            DEFAULT_DATA_SHARDS,
            DEFAULT_TOTAL_SHARDS,
            DATA.len(),
        )
        .unwrap();
        assert_eq!(recovered, DATA);
    }

    #[test]
    fn decode_with_5_missing_data_shards() {
        let shards = rs_encode(DATA, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap();
        // Drop data shards 0–4, use remaining data + recovery.
        let indexed: Vec<(usize, Vec<u8>)> = shards
            .iter()
            .cloned()
            .enumerate()
            .filter(|(i, _)| *i >= 5)
            .collect();
        let recovered = rs_decode(
            &indexed,
            DEFAULT_DATA_SHARDS,
            DEFAULT_TOTAL_SHARDS,
            DATA.len(),
        )
        .unwrap();
        assert_eq!(recovered, DATA);
    }

    #[test]
    fn decode_only_recovery_shards_sufficient() {
        let shards = rs_encode(DATA, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap();
        // Drop ALL data shards; use only 10 recovery shards.
        let indexed: Vec<(usize, Vec<u8>)> = shards[DEFAULT_DATA_SHARDS..]
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, s)| (i + DEFAULT_DATA_SHARDS, s))
            .collect();
        let recovered = rs_decode(
            &indexed,
            DEFAULT_DATA_SHARDS,
            DEFAULT_TOTAL_SHARDS,
            DATA.len(),
        )
        .unwrap();
        assert_eq!(recovered, DATA);
    }

    #[test]
    fn insufficient_shards_returns_error() {
        let shards = rs_encode(DATA, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap();
        let indexed: Vec<(usize, Vec<u8>)> = shards.into_iter().enumerate().take(9).collect();
        assert!(rs_decode(
            &indexed,
            DEFAULT_DATA_SHARDS,
            DEFAULT_TOTAL_SHARDS,
            DATA.len()
        )
        .is_err());
    }

    #[test]
    fn shard_lengths_are_equal() {
        let data = vec![0x5Au8; 1024 * 100]; // 100 KiB
        let shards = rs_encode(&data, DEFAULT_DATA_SHARDS, DEFAULT_TOTAL_SHARDS).unwrap();
        let first_len = shards[0].len();
        assert!(shards.iter().all(|s| s.len() == first_len));
    }
}
