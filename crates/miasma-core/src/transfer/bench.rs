//! A measurement harness for the redundancy setting (`k` of `n`).
//!
//! For each `k/n` it runs the *real* dissolve and recover code on an in-memory
//! buffer and reports what the setting actually costs and what it actually
//! buys: bytes stored per byte of file, dissolve and recover throughput, and
//! whether losing exactly `n - k` pieces is survivable while `n - k + 1` fails
//! cleanly.
//!
//! Two of those numbers do not depend on the machine or the build and can be
//! trusted anywhere: the measured storage factor and the loss tolerance. The
//! throughput figures do: run this in a `--release` build on the machine that
//! will actually do the transfer. Nothing here touches the network.

use std::time::{Duration, Instant};

use super::protection::PasswordProtection;
use crate::{
    crypto::{aead::encrypt, hash::ContentId, rs::rs_encode, sss::sss_split},
    dissolution::{
        segment::{dissolve_segment_with, retrieve_segment_with},
        SegmentMeta, DEFAULT_SEGMENT_SIZE,
    },
    network::coordinator::max_segment_size_for,
    pipeline::DissolutionParams,
    share::MiasmaShare,
    store::LocalShareStore,
    MiasmaError,
};

/// The settings worth comparing for a 1:1 transfer.
pub const DEFAULT_PRESETS: [(usize, usize); 5] = [(10, 10), (10, 11), (10, 12), (10, 15), (10, 20)];

#[derive(Debug, Clone)]
pub struct BenchRow {
    pub data_shards: usize,
    pub total_shards: usize,
    /// `n / k`, from the parameters alone.
    pub nominal_factor: f64,
    /// Serialized share bytes stored per byte of input, measured.
    pub measured_factor: f64,
    /// Pieces of a segment that may be lost with the data still recoverable.
    pub tolerated_losses: usize,
    /// Recovery from exactly `n - k` lost pieces was verified byte-for-byte.
    pub survives_tolerated_loss: bool,
    /// One more lost piece (`n - k + 1`) failed as `InsufficientShares`, not a panic
    /// or wrong data.
    pub fails_cleanly_beyond_tolerance: bool,
    pub segments: usize,
    pub dissolve: Duration,
    pub recover: Duration,
    /// Time spent writing every share to a local store, when one was given.
    pub store: Option<Duration>,
    pub input_bytes: usize,
    pub stage_encrypt: Duration,
    pub stage_reed_solomon: Duration,
    pub stage_shamir: Duration,
}

impl BenchRow {
    pub fn dissolve_mib_s(&self) -> f64 {
        mib_s(self.input_bytes, self.dissolve)
    }
    pub fn recover_mib_s(&self) -> f64 {
        mib_s(self.input_bytes, self.recover)
    }
    pub fn store_mib_s(&self) -> Option<f64> {
        self.store.map(|d| mib_s(self.input_bytes, d))
    }
}

fn mib_s(bytes: usize, d: Duration) -> f64 {
    let secs = d.as_secs_f64();
    if secs > 0.0 {
        bytes as f64 / 1_048_576.0 / secs
    } else {
        f64::INFINITY
    }
}

/// Deterministic, incompressible-looking bytes (xorshift), so the run is repeatable.
fn fill(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = vec![0u8; len];
    for chunk in out.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    out
}

/// Run every preset over `size_mib` MiB of data.
///
/// `store_dir`, when given, also writes every share to a real
/// [`LocalShareStore`] in that directory (which is then left behind) so the local
/// disk and at-rest encryption are part of the measurement.
pub fn run_redundancy_bench(
    size_mib: usize,
    presets: &[(usize, usize)],
    store_dir: Option<&std::path::Path>,
) -> Result<Vec<BenchRow>, MiasmaError> {
    let data = fill(size_mib.max(1) * 1024 * 1024);
    let mut rows = Vec::with_capacity(presets.len());
    for &(k, n) in presets {
        rows.push(bench_one(&data, k, n, store_dir)?);
    }
    Ok(rows)
}

fn bench_one(
    data: &[u8],
    k: usize,
    n: usize,
    store_dir: Option<&std::path::Path>,
) -> Result<BenchRow, MiasmaError> {
    let params = DissolutionParams {
        data_shards: k,
        total_shards: n,
    };
    let segment_size = DEFAULT_SEGMENT_SIZE.min(max_segment_size_for(k));
    let mid = ContentId::compute(data, &params.to_param_bytes());
    // The password path is the one that will be used; its cost per segment is one
    // HKDF, so it does not skew the comparison.
    let (_, key) = PasswordProtection::create_with_cost("redundancy-bench", 64, 1, 1)?;

    // Stage attribution on the first segment (the real dissolve below is what is
    // reported as the total).
    let first = &data[..data.len().min(segment_size)];
    let t = Instant::now();
    let (ct, k_enc, _nonce) = encrypt(first)?;
    let stage_encrypt = t.elapsed();
    let t = Instant::now();
    let _ = rs_encode(&ct, k, n)?;
    let stage_reed_solomon = t.elapsed();
    let t = Instant::now();
    let _ = sss_split(k_enc.as_ref(), k as u8, n as u8)?;
    let stage_shamir = t.elapsed();

    let store = match store_dir {
        Some(d) => Some(LocalShareStore::open(
            &d.join(format!("bench-{k}-{n}")),
            1_000_000,
        )?),
        None => None,
    };

    let mut segments: Vec<(SegmentMeta, Vec<MiasmaShare>)> = Vec::new();
    let mut dissolve = Duration::ZERO;
    let mut store_time = Duration::ZERO;
    let mut stored_bytes = 0usize;
    for (i, chunk) in data.chunks(segment_size).enumerate() {
        let t = Instant::now();
        let (meta, shares) = dissolve_segment_with(chunk, &mid, i as u32, 0, params, Some(&key))?;
        dissolve += t.elapsed();
        for s in &shares {
            stored_bytes += s.to_bytes()?.len();
        }
        if let Some(st) = &store {
            let t = Instant::now();
            for s in &shares {
                st.put(s)?;
            }
            store_time += t.elapsed();
        }
        segments.push((meta, shares));
    }

    // Recover from the worst case: the *last* k pieces (all parity first), so
    // Reed-Solomon reconstruction really runs.
    let mut recover = Duration::ZERO;
    let mut rebuilt = Vec::with_capacity(data.len());
    for (meta, shares) in &segments {
        let keep: Vec<MiasmaShare> = shares[n - k..].to_vec();
        let t = Instant::now();
        let bytes = retrieve_segment_with(&mid, &keep, meta, params, Some(&key))?;
        recover += t.elapsed();
        rebuilt.extend_from_slice(&bytes);
    }
    let survives_tolerated_loss = rebuilt == data;

    // Loss tolerance on the first segment: n-k lost is fine, n-k+1 fails cleanly.
    let (meta0, shares0) = &segments[0];
    let too_few: Vec<MiasmaShare> = shares0[n - k + 1..].to_vec();
    let fails_cleanly_beyond_tolerance = matches!(
        retrieve_segment_with(&mid, &too_few, meta0, params, Some(&key)),
        Err(MiasmaError::InsufficientShares { .. })
    );

    Ok(BenchRow {
        data_shards: k,
        total_shards: n,
        nominal_factor: n as f64 / k as f64,
        measured_factor: stored_bytes as f64 / data.len() as f64,
        tolerated_losses: n - k,
        survives_tolerated_loss,
        fails_cleanly_beyond_tolerance,
        segments: segments.len(),
        dissolve,
        recover,
        store: store.map(|_| store_time),
        input_bytes: data.len(),
        stage_encrypt,
        stage_reed_solomon,
        stage_shamir,
    })
}

/// A Markdown table of the results.
pub fn format_table(rows: &[BenchRow]) -> String {
    let with_store = rows.iter().any(|r| r.store.is_some());
    let mut out = String::new();
    out.push_str("| k/n | stored per byte (nominal / measured) | lost pieces tolerated | tolerance verified | dissolve MiB/s | recover MiB/s |");
    if with_store {
        out.push_str(" local store MiB/s |");
    }
    out.push('\n');
    out.push_str("|---|---|---|---|---|---|");
    if with_store {
        out.push_str("---|");
    }
    out.push('\n');
    for r in rows {
        let verified = if r.survives_tolerated_loss && r.fails_cleanly_beyond_tolerance {
            "yes"
        } else {
            "NO"
        };
        out.push_str(&format!(
            "| {}/{} | {:.2}x / {:.3}x | {} | {} | {:.1} | {:.1} |",
            r.data_shards,
            r.total_shards,
            r.nominal_factor,
            r.measured_factor,
            r.tolerated_losses,
            verified,
            r.dissolve_mib_s(),
            r.recover_mib_s()
        ));
        if with_store {
            out.push_str(&format!(" {:.1} |", r.store_mib_s().unwrap_or(0.0)));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_default_preset_runs_and_its_tolerance_is_verified() {
        let rows = run_redundancy_bench(1, &DEFAULT_PRESETS, None).unwrap();
        assert_eq!(rows.len(), DEFAULT_PRESETS.len());
        for r in &rows {
            assert!(
                r.survives_tolerated_loss,
                "{}/{}: losing n-k pieces must be survivable",
                r.data_shards, r.total_shards
            );
            assert!(
                r.fails_cleanly_beyond_tolerance,
                "{}/{}: losing n-k+1 must fail as InsufficientShares",
                r.data_shards, r.total_shards
            );
            assert_eq!(r.tolerated_losses, r.total_shards - r.data_shards);
        }
    }

    #[test]
    fn the_measured_storage_factor_tracks_n_over_k() {
        let rows = run_redundancy_bench(2, &DEFAULT_PRESETS, None).unwrap();
        for r in &rows {
            // Per-share overhead (headers, hashes, key share) is small next to
            // 2 MiB of payload, but never negative and never large.
            assert!(
                r.measured_factor >= r.nominal_factor,
                "{}/{}: {} < {}",
                r.data_shards,
                r.total_shards,
                r.measured_factor,
                r.nominal_factor
            );
            assert!(
                r.measured_factor < r.nominal_factor * 1.02,
                "{}/{}: overhead too large ({} vs {})",
                r.data_shards,
                r.total_shards,
                r.measured_factor,
                r.nominal_factor
            );
        }
        // And redundancy really is ordered.
        for w in rows.windows(2) {
            assert!(w[0].measured_factor < w[1].measured_factor);
        }
    }

    #[test]
    fn a_store_can_be_included_in_the_measurement() {
        let dir = tempfile::tempdir().unwrap();
        let rows = run_redundancy_bench(1, &[(10, 12)], Some(dir.path())).unwrap();
        assert!(rows[0].store.is_some());
        assert!(rows[0].store_mib_s().unwrap() > 0.0);
        let table = format_table(&rows);
        assert!(table.contains("local store MiB/s"), "{table}");
    }

    #[test]
    fn the_table_names_every_preset() {
        let rows = run_redundancy_bench(1, &DEFAULT_PRESETS, None).unwrap();
        let table = format_table(&rows);
        for (k, n) in DEFAULT_PRESETS {
            assert!(table.contains(&format!("| {k}/{n} |")), "{table}");
        }
        assert!(!table.contains("| NO |"), "{table}");
    }
}
