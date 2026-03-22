use sharks::{Share, Sharks};
use zeroize::Zeroizing;

use crate::MiasmaError;

/// Split a secret (K_enc) into `n` shares where any `k` shares suffice to
/// reconstruct it.
///
/// The secret is typically a 32-byte AES-256-GCM key.
///
/// # SECURITY NOTE (ADR-003)
/// K_enc reconstruction requires k shares. Until k shares are collected,
/// MAC verification (K_tag derived from K_enc) is impossible — by design.
/// Coarse per-share verification is handled by shard_hash + mid_prefix (ADR-003 ①).
pub fn sss_split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Vec<u8>>, MiasmaError> {
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

/// Reconstruct the secret from at least k serialized shares.
///
/// Returns the reconstructed secret wrapped in `Zeroizing` so it is wiped
/// from memory when dropped.
pub fn sss_combine(shares: &[Vec<u8>], k: u8) -> Result<Zeroizing<Vec<u8>>, MiasmaError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42";

    #[test]
    fn split_and_combine_exact_k() {
        let k = 3u8;
        let n = 5u8;
        let shares = sss_split(SECRET, k, n).unwrap();
        assert_eq!(shares.len(), n as usize);

        let recovered = sss_combine(&shares[..k as usize], k).unwrap();
        assert_eq!(recovered.as_slice(), SECRET);
    }

    #[test]
    fn combine_with_more_than_k_shares() {
        let k = 3u8;
        let n = 7u8;
        let shares = sss_split(SECRET, k, n).unwrap();
        // Use all n shares — should still work
        let recovered = sss_combine(&shares, k).unwrap();
        assert_eq!(recovered.as_slice(), SECRET);
    }

    #[test]
    fn insufficient_shares_returns_error() {
        let k = 5u8;
        let n = 10u8;
        let shares = sss_split(SECRET, k, n).unwrap();
        let result = sss_combine(&shares[..4], k); // k-1 shares
        assert!(matches!(
            result,
            Err(MiasmaError::InsufficientShares { need: 5, got: 4 })
        ));
    }

    #[test]
    fn invalid_parameters_rejected() {
        assert!(sss_split(SECRET, 0, 5).is_err());
        assert!(sss_split(SECRET, 5, 3).is_err()); // k > n
    }

    /// Published test vector — 32-byte key, k=10, n=20 (default parameters).
    #[test]
    fn default_params_k10_n20() {
        let k = 10u8;
        let n = 20u8;
        let shares = sss_split(SECRET, k, n).unwrap();
        assert_eq!(shares.len(), 20);
        let recovered = sss_combine(&shares[..10], k).unwrap();
        assert_eq!(recovered.as_slice(), SECRET);
    }
}
