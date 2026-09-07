use blahaj::{Share, Sharks};
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
    let sss = Sharks(k);
    let dealer = sss.dealer(secret);
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
    let sss = Sharks(k);
    let parsed: Result<Vec<Share>, _> = shares
        .iter()
        .map(|s| Share::try_from(s.as_slice()))
        .collect();
    let parsed = parsed.map_err(|e| MiasmaError::Sss(e.to_string()))?;

    let secret = sss
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

    /// Regression test for RUSTSEC-2024-0398 ("Bias of Polynomial Coefficients
    /// in Secret Sharing").
    ///
    /// `sharks` 0.5.0 drew the non-constant polynomial coefficients from
    /// `[1, 255]` instead of `[0, 255]`. With `k = 2` the polynomial is
    /// `f(x) = a1*x + s`, so the share at `x = 1` carries `y = a1 + s`
    /// (GF(256) addition is XOR). If `a1` can never be zero then `y` can
    /// never equal `s` -- one byte value is excluded from every share, and an
    /// attacker holding `k-1` shares of a repeatedly-shared secret can rule
    /// out an exponential number of candidates (Cure53 estimated recovery
    /// after 500-1500 re-shares of the same secret).
    ///
    /// This test asserts the *absence* of that exclusion: over `TRIALS`
    /// splits of the same one-byte secret, `y == s` must occur at least once.
    /// Under the fixed implementation it occurs with p = 1/256 per trial, so
    /// a false failure has probability (255/256)^4000 ~= 2e-7. Under the
    /// biased implementation it is impossible, so this test fails
    /// deterministically.
    #[test]
    fn leading_coefficient_can_be_zero() {
        const TRIALS: usize = 4000;
        let secret = [0x5Au8];
        let mut hits = 0usize;

        for _ in 0..TRIALS {
            let shares = sss_split(&secret, 2, 2).unwrap();
            // Serialized share layout is [x, y_0, y_1, ...]; the dealer's
            // first share is evaluated at x = 1.
            assert_eq!(shares[0].len(), 2, "1-byte secret => 1-byte y");
            assert_eq!(shares[0][0], 1, "first share must be at x = 1");
            if shares[0][1] == secret[0] {
                hits += 1;
            }
        }

        assert!(
            hits > 0,
            "no share at x=1 ever equalled the secret across {TRIALS} splits: \
             the leading coefficient is being drawn from [1,255], which is \
             exactly RUSTSEC-2024-0398"
        );
    }
}
