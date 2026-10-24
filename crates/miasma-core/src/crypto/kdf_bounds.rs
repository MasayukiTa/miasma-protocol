//! Shared Argon2id cost bounds for password-based key derivation.
//!
//! These limits apply to KDF cost parameters that may arrive from an untrusted
//! source. A receiver checks a candidate cost against them before running any
//! Argon2id work, so a value outside the range is refused rather than executed.
//!
//! The bounds live here so the segmented-transfer path and the directed-sharing
//! path share one definition instead of keeping separate copies.

/// Maximum Argon2id memory cost, in KiB.
pub const MAX_M_KIB: u32 = 128 * 1024;
/// Maximum Argon2id time cost (number of passes).
pub const MAX_T_COST: u32 = 6;
/// Maximum Argon2id parallelism (number of lanes).
pub const MAX_P_COST: u32 = 2;
/// Minimum Argon2id memory cost, in KiB. Argon2 also requires `m >= 8 * p`.
pub const MIN_M_KIB: u32 = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_form_a_usable_range() {
        // The accepted window is non-empty, including the Argon2 floor m >= 8*p
        // at the largest allowed parallelism.
        assert!(MIN_M_KIB <= MAX_M_KIB);
        assert!(MIN_M_KIB.max(8 * MAX_P_COST) <= MAX_M_KIB);
        assert!(MAX_T_COST >= 1);
        assert!(MAX_P_COST >= 1);
    }

    #[test]
    fn bounds_keep_their_pinned_values() {
        // Pinned so a change to the shared limits is a deliberate edit here.
        assert_eq!(MAX_M_KIB, 131072);
        assert_eq!(MAX_T_COST, 6);
        assert_eq!(MAX_P_COST, 2);
        assert_eq!(MIN_M_KIB, 8);
    }
}
