//! High-level privacy settings exposed through UniFFI.
//!
//! These functions intentionally persist configuration rather than trying to
//! rebuild the process-wide tracing subscriber in place. Callers are told when
//! a restart is required so a platform shell cannot silently claim a stricter
//! privacy mode than the current process is actually using.

use miasma_core::config::{NodeConfig, MAX_LOG_BUFFER_MIB, MIN_LOG_BUFFER_MIB};

use super::{validate_data_dir, MiasmaFfiError};

/// Privacy-related settings that are safe and useful at the mobile/native UI
/// boundary. This mirrors the existing `[privacy]` configuration without
/// exposing transport secrets or internal paths.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrivacyProfileFfi {
    /// Keep logs in memory only and suppress normal stderr output after restart.
    pub stealth_mode: bool,
    /// Explicitly write redacted diagnostic log files.
    pub diagnostic_logging: bool,
    /// In-memory log ring size in MiB.
    pub log_buffer_mib: u32,
}

/// Result of applying a privacy profile.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PrivacyProfileApplyResultFfi {
    /// `true` when the process must restart before all requested settings are
    /// guaranteed to be active. Stealth mode and ring capacity are fixed when
    /// the tracing subscriber is created.
    pub restart_required: bool,
    /// Whether the persisted profile will write log files after restart.
    pub writes_log_files_after_restart: bool,
}

fn load_config(path: &std::path::Path, data_dir: &str) -> Result<NodeConfig, MiasmaFfiError> {
    if !miasma_core::paths::config_file(path).exists() {
        return Err(MiasmaFfiError::NotInitialized {
            data_dir: data_dir.to_owned(),
        });
    }
    NodeConfig::load(path).map_err(|e| {
        tracing::warn!("privacy config load error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to load privacy settings".into(),
        }
    })
}

fn read_profile(
    path: &std::path::Path,
    data_dir: &str,
) -> Result<PrivacyProfileFfi, MiasmaFfiError> {
    let mut config = load_config(path, data_dir)?;
    let profile = PrivacyProfileFfi {
        stealth_mode: config.privacy.stealth_mode,
        diagnostic_logging: config.privacy.diagnostic_logging,
        log_buffer_mib: config.privacy.log_buffer_mib,
    };
    config.transport.zeroize_secret_copies();
    Ok(profile)
}

fn write_profile(
    path: &std::path::Path,
    data_dir: &str,
    profile: PrivacyProfileFfi,
) -> Result<PrivacyProfileApplyResultFfi, MiasmaFfiError> {
    if !(MIN_LOG_BUFFER_MIB..=MAX_LOG_BUFFER_MIB).contains(&profile.log_buffer_mib) {
        return Err(MiasmaFfiError::Other {
            msg: format!(
                "log_buffer_mib must be between {MIN_LOG_BUFFER_MIB} and {MAX_LOG_BUFFER_MIB}"
            ),
        });
    }

    let mut config = load_config(path, data_dir)?;
    let restart_required = config.privacy.stealth_mode != profile.stealth_mode
        || config.privacy.log_buffer_mib != profile.log_buffer_mib;

    config.privacy.stealth_mode = profile.stealth_mode;
    config.privacy.diagnostic_logging = profile.diagnostic_logging;
    config.privacy.log_buffer_mib = profile.log_buffer_mib;

    let saved = config.save(path);
    // Clear any persisted transport secret copies on every path, including a
    // failed save.
    config.transport.zeroize_secret_copies();
    saved.map_err(|e| {
        tracing::warn!("privacy config save error: {e}");
        MiasmaFfiError::Other {
            msg: "failed to save privacy settings".into(),
        }
    })?;

    let writes_log_files_after_restart = profile.diagnostic_logging || !profile.stealth_mode;
    if !writes_log_files_after_restart {
        // The persisted profile requests no files. Deleting stale diagnostic
        // files now avoids leaving them around until the next launch.
        miasma_core::logging::delete_diagnostic_files(path);
    }

    Ok(PrivacyProfileApplyResultFfi {
        restart_required,
        writes_log_files_after_restart,
    })
}

/// Read the persisted privacy profile.
#[uniffi::export]
pub fn get_privacy_profile(data_dir: String) -> Result<PrivacyProfileFfi, MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    read_profile(&path, &data_dir)
}

/// Persist a privacy profile for the next process start.
///
/// Diagnostic files are removed immediately when the resulting profile is
/// fully stealth (`stealth_mode=true`, `diagnostic_logging=false`). Changes to
/// stealth mode or ring capacity require a restart because the tracing
/// subscriber and ring allocation are process-global and created once.
#[uniffi::export]
pub fn set_privacy_profile(
    data_dir: String,
    profile: PrivacyProfileFfi,
) -> Result<PrivacyProfileApplyResultFfi, MiasmaFfiError> {
    let path = validate_data_dir(&data_dir)?;
    write_profile(&path, &data_dir, profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("miasma-ffi-privacy-{tag}-{}", std::process::id()))
    }

    #[test]
    fn set_then_get_round_trips_and_reports_restart() {
        let dir = scratch_dir("roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        NodeConfig::default().save(&dir).unwrap();
        let data_dir = dir.to_str().unwrap().to_owned();

        let current = read_profile(&dir, &data_dir).unwrap();
        let same = write_profile(&dir, &data_dir, current.clone()).unwrap();
        assert!(!same.restart_required);

        let requested = PrivacyProfileFfi {
            stealth_mode: !current.stealth_mode,
            diagnostic_logging: current.diagnostic_logging,
            log_buffer_mib: MIN_LOG_BUFFER_MIB,
        };
        let applied = write_profile(&dir, &data_dir, requested.clone()).unwrap();
        assert!(applied.restart_required);
        assert_eq!(read_profile(&dir, &data_dir).unwrap(), requested);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn out_of_range_buffer_is_rejected_and_uninitialized_dir_reported() {
        let dir = scratch_dir("uninit");
        let _ = std::fs::remove_dir_all(&dir);
        let data_dir = dir.to_str().unwrap().to_owned();
        let bad = PrivacyProfileFfi {
            stealth_mode: true,
            diagnostic_logging: false,
            log_buffer_mib: MAX_LOG_BUFFER_MIB + 1,
        };
        assert!(write_profile(&dir, &data_dir, bad).is_err());

        let ok = PrivacyProfileFfi {
            stealth_mode: true,
            diagnostic_logging: false,
            log_buffer_mib: MIN_LOG_BUFFER_MIB,
        };
        assert!(matches!(
            write_profile(&dir, &data_dir, ok),
            Err(MiasmaFfiError::NotInitialized { .. })
        ));
    }

    #[test]
    fn log_buffer_bounds_are_nonempty_and_ordered() {
        assert!(MIN_LOG_BUFFER_MIB >= 1);
        assert!(MAX_LOG_BUFFER_MIB >= MIN_LOG_BUFFER_MIB);
    }
}
