//! The little the updater remembers between runs: a version the person chose
//! to skip, and a build whose update failed its start check (so the same
//! update is not retried in a loop). Nothing about *when* a check happened is
//! stored; that stays in memory.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateState {
    /// "Skip this version": the version string offered at the time.
    #[serde(default)]
    pub skipped_version: Option<String>,
    /// `<version>/<build id of the running program>` of an update that failed
    /// its start check; automatic mode does not try that update again.
    #[serde(default)]
    pub failed_update: Option<String>,
}

impl UpdateState {
    /// Read the state; a missing or unreadable file is the empty state.
    pub fn load(data_dir: &Path) -> Self {
        std::fs::read(crate::paths::update_state(data_dir))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Write the state (an empty state removes the file).
    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        let p = crate::paths::update_state(data_dir);
        if *self == Self::default() {
            let _ = std::fs::remove_file(&p);
            return Ok(());
        }
        let tmp = p.with_extension(crate::paths::ATOMIC_TMP_EXT);
        std::fs::write(
            &tmp,
            serde_json::to_vec(self).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(&tmp, &p)
    }

    pub fn is_skipped(&self, version: &str) -> bool {
        self.skipped_version.as_deref() == Some(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_and_an_empty_state_leaves_no_file() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(UpdateState::load(d.path()), UpdateState::default());
        let s = UpdateState {
            skipped_version: Some("0.4.0".into()),
            failed_update: None,
        };
        s.save(d.path()).unwrap();
        let back = UpdateState::load(d.path());
        assert_eq!(back, s);
        assert!(back.is_skipped("0.4.0"));
        assert!(!back.is_skipped("0.4.1"));
        UpdateState::default().save(d.path()).unwrap();
        assert!(!crate::paths::update_state(d.path()).exists());
    }

    #[test]
    fn a_damaged_file_reads_as_empty() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(crate::paths::update_state(d.path()), b"\xff\xfe junk").unwrap();
        assert_eq!(UpdateState::load(d.path()), UpdateState::default());
    }
}
