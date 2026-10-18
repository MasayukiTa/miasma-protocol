//! `[update]` in `config.toml`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// What the program does about a newer build.
///
/// * `off`: nothing. No connection to GitHub is made and no local build
///   directory is looked at.
/// * `notify` (default): look once after start, tell the person, change nothing
///   until they say so.
/// * `auto`: look once after start, download, check and install by itself, but
///   only while no transfer, push or chat send is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateMode {
    Off,
    #[default]
    Notify,
    Auto,
}

impl UpdateMode {
    pub const ALL: [UpdateMode; 3] = [Self::Off, Self::Notify, Self::Auto];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Notify => "notify",
            Self::Auto => "auto",
        }
    }
}

impl FromStr for UpdateMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "notify" => Ok(Self::Notify),
            "auto" => Ok(Self::Auto),
            other => Err(format!(
                "unknown update mode '{other}': expected off, notify or auto"
            )),
        }
    }
}

impl fmt::Display for UpdateMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which releases count: `stable` ignores pre-releases, `beta` takes both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    Stable,
    #[default]
    Beta,
}

impl UpdateChannel {
    pub const ALL: [UpdateChannel; 2] = [Self::Stable, Self::Beta];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }
}

impl FromStr for UpdateChannel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            other => Err(format!(
                "unknown update channel '{other}': expected stable or beta"
            )),
        }
    }
}

impl fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_true() -> bool {
    true
}

/// `[update]` in `config.toml`. Every key has a default, so a `config.toml`
/// written by an earlier version (without the section) reads as `notify`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateConfig {
    /// `off`, `notify` (default) or `auto`.
    #[serde(default)]
    pub mode: UpdateMode,
    /// `stable` or `beta` (default).
    #[serde(default)]
    pub channel: UpdateChannel,
    /// Look for a newer build once after start (default true). With it off the
    /// check only runs when asked (`miasma update check`, the Check now button).
    #[serde(default = "default_true")]
    pub check_at_start: bool,
    /// Developer rebuild source: a folder that holds freshly built programs
    /// (for example `target\release`). Only used when `mode` is not `off`.
    #[serde(default)]
    pub local_build_dir: Option<String>,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            mode: UpdateMode::Notify,
            channel: UpdateChannel::Beta,
            check_at_start: true,
            local_build_dir: None,
        }
    }
}

impl UpdateConfig {
    /// The settings a stealth / portable preset starts from: updating is off,
    /// so the program makes no connection to GitHub on its own.
    pub fn stealth_preset() -> Self {
        Self {
            mode: UpdateMode::Off,
            ..Self::default()
        }
    }

    /// Whether anything about updating may run at all.
    pub fn is_enabled(&self) -> bool {
        self.mode != UpdateMode::Off
    }

    /// The configured local build folder, when set and not blank.
    pub fn local_dir(&self) -> Option<std::path::PathBuf> {
        self.local_build_dir
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;

    #[test]
    fn an_old_config_without_the_section_reads_as_notify_beta() {
        let cfg: NodeConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.update.mode, UpdateMode::Notify);
        assert_eq!(cfg.update.channel, UpdateChannel::Beta);
        assert!(cfg.update.check_at_start);
        assert!(cfg.update.local_build_dir.is_none());
    }

    #[test]
    fn the_section_reads_and_round_trips() {
        let cfg: NodeConfig = toml::from_str(
            "[update]\nmode = \"auto\"\nchannel = \"stable\"\ncheck_at_start = false\nlocal_build_dir = \"/tmp/x\"\n",
        )
        .unwrap();
        assert_eq!(cfg.update.mode, UpdateMode::Auto);
        assert_eq!(cfg.update.channel, UpdateChannel::Stable);
        assert!(!cfg.update.check_at_start);
        assert_eq!(
            cfg.update.local_dir().unwrap(),
            std::path::PathBuf::from("/tmp/x")
        );
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back: NodeConfig = toml::from_str(&text).unwrap();
        assert_eq!(back.update, cfg.update);
    }

    #[test]
    fn modes_and_channels_parse_and_reject_unknown_words() {
        for m in UpdateMode::ALL {
            assert_eq!(m.as_str().parse::<UpdateMode>().unwrap(), m);
        }
        for c in UpdateChannel::ALL {
            assert_eq!(c.as_str().parse::<UpdateChannel>().unwrap(), c);
        }
        assert!("sometimes".parse::<UpdateMode>().is_err());
        assert!("nightly".parse::<UpdateChannel>().is_err());
    }

    #[test]
    fn the_stealth_preset_is_off_and_nothing_else_changes() {
        let p = UpdateConfig::stealth_preset();
        assert_eq!(p.mode, UpdateMode::Off);
        assert!(!p.is_enabled());
        assert_eq!(p.channel, UpdateConfig::default().channel);
        assert!(UpdateConfig::default().is_enabled());
    }

    #[test]
    fn a_blank_local_build_dir_counts_as_unset() {
        let c = UpdateConfig {
            local_build_dir: Some("   ".into()),
            ..UpdateConfig::default()
        };
        assert!(c.local_dir().is_none());
    }
}
