/// Node configuration — persisted to `{data_dir}/config.toml`.
use std::{
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::MiasmaError;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    /// Trusted-contact push.
    #[serde(default)]
    pub push: PushConfig,
    /// One-to-one chat.
    #[serde(default)]
    pub chat: ChatConfig,
    /// Logging and traces left on this machine.
    #[serde(default)]
    pub privacy: PrivacyConfig,
    /// Looking for, and installing, newer builds.
    #[serde(default)]
    pub update: crate::update::UpdateConfig,
    /// How published transfers are written on the wire.
    #[serde(default)]
    pub transfer: TransferConfig,
}

/// `[privacy]` in `config.toml`: what the programs may leave behind.
///
/// Every key has a default, so a `config.toml` written by an older version
/// (without the section) reads as stealth mode with no log files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyConfig {
    /// Stealth mode (default **on**, also after an upgrade): the programs keep
    /// their log lines only in a bounded in-memory buffer; nothing is printed
    /// by library code and no log file is written. With it off, log lines also
    /// go to stderr and to the rotating log files, as in earlier versions.
    #[serde(default = "default_true")]
    pub stealth_mode: bool,
    /// Opt-in diagnostic logging (default **off**): writes size-rotated log
    /// files to the data directory even in stealth mode. They show that Miasma
    /// was used and when. Turning it off deletes them.
    #[serde(default)]
    pub diagnostic_logging: bool,
    /// Size of the in-memory log buffer per program, in MiB (1-8, default 2).
    #[serde(default = "default_log_buffer_mib")]
    pub log_buffer_mib: u32,
    /// The one-time notice about old log files has been shown.
    #[serde(default)]
    pub old_logs_notice_shown: bool,
    /// The user chose to keep old log files; they are not offered for removal
    /// again.
    #[serde(default)]
    pub old_logs_keep: bool,
    /// Hybrid post-quantum upgrade of private-conversation sessions. Not set
    /// (the default) means [`PqcMode::DEFAULT`] (`require`); the key is written
    /// only once a person has chosen a value. Use [`PrivacyConfig::pqc_mode`] for
    /// the value in force. Only builds with the `pqc` cargo feature act on it;
    /// other builds ignore it and report that they cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_mode: Option<PqcMode>,
    /// Which default of `pqc_mode` this file was written under, so a value an
    /// older default wrote is not read as a choice. Files written before this
    /// key existed read it as `0`. See [`PQC_DEFAULT_VERSION`] for the version
    /// history and [`PrivacyConfig::migrate_pqc_default`] for how each step is
    /// applied. Every save writes the current value, so a choice made after a
    /// migration is kept as it is.
    #[serde(default)]
    pub pqc_default_version: u32,
}

/// Value of [`PrivacyConfig::pqc_default_version`] written by this build.
///
/// Version history (each step is applied once, when the file is read under an
/// older version; see [`PrivacyConfig::migrate_pqc_default`]):
/// * `0`: no key in the file (read as `0`). The default was `off`, so an
///   `off` value written under version `0` was a save, not a choice.
/// * `1`: the default became `prefer`. An `off` left by version `0` was read
///   as never chosen and cleared, so the `prefer` default applied.
/// * `2`: the default becomes `require`. Two values a pre-beta.12 default left
///   behind are carried forward so beta.12 keeps no setting that would allow a
///   silent classical fallback: an `off` from version `0` (the sole version
///   whose default was `off`) is cleared to never chosen, and a `prefer` found
///   at version `0` or `1` (the standard choice of the old screen) is moved to
///   `require`. An `off` recorded at version `1` or later, and a `prefer`,
///   `off` or `require` set at version `2` or later, were explicit choices and
///   are kept, as is any value set after this migration (the file is then at
///   version `2`).
pub const PQC_DEFAULT_VERSION: u32 = 2;

/// `privacy.pqc_mode`: whether private-conversation sessions are upgraded with
/// a hybrid X25519 + ML-KEM-768 key exchange.
///
/// * `require` (default): messages to a contact are sent only once the hybrid
///   exchange with that contact has completed. If the contact does not offer
///   it, the messages fail on this device with a stated reason; nothing is
///   sent in the classical session. The contact's own settings are not
///   affected.
/// * `prefer`: offer the hybrid exchange. Use it when the peer agrees; when
///   the peer does not, keep the classical session and show "classical only".
///   This lowers the guarantee to the peer's level, so it is not a value the
///   normal settings offer: it is honoured only when written into the
///   configuration file by hand or passed to an advanced command-line option,
///   and the status then warns that a classical fallback is allowed.
/// * `off`: nothing changes. This build offers nothing and answers nothing,
///   so every peer sees exactly what it saw before. Like `prefer`, it is only
///   honoured when set explicitly (file or advanced option) and the status
///   warns about the classical fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PqcMode {
    Off,
    Prefer,
    #[default]
    Require,
}

impl PqcMode {
    /// What applies when a person never chose a value.
    pub const DEFAULT: Self = Self::Require;

    /// True for a value that lowers the guarantee below `require` (a classical
    /// fallback is then allowed). Such a value is honoured only when set
    /// explicitly; the status warns while one is in force.
    pub fn allows_classical_fallback(self) -> bool {
        matches!(self, Self::Off | Self::Prefer)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Prefer => "prefer",
            Self::Require => "require",
        }
    }

    /// True when this build contains the hybrid exchange at all.
    pub const fn available() -> bool {
        cfg!(feature = "pqc")
    }
}

impl std::str::FromStr for PqcMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            other => Err(format!(
                "unknown pqc mode '{other}': expected off, prefer or require"
            )),
        }
    }
}

impl fmt::Display for PqcMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persist `privacy.pqc_mode` in `config.toml` (a running daemon reads it at
/// its next start). With no configuration file yet, start from the defaults,
/// apply the choice and write it; a file that exists but cannot be read is an
/// error and is left untouched, so a damaged file is never overwritten with
/// defaults.
pub fn set_pqc_mode_persistent(data_dir: &Path, mode: PqcMode) -> std::io::Result<()> {
    let mut c = NodeConfig::load(data_dir)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    if c.privacy.pqc_mode != Some(mode) {
        c.privacy.pqc_mode = Some(mode);
        c.save(data_dir)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }
    c.transport.zeroize_secret_copies();
    Ok(())
}

pub const DEFAULT_LOG_BUFFER_MIB: u32 = 2;
pub const MIN_LOG_BUFFER_MIB: u32 = 1;
pub const MAX_LOG_BUFFER_MIB: u32 = 8;

fn default_log_buffer_mib() -> u32 {
    DEFAULT_LOG_BUFFER_MIB
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            stealth_mode: true,
            diagnostic_logging: false,
            log_buffer_mib: DEFAULT_LOG_BUFFER_MIB,
            old_logs_notice_shown: false,
            old_logs_keep: false,
            pqc_mode: None,
            pqc_default_version: PQC_DEFAULT_VERSION,
        }
    }
}

impl PrivacyConfig {
    /// The mode in force: the person's choice, else [`PqcMode::DEFAULT`].
    pub fn pqc_mode(&self) -> PqcMode {
        self.pqc_mode.unwrap_or(PqcMode::DEFAULT)
    }

    /// Move a file written under an older default up to the current one, once.
    /// The step runs only while the file predates the current version, so a
    /// value a person set after a migration (the file is then at the current
    /// version) is never read as an older default and is kept.
    ///
    /// Two values a pre-beta.12 default left behind are carried forward, so
    /// beta.12 never keeps a setting that would allow a silent classical
    /// fallback by default:
    ///
    /// * an `off` the version `0` default wrote (no version key) was a save,
    ///   not a choice, so it is cleared to "never chosen" and the current
    ///   default (`require`) applies. Version `0` was the only default of
    ///   `off`, so an `off` recorded at version `1` or later was an explicit
    ///   choice and is kept.
    /// * a `prefer` found at version `0` or `1` is the carried-over old
    ///   default (`prefer` was the standard choice in the pre-beta.12 screen),
    ///   so it is moved to `require`. A `prefer` set at version `2` or later
    ///   is an explicit advanced choice and is kept (the status then warns).
    ///
    /// What each (version, value) reaches after this runs:
    ///
    /// | version | unset   | `off`   | `prefer`  | `require` |
    /// |---------|---------|---------|-----------|-----------|
    /// | `0`     | require (unset) | require (cleared) | require | require (kept) |
    /// | `1`     | require (unset) | off (kept) | require | require (kept) |
    /// | `2`     | require (unset) | off (kept) | prefer (kept) | require (kept) |
    ///
    /// ("unset" means `pqc_mode` is `None`, which resolves to the current
    /// default `require` through [`PrivacyConfig::pqc_mode`].)
    fn migrate_pqc_default(&mut self) {
        if self.pqc_default_version < PQC_DEFAULT_VERSION {
            match self.pqc_mode {
                // The version `0` default wrote this `off`; it was never
                // chosen. Versions `1` and `2` never defaulted to `off`, so an
                // `off` from those versions is an explicit choice and is left
                // untouched by the guard.
                Some(PqcMode::Off) if self.pqc_default_version < 1 => {
                    self.pqc_mode = None;
                }
                // A `prefer` from version `0` or `1` is the old standard
                // default carried over, not an advanced choice, so it moves to
                // `require`. A `prefer` set at version `2` or later never
                // reaches here (the outer check excludes it) and is kept.
                Some(PqcMode::Prefer) => {
                    self.pqc_mode = Some(PqcMode::Require);
                }
                _ => {}
            }
            self.pqc_default_version = PQC_DEFAULT_VERSION;
        }
    }

    /// The ring buffer size in bytes, clamped to the allowed range.
    pub fn log_buffer_bytes(&self) -> usize {
        self.log_buffer_mib
            .clamp(MIN_LOG_BUFFER_MIB, MAX_LOG_BUFFER_MIB) as usize
            * 1024
            * 1024
    }

    /// Whether log files are written: the opt-in switch, or stealth mode off.
    pub fn writes_log_files(&self) -> bool {
        self.diagnostic_logging || !self.stealth_mode
    }
}

/// `[chat]` in `config.toml`: one-to-one chat between registered contacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatConfig {
    /// Chat on or off (default on). Takes effect when the daemon starts.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Keep the message history on disk (encrypted). Not set (the default):
    /// the history is saved. Set it to `false` to keep it in memory only (it is
    /// then gone when the daemon stops). `privacy.stealth_mode` does not change
    /// this.
    #[serde(default)]
    pub history_save: Option<bool>,
    /// Longest message accepted, in bytes (1-4096, default 4096).
    #[serde(default = "default_chat_max_message_bytes")]
    pub max_message_bytes: usize,
    /// Messages that may wait for delivery at once (1-500, default 500).
    #[serde(default = "default_chat_outbox_max")]
    pub outbox_max: usize,
    /// Saved messages older than this many days are removed (0 = keep).
    #[serde(default)]
    pub retention_days: u64,
    /// Tell a contact when its messages have been read, and show when yours
    /// have been (default on). Both sides must have it on for a message to
    /// show as read; with it off here nothing is sent and what arrives is
    /// hidden. Each contact can also be switched off on its own. Takes effect
    /// when the daemon starts.
    #[serde(default = "default_true")]
    pub read_receipts: bool,
    /// Hold sealed messages in memory for trusted contacts who are offline
    /// (default off). Nothing listens for it yet; the setting only decides
    /// whether the in-memory custody store accepts items.
    #[serde(default)]
    pub custody_enabled: bool,
    /// Join a group at once when a trusted contact who administers it adds
    /// you (default on). Off: the invitation waits for an answer (Accept or
    /// Decline). Either way you can leave with one action, and an invitation
    /// from someone who is not a trusted contact is refused.
    #[serde(default = "default_true")]
    pub group_auto_join: bool,
}

pub const DEFAULT_CHAT_MAX_MESSAGE_BYTES: usize = 4096;
pub const DEFAULT_CHAT_OUTBOX_MAX: usize = 500;

fn default_chat_max_message_bytes() -> usize {
    DEFAULT_CHAT_MAX_MESSAGE_BYTES
}
fn default_chat_outbox_max() -> usize {
    DEFAULT_CHAT_OUTBOX_MAX
}

impl Default for ChatConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            history_save: None,
            max_message_bytes: DEFAULT_CHAT_MAX_MESSAGE_BYTES,
            outbox_max: DEFAULT_CHAT_OUTBOX_MAX,
            retention_days: 0,
            read_receipts: true,
            custody_enabled: false,
            group_auto_join: true,
        }
    }
}

impl ChatConfig {
    /// Whether messages are written to disk: yes unless `history_save = false`
    /// is set explicitly.
    pub fn history_saved(&self) -> bool {
        self.history_save.unwrap_or(true)
    }
}

/// `[transfer]` in `config.toml`: how a published transfer is written.
///
/// Every key has a default, so a `config.toml` written by an older version
/// (without the section) reads with the compatible object format.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TransferConfig {
    /// Which object format a new publish writes. Defaults to
    /// [`ObjectFormat::Compat`]: the output is byte-for-byte what shipped
    /// builds write, which every released build can read. [`ObjectFormat::Latest`]
    /// writes a transfer with a version-4 manifest and version-2 shares.
    /// `latest` is experimental: a transfer sent with `latest` can be received
    /// by current builds, but it is not yet registered for upkeep and
    /// replication, so it is not maintained like a default (`compat`) send,
    /// and older builds refuse it with the update message. `compat` stays the
    /// default and is what every released build can read.
    /// A publish with no manifest (a single share) is unaffected and stays on
    /// the compatible format regardless of this setting.
    #[serde(default)]
    pub object_format: ObjectFormat,
}

/// `transfer.object_format`: the object format a new publish writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectFormat {
    /// The format shipped builds write today: a version-3 manifest and
    /// version-1 shares (`ObjectSuite::Suite1`). The default.
    #[default]
    Compat,
    /// The newer format: a version-4 manifest and version-2 shares
    /// (`ObjectSuite::Suite2`, AAD-bound AES-256-GCM).
    Latest,
}

impl ObjectFormat {
    /// The object suite this format writes.
    pub fn object_suite(self) -> crate::format::ObjectSuite {
        match self {
            Self::Compat => crate::format::ObjectSuite::Suite1,
            Self::Latest => crate::format::ObjectSuite::Suite2,
        }
    }

    /// The wire word for this format, as used by the CLI and the IPC/HTTP
    /// request field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compat => "compat",
            Self::Latest => "latest",
        }
    }
}

impl std::str::FromStr for ObjectFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "compat" => Ok(Self::Compat),
            "latest" => Ok(Self::Latest),
            other => Err(format!(
                "unknown object format '{other}': expected compat or latest"
            )),
        }
    }
}

impl fmt::Display for ObjectFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod chat_config_tests {
    use super::*;

    #[test]
    fn history_is_saved_unless_switched_off_explicitly() {
        let mut cfg = NodeConfig::default();
        assert_eq!(cfg.chat.history_save, None);
        assert!(cfg.chat.history_saved());
        for stealth in [true, false] {
            cfg.privacy.stealth_mode = stealth;
            cfg.chat.history_save = None;
            assert!(cfg.chat.history_saved(), "unset, stealth {stealth}");
            cfg.chat.history_save = Some(true);
            assert!(cfg.chat.history_saved(), "true, stealth {stealth}");
            cfg.chat.history_save = Some(false);
            assert!(!cfg.chat.history_saved(), "false, stealth {stealth}");
        }
    }

    #[test]
    fn the_setting_reads_from_toml() {
        let off: NodeConfig = toml::from_str(
            "[chat]
history_save = false
",
        )
        .unwrap();
        assert!(!off.chat.history_saved());
        let unset: NodeConfig = toml::from_str(
            "[chat]
enabled = true
",
        )
        .unwrap();
        assert!(unset.chat.history_saved());
        let none: NodeConfig = toml::from_str("").unwrap();
        assert!(none.chat.history_saved());
    }

    #[test]
    fn joining_a_group_at_once_is_on_unless_switched_off_and_round_trips() {
        assert!(NodeConfig::default().chat.group_auto_join);
        // A file that never heard of the key keeps the default.
        let old: NodeConfig = toml::from_str("[chat]\nenabled = true\n").unwrap();
        assert!(old.chat.group_auto_join);
        let off: NodeConfig = toml::from_str("[chat]\ngroup_auto_join = false\n").unwrap();
        assert!(!off.chat.group_auto_join);
        // Saved and read back, both ways.
        for on in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = NodeConfig::default();
            cfg.chat.group_auto_join = on;
            cfg.save(dir.path()).unwrap();
            assert_eq!(
                NodeConfig::load(dir.path()).unwrap().chat.group_auto_join,
                on
            );
        }
    }
}

/// `[push]` in `config.toml`: where pushed files land and the limits on them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushConfig {
    /// Folder for received files (one sub-folder per contact). Empty means
    /// `<data_dir>/inbox`.
    #[serde(default)]
    pub inbox_dir: Option<String>,
    /// Largest file accepted from any contact, in bytes (default 20 GiB).
    #[serde(default = "default_push_max_file_size")]
    pub max_file_size: u64,
    /// Free space that must remain after a file is received, in bytes
    /// (default 2 GiB).
    #[serde(default = "default_push_min_free_bytes")]
    pub min_free_bytes: u64,
    /// Inbound transfers served at once (default 2).
    #[serde(default = "default_push_max_inbound")]
    pub max_concurrent_inbound: usize,
    /// Unfinished `.part` files of a transfer the sender never resumed are
    /// removed after this many days (default 7; 0 = keep them forever).
    #[serde(default = "default_push_part_retention_days")]
    pub part_retention_days: u64,
    /// How long a send keeps retrying by itself after the other side cannot be
    /// reached, in hours, counted from the last time bytes moved (default 24;
    /// 0 = never give up).
    #[serde(default = "default_push_retry_window_hours")]
    pub retry_window_hours: u64,
    /// A send that moves no byte for this many seconds is treated as a lost
    /// connection and resumed on a new one (default 30).
    #[serde(default = "default_push_stall_secs")]
    pub stall_timeout_secs: u64,
    /// Cap on the outbound rate of the file-push send loop, in KiB per second
    /// (default 0 = no cap, the previous behaviour). When non-zero, the send
    /// loop keeps its rate at or below this value; it also yields to chat by
    /// slowing down while chat traffic is in flight. This cap applies per
    /// transfer, not to the node's uplink as a whole: several transfers running
    /// at once each pace to this value independently.
    #[serde(default)]
    pub max_send_kib_per_sec: u32,
}

pub const DEFAULT_PUSH_PART_RETENTION_DAYS: u64 = 7;
pub const DEFAULT_PUSH_MAX_FILE_SIZE: u64 = 20 * 1024 * 1024 * 1024;
pub const DEFAULT_PUSH_MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_PUSH_RETRY_WINDOW_HOURS: u64 = 24;
pub const DEFAULT_PUSH_STALL_SECS: u64 = 30;
fn default_push_retry_window_hours() -> u64 {
    DEFAULT_PUSH_RETRY_WINDOW_HOURS
}
fn default_push_stall_secs() -> u64 {
    DEFAULT_PUSH_STALL_SECS
}

fn default_push_max_file_size() -> u64 {
    DEFAULT_PUSH_MAX_FILE_SIZE
}
fn default_push_min_free_bytes() -> u64 {
    DEFAULT_PUSH_MIN_FREE_BYTES
}
fn default_push_max_inbound() -> usize {
    2
}
fn default_push_part_retention_days() -> u64 {
    DEFAULT_PUSH_PART_RETENTION_DAYS
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            inbox_dir: None,
            max_file_size: DEFAULT_PUSH_MAX_FILE_SIZE,
            min_free_bytes: DEFAULT_PUSH_MIN_FREE_BYTES,
            max_concurrent_inbound: 2,
            part_retention_days: DEFAULT_PUSH_PART_RETENTION_DAYS,
            retry_window_hours: DEFAULT_PUSH_RETRY_WINDOW_HOURS,
            stall_timeout_secs: DEFAULT_PUSH_STALL_SECS,
            max_send_kib_per_sec: 0,
        }
    }
}

impl PushConfig {
    /// The inbox folder for `data_dir`.
    pub fn resolved_inbox(&self, data_dir: &Path) -> PathBuf {
        match self.inbox_dir.as_deref().map(str::trim) {
            Some(d) if !d.is_empty() => PathBuf::from(d),
            _ => crate::paths::default_push_inbox(data_dir),
        }
    }
}

pub const DEFAULT_HOSTED_QUOTA_MB: u64 = 1_024;

fn default_hosted_quota_mb() -> u64 {
    DEFAULT_HOSTED_QUOTA_MB
}

/// The sizes the Settings screen offers for keeping encrypted pieces for others, in MiB
/// (`0` = off). A value in the file that is none of these is kept as it is and shown as
/// a custom size.
pub const HOSTED_QUOTA_CHOICES_MB: [u64; 4] = [0, 256, 1_024, 5_120];

/// The hosted quota a fresh install starts with: a Microsoft Store (MSIX) install keeps
/// nothing for others until the person turns it on; every other install keeps today's
/// default.
pub fn default_hosted_quota_mb_for(packaged: bool) -> u64 {
    if packaged {
        0
    } else {
        DEFAULT_HOSTED_QUOTA_MB
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum storage for held shares, in MiB.
    pub quota_mb: u64,
    /// Maximum storage for shares hosted on behalf of remote publishers, in MiB.
    /// Kept separate from the node's owned-share quota so remote traffic cannot
    /// evict locally published shares.
    ///
    /// Defaults to `DEFAULT_HOSTED_QUOTA_MB` (also for a `config.toml` written
    /// before the key existed) so the shipped node takes part in distributed
    /// hosting. It is a hard cap, not an opt-in switch: set
    /// `miasma config --key storage.hosted_quota_mb --value 0` to refuse every
    /// pushed share, or a larger value on a helper node. Takes effect when the
    /// daemon starts. There is no eviction and no per-peer limit yet: once the
    /// quota is full, further pushes are refused.
    #[serde(default = "default_hosted_quota_mb")]
    pub hosted_quota_mb: u64,
    /// Maximum outbound bandwidth for share serving, in MiB/day.
    pub bandwidth_mb_day: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// QUIC listen multiaddr.
    pub listen_addr: String,
    /// Bootstrap peer multiaddrs.
    pub bootstrap_peers: Vec<String>,
}

/// How the iroh direct transport (receive by share ID alone) is set up.
///
/// * `n0`: the default. Number 0's public relays and its discovery service
///   (DNS/pkarr) are used, so a receiver finds the sender from the share ID
///   alone. The sender's endpoint ID, home relay and IP addresses are published
///   to n0's discovery service while the daemon runs; see SECURITY.md.
/// * `custom`: only the relays in `iroh_relay_urls` (your own), nothing of n0's
///   unless `iroh_discovery` is on.
/// * `off`: no iroh endpoint is started and none is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IrohMode {
    #[default]
    N0,
    Custom,
    Off,
}

impl IrohMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::N0 => "n0",
            Self::Custom => "custom",
            Self::Off => "off",
        }
    }
}

impl std::str::FromStr for IrohMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "n0" => Ok(Self::N0),
            "custom" => Ok(Self::Custom),
            "off" => Ok(Self::Off),
            other => Err(format!(
                "unknown iroh mode '{other}': expected n0, custom or off"
            )),
        }
    }
}

impl fmt::Display for IrohMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_true() -> bool {
    true
}

/// Seconds a receive waits to reach a sender over iroh before it tries the next
/// source.
pub const DEFAULT_IROH_CONNECT_TIMEOUT_SECS: u64 = 25;

fn default_iroh_connect_timeout_secs() -> u64 {
    DEFAULT_IROH_CONNECT_TIMEOUT_SECS
}

/// Transport-layer configuration for restrictive networks.
#[derive(Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// iroh direct transport: `n0` (default), `custom` or `off`. See
    /// [`IrohMode`]. Takes effect when the daemon starts.
    #[serde(default)]
    pub iroh_mode: IrohMode,
    /// Relay URLs (`https://...`) for `custom` mode, and extra relay hints for
    /// dialing in every mode.
    #[serde(default)]
    pub iroh_relay_urls: Vec<String>,
    /// Publish this node's address to, and look senders up in, n0's discovery
    /// service (`n0` mode always; `custom` mode if true). With it off a receiver
    /// can only reach senders through `iroh_relay_urls`.
    #[serde(default = "default_true")]
    pub iroh_discovery: bool,
    /// Path to a PEM or DER file with extra CA certificate(s) trusted for the
    /// relay's and discovery service's TLS, on top of the OS certificate store.
    /// For a network that re-signs HTTPS (TLS inspection) when the OS store
    /// cannot be read by the program. Takes effect when the daemon starts.
    #[serde(default)]
    pub iroh_extra_ca_pem: Option<String>,
    /// Announce this node on, and look senders up in, the local network (mDNS),
    /// so two machines on one LAN connect without the internet. The announcement
    /// carries the endpoint ID and the LAN addresses and is visible to the whole
    /// LAN; turn it off on a network you do not trust.
    #[serde(default = "default_true")]
    pub iroh_lan_discovery: bool,
    /// How long one receive tries to reach a sender over iroh, in seconds.
    #[serde(default = "default_iroh_connect_timeout_secs")]
    pub iroh_connect_timeout_secs: u64,
    /// Port for the WebSocket share server, on 127.0.0.1. `0` (the default)
    /// picks a free port each start. Set a fixed port to expose the server
    /// through an outbound tunnel, e.g. `cloudflared tunnel --url
    /// http://127.0.0.1:<port>`; the tunnel terminates TLS, so leave
    /// `wss_tls_enabled` off for that use.
    #[serde(default)]
    pub wss_port: u16,
    /// Enable TLS on the WSS share server and client connections.
    #[serde(default)]
    pub wss_tls_enabled: bool,
    /// SNI hostname for WSS TLS (should look like a CDN domain).
    #[serde(default)]
    pub wss_sni: Option<String>,
    /// Path to PEM-encoded server certificate for WSS TLS.
    #[serde(default)]
    pub wss_cert_pem_path: Option<String>,
    /// Path to PEM-encoded server private key for WSS TLS.
    #[serde(default)]
    pub wss_key_pem_path: Option<String>,
    /// Outbound proxy type: "socks5" or "http-connect".
    #[serde(default)]
    pub proxy_type: Option<String>,
    /// Outbound proxy address (e.g. "127.0.0.1:1080").
    #[serde(default)]
    pub proxy_addr: Option<String>,
    /// Proxy username (optional).
    #[serde(default)]
    pub proxy_username: Option<String>,
    /// Proxy password (optional).
    #[serde(default)]
    pub proxy_password: Option<String>,
    /// Enable ObfuscatedQuic REALITY transport.
    #[serde(default)]
    pub obfuscated_quic_enabled: bool,
    /// SNI for ObfuscatedQuic (e.g. "cdn.cloudflare.com").
    #[serde(default)]
    pub obfuscated_quic_sni: Option<String>,
    /// Hex-encoded 32-byte probe secret for ObfuscatedQuic.
    #[serde(default)]
    pub obfuscated_quic_secret: Option<String>,
    /// Fallback URL for ObfuscatedQuic active-probe resistance.
    #[serde(default)]
    pub obfuscated_quic_fallback_url: Option<String>,

    // ── Shadowsocks (bridge superhardening Phase 3) ─────────────────────
    /// Shadowsocks transport configuration.
    #[serde(default)]
    pub shadowsocks: crate::transport::shadowsocks::ShadowsocksConfig,

    // ── Tor (bridge superhardening Phase 4) ─────────────────────────────
    /// Tor transport configuration.
    #[serde(default)]
    pub tor: crate::transport::tor::TorConfig,

    /// Optional shaping profile above individual transports. Protocol-required
    /// padding remains active even when this is `off`.
    #[serde(default)]
    pub traffic_shape_policy: crate::cover_traffic::TrafficShapePolicy,

    /// Low-rate one-hop cover traffic carried inside the normal encrypted onion
    /// request envelope. Disabled by default for mobile/metered-network safety.
    #[serde(default)]
    pub cover_traffic: crate::cover_traffic::CoverTrafficConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            iroh_mode: IrohMode::default(),
            iroh_relay_urls: Vec::new(),
            iroh_discovery: true,
            iroh_extra_ca_pem: None,
            iroh_lan_discovery: true,
            iroh_connect_timeout_secs: DEFAULT_IROH_CONNECT_TIMEOUT_SECS,
            wss_port: 0,
            wss_tls_enabled: false,
            wss_sni: None,
            wss_cert_pem_path: None,
            wss_key_pem_path: None,
            proxy_type: None,
            proxy_addr: None,
            proxy_username: None,
            proxy_password: None,
            obfuscated_quic_enabled: false,
            obfuscated_quic_sni: None,
            obfuscated_quic_secret: None,
            obfuscated_quic_fallback_url: None,
            shadowsocks: Default::default(),
            tor: Default::default(),
            traffic_shape_policy: Default::default(),
            cover_traffic: Default::default(),
        }
    }
}

impl fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportConfig")
            .field("iroh_mode", &self.iroh_mode)
            .field("iroh_relay_urls", &self.iroh_relay_urls)
            .field("iroh_discovery", &self.iroh_discovery)
            .field("iroh_extra_ca_pem", &self.iroh_extra_ca_pem)
            .field("iroh_lan_discovery", &self.iroh_lan_discovery)
            .field("iroh_connect_timeout_secs", &self.iroh_connect_timeout_secs)
            .field("wss_port", &self.wss_port)
            .field("wss_tls_enabled", &self.wss_tls_enabled)
            .field("wss_sni", &self.wss_sni)
            .field("wss_cert_pem_path", &self.wss_cert_pem_path)
            .field("wss_key_pem_path", &self.wss_key_pem_path)
            .field("proxy_type", &self.proxy_type)
            .field("proxy_addr", &self.proxy_addr)
            .field("proxy_username_configured", &self.proxy_username.is_some())
            .field("proxy_password_configured", &self.proxy_password.is_some())
            .field("obfuscated_quic_enabled", &self.obfuscated_quic_enabled)
            .field("obfuscated_quic_sni", &self.obfuscated_quic_sni)
            .field(
                "obfuscated_quic_secret_configured",
                &self.obfuscated_quic_secret.is_some(),
            )
            .field(
                "obfuscated_quic_fallback_url",
                &self.obfuscated_quic_fallback_url,
            )
            .field("shadowsocks", &self.shadowsocks)
            .field("tor", &self.tor)
            .field("traffic_shape_policy", &self.traffic_shape_policy)
            .field("cover_traffic", &self.cover_traffic)
            .finish()
    }
}

impl TransportConfig {
    /// Parse the ObfuscatedQuic probe secret using the same fail-closed rules
    /// everywhere. Disabled transport returns `Ok(None)` without interpreting a
    /// stale configured value.
    pub fn parsed_obfuscated_quic_secret(&self) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
        if !self.obfuscated_quic_enabled {
            return Ok(None);
        }
        let hex_secret = self
            .obfuscated_quic_secret
            .as_deref()
            .ok_or_else(|| "ObfuscatedQuic enabled but probe secret is missing".to_string())?;
        let decoded = Zeroizing::new(
            hex::decode(hex_secret)
                .map_err(|_| "ObfuscatedQuic probe secret must be valid hex".to_string())?,
        );
        if decoded.len() != 32 {
            return Err("ObfuscatedQuic probe secret must be exactly 32 bytes".into());
        }
        let mut secret = Zeroizing::new([0u8; 32]);
        secret.copy_from_slice(&decoded);
        if secret.iter().all(|byte| *byte == 0) {
            return Err("ObfuscatedQuic probe secret must not be all-zero".into());
        }
        Ok(Some(secret))
    }

    fn zeroize_option_string(value: &mut Option<String>) -> bool {
        if let Some(mut secret) = value.take() {
            secret.zeroize();
            true
        } else {
            false
        }
    }

    /// Erase secret String copies held by this in-memory transport config without
    /// changing enablement semantics. Call only after runtime key material has
    /// been extracted into dedicated zeroizing state.
    pub fn zeroize_secret_copies(&mut self) {
        Self::zeroize_option_string(&mut self.proxy_username);
        Self::zeroize_option_string(&mut self.proxy_password);
        Self::zeroize_option_string(&mut self.obfuscated_quic_secret);
        Self::zeroize_option_string(&mut self.shadowsocks.password);
    }
}

impl Drop for TransportConfig {
    fn drop(&mut self) {
        self.zeroize_secret_copies();
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            quota_mb: 10_240, // 10 GiB desktop default
            hosted_quota_mb: DEFAULT_HOSTED_QUOTA_MB,
            bandwidth_mb_day: 1_024,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/udp/0/quic-v1".into(),
            bootstrap_peers: vec![],
        }
    }
}

impl NodeConfig {
    /// The settings of a fresh install. A packaged (Microsoft Store) install starts with
    /// hosting for others and self-update off; any other install is [`NodeConfig::default`].
    pub fn default_for(packaged: bool) -> Self {
        let mut c = Self::default();
        c.storage.hosted_quota_mb = default_hosted_quota_mb_for(packaged);
        if packaged {
            c.update.mode = crate::update::UpdateMode::Off;
        }
        c
    }

    /// [`NodeConfig::load`] for a given kind of install. Only a missing `config.toml` is
    /// answered with [`NodeConfig::default_for`]; a file that exists is read as written, so
    /// a value the person chose is never replaced (the one reading rule is
    /// [`PrivacyConfig::pqc_mode`]: an `off` that only the old default wrote
    /// counts as not chosen).
    pub fn load_with(data_dir: &Path, packaged: bool) -> Result<Self, MiasmaError> {
        let path = crate::paths::config_file(data_dir);
        if !path.exists() {
            return Ok(Self::default_for(packaged));
        }
        let raw = Zeroizing::new(std::fs::read_to_string(&path)?);
        let mut c: Self =
            toml::from_str(raw.as_str()).map_err(|e| MiasmaError::Serialization(e.to_string()))?;
        c.privacy.migrate_pqc_default();
        Ok(c)
    }

    /// First start of a packaged install: write the packaged defaults when there is no
    /// `config.toml` yet. Returns whether it wrote. An existing file is never touched, and
    /// nothing is written for a normal install.
    pub fn seed_first_start(data_dir: &Path, packaged: bool) -> Result<bool, MiasmaError> {
        if !packaged || crate::paths::config_file(data_dir).exists() {
            return Ok(false);
        }
        Self::default_for(true).save(data_dir)?;
        Ok(true)
    }

    pub fn load(data_dir: &Path) -> Result<Self, MiasmaError> {
        Self::load_with(data_dir, crate::update::package::is_packaged())
    }

    pub fn save(&self, data_dir: &Path) -> Result<(), MiasmaError> {
        self.transport
            .parsed_obfuscated_quic_secret()
            .map_err(|e| MiasmaError::Serialization(format!("invalid transport config: {e}")))?;
        std::fs::create_dir_all(data_dir)?;
        let path = crate::paths::config_file(data_dir);
        let raw = Zeroizing::new(
            toml::to_string_pretty(self).map_err(|e| MiasmaError::Serialization(e.to_string()))?,
        );

        // If persisted transport secrets are present, write with restricted
        // permissions from the start (Win32 DACL / Unix 0o600). If we're
        // rewriting an already-restricted config after scrubbing secrets, keep
        // using the restricted writer so Windows can safely replace it.
        let has_secrets = self.has_persisted_secrets();
        let was_restricted = if path.exists() {
            crate::secure_file::verify_restricted(&path).unwrap_or(false)
        } else {
            false
        };

        if has_secrets || was_restricted {
            // Atomic restricted write: a temp file (born with the restricted
            // DACL / 0o600) is written, then renamed over the final path so a
            // crash or a concurrent save never leaves a truncated or
            // permission-relaxed config.toml behind.
            crate::secure_file::atomic_write_restricted(&path, raw.as_bytes())?;
        } else {
            // Atomic plain write through the shared primitive: it writes a
            // uniquely named temp file in the same directory and renames it
            // into place, so a crash or a concurrent save cannot leave a
            // partially written config.toml at the final path.
            crate::secure_file::atomic_write(&path, raw.as_bytes())?;
        }
        Ok(())
    }

    /// Whether `config.toml` currently contains persisted secret material.
    /// Paths to externally managed key files are not counted here because the
    /// path itself is not the key material and may point outside the data dir.
    pub fn has_persisted_secrets(&self) -> bool {
        self.transport.proxy_username.is_some()
            || self.transport.proxy_password.is_some()
            || self.transport.obfuscated_quic_secret.is_some()
            || self.transport.shadowsocks.password.is_some()
    }

    /// Scrub persisted transport credentials/secrets from this config, then save
    /// the sanitized version back to disk.
    pub fn scrub_credentials(&mut self, data_dir: &Path) -> Result<(), MiasmaError> {
        TransportConfig::zeroize_option_string(&mut self.transport.proxy_username);
        TransportConfig::zeroize_option_string(&mut self.transport.proxy_password);
        if TransportConfig::zeroize_option_string(&mut self.transport.obfuscated_quic_secret) {
            self.transport.obfuscated_quic_enabled = false;
        }
        let shadowsocks_secret_removed =
            TransportConfig::zeroize_option_string(&mut self.transport.shadowsocks.password);
        if shadowsocks_secret_removed && self.transport.shadowsocks.server.is_some() {
            // Native Shadowsocks cannot operate after its PSK is destroyed.
            self.transport.shadowsocks.enabled = false;
        }
        self.save(data_dir)
    }
}

/// Return the default Miasma data directory.
///
/// - Linux:       `~/.local/share/miasma`
/// - macOS:       `~/Library/Application Support/miasma`
/// - Windows:     `%LOCALAPPDATA%\miasma\data` (the `data` component is added by
///   `directories::ProjectDirs::data_local_dir`; it is the local, non-roaming
///   profile, not `%APPDATA%`)
pub fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "miasma")
        .map(|d| d.data_local_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".miasma"))
}

/// Stamp the data directory with the running binary version.
///
/// Written on every startup to support future upgrade detection.
/// The file is a simple text file containing the version string.
pub fn stamp_version(data_dir: &Path, version: &str) {
    let path = crate::paths::version_stamp(data_dir);
    // Best-effort stamp written through the shared atomic primitive so the
    // file is replaced in one rename rather than truncated in place.
    let _ = crate::secure_file::atomic_write(&path, version.as_bytes());
}

/// Read the last-stamped version from the data directory.
pub fn read_stamped_version(data_dir: &Path) -> Option<String> {
    std::fs::read_to_string(crate::paths::version_stamp(data_dir))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    #[test]
    fn storage_config_defaults_to_positive_hosted_quota() {
        let storage = StorageConfig::default();
        assert_eq!(storage.hosted_quota_mb, DEFAULT_HOSTED_QUOTA_MB);
        assert!(storage.hosted_quota_mb > 0);
    }

    #[test]
    fn legacy_storage_config_gets_hosted_quota_default() {
        let storage: StorageConfig = toml::from_str(
            "quota_mb = 2048
bandwidth_mb_day = 512
",
        )
        .unwrap();
        assert_eq!(storage.quota_mb, 2_048);
        assert_eq!(storage.bandwidth_mb_day, 512);
        assert_eq!(storage.hosted_quota_mb, DEFAULT_HOSTED_QUOTA_MB);
    }

    #[test]
    fn an_old_config_without_iroh_keys_gets_the_defaults() {
        let t: TransportConfig = toml::from_str("wss_port = 7\n").unwrap();
        assert_eq!(t.wss_port, 7);
        assert_eq!(t.iroh_mode, IrohMode::N0);
        assert!(t.iroh_relay_urls.is_empty());
        assert!(t.iroh_discovery);
        assert!(t.iroh_lan_discovery);
        assert_eq!(
            t.iroh_connect_timeout_secs,
            DEFAULT_IROH_CONNECT_TIMEOUT_SECS
        );
        let d = TransportConfig::default();
        assert_eq!(d.iroh_mode, IrohMode::N0);
        assert!(d.iroh_discovery);
        assert_eq!(
            t.traffic_shape_policy,
            crate::cover_traffic::TrafficShapePolicy::Off
        );
        assert!(!t.cover_traffic.enabled);
        assert_eq!(
            d.traffic_shape_policy,
            crate::cover_traffic::TrafficShapePolicy::Off
        );
        assert!(!d.cover_traffic.enabled);
    }

    #[test]
    fn iroh_mode_parses_and_round_trips_through_toml() {
        assert_eq!("off".parse::<IrohMode>().unwrap(), IrohMode::Off);
        assert_eq!(" Custom ".parse::<IrohMode>().unwrap(), IrohMode::Custom);
        assert!("everything".parse::<IrohMode>().is_err());
        let t: TransportConfig = toml::from_str("iroh_mode = \"off\"\n").unwrap();
        assert_eq!(t.iroh_mode, IrohMode::Off);
        let text = toml::to_string_pretty(&t).unwrap();
        assert!(text.contains("iroh_mode = \"off\""), "{text}");
    }

    #[test]
    fn transport_config_debug_redacts_secrets() {
        let mut cfg = TransportConfig::default();
        cfg.proxy_username = Some("debug-user-value".into());
        cfg.proxy_password = Some("debug-password-value".into());
        cfg.obfuscated_quic_secret = Some("debug-probe-value".into());
        cfg.shadowsocks.password = Some("debug-shadow-value".into());
        let rendered = format!("{cfg:?}");
        for value in [
            "debug-user-value",
            "debug-password-value",
            "debug-probe-value",
            "debug-shadow-value",
        ] {
            assert!(!rendered.contains(value));
        }
        assert!(rendered.contains("proxy_password_configured: true"));
        assert!(rendered.contains("obfuscated_quic_secret_configured: true"));
    }
}

#[cfg(test)]
mod store_install_tests {
    use super::*;
    use crate::update::UpdateMode;

    fn read_hosted(dir: &Path) -> u64 {
        NodeConfig::load_with(dir, false)
            .unwrap()
            .storage
            .hosted_quota_mb
    }

    #[test]
    fn a_packaged_fresh_install_keeps_nothing_for_others_and_does_not_self_update() {
        let c = NodeConfig::default_for(true);
        assert_eq!(c.storage.hosted_quota_mb, 0);
        assert_eq!(c.update.mode, UpdateMode::Off);
    }

    #[test]
    fn a_normal_fresh_install_keeps_todays_defaults() {
        let c = NodeConfig::default_for(false);
        assert_eq!(c.storage.hosted_quota_mb, DEFAULT_HOSTED_QUOTA_MB);
        assert_eq!(c.update.mode, UpdateMode::Notify);
        assert_eq!(
            c.storage.hosted_quota_mb,
            NodeConfig::default().storage.hosted_quota_mb
        );
    }

    #[test]
    fn the_choices_include_off_and_todays_default() {
        assert_eq!(HOSTED_QUOTA_CHOICES_MB[0], 0);
        assert!(HOSTED_QUOTA_CHOICES_MB.contains(&DEFAULT_HOSTED_QUOTA_MB));
        assert!(HOSTED_QUOTA_CHOICES_MB.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn first_start_writes_the_packaged_defaults_once() {
        let d = tempfile::tempdir().unwrap();
        assert!(NodeConfig::seed_first_start(d.path(), true).unwrap());
        assert!(crate::paths::config_file(d.path()).exists());
        // The file is read back as written, also by a loader that says "normal install".
        assert_eq!(read_hosted(d.path()), 0);
        let back = NodeConfig::load_with(d.path(), false).unwrap();
        assert_eq!(back.update.mode, UpdateMode::Off);
        // A second start writes nothing.
        assert!(!NodeConfig::seed_first_start(d.path(), true).unwrap());
    }

    #[test]
    fn a_normal_install_writes_nothing_at_first_start() {
        let d = tempfile::tempdir().unwrap();
        assert!(!NodeConfig::seed_first_start(d.path(), false).unwrap());
        assert!(!crate::paths::config_file(d.path()).exists());
    }

    #[test]
    fn first_start_never_replaces_an_existing_choice() {
        let d = tempfile::tempdir().unwrap();
        let mut c = NodeConfig::default();
        c.storage.hosted_quota_mb = 5_120;
        c.update.mode = UpdateMode::Auto;
        c.save(d.path()).unwrap();
        assert!(!NodeConfig::seed_first_start(d.path(), true).unwrap());
        // Loading as packaged reads the file as written too.
        let back = NodeConfig::load_with(d.path(), true).unwrap();
        assert_eq!(back.storage.hosted_quota_mb, 5_120);
        assert_eq!(back.update.mode, UpdateMode::Auto);
    }

    #[test]
    fn an_explicit_zero_or_default_value_survives_both_kinds_of_loader() {
        for explicit in [0, DEFAULT_HOSTED_QUOTA_MB] {
            let d = tempfile::tempdir().unwrap();
            let mut c = NodeConfig::default();
            c.storage.hosted_quota_mb = explicit;
            c.save(d.path()).unwrap();
            for packaged in [false, true] {
                let back = NodeConfig::load_with(d.path(), packaged).unwrap();
                assert_eq!(
                    back.storage.hosted_quota_mb, explicit,
                    "packaged={packaged}"
                );
            }
        }
    }

    #[test]
    fn a_packaged_choice_made_later_persists() {
        let d = tempfile::tempdir().unwrap();
        NodeConfig::seed_first_start(d.path(), true).unwrap();
        let mut c = NodeConfig::load_with(d.path(), true).unwrap();
        c.storage.hosted_quota_mb = 256;
        c.save(d.path()).unwrap();
        assert_eq!(
            NodeConfig::load_with(d.path(), true)
                .unwrap()
                .storage
                .hosted_quota_mb,
            256
        );
        assert!(!NodeConfig::seed_first_start(d.path(), true).unwrap());
        assert_eq!(read_hosted(d.path()), 256);
    }
}

#[cfg(test)]
mod pqc_default_tests {
    use super::*;

    /// The shape of `[privacy]` as the previous release wrote it: the mode is a
    /// plain value, so every save carried it, chosen or not.
    #[derive(Serialize)]
    struct LegacyPrivacy {
        stealth_mode: bool,
        diagnostic_logging: bool,
        log_buffer_mib: u32,
        old_logs_notice_shown: bool,
        old_logs_keep: bool,
        pqc_mode: PqcMode,
    }

    #[derive(Serialize)]
    struct LegacyNode {
        privacy: LegacyPrivacy,
    }

    fn legacy_file(dir: &Path, mode: PqcMode) {
        let old = LegacyNode {
            privacy: LegacyPrivacy {
                stealth_mode: true,
                diagnostic_logging: false,
                log_buffer_mib: 2,
                old_logs_notice_shown: false,
                old_logs_keep: false,
                pqc_mode: mode,
            },
        };
        let text = toml::to_string_pretty(&old).unwrap();
        assert!(text.contains(&format!("pqc_mode = \"{mode}\"")), "{text}");
        assert!(!text.contains("pqc_default_version"), "{text}");
        std::fs::write(crate::paths::config_file(dir), text).unwrap();
    }

    #[test]
    fn the_default_is_require_and_is_not_written_to_the_file() {
        assert_eq!(PqcMode::default(), PqcMode::Require);
        let c = NodeConfig::default();
        assert_eq!(c.privacy.pqc_mode, None);
        assert_eq!(c.privacy.pqc_mode(), PqcMode::Require);
        let dir = tempfile::tempdir().unwrap();
        c.save(dir.path()).unwrap();
        let text = std::fs::read_to_string(crate::paths::config_file(dir.path())).unwrap();
        assert!(!text.contains("pqc_mode = "), "{text}");
        assert!(text.contains("pqc_default_version = 2"), "{text}");
        let back = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(back.privacy.pqc_mode(), PqcMode::Require);
    }

    #[test]
    fn only_off_and_prefer_allow_a_classical_fallback() {
        // `require` holds the message back for a contact that cannot do the
        // hybrid exchange; `off` and `prefer` let it fall back to a classical
        // session. The status surfaces warn on exactly the latter two.
        assert!(!PqcMode::Require.allows_classical_fallback());
        assert!(PqcMode::Off.allows_classical_fallback());
        assert!(PqcMode::Prefer.allows_classical_fallback());
    }

    #[test]
    fn an_old_file_with_the_old_default_reads_as_never_chosen() {
        let dir = tempfile::tempdir().unwrap();
        legacy_file(dir.path(), PqcMode::Off);
        let c = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(c.privacy.pqc_mode, None);
        assert_eq!(c.privacy.pqc_mode(), PqcMode::Require);
        // A file from before the key existed reads the same way.
        std::fs::write(
            crate::paths::config_file(dir.path()),
            "[privacy]\nstealth_mode = true\n",
        )
        .unwrap();
        assert_eq!(
            NodeConfig::load(dir.path()).unwrap().privacy.pqc_mode(),
            PqcMode::Require
        );
    }

    #[test]
    fn an_old_file_with_require_keeps_it() {
        // `require` is the current default; a version-`0` file that already
        // held it stays on it (and is moved up to the current version).
        let dir = tempfile::tempdir().unwrap();
        legacy_file(dir.path(), PqcMode::Require);
        let c = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(c.privacy.pqc_mode, Some(PqcMode::Require));
        assert_eq!(c.privacy.pqc_mode(), PqcMode::Require);
        assert_eq!(c.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
    }

    /// The owner's real file: a version-`0` `[privacy]` that carries only
    /// `pqc_mode = "prefer"` (no `pqc_default_version` key). `prefer` was the
    /// standard choice in the pre-beta.12 screen, so beta.12 reads it as the
    /// old default carried over and moves it to `require`, leaving no silent
    /// classical fallback.
    #[test]
    fn a_version_0_prefer_moves_to_require() {
        let dir = tempfile::tempdir().unwrap();
        legacy_file(dir.path(), PqcMode::Prefer);
        // The file is the owner's shape: `pqc_mode` present, version key absent.
        let text = std::fs::read_to_string(crate::paths::config_file(dir.path())).unwrap();
        assert!(text.contains("pqc_mode = \"prefer\""), "{text}");
        assert!(!text.contains("pqc_default_version"), "{text}");
        let c = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(c.privacy.pqc_mode, Some(PqcMode::Require));
        assert_eq!(c.privacy.pqc_mode(), PqcMode::Require);
        assert!(!c.privacy.pqc_mode().allows_classical_fallback());
        assert_eq!(c.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
    }

    /// A version-`1` file (default `prefer`) that recorded `prefer` is still
    /// the carried-over old default, not an advanced choice, so beta.12 moves
    /// it to `require` as well.
    #[test]
    fn a_version_1_prefer_moves_to_require() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            crate::paths::config_file(dir.path()),
            "[privacy]\nstealth_mode = true\npqc_mode = \"prefer\"\npqc_default_version = 1\n",
        )
        .unwrap();
        let c = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(c.privacy.pqc_mode, Some(PqcMode::Require));
        assert_eq!(c.privacy.pqc_mode(), PqcMode::Require);
        assert!(!c.privacy.pqc_mode().allows_classical_fallback());
        assert_eq!(c.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
    }

    /// A `prefer` set at version `2` or later is an explicit advanced choice,
    /// not a carried-over default, so it is kept; the status then warns about
    /// the classical fallback it allows. A version-`2` `require` is kept too.
    #[test]
    fn a_version_2_prefer_or_require_is_kept() {
        for mode in [PqcMode::Prefer, PqcMode::Require] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                crate::paths::config_file(dir.path()),
                format!(
                    "[privacy]\nstealth_mode = true\npqc_mode = \"{mode}\"\npqc_default_version = 2\n"
                ),
            )
            .unwrap();
            let c = NodeConfig::load(dir.path()).unwrap();
            assert_eq!(c.privacy.pqc_mode, Some(mode));
            assert_eq!(c.privacy.pqc_mode(), mode);
            assert_eq!(c.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
        }
        // The kept `prefer` is one the status warns about (classical fallback).
        assert!(PqcMode::Prefer.allows_classical_fallback());
    }

    /// Reading the owner's version-`0` `prefer` file, saving it, and reading it
    /// again must not migrate a second time: the first read moves it to
    /// `require` at version `2`, and the second read leaves that `require`
    /// alone (idempotent).
    #[test]
    fn the_prefer_migration_runs_once() {
        let dir = tempfile::tempdir().unwrap();
        legacy_file(dir.path(), PqcMode::Prefer);
        // First read: carried-over `prefer` becomes `require` at version 2.
        let c = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(c.privacy.pqc_mode, Some(PqcMode::Require));
        assert_eq!(c.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
        c.save(dir.path()).unwrap();
        let text = std::fs::read_to_string(crate::paths::config_file(dir.path())).unwrap();
        assert!(text.contains("pqc_default_version = 2"), "{text}");
        // Second read (and a further save) keep the same `require`.
        for _ in 0..2 {
            let back = NodeConfig::load(dir.path()).unwrap();
            assert_eq!(back.privacy.pqc_mode, Some(PqcMode::Require));
            assert_eq!(back.privacy.pqc_mode(), PqcMode::Require);
            assert_eq!(back.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
            back.save(dir.path()).unwrap();
        }
    }

    #[test]
    fn a_choice_of_off_made_after_the_change_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        legacy_file(dir.path(), PqcMode::Off);
        // The migration is only in memory until something saves; the choice
        // goes through the same persistent setter the programs use.
        set_pqc_mode_persistent(dir.path(), PqcMode::Off).unwrap();
        let text = std::fs::read_to_string(crate::paths::config_file(dir.path())).unwrap();
        assert!(text.contains("pqc_mode = \"off\""), "{text}");
        assert!(text.contains("pqc_default_version = 2"), "{text}");
        for _ in 0..2 {
            let c = NodeConfig::load(dir.path()).unwrap();
            assert_eq!(c.privacy.pqc_mode, Some(PqcMode::Off));
            assert_eq!(c.privacy.pqc_mode(), PqcMode::Off);
            c.save(dir.path()).unwrap();
        }
    }

    /// A file written by a version-`1` build (default `prefer`) with an
    /// explicit `off` must keep that `off` when a version-`2` build reads it:
    /// `off` was never a version-`1` default, so it was a choice, not a
    /// carried-over default. The kept value still allows a classical fallback,
    /// so the status is expected to warn about it (see
    /// `PqcMode::allows_classical_fallback`).
    #[test]
    fn an_explicit_off_written_at_version_1_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        // A version-`1` file: the version key is present and set to 1, with an
        // explicit `off`. Written directly because no current build emits
        // version 1 any more.
        std::fs::write(
            crate::paths::config_file(dir.path()),
            "[privacy]\nstealth_mode = true\npqc_mode = \"off\"\npqc_default_version = 1\n",
        )
        .unwrap();
        let c = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(c.privacy.pqc_mode, Some(PqcMode::Off));
        assert_eq!(c.privacy.pqc_mode(), PqcMode::Off);
        // The kept value is one the status warns about (classical fallback).
        assert!(c.privacy.pqc_mode().allows_classical_fallback());
        // The file is moved up to the current version but the choice stays.
        assert_eq!(c.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
    }

    #[test]
    fn a_later_save_by_another_setting_writes_the_marker_without_choosing() {
        let dir = tempfile::tempdir().unwrap();
        legacy_file(dir.path(), PqcMode::Off);
        let mut c = NodeConfig::load(dir.path()).unwrap();
        c.privacy.diagnostic_logging = true;
        c.save(dir.path()).unwrap();
        let back = NodeConfig::load(dir.path()).unwrap();
        assert!(back.privacy.diagnostic_logging);
        assert_eq!(back.privacy.pqc_mode, None);
        assert_eq!(back.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
        assert_eq!(back.privacy.pqc_mode(), PqcMode::Require);
    }

    #[test]
    fn a_choice_with_no_file_yet_creates_one_and_is_kept() {
        // A fresh install with no config.toml: the choice from the screen must
        // persist rather than fail silently.
        for mode in [PqcMode::Off, PqcMode::Require] {
            let dir = tempfile::tempdir().unwrap();
            assert!(
                !crate::paths::config_file(dir.path()).exists(),
                "no file to start with"
            );
            set_pqc_mode_persistent(dir.path(), mode).unwrap();
            assert!(
                crate::paths::config_file(dir.path()).exists(),
                "the setter created the file"
            );
            let back = NodeConfig::load(dir.path()).unwrap();
            assert_eq!(back.privacy.pqc_mode, Some(mode));
            assert_eq!(back.privacy.pqc_mode(), mode);
            assert_eq!(back.privacy.pqc_default_version, PQC_DEFAULT_VERSION);
        }
    }

    #[test]
    fn a_damaged_file_is_an_error_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::paths::config_file(dir.path());
        let damaged = "[privacy\nstealth_mode = ";
        std::fs::write(&path, damaged).unwrap();
        let err = set_pqc_mode_persistent(dir.path(), PqcMode::Off).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // The damaged file is left exactly as it was: not replaced by defaults.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), damaged);
    }

    /// A freshly generated, non-fixed secret value for tests. Generated at
    /// runtime so no fixed credential is written into the source.
    fn random_secret() -> String {
        hex::encode(rand::random::<[u8; 16]>())
    }

    #[test]
    fn a_plain_save_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = NodeConfig::default();
        cfg.save(dir.path()).unwrap();
        let path = crate::paths::config_file(dir.path());
        assert!(path.exists(), "the config file was written");
        assert!(
            !crate::paths::atomic_tmp(&path).exists(),
            "the plain temp file was renamed away, not left behind"
        );
        assert!(
            !crate::paths::atomic_secure_tmp(&path).exists(),
            "no restricted temp file for a secret-free config"
        );
    }

    #[test]
    fn a_secret_save_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = NodeConfig::default();
        cfg.transport.proxy_password = Some(random_secret());
        cfg.save(dir.path()).unwrap();
        let path = crate::paths::config_file(dir.path());
        assert!(path.exists(), "the config file was written");
        assert!(
            !crate::paths::atomic_secure_tmp(&path).exists(),
            "the restricted temp file was renamed away, not left behind"
        );
        assert!(
            !crate::paths::atomic_tmp(&path).exists(),
            "no plain temp file on the restricted path"
        );
    }

    #[test]
    fn a_config_with_a_secret_round_trips_through_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let secret = random_secret();
        let mut cfg = NodeConfig::default();
        cfg.transport.proxy_password = Some(secret.clone());
        cfg.save(dir.path()).unwrap();
        let back = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(
            back.transport.proxy_password.as_deref(),
            Some(secret.as_str())
        );
    }

    /// A save that cannot complete must not damage the config that is already
    /// on disk: the temp-file + rename approach means the final path keeps its
    /// previous, valid contents. Unix-only because it forces the failure by
    /// dropping write permission on the directory, which is a no-op on Windows.
    #[cfg(unix)]
    #[test]
    fn a_failed_save_does_not_corrupt_the_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut cfg = NodeConfig::default();
        cfg.push.max_send_kib_per_sec = 111;
        cfg.save(dir.path()).unwrap();
        let path = crate::paths::config_file(dir.path());
        let before = std::fs::read_to_string(&path).unwrap();

        // Drop write permission on the directory so creating the temp file
        // fails. The pre-existing config.toml stays intact.
        let ro = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(dir.path(), ro).unwrap();

        let mut cfg2 = cfg.clone();
        cfg2.push.max_send_kib_per_sec = 222;
        let result = cfg2.save(dir.path());

        // Restore permission before any assertion so the tempdir can clean up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(result.is_err(), "the save could not complete");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, before, "the existing config was left untouched");
        assert!(
            !crate::paths::atomic_tmp(&path).exists(),
            "no temp file left behind after the failure"
        );
    }

    /// Windows counterpart of the failure test. The Unix version forces the
    /// failure by dropping directory permissions, which is a no-op on Windows,
    /// so this drives the same guarantee through a failure Windows can produce:
    /// a save whose data directory cannot be created because an ancestor path
    /// is a regular file. The config that was already saved elsewhere must be
    /// left intact and no temp file may be left behind.
    #[cfg(windows)]
    #[test]
    fn a_failed_save_on_windows_does_not_corrupt_the_existing_file() {
        let base = tempfile::tempdir().unwrap();

        // A good data dir with a valid config already on disk.
        let good = base.path().join("good");
        let mut cfg = NodeConfig::default();
        cfg.push.max_send_kib_per_sec = 111;
        cfg.save(&good).unwrap();
        let path = crate::paths::config_file(&good);
        let before = std::fs::read_to_string(&path).unwrap();

        // A plain file that will stand in for a directory component.
        let blocker = base.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();

        // Saving under a path whose parent is that regular file cannot create
        // the data directory, so the save fails before writing anything.
        let doomed = blocker.join("sub");
        let mut cfg2 = cfg.clone();
        cfg2.push.max_send_kib_per_sec = 222;
        let result = cfg2.save(&doomed);

        assert!(result.is_err(), "the save could not complete");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, before, "the existing config was left untouched");
        assert!(
            !crate::paths::config_file(&doomed).exists(),
            "no config was written at the doomed path"
        );
    }
}

#[cfg(test)]
mod push_send_rate_config_tests {
    use super::*;

    #[test]
    fn the_send_rate_cap_defaults_to_zero() {
        assert_eq!(PushConfig::default().max_send_kib_per_sec, 0);
        assert_eq!(NodeConfig::default().push.max_send_kib_per_sec, 0);
    }

    #[test]
    fn an_old_push_section_without_the_key_reads_as_zero() {
        // A file written before the key existed keeps the no-cap default.
        let c: NodeConfig = toml::from_str("[push]\nstall_timeout_secs = 45\n").unwrap();
        assert_eq!(c.push.stall_timeout_secs, 45);
        assert_eq!(c.push.max_send_kib_per_sec, 0);
        // An empty file reads the same way.
        let none: NodeConfig = toml::from_str("").unwrap();
        assert_eq!(none.push.max_send_kib_per_sec, 0);
    }

    #[test]
    fn the_send_rate_cap_reads_from_toml() {
        let c: NodeConfig = toml::from_str("[push]\nmax_send_kib_per_sec = 512\n").unwrap();
        assert_eq!(c.push.max_send_kib_per_sec, 512);
    }

    #[test]
    fn the_send_rate_cap_round_trips_through_save_and_load() {
        for cap in [0u32, 256, 8_192] {
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = NodeConfig::default();
            cfg.push.max_send_kib_per_sec = cap;
            cfg.save(dir.path()).unwrap();
            assert_eq!(
                NodeConfig::load(dir.path())
                    .unwrap()
                    .push
                    .max_send_kib_per_sec,
                cap
            );
        }
    }
}

#[cfg(test)]
mod transfer_object_format_tests {
    use super::*;

    // transfer.object_format: the writer picks the object format; compat
    // (default) stays byte-compatible on Suite1, latest selects Suite2.
    #[test]
    fn the_object_format_defaults_to_compat() {
        // A fresh config, and a file with no [transfer] section, both read as
        // compat — the byte-for-byte format shipped builds write.
        assert_eq!(
            TransferConfig::default().object_format,
            ObjectFormat::Compat
        );
        assert_eq!(
            NodeConfig::default().transfer.object_format,
            ObjectFormat::Compat
        );
        let none: NodeConfig = toml::from_str("").unwrap();
        assert_eq!(none.transfer.object_format, ObjectFormat::Compat);
    }

    #[test]
    fn the_object_format_reads_from_toml() {
        let c: NodeConfig = toml::from_str("[transfer]\nobject_format = \"latest\"\n").unwrap();
        assert_eq!(c.transfer.object_format, ObjectFormat::Latest);
        let c: NodeConfig = toml::from_str("[transfer]\nobject_format = \"compat\"\n").unwrap();
        assert_eq!(c.transfer.object_format, ObjectFormat::Compat);
    }

    #[test]
    fn an_old_transfer_section_without_the_key_reads_as_compat() {
        // A [transfer] table written before the key existed keeps the compat
        // default rather than failing to parse.
        let c: NodeConfig = toml::from_str("[transfer]\n").unwrap();
        assert_eq!(c.transfer.object_format, ObjectFormat::Compat);
    }

    #[test]
    fn the_object_format_round_trips_through_toml() {
        for fmt in [ObjectFormat::Compat, ObjectFormat::Latest] {
            let cfg = TransferConfig { object_format: fmt };
            let text = toml::to_string_pretty(&cfg).unwrap();
            assert!(
                text.contains(&format!("object_format = \"{}\"", fmt.as_str())),
                "{text}"
            );
            let back: TransferConfig = toml::from_str(&text).unwrap();
            assert_eq!(back.object_format, fmt);
        }
    }

    #[test]
    fn the_object_format_round_trips_through_save_and_load() {
        for fmt in [ObjectFormat::Compat, ObjectFormat::Latest] {
            let dir = tempfile::tempdir().unwrap();
            let mut cfg = NodeConfig::default();
            cfg.transfer.object_format = fmt;
            cfg.save(dir.path()).unwrap();
            assert_eq!(
                NodeConfig::load(dir.path()).unwrap().transfer.object_format,
                fmt
            );
        }
    }

    #[test]
    fn each_object_format_selects_its_object_suite() {
        // compat stays on Suite1 (the shipped, byte-compatible wire format);
        // latest selects Suite2. This is what the publish path branches on.
        assert_eq!(
            ObjectFormat::Compat.object_suite(),
            crate::format::ObjectSuite::Suite1
        );
        assert_eq!(
            ObjectFormat::Latest.object_suite(),
            crate::format::ObjectSuite::Suite2
        );
    }

    #[test]
    fn the_object_format_wire_word_round_trips() {
        for fmt in [ObjectFormat::Compat, ObjectFormat::Latest] {
            assert_eq!(fmt.as_str().parse::<ObjectFormat>().unwrap(), fmt);
        }
        assert!("gibberish".parse::<ObjectFormat>().is_err());
    }

    // The `transfer` field carries a default, so a NodeConfig built field by
    // field (as the init paths in the CLI, the mobile bridge and the desktop
    // worker do) equals the all-defaults config, and the key is optional for a
    // config file written before it existed.
    #[test]
    fn the_default_node_config_has_the_compat_transfer_section() {
        let c = NodeConfig::default();
        assert_eq!(c.transfer, TransferConfig::default());
        assert_eq!(c.transfer.object_format, ObjectFormat::Compat);
    }

    #[test]
    fn a_node_config_file_without_a_transfer_section_reads_as_compat() {
        // A whole config.toml from before the [transfer] section existed still
        // parses, and the missing section reads as the compat default.
        let c: NodeConfig = toml::from_str("[chat]\nenabled = true\n").unwrap();
        assert_eq!(c.transfer, TransferConfig::default());
        assert_eq!(c.transfer.object_format, ObjectFormat::Compat);
    }
}
