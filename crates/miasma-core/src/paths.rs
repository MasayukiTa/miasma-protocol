//! Persisted-paths registry.
//!
//! The single place that **names** everything the product may create on disk,
//! in the temp directory, or in the Windows registry. Every entry says what the
//! thing is for, how sensitive its content is, how a wipe removes it, and
//! whether it is meant to be encrypted at rest.
//!
//! Code that needs one of these locations takes the name from here instead of
//! spelling it out, and a lint (`tests/persisted_paths_lint.rs`) fails when new
//! code writes files outside an explicit allow-list or respells a registered
//! name. Iterating [`REGISTRY`] gives the complete list of what the product can
//! leave behind, so a cleanup that walks it cannot forget a path.
//!
//! The [`PathSpec::inventory`] field is a short label that groups entries by
//! kind of artifact (D = data directory, T = temp, R = registry, A = Android).

use std::path::{Path, PathBuf};

/// What kind of object an entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One regular file with a fixed name.
    File,
    /// One directory with a fixed name (the name may be a `/`-separated
    /// relative path below its [`Location`]).
    Dir,
    /// A family of files; `name` contains a `*` standing for the variable part.
    Pattern,
    /// A rolling log: files are `<name>.<date>` (as `tracing_appender` writes).
    RollingLog,
    /// A Windows registry key (name is relative to its hive).
    RegistryKey,
}

/// Where the object lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// Directly under the node data directory.
    DataDir,
    /// Under the data directory unless the user configured another folder
    /// (`push.inbox_dir`).
    DataDirOrConfigured,
    /// Under the bridge's own data directory (a different default location
    /// from the daemon's).
    BridgeDataDir,
    /// Inside the bridge's user-chosen inbox directory.
    BridgeInbox,
    /// The operating system temp directory.
    OsTemp,
    /// A path the user picked (Save As, `-o`, a custom folder, `$MIASMA_UI_SNAP`).
    UserChosen,
    /// `HKEY_CURRENT_USER`.
    RegistryHkcu,
    /// `HKEY_LOCAL_MACHINE` (installer-managed; the app cannot remove it).
    RegistryHklm,
}

/// Sensitivity of the content (not of the name: almost every name reveals
/// that Miasma was used).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Key material or a credential.
    Secret,
    /// Application state that describes what the user did or who they know.
    State,
    /// Plaintext user content (received files, downloads, exports).
    UserVisible,
    /// Process coordination (locks, ports, hand-off files); no lasting content.
    Runtime,
    /// Logs and diagnostics.
    Diagnostic,
    /// Not a product artifact in the sense of content (shell registration etc.).
    Integration,
}

/// What is meant to happen to the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Treatment {
    /// To be encrypted at rest under a key derived from the master key.
    Encrypt,
    /// Must stay as it is (already ciphertext, or needed before any key exists).
    Plain,
    /// May be left unwritten when the user asks for a trace-free run.
    Skippable,
    /// Plaintext the user must be able to open; tracked in the saved-file ledger.
    Ledger,
    /// Created by the installer or the OS; the app does not control it.
    External,
}

/// How the emergency wipe removes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WipeMethod {
    /// Destroy the master key (makes encrypted items unreadable), then overwrite
    /// with random bytes and unlink.
    CryptoEraseOverwriteRemove,
    /// Overwrite once with random bytes, then unlink.
    OverwriteRemove,
    /// Unlink / remove the directory.
    Remove,
    /// Delete through the registry API.
    RegistryDelete,
    /// Overwrite and unlink the files named in the saved-file ledger.
    LedgerOverwriteRemove,
    /// Not removable by the app (installer / OS state); reported as such.
    NotRemovable,
}

/// One persisted object.
#[derive(Debug, Clone, Copy)]
pub struct PathSpec {
    /// Stable identifier (also the constant's name, lower case).
    pub id: &'static str,
    /// File or directory name (relative path below the location for `Dir`,
    /// `/` separated), pattern, log prefix, or registry key.
    pub name: &'static str,
    pub kind: Kind,
    pub location: Location,
    /// What it is for.
    pub purpose: &'static str,
    pub class: Class,
    pub treatment: Treatment,
    pub wipe: WipeMethod,
    /// Short label grouping the entry by kind of artifact.
    pub inventory: &'static str,
}

impl PathSpec {
    /// True when the content is meant to be encrypted at rest.
    pub const fn encrypted_later(&self) -> bool {
        matches!(self.treatment, Treatment::Encrypt)
    }

    /// The path of a `File` or `Dir` entry below `base`.
    ///
    /// For a `Dir` whose name is a relative path (`directed/incoming`) every
    /// component is joined in turn. Using this on a pattern, log or registry
    /// entry is a programming error (checked in debug builds).
    pub fn in_dir(&self, base: &Path) -> PathBuf {
        debug_assert!(
            matches!(self.kind, Kind::File | Kind::Dir),
            "in_dir() on non-file entry {}",
            self.id
        );
        let mut p = base.to_path_buf();
        for part in self.name.split('/') {
            p.push(part);
        }
        p
    }

    /// For a [`Kind::RollingLog`]: the glob that matches its files.
    pub fn log_glob(&self, base: &Path) -> PathBuf {
        debug_assert!(matches!(self.kind, Kind::RollingLog));
        base.join(format!("{}.*", self.name))
    }

    /// For a registry entry: the key as `reg.exe` and the Win32 API spell it
    /// (`HKCU\...`).
    pub fn registry_path(&self) -> String {
        let hive = match self.location {
            Location::RegistryHklm => "HKLM",
            _ => "HKCU",
        };
        format!(r"{hive}\{}", self.name)
    }
}

macro_rules! spec {
    ($id:ident, $name:expr, $kind:ident, $loc:ident, $class:ident, $treat:ident, $wipe:ident,
     $inv:expr, $purpose:expr) => {
        pub const $id: PathSpec = PathSpec {
            id: stringify!($id),
            name: $name,
            kind: Kind::$kind,
            location: Location::$loc,
            purpose: $purpose,
            class: Class::$class,
            treatment: Treatment::$treat,
            wipe: WipeMethod::$wipe,
            inventory: $inv,
        };
    };
}

// ── Data directory: secrets ─────────────────────────────────────────────────

spec!(
    MASTER_KEY,
    "master.key",
    File,
    DataDir,
    Secret,
    Plain,
    OverwriteRemove,
    "D1",
    "32-byte master key; identity and every state key derive from it. First thing destroyed."
);
spec!(
    MASTER_KEY_WRAPPED,
    "master.key.enc",
    File,
    DataDir,
    Secret,
    Plain,
    OverwriteRemove,
    "A1",
    "Platform-wrapped (Android Keystore) copy of the master key."
);
spec!(
    MASTER_KEY_WRAP_IV,
    "master.key.iv",
    File,
    DataDir,
    Secret,
    Plain,
    OverwriteRemove,
    "A1",
    "IV belonging to master.key.enc."
);
spec!(
    DAEMON_TOKEN,
    "daemon.token",
    File,
    DataDir,
    Secret,
    Plain,
    OverwriteRemove,
    "D7",
    "Local control credential the CLI reads before it can talk to the daemon."
);

// ── Data directory: state ───────────────────────────────────────────────────

spec!(
    CONFIG,
    "config.toml",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D2",
    "Node configuration (may hold transport secrets, proxy credentials, chosen paths)."
);
spec!(
    VERSION_STAMP,
    "version",
    File,
    DataDir,
    State,
    Skippable,
    Remove,
    "D3",
    "Version of the binary that last started (upgrade detection)."
);
spec!(
    STORE_INDEX,
    "store_index.json",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D4",
    "Index of stored shares: content address, size, last access, origin, hosted principal."
);
spec!(
    SHARES_DIR,
    "shares",
    Dir,
    DataDir,
    State,
    Plain,
    CryptoEraseOverwriteRemove,
    "D5",
    "Directory of share blobs (already XChaCha20-Poly1305 encrypted per file)."
);
spec!(
    SHARE_BLOB,
    "shares/*.ms",
    Pattern,
    DataDir,
    State,
    Plain,
    CryptoEraseOverwriteRemove,
    "D5",
    "One encrypted share; the file name is the content address."
);
spec!(
    REPLICATION_WAL,
    "replication_wal.jsonl",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D6",
    "Replication write-ahead log: DHT records and shard locations."
);
spec!(
    REPLICATION_WAL_TMP,
    "replication_wal.jsonl.tmp",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D6",
    "Compaction copy of the replication WAL (renamed over the original)."
);
spec!(
    DESKTOP_PREFS,
    "desktop-prefs.toml",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D12",
    "Desktop UI preferences: mode, theme, locale."
);
spec!(
    CONTACTS,
    "contacts.json",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D13",
    "Contacts: labels, iroh endpoint ids, permissions (the social graph)."
);
spec!(
    CONTACTS_CORRUPT,
    "contacts.json.corrupt-*",
    Pattern,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D13",
    "Unreadable contacts file set aside by the loader."
);
spec!(
    PUSH_HISTORY,
    "push_history.jsonl",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D14",
    "Send/receive history: names, sizes, contact labels, saved-as paths."
);
spec!(
    PUSH_HISTORY_TMP,
    "push_history.jsonl.tmp",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D14",
    "Trim copy of the history file (renamed over the original)."
);
spec!(
    TRANSFERS_DIR,
    "transfers",
    Dir,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D17",
    "Directory of transfer journals."
);
spec!(
    RECV_JOURNAL,
    "transfers/recv-*.json",
    Pattern,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D17",
    "Receive journal: output path, part path, MID, segment progress."
);
spec!(
    SEND_JOURNAL,
    "transfers/send-*.jsonl",
    Pattern,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D17",
    "Publish journal: source file path, size, mtime, MID, per-segment records."
);
spec!(
    DIRECTED_DIR,
    "directed",
    Dir,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D18",
    "Directed-share envelopes."
);
spec!(
    DIRECTED_INCOMING,
    "directed/incoming",
    Dir,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D18",
    "Incoming envelopes (<id>.json) and their .challenge / .peer sidecars."
);
spec!(
    DIRECTED_OUTGOING,
    "directed/outgoing",
    Dir,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D18",
    "Outgoing envelopes (<id>.json) and their .peer sidecars."
);

spec!(
    CHAT_DIR,
    "chat",
    Dir,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D27",
    "Directory of chat state: per-contact sessions and history, and the outbox."
);
spec!(
    CHAT_SESSION,
    "chat/*.sess",
    Pattern,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D27",
    "Chat session of one contact: ratchet keys, delivery counters, summary (file name is a keyed hash)."
);
spec!(
    CHAT_HISTORY,
    "chat/*.msgs",
    Pattern,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D27",
    "Chat messages of one contact (encrypted record log; absent in ephemeral mode)."
);
spec!(
    CHAT_OUTBOX,
    "chat/outbox.log",
    File,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D27",
    "Chat messages waiting to be delivered."
);
spec!(
    CHAT_TMP,
    "chat/*.tmp",
    Pattern,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D27",
    "Replacement copy of a chat log while it is rewritten (trim, delete, compaction)."
);

// ── Data directory: runtime coordination ────────────────────────────────────

spec!(
    DAEMON_PORT,
    "daemon.port",
    File,
    DataDir,
    Runtime,
    Plain,
    Remove,
    "D8",
    "IPC port of the running daemon (discovery)."
);
spec!(
    DAEMON_HTTP,
    "daemon.http",
    File,
    DataDir,
    Runtime,
    Plain,
    Remove,
    "D8",
    "HTTP port of the running daemon (discovery)."
);
spec!(
    DESKTOP_LOCK,
    "desktop.lock",
    File,
    DataDir,
    Runtime,
    Plain,
    Remove,
    "D9",
    "Single-instance lock of the desktop app."
);
spec!(
    PENDING_LINK,
    "pending-link.txt",
    File,
    DataDir,
    Runtime,
    Skippable,
    Remove,
    "D10",
    "miasma-share link handed to the running window (valid for 60 s)."
);
spec!(
    PENDING_LINK_TMP,
    "pending-link.txt.*.tmp",
    Pattern,
    DataDir,
    Runtime,
    Skippable,
    Remove,
    "D10",
    "Per-process temp copy used to write the hand-off file atomically."
);
spec!(
    URL_SCHEME_MARKER,
    "url-scheme-registered.txt",
    File,
    DataDir,
    Integration,
    Skippable,
    Remove,
    "D11",
    "Remembers which exe the miasma-share URL scheme was registered for."
);
spec!(
    ATOMIC_TMP,
    "*.tmp",
    Pattern,
    DataDir,
    State,
    Plain,
    CryptoEraseOverwriteRemove,
    "T5",
    "Leftover copy of a sensitive file if the process died between write and rename."
);
spec!(
    ATOMIC_SECURE_TMP,
    "*.sec.tmp",
    Pattern,
    DataDir,
    Secret,
    Plain,
    OverwriteRemove,
    "T5",
    "Leftover restricted temp copy (master key, config with secrets, envelopes)."
);

spec!(
    STATE_MIGRATION_LOCK,
    "state-migration.lock",
    File,
    DataDir,
    Runtime,
    Plain,
    Remove,
    "D22",
    "Advisory lock that serialises the one-time conversion of older plaintext state files; created only when there is something to convert."
);
spec!(
    PREMIGRATE_COPY,
    "*.premigrate",
    Pattern,
    DataDir,
    State,
    Plain,
    OverwriteRemove,
    "D22",
    "Plaintext original of a state file that is being converted; overwritten and removed within the same step, so it only survives an interruption."
);
spec!(
    STATE_CORRUPT_ASIDE,
    "*.corrupt-*",
    Pattern,
    DataDir,
    State,
    Encrypt,
    CryptoEraseOverwriteRemove,
    "D22",
    "A protected state file that failed to open (wrong key or damage), set aside instead of being overwritten."
);

// ── Logs ────────────────────────────────────────────────────────────────────

spec!(
    DAEMON_LOG,
    "daemon.log",
    RollingLog,
    DataDir,
    Diagnostic,
    Skippable,
    OverwriteRemove,
    "D19",
    "Legacy daemon log, one file per day (daemon.log.<date>). No longer written; found and removed by the old-log cleanup."
);
spec!(
    DESKTOP_LOG,
    "desktop.log",
    RollingLog,
    DataDir,
    Diagnostic,
    Skippable,
    OverwriteRemove,
    "D20",
    "Legacy desktop log, one file per day (desktop.log.<date>). No longer written; found and removed by the old-log cleanup."
);
spec!(
    BRIDGE_LOG,
    "bridge.log",
    RollingLog,
    BridgeDataDir,
    Diagnostic,
    Skippable,
    OverwriteRemove,
    "D21",
    "Legacy bridge log, one file per day (bridge.log.<date>). No longer written; found and removed by the old-log cleanup."
);

spec!(
    DIAG_LOG_DIR,
    "lg",
    Dir,
    DataDir,
    Diagnostic,
    Skippable,
    OverwriteRemove,
    "D19",
    "Folder of opt-in diagnostic log files; exists only while diagnostic logging is on."
);
spec!(
    DIAG_LOG_FILE,
    "lg/*.dat",
    Pattern,
    DataDir,
    Diagnostic,
    Skippable,
    OverwriteRemove,
    "D19",
    "Opt-in diagnostic log, size-rotated, neutral names (<letter><n>.dat), no dates."
);

// ── Plaintext user content ──────────────────────────────────────────────────

spec!(
    PUSH_INBOX,
    "inbox",
    Dir,
    DataDirOrConfigured,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "D15",
    "Received push files (plaintext). Default location; push.inbox_dir can point elsewhere."
);
spec!(
    PUSH_PART,
    ".*.part",
    Pattern,
    DataDirOrConfigured,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "D15",
    "In-progress push receive inside the inbox (.<hash>-<size>.part)."
);
spec!(
    OUTPUT_PART,
    "*.part",
    Pattern,
    UserChosen,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "D16",
    "Partial file `<output>.part` next to a user-chosen output path."
);
spec!(
    SAVE_AS_TARGET,
    "*",
    Pattern,
    UserChosen,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "T3",
    "Files the user saves (Save As, CLI -o) and exported diagnostics reports."
);
spec!(
    RETRIEVE_TMP,
    "miasma-retrieve-*.tmp",
    Pattern,
    OsTemp,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "T1/T2",
    "Decrypted download staged in the OS temp dir before the user saves it."
);
spec!(
    UI_SNAPSHOT,
    "snap_*.ppm",
    Pattern,
    UserChosen,
    Diagnostic,
    Skippable,
    Remove,
    "D26",
    "GUI screenshots written only when $MIASMA_UI_SNAP is set (dev/QA)."
);

// ── Bridge ──────────────────────────────────────────────────────────────────

spec!(
    BRIDGE_INBOX_MARKER,
    ".miasma-bridge-inbox",
    File,
    BridgeInbox,
    Runtime,
    Plain,
    Remove,
    "D23",
    "Marker that tells the bridge a directory is its inbox."
);
spec!(
    BRIDGE_PROCESSED,
    ".processed",
    Dir,
    BridgeInbox,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "D23",
    "Plaintext originals of everything the bridge imported."
);
spec!(
    BRIDGE_DOWNLOADS,
    "bridge-downloads",
    Dir,
    BridgeDataDir,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "D24",
    "Torrent payloads downloaded by `miasma-bridge` (plaintext)."
);
spec!(
    BRIDGE_DOWNLOADS_TEMP,
    "miasma-bridge-downloads",
    Dir,
    OsTemp,
    UserVisible,
    Ledger,
    LedgerOverwriteRemove,
    "D24",
    "Default torrent output dir of the torrent client config (plaintext)."
);

// ── Windows registry ────────────────────────────────────────────────────────

spec!(
    URL_SCHEME_KEY,
    r"Software\Classes\miasma-share",
    RegistryKey,
    RegistryHkcu,
    Integration,
    Skippable,
    RegistryDelete,
    "R1",
    "miasma-share: URL scheme registration (default value, URL Protocol)."
);
spec!(
    URL_SCHEME_COMMAND_KEY,
    r"Software\Classes\miasma-share\shell\open\command",
    RegistryKey,
    RegistryHkcu,
    Integration,
    Skippable,
    RegistryDelete,
    "R1",
    "Open command of the URL scheme: the full exe path."
);
spec!(
    INSTALLER_UNINSTALL_KEY,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    RegistryKey,
    RegistryHklm,
    Integration,
    External,
    NotRemovable,
    "R2",
    "MSI product registration (Add/Remove Programs). Installer-managed."
);
spec!(
    INSTALLER_SHORTCUT_KEY,
    r"Software\Miasma Protocol",
    RegistryKey,
    RegistryHkcu,
    Integration,
    External,
    NotRemovable,
    "R3",
    "MSI shortcut bookkeeping key. Installer-managed."
);
spec!(
    INSTALLER_PATH_KEY,
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    RegistryKey,
    RegistryHklm,
    Integration,
    External,
    NotRemovable,
    "R4",
    "PATH entry added by the MSI. Installer-managed."
);
spec!(
    INSTALLER_HANDLERS_KEY,
    r"SOFTWARE\Classes\Miasma.Magnet",
    RegistryKey,
    RegistryHklm,
    Integration,
    External,
    NotRemovable,
    "R5",
    "magnet / .torrent handler registrations added by the MSI. Installer-managed."
);

/// Every registered object, in documentation order.
pub const REGISTRY: &[PathSpec] = &[
    MASTER_KEY,
    MASTER_KEY_WRAPPED,
    MASTER_KEY_WRAP_IV,
    DAEMON_TOKEN,
    CONFIG,
    VERSION_STAMP,
    STORE_INDEX,
    SHARES_DIR,
    SHARE_BLOB,
    REPLICATION_WAL,
    REPLICATION_WAL_TMP,
    DESKTOP_PREFS,
    CONTACTS,
    CONTACTS_CORRUPT,
    PUSH_HISTORY,
    PUSH_HISTORY_TMP,
    TRANSFERS_DIR,
    RECV_JOURNAL,
    SEND_JOURNAL,
    DIRECTED_DIR,
    DIRECTED_INCOMING,
    DIRECTED_OUTGOING,
    CHAT_DIR,
    CHAT_SESSION,
    CHAT_HISTORY,
    CHAT_OUTBOX,
    CHAT_TMP,
    DAEMON_PORT,
    DAEMON_HTTP,
    DESKTOP_LOCK,
    PENDING_LINK,
    PENDING_LINK_TMP,
    URL_SCHEME_MARKER,
    ATOMIC_TMP,
    ATOMIC_SECURE_TMP,
    STATE_MIGRATION_LOCK,
    PREMIGRATE_COPY,
    STATE_CORRUPT_ASIDE,
    DAEMON_LOG,
    DESKTOP_LOG,
    BRIDGE_LOG,
    DIAG_LOG_DIR,
    DIAG_LOG_FILE,
    PUSH_INBOX,
    PUSH_PART,
    OUTPUT_PART,
    SAVE_AS_TARGET,
    RETRIEVE_TMP,
    UI_SNAPSHOT,
    BRIDGE_INBOX_MARKER,
    BRIDGE_PROCESSED,
    BRIDGE_DOWNLOADS,
    BRIDGE_DOWNLOADS_TEMP,
    URL_SCHEME_KEY,
    URL_SCHEME_COMMAND_KEY,
    INSTALLER_UNINSTALL_KEY,
    INSTALLER_SHORTCUT_KEY,
    INSTALLER_PATH_KEY,
    INSTALLER_HANDLERS_KEY,
];

// ── Name fragments shared by several call sites ─────────────────────────────

/// Extension of a share blob, including the dot.
pub const SHARE_BLOB_EXT: &str = ".ms";
/// Suffix of a partial receive, including the dot.
pub const PART_SUFFIX: &str = ".part";
/// Extension used for atomic-write temp files (`<name>.tmp` via `with_extension`).
pub const ATOMIC_TMP_EXT: &str = "tmp";
/// Extension used for restricted atomic-write temp files.
pub const ATOMIC_SECURE_TMP_EXT: &str = "sec.tmp";

// ── Typed accessors ─────────────────────────────────────────────────────────
//
// One function per path that callers build from a base directory. They return
// exactly what the call sites used to build by hand.

/// `<data>/master.key`
pub fn master_key(data_dir: &Path) -> PathBuf {
    MASTER_KEY.in_dir(data_dir)
}
/// `<data>/config.toml`
pub fn config_file(data_dir: &Path) -> PathBuf {
    CONFIG.in_dir(data_dir)
}
/// `<data>/version`
pub fn version_stamp(data_dir: &Path) -> PathBuf {
    VERSION_STAMP.in_dir(data_dir)
}
/// `<data>/shares`
pub fn shares_dir(data_dir: &Path) -> PathBuf {
    SHARES_DIR.in_dir(data_dir)
}
/// `<data>/lg`
pub fn diag_log_dir(data_dir: &Path) -> PathBuf {
    DIAG_LOG_DIR.in_dir(data_dir)
}
/// Name of diagnostic log file number `n` of the program tagged `prefix`
/// (`d` daemon, `u` desktop, `b` bridge): `<prefix><n>.dat`.
pub fn diag_log_name(prefix: char, n: usize) -> String {
    format!("{prefix}{n}.dat")
}
/// Whether `name` is one of the diagnostic log file names.
pub fn is_diag_log_name(name: &str) -> bool {
    let mut chars = name.chars();
    let (Some(p), rest) = (chars.next(), chars.as_str()) else {
        return false;
    };
    p.is_ascii_lowercase()
        && rest
            .strip_suffix(".dat")
            .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
}
/// Whether `name` is a legacy dated log file of one of the programs
/// (`daemon.log`, `daemon.log.2026-01-01`, `desktop.log.*`, `bridge.log.*`).
pub fn is_legacy_log_name(name: &str) -> bool {
    [DAEMON_LOG.name, DESKTOP_LOG.name, BRIDGE_LOG.name]
        .iter()
        .any(|base| {
            name == *base
                || name
                    .strip_prefix(base)
                    .is_some_and(|rest| rest.starts_with('.'))
        })
}
/// `<data>/transfers`
pub fn transfers_dir(data_dir: &Path) -> PathBuf {
    TRANSFERS_DIR.in_dir(data_dir)
}
/// `<data>/directed/incoming`
pub fn directed_incoming_dir(data_dir: &Path) -> PathBuf {
    DIRECTED_INCOMING.in_dir(data_dir)
}
/// `<data>/directed/outgoing`
pub fn directed_outgoing_dir(data_dir: &Path) -> PathBuf {
    DIRECTED_OUTGOING.in_dir(data_dir)
}
/// Default push inbox: `<data>/inbox`.
pub fn default_push_inbox(data_dir: &Path) -> PathBuf {
    PUSH_INBOX.in_dir(data_dir)
}
/// `<data>/daemon.port`
pub fn daemon_port_file(data_dir: &Path) -> PathBuf {
    DAEMON_PORT.in_dir(data_dir)
}
/// `<data>/daemon.http`
pub fn daemon_http_file(data_dir: &Path) -> PathBuf {
    DAEMON_HTTP.in_dir(data_dir)
}
/// `<data>/pending-link.txt`
pub fn pending_link(data_dir: &Path) -> PathBuf {
    PENDING_LINK.in_dir(data_dir)
}
/// `<data>/pending-link.txt.<pid>.tmp`
pub fn pending_link_tmp(data_dir: &Path, pid: u32) -> PathBuf {
    data_dir.join(format!("{}.{pid}.tmp", PENDING_LINK.name))
}
/// Where the bridge downloads torrents by default (torrent client config).
pub fn bridge_downloads_temp_default() -> PathBuf {
    os_temp_dir().join(BRIDGE_DOWNLOADS_TEMP.name)
}

/// The OS temp directory. The only place that asks for it, so staging files can be
/// redirected into `<data>/tmp` in one edit.
pub fn os_temp_dir() -> PathBuf {
    std::env::temp_dir()
}
/// `<temp>/miasma-retrieve-<envelope_id>.tmp`
pub fn retrieve_tmp_for_envelope(envelope_id: &str) -> PathBuf {
    os_temp_dir().join(format!("miasma-retrieve-{envelope_id}.tmp"))
}
/// `<temp>/miasma-retrieve-<pid>-<stamp>.tmp`
pub fn retrieve_tmp_unique(pid: u32, stamp: u128) -> PathBuf {
    os_temp_dir().join(format!("miasma-retrieve-{pid}-{stamp}.tmp"))
}

/// File name of the receive journal for a content id already rendered in base58.
pub fn recv_journal_name(mid_b58: &str) -> String {
    format!("recv-{mid_b58}.json")
}
/// File name of the publish journal for the 32-hex-digit hash of a source path.
pub fn send_journal_name(source_hash_hex32: &str) -> String {
    format!("send-{source_hash_hex32}.jsonl")
}

/// `<output>.part` for a user-chosen output path.
pub fn output_part_path(output: &Path) -> PathBuf {
    let mut name = output
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(PART_SUFFIX);
    output.with_file_name(name)
}
/// `.<hash32>-<size>.part` inside the push inbox.
pub fn push_part_name(hash_prefix_32: &str, size: u64) -> String {
    format!(".{hash_prefix_32}-{size}{PART_SUFFIX}")
}
/// True for names of in-progress push receives (`.<...>.part`).
pub fn is_push_part_name(name: &str) -> bool {
    name.starts_with('.') && name.ends_with(PART_SUFFIX)
}

/// `<path>.tmp` the way `store.rs` has always named its atomic-write copies.
pub fn atomic_tmp(path: &Path) -> PathBuf {
    path.with_extension(ATOMIC_TMP_EXT)
}
/// `<path>.sec.tmp` as written by `secure_file::atomic_write_restricted`.
pub fn atomic_secure_tmp(path: &Path) -> PathBuf {
    path.with_extension(ATOMIC_SECURE_TMP_EXT)
}
/// Where the contacts loader sets an unreadable file aside.
pub fn contacts_corrupt_aside(contacts_file: &Path, unix_secs: u64) -> PathBuf {
    contacts_file.with_extension(format!("json.corrupt-{unix_secs}"))
}

/// `<data>/chat`
pub fn chat_dir(data_dir: &Path) -> PathBuf {
    CHAT_DIR.in_dir(data_dir)
}

/// `<chat dir>/<stem>.msgs`: the saved messages of one contact.
pub fn chat_history_file(chat_dir: &Path, stem: &str) -> PathBuf {
    chat_dir.join(format!("{stem}.msgs"))
}

/// `<chat dir>/<stem>.sess`: the session document of one contact.
pub fn chat_session_file(chat_dir: &Path, stem: &str) -> PathBuf {
    chat_dir.join(format!("{stem}.sess"))
}

/// `<chat dir>/outbox.log`
pub fn chat_outbox_file(chat_dir: &Path) -> PathBuf {
    chat_dir.join("outbox.log")
}

/// True for a per-contact session document name.
pub fn is_chat_session_file(p: &Path) -> bool {
    p.extension().is_some_and(|e| e == "sess")
}

/// Suffix of the plaintext original while a state file is being converted.
pub const PREMIGRATE_SUFFIX: &str = ".premigrate";

/// `<data>/state-migration.lock`
pub fn state_migration_lock(data_dir: &Path) -> PathBuf {
    STATE_MIGRATION_LOCK.in_dir(data_dir)
}
/// `<file>.premigrate`: where the plaintext original waits while its protected
/// replacement is moved into place.
pub fn premigrate_copy(path: &Path) -> PathBuf {
    append_to_name(path, PREMIGRATE_SUFFIX)
}
/// `<file>.sec.tmp`: staging copy of a protected state file. The full file name
/// is kept so `<id>.json` and `<id>.peer` never share a temp name.
pub fn staged_tmp(path: &Path) -> PathBuf {
    append_to_name(path, ".sec.tmp")
}
/// `<file>.corrupt-<unix seconds>`: where a protected file that failed to open
/// is set aside.
pub fn corrupt_aside(path: &Path, unix_secs: u64) -> PathBuf {
    append_to_name(path, &format!(".corrupt-{unix_secs}"))
}
fn append_to_name(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}
/// A contacts file set aside by the contacts loader (`contacts.json.corrupt-*`).
pub fn is_contacts_corrupt_name(name: &str) -> bool {
    name.strip_prefix(CONTACTS.name)
        .is_some_and(|rest| rest.starts_with(".corrupt-"))
}
/// `recv-<mid>.json`
pub fn is_recv_journal_name(name: &str) -> bool {
    name.starts_with("recv-") && name.ends_with(".json")
}
/// `send-<hash>.jsonl`
pub fn is_send_journal_name(name: &str) -> bool {
    name.starts_with("send-") && name.ends_with(".jsonl")
}
/// A directed-share file: the envelope (`.json`) or one of its sidecars
/// (`.challenge`, `.peer`).
pub fn is_directed_meta_name(name: &str) -> bool {
    [".json", ".challenge", ".peer"]
        .iter()
        .any(|ext| name.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_and_match_the_constant_name() {
        let mut seen = HashSet::new();
        for s in REGISTRY {
            assert!(seen.insert(s.id), "duplicate id {}", s.id);
            assert!(!s.name.is_empty() && !s.purpose.is_empty(), "{}", s.id);
            assert_eq!(s.id, s.id.to_ascii_uppercase(), "{}", s.id);
        }
    }

    #[test]
    fn no_two_entries_claim_the_same_place() {
        let mut seen = HashSet::new();
        for s in REGISTRY {
            let key = (format!("{:?}", s.location), s.name);
            assert!(seen.insert(key), "{} repeats another entry", s.id);
        }
    }

    #[test]
    fn kinds_and_names_are_consistent() {
        for s in REGISTRY {
            match s.kind {
                Kind::Pattern => assert!(s.name.contains('*'), "{}", s.id),
                Kind::File | Kind::Dir | Kind::RollingLog => {
                    assert!(!s.name.contains('*'), "{}", s.id);
                    assert!(!s.name.contains('\\'), "{}", s.id);
                    assert!(!s.name.starts_with('/'), "{}", s.id);
                    assert!(!s.name.contains(".."), "{}", s.id);
                }
                Kind::RegistryKey => assert!(
                    matches!(s.location, Location::RegistryHkcu | Location::RegistryHklm),
                    "{}",
                    s.id
                ),
            }
            // Registry keys are the only entries with a registry-style wipe.
            assert_eq!(
                s.wipe == WipeMethod::RegistryDelete,
                matches!(s.kind, Kind::RegistryKey) && s.treatment != Treatment::External,
                "{}",
                s.id
            );
        }
    }

    #[test]
    fn secrets_are_never_marked_for_later_encryption_or_ledger() {
        for s in REGISTRY {
            if s.class == Class::Secret {
                assert!(
                    matches!(s.treatment, Treatment::Plain),
                    "{} must stay plain until the key vault exists",
                    s.id
                );
            }
            if s.encrypted_later() {
                assert!(matches!(s.class, Class::State), "{}", s.id);
            }
        }
    }

    /// The registry must not rename anything: these are the names shipped today.
    #[test]
    fn on_disk_names_are_unchanged() {
        let d = Path::new("D");
        let join = |p: &str| {
            let mut b = d.to_path_buf();
            for c in p.split('/') {
                b.push(c);
            }
            b
        };
        assert_eq!(master_key(d), join("master.key"));
        assert_eq!(config_file(d), join("config.toml"));
        assert_eq!(version_stamp(d), join("version"));
        assert_eq!(STORE_INDEX.in_dir(d), join("store_index.json"));
        assert_eq!(shares_dir(d), join("shares"));
        assert_eq!(REPLICATION_WAL.in_dir(d), join("replication_wal.jsonl"));
        assert_eq!(
            REPLICATION_WAL_TMP.in_dir(d),
            join("replication_wal.jsonl.tmp")
        );
        assert_eq!(DAEMON_TOKEN.in_dir(d), join("daemon.token"));
        assert_eq!(daemon_port_file(d), join("daemon.port"));
        assert_eq!(daemon_http_file(d), join("daemon.http"));
        assert_eq!(DESKTOP_LOCK.in_dir(d), join("desktop.lock"));
        assert_eq!(pending_link(d), join("pending-link.txt"));
        assert_eq!(pending_link_tmp(d, 7), join("pending-link.txt.7.tmp"));
        assert_eq!(
            URL_SCHEME_MARKER.in_dir(d),
            join("url-scheme-registered.txt")
        );
        assert_eq!(DESKTOP_PREFS.in_dir(d), join("desktop-prefs.toml"));
        assert_eq!(CONTACTS.in_dir(d), join("contacts.json"));
        assert_eq!(PUSH_HISTORY.in_dir(d), join("push_history.jsonl"));
        assert_eq!(default_push_inbox(d), join("inbox"));
        assert_eq!(transfers_dir(d), join("transfers"));
        assert_eq!(directed_incoming_dir(d), join("directed/incoming"));
        assert_eq!(directed_outgoing_dir(d), join("directed/outgoing"));
        assert_eq!(diag_log_dir(d), join("lg"));
        assert_eq!(diag_log_name('d', 0), "d0.dat");
        assert!(is_diag_log_name("u12.dat"));
        assert!(!is_diag_log_name("daemon.log"));
        assert!(!is_diag_log_name("x.dat"));
        assert!(is_legacy_log_name("daemon.log.2026-01-01"));
        assert!(is_legacy_log_name("bridge.log"));
        assert!(!is_legacy_log_name("daemon.logger"));
        assert!(!is_legacy_log_name("notes.log"));
        assert_eq!(DAEMON_LOG.name, "daemon.log");
        assert_eq!(DESKTOP_LOG.name, "desktop.log");
        assert_eq!(BRIDGE_LOG.name, "bridge.log");
        assert_eq!(DAEMON_LOG.log_glob(d), join("daemon.log.*"));
        assert_eq!(BRIDGE_INBOX_MARKER.name, ".miasma-bridge-inbox");
        assert_eq!(BRIDGE_PROCESSED.name, ".processed");
        assert_eq!(BRIDGE_DOWNLOADS.name, "bridge-downloads");
        assert_eq!(BRIDGE_DOWNLOADS_TEMP.name, "miasma-bridge-downloads");
        assert_eq!(SHARE_BLOB_EXT, ".ms");
    }

    #[test]
    fn dynamic_names_are_unchanged() {
        assert_eq!(recv_journal_name("abc"), "recv-abc.json");
        assert_eq!(send_journal_name("0f"), "send-0f.jsonl");
        assert_eq!(push_part_name("aa", 5), ".aa-5.part");
        assert!(is_push_part_name(".aa-5.part"));
        assert!(!is_push_part_name("aa-5.part"));
        assert!(!is_push_part_name(".aa-5.txt"));
        assert_eq!(
            output_part_path(Path::new("C:/out/file.bin")),
            PathBuf::from("C:/out/file.bin.part")
        );
        assert_eq!(
            output_part_path(Path::new("noext")),
            PathBuf::from("noext.part")
        );
        assert_eq!(
            atomic_tmp(Path::new("d/store_index.json")),
            PathBuf::from("d/store_index.tmp")
        );
        assert_eq!(
            atomic_secure_tmp(Path::new("d/master.key")),
            PathBuf::from("d/master.sec.tmp")
        );
        assert_eq!(
            contacts_corrupt_aside(Path::new("d/contacts.json"), 9),
            PathBuf::from("d/contacts.json.corrupt-9")
        );
        assert_eq!(
            retrieve_tmp_for_envelope("e1").file_name().unwrap(),
            "miasma-retrieve-e1.tmp"
        );
        assert_eq!(
            retrieve_tmp_unique(3, 4).file_name().unwrap(),
            "miasma-retrieve-3-4.tmp"
        );
    }

    #[test]
    fn registry_paths_are_spelled_for_reg_exe() {
        assert_eq!(
            URL_SCHEME_KEY.registry_path(),
            r"HKCU\Software\Classes\miasma-share"
        );
        assert_eq!(
            URL_SCHEME_COMMAND_KEY.registry_path(),
            r"HKCU\Software\Classes\miasma-share\shell\open\command"
        );
    }
}
