//! The data side of the Network section: the settings being edited, their validation, how they
//! are read from and written to the node configuration, and the view model of a reachability
//! report. Nothing here draws anything or touches the network, so all of it is tested directly.
//!
//! The settings are read and written with `NodeConfig::load` / `NodeConfig::save`, the same
//! calls `miasma config` uses, and the report is the one `miasma netcheck --matrix --json`
//! prints.

use std::path::Path;

use miasma_core::config::{IrohMode, NodeConfig};
use miasma_core::transport::iroh_direct::parse_ca_roots;
use miasma_core::transport::reach::{AdviceCode, Group, MatrixReport, Outcome, Role};

/// Most relay addresses that can be listed.
pub const MAX_RELAYS: usize = 8;
/// Longest retry window that can be set (one year).
pub const MAX_RETRY_HOURS: u64 = 24 * 365;
/// Largest certificate file that is read (the same limit the transport applies).
pub const MAX_CA_FILE_BYTES: u64 = 256 * 1024;

// ─── Relay addresses ─────────────────────────────────────────────────────────

/// Why a relay address is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    Empty,
    NotHttps,
    Space,
    UserInfo,
    Host,
    Port,
    QueryOrFragment,
    Duplicate,
    TooMany,
}

fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn valid_ipv6_literal(inner: &str) -> bool {
    !inner.is_empty() && inner.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Check one relay address and return it in the form that is stored: `https://` and the host
/// in lower case, no trailing slash. Only `https` is accepted, with no user name, query or
/// fragment.
pub fn normalize_relay_url(input: &str) -> Result<String, UrlError> {
    let text = input.trim();
    if text.is_empty() {
        return Err(UrlError::Empty);
    }
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(UrlError::Space);
    }
    const SCHEME: &str = "https://";
    if !text
        .get(..SCHEME.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(SCHEME))
    {
        return Err(UrlError::NotHttps);
    }
    let rest = &text[SCHEME.len()..];
    if rest.contains('?') || rest.contains('#') {
        return Err(UrlError::QueryOrFragment);
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.contains('@') {
        return Err(UrlError::UserInfo);
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let Some(end) = stripped.find(']') else {
            return Err(UrlError::Host);
        };
        let inner = &stripped[..end];
        if !valid_ipv6_literal(inner) {
            return Err(UrlError::Host);
        }
        let after = &stripped[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err(UrlError::Host),
        };
        (format!("[{}]", inner.to_ascii_lowercase()), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_ascii_lowercase(), Some(p)),
            None => (authority.to_ascii_lowercase(), None),
        }
    };
    if !host.starts_with('[') && !valid_host(&host) {
        return Err(UrlError::Host);
    }
    let mut out = format!("https://{host}");
    if let Some(p) = port {
        match p.parse::<u16>() {
            Ok(n) if n != 0 && p.chars().all(|c| c.is_ascii_digit()) => {
                out.push(':');
                out.push_str(&n.to_string());
            }
            _ => return Err(UrlError::Port),
        }
    }
    if path != "/" {
        out.push_str(path);
    }
    Ok(out)
}

/// Add `input` to `list` if it is acceptable. Returns the stored form.
pub fn add_relay_url(list: &mut Vec<String>, input: &str) -> Result<String, UrlError> {
    let url = normalize_relay_url(input)?;
    if list.iter().any(|u| u.eq_ignore_ascii_case(&url)) {
        return Err(UrlError::Duplicate);
    }
    if list.len() >= MAX_RELAYS {
        return Err(UrlError::TooMany);
    }
    list.push(url.clone());
    Ok(url)
}

// ─── The extra certificate file ──────────────────────────────────────────────

/// What was found when the chosen certificate file was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaCheck {
    /// No file chosen.
    Empty,
    Missing,
    Unreadable,
    TooLarge,
    /// The file is there but holds no usable certificate.
    Invalid,
    /// The file parses; `certs` certificates were found.
    Valid {
        certs: usize,
    },
}

/// Read `path` and say whether the transport can use it (the same parser the transport uses).
pub fn check_ca_file(path: &str) -> CaCheck {
    let path = path.trim();
    if path.is_empty() {
        return CaCheck::Empty;
    }
    let p = Path::new(path);
    let meta = match std::fs::metadata(p) {
        Ok(m) if m.is_file() => m,
        Ok(_) => return CaCheck::Invalid,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return CaCheck::Missing,
        Err(_) => return CaCheck::Unreadable,
    };
    if meta.len() > MAX_CA_FILE_BYTES {
        return CaCheck::TooLarge;
    }
    match std::fs::read(p) {
        Ok(bytes) => match parse_ca_roots(&bytes) {
            Ok(certs) => CaCheck::Valid { certs: certs.len() },
            Err(_) => CaCheck::Invalid,
        },
        Err(_) => CaCheck::Unreadable,
    }
}

/// The file name of `path`, for display (the folder is not shown).
pub fn file_name_of(path: &str) -> String {
    Path::new(path.trim())
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.trim().to_owned())
}

// ─── The settings ────────────────────────────────────────────────────────────

/// A reason the settings cannot be saved yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    /// "My own relay" is chosen but no address is listed.
    OwnRelayNeedsUrl,
    /// The retry window is outside 0..=[`MAX_RETRY_HOURS`].
    RetryRange,
    /// The chosen certificate file cannot be used.
    CertificateUnusable,
}

/// The values of the Network section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSettings {
    pub mode: IrohMode,
    pub relay_urls: Vec<String>,
    pub lan_discovery: bool,
    /// Path of the extra certificate file, empty for none.
    pub ca_path: String,
    pub retry_hours: u64,
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self::from_config(&NodeConfig::default())
    }
}

impl NetworkSettings {
    pub fn from_config(c: &NodeConfig) -> Self {
        Self {
            mode: c.transport.iroh_mode,
            relay_urls: c.transport.iroh_relay_urls.clone(),
            lan_discovery: c.transport.iroh_lan_discovery,
            ca_path: c.transport.iroh_extra_ca_pem.clone().unwrap_or_default(),
            retry_hours: c.push.retry_window_hours,
        }
    }

    /// Everything that stops these values from being saved. `ca` is the result of
    /// [`check_ca_file`] for `ca_path`.
    pub fn issues(&self, ca: &CaCheck) -> Vec<Issue> {
        let mut v = Vec::new();
        if self.mode == IrohMode::Custom && self.relay_urls.is_empty() {
            v.push(Issue::OwnRelayNeedsUrl);
        }
        if self.retry_hours > MAX_RETRY_HOURS {
            v.push(Issue::RetryRange);
        }
        if !matches!(ca, CaCheck::Empty | CaCheck::Valid { .. }) {
            v.push(Issue::CertificateUnusable);
        }
        v
    }

    /// Write these values into `c`; the other settings are left as they are.
    pub fn apply_to(&self, c: &mut NodeConfig) {
        c.transport.iroh_mode = self.mode;
        c.transport.iroh_relay_urls = self.relay_urls.clone();
        c.transport.iroh_lan_discovery = self.lan_discovery;
        let ca = self.ca_path.trim();
        c.transport.iroh_extra_ca_pem = if ca.is_empty() {
            None
        } else {
            Some(ca.to_owned())
        };
        c.push.retry_window_hours = self.retry_hours;
    }
}

/// Read the saved settings. `Err` carries the reason; the caller then shows the defaults.
pub fn load_settings(data_dir: &Path) -> Result<NetworkSettings, String> {
    let mut c = NodeConfig::load(data_dir).map_err(|e| e.to_string())?;
    let s = NetworkSettings::from_config(&c);
    c.transport.zeroize_secret_copies();
    Ok(s)
}

/// Validate and save, the way `miasma config` does: load the file, change the keys, save.
pub fn save_settings(data_dir: &Path, s: &NetworkSettings) -> Result<(), String> {
    let issues = s.issues(&check_ca_file(&s.ca_path));
    if !issues.is_empty() {
        return Err(format!("invalid settings: {issues:?}"));
    }
    let mut c = NodeConfig::load(data_dir).map_err(|e| e.to_string())?;
    s.apply_to(&mut c);
    let r = c.save(data_dir).map_err(|e| e.to_string());
    c.transport.zeroize_secret_copies();
    r
}

// ─── The reachability report ─────────────────────────────────────────────────

/// How one row of the report is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowState {
    Works,
    Failed,
    Skipped,
}

/// One line of the result table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowView {
    pub group: Group,
    pub role: Role,
    pub target: String,
    pub state: RowState,
    pub outcome: Outcome,
    /// The report's remark, shown for a certificate from a non-public authority (its name).
    pub detail: Option<String>,
    pub rtt_ms: Option<u64>,
    pub kib_per_s: Option<u64>,
}

/// A report arranged for the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixView {
    pub rows: Vec<RowView>,
    pub works: usize,
    pub failed: usize,
    pub skipped: usize,
    pub elapsed_secs: u64,
    pub advice: Vec<AdviceCode>,
}

impl MatrixView {
    pub fn from_report(r: &MatrixReport) -> Self {
        let rows: Vec<RowView> = r
            .probes
            .iter()
            .map(|p| {
                let state = if p.ok && p.outcome == Outcome::Ok {
                    RowState::Works
                } else if p.outcome == Outcome::Skipped {
                    RowState::Skipped
                } else {
                    RowState::Failed
                };
                RowView {
                    group: p.group,
                    role: p.role,
                    target: p.target.clone(),
                    state,
                    outcome: p.outcome,
                    detail: match p.outcome {
                        Outcome::NonPublicCa => p.detail.clone(),
                        _ => None,
                    },
                    rtt_ms: p.rtt_ms,
                    kib_per_s: p.kib_per_s,
                }
            })
            .collect();
        let count = |s: RowState| rows.iter().filter(|r| r.state == s).count();
        Self {
            works: count(RowState::Works),
            failed: count(RowState::Failed),
            skipped: count(RowState::Skipped),
            elapsed_secs: r.elapsed_ms / 1000,
            advice: r.advice.iter().map(|a| a.code).collect(),
            rows,
        }
    }
}

/// The text `miasma netcheck --matrix --json` prints (and `--out` writes).
pub fn report_json(r: &MatrixReport) -> Result<String, String> {
    let mut t = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    t.push('\n');
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::transport::reach::{Advice, ProbeResult, SCHEMA_VERSION};

    // ── relay addresses ─────────────────────────────────────────────────────

    #[test]
    fn https_addresses_are_accepted_and_normalised() {
        assert_eq!(
            normalize_relay_url("https://relay.example.org").unwrap(),
            "https://relay.example.org"
        );
        assert_eq!(
            normalize_relay_url("  HTTPS://Relay.Example.ORG/  ").unwrap(),
            "https://relay.example.org"
        );
        assert_eq!(
            normalize_relay_url("https://relay.example.org:8443/x").unwrap(),
            "https://relay.example.org:8443/x"
        );
        assert_eq!(
            normalize_relay_url("https://[2001:db8::1]:8443").unwrap(),
            "https://[2001:db8::1]:8443"
        );
        assert_eq!(
            normalize_relay_url("https://192.0.2.7").unwrap(),
            "https://192.0.2.7"
        );
    }

    #[test]
    fn unsafe_or_malformed_addresses_are_refused() {
        let cases = [
            ("", UrlError::Empty),
            ("   ", UrlError::Empty),
            ("http://relay.example.org", UrlError::NotHttps),
            ("relay.example.org", UrlError::NotHttps),
            ("wss://relay.example.org", UrlError::NotHttps),
            ("https:/relay.example.org", UrlError::NotHttps),
            ("https://relay example.org", UrlError::Space),
            ("https://user:pw@relay.example.org", UrlError::UserInfo),
            ("https://", UrlError::Host),
            ("https://.example.org", UrlError::Host),
            ("https://-a.example.org", UrlError::Host),
            ("https://exa_mple.org", UrlError::Host),
            ("https://[nothex]", UrlError::Host),
            ("https://[::1", UrlError::Host),
            ("https://relay.example.org:0", UrlError::Port),
            ("https://relay.example.org:99999", UrlError::Port),
            ("https://relay.example.org:abc", UrlError::Port),
            ("https://relay.example.org:+80", UrlError::Port),
            ("https://relay.example.org?x=1", UrlError::QueryOrFragment),
            ("https://relay.example.org/#f", UrlError::QueryOrFragment),
        ];
        for (input, want) in cases {
            assert_eq!(normalize_relay_url(input), Err(want), "{input:?}");
        }
        // Surrounding white space is trimmed; white space inside is refused.
        assert!(normalize_relay_url("https://relay.example.org\n").is_ok());
        // A multi-byte character at the scheme boundary is a plain refusal, not a panic.
        assert_eq!(normalize_relay_url("httpsé//x"), Err(UrlError::NotHttps));
    }

    #[test]
    fn the_list_refuses_duplicates_and_a_ninth_entry() {
        let mut list = Vec::new();
        add_relay_url(&mut list, "https://a.example.org").unwrap();
        assert_eq!(
            add_relay_url(&mut list, "HTTPS://A.example.org/"),
            Err(UrlError::Duplicate)
        );
        assert_eq!(list.len(), 1);
        for i in 1..MAX_RELAYS {
            add_relay_url(&mut list, &format!("https://r{i}.example.org")).unwrap();
        }
        assert_eq!(
            add_relay_url(&mut list, "https://one-more.example.org"),
            Err(UrlError::TooMany)
        );
        assert_eq!(list.len(), MAX_RELAYS);
        // A refused address leaves the list as it was.
        assert_eq!(
            add_relay_url(&mut list, "http://x.example.org"),
            Err(UrlError::NotHttps)
        );
        assert_eq!(list.len(), MAX_RELAYS);
    }

    // ── settings ────────────────────────────────────────────────────────────

    #[test]
    fn defaults_come_from_the_node_configuration() {
        let s = NetworkSettings::default();
        assert_eq!(s.mode, IrohMode::N0);
        assert!(s.relay_urls.is_empty());
        assert!(s.lan_discovery);
        assert!(s.ca_path.is_empty());
        assert_eq!(s.retry_hours, 24);
        assert!(s.issues(&CaCheck::Empty).is_empty());
    }

    #[test]
    fn validation_reports_each_blocking_problem() {
        let mut s = NetworkSettings {
            mode: IrohMode::Custom,
            ..NetworkSettings::default()
        };
        assert_eq!(s.issues(&CaCheck::Empty), vec![Issue::OwnRelayNeedsUrl]);
        s.relay_urls.push("https://relay.example.org".into());
        assert!(s.issues(&CaCheck::Empty).is_empty());
        s.retry_hours = MAX_RETRY_HOURS + 1;
        s.ca_path = "x.pem".into();
        assert_eq!(
            s.issues(&CaCheck::Missing),
            vec![Issue::RetryRange, Issue::CertificateUnusable]
        );
        s.retry_hours = 0;
        assert_eq!(s.issues(&CaCheck::Valid { certs: 1 }), Vec::new());
        // The other two modes need no relay address.
        s.relay_urls.clear();
        for m in [IrohMode::N0, IrohMode::Off] {
            s.mode = m;
            assert!(s.issues(&CaCheck::Empty).is_empty());
        }
    }

    #[test]
    fn saving_changes_only_the_network_keys_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut before = NodeConfig::default();
        before.storage.quota_mb = 1234;
        before.save(dir.path()).unwrap();

        let s = NetworkSettings {
            mode: IrohMode::Custom,
            relay_urls: vec!["https://relay.example.org".into()],
            lan_discovery: false,
            ca_path: String::new(),
            retry_hours: 0,
        };
        save_settings(dir.path(), &s).unwrap();

        let after = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(after.transport.iroh_mode, IrohMode::Custom);
        assert_eq!(after.transport.iroh_relay_urls, s.relay_urls);
        assert!(!after.transport.iroh_lan_discovery);
        assert_eq!(after.transport.iroh_extra_ca_pem, None);
        assert_eq!(after.push.retry_window_hours, 0);
        assert_eq!(after.storage.quota_mb, 1234, "other settings are untouched");
        assert_eq!(load_settings(dir.path()).unwrap(), s);
    }

    #[test]
    fn invalid_settings_are_not_written() {
        let dir = tempfile::tempdir().unwrap();
        NodeConfig::default().save(dir.path()).unwrap();
        let bad = NetworkSettings {
            mode: IrohMode::Custom,
            ..NetworkSettings::default()
        };
        assert!(save_settings(dir.path(), &bad).is_err());
        let after = NodeConfig::load(dir.path()).unwrap();
        assert_eq!(after.transport.iroh_mode, IrohMode::N0);
    }

    #[test]
    fn a_missing_config_file_gives_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            load_settings(dir.path()).unwrap(),
            NetworkSettings::default()
        );
    }

    #[test]
    fn the_certificate_file_is_checked_by_the_transport_parser() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_ca_file(""), CaCheck::Empty);
        assert_eq!(check_ca_file("   "), CaCheck::Empty);
        let missing = dir.path().join("nope.pem");
        assert_eq!(check_ca_file(&missing.to_string_lossy()), CaCheck::Missing);
        assert_eq!(
            check_ca_file(&dir.path().to_string_lossy()),
            CaCheck::Invalid,
            "a folder is not a certificate"
        );
        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, b"not a certificate").unwrap();
        assert_eq!(check_ca_file(&junk.to_string_lossy()), CaCheck::Invalid);
        let empty_pem = dir.path().join("empty.pem");
        std::fs::write(&empty_pem, b"-----BEGIN NOTHING-----\n").unwrap();
        assert_eq!(
            check_ca_file(&empty_pem.to_string_lossy()),
            CaCheck::Invalid
        );
        let big = dir.path().join("big.pem");
        std::fs::write(&big, vec![b'a'; MAX_CA_FILE_BYTES as usize + 1]).unwrap();
        assert_eq!(check_ca_file(&big.to_string_lossy()), CaCheck::TooLarge);
        assert_eq!(file_name_of(&junk.to_string_lossy()), "junk.pem");
    }

    // ── the report ──────────────────────────────────────────────────────────

    fn probe(id: &str, group: Group, role: Role, ok: bool, outcome: Outcome) -> ProbeResult {
        ProbeResult {
            id: id.into(),
            group,
            role,
            target: "relay.example.org".into(),
            ok,
            outcome,
            millis: Some(40),
            rtt_ms: None,
            kib_per_s: None,
            detail: None,
        }
    }

    fn fixture() -> MatrixReport {
        let mut relay = probe(
            "relay:relay:a",
            Group::Relay,
            Role::Relay,
            true,
            Outcome::Ok,
        );
        relay.rtt_ms = Some(87);
        relay.kib_per_s = Some(512);
        let mut tls = probe(
            "tls:relay:a",
            Group::Tls,
            Role::Relay,
            false,
            Outcome::NonPublicCa,
        );
        tls.detail = Some("Example Inspection CA".into());
        let mut dns = probe("dns:relay:a", Group::Dns, Role::Relay, true, Outcome::Ok);
        dns.detail = Some("ip#2".into());
        MatrixReport {
            schema: SCHEMA_VERSION,
            iroh_mode: "n0".into(),
            elapsed_ms: 12_345,
            probes: vec![
                dns,
                probe("tcp:relay:a", Group::Tcp, Role::Relay, true, Outcome::Ok),
                tls,
                probe(
                    "udp:local",
                    Group::Udp,
                    Role::Local,
                    false,
                    Outcome::UdpBlocked,
                ),
                probe(
                    "quic:relay:a",
                    Group::Quic,
                    Role::Relay,
                    false,
                    Outcome::Skipped,
                ),
                relay,
            ],
            advice: vec![
                Advice {
                    code: AdviceCode::TlsInspectedUntrusted,
                    config_keys: vec!["transport.iroh_extra_ca_pem"],
                },
                Advice {
                    code: AdviceCode::UdpNotObserved,
                    config_keys: vec![],
                },
            ],
        }
    }

    #[test]
    fn the_view_has_one_row_per_probe_with_its_state() {
        let v = MatrixView::from_report(&fixture());
        assert_eq!(v.rows.len(), 6);
        assert_eq!((v.works, v.failed, v.skipped), (3, 2, 1));
        assert_eq!(v.elapsed_secs, 12);
        let states: Vec<RowState> = v.rows.iter().map(|r| r.state).collect();
        assert_eq!(
            states,
            vec![
                RowState::Works,
                RowState::Works,
                RowState::Failed,
                RowState::Failed,
                RowState::Skipped,
                RowState::Works,
            ]
        );
        assert_eq!(v.rows[2].outcome, Outcome::NonPublicCa);
        assert_eq!(v.rows[2].detail.as_deref(), Some("Example Inspection CA"));
        assert_eq!(v.rows[0].detail, None, "machine remarks are not shown");
        assert_eq!(v.rows[5].rtt_ms, Some(87));
        assert_eq!(v.rows[5].kib_per_s, Some(512));
        assert_eq!(
            v.advice,
            vec![
                AdviceCode::TlsInspectedUntrusted,
                AdviceCode::UdpNotObserved
            ]
        );
    }

    #[test]
    fn a_row_counts_as_working_only_when_ok_and_classified_ok() {
        let mut r = fixture();
        r.probes = vec![
            probe("a", Group::Tcp, Role::Relay, true, Outcome::Failed),
            probe("b", Group::Tcp, Role::Relay, false, Outcome::Ok),
        ];
        let v = MatrixView::from_report(&r);
        assert_eq!((v.works, v.failed, v.skipped), (0, 2, 0));
    }

    #[test]
    fn an_empty_report_makes_an_empty_view() {
        let mut r = fixture();
        r.probes.clear();
        r.advice.clear();
        let v = MatrixView::from_report(&r);
        assert!(v.rows.is_empty() && v.advice.is_empty());
        assert_eq!((v.works, v.failed, v.skipped), (0, 0, 0));
    }

    #[test]
    fn every_outcome_and_advice_code_has_text_for_the_table() {
        // The view keeps the codes; the strings module has a text for each.
        use crate::locale::Locale;
        for l in Locale::ALL {
            for o in Outcome::ALL {
                assert!(!crate::network_strings::outcome_text(o, l).is_empty());
            }
            for a in AdviceCode::ALL {
                assert!(!crate::network_strings::advice_text(a, l).is_empty());
            }
        }
    }

    #[test]
    fn the_saved_report_has_the_schema_of_the_command_line_json() {
        let text = report_json(&fixture()).unwrap();
        assert!(text.ends_with('\n'));
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema"], SCHEMA_VERSION);
        assert_eq!(v["iroh_mode"], "n0");
        assert_eq!(v["elapsed_ms"], 12_345);
        assert_eq!(v["probes"].as_array().unwrap().len(), 6);
        assert_eq!(v["probes"][2]["outcome"], "non_public_ca");
        assert_eq!(v["probes"][2]["group"], "tls");
        assert_eq!(v["advice"][0]["code"], "tls_inspected_untrusted");
        // Exactly what the command prints.
        let mut cli = serde_json::to_string_pretty(&fixture()).unwrap();
        cli.push('\n');
        assert_eq!(text, cli);
    }
}
