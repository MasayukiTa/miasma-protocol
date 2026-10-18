//! The reachability matrix (`miasma netcheck --matrix`).
//!
//! `miasma netcheck` answers "what will happen"; the matrix answers "which
//! paths work on the network I am standing in", one row per path, each with a
//! classified reason, so a configuration can be chosen from observation:
//!
//! * DNS: the system resolver against two public resolvers asked over UDP.
//! * TCP: connect to every address of the relay, discovery and neutral hosts.
//! * TLS: a handshake with the real server name, and the same address with a
//!   neutral name (what the network does differently, if anything).
//! * UDP / QUIC: iroh's own net report.
//! * A tiny round trip and a 1 MiB transfer through the relay.
//! * The local network (mDNS).
//! * Any `--probe wss://host/path` the user adds.
//!
//! Only ordinary connection attempts are made, each with a short timeout; at
//! most four run at once and the whole run ends inside [`TOTAL_BUDGET`]. No
//! user data is sent. This module is the measuring order and the judging; the
//! actual network calls sit behind the [`Net`] trait ([`super::reach_net`] has
//! the real one), so every classification is tested with fakes.
//!
//! The report names only the hosts that were probed. It holds no address of
//! this computer, no endpoint ID and no resolved address.

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::{stream, StreamExt};
use serde::Serialize;
use tokio::sync::Semaphore;

use super::{iroh_direct::IrohSettings, reach_dns::v4_only};
use crate::config::IrohMode;

/// Version of the JSON layout. Bumped only when a field is renamed or removed.
pub const SCHEMA_VERSION: u32 = 1;
/// Probes in flight at once.
pub const MAX_CONCURRENCY: usize = 4;
/// The whole run, from the first query to the last row.
pub const TOTAL_BUDGET: Duration = Duration::from_secs(38);

const DNS_LIMIT: Duration = Duration::from_secs(3);
const TCP_LIMIT: Duration = Duration::from_secs(5);
const TLS_LIMIT: Duration = Duration::from_secs(6);
const UDP_LIMIT: Duration = Duration::from_secs(8);
const RELAY_LIMIT: Duration = Duration::from_secs(14);
const LAN_LIMIT: Duration = Duration::from_secs(4);
const WS_LIMIT: Duration = Duration::from_secs(8);
/// Addresses tried per host.
const MAX_ADDRS: usize = 2;

/// Relay hosts probed in `n0` mode (the ones `miasma netcheck` uses).
const N0_RELAY_HOSTS: &[&str] = &["use1-1.relay.n0.iroh.link", "aps1-1.relay.n0.iroh.link"];
/// The discovery service the daemon publishes to and resolves from.
const N0_DISCOVERY_HOST: &str = "dns.iroh.link";
/// Needed by `miasma tunnel` and `--via wss://…trycloudflare.com`.
const TUNNEL_HOST: &str = "api.trycloudflare.com";
/// Well-known hosts that have nothing to do with Miasma: a control group.
const NEUTRAL_HOSTS: &[&str] = &["example.com", "www.wikipedia.org", "one.one.one.one"];
/// A name that is not the relay's, for the SNI comparison.
const NEUTRAL_SNI: &str = "example.com";
/// Public resolvers asked directly over UDP port 53.
const PUBLIC_RESOLVERS: [([u8; 4], u16); 2] = [([1, 1, 1, 1], 53), ([8, 8, 8, 8], 53)];

// ─── The report ──────────────────────────────────────────────────────────────

/// Which kind of path a row is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    Dns,
    Tcp,
    Tls,
    Sni,
    Udp,
    Quic,
    Relay,
    Lan,
}

impl Group {
    pub const ALL: [Group; 8] = [
        Group::Dns,
        Group::Tcp,
        Group::Tls,
        Group::Sni,
        Group::Udp,
        Group::Quic,
        Group::Relay,
        Group::Lan,
    ];
    fn rank(self) -> usize {
        Self::ALL.iter().position(|g| *g == self).unwrap_or(0)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Dns => "dns",
            Group::Tcp => "tcp",
            Group::Tls => "tls",
            Group::Sni => "sni",
            Group::Udp => "udp",
            Group::Quic => "quic",
            Group::Relay => "relay",
            Group::Lan => "lan",
        }
    }
}

/// What the probed host is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// An iroh relay (the configured ones in `custom` mode).
    Relay,
    /// n0's discovery service.
    Discovery,
    /// The tunnel API `miasma tunnel` needs.
    Tunnel,
    /// A well-known host unrelated to Miasma (control group).
    Neutral,
    /// An endpoint given with `--probe`.
    Custom,
    /// Not tied to one host (UDP, LAN).
    Local,
}

impl Role {
    pub const ALL: [Role; 6] = [
        Role::Relay,
        Role::Discovery,
        Role::Tunnel,
        Role::Neutral,
        Role::Custom,
        Role::Local,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Relay => "relay",
            Role::Discovery => "discovery",
            Role::Tunnel => "tunnel",
            Role::Neutral => "neutral",
            Role::Custom => "custom",
            Role::Local => "local",
        }
    }
}

/// The classified result of one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    /// The system resolver says the name does not exist.
    Nxdomain,
    /// No answer in time (a lookup, a connect, a handshake or a transfer).
    Timeout,
    /// The system resolver's answer shares no address with the public
    /// resolvers' (possible tampering, or a host that answers by location).
    AnswerDiffers,
    /// The system resolver answers, but UDP DNS to public resolvers gets none.
    UdpDnsBlocked,
    /// The port answered with a refusal.
    Refused,
    /// The connection was reset.
    Reset,
    /// No route to the network or host.
    Unreachable,
    /// The connection was reset or closed during the TLS handshake.
    ResetInHandshake,
    /// The certificate comes from a CA that is not a public one (the issuer's
    /// common name is in `detail`).
    NonPublicCa,
    /// The certificate was refused (a public issuer, but not valid for the name).
    CertUntrusted,
    /// The real and the neutral server name got different treatment.
    SniDiffers,
    /// UDP does not get out.
    UdpBlocked,
    /// Something else went wrong (`detail` may say what, in a word).
    Failed,
    /// Not tried because an earlier step shows it cannot work.
    Skipped,
}

impl Outcome {
    pub const ALL: [Outcome; 15] = [
        Outcome::Ok,
        Outcome::Nxdomain,
        Outcome::Timeout,
        Outcome::AnswerDiffers,
        Outcome::UdpDnsBlocked,
        Outcome::Refused,
        Outcome::Reset,
        Outcome::Unreachable,
        Outcome::ResetInHandshake,
        Outcome::NonPublicCa,
        Outcome::CertUntrusted,
        Outcome::SniDiffers,
        Outcome::UdpBlocked,
        Outcome::Failed,
        Outcome::Skipped,
    ];
}

/// One row of the matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeResult {
    /// Stable key: `group:role:host[#n]`.
    pub id: String,
    pub group: Group,
    pub role: Role,
    /// The probed host name (or a fixed label for rows that have none).
    pub target: String,
    /// The path was observed to work.
    pub ok: bool,
    pub outcome: Outcome,
    /// How long the step took.
    pub millis: Option<u64>,
    /// Round trip through the path, where one was measured.
    pub rtt_ms: Option<u64>,
    /// Transfer rate through the path, where one was measured.
    pub kib_per_s: Option<u64>,
    /// A short machine-readable remark (an issuer name, `ip#2`, `real=…`).
    pub detail: Option<String>,
}

/// What the observations suggest. Never a promise that a path will work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdviceCode {
    /// The relays were reached with the current settings.
    RelayObserved,
    /// UDP and QUIC to a relay worked: a direct path may form.
    DirectUdpObserved,
    /// A relay works but UDP does not: transfers go through the relay.
    UdpNotObserved,
    /// The relay's certificate comes from a non-public CA this computer trusts.
    TlsInspectedTrusted,
    /// The same, and this computer does not trust it.
    TlsInspectedUntrusted,
    /// The relay hosts are reachable by TCP but the TLS handshake is cut.
    HandshakeCut,
    /// The relay hosts' names do not resolve as expected.
    DnsProblem,
    /// The discovery service was not reached.
    DiscoveryNotObserved,
    /// Local-network discovery worked.
    LanObserved,
    /// Local-network discovery did not work.
    LanNotObserved,
    /// The tunnel API was reached.
    TunnelObserved,
    /// The tunnel API was not reached.
    TunnelNotObserved,
    /// An endpoint given with `--probe` was reached.
    CustomEndpointObserved,
    /// An endpoint given with `--probe` was not reached.
    CustomEndpointNotObserved,
    /// None of the paths worked.
    NothingObserved,
}

impl AdviceCode {
    pub const ALL: [AdviceCode; 15] = [
        AdviceCode::RelayObserved,
        AdviceCode::DirectUdpObserved,
        AdviceCode::UdpNotObserved,
        AdviceCode::TlsInspectedTrusted,
        AdviceCode::TlsInspectedUntrusted,
        AdviceCode::HandshakeCut,
        AdviceCode::DnsProblem,
        AdviceCode::DiscoveryNotObserved,
        AdviceCode::LanObserved,
        AdviceCode::LanNotObserved,
        AdviceCode::TunnelObserved,
        AdviceCode::TunnelNotObserved,
        AdviceCode::CustomEndpointObserved,
        AdviceCode::CustomEndpointNotObserved,
        AdviceCode::NothingObserved,
    ];
}

/// One suggestion and the configuration keys it concerns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Advice {
    pub code: AdviceCode,
    pub config_keys: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixReport {
    pub schema: u32,
    /// `transport.iroh_mode` as configured when the matrix ran.
    pub iroh_mode: String,
    pub elapsed_ms: u64,
    pub probes: Vec<ProbeResult>,
    pub advice: Vec<Advice>,
}

// ─── Raw events from the network layer ───────────────────────────────────────

/// Why a name did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsFail {
    NxDomain,
    Timeout,
    /// Any other failure (SERVFAIL, REFUSED, a socket error).
    Other,
}

pub type DnsResult = Result<Vec<IpAddr>, DnsFail>;

/// How a TCP connect ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpEvent {
    Connected,
    Refused,
    Reset,
    Timeout,
    Unreachable,
    Other,
}

/// How a TLS handshake ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsEvent {
    /// A certificate was presented.
    Cert {
        issuer: String,
        public_ca: bool,
        trusted: bool,
    },
    Reset,
    Timeout,
    Other,
}

/// What the iroh net report found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UdpEvent {
    pub udp_v4: bool,
    pub udp_v6: bool,
    pub nat_varies: Option<bool>,
    /// Relays reached with QUIC address discovery.
    pub quic_relays: usize,
    /// The report did not finish or could not start.
    pub failed: bool,
}

/// A round trip (and optionally a transfer) through the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEvent {
    Done { rtt_ms: u64, kib_per_s: Option<u64> },
    Timeout,
    Failed,
}

/// A WebSocket upgrade to a user-supplied endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    Upgraded { rtt_ms: Option<u64> },
    Reset,
    Timeout,
    Refused,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanEvent {
    Seen,
    NotSeen,
    Failed,
}

/// Every network call the matrix makes. [`super::reach_net::SystemNet`] is the
/// real one; the tests bring fakes.
#[async_trait]
pub trait Net: Send + Sync {
    async fn system_dns(&self, host: &str, limit: Duration) -> DnsResult;
    async fn udp_dns(&self, resolver: SocketAddr, host: &str, limit: Duration) -> DnsResult;
    async fn tcp(&self, addr: SocketAddr, limit: Duration) -> TcpEvent;
    async fn tls(&self, addr: SocketAddr, sni: &str, limit: Duration) -> TlsEvent;
    async fn udp(&self, limit: Duration) -> UdpEvent;
    async fn relay_path(&self, limit: Duration) -> RelayEvent;
    async fn websocket(&self, addr: SocketAddr, target: &Target, limit: Duration) -> WsEvent;
    async fn lan(&self, limit: Duration) -> LanEvent;
}

// ─── What to probe ───────────────────────────────────────────────────────────

/// One host:port to probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub role: Role,
    /// The request path for a WebSocket probe (`/` for none).
    pub path: String,
    /// TLS (`wss`, `https`) or plain.
    pub tls: bool,
}

impl Target {
    fn new(host: &str, port: u16, role: Role) -> Self {
        Self {
            host: host.to_owned(),
            port,
            role,
            path: "/".into(),
            tls: true,
        }
    }
}

/// An endpoint the user wants tried (`--probe wss://host/path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProbe(pub Target);

impl UserProbe {
    /// `wss://host[:port][/path]`, `ws://…`, `https://…` or `http://…`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (tls, rest) = if let Some(r) = text.strip_prefix("wss://") {
            (true, r)
        } else if let Some(r) = text.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = text.strip_prefix("ws://") {
            (false, r)
        } else if let Some(r) = text.strip_prefix("http://") {
            (false, r)
        } else {
            return Err("expected wss://host[:port][/path] (or ws://, https://, http://)".into());
        };
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err("credentials in the URL are not accepted".into());
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (
                h,
                p.parse::<u16>()
                    .map_err(|_| "the port is not a number".to_owned())?,
            ),
            _ => (authority, if tls { 443 } else { 80 }),
        };
        if host.is_empty()
            || host.len() > 253
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err("the host name is not valid".into());
        }
        Ok(Self(Target {
            host: host.to_ascii_lowercase(),
            port,
            role: Role::Custom,
            path: if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{path}")
            },
            tls,
        }))
    }
}

/// What the matrix probes and how.
#[derive(Debug, Clone)]
pub struct MatrixOptions {
    pub targets: Vec<Target>,
    pub resolvers: [SocketAddr; 2],
    pub neutral_sni: String,
    pub budget: Duration,
    pub iroh_mode: IrohMode,
    /// Run the iroh-based rows (UDP, QUIC, relay round trip, LAN).
    pub run_iroh: bool,
    /// Whether the configuration has relay URLs of its own.
    pub custom_relays: bool,
}

impl MatrixOptions {
    pub fn from_settings(s: &IrohSettings, user: Vec<UserProbe>) -> Self {
        let mut targets: Vec<Target> = Vec::new();
        let mut custom_relays = false;
        match s.mode {
            IrohMode::Off => {}
            IrohMode::N0 => {
                for h in N0_RELAY_HOSTS {
                    targets.push(Target::new(h, 443, Role::Relay));
                }
            }
            IrohMode::Custom => {
                for u in &s.relay_urls {
                    if let Some(t) = relay_target(u) {
                        custom_relays = true;
                        targets.push(t);
                    }
                }
            }
        }
        if s.mode != IrohMode::Off && s.discovery {
            targets.push(Target::new(N0_DISCOVERY_HOST, 443, Role::Discovery));
        }
        targets.push(Target::new(TUNNEL_HOST, 443, Role::Tunnel));
        for h in NEUTRAL_HOSTS {
            targets.push(Target::new(h, 443, Role::Neutral));
        }
        targets.extend(user.into_iter().map(|u| u.0));
        Self {
            targets,
            resolvers: PUBLIC_RESOLVERS.map(|(ip, port)| SocketAddr::from((ip, port))),
            neutral_sni: NEUTRAL_SNI.to_owned(),
            budget: TOTAL_BUDGET,
            iroh_mode: s.mode,
            run_iroh: s.mode != IrohMode::Off,
            custom_relays,
        }
    }
}

/// The host and port of a relay URL (`https://host[:port][/…]`).
fn relay_target(url: &str) -> Option<Target> {
    let u = UserProbe::parse(url.trim()).ok()?;
    let mut t = u.0;
    t.role = Role::Relay;
    Some(t)
}

// ─── Judging (pure) ──────────────────────────────────────────────────────────

fn v4_set(r: &DnsResult) -> Vec<std::net::Ipv4Addr> {
    match r {
        Ok(ips) => v4_only(ips),
        Err(_) => Vec::new(),
    }
}

/// The outcome of resolving one name: the system resolver against the public
/// resolvers asked over UDP.
pub fn classify_dns(sys: &DnsResult, public: &[DnsResult]) -> (Outcome, Option<String>) {
    match sys {
        Err(DnsFail::NxDomain) => {
            let detail = public
                .iter()
                .any(|r| r.as_ref().is_ok_and(|v| !v.is_empty()))
                .then(|| "public_resolvers_answer".to_owned());
            (Outcome::Nxdomain, detail)
        }
        Err(DnsFail::Timeout) => (Outcome::Timeout, None),
        Err(DnsFail::Other) => (Outcome::Failed, None),
        Ok(ips) => {
            let sys4 = v4_only(ips);
            let answered: Vec<Vec<std::net::Ipv4Addr>> = public
                .iter()
                .map(v4_set)
                .filter(|v| !v.is_empty())
                .collect();
            if !answered.is_empty()
                && !sys4.is_empty()
                && !answered
                    .iter()
                    .any(|a| a.iter().any(|ip| sys4.contains(ip)))
            {
                return (Outcome::AnswerDiffers, None);
            }
            if answered.is_empty()
                && !public.is_empty()
                && public.iter().all(|r| matches!(r, Err(DnsFail::NxDomain)))
            {
                return (
                    Outcome::AnswerDiffers,
                    Some("public_resolvers_say_nxdomain".into()),
                );
            }
            if !public.is_empty() && public.iter().all(|r| matches!(r, Err(DnsFail::Timeout))) {
                return (Outcome::UdpDnsBlocked, None);
            }
            (Outcome::Ok, None)
        }
    }
}

/// The outcome of one TCP connect.
pub fn classify_tcp(e: &TcpEvent) -> Outcome {
    match e {
        TcpEvent::Connected => Outcome::Ok,
        TcpEvent::Refused => Outcome::Refused,
        TcpEvent::Reset => Outcome::Reset,
        TcpEvent::Timeout => Outcome::Timeout,
        TcpEvent::Unreachable => Outcome::Unreachable,
        TcpEvent::Other => Outcome::Failed,
    }
}

/// An issuer name made safe to print: control characters dropped, 64 characters.
pub fn clean_issuer(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}

/// The outcome of one TLS handshake with the real server name.
pub fn classify_tls(e: &TlsEvent) -> (Outcome, bool, Option<String>) {
    match e {
        TlsEvent::Cert {
            public_ca: true,
            trusted: true,
            ..
        } => (Outcome::Ok, true, None),
        TlsEvent::Cert {
            public_ca: false,
            trusted,
            issuer,
        } => (
            Outcome::NonPublicCa,
            *trusted,
            Some(format!(
                "issuer={}; trusted={}",
                clean_issuer(issuer),
                trusted
            )),
        ),
        TlsEvent::Cert { .. } => (Outcome::CertUntrusted, false, None),
        TlsEvent::Reset => (Outcome::ResetInHandshake, false, None),
        TlsEvent::Timeout => (Outcome::Timeout, false, None),
        TlsEvent::Other => (Outcome::Failed, false, None),
    }
}

fn tls_class(e: &TlsEvent) -> &'static str {
    match e {
        TlsEvent::Cert { .. } => "handshake",
        TlsEvent::Reset => "reset",
        TlsEvent::Timeout => "timeout",
        TlsEvent::Other => "failed",
    }
}

/// Whether the real and the neutral server name were treated alike.
pub fn classify_sni(real: &TlsEvent, neutral: &TlsEvent) -> (Outcome, Option<String>) {
    let (r, n) = (tls_class(real), tls_class(neutral));
    if r == n {
        (Outcome::Ok, Some(format!("both={r}")))
    } else {
        (Outcome::SniDiffers, Some(format!("real={r}; neutral={n}")))
    }
}

fn row(
    group: Group,
    role: Role,
    target: &str,
    suffix: Option<usize>,
    ok: bool,
    outcome: Outcome,
) -> ProbeResult {
    let id = match suffix {
        Some(n) => format!("{}:{}:{}#{}", group.as_str(), role.as_str(), target, n),
        None => format!("{}:{}:{}", group.as_str(), role.as_str(), target),
    };
    ProbeResult {
        id,
        group,
        role,
        target: target.to_owned(),
        ok,
        outcome,
        millis: None,
        rtt_ms: None,
        kib_per_s: None,
        detail: None,
    }
}

fn skipped(
    group: Group,
    role: Role,
    target: &str,
    suffix: Option<usize>,
    why: &str,
) -> ProbeResult {
    let mut r = row(group, role, target, suffix, false, Outcome::Skipped);
    r.detail = Some(why.to_owned());
    r
}

fn ms(t: Instant) -> Option<u64> {
    Some(t.elapsed().as_millis() as u64)
}

// ─── Advice ──────────────────────────────────────────────────────────────────

/// Map the observations to suggestions. Each says what was observed; none says
/// a path will work.
pub fn advise(probes: &[ProbeResult], iroh_mode: IrohMode, run_iroh: bool) -> Vec<Advice> {
    let any = |g: Group, r: Role, f: &dyn Fn(&ProbeResult) -> bool| {
        probes.iter().any(|p| p.group == g && p.role == r && f(p))
    };
    let all_roles =
        |g: Group, f: &dyn Fn(&ProbeResult) -> bool| probes.iter().any(|p| p.group == g && f(p));
    let mut out: Vec<Advice> = Vec::new();
    let mut add = |code: AdviceCode, keys: &[&'static str]| {
        out.push(Advice {
            code,
            config_keys: keys.to_vec(),
        })
    };

    let relay_path_ok = all_roles(Group::Relay, &|p| p.role == Role::Relay && p.ok);
    let relay_tls_ok = any(Group::Tls, Role::Relay, &|p| p.ok);
    let relay_ok = relay_path_ok || relay_tls_ok;
    let udp_ok = all_roles(Group::Udp, &|p| p.ok) && all_roles(Group::Quic, &|p| p.ok);
    let tunnel_ok = any(Group::Tcp, Role::Tunnel, &|p| p.ok);
    let custom_ok = probes
        .iter()
        .any(|p| p.role == Role::Custom && matches!(p.group, Group::Relay) && p.ok);
    let custom_tried = probes.iter().any(|p| p.role == Role::Custom);
    let lan_ok = all_roles(Group::Lan, &|p| p.ok);
    let lan_tried = all_roles(Group::Lan, &|p| p.outcome != Outcome::Skipped);

    if relay_ok {
        add(AdviceCode::RelayObserved, &["transport.iroh_mode"]);
    }
    if run_iroh && relay_ok {
        if udp_ok {
            add(AdviceCode::DirectUdpObserved, &[]);
        } else {
            add(AdviceCode::UdpNotObserved, &[]);
        }
    }
    let relay_cert = |trusted: bool| {
        any(Group::Tls, Role::Relay, &|p| {
            p.outcome == Outcome::NonPublicCa
                && p.detail
                    .as_deref()
                    .is_some_and(|d| d.ends_with(if trusted { "true" } else { "false" }))
        })
    };
    if relay_cert(false) {
        add(
            AdviceCode::TlsInspectedUntrusted,
            &["transport.iroh_extra_ca_pem"],
        );
    } else if relay_cert(true) {
        add(AdviceCode::TlsInspectedTrusted, &[]);
    }
    let relay_tcp_ok = any(Group::Tcp, Role::Relay, &|p| p.ok);
    let handshake_cut = any(Group::Tls, Role::Relay, &|p| {
        matches!(p.outcome, Outcome::ResetInHandshake | Outcome::Timeout)
    });
    if iroh_mode != IrohMode::Off && relay_tcp_ok && handshake_cut && !relay_tls_ok {
        add(
            AdviceCode::HandshakeCut,
            &["transport.iroh_mode", "transport.iroh_relay_urls"],
        );
    }
    let dns_bad = any(Group::Dns, Role::Relay, &|p| {
        matches!(
            p.outcome,
            Outcome::Nxdomain | Outcome::Timeout | Outcome::AnswerDiffers | Outcome::Failed
        )
    });
    if dns_bad {
        add(AdviceCode::DnsProblem, &["transport.iroh_relay_urls"]);
    }
    let discovery_tried = probes.iter().any(|p| p.role == Role::Discovery);
    if discovery_tried
        && !any(Group::Tls, Role::Discovery, &|p| p.ok)
        && !any(Group::Tcp, Role::Discovery, &|p| p.ok)
    {
        add(
            AdviceCode::DiscoveryNotObserved,
            &["transport.iroh_discovery", "transport.iroh_relay_urls"],
        );
    }
    if lan_tried {
        if lan_ok {
            add(AdviceCode::LanObserved, &["transport.iroh_lan_discovery"]);
        } else {
            add(
                AdviceCode::LanNotObserved,
                &["transport.iroh_lan_discovery"],
            );
        }
    }
    if tunnel_ok {
        add(AdviceCode::TunnelObserved, &[]);
    } else {
        add(AdviceCode::TunnelNotObserved, &[]);
    }
    if custom_tried {
        if custom_ok {
            add(AdviceCode::CustomEndpointObserved, &[]);
        } else {
            add(AdviceCode::CustomEndpointNotObserved, &[]);
        }
    }
    if !relay_ok && !tunnel_ok && !custom_ok && !lan_ok {
        add(AdviceCode::NothingObserved, &[]);
    }
    out
}

// ─── Running ─────────────────────────────────────────────────────────────────

struct Ctx<'a> {
    net: &'a dyn Net,
    sem: Semaphore,
    deadline: Instant,
}

impl Ctx<'_> {
    fn left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Run one network call under the concurrency cap, with the smaller of
    /// `want` and what is left of the budget. `None`: the budget is used up.
    async fn gated<F, Fut, T>(&self, want: Duration, f: F) -> Option<T>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: Future<Output = T>,
    {
        let _permit = self.sem.acquire().await.ok()?;
        let limit = want.min(self.left());
        if limit.is_zero() {
            return None;
        }
        Some(f(limit).await)
    }
}

struct Resolved {
    ips: Vec<IpAddr>,
    from_public: bool,
}

/// Run every probe and judge the result.
pub async fn run_matrix(net: &dyn Net, opts: &MatrixOptions) -> MatrixReport {
    let started = Instant::now();
    let ctx = Ctx {
        net,
        sem: Semaphore::new(MAX_CONCURRENCY),
        deadline: started + opts.budget,
    };
    let mut rows: Vec<(usize, ProbeResult)> = Vec::new();

    // One entry per distinct host, in the order given.
    let mut hosts: Vec<&Target> = Vec::new();
    for t in &opts.targets {
        if !hosts.iter().any(|h| h.host == t.host) {
            hosts.push(t);
        }
    }

    // Stage 1: DNS.
    let dns: Vec<(usize, ProbeResult, Resolved)> = stream::iter(
        hosts
            .iter()
            .enumerate()
            .map(|(i, t)| dns_job(&ctx, opts, i, t)),
    )
    .buffer_unordered(MAX_CONCURRENCY)
    .collect()
    .await;
    let mut resolved: std::collections::HashMap<String, Resolved> = Default::default();
    for (i, r, res) in dns {
        resolved.insert(r.target.clone(), res);
        rows.push((i, r));
    }

    // Stage 2: TCP to the first addresses of every target.
    struct TcpJob<'a> {
        order: usize,
        target: &'a Target,
        n: usize,
        addr: Option<SocketAddr>,
        via_public: bool,
    }
    let mut jobs = Vec::new();
    for (ti, t) in opts.targets.iter().enumerate() {
        let (ips, via_public) = resolved
            .get(&t.host)
            .map(|r| (r.ips.clone(), r.from_public))
            .unwrap_or_default();
        let take = if t.role == Role::Neutral {
            1
        } else {
            MAX_ADDRS
        };
        if ips.is_empty() {
            jobs.push(TcpJob {
                order: ti * 10,
                target: t,
                n: 1,
                addr: None,
                via_public,
            });
        }
        for (n, ip) in ips.into_iter().take(take).enumerate() {
            jobs.push(TcpJob {
                order: ti * 10 + n,
                target: t,
                n: n + 1,
                addr: Some(SocketAddr::new(ip, t.port)),
                via_public,
            });
        }
    }
    let tcp: Vec<(usize, ProbeResult, Option<SocketAddr>)> =
        stream::iter(jobs.into_iter().map(|j| {
            let ctx = &ctx;
            async move {
                let t = j.target;
                let Some(addr) = j.addr else {
                    return (
                        j.order,
                        skipped(Group::Tcp, t.role, &t.host, Some(j.n), "no_address"),
                        None,
                    );
                };
                let t0 = Instant::now();
                let ev = ctx.gated(TCP_LIMIT, |l| ctx.net.tcp(addr, l)).await;
                let mut r = match ev {
                    Some(ev) => {
                        let o = classify_tcp(&ev);
                        row(Group::Tcp, t.role, &t.host, Some(j.n), o == Outcome::Ok, o)
                    }
                    None => skipped(Group::Tcp, t.role, &t.host, Some(j.n), "time_budget"),
                };
                r.millis = ms(t0);
                if j.via_public {
                    r.detail = Some("address_from_public_resolver".into());
                }
                let ok = r.ok;
                (j.order, r, ok.then_some(addr))
            }
        }))
        .buffer_unordered(MAX_CONCURRENCY)
        .collect()
        .await;
    let mut reachable: std::collections::HashMap<String, SocketAddr> = Default::default();
    let mut tcp_sorted = tcp;
    tcp_sorted.sort_by_key(|(o, _, _)| *o);
    for (o, r, addr) in tcp_sorted {
        if let Some(a) = addr {
            reachable.entry(r.target.clone()).or_insert(a);
        }
        rows.push((1000 + o, r));
    }
    let relay_reachable = opts
        .targets
        .iter()
        .any(|t| t.role == Role::Relay && reachable.contains_key(&t.host));

    // Stage 3: everything that needs a reachable address, plus the iroh rows.
    enum Job<'a> {
        Tls(usize, &'a Target),
        Neutral(&'a Target),
        Ws(usize, &'a Target),
        Udp,
        Relay,
        Lan,
    }
    enum Done {
        Rows(Vec<(usize, ProbeResult)>),
        Both((usize, ProbeResult), String, TlsEvent),
        Neutral(String, TlsEvent),
    }
    let mut jobs3: Vec<Job> = Vec::new();
    if opts.run_iroh {
        jobs3.push(Job::Relay);
        jobs3.push(Job::Udp);
        jobs3.push(Job::Lan);
    }
    for (ti, t) in opts.targets.iter().enumerate() {
        match t.role {
            Role::Relay | Role::Discovery if t.tls => jobs3.push(Job::Tls(ti, t)),
            Role::Custom => {
                if t.tls {
                    jobs3.push(Job::Tls(ti, t));
                }
                jobs3.push(Job::Ws(ti, t));
            }
            _ => {}
        }
    }
    if let Some(t) = opts
        .targets
        .iter()
        .find(|t| t.role == Role::Relay && t.tls && reachable.contains_key(&t.host))
    {
        jobs3.push(Job::Neutral(t));
    }
    let done: Vec<Done> = stream::iter(jobs3.into_iter().map(|job| {
        let ctx = &ctx;
        let reachable = &reachable;
        async move {
            match job {
                Job::Tls(ti, t) => {
                    let Some(addr) = reachable.get(&t.host).copied() else {
                        return Done::Rows(vec![(
                            2000 + ti,
                            skipped(Group::Tls, t.role, &t.host, None, "no_tcp"),
                        )]);
                    };
                    let t0 = Instant::now();
                    let ev = ctx
                        .gated(TLS_LIMIT, |l| ctx.net.tls(addr, &t.host, l))
                        .await;
                    let mut r = match &ev {
                        Some(ev) => {
                            let (o, ok, d) = classify_tls(ev);
                            let mut r = row(Group::Tls, t.role, &t.host, None, ok, o);
                            r.detail = d;
                            r
                        }
                        None => skipped(Group::Tls, t.role, &t.host, None, "time_budget"),
                    };
                    r.millis = ms(t0);
                    // The raw event is kept for the SNI comparison.
                    match ev {
                        Some(ev) => Done::Both((2000 + ti, r), t.host.clone(), ev),
                        None => Done::Rows(vec![(2000 + ti, r)]),
                    }
                }
                Job::Neutral(t) => {
                    let addr = reachable[&t.host];
                    let ev = ctx
                        .gated(TLS_LIMIT, |l| ctx.net.tls(addr, &opts.neutral_sni, l))
                        .await
                        .unwrap_or(TlsEvent::Timeout);
                    Done::Neutral(t.host.clone(), ev)
                }
                Job::Ws(ti, t) => {
                    let Some(addr) = reachable.get(&t.host).copied() else {
                        return Done::Rows(vec![(
                            3000 + ti,
                            skipped(Group::Relay, t.role, &t.host, None, "no_tcp"),
                        )]);
                    };
                    let t0 = Instant::now();
                    let ev = ctx.gated(WS_LIMIT, |l| ctx.net.websocket(addr, t, l)).await;
                    let (o, rtt) = match ev {
                        Some(WsEvent::Upgraded { rtt_ms }) => (Outcome::Ok, rtt_ms),
                        Some(WsEvent::Reset) => (Outcome::ResetInHandshake, None),
                        Some(WsEvent::Timeout) => (Outcome::Timeout, None),
                        Some(WsEvent::Refused) => (Outcome::Refused, None),
                        Some(WsEvent::Other) => (Outcome::Failed, None),
                        None => (Outcome::Skipped, None),
                    };
                    let mut r = row(Group::Relay, t.role, &t.host, None, o == Outcome::Ok, o);
                    r.millis = ms(t0);
                    r.rtt_ms = rtt;
                    Done::Rows(vec![(3000 + ti, r)])
                }
                Job::Udp => {
                    let t0 = Instant::now();
                    let ev = ctx.gated(UDP_LIMIT, |l| ctx.net.udp(l)).await;
                    let mut out = Vec::new();
                    let (udp_row, quic_row) = match ev {
                        Some(e) => udp_rows(&e),
                        None => (
                            skipped(Group::Udp, Role::Local, "udp", None, "time_budget"),
                            skipped(Group::Quic, Role::Relay, "quic", None, "time_budget"),
                        ),
                    };
                    let mut u = udp_row;
                    u.millis = ms(t0);
                    out.push((4000, u));
                    out.push((4001, quic_row));
                    Done::Rows(out)
                }
                Job::Relay => {
                    if !relay_reachable {
                        return Done::Rows(vec![(
                            5000,
                            skipped(
                                Group::Relay,
                                Role::Relay,
                                "iroh-relay",
                                None,
                                "relay_unreachable",
                            ),
                        )]);
                    }
                    let t0 = Instant::now();
                    let ev = ctx.gated(RELAY_LIMIT, |l| ctx.net.relay_path(l)).await;
                    let mut r = match ev {
                        Some(RelayEvent::Done { rtt_ms, kib_per_s }) => {
                            let mut r = row(
                                Group::Relay,
                                Role::Relay,
                                "iroh-relay",
                                None,
                                true,
                                Outcome::Ok,
                            );
                            r.rtt_ms = Some(rtt_ms);
                            r.kib_per_s = kib_per_s;
                            r
                        }
                        Some(RelayEvent::Timeout) => row(
                            Group::Relay,
                            Role::Relay,
                            "iroh-relay",
                            None,
                            false,
                            Outcome::Timeout,
                        ),
                        Some(RelayEvent::Failed) => row(
                            Group::Relay,
                            Role::Relay,
                            "iroh-relay",
                            None,
                            false,
                            Outcome::Failed,
                        ),
                        None => {
                            skipped(Group::Relay, Role::Relay, "iroh-relay", None, "time_budget")
                        }
                    };
                    r.millis = ms(t0);
                    Done::Rows(vec![(5000, r)])
                }
                Job::Lan => {
                    let t0 = Instant::now();
                    let ev = ctx.gated(LAN_LIMIT, |l| ctx.net.lan(l)).await;
                    let (ok, o) = match ev {
                        Some(LanEvent::Seen) => (true, Outcome::Ok),
                        Some(LanEvent::NotSeen) => (false, Outcome::Timeout),
                        Some(LanEvent::Failed) => (false, Outcome::Failed),
                        None => (false, Outcome::Skipped),
                    };
                    let mut r = row(Group::Lan, Role::Local, "mdns", None, ok, o);
                    r.millis = ms(t0);
                    Done::Rows(vec![(6000, r)])
                }
            }
        }
    }))
    .buffer_unordered(MAX_CONCURRENCY)
    .collect()
    .await;

    let mut real_events: std::collections::HashMap<String, TlsEvent> = Default::default();
    let mut neutral: Option<(String, TlsEvent)> = None;
    for d in done {
        match d {
            Done::Rows(rs) => rows.extend(rs),
            Done::Both(row, host, ev) => {
                rows.push(row);
                real_events.insert(host, ev);
            }
            Done::Neutral(h, ev) => neutral = Some((h, ev)),
        }
    }
    if let Some((host, n_ev)) = neutral {
        let role = opts
            .targets
            .iter()
            .find(|t| t.host == host)
            .map(|t| t.role)
            .unwrap_or(Role::Relay);
        let r = match real_events.get(&host) {
            Some(real) => {
                let (o, d) = classify_sni(real, &n_ev);
                let mut r = row(Group::Sni, role, &host, None, o == Outcome::Ok, o);
                r.detail = d;
                r
            }
            None => skipped(Group::Sni, role, &host, None, "no_real_handshake"),
        };
        rows.push((2500, r));
    }

    rows.sort_by_key(|(o, r)| (r.group.rank(), *o));
    let probes: Vec<ProbeResult> = rows.into_iter().map(|(_, r)| r).collect();
    let advice = advise(&probes, opts.iroh_mode, opts.run_iroh);
    MatrixReport {
        schema: SCHEMA_VERSION,
        iroh_mode: opts.iroh_mode.as_str().to_owned(),
        elapsed_ms: started.elapsed().as_millis() as u64,
        probes,
        advice,
    }
}

fn udp_rows(e: &UdpEvent) -> (ProbeResult, ProbeResult) {
    let udp_ok = e.udp_v4 || e.udp_v6;
    let mut u = row(
        Group::Udp,
        Role::Local,
        "udp",
        None,
        udp_ok,
        if udp_ok {
            Outcome::Ok
        } else if e.failed {
            Outcome::Failed
        } else {
            Outcome::UdpBlocked
        },
    );
    let mut parts = Vec::new();
    parts.push(format!("v4={}", e.udp_v4));
    parts.push(format!("v6={}", e.udp_v6));
    if let Some(v) = e.nat_varies {
        parts.push(format!("nat_mapping_varies={v}"));
    }
    u.detail = Some(parts.join("; "));
    let quic_ok = e.quic_relays > 0;
    let q = row(
        Group::Quic,
        Role::Relay,
        "quic",
        None,
        quic_ok,
        if quic_ok {
            Outcome::Ok
        } else if e.failed {
            Outcome::Failed
        } else {
            Outcome::UdpBlocked
        },
    );
    (u, q)
}

async fn dns_job(
    ctx: &Ctx<'_>,
    opts: &MatrixOptions,
    order: usize,
    t: &Target,
) -> (usize, ProbeResult, Resolved) {
    let t0 = Instant::now();
    let host = t.host.as_str();
    // An IP literal needs no lookup.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let mut r = row(Group::Dns, t.role, host, None, true, Outcome::Ok);
        r.detail = Some("ip_literal".into());
        return (
            order,
            r,
            Resolved {
                ips: vec![ip],
                from_public: false,
            },
        );
    }
    let sys = async { ctx.gated(DNS_LIMIT, |l| ctx.net.system_dns(host, l)).await };
    let p0 = async {
        ctx.gated(DNS_LIMIT, |l| ctx.net.udp_dns(opts.resolvers[0], host, l))
            .await
    };
    let p1 = async {
        ctx.gated(DNS_LIMIT, |l| ctx.net.udp_dns(opts.resolvers[1], host, l))
            .await
    };
    let (sys, p0, p1) = futures::join!(sys, p0, p1);
    let Some(sys) = sys else {
        return (
            order,
            skipped(Group::Dns, t.role, host, None, "time_budget"),
            Resolved {
                ips: Vec::new(),
                from_public: false,
            },
        );
    };
    let public: Vec<DnsResult> = [p0, p1].into_iter().flatten().collect();
    let (outcome, detail) = classify_dns(&sys, &public);
    let ok = matches!(outcome, Outcome::Ok | Outcome::UdpDnsBlocked);
    let mut r = row(Group::Dns, t.role, host, None, ok, outcome);
    r.detail = detail;
    r.millis = ms(t0);
    // Addresses to try: the system resolver's, else what a public resolver
    // said, so a lookup that is cut can still be told apart from a path that is.
    let (ips, from_public) = match &sys {
        Ok(v) if !v.is_empty() => (v.clone(), false),
        _ => (
            public
                .iter()
                .find_map(|r| r.as_ref().ok().filter(|v| !v.is_empty()).cloned())
                .unwrap_or_default(),
            true,
        ),
    };
    (order, r, Resolved { ips, from_public })
}

#[cfg(test)]
mod tests;
