//! Network path diagnosis for the iroh transport (`miasma netcheck`).
//!
//! A receive can fail for reasons that look the same from outside: UDP is
//! blocked, the NAT maps a different port per destination (hole punching then
//! fails), a TLS-inspecting proxy distrusts the relay, or nothing but HTTPS gets
//! out. This module measures each of them on a throw-away client endpoint and
//! reduces the result to one [`Verdict`], so a failed transfer can be explained
//! instead of guessed at.
//!
//! Nothing here sends user data. The probes are iroh's own net report (QUIC
//! address discovery against the relays), a TCP connect to the relay hosts on
//! 443, and a TCP connect to Cloudflare's tunnel API on 443 (the path the
//! `--via wss://…trycloudflare.com` fallback needs).

use std::time::{Duration, Instant};

use iroh::Watcher;
use serde::Serialize;
use tokio::net::{lookup_host, TcpStream};

use super::iroh_direct::{endpoint_builder, IrohSettings};
use crate::MiasmaError;

/// Hosts probed on 443 when the net report names no relay of its own.
const FALLBACK_RELAY_HOSTS: &[&str] = &["use1-1.relay.n0.iroh.link", "aps1-1.relay.n0.iroh.link"];
/// Needed by `miasma tunnel` and the `--via wss://…trycloudflare.com` path.
const TUNNEL_HOST: &str = "api.trycloudflare.com";

/// One TCP-connect probe.
#[derive(Debug, Clone, Serialize)]
pub struct TcpProbe {
    pub host: String,
    pub port: u16,
    pub ok: bool,
    pub millis: Option<u64>,
    /// Short reason when `ok` is false (`dns`, `timeout`, `refused`, …).
    pub error: Option<String>,
}

/// What the measurements add up to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// UDP works and the NAT keeps one mapping per source port: a direct
    /// (hole-punched) path is likely, relay is the backup.
    DirectLikely,
    /// The relay is reachable but a direct path is unlikely (UDP blocked, or a
    /// per-destination NAT mapping). Transfers go through the relay: slow.
    RelayOnly,
    /// No relay, but HTTPS to the internet works: use a tunnel (`--via wss://…`).
    HttpsOnly,
    /// Nothing reached the network.
    Offline,
}

/// Facts a caller may want to explain in words (the CLI maps each to a message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Note {
    UdpBlocked,
    NatMappingVaries,
    CaptivePortal,
    ProxyInUse,
    RelayTcpButNoRelay,
    TunnelApiUnreachable,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetcheckReport {
    pub udp_v4: bool,
    pub udp_v6: bool,
    /// `Some(true)`: the public port differs per destination (symmetric-style
    /// NAT, hole punching rarely works). `None`: not measurable.
    pub nat_mapping_varies: Option<bool>,
    pub captive_portal: Option<bool>,
    /// The endpoint got a home relay connection (relay TLS and HTTP upgrade OK).
    pub relay_connected: bool,
    pub preferred_relay: Option<String>,
    /// `(relay URL, round trip in ms)`.
    pub relay_latency: Vec<(String, u64)>,
    pub proxy_from_env: bool,
    pub tcp: Vec<TcpProbe>,
    pub verdict: Verdict,
    pub notes: Vec<Note>,
}

/// Run every probe, at most `limit` for the iroh part.
pub async fn run_netcheck(
    settings: &IrohSettings,
    limit: Duration,
) -> Result<NetcheckReport, MiasmaError> {
    let endpoint = endpoint_builder(None, settings, false)?
        .bind()
        .await
        .map_err(|e| MiasmaError::Network(format!("cannot start the iroh endpoint: {e}")))?;

    let report = tokio::time::timeout(limit, endpoint.net_report().initialized())
        .await
        .ok();
    let relay_connected = tokio::time::timeout(limit, endpoint.online()).await.is_ok();
    endpoint.close().await;

    let (mut udp_v4, mut udp_v6, mut varies, mut captive) = (false, false, None, None);
    let mut preferred_relay = None;
    let mut relay_latency: Vec<(String, u64)> = Vec::new();
    if let Some(r) = &report {
        udp_v4 = r.udp_v4;
        udp_v6 = r.udp_v6;
        varies = r.mapping_varies_by_dest();
        captive = r.captive_portal;
        preferred_relay = r.preferred_relay.as_ref().map(|u| u.to_string());
        relay_latency = r
            .relay_latency
            .iter()
            .map(|(_, url, d)| (url.to_string(), d.as_millis() as u64))
            .collect();
        relay_latency.sort();
        relay_latency.dedup_by(|a, b| a.0 == b.0);
    }

    let mut hosts: Vec<String> = relay_latency
        .iter()
        .filter_map(|(u, _)| host_of(u))
        .collect();
    if hosts.is_empty() {
        hosts = FALLBACK_RELAY_HOSTS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
    }
    hosts.dedup();
    let mut tcp = Vec::new();
    for h in &hosts {
        tcp.push(probe_tcp(h, 443, Duration::from_secs(6)).await);
    }
    tcp.push(probe_tcp(TUNNEL_HOST, 443, Duration::from_secs(6)).await);

    let proxy = settings.proxy_from_env;
    let any_relay_tcp = tcp[..tcp.len() - 1].iter().any(|p| p.ok);
    let tunnel_tcp = tcp.last().is_some_and(|p| p.ok);
    let (verdict, notes) = judge(
        udp_v4 || udp_v6,
        varies,
        captive,
        relay_connected,
        any_relay_tcp,
        tunnel_tcp,
        proxy,
    );
    Ok(NetcheckReport {
        udp_v4,
        udp_v6,
        nat_mapping_varies: varies,
        captive_portal: captive,
        relay_connected,
        preferred_relay,
        relay_latency,
        proxy_from_env: proxy,
        tcp,
        verdict,
        notes,
    })
}

/// The decision, separate from the measuring so it can be tested.
pub fn judge(
    udp: bool,
    nat_varies: Option<bool>,
    captive: Option<bool>,
    relay_connected: bool,
    relay_tcp_ok: bool,
    tunnel_tcp_ok: bool,
    proxy: bool,
) -> (Verdict, Vec<Note>) {
    let mut notes = Vec::new();
    if !udp {
        notes.push(Note::UdpBlocked);
    }
    if nat_varies == Some(true) {
        notes.push(Note::NatMappingVaries);
    }
    if captive == Some(true) {
        notes.push(Note::CaptivePortal);
    }
    if proxy {
        notes.push(Note::ProxyInUse);
    }
    if relay_tcp_ok && !relay_connected {
        notes.push(Note::RelayTcpButNoRelay);
    }
    if !tunnel_tcp_ok {
        notes.push(Note::TunnelApiUnreachable);
    }
    let verdict = if relay_connected {
        if udp && nat_varies != Some(true) {
            Verdict::DirectLikely
        } else {
            Verdict::RelayOnly
        }
    } else if relay_tcp_ok || tunnel_tcp_ok {
        Verdict::HttpsOnly
    } else {
        Verdict::Offline
    };
    (verdict, notes)
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let host = rest.split(['/', ':']).next()?.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_owned())
}

async fn probe_tcp(host: &str, port: u16, limit: Duration) -> TcpProbe {
    let started = Instant::now();
    let fail = |why: &str| TcpProbe {
        host: host.to_owned(),
        port,
        ok: false,
        millis: None,
        error: Some(why.to_owned()),
    };
    let addrs = match tokio::time::timeout(limit, lookup_host((host, port))).await {
        Err(_) => return fail("timeout"),
        Ok(Err(_)) => return fail("dns"),
        Ok(Ok(a)) => a.collect::<Vec<_>>(),
    };
    if addrs.is_empty() {
        return fail("dns");
    }
    for addr in addrs {
        let left = limit.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                return TcpProbe {
                    host: host.to_owned(),
                    port,
                    ok: true,
                    millis: Some(started.elapsed().as_millis() as u64),
                    error: None,
                }
            }
            Ok(Err(_)) => continue,
            Err(_) => break,
        }
    }
    fail(if started.elapsed() >= limit {
        "timeout"
    } else {
        "refused"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_network_is_direct_likely() {
        let (v, n) = judge(true, Some(false), Some(false), true, true, true, false);
        assert_eq!(v, Verdict::DirectLikely);
        assert!(n.is_empty());
    }

    #[test]
    fn udp_blocked_with_relay_is_relay_only() {
        let (v, n) = judge(false, None, None, true, true, true, false);
        assert_eq!(v, Verdict::RelayOnly);
        assert!(n.contains(&Note::UdpBlocked));
    }

    #[test]
    fn varying_nat_mapping_is_relay_only() {
        let (v, n) = judge(true, Some(true), None, true, true, true, false);
        assert_eq!(v, Verdict::RelayOnly);
        assert!(n.contains(&Note::NatMappingVaries));
    }

    #[test]
    fn https_only_when_relay_fails_but_tcp_443_works() {
        let (v, n) = judge(false, None, None, false, true, true, true);
        assert_eq!(v, Verdict::HttpsOnly);
        assert!(n.contains(&Note::RelayTcpButNoRelay));
        assert!(n.contains(&Note::ProxyInUse));
    }

    #[test]
    fn nothing_reachable_is_offline() {
        let (v, _) = judge(false, None, None, false, false, false, false);
        assert_eq!(v, Verdict::Offline);
    }

    #[test]
    fn host_of_strips_scheme_port_and_trailing_dot() {
        assert_eq!(
            host_of("https://aps1-1.relay.n0.iroh.link./").as_deref(),
            Some("aps1-1.relay.n0.iroh.link")
        );
        assert_eq!(
            host_of("https://r.example:8443/x").as_deref(),
            Some("r.example")
        );
    }
}
