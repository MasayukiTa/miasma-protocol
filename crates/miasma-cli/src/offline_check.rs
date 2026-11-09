//! `miasma offline-check`: a one-command self-check for offline delivery.
//!
//! It answers one question without sending any user data: if a message or file
//! were deposited right now for a contact who is offline, would it actually be
//! held somewhere they can collect it later? It reads only local config, the
//! running daemon's status snapshot, and the number of eligible contacts. It
//! never opens a transfer, never contacts a holder, and never touches message
//! or file content.
//!
//! The verdict logic lives in [`evaluate`], a pure function over a plain input
//! struct so it can be unit-tested without a daemon or a network.

use std::path::Path;

use anyhow::Result;
use miasma_core::config::NodeConfig;

/// Why the configured bootstrap list cannot, by itself, reach a holder at
/// another site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapReach {
    /// No bootstrap peer is configured. Holder discovery relies on iroh.
    NoneConfigured,
    /// Every configured bootstrap peer is a private / non-routable literal, so
    /// a node at another site cannot use it to find a holder.
    OnlyPrivate,
    /// At least one configured bootstrap peer is a routable literal or a
    /// hostname (a `/dns4/...` form).
    HasPublic,
}

/// Plain inputs gathered from config, the daemon status snapshot, and the
/// contact list. Collected by [`collect`]; judged by [`evaluate`].
#[derive(Debug, Clone)]
pub struct OfflineCheckInput {
    /// Configured libp2p bootstrap multiaddrs (from `NodeConfig`).
    pub bootstrap_peers: Vec<String>,
    /// Whether the daemon answered a status request.
    pub daemon_running: bool,
    /// libp2p connected peer count from the daemon (`None` if no daemon).
    pub peer_count: Option<usize>,
    /// Whether the iroh transport is present in the daemon status.
    pub iroh_present: bool,
    /// Whether iroh's home relay is currently connected.
    pub iroh_relay_connected: bool,
    /// Whether chat custody (holding deposits for contacts) is enabled.
    pub custody_enabled: bool,
    pub file_custody_enabled: bool,
    /// Configured number of custody copies to aim for.
    pub custody_copies: usize,
    /// Contacts that can act as a holder for a deposit: they have a usable iroh
    /// endpoint and we are allowed both to send to and receive from them.
    pub holder_candidates: usize,
}

/// Whether a deposit would currently succeed, and how fully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositVerdict {
    /// At least one copy can be deposited, and enough holders exist to meet the
    /// configured copy count.
    Ok,
    /// At least one copy can be deposited, but fewer holders are reachable than
    /// the configured copy count (reduced redundancy).
    Partial,
    /// No copy can be deposited right now; `reason` says why.
    No,
}

/// The judged result for each line the self-check prints.
#[derive(Debug, Clone)]
pub struct OfflineCheckReport {
    pub bootstrap: BootstrapReach,
    pub daemon_running: bool,
    pub peer_count: Option<usize>,
    pub iroh_relay_connected: bool,
    pub holders_reachable: usize,
    pub custody_enabled: bool,
    pub file_custody_enabled: bool,
    pub custody_copies: usize,
    pub deposit: DepositVerdict,
    /// Short machine-stable reason for the deposit verdict.
    pub deposit_reason: &'static str,
}

/// True for RFC1918 private, loopback, link-local and CGNAT (RFC6598) IPv4
/// literals, plus `0.0.0.0`. Anything that does not parse as four octets is
/// treated as routable (it is not a private literal we are guarding against).
///
/// This mirrors the `#[cfg(test)]` classifier in `miasma-core::config`; it is
/// duplicated here (a few lines) because that one is test-only and this runs in
/// production. Keep the two in step if the ranges ever change.
fn ipv4_is_nonroutable(ip: &str) -> bool {
    let o: Vec<u8> = ip.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    if o.len() != 4 {
        return false;
    }
    let (a, b) = (o[0], o[1]);
    (a == 10)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 127)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
        || (a == 0)
}

/// Classify the `/ip4/A.B.C.D` literal inside a libp2p multiaddr as
/// non-routable. `/dns4/...` and `/ip6/...` forms are treated as routable (a
/// hostname may resolve to a public address).
fn multiaddr_is_nonroutable(addr: &str) -> bool {
    let mut parts = addr.split('/');
    while let Some(seg) = parts.next() {
        if seg == "ip4" {
            if let Some(ip) = parts.next() {
                return ipv4_is_nonroutable(ip);
            }
        }
    }
    false
}

/// Classify the configured bootstrap list.
fn classify_bootstrap(peers: &[String]) -> BootstrapReach {
    if peers.is_empty() {
        return BootstrapReach::NoneConfigured;
    }
    if peers.iter().all(|p| multiaddr_is_nonroutable(p)) {
        BootstrapReach::OnlyPrivate
    } else {
        BootstrapReach::HasPublic
    }
}

/// Judge whether a deposit would currently succeed, from plain inputs. Pure:
/// no I/O, no clock, no network. This is the whole decision the command makes.
pub fn evaluate(input: &OfflineCheckInput) -> OfflineCheckReport {
    let bootstrap = classify_bootstrap(&input.bootstrap_peers);

    // Holders are only reachable for an offline deposit when iroh's relay is up
    // (that is the transport that actually connects between contacts) and at
    // least one eligible contact exists to hold a copy.
    let holders_reachable = if input.iroh_present && input.iroh_relay_connected {
        input.holder_candidates
    } else {
        0
    };

    let (deposit, deposit_reason) = if !input.custody_enabled {
        (DepositVerdict::No, "custody disabled")
    } else if !input.file_custody_enabled {
        (DepositVerdict::No, "file custody disabled")
    } else if !input.iroh_present || !input.iroh_relay_connected {
        (DepositVerdict::No, "iroh relay not connected")
    } else if holders_reachable == 0 {
        (DepositVerdict::No, "no reachable holder contact")
    } else if holders_reachable < input.custody_copies {
        (DepositVerdict::Partial, "fewer holders than custody_copies")
    } else {
        (DepositVerdict::Ok, "enough reachable holders")
    };

    OfflineCheckReport {
        bootstrap,
        daemon_running: input.daemon_running,
        peer_count: input.peer_count,
        iroh_relay_connected: input.iroh_relay_connected,
        holders_reachable,
        custody_enabled: input.custody_enabled,
        file_custody_enabled: input.file_custody_enabled,
        custody_copies: input.custody_copies,
        deposit,
        deposit_reason,
    }
}

/// Count contacts eligible to hold a deposit: a usable iroh endpoint, and both
/// send and receive allowed (a holder must accept our deposit and let us
/// collect later). Reads the contact list read-only.
fn count_holder_candidates(data_dir: &Path) -> usize {
    let store = miasma_core::push::ContactStore::open(data_dir);
    store
        .list()
        .iter()
        .filter(|c| c.allow_send && c.allow_receive && c.endpoint_bytes().is_some())
        .count()
}

/// Gather inputs from config, the daemon status snapshot, and the contact list.
/// Sends no user data: it issues a single `Status` IPC (the same call `miasma
/// status` makes) and reads local files.
pub async fn collect(data_dir: &Path) -> OfflineCheckInput {
    use miasma_core::{daemon_request, ControlRequest, ControlResponse};

    let config = NodeConfig::load(data_dir).ok();
    let bootstrap_peers = config
        .as_ref()
        .map(|c| c.network.bootstrap_peers.clone())
        .unwrap_or_default();
    let custody_copies = config
        .as_ref()
        .map(|c| c.chat.custody_copies)
        .unwrap_or(miasma_core::config::DEFAULT_CHAT_CUSTODY_COPIES);
    let custody_enabled = miasma_core::config::load_custody_enabled(data_dir);
    let file_custody_enabled = config
        .as_ref()
        .map(|c| c.push.file_custody_enabled)
        .unwrap_or_else(|| miasma_core::config::PushConfig::default().file_custody_enabled);

    let status = match daemon_request(data_dir, ControlRequest::Status).await {
        Ok(ControlResponse::Status(s)) => Some(s),
        _ => None,
    };
    let daemon_running = status.is_some();
    let peer_count = status.as_ref().map(|s| s.peer_count);
    let (iroh_present, iroh_relay_connected) = match status.as_ref().and_then(|s| s.iroh.as_ref()) {
        Some(i) => (true, i.relay_connected),
        None => (false, false),
    };

    OfflineCheckInput {
        bootstrap_peers,
        daemon_running,
        peer_count,
        iroh_present,
        iroh_relay_connected,
        custody_enabled,
        file_custody_enabled,
        custody_copies,
        holder_candidates: count_holder_candidates(data_dir),
    }
}

fn bootstrap_line(b: BootstrapReach) -> &'static str {
    match b {
        BootstrapReach::NoneConfigured => {
            "none configured (holder discovery relies on iroh + contacts)"
        }
        BootstrapReach::OnlyPrivate => {
            "only a private / non-routable address (cannot reach a remote-site holder)"
        }
        BootstrapReach::HasPublic => "a routable bootstrap peer is configured",
    }
}

fn deposit_line(v: DepositVerdict) -> &'static str {
    match v {
        DepositVerdict::Ok => "YES",
        DepositVerdict::Partial => "PARTIAL",
        DepositVerdict::No => "NO",
    }
}

/// Run the self-check: gather, judge, and print. Human text by default; a
/// stable JSON object with `--json`.
pub async fn run(data_dir: &Path, json: bool) -> Result<()> {
    let input = collect(data_dir).await;
    let report = evaluate(&input);
    let status =
        match miasma_core::daemon_request(data_dir, miasma_core::ControlRequest::Status).await {
            Ok(miasma_core::ControlResponse::Status(s)) => Some(s),
            _ => None,
        };
    let discovery_enabled = status
        .as_ref()
        .map(|s| s.discovery_enabled)
        .unwrap_or_else(|| {
            NodeConfig::load(data_dir)
                .map(|c| c.discovery.enabled)
                .unwrap_or(false)
        });
    let discovery_peers_found = status
        .as_ref()
        .map(|s| s.discovery_peers_found)
        .unwrap_or(0);

    if json {
        let obj = serde_json::json!({
            "discovery_enabled": discovery_enabled,
            "discovery_peers_found": discovery_peers_found,
            "bootstrap_reachability": match report.bootstrap {
                BootstrapReach::NoneConfigured => "none_configured",
                BootstrapReach::OnlyPrivate => "only_private",
                BootstrapReach::HasPublic => "has_public",
            },
            "daemon_running": report.daemon_running,
            "connected_peers": report.peer_count,
            "storage_candidates_verified_peers": status.as_ref().map(|s| s.verified_peers),
            "iroh_relay_connected": report.iroh_relay_connected,
            "holders_reachable_via_iroh": report.holders_reachable,
            "custody_enabled": report.custody_enabled,
            "file_custody_enabled": report.file_custody_enabled,
            "custody_copies": report.custody_copies,
            "deposit_would_succeed": match report.deposit {
                DepositVerdict::Ok => "yes",
                DepositVerdict::Partial => "partial",
                DepositVerdict::No => "no",
            },
            "deposit_reason": report.deposit_reason,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }

    println!("Miasma Offline-Delivery Self-Check");
    println!(
        "  Network discovery: {}, peers found last round {}",
        if discovery_enabled {
            "enabled"
        } else {
            "disabled"
        },
        discovery_peers_found
    );
    println!(
        "  Bootstrap reachability:     {}",
        bootstrap_line(report.bootstrap)
    );
    match report.peer_count {
        Some(n) => println!("  Connected peers (libp2p):   {n}"),
        None => println!("  Connected peers (libp2p):   unknown (daemon not running)"),
    }
    match status.as_ref() {
        Some(s) => println!("  Storage candidates: {} verified peers", s.verified_peers),
        None => println!("  Storage candidates: unknown (daemon not running)"),
    }
    println!(
        "  iroh relay connected:       {}",
        if report.iroh_relay_connected {
            "yes"
        } else {
            "no"
        }
    );
    println!("  Holders reachable via iroh: {}", report.holders_reachable);
    println!(
        "  Custody enabled:            {} (copies wanted: {})",
        if report.custody_enabled { "yes" } else { "no" },
        report.custody_copies
    );
    println!(
        "  File custody enabled:       {}",
        if report.file_custody_enabled {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "  Deposit would succeed now:  {} ({})",
        deposit_line(report.deposit),
        report.deposit_reason
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> OfflineCheckInput {
        OfflineCheckInput {
            bootstrap_peers: vec![],
            daemon_running: true,
            peer_count: Some(0),
            iroh_present: true,
            iroh_relay_connected: true,
            custody_enabled: true,
            file_custody_enabled: true,
            custody_copies: 2,
            holder_candidates: 2,
        }
    }

    #[test]
    fn ipv4_private_ranges_are_nonroutable() {
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
        ] {
            assert!(ipv4_is_nonroutable(ip), "{ip} should be non-routable");
        }
    }

    #[test]
    fn ipv4_public_literals_are_routable() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
            "100.63.0.1",
            "100.128.0.1",
        ] {
            assert!(!ipv4_is_nonroutable(ip), "{ip} should be routable");
        }
    }

    #[test]
    fn private_multiaddr_is_flagged() {
        assert!(multiaddr_is_nonroutable(
            "/ip4/172.24.51.174/udp/19900/quic-v1/p2p/12D3KooExample"
        ));
    }

    #[test]
    fn public_and_dns_multiaddrs_are_not_flagged() {
        assert!(!multiaddr_is_nonroutable(
            "/ip4/203.0.113.7/udp/19900/quic-v1"
        ));
        assert!(!multiaddr_is_nonroutable(
            "/dns4/bootstrap.example.org/udp/19900/quic-v1"
        ));
    }

    #[test]
    fn bootstrap_empty_is_none_configured() {
        assert_eq!(classify_bootstrap(&[]), BootstrapReach::NoneConfigured);
    }

    #[test]
    fn bootstrap_all_private_is_only_private() {
        let peers = vec!["/ip4/172.24.51.174/udp/19900/quic-v1".to_string()];
        assert_eq!(classify_bootstrap(&peers), BootstrapReach::OnlyPrivate);
    }

    #[test]
    fn bootstrap_with_one_public_is_has_public() {
        let peers = vec![
            "/ip4/10.0.0.1/udp/19900/quic-v1".to_string(),
            "/dns4/bootstrap.example.org/udp/19900/quic-v1".to_string(),
        ];
        assert_eq!(classify_bootstrap(&peers), BootstrapReach::HasPublic);
    }

    #[test]
    fn deposit_ok_when_relay_up_and_enough_holders() {
        let r = evaluate(&base());
        assert_eq!(r.deposit, DepositVerdict::Ok);
        assert_eq!(r.holders_reachable, 2);
    }

    #[test]
    fn deposit_partial_when_fewer_holders_than_copies() {
        let mut i = base();
        i.holder_candidates = 1;
        let r = evaluate(&i);
        assert_eq!(r.deposit, DepositVerdict::Partial);
    }

    #[test]
    fn deposit_no_when_custody_disabled() {
        let mut i = base();
        i.custody_enabled = false;
        let r = evaluate(&i);
        assert_eq!(r.deposit, DepositVerdict::No);
        assert_eq!(r.deposit_reason, "custody disabled");
    }

    #[test]
    fn deposit_no_when_file_custody_disabled() {
        let mut i = base();
        i.file_custody_enabled = false;
        let r = evaluate(&i);
        assert_eq!(r.deposit, DepositVerdict::No);
        assert_eq!(r.deposit_reason, "file custody disabled");
    }

    #[test]
    fn deposit_no_when_relay_down() {
        let mut i = base();
        i.iroh_relay_connected = false;
        let r = evaluate(&i);
        assert_eq!(r.deposit, DepositVerdict::No);
        assert_eq!(r.deposit_reason, "iroh relay not connected");
        assert_eq!(
            r.holders_reachable, 0,
            "no holders are counted when the relay is down"
        );
    }

    #[test]
    fn deposit_no_when_no_holder_contacts() {
        let mut i = base();
        i.holder_candidates = 0;
        let r = evaluate(&i);
        assert_eq!(r.deposit, DepositVerdict::No);
        assert_eq!(r.deposit_reason, "no reachable holder contact");
    }

    #[test]
    fn relay_down_hides_holders_even_if_custody_on() {
        let mut i = base();
        i.iroh_present = false;
        i.iroh_relay_connected = false;
        let r = evaluate(&i);
        assert_eq!(r.holders_reachable, 0);
        assert_eq!(r.deposit, DepositVerdict::No);
    }
}
