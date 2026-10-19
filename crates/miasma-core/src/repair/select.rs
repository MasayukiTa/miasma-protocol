//! Holder selection for piece maintenance: which node receives a new replica.
//!
//! Selection is a pure function of the planner's action, the candidate list and
//! the load already placed on each holder, so it can be tested without a
//! network. Failure-domain labels are derived from announced addresses by
//! [`failure_domain_for_addrs`].

use std::collections::{HashMap, HashSet};

use super::maintenance::PieceMaintenanceAction;

/// A node that could receive a replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Stable holder identity (PeerId text), the same namespace as
    /// [`super::ReplicaObservation::holder_id`].
    pub peer_id: String,
    /// Failure-domain label, or `None` when unknown (never treated as diverse).
    pub failure_domain: Option<String>,
}

/// The outcome of a successful selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection<'a> {
    pub candidate: &'a Candidate,
    /// The candidate sits in a failure domain not yet used by this slot.
    pub adds_domain_diversity: bool,
}

/// Choose the holder for one maintenance action.
///
/// * Holders in `action.avoid_holders` and holders already at `per_holder_cap`
///   pieces of this content never receive another one.
/// * A candidate in a failure domain the slot does not use yet is always
///   preferred; among equals the least-loaded candidate wins, then the
///   backend's own ranking (the input order).
/// * When no such candidate exists, a correlated copy (unknown or already used
///   domain) is accepted only if the slot is short of `target_replicas`: it
///   restores the copy count but is never recorded as independent durability.
///   A purely diversity-driven action returns `None` instead of adding a copy
///   that cannot improve diversity.
pub fn select_holder<'a>(
    candidates: &'a [Candidate],
    action: &PieceMaintenanceAction,
    target_replicas: usize,
    holder_load: &HashMap<String, usize>,
    per_holder_cap: usize,
) -> Option<Selection<'a>> {
    let avoid_holders: HashSet<&str> = action.avoid_holders.iter().map(String::as_str).collect();
    let avoid_domains: HashSet<&str> = action
        .avoid_failure_domains
        .iter()
        .map(String::as_str)
        .collect();

    let eligible = |c: &&Candidate| {
        !avoid_holders.contains(c.peer_id.as_str())
            && holder_load.get(&c.peer_id).copied().unwrap_or(0) < per_holder_cap.max(1)
    };
    let load = |c: &&Candidate| holder_load.get(&c.peer_id).copied().unwrap_or(0);

    let diverse = candidates
        .iter()
        .filter(eligible)
        .filter(|c| {
            c.failure_domain
                .as_deref()
                .is_some_and(|d| !avoid_domains.contains(d))
        })
        // `min_by_key` returns the first minimum, preserving backend ranking.
        .min_by_key(load);
    if let Some(candidate) = diverse {
        return Some(Selection {
            candidate,
            adds_domain_diversity: true,
        });
    }

    if action.reachable_replicas >= target_replicas.max(1) {
        return None;
    }
    // Prefer an unknown domain over a known-correlated one.
    let fallback = candidates
        .iter()
        .filter(eligible)
        .min_by_key(|c| (c.failure_domain.is_some(), load(c)));
    fallback.map(|candidate| Selection {
        candidate,
        adds_domain_diversity: false,
    })
}

/// Derive a coarse failure-domain label from a holder's announced multiaddrs.
///
/// The first address that yields a label wins. Loopback, unspecified and
/// link-local addresses yield nothing: they say nothing about independence.
///
/// * public IPv4 -> `ip4:a.b.c` (a /24), private IPv4 -> `lan:a.b.c`
/// * IPv6 -> `ip6:` plus the first three hextets (a /48)
/// * DNS names -> `dns:` plus the last two labels
/// * circuit relay addresses -> `relay:<relay peer>`
pub fn failure_domain_for_addrs(addrs: &[String]) -> Option<String> {
    addrs.iter().find_map(|a| failure_domain_for_addr(a))
}

fn failure_domain_for_addr(addr: &str) -> Option<String> {
    let parts: Vec<&str> = addr.split('/').filter(|s| !s.is_empty()).collect();

    if let Some(circuit) = parts.iter().position(|p| *p == "p2p-circuit") {
        // /…/p2p/<relay>/p2p-circuit: the relay is the shared dependency.
        if circuit >= 2 && parts[circuit - 2] == "p2p" {
            return Some(format!("relay:{}", parts[circuit - 1]));
        }
        return None;
    }

    let mut it = parts.iter();
    while let Some(proto) = it.next() {
        let value = it.next();
        match (*proto, value) {
            ("ip4", Some(v)) => return ipv4_domain(v),
            ("ip6", Some(v)) => return ipv6_domain(v),
            ("dns" | "dns4" | "dns6" | "dnsaddr", Some(v)) => return dns_domain(v),
            _ => {}
        }
    }
    None
}

fn ipv4_domain(text: &str) -> Option<String> {
    let ip: std::net::Ipv4Addr = text.parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_broadcast() {
        return None;
    }
    let o = ip.octets();
    let kind = if ip.is_private() { "lan" } else { "ip4" };
    Some(format!("{kind}:{}.{}.{}", o[0], o[1], o[2]))
}

fn ipv6_domain(text: &str) -> Option<String> {
    let ip: std::net::Ipv6Addr = text.parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    let s = ip.segments();
    // fe80::/10 link-local carries no provider information.
    if s[0] & 0xffc0 == 0xfe80 {
        return None;
    }
    Some(format!("ip6:{:x}:{:x}:{:x}", s[0], s[1], s[2]))
}

fn dns_domain(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host == "localhost" {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let tail = labels[labels.len().saturating_sub(2)..].join(".");
    Some(format!("dns:{tail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, domain: Option<&str>) -> Candidate {
        Candidate {
            peer_id: id.into(),
            failure_domain: domain.map(str::to_owned),
        }
    }

    fn action(
        avoid_holders: &[&str],
        avoid_domains: &[&str],
        replicas: usize,
    ) -> PieceMaintenanceAction {
        PieceMaintenanceAction {
            slot_index: 0,
            avoid_holders: avoid_holders.iter().map(|s| s.to_string()).collect(),
            avoid_failure_domains: avoid_domains.iter().map(|s| s.to_string()).collect(),
            reachable_replicas: replicas,
            known_failure_domains: avoid_domains.len(),
        }
    }

    #[test]
    fn prefers_a_new_failure_domain_over_ranking_order() {
        let cands = vec![cand("same", Some("asn-a")), cand("other", Some("asn-b"))];
        let s = select_holder(
            &cands,
            &action(&["a"], &["asn-a"], 1),
            2,
            &HashMap::new(),
            2,
        )
        .unwrap();
        assert_eq!(s.candidate.peer_id, "other");
        assert!(s.adds_domain_diversity);
    }

    #[test]
    fn never_reuses_an_existing_holder_or_a_full_holder() {
        let cands = vec![
            cand("a", Some("x")),
            cand("full", Some("y")),
            cand("ok", Some("z")),
        ];
        let mut load = HashMap::new();
        load.insert("full".to_string(), 1usize);
        let s = select_holder(&cands, &action(&["a"], &["x"], 1), 2, &load, 1).unwrap();
        assert_eq!(s.candidate.peer_id, "ok");
    }

    #[test]
    fn least_loaded_wins_among_equally_diverse_candidates() {
        let cands = vec![cand("busy", Some("x")), cand("idle", Some("y"))];
        let mut load = HashMap::new();
        load.insert("busy".to_string(), 1usize);
        let s = select_holder(&cands, &action(&[], &[], 0), 1, &load, 5).unwrap();
        assert_eq!(s.candidate.peer_id, "idle");
    }

    #[test]
    fn correlated_copy_is_accepted_only_when_the_slot_is_short_of_replicas() {
        let cands = vec![cand("c1", Some("asn-a")), cand("c2", None)];
        // Short of the target: restore the count, preferring the unknown domain.
        let s = select_holder(
            &cands,
            &action(&["h"], &["asn-a"], 1),
            2,
            &HashMap::new(),
            2,
        )
        .unwrap();
        assert_eq!(s.candidate.peer_id, "c2");
        assert!(!s.adds_domain_diversity);
        // Already at the target (diversity-only action): refuse.
        assert!(select_holder(
            &cands,
            &action(&["h"], &["asn-a"], 2),
            2,
            &HashMap::new(),
            2
        )
        .is_none());
    }

    #[test]
    fn no_candidates_means_no_selection() {
        assert!(select_holder(&[], &action(&[], &[], 0), 1, &HashMap::new(), 1).is_none());
    }

    #[test]
    fn domains_are_derived_from_announced_addresses() {
        let d = |a: &str| failure_domain_for_addrs(&[a.to_string()]);
        assert_eq!(
            d("/ip4/203.0.113.9/tcp/4001").as_deref(),
            Some("ip4:203.0.113")
        );
        assert_eq!(
            d("/ip4/192.168.1.5/udp/9/quic-v1").as_deref(),
            Some("lan:192.168.1")
        );
        assert_eq!(d("/ip4/127.0.0.1/tcp/1"), None);
        assert_eq!(d("/ip4/0.0.0.0/tcp/1"), None);
        assert_eq!(
            d("/ip6/2001:db8:1:2::1/tcp/1").as_deref(),
            Some("ip6:2001:db8:1")
        );
        assert_eq!(d("/ip6/::1/tcp/1"), None);
        assert_eq!(d("/ip6/fe80::1/tcp/1"), None);
        assert_eq!(
            d("/dns4/node7.Example.org/tcp/443/wss").as_deref(),
            Some("dns:example.org")
        );
        assert_eq!(d("/dns4/localhost/tcp/1"), None);
        assert_eq!(
            d("/ip4/198.51.100.1/tcp/4001/p2p/12D3KooWRelay/p2p-circuit").as_deref(),
            Some("relay:12D3KooWRelay")
        );
        assert_eq!(d("garbage"), None);
        // First address that yields a label wins; loopback is skipped.
        assert_eq!(
            failure_domain_for_addrs(&[
                "/ip4/127.0.0.1/tcp/1".to_string(),
                "/ip4/203.0.113.77/tcp/1".to_string()
            ])
            .as_deref(),
            Some("ip4:203.0.113")
        );
    }
}
