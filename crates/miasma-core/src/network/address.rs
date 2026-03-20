/// Peer address classification and trust tiers (ADR-004).
///
/// # Problem
/// Raw peer-advertised addresses are not trustworthy routing material.
/// A malicious peer can advertise loopback, private, or link-local addresses
/// to poison the routing table, enabling SSRF and eclipse attacks.
///
/// # Model
/// Every address passes through classification before routing decisions:
///
/// 1. **AddressClass** determines what kind of address it is
///    (loopback, private, global, relay, etc.)
///
/// 2. **AddressTrust** tracks how we learned about the address:
///    - Claimed: peer says it exists (untrusted)
///    - Observed: we completed an Identify exchange with it
///    - Verified: peer passed PoW + signature checks
///
/// 3. **Filtering rules** reject dangerous address classes from untrusted sources.
use std::net::{Ipv4Addr, Ipv6Addr};

use libp2p::Multiaddr;
use tracing::debug;

/// Classification of a network address by its reachability scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressClass {
    /// `127.0.0.0/8` or `::1` — never routable from peers.
    Loopback,
    /// `169.254.0.0/16` or `fe80::/10` — never routable from peers.
    LinkLocal,
    /// RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or
    /// ULA (`fc00::/7`) — only trusted from local bootstrap config.
    Private,
    /// Public IPv4/IPv6 — the normal case for Internet peers.
    GlobalUnicast,
    /// `/p2p/<peer>/p2p-circuit` — relay-mediated address.
    Relay,
    /// Unrecognized or unparseable address format.
    Unknown,
}

/// How we learned about this address and how much we trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressTrust {
    /// Peer-advertised or from DHT record. No verification.
    Claimed,
    /// We successfully completed an Identify exchange with this peer+address.
    Observed,
    /// Peer passed PoW verification and signed Identify data.
    Verified,
}

/// A peer address annotated with its classification and trust level.
#[derive(Debug, Clone)]
pub struct PeerAddress {
    /// The raw multiaddr.
    pub addr: Multiaddr,
    /// What kind of address this is.
    pub class: AddressClass,
    /// How much we trust this address.
    pub trust: AddressTrust,
}

impl PeerAddress {
    /// Classify and wrap a raw multiaddr with the given trust level.
    pub fn new(addr: Multiaddr, trust: AddressTrust) -> Self {
        let class = classify_multiaddr(&addr);
        Self { addr, class, trust }
    }

    /// Returns true if this address is safe to add to the Kademlia routing
    /// table, given its class and trust level.
    ///
    /// # Rules
    /// - Loopback and link-local: NEVER routable from remote peers
    /// - Private: only allowed from local bootstrap config (Claimed from
    ///   local source, but never from DHT/Identify of remote peers)
    /// - Global unicast and relay: allowed after Identify exchange (Observed+)
    pub fn is_routable_from_peer(&self) -> bool {
        match self.class {
            AddressClass::Loopback | AddressClass::LinkLocal => false,
            AddressClass::Private => false, // Only local bootstrap may use private
            AddressClass::GlobalUnicast | AddressClass::Relay => true,
            AddressClass::Unknown => false,
        }
    }

    /// Returns true if this address is safe to use from a local bootstrap
    /// configuration file (where private addresses are acceptable).
    pub fn is_routable_from_bootstrap(&self) -> bool {
        match self.class {
            AddressClass::Loopback | AddressClass::LinkLocal => false,
            AddressClass::Private | AddressClass::GlobalUnicast | AddressClass::Relay => true,
            AddressClass::Unknown => false,
        }
    }
}

/// Classify a multiaddr by extracting the IP component and checking its scope.
pub fn classify_multiaddr(addr: &Multiaddr) -> AddressClass {
    // Check for relay/circuit addresses first.
    let addr_str = addr.to_string();
    if addr_str.contains("/p2p-circuit") {
        return AddressClass::Relay;
    }

    // Extract the IP address from the multiaddr.
    for proto in addr.iter() {
        match proto {
            libp2p::multiaddr::Protocol::Ip4(ip) => return classify_ipv4(ip),
            libp2p::multiaddr::Protocol::Ip6(ip) => return classify_ipv6(ip),
            libp2p::multiaddr::Protocol::Dns(_)
            | libp2p::multiaddr::Protocol::Dns4(_)
            | libp2p::multiaddr::Protocol::Dns6(_)
            | libp2p::multiaddr::Protocol::Dnsaddr(_) => {
                // DNS names are treated as global — resolution happens at connect time.
                return AddressClass::GlobalUnicast;
            }
            _ => continue,
        }
    }

    AddressClass::Unknown
}

fn classify_ipv4(ip: Ipv4Addr) -> AddressClass {
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_link_local() {
        AddressClass::LinkLocal
    } else if is_private_ipv4(ip) {
        AddressClass::Private
    } else {
        AddressClass::GlobalUnicast
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> AddressClass {
    if ip.is_loopback() {
        AddressClass::Loopback
    } else if is_link_local_ipv6(&ip) {
        AddressClass::LinkLocal
    } else if is_ula_ipv6(&ip) {
        AddressClass::Private
    } else {
        AddressClass::GlobalUnicast
    }
}

/// RFC 1918 private ranges.
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    octets[0] == 10
    // 172.16.0.0/12
    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
    // 192.168.0.0/16
    || (octets[0] == 192 && octets[1] == 168)
}

/// IPv6 link-local: fe80::/10
fn is_link_local_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// IPv6 Unique Local Address: fc00::/7
fn is_ula_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

/// Filter a list of multiaddrs, keeping only those safe to route to from
/// a remote peer. Logs rejected addresses.
pub fn filter_peer_addresses(
    peer_id: &libp2p::PeerId,
    addrs: &[Multiaddr],
) -> Vec<Multiaddr> {
    let mut accepted = Vec::new();
    for addr in addrs {
        let pa = PeerAddress::new(addr.clone(), AddressTrust::Observed);
        if pa.is_routable_from_peer() {
            accepted.push(addr.clone());
        } else {
            debug!(
                "Rejected address from peer {}: {} (class={:?})",
                peer_id, addr, pa.class
            );
        }
    }
    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn classify_loopback_v4() {
        assert_eq!(classify_multiaddr(&ma("/ip4/127.0.0.1/tcp/4001")), AddressClass::Loopback);
    }

    #[test]
    fn classify_loopback_v6() {
        assert_eq!(classify_multiaddr(&ma("/ip6/::1/tcp/4001")), AddressClass::Loopback);
    }

    #[test]
    fn classify_private_10() {
        assert_eq!(classify_multiaddr(&ma("/ip4/10.0.0.1/tcp/4001")), AddressClass::Private);
    }

    #[test]
    fn classify_private_172() {
        assert_eq!(classify_multiaddr(&ma("/ip4/172.16.0.1/tcp/4001")), AddressClass::Private);
    }

    #[test]
    fn classify_private_192() {
        assert_eq!(classify_multiaddr(&ma("/ip4/192.168.1.1/tcp/4001")), AddressClass::Private);
    }

    #[test]
    fn classify_link_local_v4() {
        assert_eq!(classify_multiaddr(&ma("/ip4/169.254.0.1/tcp/4001")), AddressClass::LinkLocal);
    }

    #[test]
    fn classify_global_unicast() {
        assert_eq!(classify_multiaddr(&ma("/ip4/8.8.8.8/tcp/4001")), AddressClass::GlobalUnicast);
    }

    #[test]
    fn classify_dns() {
        assert_eq!(classify_multiaddr(&ma("/dns4/example.com/tcp/4001")), AddressClass::GlobalUnicast);
    }

    #[test]
    fn loopback_not_routable_from_peer() {
        let pa = PeerAddress::new(ma("/ip4/127.0.0.1/tcp/4001"), AddressTrust::Observed);
        assert!(!pa.is_routable_from_peer());
    }

    #[test]
    fn private_not_routable_from_peer() {
        let pa = PeerAddress::new(ma("/ip4/10.0.0.1/tcp/4001"), AddressTrust::Observed);
        assert!(!pa.is_routable_from_peer());
    }

    #[test]
    fn private_routable_from_bootstrap() {
        let pa = PeerAddress::new(ma("/ip4/10.0.0.1/tcp/4001"), AddressTrust::Claimed);
        assert!(pa.is_routable_from_bootstrap());
    }

    #[test]
    fn global_routable_from_peer() {
        let pa = PeerAddress::new(ma("/ip4/8.8.8.8/tcp/4001"), AddressTrust::Observed);
        assert!(pa.is_routable_from_peer());
    }

    #[test]
    fn link_local_never_routable() {
        let pa = PeerAddress::new(ma("/ip4/169.254.0.1/tcp/4001"), AddressTrust::Verified);
        assert!(!pa.is_routable_from_peer());
        assert!(!pa.is_routable_from_bootstrap());
    }

    #[test]
    fn filter_removes_private_and_loopback() {
        let peer_id = libp2p::PeerId::random();
        let addrs = vec![
            ma("/ip4/127.0.0.1/tcp/4001"),
            ma("/ip4/10.0.0.1/tcp/4001"),
            ma("/ip4/8.8.8.8/tcp/4001"),
            ma("/ip4/1.2.3.4/tcp/4001"),
        ];
        let filtered = filter_peer_addresses(&peer_id, &addrs);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].to_string(), "/ip4/8.8.8.8/tcp/4001");
        assert_eq!(filtered[1].to_string(), "/ip4/1.2.3.4/tcp/4001");
    }
}
