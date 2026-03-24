/// Network environment detection — ZTNA, VPN, captive portal, filtering.
///
/// Detects the type of network environment the daemon is operating in
/// and informs transport selection strategy accordingly.
///
/// # Detection heuristics
/// - UDP reachability (QUIC probe)
/// - Port filtering (443, 80, high-port)
/// - TLS inspection (certificate chain analysis)
/// - Captive portal (HTTP redirect detection)
/// - VPN (routing table heuristics)
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ─── Network environment classification ─────────────────────────────────────

/// Classification of the current network environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkEnvironment {
    /// No restrictions detected — all transports expected to work.
    Open,
    /// Corporate proxy detected (HTTP CONNECT / SOCKS available).
    CorporateProxy,
    /// Split-tunnel VPN — some traffic goes through VPN, some direct.
    SplitTunnelVpn,
    /// Full-tunnel VPN — all traffic goes through VPN.
    FullTunnelVpn,
    /// Captive portal detected — user needs to authenticate.
    CaptivePortal,
    /// Active filtering detected (protocol/port blocking).
    Filtered,
    /// Not yet determined.
    Unknown,
}

impl fmt::Display for NetworkEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::CorporateProxy => write!(f, "corporate-proxy"),
            Self::SplitTunnelVpn => write!(f, "split-tunnel-vpn"),
            Self::FullTunnelVpn => write!(f, "full-tunnel-vpn"),
            Self::CaptivePortal => write!(f, "captive-portal"),
            Self::Filtered => write!(f, "filtered"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── Network capabilities ───────────────────────────────────────────────────

/// Detected network capabilities and restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCapabilities {
    /// Whether UDP traffic can flow (needed for QUIC).
    pub udp_available: bool,
    /// Whether TCP to high ports works.
    pub tcp_high_ports_available: bool,
    /// Whether port 443 is reachable.
    pub port_443_available: bool,
    /// Whether port 80 is reachable.
    pub port_80_available: bool,
    /// Whether TLS inspection (MITM) was detected.
    pub tls_inspection_detected: bool,
    /// Name of the detected TLS inspector (Zscaler, Netskope, etc.).
    pub tls_inspector: Option<String>,
    /// Whether a captive portal redirect was detected.
    pub captive_portal_detected: bool,
    /// Whether a VPN interface was detected.
    pub vpn_detected: bool,
}

impl Default for NetworkCapabilities {
    fn default() -> Self {
        Self {
            udp_available: true,        // Assume open until proven otherwise
            tcp_high_ports_available: true,
            port_443_available: true,
            port_80_available: true,
            tls_inspection_detected: false,
            tls_inspector: None,
            captive_portal_detected: false,
            vpn_detected: false,
        }
    }
}

impl NetworkCapabilities {
    /// Derive the network environment from detected capabilities.
    pub fn classify(&self) -> NetworkEnvironment {
        if self.captive_portal_detected {
            return NetworkEnvironment::CaptivePortal;
        }
        if self.tls_inspection_detected {
            return NetworkEnvironment::CorporateProxy;
        }
        if self.vpn_detected {
            if self.udp_available && self.tcp_high_ports_available {
                return NetworkEnvironment::SplitTunnelVpn;
            }
            return NetworkEnvironment::FullTunnelVpn;
        }
        if !self.udp_available || !self.tcp_high_ports_available {
            return NetworkEnvironment::Filtered;
        }
        NetworkEnvironment::Open
    }
}

// ─── Known TLS inspectors ───────────────────────────────────────────────────

/// Known ZTNA/corporate TLS inspection CA issuer strings.
///
/// When a TLS connection's certificate chain contains an issuer matching
/// one of these patterns, TLS inspection is detected.
const KNOWN_TLS_INSPECTORS: &[(&str, &str)] = &[
    ("zscaler", "Zscaler"),
    ("netskope", "Netskope"),
    ("palo alto", "Palo Alto GlobalProtect"),
    ("forcepoint", "Forcepoint"),
    ("symantec", "Symantec/Broadcom"),
    ("bluecoat", "Blue Coat/Symantec"),
    ("fortinet", "Fortinet"),
    ("barracuda", "Barracuda"),
    ("sophos", "Sophos"),
    ("mcafee", "McAfee/Trellix"),
    ("websense", "Websense/Forcepoint"),
    ("checkpoint", "Check Point"),
];

/// Check if a certificate issuer string matches a known TLS inspector.
pub fn detect_tls_inspector(issuer: &str) -> Option<&'static str> {
    let lower = issuer.to_lowercase();
    for (pattern, name) in KNOWN_TLS_INSPECTORS {
        if lower.contains(pattern) {
            return Some(name);
        }
    }
    None
}

// ─── Transport recommendation ───────────────────────────────────────────────

/// Recommended transport adaptation based on detected environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportRecommendation {
    /// Recommended primary transport.
    pub primary: String,
    /// Recommended fallback transports (in order).
    pub fallbacks: Vec<String>,
    /// Human-readable explanation.
    pub reason: String,
    /// Whether the user needs to take action (e.g., captive portal auth).
    pub user_action_required: bool,
    /// Action message for the user, if any.
    pub user_action_message: Option<String>,
}

/// Generate transport recommendations based on network capabilities.
pub fn recommend_transport(caps: &NetworkCapabilities) -> TransportRecommendation {
    let env = caps.classify();

    match env {
        NetworkEnvironment::Open => TransportRecommendation {
            primary: "direct-libp2p".to_string(),
            fallbacks: vec!["tcp-direct".to_string()],
            reason: "No restrictions detected".to_string(),
            user_action_required: false,
            user_action_message: None,
        },
        NetworkEnvironment::CorporateProxy => TransportRecommendation {
            primary: "obfuscated-quic".to_string(),
            fallbacks: vec!["wss-tunnel".to_string(), "relay-hop".to_string()],
            reason: format!(
                "TLS inspection detected{}",
                caps.tls_inspector
                    .as_ref()
                    .map(|i| format!(" ({i})"))
                    .unwrap_or_default()
            ),
            user_action_required: false,
            user_action_message: None,
        },
        NetworkEnvironment::SplitTunnelVpn | NetworkEnvironment::FullTunnelVpn => {
            TransportRecommendation {
                primary: if caps.udp_available {
                    "direct-libp2p".to_string()
                } else {
                    "wss-tunnel".to_string()
                },
                fallbacks: vec!["obfuscated-quic".to_string(), "relay-hop".to_string()],
                reason: format!("VPN detected ({env})"),
                user_action_required: false,
                user_action_message: None,
            }
        }
        NetworkEnvironment::CaptivePortal => TransportRecommendation {
            primary: "none".to_string(),
            fallbacks: vec![],
            reason: "Captive portal detected — authentication required".to_string(),
            user_action_required: true,
            user_action_message: Some(
                "Network requires authentication. Please open a browser and complete sign-in, \
                 then Miasma will retry automatically."
                    .to_string(),
            ),
        },
        NetworkEnvironment::Filtered => {
            let primary = if caps.port_443_available {
                "wss-tunnel"
            } else {
                "obfuscated-quic"
            };
            TransportRecommendation {
                primary: primary.to_string(),
                fallbacks: vec!["relay-hop".to_string()],
                reason: format!(
                    "Filtering detected: UDP={}, high-port TCP={}, 443={}",
                    if caps.udp_available { "ok" } else { "blocked" },
                    if caps.tcp_high_ports_available {
                        "ok"
                    } else {
                        "blocked"
                    },
                    if caps.port_443_available {
                        "ok"
                    } else {
                        "blocked"
                    }
                ),
                user_action_required: false,
                user_action_message: None,
            }
        }
        NetworkEnvironment::Unknown => TransportRecommendation {
            primary: "direct-libp2p".to_string(),
            fallbacks: vec![
                "tcp-direct".to_string(),
                "wss-tunnel".to_string(),
                "obfuscated-quic".to_string(),
                "relay-hop".to_string(),
            ],
            reason: "Environment not yet determined — trying all transports".to_string(),
            user_action_required: false,
            user_action_message: None,
        },
    }
}

// ─── Environment snapshot ───────────────────────────────────────────────────

/// Timestamped snapshot of the detected network environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    /// Unix timestamp of this snapshot.
    pub timestamp: u64,
    /// Detected environment type.
    pub environment: NetworkEnvironment,
    /// Detailed capabilities.
    pub capabilities: NetworkCapabilities,
    /// Transport recommendation.
    pub recommendation: TransportRecommendation,
}

impl Default for EnvironmentSnapshot {
    fn default() -> Self {
        Self::from_capabilities(NetworkCapabilities::default())
    }
}

impl EnvironmentSnapshot {
    /// Create a snapshot from capabilities.
    pub fn from_capabilities(caps: NetworkCapabilities) -> Self {
        let environment = caps.classify();
        let recommendation = recommend_transport(&caps);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        Self {
            timestamp,
            environment,
            capabilities: caps,
            recommendation,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_open() {
        let caps = NetworkCapabilities::default();
        assert_eq!(caps.classify(), NetworkEnvironment::Open);
    }

    #[test]
    fn classify_captive_portal() {
        let caps = NetworkCapabilities {
            captive_portal_detected: true,
            ..Default::default()
        };
        assert_eq!(caps.classify(), NetworkEnvironment::CaptivePortal);
    }

    #[test]
    fn classify_corporate_proxy() {
        let caps = NetworkCapabilities {
            tls_inspection_detected: true,
            tls_inspector: Some("Zscaler".to_string()),
            ..Default::default()
        };
        assert_eq!(caps.classify(), NetworkEnvironment::CorporateProxy);
    }

    #[test]
    fn classify_split_tunnel_vpn() {
        let caps = NetworkCapabilities {
            vpn_detected: true,
            udp_available: true,
            tcp_high_ports_available: true,
            ..Default::default()
        };
        assert_eq!(caps.classify(), NetworkEnvironment::SplitTunnelVpn);
    }

    #[test]
    fn classify_full_tunnel_vpn() {
        let caps = NetworkCapabilities {
            vpn_detected: true,
            udp_available: false,
            ..Default::default()
        };
        assert_eq!(caps.classify(), NetworkEnvironment::FullTunnelVpn);
    }

    #[test]
    fn classify_filtered_no_udp() {
        let caps = NetworkCapabilities {
            udp_available: false,
            ..Default::default()
        };
        assert_eq!(caps.classify(), NetworkEnvironment::Filtered);
    }

    #[test]
    fn classify_filtered_no_high_ports() {
        let caps = NetworkCapabilities {
            tcp_high_ports_available: false,
            ..Default::default()
        };
        assert_eq!(caps.classify(), NetworkEnvironment::Filtered);
    }

    #[test]
    fn captive_portal_takes_priority() {
        // Captive portal should be detected even with TLS inspection
        let caps = NetworkCapabilities {
            captive_portal_detected: true,
            tls_inspection_detected: true,
            ..Default::default()
        };
        assert_eq!(caps.classify(), NetworkEnvironment::CaptivePortal);
    }

    #[test]
    fn detect_known_inspectors() {
        assert_eq!(
            detect_tls_inspector("CN=Zscaler Root CA"),
            Some("Zscaler")
        );
        assert_eq!(
            detect_tls_inspector("O=Netskope Inc"),
            Some("Netskope")
        );
        assert_eq!(
            detect_tls_inspector("CN=Palo Alto Networks Root CA"),
            Some("Palo Alto GlobalProtect")
        );
        assert_eq!(detect_tls_inspector("CN=DigiCert Global Root"), None);
    }

    #[test]
    fn recommend_open() {
        let caps = NetworkCapabilities::default();
        let rec = recommend_transport(&caps);
        assert_eq!(rec.primary, "direct-libp2p");
        assert!(!rec.user_action_required);
    }

    #[test]
    fn recommend_captive_portal_requires_action() {
        let caps = NetworkCapabilities {
            captive_portal_detected: true,
            ..Default::default()
        };
        let rec = recommend_transport(&caps);
        assert!(rec.user_action_required);
        assert!(rec.user_action_message.is_some());
    }

    #[test]
    fn recommend_filtered_prefers_443() {
        let caps = NetworkCapabilities {
            udp_available: false,
            tcp_high_ports_available: false,
            port_443_available: true,
            ..Default::default()
        };
        let rec = recommend_transport(&caps);
        assert_eq!(rec.primary, "wss-tunnel");
    }

    #[test]
    fn recommend_corporate_uses_obfuscated() {
        let caps = NetworkCapabilities {
            tls_inspection_detected: true,
            tls_inspector: Some("Zscaler".to_string()),
            ..Default::default()
        };
        let rec = recommend_transport(&caps);
        assert_eq!(rec.primary, "obfuscated-quic");
    }

    #[test]
    fn environment_display() {
        assert_eq!(NetworkEnvironment::Open.to_string(), "open");
        assert_eq!(NetworkEnvironment::CorporateProxy.to_string(), "corporate-proxy");
        assert_eq!(NetworkEnvironment::CaptivePortal.to_string(), "captive-portal");
    }

    #[test]
    fn snapshot_from_capabilities() {
        let caps = NetworkCapabilities {
            udp_available: false,
            ..Default::default()
        };
        let snap = EnvironmentSnapshot::from_capabilities(caps);
        assert_eq!(snap.environment, NetworkEnvironment::Filtered);
        assert!(snap.timestamp > 0);
    }

    #[test]
    fn capabilities_serde() {
        let caps = NetworkCapabilities {
            udp_available: false,
            tls_inspection_detected: true,
            tls_inspector: Some("Zscaler".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&caps).unwrap();
        let de: NetworkCapabilities = serde_json::from_str(&json).unwrap();
        assert!(!de.udp_available);
        assert!(de.tls_inspection_detected);
        assert_eq!(de.tls_inspector, Some("Zscaler".to_string()));
    }

    #[test]
    fn snapshot_serde() {
        let snap = EnvironmentSnapshot::from_capabilities(NetworkCapabilities::default());
        let json = serde_json::to_string(&snap).unwrap();
        let de: EnvironmentSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(de.environment, NetworkEnvironment::Open);
    }
}
