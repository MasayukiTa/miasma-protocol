use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Result;
use sha1::{Digest, Sha1};

use crate::config::DiscoveryConfig;

const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PEERS: usize = 64;

/// Rendezvous using a fixed Mainline info hash. Operations are time bounded.
pub struct MainlineDiscovery {
    config: DiscoveryConfig,
}

impl MainlineDiscovery {
    pub fn new(config: DiscoveryConfig) -> Self {
        Self { config }
    }

    pub fn info_hash() -> [u8; 20] {
        Sha1::digest(b"miasma-network-v1").into()
    }

    /// Announce a service port; network failures are logged and treated as offline.
    pub async fn announce(&self, port: u16) -> Result<()> {
        if !self.config.enabled || !self.config.announce {
            return Ok(());
        }
        let config = self.config.clone();
        let task = tokio::task::spawn_blocking(move || -> Result<()> {
            let dht = build(&config)?;
            dht.announce_peer(Self::info_hash().into(), Some(port))?;
            Ok(())
        });
        match tokio::time::timeout(TIMEOUT, task).await {
            Ok(Ok(Ok(()))) => (),
            other => tracing::warn!(?other, "Mainline announcement unavailable"),
        }
        Ok(())
    }

    /// Look up up to 64 unique addresses, filtering local addresses by default.
    pub async fn lookup(&self) -> Result<Vec<SocketAddr>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }
        let config = self.config.clone();
        let task = tokio::task::spawn_blocking(move || -> Result<Vec<SocketAddr>> {
            let dht = build(&config)?;
            let mut peers = HashSet::new();
            for batch in dht.get_peers(Self::info_hash().into()) {
                for address in batch {
                    let address = SocketAddr::V4(address);
                    if config.allow_private || public(address.ip()) {
                        peers.insert(address);
                    }
                    if peers.len() == MAX_PEERS {
                        return Ok(peers.into_iter().collect());
                    }
                }
            }
            Ok(peers.into_iter().collect())
        });
        match tokio::time::timeout(TIMEOUT, task).await {
            Ok(Ok(Ok(peers))) => {
                if peers.is_empty() {
                    tracing::warn!("Mainline lookup returned no peers");
                }
                Ok(peers)
            }
            other => {
                tracing::warn!(?other, "Mainline lookup unavailable");
                Ok(Vec::new())
            }
        }
    }
}

fn build(config: &DiscoveryConfig) -> Result<mainline::Dht> {
    let mut builder = mainline::Dht::builder();
    builder.request_timeout(Duration::from_secs(2));
    if !config.bootstrap.is_empty() {
        builder.bootstrap(&config.bootstrap);
    }
    Ok(builder.build()?)
}

fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_and_filter() {
        let expected: [u8; 20] = Sha1::digest(b"miasma-network-v1").into();
        assert_eq!(MainlineDiscovery::info_hash(), expected);
        assert!(!public("127.0.0.1".parse().unwrap()));
        assert!(!public("192.168.1.1".parse().unwrap()));
        assert!(!public("169.254.1.1".parse().unwrap()));
    }
    #[tokio::test]
    async fn local_network() {
        let net = mainline::Testnet::new_async(10).await.unwrap();
        let config = DiscoveryConfig {
            bootstrap: net.bootstrap.clone(),
            allow_private: true,
            ..Default::default()
        };
        let a = MainlineDiscovery::new(config.clone());
        let b = MainlineDiscovery::new(config.clone());
        assert!(b.lookup().await.unwrap().is_empty());
        let port = 10000 + rand::random::<u16>() % 50000;
        a.announce(port).await.unwrap();
        assert!(b.lookup().await.unwrap().iter().any(|p| p.port() == port));
        let filtered = MainlineDiscovery::new(DiscoveryConfig {
            allow_private: false,
            ..config
        });
        assert!(filtered.lookup().await.unwrap().is_empty());
    }
}
