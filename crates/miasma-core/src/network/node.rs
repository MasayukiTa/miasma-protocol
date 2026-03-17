/// Miasma libp2p node — Phase 1 (ADR-001: libp2p-quic).
///
/// Transport: QUIC only (`libp2p-quic`, ADR-001)
/// DHT: Kademlia — accessed ONLY via `OnionAwareDhtExecutor` (ADR-002)
/// NAT: AutoNAT (external address probing) + DCUtR (QUIC hole-punching via relay)
use std::time::Duration;

use futures::StreamExt as _;
use libp2p::{
    autonat, dcutr, identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    noise, ping, relay, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use tokio::sync::mpsc;
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::{crypto::keyderive::NodeKeys, MiasmaError};

use super::types::NodeType;

// ─── Behaviour ────────────────────────────────────────────────────────────────

/// Combined libp2p behaviour for a Miasma node.
///
/// # NAT traversal (ADR-001)
/// - `autonat`: probes external address reachability via cooperating peers.
///   When the node is behind NAT it classifies itself as `Private` and
///   activates relay-assisted connectivity.
/// - `relay`: relay client — establishes a reservation on a relay server so
///   that peers behind NAT can route through it.
/// - `dcutr`: Direct Connection Upgrade through Relay — attempts a QUIC
///   hole-punch after an initial relay connection is established.
///
/// Kademlia is NOT called directly — use `OnionAwareDhtExecutor` (ADR-002).
#[derive(NetworkBehaviour)]
pub struct MiasmaBehaviour {
    pub(crate) kademlia: kad::Behaviour<MemoryStore>,
    pub(crate) identify: identify::Behaviour,
    pub(crate) ping: ping::Behaviour,
    pub(crate) autonat: autonat::Behaviour,
    pub(crate) relay: relay::client::Behaviour,
    pub(crate) dcutr: dcutr::Behaviour,
}

// ─── MiasmaNode ───────────────────────────────────────────────────────────────

pub struct MiasmaNode {
    pub local_peer_id: PeerId,
    pub node_type: NodeType,
    swarm: Swarm<MiasmaBehaviour>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
}

impl MiasmaNode {
    /// Build a node from the given master key.
    /// The libp2p keypair is derived deterministically via HKDF (from dht_signing_key).
    pub fn new(
        master_key: &Zeroizing<[u8; 32]>,
        node_type: NodeType,
        listen_addr: &str,
    ) -> Result<Self, MiasmaError> {
        let node_keys = NodeKeys::derive(master_key.as_ref())?;

        // ed25519_from_bytes requires a mutable slice and zeroes it on drop.
        let mut signing_bytes: [u8; 32] = *node_keys.dht_signing_key;
        let keypair = Keypair::ed25519_from_bytes(&mut signing_bytes)
            .map_err(|e| MiasmaError::KeyDerivation(e.to_string()))?;
        // Zero the copy — the Keypair now holds its own copy internally.
        zeroize::Zeroize::zeroize(&mut signing_bytes);

        let local_peer_id = PeerId::from(keypair.public());
        info!("Miasma node: peer_id={local_peer_id}, type={node_type:?}");

        let swarm = build_swarm(keypair, local_peer_id, listen_addr)?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        Ok(Self {
            local_peer_id,
            node_type,
            swarm,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Register a bootstrap peer in the Kademlia routing table.
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, addr.clone());
        info!("Bootstrap peer added: {peer_id} @ {addr}");
    }

    /// Register a relay server for NAT traversal.
    ///
    /// Instructs the relay client behaviour to establish a reservation on the
    /// given relay peer so that inbound connections can be routed through it
    /// when this node is behind NAT. DCUtR will then attempt a direct
    /// hole-punch upgrade on subsequent connections through the relay.
    pub fn add_relay_server(&mut self, peer_id: PeerId, addr: Multiaddr) {
        // Add to Kademlia routing table as well.
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, addr.clone());
        // Capture display strings before consuming values.
        let peer_id_str = peer_id.to_string();
        let addr_str = addr.to_string();
        // Dial the relay so we can establish a reservation.
        let relay_addr = addr
            .with(libp2p::multiaddr::Protocol::P2p(peer_id))
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        if let Err(e) = self.swarm.dial(relay_addr) {
            debug!("relay dial failed for {peer_id_str}: {e}");
        } else {
            info!("Relay server registered: {peer_id_str} @ {addr_str}");
        }
    }

    /// Initiate Kademlia bootstrap (find nodes close to our own ID).
    pub fn bootstrap_dht(&mut self) -> Result<(), MiasmaError> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map_err(|e| MiasmaError::Sss(format!("DHT bootstrap: {e:?}")))?;
        Ok(())
    }

    /// Clone of the shutdown sender — send `()` to stop the event loop.
    pub fn shutdown_handle(&self) -> mpsc::Sender<()> {
        self.shutdown_tx.clone()
    }

    /// Run the node event loop. Blocks until shutdown signal or error.
    pub async fn run(&mut self) -> Result<(), MiasmaError> {
        loop {
            tokio::select! {
                event = self.swarm.next() => {
                    match event {
                        Some(ev) => self.handle_event(ev),
                        None => break, // swarm closed
                    }
                }
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_event(&mut self, event: SwarmEvent<MiasmaBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {address}");
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected: {peer_id}");
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!("Disconnected: {peer_id} ({cause:?})");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                // Add peer's listen addresses to Kademlia and AutoNAT.
                for addr in &info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
                // Feed first address to AutoNAT for reachability probing.
                if let Some(first_addr) = info.listen_addrs.first() {
                    self.swarm
                        .behaviour_mut()
                        .autonat
                        .add_server(peer_id, Some(first_addr.clone()));
                }
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Kademlia(ev)) => {
                debug!("Kad: {ev:?}");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Autonat(ev)) => {
                match &ev {
                    autonat::Event::StatusChanged { old, new } => {
                        info!("AutoNAT: {old:?} → {new:?}");
                    }
                    _ => debug!("AutoNAT: {ev:?}"),
                }
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Dcutr(ev)) => {
                debug!("DCUtR: {ev:?}");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Relay(ev)) => {
                debug!("Relay client: {ev:?}");
            }
            SwarmEvent::Behaviour(MiasmaBehaviourEvent::Ping(_)) => {}
            _ => {}
        }
    }
}

// ─── Swarm builder ────────────────────────────────────────────────────────────

fn build_swarm(
    keypair: Keypair,
    local_peer_id: PeerId,
    listen_addr: &str,
) -> Result<Swarm<MiasmaBehaviour>, MiasmaError> {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| MiasmaError::Sss(format!("relay client init failed: {e}")))?
        .with_behaviour(|key: &Keypair, relay_client| {
            let store = MemoryStore::new(local_peer_id);
            let kad_config = kad::Config::new(StreamProtocol::new("/miasma/kad/1.0.0"));
            let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);
            kademlia.set_mode(Some(kad::Mode::Server));

            let identify_cfg = identify::Config::new("/miasma/id/1.0.0".into(), key.public());
            let identify = identify::Behaviour::new(identify_cfg);

            let ping = ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(30)),
            );

            let autonat = autonat::Behaviour::new(
                local_peer_id,
                autonat::Config {
                    // Probe every 60 seconds; retry after 10 failed probes.
                    refresh_interval: Duration::from_secs(60),
                    retry_interval: Duration::from_secs(10),
                    ..Default::default()
                },
            );

            let dcutr = dcutr::Behaviour::new(local_peer_id);

            Ok(MiasmaBehaviour {
                kademlia,
                identify,
                ping,
                autonat,
                relay: relay_client,
                dcutr,
            })
        })
        .map_err(|e| MiasmaError::Sss(format!("behaviour init failed: {e}")))?
        .build();

    let addr: Multiaddr = listen_addr
        .parse()
        .map_err(|e| MiasmaError::Sss(format!("invalid listen addr '{listen_addr}': {e}")))?;
    swarm
        .listen_on(addr)
        .map_err(|e| MiasmaError::Sss(format!("listen_on failed: {e}")))?;

    Ok(swarm)
}
