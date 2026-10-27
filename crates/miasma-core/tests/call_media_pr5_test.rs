//! Media over two real endpoints on a local relay. This does not assert a direct path.
#![cfg(feature = "iroh")]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use iroh::{endpoint::Connection, tls::CaTlsConfig};
use miasma_core::{
    chat::call::{
        device::{RecordingSink, ToneSource},
        media::Direction,
        session::{DatagramLink, MediaSession, TickStatus},
    },
    config::IrohMode,
    transport::{
        call_link::IrohDatagramLink,
        iroh_direct::{
            endpoint_builder, CallConnectionHandler, IrohNode, IrohServerLimits, IrohSettings,
        },
    },
};
use zeroize::Zeroizing;

struct Relay {
    _server: iroh_relay::server::Server,
    url: String,
}

async fn relay() -> Relay {
    let mut cfg = iroh_relay::server::testing::server_config();
    cfg.quic = None;
    let server = iroh_relay::server::Server::spawn(cfg).await.unwrap();
    let url = format!("https://{}", server.https_addr().unwrap());
    Relay {
        _server: server,
        url,
    }
}

async fn start_node(url: &str) -> (Arc<IrohNode>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    miasma_core::state_crypto::provision_master_key(dir.path()).unwrap();
    let store = Arc::new(miasma_core::LocalShareStore::open(dir.path(), 10).unwrap());
    let settings = IrohSettings {
        mode: IrohMode::Custom,
        relay_urls: vec![url.to_owned()],
        discovery: false,
        lan_discovery: false,
        connect_timeout: Duration::from_secs(20),
        ca_pem: None,
        proxy_from_env: false,
    };
    let seed = Zeroizing::new(rand::random::<[u8; 32]>());
    let builder = endpoint_builder(Some(&seed), &settings, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    let node =
        IrohNode::start_from_builder(builder, settings, store, None, IrohServerLimits::default())
            .await
            .unwrap();
    assert!(node.wait_online(Duration::from_secs(20)).await);
    (node, dir)
}

struct Accept {
    sender: Mutex<Option<tokio::sync::oneshot::Sender<Connection>>>,
    expected: [u8; 32],
}

#[async_trait]
impl CallConnectionHandler for Accept {
    async fn handle(&self, conn: Connection) {
        if conn.remote_id().as_bytes() != &self.expected {
            return;
        }
        let sender = self.sender.lock().ok().and_then(|mut sender| sender.take());
        if let Some(sender) = sender {
            let _ = sender.send(conn.clone());
            conn.closed().await;
        }
    }
}

// Count every attempted send and reject an incorrectly sized frame.
struct CheckedLink {
    inner: IrohDatagramLink,
    wrong_length: u64,
}

impl DatagramLink for CheckedLink {
    fn max_len(&self) -> usize {
        self.inner.max_len()
    }
    fn send(&mut self, packet: &[u8]) -> bool {
        if packet.len() != 90 {
            self.wrong_length += 1;
            return false;
        }
        self.inner.send(packet)
    }
    fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.inner.try_recv()
    }
}

async fn drive(
    mut session: MediaSession<ToneSource, RecordingSink, CheckedLink>,
) -> MediaSession<ToneSource, RecordingSink, CheckedLink> {
    let start = tokio::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for _ in 0..150 {
        interval.tick().await;
        let now_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
        assert_eq!(session.tick(now_ms), TickStatus::Running);
    }
    let stats = session.stats();
    assert!(stats.sent >= 100);
    assert_eq!(stats.send_failed, 0);
    let frames = session.sink().frames();
    assert!(frames.len() >= 100);
    for frame in frames {
        assert!(frame.iter().all(|byte| *byte == frame[0]));
    }
    for pair in frames.windows(2) {
        assert!(pair[1][0] > pair[0][0]);
    }
    session
}

#[tokio::test]
async fn media_roundtrip_over_call_transport() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let relay = relay().await;
        let (caller, _caller_dir) = start_node(&relay.url).await;
        let (callee, _callee_dir) = start_node(&relay.url).await;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        callee.set_call_handler(Arc::new(Accept {
            sender: Mutex::new(Some(sender)),
            expected: caller.endpoint_id(),
        }));
        let a = caller
            .connect_call(&callee.endpoint_id())
            .await
            .expect("call connection");
        let b = receiver.await.expect("accepted call connection");
        let a = CheckedLink {
            inner: IrohDatagramLink::new(a),
            wrong_length: 0,
        };
        let b = CheckedLink {
            inner: IrohDatagramLink::new(b),
            wrong_length: 0,
        };
        assert!(a.max_len() >= 90 && b.max_len() >= 90);
        // TEST-ONLY random root and call id: real call key derivation is not wired yet.
        let root = Zeroizing::new(rand::random::<[u8; 32]>());
        let call_id = rand::random::<[u8; 16]>();
        let a = MediaSession::new(
            &root,
            call_id,
            Direction::Caller,
            0,
            ToneSource::new(),
            RecordingSink::new(),
            a,
        )
        .unwrap();
        let b = MediaSession::new(
            &root,
            call_id,
            Direction::Callee,
            0,
            ToneSource::new(),
            RecordingSink::new(),
            b,
        )
        .unwrap();
        let (_a, _b) = tokio::join!(drive(a), drive(b));
    })
    .await
    .expect("media round trip timed out");
}
