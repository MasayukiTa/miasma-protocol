//! The hybrid upgrade of private conversations over a local iroh relay:
//! in-process nodes running the real chat service and delivery workers, no
//! traffic to any public service (features `iroh` and `pqc`).

#![cfg(all(feature = "iroh", feature = "pqc"))]

use std::{sync::Arc, time::Duration};

use iroh::tls::CaTlsConfig;
use miasma_core::{
    chat::{
        crypto::Identity,
        ipc::{handle_with, ConversationInfo},
        service::{ChatService, ChatSettings},
        store::{MsgState, StoreSettings},
        ChatRequest, ChatResponse,
    },
    config::{IrohMode, PqcMode},
    push::{ContactCode, ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{endpoint_builder, IrohNode, IrohServerLimits, IrohSettings},
    LocalShareStore,
};
use tempfile::TempDir;

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

fn settings(mode: PqcMode) -> ChatSettings {
    ChatSettings {
        retry_delays: vec![Duration::from_millis(200)],
        retry_every: Duration::from_millis(300),
        retry_jitter: 0.0,
        idle_timeout: Duration::from_secs(20),
        pqc_mode: mode,
        ..ChatSettings::default()
    }
}

async fn start_node(relay: &Relay, seed: &[u8; 32]) -> Arc<IrohNode> {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(store_dir.path(), 10).unwrap());
    let s = IrohSettings {
        mode: IrohMode::Custom,
        relay_urls: vec![relay.url.clone()],
        discovery: false,
        lan_discovery: false,
        connect_timeout: Duration::from_secs(4),
        ca_pem: None,
        proxy_from_env: false,
    };
    let builder = endpoint_builder(Some(seed), &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    let node = IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
        .await
        .unwrap();
    assert!(node.wait_online(Duration::from_secs(20)).await);
    std::mem::forget(store_dir);
    node
}

struct Peer {
    node: Arc<IrohNode>,
    svc: Arc<ChatService>,
    contacts: Arc<ContactStore>,
    _dir: TempDir,
}

impl Peer {
    fn id(&self) -> [u8; 32] {
        self.node.endpoint_id()
    }
}

async fn peer(relay: &Relay, mode: PqcMode) -> Peer {
    let dir = tempfile::tempdir().unwrap();
    let seed: [u8; 32] = rand::random();
    let node = start_node(relay, &seed).await;
    let contacts = Arc::new(ContactStore::open(dir.path()));
    let keys = Arc::new(StateKeys::open_or_init(dir.path()).unwrap());
    let svc = ChatService::start(
        &dir.path().join("chat"),
        node.clone(),
        &seed,
        keys,
        contacts.clone(),
        StoreSettings::default(),
        settings(mode),
    )
    .expect("chat starts");
    assert_eq!(Identity::from_seed(&seed).id(), node.endpoint_id());
    Peer {
        node,
        svc,
        contacts,
        _dir: dir,
    }
}

fn register(a: &Peer, b_id: [u8; 32], label: &str) {
    a.contacts
        .add(&ContactCode::new(b_id), Some(label), Some(&a.id()))
        .unwrap();
}

fn send(a: &Peer, label: &str, text: &str) {
    let r = handle_with(
        &a.svc,
        ChatRequest::Send {
            contact: label.into(),
            text: text.into(),
        },
    );
    assert!(matches!(r, ChatResponse::Queued { .. }), "{r:?}");
}

fn texts(p: &Peer, other: &[u8; 32]) -> Vec<String> {
    p.svc
        .core()
        .history(other, None, 200)
        .into_iter()
        .map(|m| m.text)
        .collect()
}

fn conversation(p: &Peer, other: &[u8; 32]) -> Option<ConversationInfo> {
    match handle_with(&p.svc, ChatRequest::Conversations {}) {
        ChatResponse::Conversations(list) => list
            .into_iter()
            .find(|c| c.endpoint_id == hex::encode(other)),
        other => panic!("{other:?}"),
    }
}

fn pqc_of(p: &Peer, other: &[u8; 32]) -> (Option<String>, Option<String>) {
    conversation(p, other).map_or((None, None), |c| (c.pqc, c.pqc_reason))
}

async fn until(secs: u64, what: &str, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(
            std::time::Instant::now() < end,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_builds_with_the_setting_on_reach_hybrid_and_keep_talking() {
    let r = relay().await;
    let (a, b) = (
        peer(&r, PqcMode::Prefer).await,
        peer(&r, PqcMode::Prefer).await,
    );
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    send(&a, "bob", "first");
    until(60, "the first message", || texts(&b, &a.id()).len() == 1).await;
    until(60, "hybrid at both", || {
        pqc_of(&a, &b.id()).0.as_deref() == Some("hybrid")
            && pqc_of(&b, &a.id()).0.as_deref() == Some("hybrid")
    })
    .await;
    // From here on the messages are protected by the hybrid key as well.
    send(&b, "alice", "from bob");
    send(&a, "bob", "second");
    until(60, "messages after the upgrade", || {
        texts(&a, &b.id()).len() == 3 && texts(&b, &a.id()).len() == 3
    })
    .await;
    until(30, "acknowledgements", || {
        a.svc.core().outbox.is_empty() && b.svc.core().outbox.is_empty()
    })
    .await;
    assert!(a
        .svc
        .core()
        .history(&b.id(), None, 50)
        .iter()
        .filter(|m| m.outgoing)
        .all(|m| m.state == MsgState::Delivered));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_with_the_setting_off_is_shown_as_classical_only() {
    let r = relay().await;
    let (a, b) = (
        peer(&r, PqcMode::Prefer).await,
        peer(&r, PqcMode::Off).await,
    );
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    send(&a, "bob", "hello");
    until(60, "the message", || texts(&b, &a.id()).len() == 1).await;
    until(60, "classical only", || {
        pqc_of(&a, &b.id()) == (Some("classical".into()), Some("peer_no_hybrid".into()))
    })
    .await;
    send(&b, "alice", "reply");
    until(60, "the reply", || texts(&a, &b.id()).len() == 2).await;
    // The side that has it off shows nothing and negotiated nothing.
    assert_eq!(pqc_of(&b, &a.id()), (None, None));
}

#[tokio::test(flavor = "multi_thread")]
async fn require_fails_locally_when_the_peer_does_not_offer_it() {
    let r = relay().await;
    let (a, b) = (
        peer(&r, PqcMode::Require).await,
        peer(&r, PqcMode::Off).await,
    );
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    send(&a, "bob", "secret");
    until(90, "the refusal", || {
        a.svc
            .core()
            .history(&b.id(), None, 10)
            .iter()
            .any(|m| m.state == MsgState::Failed)
    })
    .await;
    let hist = a.svc.core().history(&b.id(), None, 10);
    assert_eq!(hist[0].reason.as_deref(), Some("pqc_peer_no_hybrid"));
    // Nothing was sent in the classical session.
    assert!(texts(&b, &a.id()).is_empty());
    // The other side is unaffected and can still write.
    send(&b, "alice", "still here");
    until(60, "the message from the other side", || {
        texts(&a, &b.id()).iter().any(|t| t == "still here")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn require_sends_once_the_peer_has_agreed() {
    let r = relay().await;
    let (a, b) = (
        peer(&r, PqcMode::Require).await,
        peer(&r, PqcMode::Prefer).await,
    );
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    send(&a, "bob", "protected");
    until(60, "the message", || texts(&b, &a.id()).len() == 1).await;
    assert_eq!(pqc_of(&a, &b.id()).0.as_deref(), Some("hybrid"));
}

/// The mode a fresh configuration now gives (`prefer`) against the mode the
/// previous release gave (`off`): nothing is held back in either direction, and
/// the new-default side reports "classical only" for the older one.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_default_build_and_an_old_default_build_keep_talking() {
    let new_default = miasma_core::config::NodeConfig::default()
        .privacy
        .pqc_mode();
    assert_eq!(new_default, PqcMode::Prefer);
    let old_default: PqcMode = "off".parse().unwrap();
    let r = relay().await;
    let (a, b) = (peer(&r, new_default).await, peer(&r, old_default).await);
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    for i in 0..3 {
        send(&a, "bob", &format!("to old {i}"));
        send(&b, "alice", &format!("to new {i}"));
    }
    until(90, "all six messages", || {
        texts(&a, &b.id()).len() == 6 && texts(&b, &a.id()).len() == 6
    })
    .await;
    until(60, "classical only", || {
        pqc_of(&a, &b.id()) == (Some("classical".into()), Some("peer_no_hybrid".into()))
    })
    .await;
    assert_eq!(pqc_of(&b, &a.id()), (None, None));
    until(30, "acknowledgements", || {
        a.svc.core().outbox.is_empty() && b.svc.core().outbox.is_empty()
    })
    .await;
}
