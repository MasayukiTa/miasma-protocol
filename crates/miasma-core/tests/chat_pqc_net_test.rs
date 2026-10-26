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

/// The bodies this side received from `other` (incoming only). `texts` mixes in
/// this side's own outgoing bodies, which share the same conversation key, so a
/// check for "did the peer's body arrive" must exclude what we sent ourselves.
fn received(p: &Peer, other: &[u8; 32]) -> Vec<String> {
    p.svc
        .core()
        .history(other, None, 200)
        .into_iter()
        .filter(|m| !m.outgoing)
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
    until(60, "the first message", || received(&b, &a.id()).len() == 1).await;
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
    until(60, "the message", || received(&b, &a.id()).len() == 1).await;
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
    // Nothing was sent in the classical session (b received no body from a).
    assert!(received(&b, &a.id()).is_empty());
    // The other side is unaffected and can still write.
    send(&b, "alice", "still here");
    until(60, "the message from the other side", || {
        received(&a, &b.id()).iter().any(|t| t == "still here")
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
    until(60, "the message", || received(&b, &a.id()).len() == 1).await;
    assert_eq!(pqc_of(&a, &b.id()).0.as_deref(), Some("hybrid"));
}

/// The mode a fresh configuration now gives (`require`) against the mode the
/// previous release gave (`off`): the new-default side refuses rather than fall
/// back to a classical session, so its own messages fail and nothing is sent in
/// the clear; the old-default side is unaffected and its messages still arrive.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_default_build_refuses_an_old_default_build_and_does_not_fall_back() {
    let new_default = miasma_core::config::NodeConfig::default()
        .privacy
        .pqc_mode();
    assert_eq!(new_default, PqcMode::Require);
    let old_default: PqcMode = "off".parse().unwrap();
    let r = relay().await;
    let (a, b) = (peer(&r, new_default).await, peer(&r, old_default).await);
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    for i in 0..3 {
        send(&a, "bob", &format!("to old {i}"));
        send(&b, "alice", &format!("to new {i}"));
    }
    // The old-default side can still send in the classical session: `a` receives.
    // Count only incoming bodies: `a`'s own three outgoing sends fail but remain
    // in history, so `texts` would read six here and never equal three.
    until(90, "the three messages from the old build", || {
        received(&a, &b.id()).len() == 3
    })
    .await;
    // The require side never sends in the clear: `b` receives none of a's three.
    until(90, "a's messages all failing on the require side", || {
        let h = a.svc.core().history(&b.id(), None, 20);
        h.iter().filter(|m| m.outgoing).count() == 3
            && h.iter()
                .filter(|m| m.outgoing)
                .all(|m| m.state == MsgState::Failed)
    })
    .await;
    assert!(
        received(&b, &a.id()).is_empty(),
        "no classical fallback under require"
    );
    // Every outgoing message failed for the no-hybrid reason. The history also
    // holds the three incoming bodies from the off side, so the first entry is
    // not necessarily one of ours: check each outgoing entry, not entry zero.
    let h = a.svc.core().history(&b.id(), None, 20);
    let ours: Vec<_> = h.iter().filter(|m| m.outgoing).collect();
    assert_eq!(ours.len(), 3);
    assert!(
        ours.iter()
            .all(|m| m.reason.as_deref() == Some("pqc_peer_no_hybrid")),
        "every refused send carries the no-hybrid reason"
    );
}

/// Guards the test helper itself: a conversation key is shared by both
/// directions, so `texts` returns this side's own sent bodies as well as what
/// arrived, while `received` returns only the incoming ones. A check for "did
/// the peer's body arrive" must use `received`, or a side that has only sent
/// would look as if it had received.
#[tokio::test(flavor = "multi_thread")]
async fn received_excludes_this_sides_own_outgoing_bodies() {
    let r = relay().await;
    let (a, b) = (
        peer(&r, PqcMode::Prefer).await,
        peer(&r, PqcMode::Prefer).await,
    );
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    send(&a, "bob", "only from a");
    until(60, "a's body to arrive at b", || {
        received(&b, &a.id()).iter().any(|t| t == "only from a")
    })
    .await;
    // a has sent one and received nothing: `texts` shows its own body, but
    // `received` is empty for a.
    until(30, "a's own send to settle", || {
        texts(&a, &b.id()).iter().any(|t| t == "only from a")
    })
    .await;
    assert!(
        texts(&a, &b.id()).iter().any(|t| t == "only from a"),
        "texts includes this side's own outgoing body"
    );
    assert!(
        received(&a, &b.id()).is_empty(),
        "received excludes this side's own outgoing body"
    );
}

/// The require side must not put a body in the clear even when the old-default
/// peer transmits first: `b` sends three before `a` is asked to, yet none of
/// `a`'s own bodies reach `b`. This pins the ordering where the peer's traffic
/// arrives before the local refusal is decided.
#[tokio::test(flavor = "multi_thread")]
async fn require_does_not_leak_bodies_even_when_the_peer_sends_first() {
    let r = relay().await;
    let (a, b) = (
        peer(&r, PqcMode::Require).await,
        peer(&r, PqcMode::Off).await,
    );
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    // The old-default side transmits first and repeatedly.
    for i in 0..3 {
        send(&b, "alice", &format!("old first {i}"));
    }
    until(90, "all three from the old build to arrive at a", || {
        received(&a, &b.id()).len() == 3
    })
    .await;
    // Only now does the require side try to send.
    for i in 0..3 {
        send(&a, "bob", &format!("from require {i}"));
    }
    until(90, "a's messages all failing on the require side", || {
        let h = a.svc.core().history(&b.id(), None, 20);
        h.iter().filter(|m| m.outgoing).count() == 3
            && h.iter()
                .filter(|m| m.outgoing)
                .all(|m| m.state == MsgState::Failed)
    })
    .await;
    // None of a's bodies were put in the clear: b received nothing from a.
    assert!(
        received(&b, &a.id()).is_empty(),
        "no classical fallback under require even when the peer sends first"
    );
}

/// Pins the wait-condition contract that the timeout bug violated: when the
/// require side (`a`) has itself sent three bodies to the off side (`b`) that
/// all fail and stay in history, a wait for "the peer's three arrived" must use
/// `received` (incoming only). `texts` on `a` mixes in its own three failed
/// sends and settles at six, so a wait written as `texts(&a).len() == 3` never
/// holds. This guards the condition, not just the assertion.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_for_the_peers_bodies_counts_incoming_not_our_failed_sends() {
    let r = relay().await;
    let (a, b) = (
        peer(&r, PqcMode::Require).await,
        peer(&r, PqcMode::Off).await,
    );
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    for i in 0..3 {
        send(&a, "bob", &format!("to old {i}"));
        send(&b, "alice", &format!("to new {i}"));
    }
    // The three incoming bodies from the off side settle at exactly three.
    until(90, "the three incoming bodies on the require side", || {
        received(&a, &b.id()).len() == 3
    })
    .await;
    // `a`'s own three sends all fail under require and remain in history.
    until(90, "a's own three sends all failing", || {
        let h = a.svc.core().history(&b.id(), None, 20);
        h.iter().filter(|m| m.outgoing).count() == 3
            && h.iter()
                .filter(|m| m.outgoing)
                .all(|m| m.state == MsgState::Failed)
    })
    .await;
    // The distinction the fix depends on: `received` is the three that arrived,
    // while `texts` additionally counts `a`'s own three failed sends.
    assert_eq!(
        received(&a, &b.id()).len(),
        3,
        "received counts only the peer's incoming bodies"
    );
    assert_eq!(
        texts(&a, &b.id()).len(),
        6,
        "texts also counts this side's own three failed outgoing sends"
    );
}
