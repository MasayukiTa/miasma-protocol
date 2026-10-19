//! A current node against peers that speak the protocol set of an earlier
//! release, over a local iroh relay: what the sender sees when a message
//! cannot be delivered, and that a peer of any age still shows up as a
//! suggestion when it is not yet a contact.

#![cfg(feature = "iroh")]

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use iroh::{endpoint::Connection, tls::CaTlsConfig};
use miasma_core::{
    chat::{
        crypto::Identity,
        engine::ChatCore,
        ipc::handle_with,
        outbox::{new_receipt, Outbox},
        proto::{self, Ack, Frame, CLOSE_NOT_ALLOWED},
        service::{ChatService, ChatSettings},
        store::{ChatStore, MsgState, StoreSettings},
        ChatRequest, ChatResponse,
    },
    config::IrohMode,
    push::{ContactCode, ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{
        endpoint_builder, ChatConnectionHandler, IrohNode, IrohServerLimits, IrohSettings,
        CHAT_ALPN, IROH_ALPN, PUSH_ALPN,
    },
    LocalShareStore,
};

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

/// A node. With `alpns` it lists only those application protocols, like a
/// build from before the others existed.
async fn start_node(
    relay: &Relay,
    seed: &[u8; 32],
    alpns: Option<Vec<&'static [u8]>>,
) -> Arc<IrohNode> {
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
    let mut builder = endpoint_builder(Some(seed), &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    if let Some(list) = alpns {
        builder = builder.alpns(list.into_iter().map(|a| a.to_vec()).collect());
    }
    let node = IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
        .await
        .unwrap();
    assert!(node.wait_online(Duration::from_secs(20)).await);
    std::mem::forget(store_dir);
    node
}

fn fast() -> ChatSettings {
    ChatSettings {
        retry_delays: vec![Duration::from_millis(200)],
        retry_every: Duration::from_millis(300),
        retry_jitter: 0.0,
        idle_timeout: Duration::from_secs(20),
        ..ChatSettings::default()
    }
}

struct Side {
    svc: Arc<ChatService>,
    contacts: Arc<ContactStore>,
    node: Arc<IrohNode>,
    id: [u8; 32],
    _dir: tempfile::TempDir,
}

/// A full current chat service.
async fn current(relay: &Relay, alpns: Option<Vec<&'static [u8]>>) -> Side {
    let seed: [u8; 32] = rand::random();
    let dir = tempfile::tempdir().unwrap();
    let node = start_node(relay, &seed, alpns).await;
    let contacts = Arc::new(ContactStore::open(dir.path()));
    let keys = Arc::new(StateKeys::open_or_init(dir.path()).unwrap());
    let svc = ChatService::start(
        &dir.path().join("chat"),
        node.clone(),
        &seed,
        keys,
        contacts.clone(),
        StoreSettings::default(),
        fast(),
    )
    .expect("chat starts");
    Side {
        svc,
        contacts,
        id: node.endpoint_id(),
        node,
        _dir: dir,
    }
}

fn add_contact(of: &Side, other: &Side, label: &str) {
    of.contacts
        .add(&ContactCode::new(other.id), Some(label), Some(&of.id))
        .unwrap();
}

fn send(a: &Arc<ChatService>, to: &str, text: &str) {
    assert!(matches!(
        handle_with(
            a,
            ChatRequest::Send {
                contact: to.into(),
                text: text.into(),
            },
        ),
        ChatResponse::Queued { .. }
    ));
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

/// A hand-written receiver standing in for a release. `bad_after`: from this
/// delivery on it answers "bad request" without looking (a build that does not
/// know the record). `raw_status`: answer with this status byte plus two
/// appended bytes (a build with a newer acknowledgement).
struct Hand {
    core: Arc<ChatCore>,
    delivers: AtomicUsize,
    bad_after: usize,
    raw_status: Option<u8>,
}

impl Hand {
    fn new(seed: &[u8; 32], peer: &Side, bad_after: usize, raw_status: Option<u8>) -> Arc<Self> {
        let dir = tempfile::tempdir().unwrap();
        let keys = Arc::new(StateKeys::open_or_init(dir.path()).unwrap());
        let id = Identity::from_seed(seed);
        let chat = dir.path().join("chat");
        let store =
            ChatStore::open(&chat, keys.clone(), id.id(), StoreSettings::default()).unwrap();
        let (outbox, _) = Outbox::open(
            &miasma_core::paths::chat_outbox_file(&chat),
            keys,
            StoreSettings::default(),
            1,
        );
        std::mem::forget(dir);
        let _ = peer;
        Arc::new(Self {
            core: Arc::new(ChatCore::new(store, outbox, id, 4096)),
            delivers: AtomicUsize::new(0),
            bad_after,
            raw_status,
        })
    }
}

#[async_trait::async_trait]
impl ChatConnectionHandler for Hand {
    async fn handle(&self, conn: Connection) {
        let remote = *conn.remote_id().as_bytes();
        // Like a build from before the catch-up: bidirectional streams only.
        while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
            let Ok(Frame::Deliver(wire)) = proto::read_frame(&mut rx).await else {
                return;
            };
            let n = self.delivers.fetch_add(1, Ordering::SeqCst);
            let env_id: [u8; 16] = wire[3..19].try_into().unwrap();
            if let Some(code) = self.raw_status {
                let mut payload = vec![code];
                payload.extend_from_slice(&env_id);
                payload.extend_from_slice(&[1, 2]);
                let mut f = ((payload.len() + 1) as u32).to_be_bytes().to_vec();
                f.push(proto::FRAME_ACK);
                f.extend_from_slice(&payload);
                let _ = tokio::io::AsyncWriteExt::write_all(&mut tx, &f).await;
            } else {
                let status = if n >= self.bad_after {
                    proto::AckStatus::BadRequest
                } else {
                    self.core.accept(&remote, &wire, 1).status
                };
                let _ = proto::write_frame(
                    &mut tx,
                    &Frame::Ack(Ack {
                        status,
                        envelope_id: env_id,
                    }),
                )
                .await;
            }
            let _ = tx.finish();
        }
    }
}

fn waiting_row(a: &Side, peer: &[u8; 32]) -> Option<miasma_core::chat::store::StoredMessage> {
    a.svc
        .core()
        .history(peer, None, 20)
        .into_iter()
        .find(|m| m.outgoing)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_without_chat_leaves_the_message_waiting_with_the_reason_and_the_time() {
    let r = relay().await;
    let a = current(&r, None).await;
    // A build from before chat: file push and direct fetch only.
    let b_seed: [u8; 32] = rand::random();
    let b_node = start_node(&r, &b_seed, Some(vec![IROH_ALPN, PUSH_ALPN])).await;
    a.contacts
        .add(&ContactCode::new(b_node.endpoint_id()), Some("bob"), None)
        .unwrap();
    send(&a.svc, "bob", "are you there");
    let peer = b_node.endpoint_id();
    let end = std::time::Instant::now() + Duration::from_secs(30);
    let m = loop {
        let row = waiting_row(&a, &peer);
        if let Some(m) = row
            .clone()
            .filter(|m| m.reason.as_deref() == Some("peer_no_chat"))
        {
            break m;
        }
        assert!(
            std::time::Instant::now() < end,
            "no peer_no_chat reason; the row is {row:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        matches!(m.state, MsgState::Queued | MsgState::Sending),
        "still waiting, not failed: {:?}",
        m.state
    );
    assert!(m.tried_ms > 0, "the time of the last attempt is carried");
    // The same through the IPC the CLI and the desktop read.
    match handle_with(&a.svc, ChatRequest::Conversations {}) {
        ChatResponse::Conversations(list) => {
            let c = list
                .iter()
                .find(|c| c.label.as_deref() == Some("bob"))
                .unwrap();
            assert_eq!(c.pending, 1);
            assert_eq!(c.pending_reason.as_deref(), Some("peer_no_chat"));
            assert!(c.pending_tried_ms > 0);
        }
        other => panic!("{other:?}"),
    }
    let h = handle_with(
        &a.svc,
        ChatRequest::History {
            contact: "bob".into(),
            before: None,
            limit: Some(20),
        },
    );
    match h {
        ChatResponse::History { messages, .. } => {
            assert_eq!(messages[0].state, "queued");
            assert_eq!(messages[0].reason.as_deref(), Some("peer_no_chat"));
            assert!(messages[0].tried_ms > 0);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_has_not_registered_us_ends_the_message_as_not_allowed() {
    let r = relay().await;
    let a = current(&r, None).await;
    let b = current(&r, None).await; // has no contact for A
    add_contact(&a, &b, "bob");
    send(&a.svc, "bob", "hello stranger");
    until(
        40,
        "the message to end as failed",
        || matches!(waiting_row(&a, &b.id), Some(m) if m.state == MsgState::Failed),
    )
    .await;
    let m = waiting_row(&a, &b.id).unwrap();
    assert_eq!(m.reason.as_deref(), Some("not_allowed"));
    // And B keeps the sender as a suggestion for its contact list.
    until(10, "the suggestion", || {
        b.contacts
            .unknown()
            .list()
            .iter()
            .any(|s| s.endpoint == a.id)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_of_beta_2_still_becomes_a_suggestion_when_it_is_not_a_contact() {
    let r = relay().await;
    let a = current(&r, None).await; // no contacts at all
    let old_seed: [u8; 32] = rand::random();
    // beta.2: direct, push and chat, no group ALPN.
    let old = start_node(&r, &old_seed, Some(vec![IROH_ALPN, PUSH_ALPN, CHAT_ALPN])).await;
    let conn = old.connect_alpn(&a.id, CHAT_ALPN).await.expect("dials");
    // It writes a delivery as that release does; the answer is a refusal.
    let (mut tx, _rx) = conn.open_bi().await.unwrap();
    let junk = proto::encode_frame(&Frame::Deliver(vec![0; 64]));
    let _ = tokio::io::AsyncWriteExt::write_all(&mut tx, &junk).await;
    let _ = tx.finish();
    let closed = tokio::time::timeout(Duration::from_secs(10), conn.closed())
        .await
        .expect("the receiver closes the connection");
    let text = format!("{closed:?}");
    assert!(
        text.contains(&CLOSE_NOT_ALLOWED.to_string()),
        "closed with 403: {text}"
    );
    assert!(a
        .contacts
        .unknown()
        .list()
        .iter()
        .any(|s| s.endpoint == old.endpoint_id()));
}

#[tokio::test(flavor = "multi_thread")]
async fn read_receipts_stop_after_a_peer_that_predates_them_refuses_one() {
    let r = relay().await;
    let a = current(&r, None).await;
    let b_seed: [u8; 32] = rand::random();
    let b_node = start_node(&r, &b_seed, Some(vec![IROH_ALPN, PUSH_ALPN, CHAT_ALPN])).await;
    // Takes the first delivery (the text), answers every later one "bad request".
    let hand = Hand::new(&b_seed, &a, 1, None);
    b_node.set_chat_handler(hand.clone());
    a.contacts
        .add(&ContactCode::new(b_node.endpoint_id()), Some("bob"), None)
        .unwrap();
    let peer = b_node.endpoint_id();
    send(&a.svc, "bob", "hi");
    until(40, "the text to arrive", || a.svc.core().outbox.is_empty()).await;
    assert_eq!(hand.delivers.load(Ordering::SeqCst), 1);

    let now = miasma_core::chat::engine::now_ms();
    let queue_receipt = |up_to: u64| {
        a.svc
            .core()
            .outbox
            .push_receipt(new_receipt(rand::random(), peer, up_to, now))
            .unwrap();
        a.svc.kick(&peer);
    };
    queue_receipt(1);
    until(30, "the first receipt to be tried and dropped", || {
        hand.delivers.load(Ordering::SeqCst) == 2 && a.svc.core().outbox.is_empty()
    })
    .await;
    // The next one is not sent at all.
    queue_receipt(1);
    until(10, "the second receipt to be dropped", || {
        a.svc.core().outbox.is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        hand.delivers.load(Ordering::SeqCst),
        2,
        "no further receipt reached the old peer"
    );
    // Nothing shows up as failed.
    assert!(a
        .svc
        .core()
        .history(&peer, None, 20)
        .iter()
        .all(|m| m.state != MsgState::Failed));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_acknowledgement_from_a_newer_build_keeps_the_message_waiting() {
    let r = relay().await;
    let a = current(&r, None).await;
    let b_seed: [u8; 32] = rand::random();
    let b_node = start_node(&r, &b_seed, None).await;
    let hand = Hand::new(&b_seed, &a, usize::MAX, Some(77));
    b_node.set_chat_handler(hand.clone());
    a.contacts
        .add(&ContactCode::new(b_node.endpoint_id()), Some("bob"), None)
        .unwrap();
    send(&a.svc, "bob", "hello from the past");
    let peer = b_node.endpoint_id();
    until(30, "the status to be noted", || {
        matches!(waiting_row(&a, &peer), Some(m) if m.reason.as_deref() == Some("peer_status_unknown"))
    })
    .await;
    let m = waiting_row(&a, &peer).unwrap();
    assert!(matches!(m.state, MsgState::Queued | MsgState::Sending));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frame_from_a_newer_build_does_not_end_the_connection() {
    let r = relay().await;
    let a = current(&r, None).await;
    let n_seed: [u8; 32] = rand::random();
    let newer = start_node(&r, &n_seed, None).await;
    // A must know the dialer, or it refuses the connection first.
    a.contacts
        .add(&ContactCode::new(newer.endpoint_id()), Some("newer"), None)
        .unwrap();
    let conn = newer.connect_alpn(&a.id, CHAT_ALPN).await.expect("dials");
    // A unidirectional frame of a type this build does not know.
    let mut tx = conn.open_uni().await.unwrap();
    let mut f = 3u32.to_be_bytes().to_vec();
    f.extend_from_slice(&[0x7e, 1, 2]);
    tokio::io::AsyncWriteExt::write_all(&mut tx, &f)
        .await
        .unwrap();
    let _ = tx.finish();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        conn.close_reason().is_none(),
        "the connection is still up: {:?}",
        conn.close_reason()
    );
}
