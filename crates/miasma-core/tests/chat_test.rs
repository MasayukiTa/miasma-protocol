//! One-to-one chat over a local iroh relay: in-process nodes, no traffic to any
//! public service.

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
        outbox::Outbox,
        proto::{self, Ack, AckStatus, Frame},
        service::{ChatService, ChatSettings},
        store::{ChatStore, MsgState, StoreSettings},
        ChatRequest, ChatResponse,
    },
    config::IrohMode,
    push::{ContactCode, ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{
        endpoint_builder, ChatConnectionHandler, IrohNode, IrohServerLimits, IrohSettings,
        CHAT_ALPN, PUSH_ALPN,
    },
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

fn fast() -> ChatSettings {
    ChatSettings {
        retry_delays: vec![Duration::from_millis(200)],
        retry_every: Duration::from_millis(300),
        retry_jitter: 0.0,
        idle_timeout: Duration::from_secs(20),
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
    dir: TempDir,
    seed: [u8; 32],
}

impl Peer {
    fn id(&self) -> [u8; 32] {
        self.node.endpoint_id()
    }
}

fn id_of(seed: &[u8; 32]) -> [u8; 32] {
    Identity::from_seed(seed).id()
}

async fn peer_in(
    relay: &Relay,
    dir: TempDir,
    seed: [u8; 32],
    settings: ChatSettings,
    store: StoreSettings,
) -> Peer {
    let node = start_node(relay, &seed).await;
    let contacts = Arc::new(ContactStore::open(dir.path()));
    let keys = Arc::new(StateKeys::open_or_init(dir.path()).unwrap());
    let svc = ChatService::start(
        &dir.path().join("chat"),
        node.clone(),
        &seed,
        keys,
        contacts.clone(),
        store,
        settings,
    )
    .expect("chat starts");
    Peer {
        node,
        svc,
        contacts,
        dir,
        seed,
    }
}

async fn peer(relay: &Relay) -> Peer {
    peer_in(
        relay,
        tempfile::tempdir().unwrap(),
        rand::random(),
        fast(),
        StoreSettings::default(),
    )
    .await
}

/// `a` registers `b` as `label` (permits both directions).
fn register(a: &Peer, b_id: [u8; 32], label: &str) {
    a.contacts
        .add(&ContactCode::new(b_id), Some(label), Some(&a.id()))
        .unwrap();
}

fn send(a: &Peer, label: &str, text: &str) -> ChatResponse {
    handle_with(
        &a.svc,
        ChatRequest::Send {
            contact: label.into(),
            text: text.into(),
        },
    )
}

fn texts(p: &Peer, other: &[u8; 32]) -> Vec<String> {
    p.svc
        .core()
        .history(other, None, 200)
        .into_iter()
        .map(|m| m.text)
        .collect()
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
async fn both_registered_messages_arrive_both_ways_in_order() {
    let r = relay().await;
    let (a, b) = (peer(&r).await, peer(&r).await);
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    for i in 0..6 {
        assert!(matches!(
            send(&a, "bob", &format!("a{i}")),
            ChatResponse::Queued { .. }
        ));
    }
    until(30, "6 messages at bob", || texts(&b, &a.id()).len() == 6).await;
    assert!(matches!(
        send(&b, "alice", "こんにちは"),
        ChatResponse::Queued { .. }
    ));
    send(&b, "alice", "second");
    until(30, "replies at alice", || texts(&a, &b.id()).len() == 8).await;
    assert_eq!(
        texts(&b, &a.id())[..6],
        ["a0", "a1", "a2", "a3", "a4", "a5"].map(String::from)
    );
    let at_a = texts(&a, &b.id());
    assert_eq!(at_a[6..], ["こんにちは", "second"].map(String::from));
    until(30, "acknowledgements", || {
        a.svc.core().outbox.is_empty() && b.svc.core().outbox.is_empty()
    })
    .await;
    let hist = a.svc.core().history(&b.id(), None, 50);
    assert!(hist
        .iter()
        .filter(|m| m.outgoing)
        .all(|m| m.state == MsgState::Delivered));
    // Nothing was applied twice.
    assert_eq!(texts(&b, &a.id()).len(), 8); // 6 received + its own 2
}

#[tokio::test(flavor = "multi_thread")]
async fn a_receiver_that_has_not_registered_the_sender_stores_nothing() {
    let r = relay().await;
    let (a, b) = (peer(&r).await, peer(&r).await);
    register(&a, b.id(), "bob"); // bob does not register alice
    send(&a, "bob", "let me in");
    until(30, "the refusal", || a.svc.core().outbox.is_empty()).await;
    let hist = a.svc.core().history(&b.id(), None, 10);
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].state, MsgState::Failed);
    assert_eq!(hist[0].reason.as_deref(), Some("not_allowed"));
    assert!(b.svc.core().store.conversations().is_empty());
    assert!(texts(&b, &a.id()).is_empty());
    // A contact who may not send (allow_receive off) is refused too.
    register(&b, a.id(), "alice");
    b.contacts
        .update(
            "alice",
            &miasma_core::push::ContactUpdate {
                allow_receive: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    send(&a, "bob", "again");
    until(30, "second refusal", || a.svc.core().outbox.is_empty()).await;
    assert!(texts(&b, &a.id()).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_to_an_offline_contact_is_delivered_when_it_comes_online() {
    let r = relay().await;
    let a = peer(&r).await;
    let b_seed: [u8; 32] = rand::random();
    let b_dir = tempfile::tempdir().unwrap();
    register(&a, id_of(&b_seed), "bob");
    send(&a, "bob", "are you there?");
    send(&a, "bob", "second while away");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(a.svc.core().outbox.len(), 2, "still waiting");
    // Queued messages show up in the history as waiting.
    let h = a.svc.core().history(&id_of(&b_seed), None, 10);
    assert!(h.iter().all(|m| m.state != MsgState::Delivered));
    // Bob starts, and has registered alice.
    let b_contacts_first = ContactStore::open(b_dir.path());
    b_contacts_first
        .add(&ContactCode::new(a.id()), Some("alice"), None)
        .unwrap();
    drop(b_contacts_first);
    let b = peer_in(&r, b_dir, b_seed, fast(), StoreSettings::default()).await;
    until(40, "delivery after start", || texts(&b, &a.id()).len() == 2).await;
    assert_eq!(
        texts(&b, &a.id()),
        ["are you there?", "second while away"].map(String::from)
    );
    until(10, "acks", || a.svc.core().outbox.is_empty()).await;
}

/// A receiver written by hand that misbehaves on the first attempt.
struct Flaky {
    core: Arc<ChatCore>,
    contacts: Arc<ContactStore>,
    attempts: AtomicUsize,
    /// Apply the first message before dropping the connection (a lost
    /// acknowledgement) or drop it before (a lost message).
    apply_first: bool,
}

#[async_trait::async_trait]
impl ChatConnectionHandler for Flaky {
    async fn handle(&self, conn: Connection) {
        let remote = *conn.remote_id().as_bytes();
        assert!(self.contacts.by_endpoint(&remote).is_some());
        while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
            let Ok(Frame::Deliver(wire)) = proto::read_frame(&mut rx).await else {
                return;
            };
            let n = self.attempts.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                if self.apply_first {
                    let o = self.core.accept(&remote, &wire, 1);
                    assert_eq!(o.status, AckStatus::Stored);
                }
                conn.close(7u32.into(), b"cut");
                return;
            }
            let status = self.core.accept(&remote, &wire, 2).status;
            let env_id: [u8; 16] = wire[3..19].try_into().unwrap();
            let _ = proto::write_frame(
                &mut tx,
                &Frame::Ack(Ack {
                    status,
                    envelope_id: env_id,
                }),
            )
            .await;
            let _ = tx.finish();
        }
    }
}

async fn flaky_run(apply_first: bool) {
    let r = relay().await;
    let a = peer(&r).await;
    let b_seed: [u8; 32] = rand::random();
    let b_dir = tempfile::tempdir().unwrap();
    let b_node = start_node(&r, &b_seed).await;
    let contacts = Arc::new(ContactStore::open(b_dir.path()));
    contacts
        .add(&ContactCode::new(a.id()), Some("alice"), None)
        .unwrap();
    let keys = Arc::new(StateKeys::open_or_init(b_dir.path()).unwrap());
    let id = Identity::from_seed(&b_seed);
    let chat = b_dir.path().join("chat");
    let store = ChatStore::open(&chat, keys.clone(), id.id(), StoreSettings::default()).unwrap();
    let (outbox, _) = Outbox::open(
        &miasma_core::paths::chat_outbox_file(&chat),
        keys,
        StoreSettings::default(),
        1,
    );
    let core = Arc::new(ChatCore::new(store, outbox, id, 4096));
    let flaky = Arc::new(Flaky {
        core: core.clone(),
        contacts,
        attempts: AtomicUsize::new(0),
        apply_first,
    });
    b_node.set_chat_handler(flaky.clone());
    register(&a, b_node.endpoint_id(), "bob");
    send(&a, "bob", "cut in the middle");
    until(30, "delivery after the cut", || {
        a.svc.core().outbox.is_empty()
    })
    .await;
    let got: Vec<String> = core
        .history(&a.id(), None, 10)
        .into_iter()
        .map(|m| m.text)
        .collect();
    assert_eq!(got, ["cut in the middle"], "neither lost nor doubled");
    assert!(flaky.attempts.load(Ordering::SeqCst) >= 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_acknowledgement_does_not_duplicate_the_message() {
    flaky_run(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_cut_before_the_message_was_applied_does_not_lose_it() {
    flaky_run(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_removed_contact_keeps_the_conversation_but_cannot_be_written_to() {
    let r = relay().await;
    let (a, b) = (peer(&r).await, peer(&r).await);
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    send(&a, "bob", "before");
    until(30, "first delivery", || texts(&b, &a.id()).len() == 1).await;
    // Bob has the message as soon as he stored it; alice only counts it in the
    // conversation once bob's acknowledgement came back and she moved it from
    // the outbox into her history (the history view shows queued messages too,
    // the conversation list does not). Wait for that before removing bob.
    until(30, "acknowledgement", || a.svc.core().outbox.is_empty()).await;
    a.contacts.remove("bob").unwrap();
    match send(&a, "bob", "after removal") {
        ChatResponse::Error { kind, .. } => assert_eq!(kind, "unknown_contact"),
        other => panic!("{other:?}"),
    }
    // The conversation is still there, reachable by endpoint ID.
    let hex_id = hex::encode(b.id());
    match handle_with(
        &a.svc,
        ChatRequest::History {
            contact: hex_id.clone(),
            before: None,
            limit: None,
        },
    ) {
        ChatResponse::History {
            messages, label, ..
        } => {
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].text, "before");
            assert!(label.is_none());
        }
        other => panic!("{other:?}"),
    }
    match handle_with(&a.svc, ChatRequest::Conversations {}) {
        ChatResponse::Conversations(c) => {
            assert_eq!(c.len(), 1);
            assert!(c[0].label.is_none());
        }
        other => panic!("{other:?}"),
    }
    // Bob can no longer write to alice? He still can: alice's own list decides.
    // Alice removed bob, so his message is refused.
    send(&b, "alice", "hello?");
    until(30, "refusal", || b.svc.core().outbox.is_empty()).await;
    assert_eq!(texts(&a, &b.id()), ["before"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_queued_before_the_contact_was_removed_fails_for_that_reason() {
    let r = relay().await;
    let a = peer(&r).await;
    let ghost = id_of(&rand::random());
    register(&a, ghost, "ghost");
    send(&a, "ghost", "into the void");
    a.contacts.remove("ghost").unwrap();
    until(30, "failure", || a.svc.core().outbox.is_empty()).await;
    let h = a.svc.core().history(&ghost, None, 10);
    assert_eq!(h[0].state, MsgState::Failed);
    assert_eq!(h[0].reason.as_deref(), Some("contact_removed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn history_persists_across_a_restart_and_is_encrypted_on_disk() {
    let r = relay().await;
    let b = peer(&r).await;
    let a_seed: [u8; 32] = rand::random();
    let a = peer_in(
        &r,
        tempfile::tempdir().unwrap(),
        a_seed,
        fast(),
        StoreSettings::default(),
    )
    .await;
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    let marker = "PERSIST-MARKER-5d2e-日本語";
    send(&a, "bob", marker);
    send(&b, "alice", marker);
    until(30, "both ways", || {
        texts(&a, &b.id()).len() == 2 && texts(&b, &a.id()).len() == 2
    })
    .await;
    until(10, "acks", || a.svc.core().outbox.is_empty()).await;
    let b_id = b.id();
    // Restart alice: same directory, same identity, new node.
    a.svc.shutdown();
    a.node.shutdown().await;
    let Peer { dir, seed, .. } = a;
    let a2 = peer_in(&r, dir, seed, fast(), StoreSettings::default()).await;
    assert_eq!(texts(&a2, &b_id), [marker, marker]);
    // And it keeps working with the old session.
    send(&a2, "bob", "after restart");
    until(30, "post-restart delivery", || {
        texts(&b, &a2.id()).len() == 3
    })
    .await;
    // Nothing readable on disk.
    a2.svc.shutdown();
    let mut files = vec![a2.dir.path().to_path_buf()];
    while let Some(p) = files.pop() {
        for e in std::fs::read_dir(&p).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                files.push(path);
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(14).any(|w| w == b"PERSIST-MARKER"),
                "plaintext in {path:?}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flood_from_one_contact_is_slowed_down_not_dropped() {
    let r = relay().await;
    let a = peer(&r).await;
    let b = peer_in(
        &r,
        tempfile::tempdir().unwrap(),
        rand::random(),
        ChatSettings {
            inbound_burst: 3.0,
            inbound_per_minute: 6.0,
            ..fast()
        },
        StoreSettings::default(),
    )
    .await;
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    for i in 0..6 {
        send(&a, "bob", &format!("m{i}"));
    }
    until(30, "the burst", || texts(&b, &a.id()).len() >= 3).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(texts(&b, &a.id()).len() < 6, "the limit has an effect");
    // Slowly, all of them arrive, each once and in order.
    until(60, "the rest", || texts(&b, &a.id()).len() == 6).await;
    assert_eq!(
        texts(&b, &a.id()),
        ["m0", "m1", "m2", "m3", "m4", "m5"].map(String::from)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ipc_surface_round_trips() {
    let r = relay().await;
    let (a, b) = (peer(&r).await, peer(&r).await);
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    match send(&a, "bob", "") {
        ChatResponse::Error { kind, .. } => assert_eq!(kind, "empty"),
        other => panic!("{other:?}"),
    }
    match send(&a, "bob", &"x".repeat(5000)) {
        ChatResponse::Error { kind, .. } => assert_eq!(kind, "too_big"),
        other => panic!("{other:?}"),
    }
    match send(&a, "nobody", "hi") {
        ChatResponse::Error { kind, .. } => assert_eq!(kind, "unknown_contact"),
        other => panic!("{other:?}"),
    }
    let ChatResponse::Queued { id } = send(&a, "bob", "hello bob") else {
        panic!()
    };
    until(30, "delivery", || texts(&b, &a.id()).len() == 1).await;
    until(10, "ack", || a.svc.core().outbox.is_empty()).await;
    // Events on both sides.
    match handle_with(&b.svc, ChatRequest::Events { since: 0 }) {
        ChatResponse::Events { events, next } => {
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].kind, "received");
            assert_eq!(events[0].label.as_deref(), Some("alice"));
            assert!(next >= 1);
        }
        other => panic!("{other:?}"),
    }
    match handle_with(&a.svc, ChatRequest::Status {}) {
        ChatResponse::Status(s) => {
            assert!(s.history_saved);
            assert_eq!(s.outbox, 0);
            assert_eq!(s.conversations, 1);
            assert_eq!(s.max_message_bytes, 4096);
        }
        other => panic!("{other:?}"),
    }
    // Paging.
    for i in 0..5 {
        send(&a, "bob", &format!("p{i}"));
    }
    until(30, "pages", || texts(&b, &a.id()).len() == 6).await;
    until(10, "ack", || a.svc.core().outbox.is_empty()).await;
    let page = |before: Option<u64>, limit: u32| match handle_with(
        &b.svc,
        ChatRequest::History {
            contact: "alice".into(),
            before,
            limit: Some(limit),
        },
    ) {
        ChatResponse::History { messages, .. } => messages,
        other => panic!("{other:?}"),
    };
    let newest = page(None, 2);
    assert_eq!(newest.len(), 2);
    assert_eq!(newest[1].text, "p4");
    let older = page(Some(newest[0].ord), 3);
    assert_eq!(older.len(), 3);
    assert_eq!(older[2].text, "p2");
    // Delete one message, then the conversation.
    match handle_with(
        &a.svc,
        ChatRequest::DeleteLocal {
            contact: "bob".into(),
            message_id: Some(id),
        },
    ) {
        ChatResponse::Deleted { count } => assert_eq!(count, 1),
        other => panic!("{other:?}"),
    }
    assert_eq!(texts(&a, &b.id()).len(), 5);
    match handle_with(
        &a.svc,
        ChatRequest::DeleteLocal {
            contact: "bob".into(),
            message_id: Some("zz".into()),
        },
    ) {
        ChatResponse::Error { kind, .. } => assert_eq!(kind, "bad_message_id"),
        other => panic!("{other:?}"),
    }
    handle_with(
        &a.svc,
        ChatRequest::DeleteLocal {
            contact: "bob".into(),
            message_id: None,
        },
    );
    assert!(texts(&a, &b.id()).is_empty());
    // The other side keeps its copy.
    assert_eq!(texts(&b, &a.id()).len(), 6);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_push_alpn_is_unaffected_and_a_missing_chat_handler_closes_politely() {
    let r = relay().await;
    // A node with no chat service: the chat ALPN is closed as unavailable.
    let bare = start_node(&r, &rand::random()).await;
    let caller = start_node(&r, &rand::random()).await;
    let conn = caller
        .connect_alpn(&bare.endpoint_id(), CHAT_ALPN)
        .await
        .unwrap();
    let res = tokio::time::timeout(Duration::from_secs(10), conn.closed()).await;
    assert!(res.is_ok(), "the connection is closed");
    // The push ALPN is still served by whatever handler is installed for it
    // (none here: closed with the same code), independent of chat.
    let conn = caller
        .connect_alpn(&bare.endpoint_id(), PUSH_ALPN)
        .await
        .unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(10), conn.closed())
        .await
        .is_ok());
}

fn mark_read(p: &Peer, label: &str, up_to: u64) -> ChatResponse {
    handle_with(
        &p.svc,
        ChatRequest::MarkRead {
            contact: label.into(),
            up_to_seq: up_to,
        },
    )
}

fn outgoing_states(p: &Peer, other: &[u8; 32]) -> Vec<MsgState> {
    p.svc
        .core()
        .history(other, None, 200)
        .into_iter()
        .filter(|m| m.outgoing)
        .map(|m| m.state)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn read_receipts_travel_between_two_nodes_and_respect_both_switches() {
    let r = relay().await;
    let (a, b) = (peer(&r).await, peer(&r).await);
    register(&a, b.id(), "bob");
    register(&b, a.id(), "alice");
    b.svc.core().set_receipt_interval_ms(0);
    for t in ["one", "two"] {
        send(&a, "bob", t);
    }
    until(30, "both texts delivered", || {
        outgoing_states(&a, &b.id()) == [MsgState::Delivered; 2]
    })
    .await;
    // Arrival alone sends nothing.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(b.svc.core().outbox.is_empty());

    // Both on: bob has the conversation in view, alice sees "read".
    assert!(matches!(
        mark_read(&b, "alice", 2),
        ChatResponse::ReadMarked {
            sent: true,
            disabled: false,
            ..
        }
    ));
    until(30, "the receipt at alice", || {
        outgoing_states(&a, &b.id()) == [MsgState::Read; 2]
    })
    .await;
    until(30, "the receipt leaving bob's outbox", || {
        b.svc.core().outbox.is_empty()
    })
    .await;
    // The same point again sends nothing more.
    assert!(matches!(
        mark_read(&b, "alice", 2),
        ChatResponse::ReadMarked {
            sent: false,
            disabled: false,
            ..
        }
    ));
    // The events say so too.
    match handle_with(&a.svc, ChatRequest::Events { since: 0 }) {
        ChatResponse::Events { events, .. } => {
            assert_eq!(events.iter().filter(|e| e.kind == "read").count(), 1)
        }
        other => panic!("{other:?}"),
    }

    // Bob switches receipts off for alice: nothing is sent for new texts.
    assert!(matches!(
        handle_with(
            &b.svc,
            ChatRequest::SetReadReceipts {
                contact: "alice".into(),
                enabled: false
            }
        ),
        ChatResponse::ReceiptsSet { enabled: false }
    ));
    send(&a, "bob", "three");
    until(30, "the third text", || {
        outgoing_states(&a, &b.id()).len() == 3
            && outgoing_states(&a, &b.id())[2] == MsgState::Delivered
    })
    .await;
    assert!(matches!(
        mark_read(&b, "alice", 3),
        ChatResponse::ReadMarked {
            sent: false,
            disabled: true,
            ..
        }
    ));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        outgoing_states(&a, &b.id()),
        [MsgState::Read, MsgState::Read, MsgState::Delivered]
    );

    // Alice switches hers off: what bob would send is hidden from her.
    handle_with(
        &b.svc,
        ChatRequest::SetReadReceipts {
            contact: "alice".into(),
            enabled: true,
        },
    );
    handle_with(
        &a.svc,
        ChatRequest::SetReadReceipts {
            contact: "bob".into(),
            enabled: false,
        },
    );
    assert!(matches!(
        mark_read(&b, "alice", 3),
        ChatResponse::ReadMarked { sent: true, .. }
    ));
    until(30, "the hidden receipt to be taken", || {
        b.svc.core().outbox.is_empty()
    })
    .await;
    assert_eq!(
        outgoing_states(&a, &b.id()),
        [
            MsgState::Delivered,
            MsgState::Delivered,
            MsgState::Delivered
        ]
    );
}
