//! The catch-up of a new chat connection over a local iroh relay: a receiver
//! that answers it, and a receiver from before it existed.

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
        proto::{self, Ack, Frame},
        service::{ChatService, ChatSettings},
        store::{ChatStore, StoreSettings},
        sync, ChatRequest, ChatResponse,
    },
    config::IrohMode,
    push::{ContactCode, ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{
        endpoint_builder, ChatConnectionHandler, IrohNode, IrohServerLimits, IrohSettings,
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

/// A receiver written by hand. With `answers_sync` it also takes the
/// catch-up on a unidirectional stream; without it, it behaves like a build
/// from before the catch-up (it only ever accepts bidirectional streams).
struct Hand {
    core: Arc<ChatCore>,
    answers_sync: bool,
    /// Apply the first message, then cut the connection without the ack.
    cut_first: bool,
    conns: AtomicUsize,
    delivers: AtomicUsize,
}

impl Hand {
    async fn deliver(&self, conn: &Connection, remote: [u8; 32]) -> bool {
        let Ok((mut tx, mut rx)) = conn.accept_bi().await else {
            return false;
        };
        let Ok(Frame::Deliver(wire)) = proto::read_frame(&mut rx).await else {
            return false;
        };
        let n = self.delivers.fetch_add(1, Ordering::SeqCst);
        let status = self.core.accept(&remote, &wire, 1).status;
        if self.cut_first && n == 0 {
            conn.close(7u32.into(), b"cut");
            return false;
        }
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
        true
    }
}

#[async_trait::async_trait]
impl ChatConnectionHandler for Hand {
    async fn handle(&self, conn: Connection) {
        self.conns.fetch_add(1, Ordering::SeqCst);
        let remote = *conn.remote_id().as_bytes();
        if !self.answers_sync {
            while self.deliver(&conn, remote).await {}
            return;
        }
        loop {
            tokio::select! {
                u = conn.accept_uni() => {
                    let Ok(mut rx) = u else { return };
                    let Ok(Frame::Sync(items)) = proto::read_frame(&mut rx).await else {
                        return;
                    };
                    let have = sync::answer(&self.core, &remote, &items);
                    let Ok(mut tx) = conn.open_uni().await else { return };
                    let _ = proto::write_frame(&mut tx, &Frame::SyncReply(have)).await;
                    let _ = tx.finish();
                }
                ok = self.deliver(&conn, remote) => {
                    if !ok { return; }
                }
            }
        }
    }
}

struct Rig {
    a: Arc<ChatService>,
    a_id: [u8; 32],
    hand: Arc<Hand>,
    _dirs: Vec<tempfile::TempDir>,
}

async fn rig(answers_sync: bool, cut_first: bool) -> Rig {
    let r = relay().await;
    let a_seed: [u8; 32] = rand::random();
    let a_dir = tempfile::tempdir().unwrap();
    let a_node = start_node(&r, &a_seed).await;
    let a_contacts = Arc::new(ContactStore::open(a_dir.path()));
    let a_keys = Arc::new(StateKeys::open_or_init(a_dir.path()).unwrap());
    let a = ChatService::start(
        &a_dir.path().join("chat"),
        a_node.clone(),
        &a_seed,
        a_keys,
        a_contacts.clone(),
        StoreSettings::default(),
        ChatSettings {
            retry_delays: vec![Duration::from_millis(200)],
            retry_every: Duration::from_millis(300),
            retry_jitter: 0.0,
            idle_timeout: Duration::from_secs(20),
            ..ChatSettings::default()
        },
    )
    .expect("chat starts");

    let b_seed: [u8; 32] = rand::random();
    let b_dir = tempfile::tempdir().unwrap();
    let b_node = start_node(&r, &b_seed).await;
    let b_contacts = Arc::new(ContactStore::open(b_dir.path()));
    b_contacts
        .add(&ContactCode::new(a_node.endpoint_id()), Some("alice"), None)
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
    let hand = Arc::new(Hand {
        core,
        answers_sync,
        cut_first,
        conns: AtomicUsize::new(0),
        delivers: AtomicUsize::new(0),
    });
    b_node.set_chat_handler(hand.clone());
    a_contacts
        .add(
            &ContactCode::new(b_node.endpoint_id()),
            Some("bob"),
            Some(&a_node.endpoint_id()),
        )
        .unwrap();
    std::mem::forget(b_node);
    std::mem::forget(r);
    Rig {
        a,
        a_id: a_node.endpoint_id(),
        hand,
        _dirs: vec![a_dir, b_dir],
    }
}

fn send(a: &Arc<ChatService>, text: &str) {
    assert!(matches!(
        handle_with(
            a,
            ChatRequest::Send {
                contact: "bob".into(),
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

fn received(h: &Hand, from: &[u8; 32]) -> Vec<String> {
    h.core
        .history(from, None, 50)
        .into_iter()
        .map(|m| m.text)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_receiver_from_before_the_catch_up_keeps_its_connection() {
    let t = rig(false, false).await;
    send(&t.a, "one");
    send(&t.a, "two");
    until(40, "both delivered", || t.a.core().outbox.is_empty()).await;
    assert_eq!(received(&t.hand, &t.a_id), ["one", "two"]);
    assert_eq!(
        t.hand.conns.load(Ordering::SeqCst),
        1,
        "the unanswered catch-up did not cost the connection"
    );
    // Asked once, then left alone for a while: a later message still goes through.
    send(&t.a, "three");
    until(20, "third delivered", || t.a.core().outbox.is_empty()).await;
    assert_eq!(received(&t.hand, &t.a_id).len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_catch_up_closes_a_message_whose_acknowledgement_was_lost() {
    let t = rig(true, true).await;
    send(&t.a, "applied but not acknowledged");
    until(40, "message closed", || t.a.core().outbox.is_empty()).await;
    assert_eq!(received(&t.hand, &t.a_id), ["applied but not acknowledged"]);
    assert_eq!(
        t.hand.delivers.load(Ordering::SeqCst),
        1,
        "the message was not sent a second time"
    );
    assert!(t.hand.conns.load(Ordering::SeqCst) >= 2);
}
