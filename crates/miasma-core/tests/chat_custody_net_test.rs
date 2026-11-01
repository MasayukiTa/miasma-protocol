//! Custody over a local iroh relay: a sender leaves a copy of a message with a
//! trusted holder when the recipient cannot be reached directly, and the
//! recipient collects it from the holder once it comes online. End to end over
//! three real chat services (sender, holder, recipient), with custody on.

#![cfg(feature = "iroh")]

use std::{sync::Arc, time::Duration};

use iroh::tls::CaTlsConfig;
use miasma_core::{
    chat::{
        crypto::Identity,
        ipc::handle_with,
        service::{ChatService, ChatSettings},
        store::StoreSettings,
        ChatRequest, ChatResponse,
    },
    config::IrohMode,
    push::{ContactCode, ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{endpoint_builder, IrohNode, IrohServerLimits, IrohSettings},
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

fn settings() -> ChatSettings {
    ChatSettings {
        retry_delays: vec![Duration::from_millis(200)],
        retry_every: Duration::from_millis(300),
        retry_jitter: 0.0,
        idle_timeout: Duration::from_secs(20),
        custody_enabled: true,
        custody_copies: 1,
        ..ChatSettings::default()
    }
}

fn start_service(
    dir: &std::path::Path,
    node: Arc<IrohNode>,
    seed: &[u8; 32],
    contacts: Arc<ContactStore>,
) -> Arc<ChatService> {
    let keys = Arc::new(StateKeys::open_or_init(dir).unwrap());
    ChatService::start(
        &dir.join("chat"),
        node,
        seed,
        keys,
        contacts,
        StoreSettings::default(),
        settings(),
    )
    .expect("chat starts")
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

/// A sends to B while B is offline. The copy lands with the holder C. When B
/// starts, its worker collects from C and the message appears in B's history.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_reaches_an_offline_recipient_through_a_holder() {
    let r = relay().await;

    // Seeds and identities. B's endpoint id is known from its seed before B is
    // online, so A and C can list it as a contact.
    let a_seed: [u8; 32] = rand::random();
    let b_seed: [u8; 32] = rand::random();
    let c_seed: [u8; 32] = rand::random();
    let b_id = Identity::from_seed(&b_seed).id();

    // Holder C: trusts A and B (its contacts), online throughout.
    let c_dir = tempfile::tempdir().unwrap();
    let c_node = start_node(&r, &c_seed).await;
    let c_contacts = Arc::new(ContactStore::open(c_dir.path()));
    c_contacts
        .add(&ContactCode::new(c_node.endpoint_id()), Some("self"), None)
        .ok();
    let a_id_for_c = Identity::from_seed(&a_seed).id();
    c_contacts
        .add(&ContactCode::new(a_id_for_c), Some("alice"), None)
        .unwrap();
    c_contacts
        .add(&ContactCode::new(b_id), Some("bob"), None)
        .unwrap();
    let _c = start_service(c_dir.path(), c_node.clone(), &c_seed, c_contacts);

    // Sender A: knows B (the recipient) and C (a holder). B is listed with its
    // endpoint so A dials it; the dial fails while B is offline, and A leaves a
    // copy with C.
    let a_dir = tempfile::tempdir().unwrap();
    let a_node = start_node(&r, &a_seed).await;
    let a_contacts = Arc::new(ContactStore::open(a_dir.path()));
    a_contacts
        .add(
            &ContactCode::new(b_id),
            Some("bob"),
            Some(&a_node.endpoint_id()),
        )
        .unwrap();
    a_contacts
        .add(
            &ContactCode::new(c_node.endpoint_id()),
            Some("carol"),
            Some(&a_node.endpoint_id()),
        )
        .unwrap();
    let a = start_service(a_dir.path(), a_node.clone(), &a_seed, a_contacts);

    // A sends to B. B is offline, so the direct send cannot go through.
    assert!(matches!(
        handle_with(
            &a,
            ChatRequest::Send {
                contact: "bob".into(),
                text: "held for you".into(),
            },
        ),
        ChatResponse::Queued { .. }
    ));

    // The copy reaches the holder: C now holds one item for B.
    until(40, "holder holds the copy", || {
        _c.custody_stats().map(|s| s.items).unwrap_or(0) >= 1
    })
    .await;

    // B comes online: trusts A and C, and collects on start.
    let b_dir = tempfile::tempdir().unwrap();
    let b_node = start_node(&r, &b_seed).await;
    let b_contacts = Arc::new(ContactStore::open(b_dir.path()));
    b_contacts
        .add(
            &ContactCode::new(a_node.endpoint_id()),
            Some("alice"),
            Some(&b_node.endpoint_id()),
        )
        .unwrap();
    b_contacts
        .add(
            &ContactCode::new(c_node.endpoint_id()),
            Some("carol"),
            Some(&b_node.endpoint_id()),
        )
        .unwrap();
    let b = start_service(b_dir.path(), b_node.clone(), &b_seed, b_contacts);

    // Ask the holders at once so the collection does not wait for the timer.
    b.kick_collect();

    // The message is delivered to B through the holder.
    until(40, "recipient collected the message", || {
        let h = b.core().history(&a_node.endpoint_id(), None, 50);
        h.iter().any(|m| m.text == "held for you")
    })
    .await;

    // The holder drops the collected item.
    until(20, "holder cleared the item", || {
        _c.custody_stats().map(|s| s.items).unwrap_or(0) == 0
    })
    .await;

    std::mem::forget(a_node);
    std::mem::forget(b_node);
    std::mem::forget(c_node);
    std::mem::forget(r);
    drop((a, b));
}
