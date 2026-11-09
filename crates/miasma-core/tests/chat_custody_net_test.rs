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

#[tokio::test(flavor = "multi_thread")]
async fn file_and_legacy_chat_requests_reach_separate_stores() {
    use miasma_core::chat::mailbox::{
        client::MailboxTransport,
        holder::DepositOutcome,
        ids::{ItemId, RecipientTag},
        transport::ChatMailboxTransport,
    };
    let r = relay().await;
    let holder_seed = rand::random();
    let sender_seed = rand::random();
    let holder_node = start_node(&r, &holder_seed).await;
    let sender_node = start_node(&r, &sender_seed).await;
    let dir = tempfile::tempdir().unwrap();
    let contacts = Arc::new(ContactStore::open(dir.path()));
    contacts
        .add(
            &ContactCode::new(sender_node.endpoint_id()),
            Some("sender"),
            None,
        )
        .unwrap();
    let mut cfg = settings();
    cfg.file_custody_limits.enabled = true;
    let keys = Arc::new(StateKeys::open_or_init(dir.path()).unwrap());
    let holder = ChatService::start(
        &dir.path().join("chat"),
        holder_node.clone(),
        &holder_seed,
        keys,
        contacts,
        StoreSettings::default(),
        cfg,
    )
    .unwrap();
    let holder_id = holder_node.endpoint_id();
    let result = tokio::task::spawn_blocking(move || {
        let chat = ChatMailboxTransport::new(sender_node.clone());
        let file = ChatMailboxTransport::for_files(sender_node);
        let tag = RecipientTag([7; 16]);
        let item = ItemId([8; 16]);
        assert_eq!(
            chat.deposit(&holder_id, tag, item, b"chat", 0).unwrap(),
            DepositOutcome::Stored
        );
        assert_eq!(
            file.deposit(&holder_id, tag, item, b"file", 0).unwrap(),
            DepositOutcome::Stored
        );
        assert_eq!(
            chat.fetch(&holder_id, tag, item, 0).unwrap(),
            Some(b"chat".to_vec())
        );
        assert_eq!(
            file.fetch(&holder_id, tag, item, 0).unwrap(),
            Some(b"file".to_vec())
        );
    })
    .await;
    result.unwrap();
    assert_eq!(holder.custody_stats().unwrap().items, 1);
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

/// Custody is an intermediate state, never a success: when a direct send cannot
/// go through and there is no reachable holder to take a copy, the message is
/// reported as not deposited and is never shown as delivered. This guards the
/// contract that a deposit failure is surfaced, not swallowed.
#[tokio::test(flavor = "multi_thread")]
async fn a_deposit_with_no_holder_is_reported_not_delivered() {
    let r = relay().await;

    // Recipient B stays offline for the whole test; its endpoint id is known
    // from its seed so A can list it as a contact and dial it.
    let a_seed: [u8; 32] = rand::random();
    let b_seed: [u8; 32] = rand::random();
    let b_id = Identity::from_seed(&b_seed).id();

    // Sender A knows only B. With no other trusted contact, there is no holder
    // to leave a copy with, so the deposit after a failed direct send finds
    // zero holders.
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
    let a = start_service(a_dir.path(), a_node.clone(), &a_seed, a_contacts);

    // A sends to B. B is offline, so the direct send cannot go through and the
    // message is queued.
    assert!(matches!(
        handle_with(
            &a,
            ChatRequest::Send {
                contact: "bob".into(),
                text: "nobody to hold this".into(),
            },
        ),
        ChatResponse::Queued { .. }
    ));

    // The worker tries the direct send, fails, and runs the deposit path with
    // no holder to ask. The outbox entry records that nothing was deposited.
    until(40, "the message is marked not deposited", || {
        a.core()
            .outbox
            .pending_for(&b_id)
            .iter()
            .any(|e| e.last_error.as_deref() == Some("Not deposited with any holder"))
    })
    .await;

    // It is never shown as delivered (or read): custody did not take a copy and
    // the recipient never acknowledged anything.
    let h = a.core().history(&b_id, None, 50);
    let m = h
        .iter()
        .find(|m| m.text == "nobody to hold this")
        .expect("the message is in A's history");
    assert!(
        !matches!(
            m.state,
            miasma_core::chat::store::MsgState::Delivered
                | miasma_core::chat::store::MsgState::Read
        ),
        "a message with no holder must not be shown as delivered: {:?}",
        m.state
    );
    assert_eq!(
        m.reason.as_deref(),
        Some("Not deposited with any holder"),
        "the undelivered reason is surfaced to the person"
    );

    std::mem::forget(a_node);
    std::mem::forget(r);
    drop(a);
}
