//! Group chat over a local iroh relay: in-process nodes, no traffic to any
//! public service. Includes a peer that predates groups (it does not list the
//! group ALPN): its private chat must keep working while group delivery to it
//! simply waits.

#![cfg(feature = "iroh")]

use std::{sync::Arc, time::Duration};

use iroh::tls::CaTlsConfig;
use miasma_core::{
    chat::{
        crypto::Identity,
        group::ipc::{handle_with as group_handle, GroupRequest, GroupResponse},
        ipc::handle_with,
        service::{ChatService, ChatSettings},
        store::StoreSettings,
        ChatRequest, ChatResponse,
    },
    config::IrohMode,
    push::{ContactCode, ContactStore},
    state_crypto::StateKeys,
    transport::iroh_direct::{
        endpoint_builder, IrohNode, IrohServerLimits, IrohSettings, CHAT_ALPN, IROH_ALPN, PUSH_ALPN,
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

/// `legacy`: advertise only the ALPNs of a release that predates groups.
async fn start_node(relay: &Relay, seed: &[u8; 32], legacy: bool) -> Arc<IrohNode> {
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
    if legacy {
        builder = builder.alpns(vec![
            IROH_ALPN.to_vec(),
            PUSH_ALPN.to_vec(),
            CHAT_ALPN.to_vec(),
        ]);
    }
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

async fn peer(relay: &Relay, legacy: bool) -> Peer {
    let dir = tempfile::tempdir().unwrap();
    let seed: [u8; 32] = rand::random();
    let node = start_node(relay, &seed, legacy).await;
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
    assert_eq!(Identity::from_seed(&seed).id(), node.endpoint_id());
    Peer {
        node,
        svc,
        contacts,
        _dir: dir,
    }
}

fn register(a: &Peer, b: &Peer, label: &str) {
    a.contacts
        .add(&ContactCode::new(b.id()), Some(label), Some(&a.id()))
        .unwrap();
}

fn g(p: &Peer, req: GroupRequest) -> GroupResponse {
    group_handle(p.svc.groups().expect("group chat is on"), req)
}

fn groups(p: &Peer) -> Vec<miasma_core::chat::group::ipc::GroupInfo> {
    match g(p, GroupRequest::List {}) {
        GroupResponse::Groups(v) => v,
        other => panic!("{other:?}"),
    }
}

fn gtexts(p: &Peer, group: &str) -> Vec<String> {
    match g(
        p,
        GroupRequest::History {
            group: group.into(),
            before: None,
            limit: Some(100),
        },
    ) {
        GroupResponse::History { messages, .. } => messages.into_iter().map(|m| m.text).collect(),
        GroupResponse::Error { .. } => Vec::new(),
        other => panic!("{other:?}"),
    }
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
async fn a_group_works_over_the_network_and_a_peer_without_groups_keeps_its_private_chat() {
    let r = relay().await;
    let a = peer(&r, false).await;
    let b = peer(&r, false).await;
    let c = peer(&r, false).await;
    let old = peer(&r, true).await;
    for (x, y, l) in [
        (&a, &b, "bob"),
        (&a, &c, "carol"),
        (&a, &old, "oldie"),
        (&b, &a, "alice"),
        (&c, &a, "alice"),
        (&old, &a, "alice"),
    ] {
        register(x, y, l);
    }
    // a makes a group of bob, carol and the peer without groups.
    let created = g(
        &a,
        GroupRequest::Create {
            name: "weekend".into(),
            members: vec!["bob".into(), "carol".into(), "oldie".into()],
        },
    );
    assert!(matches!(
        created,
        GroupResponse::Created { recipients: 3, .. }
    ));
    // bob and carol are invited, and accept.
    for p in [&b, &c] {
        until(30, "the invitation", || {
            groups(p).first().is_some_and(|x| x.status == "invited")
        })
        .await;
        assert!(matches!(
            g(
                p,
                GroupRequest::Accept {
                    group: "weekend".into()
                }
            ),
            GroupResponse::Done {}
        ));
    }
    // Neither of them registered the other: each is an unverified member.
    match g(
        &b,
        GroupRequest::Show {
            group: "weekend".into(),
        },
    ) {
        GroupResponse::Detail(d) => {
            let carol = d
                .members
                .iter()
                .find(|m| m.endpoint_id == hex::encode(c.id()))
                .unwrap();
            assert!(!carol.verified && carol.label.is_none());
            assert!(d
                .members
                .iter()
                .any(|m| m.verified && m.label.as_deref() == Some("alice")));
        }
        other => panic!("{other:?}"),
    }
    assert!(
        b.contacts.by_endpoint(&c.id()).is_none(),
        "nobody became a contact"
    );

    // Messages from several members reach everyone who has joined.
    assert!(matches!(
        g(
            &a,
            GroupRequest::Send {
                group: "weekend".into(),
                text: "hello group".into()
            }
        ),
        GroupResponse::Queued { .. }
    ));
    until(30, "the group message at bob and carol", || {
        gtexts(&b, "weekend").contains(&"hello group".to_owned())
            && gtexts(&c, "weekend").contains(&"hello group".to_owned())
    })
    .await;
    g(
        &b,
        GroupRequest::Send {
            group: "weekend".into(),
            text: "こんにちは".into(),
        },
    );
    until(30, "bob's message at carol and alice", || {
        gtexts(&c, "weekend").contains(&"こんにちは".to_owned())
            && gtexts(&a, "weekend").contains(&"こんにちは".to_owned())
    })
    .await;

    // The peer without groups: its private chat is untouched, in both directions,
    // while group copies for it wait.
    let sent = handle_with(
        &a.svc,
        ChatRequest::Send {
            contact: "oldie".into(),
            text: "private hello".into(),
        },
    );
    assert!(matches!(sent, ChatResponse::Queued { .. }));
    until(30, "the private message at the old peer", || {
        texts(&old, &a.id()) == ["private hello"]
    })
    .await;
    handle_with(
        &old.svc,
        ChatRequest::Send {
            contact: "alice".into(),
            text: "private reply".into(),
        },
    );
    until(30, "the private reply", || {
        texts(&a, &old.id()).contains(&"private reply".to_owned())
    })
    .await;
    assert!(groups(&old).is_empty(), "it never saw the group");
    let info = groups(&a);
    assert!(info[0].pending >= 1, "copies for the old peer still wait");

    // Removing bob: carol still gets later messages, bob does not.
    assert!(matches!(
        g(
            &a,
            GroupRequest::Remove {
                group: "weekend".into(),
                member: "bob".into()
            }
        ),
        GroupResponse::Done {}
    ));
    until(30, "bob learns of the removal", || {
        groups(&b).first().is_some_and(|x| x.status == "removed")
    })
    .await;
    g(
        &a,
        GroupRequest::Send {
            group: "weekend".into(),
            text: "after bob left".into(),
        },
    );
    until(30, "the message at carol", || {
        gtexts(&c, "weekend").contains(&"after bob left".to_owned())
    })
    .await;
    assert!(!gtexts(&b, "weekend").contains(&"after bob left".to_owned()));
    assert_eq!(groups(&c)[0].epoch, 2);
}
