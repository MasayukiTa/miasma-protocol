//! Trusted-contact push over a local iroh relay (ADR-011): two in-process
//! nodes, no traffic to any public service.

#![cfg(feature = "iroh")]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use iroh::{endpoint::Connection, tls::CaTlsConfig};
use miasma_core::{
    config::{IrohMode, PushConfig},
    push::{
        ipc::handle_with,
        proto::{self, Done, Header, RejectReason, Reply, PROTOCOL_VERSION},
        service::{PushService, PushSettings},
        ContactCode, ContactUpdate, Direction, PushRequest, PushResponse, PushState,
        PushTransferInfo,
    },
    transport::iroh_direct::{
        endpoint_builder, IrohNode, IrohServerLimits, IrohSettings, PUSH_ALPN,
    },
    LocalShareStore,
};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;

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

struct Peer {
    node: Arc<IrohNode>,
    svc: Arc<PushService>,
    dir: TempDir,
    inbox: PathBuf,
}

impl Peer {
    fn id(&self) -> [u8; 32] {
        self.node.endpoint_id()
    }
}

async fn peer(relay: &Relay, tweak: impl FnOnce(&mut PushSettings)) -> Peer {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(store_dir.path(), 10).unwrap());
    let s = IrohSettings {
        mode: IrohMode::Custom,
        relay_urls: vec![relay.url.clone()],
        discovery: false,
        lan_discovery: false,
        connect_timeout: Duration::from_secs(20),
        ca_pem: None,
        proxy_from_env: false,
    };
    let seed: [u8; 32] = rand::random();
    let builder = endpoint_builder(Some(&seed), &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    let node = IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
        .await
        .unwrap();
    assert!(node.wait_online(Duration::from_secs(20)).await);
    let inbox = dir.path().join("inbox");
    let mut settings = PushSettings::from_config(&PushConfig::default(), dir.path());
    settings.min_free_bytes = 0;
    settings.retry_delays = vec![];
    settings.idle_timeout = Duration::from_secs(20);
    tweak(&mut settings);
    let svc = PushService::start(dir.path(), node.clone(), settings);
    // Keep the temp store alive as long as the test by leaking its handle: the
    // store is not used by push.
    std::mem::forget(store_dir);
    Peer {
        node,
        svc,
        dir,
        inbox,
    }
}

/// `a` registers `b` as `label`.
fn register(a: &Peer, b: &Peer, label: &str) {
    a.svc
        .add_contact(&ContactCode::new(b.id()), Some(label))
        .unwrap();
}

fn content(len: usize, seed: u32) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9 ^ seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

fn write_src(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

async fn wait_finished(svc: &PushService, id: &str, secs: u64) -> PushTransferInfo {
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let t = svc.board().get(id).expect("transfer is on the board");
        if t.state.is_finished() {
            return t;
        }
        assert!(
            std::time::Instant::now() < end,
            "timed out in state {:?}",
            t.state
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(dir, &mut v);
    v
}

fn finals(dir: &Path) -> Vec<PathBuf> {
    files_under(dir)
        .into_iter()
        .filter(|p| !p.file_name().unwrap().to_string_lossy().ends_with(".part"))
        .collect()
}

fn parts(dir: &Path) -> Vec<PathBuf> {
    files_under(dir)
        .into_iter()
        .filter(|p| p.file_name().unwrap().to_string_lossy().ends_with(".part"))
        .collect()
}

fn hash(b: &[u8]) -> String {
    blake3::hash(b).to_hex().to_string()
}

// ─── A raw protocol client (plays the sender by hand) ────────────────────────

struct Raw {
    conn: Connection,
    tx: iroh::endpoint::SendStream,
    rx: iroh::endpoint::RecvStream,
}

async fn raw_open(from: &Peer, to: &Peer, header: &Header) -> (Raw, Reply) {
    let conn = from.node.connect_alpn(&to.id(), PUSH_ALPN).await.unwrap();
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    proto::write_frame(&mut tx, header).await.unwrap();
    let reply: Reply = proto::read_frame(&mut rx).await.unwrap();
    (Raw { conn, tx, rx }, reply)
}

fn header(name: &str, data: &[u8]) -> Header {
    Header {
        v: PROTOCOL_VERSION,
        name: name.into(),
        size: data.len() as u64,
        hash: hash(data),
        note: None,
    }
}

async fn raw_finish(mut raw: Raw, data: &[u8]) -> Done {
    AsyncWriteExt::write_all(&mut raw.tx, data).await.unwrap();
    raw.tx.finish().unwrap();
    let d: Done = proto::read_frame(&mut raw.rx).await.unwrap();
    raw.conn.close(0u32.into(), b"");
    d
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn registered_both_ways_file_arrives_identical_with_japanese_name() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&alice, &bob, "bob");
    register(&bob, &alice, "alice");

    let data = content(700_000, 1);
    let src = write_src(alice.dir.path(), "報告書_最終版.txt", &data);
    let id = alice.svc.queue_send("bob", &src).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(t.bytes, data.len() as u64);

    let got = bob.inbox.join("alice").join("報告書_最終版.txt");
    assert_eq!(std::fs::read(&got).unwrap(), data);
    assert!(parts(&bob.inbox).is_empty());

    // The receiver's side is on its board and in its history.
    let inbound = bob
        .svc
        .board()
        .list()
        .into_iter()
        .find(|i| i.direction == Direction::In)
        .unwrap();
    assert_eq!(inbound.state, PushState::Done);
    assert!(!bob.svc.history().list(10).is_empty());
    assert!(!alice.svc.history().list(10).is_empty());

    // And the reverse direction works with the same registration.
    let back = write_src(bob.dir.path(), "返信.txt", b"ok");
    let id2 = bob.svc.queue_send("alice", &back).unwrap();
    assert_eq!(
        wait_finished(&bob.svc, &id2, 60).await.state,
        PushState::Done
    );
    assert_eq!(
        std::fs::read(alice.inbox.join("bob").join("返信.txt")).unwrap(),
        b"ok"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ipc_surface_round_trip() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;

    // Bob's code is found inside a pasted chat message.
    let PushResponse::Code {
        code, fingerprint, ..
    } = handle_with(&bob.svc, PushRequest::ContactCode)
    else {
        panic!()
    };
    let msg = format!("hi, my code is <{code}>, thanks!");
    let PushResponse::Contact(c) = handle_with(
        &alice.svc,
        PushRequest::ContactAdd {
            code: msg,
            label: Some("bob".into()),
        },
    ) else {
        panic!()
    };
    assert_eq!(c.fingerprint, fingerprint);
    // Duplicates, bad codes and one's own code are refused with stable kinds.
    for (req, kind) in [
        (
            PushRequest::ContactAdd {
                code: code.clone(),
                label: Some("x".into()),
            },
            "already_exists",
        ),
        (
            PushRequest::ContactAdd {
                code: "miasma-contact:nope".into(),
                label: None,
            },
            "bad_code",
        ),
        (
            PushRequest::ContactAdd {
                code: ContactCode::new(alice.id()).to_string(),
                label: None,
            },
            "this_is_me",
        ),
        (
            PushRequest::Send {
                contact: "ghost".into(),
                path: "/x".into(),
            },
            "unknown_contact",
        ),
    ] {
        match handle_with(&alice.svc, req) {
            PushResponse::Error { kind: k, .. } => assert_eq!(k, kind),
            other => panic!("{other:?}"),
        }
    }
    let PushResponse::Contacts(list) = handle_with(&alice.svc, PushRequest::ContactList) else {
        panic!()
    };
    assert_eq!(list.len(), 1);
    assert!(list[0].allow_send && list[0].allow_receive);

    // The contact list survives a restart of the store.
    let reopened = miasma_core::push::ContactStore::open(alice.dir.path());
    assert_eq!(reopened.list().len(), 1);

    let PushResponse::Contact(u) = handle_with(
        &alice.svc,
        PushRequest::ContactUpdate {
            contact: "bob".into(),
            label: None,
            allow_send: Some(false),
            allow_receive: None,
            max_size: Some(123),
        },
    ) else {
        panic!()
    };
    assert!(!u.allow_send && u.max_file_size == Some(123));
    let src = write_src(alice.dir.path(), "a.txt", b"x");
    match handle_with(
        &alice.svc,
        PushRequest::Send {
            contact: "bob".into(),
            path: src.to_string_lossy().into(),
        },
    ) {
        PushResponse::Error { kind, .. } => assert_eq!(kind, "send_disabled"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        handle_with(
            &alice.svc,
            PushRequest::ContactRemove {
                contact: "bob".into()
            }
        ),
        PushResponse::Removed
    ));
    assert!(matches!(
        handle_with(&alice.svc, PushRequest::Inbox),
        PushResponse::Inbox { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn unregistered_sender_is_rejected_and_nothing_is_written() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&alice, &bob, "bob"); // bob never registers alice
    let src = write_src(alice.dir.path(), "secret.txt", b"hello");
    let id = alice.svc.queue_send("bob", &src).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.state, PushState::Rejected);
    assert_eq!(t.reject_reason.as_deref(), Some("not_allowed"));
    assert!(files_under(&bob.inbox).is_empty());
    assert!(!bob.inbox.exists() || std::fs::read_dir(&bob.inbox).unwrap().next().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_receive_false_is_rejected() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&alice, &bob, "bob");
    register(&bob, &alice, "alice");
    bob.svc
        .update_contact(
            "alice",
            &ContactUpdate {
                allow_receive: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let src = write_src(alice.dir.path(), "x.txt", b"hello");
    let id = alice.svc.queue_send("bob", &src).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.state, PushState::Rejected);
    assert_eq!(t.reject_reason.as_deref(), Some("not_allowed"));
    assert!(files_under(&bob.inbox).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn too_large_and_no_space_are_rejected() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |s| {
        s.free_space = Some(Arc::new(|_| Some(10_000)));
        s.min_free_bytes = 1000;
    })
    .await;
    register(&alice, &bob, "bob");
    register(&bob, &alice, "alice");

    // Per-contact limit.
    bob.svc
        .update_contact(
            "alice",
            &ContactUpdate {
                max_file_size: Some(2000),
                ..Default::default()
            },
        )
        .unwrap();
    let big = write_src(alice.dir.path(), "big.bin", &content(5000, 2));
    let id = alice.svc.queue_send("bob", &big).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.state, PushState::Rejected);
    assert_eq!(t.reject_reason.as_deref(), Some("too_large"));

    // Within the limit but the disk (10 000 free, 1000 reserve) is too small.
    bob.svc
        .update_contact(
            "alice",
            &ContactUpdate {
                max_file_size: Some(100_000),
                ..Default::default()
            },
        )
        .unwrap();
    let mid = write_src(alice.dir.path(), "mid.bin", &content(20_000, 3));
    let id = alice.svc.queue_send("bob", &mid).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.state, PushState::Rejected);
    assert_eq!(t.reject_reason.as_deref(), Some("no_space"));
    assert!(finals(&bob.inbox).is_empty());
    assert!(parts(&bob.inbox).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn hash_mismatch_leaves_no_final_file_and_truncation_leaves_a_resumable_part() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&bob, &alice, "alice");
    register(&alice, &bob, "bob");

    // Wrong hash: the bytes are fine but do not match the header.
    let data = content(200_000, 4);
    let mut h = header("bad.bin", &data);
    h.hash = hash(b"something else");
    let (raw, reply) = raw_open(&alice, &bob, &h).await;
    assert_eq!(reply, Reply::Accept { offset: 0 });
    let done = raw_finish(raw, &data).await;
    assert!(!done.ok);
    assert_eq!(done.error.as_deref(), Some("hash_mismatch"));
    assert!(finals(&bob.inbox).is_empty());
    assert!(
        parts(&bob.inbox).is_empty(),
        "a damaged part must not be kept"
    );

    // Truncated: half of the bytes, then the connection is cut.
    let data = content(400_000, 5);
    let h = header("cut.bin", &data);
    let half = data.len() / 2;
    let (mut raw, reply) = raw_open(&alice, &bob, &h).await;
    assert_eq!(reply, Reply::Accept { offset: 0 });
    AsyncWriteExt::write_all(&mut raw.tx, &data[..half])
        .await
        .unwrap();
    raw.tx.flush().await.ok();
    // Let the receiver drain what was sent before the cut.
    tokio::time::sleep(Duration::from_millis(800)).await;
    raw.conn.close(7u32.into(), b"cut");
    drop(raw);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(finals(&bob.inbox).is_empty());
    let p = parts(&bob.inbox);
    assert_eq!(p.len(), 1);
    let kept = std::fs::metadata(&p[0]).unwrap().len();
    assert!(kept > 0 && kept <= half as u64, "kept {kept}");

    // Resume: same header; the receiver offers the offset it holds.
    let (raw, reply) = raw_open(&alice, &bob, &h).await;
    let Reply::Accept { offset } = reply else {
        panic!("{reply:?}")
    };
    assert_eq!(offset, kept);
    let done = raw_finish(raw, &data[offset as usize..]).await;
    assert!(done.ok, "{:?}", done.error);
    assert_eq!(
        std::fs::read(bob.inbox.join("alice").join("cut.bin")).unwrap(),
        data
    );
    assert!(parts(&bob.inbox).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn hostile_names_are_sanitized_or_refused() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&bob, &alice, "alice");

    let data = b"payload".to_vec();
    for (raw_name, want) in [
        ("../../evil.txt", Some("evil.txt")),
        ("..\\..\\win\\evil2.txt", Some("evil2.txt")),
        ("/etc/passwd", Some("passwd")),
        ("a\u{202e}b.txt", Some("ab.txt")),
        ("CON", None),
        ("nul.txt", None),
        ("..", None),
    ] {
        let (raw, reply) = raw_open(&alice, &bob, &header(raw_name, &data)).await;
        match want {
            Some(w) => {
                assert_eq!(reply, Reply::Accept { offset: 0 }, "{raw_name}");
                let d = raw_finish(raw, &data).await;
                assert!(d.ok);
                assert_eq!(d.saved_as.as_deref(), Some(w), "{raw_name}");
            }
            None => {
                assert_eq!(
                    reply,
                    Reply::Reject {
                        reason: RejectReason::BadName
                    },
                    "{raw_name}"
                );
                raw.conn.close(0u32.into(), b"");
            }
        }
    }
    // Everything landed inside <inbox>/alice, nothing escaped.
    for f in finals(&bob.inbox) {
        assert!(f.starts_with(bob.inbox.join("alice")), "{f:?}");
    }
    assert!(!bob.dir.path().join("evil.txt").exists());
    assert!(!bob.inbox.join("evil.txt").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_do_not_hurt_the_service() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&bob, &alice, "alice");
    register(&alice, &bob, "bob");

    // Absurd length prefix.
    let conn = alice.node.connect_alpn(&bob.id(), PUSH_ALPN).await.unwrap();
    let (mut tx, _rx) = conn.open_bi().await.unwrap();
    AsyncWriteExt::write_all(&mut tx, &u32::MAX.to_be_bytes())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    conn.close(0u32.into(), b"");

    // Wrong version.
    let data = b"abc".to_vec();
    let mut h = header("v.txt", &data);
    h.v = 9;
    let (raw, reply) = raw_open(&alice, &bob, &h).await;
    assert_eq!(
        reply,
        Reply::Reject {
            reason: RejectReason::BadRequest
        }
    );
    raw.conn.close(0u32.into(), b"");

    // Bad hash text.
    let mut h = header("v.txt", &data);
    h.hash = "xyz".into();
    let (raw, reply) = raw_open(&alice, &bob, &h).await;
    assert_eq!(
        reply,
        Reply::Reject {
            reason: RejectReason::BadRequest
        }
    );
    raw.conn.close(0u32.into(), b"");

    // Truncated header, then abrupt close.
    let conn = alice.node.connect_alpn(&bob.id(), PUSH_ALPN).await.unwrap();
    let (mut tx, _rx) = conn.open_bi().await.unwrap();
    AsyncWriteExt::write_all(&mut tx, &100u32.to_be_bytes())
        .await
        .unwrap();
    AsyncWriteExt::write_all(&mut tx, b"{\"v\":1,")
        .await
        .unwrap();
    conn.close(0u32.into(), b"");

    // The service still works.
    let src = write_src(alice.dir.path(), "ok.txt", b"fine");
    let id = alice.svc.queue_send("bob", &src).unwrap();
    assert_eq!(
        wait_finished(&alice.svc, &id, 60).await.state,
        PushState::Done
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn second_push_of_the_same_name_never_overwrites() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&alice, &bob, "bob");
    register(&bob, &alice, "alice");

    let first = write_src(alice.dir.path(), "same.txt", b"first version");
    let id = alice.svc.queue_send("bob", &first).unwrap();
    assert_eq!(
        wait_finished(&alice.svc, &id, 60).await.state,
        PushState::Done
    );
    std::fs::write(&first, b"second version").unwrap();
    let id = alice.svc.queue_send("bob", &first).unwrap();
    assert_eq!(
        wait_finished(&alice.svc, &id, 60).await.state,
        PushState::Done
    );

    let dir = bob.inbox.join("alice");
    assert_eq!(
        std::fs::read(dir.join("same.txt")).unwrap(),
        b"first version"
    );
    assert_eq!(
        std::fs::read(dir.join("same (1).txt")).unwrap(),
        b"second version"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_contact_mid_transfer_cancels_and_cleans_up() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&bob, &alice, "alice");

    let data = content(2_000_000, 6);
    let h = header("long.bin", &data);
    let (mut raw, reply) = raw_open(&alice, &bob, &h).await;
    assert_eq!(reply, Reply::Accept { offset: 0 });
    AsyncWriteExt::write_all(&mut raw.tx, &data[..500_000])
        .await
        .unwrap();
    // Wait until the receiver is writing.
    for _ in 0..100 {
        if !parts(&bob.inbox).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!parts(&bob.inbox).is_empty());

    bob.svc.remove_contact("alice").unwrap();

    let inbound = {
        let mut found = None;
        for _ in 0..100 {
            found = bob
                .svc
                .board()
                .list()
                .into_iter()
                .find(|i| i.direction == Direction::In && i.state == PushState::Cancelled);
            if found.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        found.expect("the inbound transfer is cancelled")
    };
    assert_eq!(inbound.state, PushState::Cancelled);
    assert!(parts(&bob.inbox).is_empty());
    assert!(finals(&bob.inbox).is_empty());
    // The dialer is now simply not a contact: a new attempt is refused.
    raw.conn.close(0u32.into(), b"");
    let src = write_src(alice.dir.path(), "again.txt", b"x");
    register(&alice, &bob, "bob");
    let id = alice.svc.queue_send("bob", &src).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.reject_reason.as_deref(), Some("not_allowed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn three_files_in_a_row_including_64_mib() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&alice, &bob, "bob");
    register(&bob, &alice, "alice");

    let small = content(10_000, 7);
    let big = content(64 * 1024 * 1024, 8);
    let empty: Vec<u8> = Vec::new();
    let files = [
        ("small.bin", &small),
        ("big_64MiB.bin", &big),
        ("empty.txt", &empty),
    ];
    let mut ids = Vec::new();
    for (name, data) in files {
        let src = write_src(alice.dir.path(), name, data);
        ids.push(alice.svc.queue_send("bob", &src).unwrap());
    }
    // Sequential per contact: they finish in queue order.
    let mut last_created = 0;
    for ((name, data), id) in files.iter().zip(&ids) {
        let t = wait_finished(&alice.svc, id, 180).await;
        assert_eq!(t.state, PushState::Done, "{name}: {:?}", t.error);
        assert!(t.created_at_ms >= last_created);
        last_created = t.created_at_ms;
        let got = std::fs::read(bob.inbox.join("alice").join(name)).unwrap();
        assert_eq!(got.len(), data.len());
        assert_eq!(hash(&got), hash(data), "{name}");
    }
    assert!(parts(&bob.inbox).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn real_sender_resumes_from_the_receivers_partial_file() {
    let relay = relay().await;
    let alice = peer(&relay, |_| {}).await;
    let bob = peer(&relay, |_| {}).await;
    register(&alice, &bob, "bob");
    register(&bob, &alice, "alice");

    let data = content(1_500_000, 9);
    let half = 700_000usize;
    // A partial file as an interrupted earlier attempt would have left it.
    let dir = bob.inbox.join("alice");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!(".{}-{}.part", &hash(&data)[..32], data.len())),
        &data[..half],
    )
    .unwrap();

    let src = write_src(alice.dir.path(), "resumed.bin", &data);
    let id = alice.svc.queue_send("bob", &src).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(std::fs::read(dir.join("resumed.bin")).unwrap(), data);
    assert!(parts(&bob.inbox).is_empty());

    // A damaged partial (right length, wrong bytes) is caught by the final
    // hash and the sender retries once from scratch.
    let data2 = content(900_000, 10);
    std::fs::write(
        dir.join(format!(".{}-{}.part", &hash(&data2)[..32], data2.len())),
        vec![0u8; 300_000],
    )
    .unwrap();
    let src2 = write_src(alice.dir.path(), "healed.bin", &data2);
    let id = alice.svc.queue_send("bob", &src2).unwrap();
    let t = wait_finished(&alice.svc, &id, 60).await;
    assert_eq!(t.state, PushState::Done, "{:?}", t.error);
    assert_eq!(std::fs::read(dir.join("healed.bin")).unwrap(), data2);
}
