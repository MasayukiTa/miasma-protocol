//! Share ID v2: the ID a receiver types binds the publisher, the protection
//! state and the content, so a forged or replayed record is refused.
//!
//! Real nodes, real daemons, the production receive engine. The attackers are
//! real too: an endpoint serving a record signed by another key, and one
//! replaying an old unprotected record of the same content. No test carries a
//! fixed secret: passwords are generated at run time (and satisfy the policy).

use std::{path::Path, sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use miasma_core::{
    daemon::{
        ipc::{daemon_request, ControlRequest, ControlResponse},
        DaemonServer,
    },
    network::sybil::SignedDhtRecord,
    transfer::{
        decode_record_value, direct::receive_file_via_id, direct::ViaConfig, encode_record_value,
        parse_transfer_id, ReceiveOutcome, ShareId, ShareIdError, ShareMismatch, TransferId,
        TransferProgress, TransferState, TransferStatus,
    },
    transport::websocket::RecordProvider,
    ContentId, DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaError, MiasmaNode,
    Multiaddr, NodeType, PublishOptions, WssShareServer,
};
use tempfile::TempDir;
use tokio::time::timeout;
use zeroize::Zeroizing;

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    }
}

/// A fresh random password: no test carries a fixed secret. Always satisfies
/// the password policy (a digit, letters and a symbol).
fn random_password() -> String {
    format!("pw-1{:032x}", rand::random::<u128>())
}

fn content(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

fn write_named(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

// ─── Senders and attackers ──────────────────────────────────────────────────

/// A node holding its shares and its DHT record locally, with the WebSocket
/// server in front of both. No peer.
struct Sender {
    coord: MiasmaCoordinator,
    port: u16,
    _dir: TempDir,
}

impl Sender {
    async fn new(key: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
        let mut node = MiasmaNode::new(&[key; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let addrs = node.collect_listen_addrs(400).await;
        let coord = MiasmaCoordinator::start(node, store.clone(), vec![addrs[0].to_string()]).await;
        let server = WssShareServer::bind(store, 0)
            .await
            .unwrap()
            .with_record_provider(Arc::new(coord.dht_handle().clone()));
        let port = server.port;
        tokio::spawn(server.run());
        Self {
            coord,
            port,
            _dir: dir,
        }
    }

    fn url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.port)
    }

    fn publisher(&self) -> [u8; 32] {
        self.coord.dht_handle().publisher_key().unwrap()
    }

    /// Publish and return the MID and the share ID the publish reported.
    async fn publish(&self, path: &Path, password: Option<&str>) -> (ContentId, ShareId) {
        let report = match password {
            Some(pw) => {
                self.coord
                    .dissolve_and_publish_file_protected(
                        path,
                        params(),
                        PublishOptions::default(),
                        pw,
                    )
                    .await
            }
            None => {
                self.coord
                    .dissolve_and_publish_file_with_options(
                        path,
                        params(),
                        PublishOptions::default(),
                    )
                    .await
            }
        }
        .unwrap();
        let share = report.share_id.expect("a file publish reports a share ID");
        (report.mid, share)
    }

    /// The signed record envelope this node serves for `mid`.
    async fn envelope(&self, mid: &ContentId) -> Vec<u8> {
        self.coord
            .dht_handle()
            .local_record_value(*mid.as_bytes())
            .await
            .expect("the record is stored locally")
    }
}

/// Serves one fixed envelope for one MID and no shares: a hostile or replaying
/// endpoint that only lies about the record.
struct FixedEnvelope {
    mid: [u8; 32],
    envelope: Vec<u8>,
}

#[async_trait::async_trait]
impl RecordProvider for FixedEnvelope {
    async fn record_value(&self, mid_digest: [u8; 32]) -> Option<Vec<u8>> {
        (mid_digest == self.mid).then(|| self.envelope.clone())
    }
}

/// Start such an endpoint; keep the returned directory alive.
async fn serve_envelope(mid: &ContentId, envelope: Vec<u8>) -> (String, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 10).unwrap());
    let server = WssShareServer::bind(store, 0)
        .await
        .unwrap()
        .with_record_provider(Arc::new(FixedEnvelope {
            mid: *mid.as_bytes(),
            envelope,
        }));
    let url = format!("ws://127.0.0.1:{}", server.port);
    tokio::spawn(server.run());
    (url, dir)
}

/// The honest record, re-signed by `attacker`: valid for the key, valid
/// signature, wrong publisher.
fn resign(envelope: &[u8], attacker: &SigningKey) -> Vec<u8> {
    let signed: SignedDhtRecord = bincode::deserialize(envelope).unwrap();
    bincode::serialize(&SignedDhtRecord::sign(
        signed.key.clone(),
        signed.value.clone(),
        attacker,
    ))
    .unwrap()
}

async fn receive_via(
    urls: Vec<String>,
    id: &TransferId,
    out: &Path,
    password: Option<&str>,
) -> (Result<ReceiveOutcome, MiasmaError>, Arc<TransferProgress>) {
    let work = tempfile::tempdir().unwrap();
    let progress = TransferProgress::new(id.mid().to_string());
    let via = ViaConfig {
        urls,
        ca_pem: None,
    };
    let r = receive_file_via_id(
        &via,
        id,
        out,
        password.map(|p| Zeroizing::new(p.to_owned())),
        &work.path().join("transfers"),
        false,
        progress.clone(),
    )
    .await;
    (r, progress)
}

fn mismatch(r: Result<ReceiveOutcome, MiasmaError>) -> ShareMismatch {
    match r {
        Err(MiasmaError::ShareMismatch(m)) => m,
        other => panic!("expected a share mismatch, got {other:?}"),
    }
}

// ─── The publisher key ──────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_publisher_key_is_the_persistent_node_key_and_survives_a_restart() {
    // The record-signing key is derived from the node's master key (master.key
    // in the data dir), so a restarted daemon signs with the same key and an
    // earlier share ID stays valid. Only the public half is ever exposed.
    let master = [0x5Cu8; 32];
    let first = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let second = MiasmaNode::new(&master, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let other = MiasmaNode::new(&[0x5Du8; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let k1 = first.dht_handle().publisher_key().unwrap();
    assert_eq!(k1, second.dht_handle().publisher_key().unwrap());
    assert_ne!(k1, other.dht_handle().publisher_key().unwrap());
    assert_ne!(k1, master, "the public key is not the master key");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publish_reports_a_share_id_bound_to_the_node_key_and_the_protection() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x71).await;
        let dir = tempfile::tempdir().unwrap();
        let path = write_named(&dir, "plain.bin", &content(5_000));

        let (mid, share) = a.publish(&path, None).await;
        assert_eq!(share.mid(), mid);
        assert_eq!(share.publisher(), &a.publisher());
        assert!(!share.protected());
        let text = share.to_string();
        assert!(text.starts_with("miasma-share:"));
        assert_eq!(text.parse::<ShareId>().unwrap(), share);

        let pw = random_password();
        let (mid2, share2) = a.publish(&path, Some(&pw)).await;
        assert_eq!(mid2, mid, "the MID names the content, not the protection");
        assert!(share2.protected());
        assert_ne!(share2.to_string(), text);
        assert_eq!(share2.publisher(), &a.publisher());
    })
    .await
    .expect("timed out");
}

// ─── Receive with the share ID over --via ───────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_share_id_receive_over_via_succeeds_and_authenticates_the_publisher() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x72).await;
        let dir = tempfile::tempdir().unwrap();
        let data = content(20_000);
        let path = write_named(&dir, "plain.bin", &data);
        let (_, share) = a.publish(&path, None).await;

        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");
        let (r, progress) = receive_via(vec![a.url()], &TransferId::Share(share), &out, None).await;
        assert!(matches!(r, Ok(ReceiveOutcome::Complete { .. })), "{r:?}");
        assert_eq!(std::fs::read(&out).unwrap(), data);
        let s = progress.snapshot();
        assert!(s.share_id_checked && s.publisher_authenticated);
        assert_eq!(s.share_id.as_deref(), Some(share.to_string().as_str()));
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_protected_share_id_receive_needs_the_password_and_the_right_one_works() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x73).await;
        let dir = tempfile::tempdir().unwrap();
        let data = content(12_000);
        let path = write_named(&dir, "secret.bin", &data);
        let pw = random_password();
        let (_, share) = a.publish(&path, Some(&pw)).await;
        assert!(share.protected());

        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");
        let id = TransferId::Share(share);
        let (r, _) = receive_via(vec![a.url()], &id, &out, None).await;
        assert!(matches!(r, Err(MiasmaError::PasswordRequired)), "{r:?}");
        assert!(!out.exists());
        let (r, p) = receive_via(vec![a.url()], &id, &out, Some(&pw)).await;
        assert!(matches!(r, Ok(ReceiveOutcome::Complete { .. })), "{r:?}");
        assert_eq!(std::fs::read(&out).unwrap(), data);
        assert!(p.snapshot().publisher_authenticated);
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_mid_still_works_but_is_not_authenticated() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x74).await;
        let dir = tempfile::tempdir().unwrap();
        let data = content(9_000);
        let path = write_named(&dir, "plain.bin", &data);
        let (mid, _) = a.publish(&path, None).await;

        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");
        let id = parse_transfer_id(&mid.to_string()).unwrap();
        assert!(matches!(id, TransferId::Mid(_)));
        let (r, progress) = receive_via(vec![a.url()], &id, &out, None).await;
        assert!(matches!(r, Ok(ReceiveOutcome::Complete { .. })), "{r:?}");
        assert_eq!(std::fs::read(&out).unwrap(), data);
        let s = progress.snapshot();
        assert!(!s.publisher_authenticated, "a bare MID cannot authenticate");
        assert!(!s.share_id_checked);
        assert!(s.share_id.is_none());
    })
    .await
    .expect("timed out");
}

// ─── C-01: a record signed by another key ───────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_record_signed_by_another_key_is_rejected_and_the_honest_one_still_wins() {
    timeout(Duration::from_secs(120), async {
        let honest = Sender::new(0x75).await;
        let dir = tempfile::tempdir().unwrap();
        let data = content(15_000);
        let path = write_named(&dir, "plain.bin", &data);
        let (mid, share) = honest.publish(&path, None).await;

        // The attacker re-signs the honest record with its own key and answers
        // first: a perfectly valid signature, for the wrong publisher.
        let attacker_key = SigningKey::from_bytes(&[0xAB; 32]);
        assert_ne!(attacker_key.verifying_key().to_bytes(), honest.publisher());
        let forged = resign(&honest.envelope(&mid).await, &attacker_key);
        let (evil_url, _keep) = serve_envelope(&mid, forged).await;

        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");
        let (r, progress) = receive_via(
            vec![evil_url.clone(), honest.url()],
            &TransferId::Share(share),
            &out,
            None,
        )
        .await;
        assert!(matches!(r, Ok(ReceiveOutcome::Complete { .. })), "{r:?}");
        assert_eq!(std::fs::read(&out).unwrap(), data);
        assert!(progress.snapshot().publisher_authenticated);

        // With only the attacker reachable the answer is a typed refusal, not
        // the forged record and not a generic "not found".
        let out2 = out_dir.path().join("never.bin");
        let (r, progress) =
            receive_via(vec![evil_url], &TransferId::Share(share), &out2, None).await;
        assert_eq!(mismatch(r), ShareMismatch::WrongSigner);
        assert!(!out2.exists());
        let s = progress.snapshot();
        assert_eq!(s.state, TransferState::Failed);
        assert!(!s.publisher_authenticated);
        assert_eq!(s.pieces_fetched, 0, "nothing is fetched from a forger");
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_share_id_naming_another_publisher_finds_nothing_to_accept() {
    timeout(Duration::from_secs(120), async {
        let honest = Sender::new(0x76).await;
        let dir = tempfile::tempdir().unwrap();
        let path = write_named(&dir, "plain.bin", &content(4_000));
        let (mid, _) = honest.publish(&path, None).await;

        // Same content, but the ID claims a different publisher.
        let other = SigningKey::from_bytes(&[0xAC; 32]).verifying_key().to_bytes();
        let wrong = ShareId::new(&mid, other, false);
        let out = tempfile::tempdir().unwrap().path().join("never.bin");
        let (r, _) = receive_via(vec![honest.url()], &TransferId::Share(wrong), &out, None).await;
        assert_eq!(mismatch(r), ShareMismatch::WrongSigner);
        assert!(!out.exists());
    })
    .await
    .expect("timed out");
}

// ─── C-06: an old unprotected record against a protected share ID ──────────

#[tokio::test(flavor = "multi_thread")]
async fn an_old_unprotected_record_replayed_against_a_protected_share_id_is_refused() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x77).await;
        let dir = tempfile::tempdir().unwrap();
        let data = content(6_000);
        let path = write_named(&dir, "doc.bin", &data);

        // First the file goes out unprotected; an observer keeps that record.
        let (mid, _) = a.publish(&path, None).await;
        let old_unprotected = a.envelope(&mid).await;
        // Later the same file is published again, now protected: same MID.
        let pw = random_password();
        let (mid2, protected_share) = a.publish(&path, Some(&pw)).await;
        assert_eq!(mid, mid2);
        assert!(protected_share.protected());

        // The replay is validly signed by the real publisher (it *is* the
        // publisher's old record): only the protection flag can refuse it.
        let (replay_url, _keep) = serve_envelope(&mid, old_unprotected).await;
        let out = tempfile::tempdir().unwrap().path().join("never.bin");
        let (r, progress) = receive_via(
            vec![replay_url],
            &TransferId::Share(protected_share),
            &out,
            Some(&pw),
        )
        .await;
        assert_eq!(mismatch(r), ShareMismatch::ProtectionDowngrade);
        assert!(!out.exists());
        assert_eq!(progress.snapshot().pieces_fetched, 0);
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unprotected_share_id_refuses_a_protected_record() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x78).await;
        let dir = tempfile::tempdir().unwrap();
        let path = write_named(&dir, "doc.bin", &content(3_000));
        let pw = random_password();
        let (mid, _) = a.publish(&path, Some(&pw)).await;
        let claims_plain = ShareId::new(&mid, a.publisher(), false);
        let out = tempfile::tempdir().unwrap().path().join("never.bin");
        let (r, _) = receive_via(
            vec![a.url()],
            &TransferId::Share(claims_plain),
            &out,
            Some(&pw),
        )
        .await;
        assert_eq!(mismatch(r), ShareMismatch::ProtectionUpgrade);
    })
    .await
    .expect("timed out");
}

// ─── Manifest v3 ────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_v2_manifest_is_refused_with_a_publish_again_message() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x79).await;
        let dir = tempfile::tempdir().unwrap();
        let path = write_named(&dir, "doc.bin", &content(3_000));
        let (mid, _) = a.publish(&path, None).await;

        // A record as a previous release published it: a version-2 trailer,
        // signed by a key the receiver's ID names.
        let signer = SigningKey::from_bytes(&[0xAD; 32]);
        let signed: SignedDhtRecord = bincode::deserialize(&a.envelope(&mid).await).unwrap();
        let mut value = signed.value.clone();
        let pos = value
            .windows(4)
            .position(|w| w == b"MNFT")
            .expect("trailer present");
        value[pos + 4] = 2;
        let old = bincode::serialize(&SignedDhtRecord::sign(signed.key, value, &signer)).unwrap();
        let (url, _keep) = serve_envelope(&mid, old).await;

        let id = ShareId::new(&mid, signer.verifying_key().to_bytes(), false);
        let out = tempfile::tempdir().unwrap().path().join("never.bin");
        let (r, _) = receive_via(vec![url], &TransferId::Share(id), &out, None).await;
        match r {
            Err(MiasmaError::InvalidManifest(m)) => {
                assert!(m.contains("no longer supported"), "{m}");
                assert!(m.contains("publish the file again"), "{m}");
            }
            other => panic!("a v2 manifest must be refused, got {other:?}"),
        }
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_published_manifest_names_the_publisher_and_only_the_file_name() {
    timeout(Duration::from_secs(120), async {
        let a = Sender::new(0x7A).await;
        let dir = tempfile::tempdir().unwrap();
        let path = write_named(&dir, "quarterly report.pdf", &content(2_000));
        let (mid, _) = a.publish(&path, None).await;
        let signed: SignedDhtRecord = bincode::deserialize(&a.envelope(&mid).await).unwrap();
        assert_eq!(signed.signer_pubkey, a.publisher());
        let (_, manifest) = decode_record_value(&signed.value).unwrap();
        let m = manifest.unwrap();
        assert_eq!(m.publisher, a.publisher());
        assert_eq!(m.name.as_deref(), Some("quarterly report.pdf"));
        // Re-encoding with a different publisher than the signer is refused by
        // the publishing handle before it is ever signed.
        let mut lying = m.clone();
        lying.publisher = [0x11; 32];
        let record = decode_record_value(&signed.value).unwrap().0;
        assert!(a
            .coord
            .dht_handle()
            .put_with_manifest(record.clone(), Some(&lying))
            .await
            .is_err());
        // ... and a manifest that names the signer encodes fine.
        assert!(encode_record_value(&record, Some(&m)).is_ok());
    })
    .await
    .expect("timed out");
}

// ─── A typo never reaches the network ───────────────────────────────────────

struct Daemon {
    dir: TempDir,
    shutdown: tokio::sync::mpsc::Sender<()>,
}

async fn start_daemon(key: u8) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
    let node = MiasmaNode::new(&[key; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server = DaemonServer::start(node, store, dir.path().to_path_buf())
        .await
        .unwrap();
    let shutdown = server.shutdown_handle();
    tokio::spawn(server.run());
    Daemon { dir, shutdown }
}

async fn ask(d: &Daemon, req: ControlRequest) -> ControlResponse {
    daemon_request(d.dir.path(), req).await.unwrap()
}

async fn status(d: &Daemon, id: &str) -> TransferStatus {
    match ask(d, ControlRequest::TransferStatus { id: id.into() }).await {
        ControlResponse::TransferStatus(s) => s,
        other => panic!("unexpected: {other:?}"),
    }
}

async fn finished(d: &Daemon, id: &str) -> TransferStatus {
    loop {
        let s = status(d, id).await;
        if s.state != TransferState::Running {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn receive_request(id: &str, out: &Path, via: Vec<String>) -> ControlRequest {
    ControlRequest::TransferStartReceive {
        mid: id.to_owned(),
        output_path: out.to_string_lossy().into_owned(),
        password: None,
        restart: false,
        via,
        via_ca_pem: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mistyped_share_id_is_refused_before_any_network_work() {
    timeout(Duration::from_secs(60), async {
        let d = start_daemon(0x7B).await;
        let mid = ContentId::compute(b"x", &params().to_param_bytes());
        let key = SigningKey::from_bytes(&[0xAE; 32]).verifying_key().to_bytes();
        let good = ShareId::new(&mid, key, true).to_string();
        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("x.bin");

        // One character changed anywhere: refused at once, nothing started. The
        // via URL points nowhere; if the ID were accepted the job would row up.
        let chars: Vec<char> = good.chars().collect();
        for pos in [13, 14, 30, 60, chars.len() - 1] {
            let mut t = chars.clone();
            t[pos] = if t[pos] == 'z' { 'y' } else { 'z' };
            let typo: String = t.into_iter().collect();
            let started = std::time::Instant::now();
            match ask(
                &d,
                receive_request(&typo, &out, vec!["ws://127.0.0.1:9".into()]),
            )
            .await
            {
                ControlResponse::Error(e) => {
                    assert!(e.starts_with("invalid share ID"), "{e}");
                }
                other => panic!("typo at {pos} must be refused, got {other:?}"),
            }
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        match ask(&d, ControlRequest::TransferList).await {
            ControlResponse::TransferList(list) => assert!(list.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }

        // The error is precise about the class.
        let e = parse_transfer_id(&format!("{}1", &good[..good.len() - 1]));
        assert!(matches!(e, Err(MiasmaError::InvalidShareId(_))), "{e:?}");
        assert!(matches!(
            ShareId::parse("miasma-share:abc0"),
            Err(ShareIdError::BadBase58)
        ));
        let _ = d.shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

// ─── Through two daemons: IPC publish result, share ID receive, folder ──────

#[tokio::test(flavor = "multi_thread")]
async fn daemons_publish_reports_the_share_id_and_a_folder_target_gets_the_original_name() {
    timeout(Duration::from_secs(300), async {
        let a = start_daemon(0x7C).await;
        let src_dir = tempfile::tempdir().unwrap();
        let data = content(30_000);
        let src = write_named(&src_dir, "minutes 2026.txt", &data);

        let id = match ask(
            &a,
            ControlRequest::TransferStartPublish {
                file_path: src.to_string_lossy().into_owned(),
                data_shards: 2,
                total_shards: 3,
                password: None,
                restart: false,
            },
        )
        .await
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
        let sent = finished(&a, &id).await;
        assert_eq!(sent.state, TransferState::Complete, "{:?}", sent.last_error);
        let share_text = sent.share_id.clone().expect("the send reports its share ID");
        let share: ShareId = share_text.parse().unwrap();
        assert_eq!(share.mid().to_string(), sent.mid);
        assert!(!share.protected());

        // The daemon's WebSocket endpoint.
        let url = {
            let port = match ask(&a, ControlRequest::Status).await {
                ControlResponse::Status(s) => s.wss_port,
                other => panic!("unexpected: {other:?}"),
            };
            format!("ws://127.0.0.1:{port}")
        };

        // Receiver daemon, a FOLDER as the target, the share ID as the input.
        let b = start_daemon(0x7D).await;
        let folder = tempfile::tempdir().unwrap();
        let rid = match ask(
            &b,
            receive_request(&share_text, folder.path(), vec![url.clone()]),
        )
        .await
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("a folder target must be accepted, got {other:?}"),
        };
        let got = finished(&b, &rid).await;
        assert_eq!(got.state, TransferState::Complete, "{:?}", got.last_error);
        assert!(got.share_id_checked && got.publisher_authenticated);
        let written = folder.path().join("minutes 2026.txt");
        assert_eq!(std::fs::read(&written).unwrap(), data);
        assert_eq!(got.name, written.to_string_lossy());

        // A second receive into the same folder never overwrites.
        std::fs::write(&written, b"keep me").unwrap();
        let rid2 = match ask(
            &b,
            receive_request(&share_text, folder.path(), vec![url.clone()]),
        )
        .await
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
        let again = finished(&b, &rid2).await;
        assert_eq!(again.state, TransferState::Failed);
        assert!(
            again
                .last_error
                .as_deref()
                .unwrap_or("")
                .contains("refusing to overwrite"),
            "{:?}",
            again.last_error
        );
        assert_eq!(std::fs::read(&written).unwrap(), b"keep me");

        // The bare MID into a file path: accepted, flagged unauthenticated.
        let out = folder.path().join("by-mid.txt");
        let rid3 = match ask(&b, receive_request(&sent.mid, &out, vec![url])).await {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
        let by_mid = finished(&b, &rid3).await;
        assert_eq!(by_mid.state, TransferState::Complete, "{:?}", by_mid.last_error);
        assert!(!by_mid.publisher_authenticated);
        assert!(!by_mid.share_id_checked);
        assert_eq!(std::fs::read(&out).unwrap(), data);

        let _ = a.shutdown.send(()).await;
        let _ = b.shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

// ─── The DHT path between two in-process nodes ──────────────────────────────

async fn spawn_node(key_byte: u8) -> (MiasmaCoordinator, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
    let mut node =
        MiasmaNode::new(&[key_byte; 32], NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let addrs = node.collect_listen_addrs(400).await;
    let coord = MiasmaCoordinator::start(node, store, vec![addrs[0].to_string()]).await;
    (coord, dir)
}

#[tokio::test(flavor = "multi_thread")]
async fn over_the_dht_only_the_named_publishers_record_is_accepted() {
    timeout(Duration::from_secs(180), async {
        let (a, _da) = spawn_node(0x7E).await;
        let (b, db) = spawn_node(0x7F).await;
        let addr_a: Multiaddr = a.listen_addrs()[0].parse().unwrap();
        b.add_bootstrap_peer(*a.peer_id(), addr_a).await.unwrap();
        b.bootstrap_dht().await.unwrap();
        b.wait_until_peer_connected(*a.peer_id(), Duration::from_secs(10))
            .await
            .unwrap();

        let src_dir = tempfile::tempdir().unwrap();
        let data = content(25_000);
        let path = write_named(&src_dir, "dht.bin", &data);
        let report = a
            .dissolve_and_publish_file_with_options(&path, params(), PublishOptions::default())
            .await
            .unwrap();
        let share = report.share_id.unwrap();
        let publisher = a.dht_handle().publisher_key().unwrap();
        assert_eq!(share.publisher(), &publisher);

        // The record query itself: the filter names the signer. The publisher's
        // key finds the record; any other key finds nothing, even though a
        // perfectly valid record sits under that DHT key.
        let mid_bytes = *report.mid.as_bytes();
        let found = b
            .dht_handle()
            .get_signed_record(mid_bytes, Some(publisher))
            .await
            .unwrap()
            .expect("the publisher's record");
        assert_eq!(found.signer, publisher);
        assert_eq!(found.manifest.unwrap().publisher, publisher);
        let stranger = SigningKey::from_bytes(&[0xAF; 32]).verifying_key().to_bytes();
        assert!(b
            .dht_handle()
            .get_signed_record(mid_bytes, Some(stranger))
            .await
            .unwrap()
            .is_none());

        // A full receive by share ID, pieces over libp2p.
        let journals = db.path().join("transfers");
        let out_dir = tempfile::tempdir().unwrap();
        let out = out_dir.path().join("got.bin");
        let progress = TransferProgress::new(report.mid.to_string());
        let outcome = b
            .receive_file_id(
                &TransferId::Share(share),
                &out,
                None,
                &journals,
                false,
                progress.clone(),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, ReceiveOutcome::Complete { .. }), "{outcome:?}");
        assert_eq!(std::fs::read(&out).unwrap(), data);
        let s = progress.snapshot();
        assert!(s.publisher_authenticated && s.share_id_checked);

        // The same by bare MID: accepted, but not authenticated.
        let out2 = out_dir.path().join("by-mid.bin");
        let progress = TransferProgress::new(report.mid.to_string());
        b.receive_file(&report.mid, &out2, None, &journals, true, progress.clone())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&out2).unwrap(), data);
        assert!(!progress.snapshot().publisher_authenticated);

        a.shutdown().await;
        b.shutdown().await;
    })
    .await
    .expect("timed out");
}
