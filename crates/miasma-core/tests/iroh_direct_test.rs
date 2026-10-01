//! Receive by share ID and password alone, over iroh: no `--via`, no DHT, no
//! bootstrap peer, no open port and no tunnel.
//!
//! The sender is a real node whose iroh endpoint uses its persistent identity key
//! (the publisher key of its share IDs). The receiver knows only the share ID.
//! Both talk through iroh's own **local relay test server**, so nothing in this
//! file contacts n0 or any other public service (except the one `#[ignore]`d
//! manual test at the end, which says so). The production receive engine,
//! verification and journal are used unchanged.
//!
//! No test carries a fixed secret: passwords and keys are generated at run time.

#![cfg(feature = "iroh")]

use std::{path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use iroh::{tls::CaTlsConfig, Endpoint, EndpointAddr, EndpointId};
use miasma_core::{
    config::{IrohMode, TransportConfig},
    daemon::{
        ipc::{daemon_request, ControlRequest, ControlResponse},
        DaemonServer,
    },
    network::sybil::SignedDhtRecord,
    transfer::{
        direct::{
            receive_file_direct_id, try_receive_direct, DirectOutcome, DirectSources,
            IrohPieceSource, IrohSource, ViaConfig,
        },
        open_signed_record,
        receive::{resolve_output_target, run_receive, PieceSource, ReceiveSpec, RetryConfig},
        ReceiveOutcome, ShareId, TransferId, TransferProgress, TransferState, TransferStatus,
    },
    transport::{
        iroh_direct::{
            endpoint_builder, node_for, IrohNode, IrohServerLimits, IrohSettings, IROH_ALPN,
        },
        websocket::RecordProvider,
    },
    ContentId, DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaError, MiasmaNode,
    MiasmaShare, NodeType, PublishOptions, WssShareServer,
};
use tempfile::TempDir;
use tokio::time::timeout;
use zeroize::Zeroizing;

/// A file one 64 KiB block longer than the largest k=2 segment: exactly two
/// segments without needing a 64 MiB fixture.
const MAX_SEGMENT_K2: usize = (8 * 1024 * 1024 - 4096) * 2;
const TWO_SEGMENT_LEN: usize = MAX_SEGMENT_K2 + 64 * 1024;

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    }
}

/// A fresh random password that satisfies the policy (a digit, letters, a symbol).
fn random_password() -> String {
    format!("pw-1{:032x}", rand::random::<u128>())
}

/// Non-repeating-looking content so a segment mix-up is visible.
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

fn write_payload(dir: &TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, bytes).unwrap();
    path
}

fn pw(s: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(s.to_owned()))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

// ─── A local relay and endpoints that use it ────────────────────────────────

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

fn settings(relay_url: &str, connect_timeout: Duration) -> IrohSettings {
    IrohSettings {
        mode: IrohMode::Custom,
        relay_urls: vec![relay_url.to_owned()],
        discovery: false,
        connect_timeout,
        ca_pem: None,
        proxy_from_env: false,
    }
}

/// An iroh node on the local relay (whose certificate is self-signed, hence the
/// one insecure setting, which exists only with the relay's `test-utils`).
async fn start_node(
    seed: Option<[u8; 32]>,
    relay_url: &str,
    connect_timeout: Duration,
    store: Arc<LocalShareStore>,
    records: Option<Arc<dyn RecordProvider>>,
    limits: IrohServerLimits,
) -> Arc<IrohNode> {
    let s = settings(relay_url, connect_timeout);
    let seed: [u8; 32] = seed.unwrap_or_else(rand::random);
    let builder = endpoint_builder(Some(&seed), &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    let node = IrohNode::start_from_builder(builder, s, store, records, limits)
        .await
        .unwrap();
    assert!(
        node.wait_online(Duration::from_secs(20)).await,
        "the endpoint must reach the local relay"
    );
    node
}

fn empty_store() -> (TempDir, Arc<LocalShareStore>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 10).unwrap());
    (dir, store)
}

/// A receiver: an iroh node that knows only the relay, no records and no shares.
async fn receiver(relay: &Relay) -> (Arc<IrohNode>, TempDir) {
    let (dir, store) = empty_store();
    let node = start_node(
        None,
        &relay.url,
        Duration::from_secs(20),
        store,
        None,
        IrohServerLimits::default(),
    )
    .await;
    (node, dir)
}

// ─── A sender ────────────────────────────────────────────────────────────────

/// A real node: its store, its DHT record store, and an iroh endpoint whose
/// identity is the node's persistent key. There is deliberately no peer and no
/// WebSocket server.
struct Sender {
    coord: MiasmaCoordinator,
    iroh: Arc<IrohNode>,
    _dir: TempDir,
}

impl Sender {
    async fn new(relay: &Relay) -> Self {
        Self::with_limits(relay, IrohServerLimits::default()).await
    }

    async fn with_limits(relay: &Relay, limits: IrohServerLimits) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
        let key: [u8; 32] = rand::random();
        let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
        let seed = node.identity_seed();
        let addrs = node.collect_listen_addrs(400).await;
        let coord = MiasmaCoordinator::start(node, store.clone(), vec![addrs[0].to_string()]).await;
        let records: Arc<dyn RecordProvider> = Arc::new(coord.dht_handle().clone());
        let iroh = start_node(
            Some(*seed),
            &relay.url,
            Duration::from_secs(20),
            store,
            Some(records),
            limits,
        )
        .await;
        Self {
            coord,
            iroh,
            _dir: dir,
        }
    }

    fn publisher(&self) -> [u8; 32] {
        self.coord.dht_handle().publisher_key().unwrap()
    }

    async fn publish(&self, bytes: &[u8], password: Option<&str>) -> (ContentId, ShareId) {
        let scratch = tempfile::tempdir().unwrap();
        let path = write_payload(&scratch, bytes);
        let report = match password {
            Some(p) => {
                self.coord
                    .dissolve_and_publish_file_protected(
                        &path,
                        params(),
                        PublishOptions::default(),
                        p,
                    )
                    .await
            }
            None => {
                self.coord
                    .dissolve_and_publish_file_with_options(
                        &path,
                        params(),
                        PublishOptions::default(),
                    )
                    .await
            }
        }
        .unwrap();
        (
            report.mid,
            report.share_id.expect("a file publish reports a share ID"),
        )
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

fn iroh_only(node: &Arc<IrohNode>) -> DirectSources {
    DirectSources {
        via: None,
        iroh: Some(IrohSource {
            node: node.clone(),
            ca_pem: None,
        }),
    }
}

async fn receive_iroh(
    node: &Arc<IrohNode>,
    share: &ShareId,
    out: &Path,
    journals: &Path,
    password: Option<&str>,
    progress: Arc<TransferProgress>,
) -> Result<ReceiveOutcome, MiasmaError> {
    receive_file_direct_id(
        &iroh_only(node),
        &TransferId::Share(*share),
        out,
        password.and_then(|p| pw(p)),
        journals,
        false,
        progress,
    )
    .await
}

// ─── (a) (b) (c): the whole receive, by share ID alone ──────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_protected_multi_segment_transfer_is_received_by_share_id_alone_and_resumes() {
    timeout(Duration::from_secs(600), async {
        let relay = relay().await;
        let sender = Sender::new(&relay).await;
        let data = content(TWO_SEGMENT_LEN);
        let password = random_password();
        let (mid, share) = sender.publish(&data, Some(&password)).await;
        assert_eq!(
            share.publisher(),
            &sender.publisher(),
            "the share ID names the node's identity key"
        );
        assert_eq!(
            sender.iroh.endpoint_id(),
            sender.publisher(),
            "the iroh endpoint ID is the publisher key of the share ID"
        );

        // The receiver has no --via, no DHT, no bootstrap: the share ID and a
        // relay to find the sender through.
        let (rx, _rx_dir) = receiver(&relay).await;
        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("got.bin");
        let journals = work.path().join("transfers");

        // (b) A wrong password is refused before a single piece is fetched.
        let progress = TransferProgress::new(mid.to_string());
        let err = receive_iroh(
            &rx,
            &share,
            &out,
            &journals,
            Some(&random_password()),
            progress.clone(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("wrong password"), "{err}");
        let s = progress.snapshot();
        assert_eq!(s.state, TransferState::Failed);
        assert_eq!(
            s.pieces_fetched, 0,
            "nothing may be fetched for a wrong password"
        );
        assert!(!out.exists());

        // A protected transfer needs its password at all.
        let progress = TransferProgress::new(mid.to_string());
        let err = receive_iroh(&rx, &share, &out, &journals, None, progress)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("password-protected"), "{err}");

        // (c) Stop deterministically after segment 0 ...
        let progress = TransferProgress::new(mid.to_string());
        progress.stop_after_segments(1);
        let first = receive_iroh(&rx, &share, &out, &journals, Some(&password), progress)
            .await
            .unwrap();
        assert_eq!(first, ReceiveOutcome::Cancelled { next_segment: 1 });
        assert!(!out.exists(), "no output name until the file is whole");

        // ... and run it again: resumes at segment 1 and finishes exactly.
        let progress = TransferProgress::new(mid.to_string());
        let started = std::time::Instant::now();
        let second = receive_iroh(
            &rx,
            &share,
            &out,
            &journals,
            Some(&password),
            progress.clone(),
        )
        .await
        .unwrap();
        let secs = started.elapsed().as_secs_f64();
        assert_eq!(
            second,
            ReceiveOutcome::Complete {
                bytes: TWO_SEGMENT_LEN as u64
            }
        );
        let s = progress.snapshot();
        assert_eq!(s.resumed_from_segment, 1);
        assert_eq!(s.segments_done, 2);
        assert_eq!(s.pieces_rejected, 0);
        assert!(s.publisher_authenticated && s.share_id_checked);
        assert!(
            matches!(s.path.as_deref(), Some("direct") | Some("relay")),
            "an iroh receive reports its path: {:?}",
            s.path
        );

        // (a) Byte-identical.
        let got = std::fs::read(&out).unwrap();
        assert_eq!(digest(&got), digest(&data), "hash of the received file");
        assert!(got == data, "byte-identical");
        eprintln!(
            "MEASURED iroh local-relay receive of segment 1 ({} MiB) in {secs:.2}s; path={:?}",
            (TWO_SEGMENT_LEN - MAX_SEGMENT_K2 / 2) / 1_048_576,
            s.path
        );
    })
    .await
    .expect("timed out");
}

// ─── (d): a server that is not the publisher is refused ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn an_endpoint_that_is_not_the_publisher_is_refused_even_at_the_right_address() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let sender = Sender::new(&relay).await;
        let data = content(200_000);
        let (mid, share) = sender.publish(&data, None).await;

        // An impostor with another key that serves the very same store and
        // records: everything it says would be valid, if it were accepted.
        let impostor_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalShareStore::open(impostor_dir.path(), 1000).unwrap());
        let records: Arc<dyn RecordProvider> = Arc::new(sender.coord.dht_handle().clone());
        let impostor = start_node(
            None,
            &relay.url,
            Duration::from_secs(20),
            store,
            Some(records),
            IrohServerLimits::default(),
        )
        .await;
        assert_ne!(impostor.endpoint_id(), sender.publisher());

        // The receiver is pointed at the impostor's real socket address while
        // dialing the publisher's key. TLS must refuse: the peer cannot prove
        // it holds that key.
        let (rx, _rx_dir) = receiver(&relay).await;
        let direct: Vec<std::net::SocketAddr> = impostor
            .endpoint()
            .bound_sockets()
            .into_iter()
            .map(|a| std::net::SocketAddr::from(([127, 0, 0, 1], a.port())))
            .collect();
        assert!(!direct.is_empty());
        let client = miasma_core::transport::iroh_direct::IrohDirectClient::new(
            rx.endpoint().clone(),
            share.publisher(),
            Vec::new(), // no relay hint: the only way to an answer is the impostor
            Duration::from_secs(4),
        )
        .unwrap()
        .with_direct_addrs(direct);
        let err = client.fetch_record(*mid.as_bytes()).await.unwrap_err();
        assert!(err.is_permanent(), "{err}");
        assert!(
            err.to_string()
                .contains("cannot reach the sender over iroh"),
            "{err}"
        );

        // Through the receive path: an error, nothing written, never a receive
        // from the impostor.
        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("got.bin");
        let progress = TransferProgress::new(mid.to_string());
        let outcome = try_receive_direct(
            &DirectSources {
                via: None,
                iroh: Some(IrohSource {
                    node: rx.clone(),
                    ca_pem: None,
                }),
            },
            &TransferId::Share(ShareId::new(
                &mid,
                *impostor_id_as_share_key(&impostor),
                false,
            )),
            &out,
            None,
            &work.path().join("transfers"),
            false,
            progress,
        )
        .await;
        // (The share ID above names the impostor's own key, which is a valid
        // dial: it is reachable, but it serves a record signed by the real
        // publisher, so the signer check refuses it.)
        match outcome {
            DirectOutcome::Unavailable(f) => {
                assert_eq!(f.len(), 1);
                assert!(
                    matches!(f[0].1, MiasmaError::ShareMismatch(_)),
                    "a record signed by another key is refused: {:?}",
                    f[0].1
                );
            }
            DirectOutcome::Finished(r) => panic!("must not be received: {r:?}"),
        }
        assert!(!out.exists());
    })
    .await
    .expect("timed out");
}

/// The impostor's own endpoint key, as a share-ID publisher key.
fn impostor_id_as_share_key(node: &Arc<IrohNode>) -> Box<[u8; 32]> {
    Box::new(node.endpoint_id())
}

// ─── (e): a forged record loses; the honest endpoint listed second wins ─────

struct FixedEnvelope {
    mid: [u8; 32],
    envelope: Vec<u8>,
}

#[async_trait]
impl RecordProvider for FixedEnvelope {
    async fn record_value(&self, mid_digest: [u8; 32]) -> Option<Vec<u8>> {
        (mid_digest == self.mid).then(|| self.envelope.clone())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_record_is_refused_and_the_honest_endpoint_listed_second_still_wins() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let sender = Sender::new(&relay).await;
        let data = content(200_000);
        let (mid, share) = sender.publish(&data, None).await;

        // A hostile WebSocket endpoint, listed FIRST, serving the honest record
        // re-signed by another key.
        let attacker = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let signed: SignedDhtRecord = bincode::deserialize(&sender.envelope(&mid).await).unwrap();
        let forged = bincode::serialize(&SignedDhtRecord::sign(
            signed.key.clone(),
            signed.value.clone(),
            &attacker,
        ))
        .unwrap();
        let hostile_dir = tempfile::tempdir().unwrap();
        let hostile_store = Arc::new(LocalShareStore::open(hostile_dir.path(), 10).unwrap());
        let server = WssShareServer::bind(hostile_store, 0)
            .await
            .unwrap()
            .with_record_provider(Arc::new(FixedEnvelope {
                mid: *mid.as_bytes(),
                envelope: forged,
            }));
        let url = format!("ws://127.0.0.1:{}", server.port);
        tokio::spawn(server.run());

        let (rx, _rx_dir) = receiver(&relay).await;
        let sources = DirectSources {
            via: Some(ViaConfig {
                urls: vec![url],
                ca_pem: None,
            }),
            iroh: Some(IrohSource {
                node: rx.clone(),
                ca_pem: None,
            }),
        };
        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("got.bin");
        let progress = TransferProgress::new(mid.to_string());
        let outcome = try_receive_direct(
            &sources,
            &TransferId::Share(share),
            &out,
            None,
            &work.path().join("transfers"),
            false,
            progress.clone(),
        )
        .await;
        match outcome {
            DirectOutcome::Finished(Ok(ReceiveOutcome::Complete { bytes })) => {
                assert_eq!(bytes, data.len() as u64)
            }
            DirectOutcome::Finished(other) => panic!("unexpected: {other:?}"),
            DirectOutcome::Unavailable(f) => panic!("the honest endpoint must win: {f:?}"),
        }
        assert!(std::fs::read(&out).unwrap() == data);
        assert!(progress.snapshot().publisher_authenticated);

        // The forged endpoint alone: refused for its signer, with the reason.
        let progress = TransferProgress::new(mid.to_string());
        let only_hostile = DirectSources {
            via: sources.via.clone(),
            iroh: None,
        };
        let err = receive_file_direct_id(
            &only_hostile,
            &TransferId::Share(share),
            &work.path().join("never.bin"),
            None,
            &work.path().join("transfers2"),
            false,
            progress.clone(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, MiasmaError::ShareMismatch(_)),
            "a forged record says why it was refused: {err}"
        );
        assert_eq!(progress.snapshot().state, TransferState::Failed);
    })
    .await
    .expect("timed out");
}

// ─── (f): a tampered piece is rejected and a spare piece is used ────────────

/// Corrupts the pieces of `slots` on their way from the real source.
struct Tamper<S> {
    inner: S,
    slots: Vec<u16>,
}

#[async_trait]
impl<S: PieceSource> PieceSource for Tamper<S> {
    async fn fetch_piece(
        &self,
        mid: &ContentId,
        segment: u32,
        slot: u16,
        holder: &miasma_core::network::types::ShardLocation,
    ) -> Result<Option<MiasmaShare>, MiasmaError> {
        let mut got = self.inner.fetch_piece(mid, segment, slot, holder).await?;
        if let Some(s) = got.as_mut() {
            if self.slots.contains(&s.slot_index) {
                let last = s.shard_data.len() - 1;
                s.shard_data[last] ^= 0x01;
            }
        }
        Ok(got)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_piece_is_rejected_reported_and_replaced_by_a_spare() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let sender = Sender::new(&relay).await;
        let data = content(300_000);
        let (mid, share) = sender.publish(&data, None).await;

        let (rx, _rx_dir) = receiver(&relay).await;
        let client = Arc::new(rx.client(share.publisher()).unwrap());
        let envelope = client
            .fetch_record(*mid.as_bytes())
            .await
            .unwrap()
            .expect("the sender has the record");
        let fetched =
            open_signed_record(mid.as_bytes(), &envelope, Some(share.publisher())).unwrap();
        assert!(fetched.manifest.is_some());

        let work = tempfile::tempdir().unwrap();
        let out = work.path().join("out.bin");
        let progress = TransferProgress::new(mid.to_string());
        // Slot 0 is corrupted in flight; slots 1 and 2 are good, k = 2.
        let source = Tamper {
            inner: IrohPieceSource::new(client.clone(), Some(progress.clone())),
            slots: vec![0],
        };
        let output = resolve_output_target(&out, fetched.manifest.as_ref()).unwrap();
        let outcome = run_receive(
            &source,
            ReceiveSpec {
                mid: mid.clone(),
                record: fetched.record,
                manifest: fetched.manifest,
                password: None,
                output_path: output,
                journal_dir: work.path().join("transfers"),
                restart: false,
                retry: RetryConfig::default(),
                expect: Some(share),
                record_signer: Some(fetched.signer),
            },
            progress.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            ReceiveOutcome::Complete {
                bytes: data.len() as u64
            }
        );
        let s = progress.snapshot();
        assert!(
            s.pieces_rejected >= 1,
            "the bad piece must be reported: {s:?}"
        );
        assert!(std::fs::read(&out).unwrap() == data);
    })
    .await
    .expect("timed out");
}

// ─── (g): a dial that cannot succeed ends with a clear error ────────────────

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_relay_ends_in_a_clear_error_not_an_endless_wait() {
    timeout(Duration::from_secs(60), async {
        // A relay URL nothing listens on.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let dead = format!("https://127.0.0.1:{closed}");
        let (dir, store) = empty_store();
        let _keep = dir;
        let rx = start_node_offline(&dead, Duration::from_secs(3), store).await;

        // A publisher that exists only as a key.
        let publisher = SigningKey::from_bytes(&rand::random::<[u8; 32]>())
            .verifying_key()
            .to_bytes();
        let mid = ContentId::compute(b"x", &params().to_param_bytes());
        let share = ShareId::new(&mid, publisher, false);
        let work = tempfile::tempdir().unwrap();
        let progress = TransferProgress::new(mid.to_string());
        let started = std::time::Instant::now();
        let err = receive_iroh(
            &rx,
            &share,
            &work.path().join("out.bin"),
            &work.path().join("transfers"),
            None,
            progress.clone(),
        )
        .await
        .unwrap_err();
        let took = started.elapsed();
        let text = err.to_string();
        assert!(text.contains("cannot reach the sender over iroh"), "{text}");
        assert!(text.contains("no connection within 3 s"), "{text}");
        assert!(
            text.contains("not connected to a relay server"),
            "the endpoint's own relay diagnosis must be in the message: {text}"
        );
        assert!(
            took < Duration::from_secs(20),
            "the timeout bounds the wait (took {took:?})"
        );
        let s = progress.snapshot();
        assert_eq!(s.state, TransferState::Failed);
        assert!(s.last_error.unwrap_or_default().contains("iroh"));
        assert!(!work.path().join("out.bin").exists());
    })
    .await
    .expect("timed out");
}

/// A node whose relay cannot be reached (it never comes online).
async fn start_node_offline(
    relay_url: &str,
    connect_timeout: Duration,
    store: Arc<LocalShareStore>,
) -> Arc<IrohNode> {
    let s = settings(relay_url, connect_timeout);
    let seed: [u8; 32] = rand::random();
    let builder = endpoint_builder(Some(&seed), &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify());
    IrohNode::start_from_builder(builder, s, store, None, IrohServerLimits::default())
        .await
        .unwrap()
}

// ─── (h): the daemon's endpoint ID is the publisher key ─────────────────────

async fn start_daemon(transport: TransportConfig) -> (TempDir, tokio::sync::mpsc::Sender<()>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalShareStore::open(dir.path(), 1000).unwrap());
    let key: [u8; 32] = rand::random();
    let node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let server =
        DaemonServer::start_with_transport(node, store, dir.path().to_path_buf(), transport)
            .await
            .unwrap();
    let shutdown = server.shutdown_handle();
    tokio::spawn(server.run());
    (dir, shutdown)
}

async fn transfer_status(dir: &Path, id: &str) -> TransferStatus {
    match daemon_request(dir, ControlRequest::TransferStatus { id: id.into() })
        .await
        .unwrap()
    {
        ControlResponse::TransferStatus(s) => s,
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_daemons_endpoint_id_is_the_publisher_key_of_its_share_ids() {
    timeout(Duration::from_secs(120), async {
        // A relay that does not exist: the endpoint still has its identity.
        let mut t = TransportConfig::default();
        t.iroh_mode = IrohMode::Custom;
        t.iroh_relay_urls = vec!["https://127.0.0.1:9".to_owned()];
        t.iroh_discovery = false;
        let (dir, shutdown) = start_daemon(t).await;

        let node = node_for(dir.path()).expect("the daemon started its iroh endpoint");
        let src = tempfile::tempdir().unwrap();
        let path = write_payload(&src, &content(120_000));
        let id = match daemon_request(
            dir.path(),
            ControlRequest::TransferStartPublish {
                file_path: path.to_string_lossy().into_owned(),
                data_shards: 2,
                total_shards: 3,
                password: None,
                restart: false,
            },
        )
        .await
        .unwrap()
        {
            ControlResponse::TransferStarted { id } => id,
            other => panic!("unexpected: {other:?}"),
        };
        let share_text = loop {
            let s = transfer_status(dir.path(), &id).await;
            assert_ne!(s.state, TransferState::Failed, "{:?}", s.last_error);
            if s.state == TransferState::Complete {
                break s.share_id.expect("a finished send has a share ID");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let share = ShareId::parse(&share_text).unwrap();
        assert_eq!(
            *share.publisher(),
            node.endpoint_id(),
            "the daemon's iroh EndpointId must be the share ID's publisher key"
        );
        // The same key as an EndpointId.
        assert_eq!(
            EndpointId::from_bytes(share.publisher()).unwrap(),
            node.endpoint().id()
        );

        // `miasma status` shows it.
        match daemon_request(dir.path(), ControlRequest::Status)
            .await
            .unwrap()
        {
            ControlResponse::Status(s) => {
                let i = s.iroh.expect("status reports the iroh endpoint");
                assert_eq!(i.endpoint_id, hex::encode(node.endpoint_id()));
                assert_eq!(i.mode, "custom");
            }
            other => panic!("unexpected: {other:?}"),
        }
        let _ = shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_with_iroh_off_runs_no_endpoint_and_says_so() {
    timeout(Duration::from_secs(60), async {
        let mut t = TransportConfig::default();
        t.iroh_mode = IrohMode::Off;
        let (dir, shutdown) = start_daemon(t).await;
        assert!(node_for(dir.path()).is_none());
        match daemon_request(dir.path(), ControlRequest::Status)
            .await
            .unwrap()
        {
            ControlResponse::Status(s) => assert!(s.iroh.is_none()),
            other => panic!("unexpected: {other:?}"),
        }
        let _ = shutdown.send(()).await;
    })
    .await
    .expect("timed out");
}

// ─── the server's limits ────────────────────────────────────────────────────

/// A raw client on the local relay (no Miasma client code), dialing `server`.
async fn raw_connection(
    relay: &Relay,
    server: &IrohNode,
) -> (Endpoint, iroh::endpoint::Connection) {
    let s = settings(&relay.url, Duration::from_secs(10));
    let ep = endpoint_builder(None, &s, false)
        .unwrap()
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .unwrap();
    let addr = EndpointAddr::new(EndpointId::from_bytes(&server.endpoint_id()).unwrap())
        .with_relay_url(relay.url.parse().unwrap());
    let conn = timeout(Duration::from_secs(10), ep.connect(addr, IROH_ALPN))
        .await
        .expect("connect in time")
        .expect("connect");
    (ep, conn)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_frame_length_ends_the_connection_before_anything_is_allocated() {
    timeout(Duration::from_secs(60), async {
        let relay = relay().await;
        let sender = Sender::new(&relay).await;
        let (_ep, conn) = raw_connection(&relay, &sender.iroh).await;

        // Declare 4 GiB - 1 and send nothing more: the server must reject the
        // length itself, not wait for or allocate that much.
        let (mut tx, _rx) = conn.open_bi().await.unwrap();
        tx.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let closed = timeout(Duration::from_secs(10), conn.closed()).await;
        assert!(
            closed.is_ok(),
            "the server must drop a connection that declares an oversized frame"
        );

        // The server is still fine for an honest client.
        let (rx, _d) = receiver(&relay).await;
        let client = rx.client(&sender.publisher()).unwrap();
        let unknown = ContentId::compute(b"never published", &params().to_param_bytes());
        assert!(client
            .fetch_record(*unknown.as_bytes())
            .await
            .unwrap()
            .is_none());
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_request_ends_the_connection_without_an_answer() {
    timeout(Duration::from_secs(60), async {
        let relay = relay().await;
        let sender = Sender::new(&relay).await;
        let (_ep, conn) = raw_connection(&relay, &sender.iroh).await;
        let (mut tx, mut rx) = conn.open_bi().await.unwrap();
        // A well-framed request with the wrong wire version byte and a junk body.
        let junk = [0xEEu8; 16];
        tx.write_all(&(junk.len() as u32).to_be_bytes())
            .await
            .unwrap();
        tx.write_all(&junk).await.unwrap();
        tx.finish().unwrap();
        let mut buf = Vec::new();
        let read = timeout(
            Duration::from_secs(10),
            tokio::io::AsyncReadExt::read_to_end(&mut rx, &mut buf),
        )
        .await
        .expect("the server answers or closes in time");
        assert!(
            read.is_err() || buf.is_empty(),
            "nothing about a malformed request is echoed back ({} bytes)",
            buf.len()
        );
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_request_cap_redials_transparently_and_an_idle_connection_is_dropped() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let limits = IrohServerLimits {
            max_requests_per_connection: 2,
            idle_timeout: Duration::from_secs(2),
            ..IrohServerLimits::default()
        };
        let sender = Sender::with_limits(&relay, limits).await;
        let (rx, _d) = receiver(&relay).await;
        let client = rx.client(&sender.publisher()).unwrap();
        let unknown = ContentId::compute(b"never published", &params().to_param_bytes());

        // Six requests across a cap of two per connection: the client redials by itself.
        for _ in 0..6 {
            assert!(client
                .fetch_record(*unknown.as_bytes())
                .await
                .unwrap()
                .is_none());
        }

        // An idle raw connection is closed by the server.
        let (_ep, conn) = raw_connection(&relay, &sender.iroh).await;
        let closed = timeout(Duration::from_secs(10), conn.closed()).await;
        assert!(
            closed.is_ok(),
            "an idle connection must be dropped after the idle timeout"
        );
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_over_the_cap_are_refused_and_slots_are_reused() {
    timeout(Duration::from_secs(120), async {
        let relay = relay().await;
        let limits = IrohServerLimits {
            max_connections: 1,
            ..IrohServerLimits::default()
        };
        let sender = Sender::with_limits(&relay, limits).await;

        let (_ep1, conn1) = raw_connection(&relay, &sender.iroh).await;
        // The one slot is held (the connection stays open and idle): a second
        // client is refused at the handshake rather than queued.
        let (rx, _d) = receiver(&relay).await;
        let second = rx.client(&sender.publisher()).unwrap();
        let unknown = ContentId::compute(b"never published", &params().to_param_bytes());
        let refused = timeout(
            Duration::from_secs(25),
            second.fetch_record(*unknown.as_bytes()),
        )
        .await
        .expect("a refused client gets an answer, not a hang");
        assert!(refused.is_err(), "over the cap: {refused:?}");

        // Release the slot: the next client is served.
        conn1.close(0u32.into(), b"done");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let (rx2, _d2) = receiver(&relay).await;
        let third = rx2.client(&sender.publisher()).unwrap();
        assert!(third
            .fetch_record(*unknown.as_bytes())
            .await
            .unwrap()
            .is_none());
    })
    .await
    .expect("timed out");
}

// ─── manual: the real n0 preset (public discovery service and relays) ───────

/// Dials a sender by its key through **n0's public discovery service and relays**.
/// This is the only test that talks to a public service; it is ignored by
/// default and is not part of CI.
///
/// Run (from the repository root, on a machine with internet access):
///
/// ```text
/// cargo test -p miasma-core --test iroh_direct_test n0_public_discovery -- --ignored --nocapture
/// ```
///
/// Both endpoints use throw-away keys; the sender's ID, home relay and addresses
/// are published to n0 while it runs (that is what this checks).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: contacts n0's public discovery service and relays"]
async fn n0_public_discovery_dials_a_sender_by_its_key_alone() {
    timeout(Duration::from_secs(120), async {
        let n0 = |timeout: Duration| IrohSettings {
            mode: IrohMode::N0,
            relay_urls: Vec::new(),
            discovery: true,
            connect_timeout: timeout,
            ca_pem: None,
            proxy_from_env: false,
        };
        let (sdir, sstore) = empty_store();
        let (rdir, rstore) = empty_store();
        let _keep = (sdir, rdir);
        let seed: [u8; 32] = rand::random();
        let sender = IrohNode::start(&seed, n0(Duration::from_secs(40)), sstore, None)
            .await
            .unwrap();
        let receiver = IrohNode::start(&rand::random(), n0(Duration::from_secs(40)), rstore, None)
            .await
            .unwrap();
        assert!(
            sender.wait_online(Duration::from_secs(30)).await,
            "sender reaches n0's relay"
        );
        eprintln!("sender status: {:?}", sender.status());

        let client = receiver.client(&sender.endpoint_id()).unwrap();
        let unknown = ContentId::compute(b"never published", &params().to_param_bytes());
        let started = std::time::Instant::now();
        let got = client.fetch_record(*unknown.as_bytes()).await;
        eprintln!(
            "dial + first request by key only: {:?} in {:.2}s; path={:?}",
            got.as_ref().map(|v| v.is_some()),
            started.elapsed().as_secs_f64(),
            client.path_kind()
        );
        assert!(
            got.unwrap().is_none(),
            "connected, protocol answered 'no record'"
        );
        sender.shutdown().await;
        receiver.shutdown().await;
    })
    .await
    .expect("timed out");
}

// ─── Relay TLS trust: OS store plus --ca-cert ───────────────────────────────

/// A relay whose certificate is issued by a throw-away CA (not self-signed), and
/// that CA's PEM: what `--ca-cert` would carry for a TLS-inspecting proxy.
async fn relay_with_own_ca() -> (Relay, Vec<u8>) {
    use iroh_relay::server::{CertConfig, TlsConfig};
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "miasma test relay ca");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
        leaf_key.serialize_der(),
    ));
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.der().clone()], key)
    .unwrap();
    let mut cfg = iroh_relay::server::testing::server_config();
    cfg.quic = None;
    cfg.relay.as_mut().unwrap().tls = Some(TlsConfig::new(
        (std::net::Ipv4Addr::LOCALHOST, 0),
        CertConfig::Manual { server_config },
    ));
    let server = iroh_relay::server::Server::spawn(cfg).await.unwrap();
    let url = format!("https://{}", server.https_addr().unwrap());
    (
        Relay {
            _server: server,
            url,
        },
        ca.pem().into_bytes(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_certificate_from_a_private_ca_is_trusted_only_with_ca_cert() {
    timeout(Duration::from_secs(90), async {
        let (relay, ca_pem) = relay_with_own_ca().await;

        // With the CA given (as `--ca-cert` does): the default verifier, no test override.
        let mut s = settings(&relay.url, Duration::from_secs(15));
        s.ca_pem = Some(ca_pem);
        let (sdir, sstore) = empty_store();
        let (rdir, rstore) = empty_store();
        let _keep = (sdir, rdir);
        let seed: [u8; 32] = rand::random();
        let sender = IrohNode::start(&seed, s.clone(), sstore, None)
            .await
            .unwrap();
        let receiver = IrohNode::start(&rand::random(), s, rstore, None)
            .await
            .unwrap();
        assert!(sender.wait_online(Duration::from_secs(20)).await);
        assert!(receiver.wait_online(Duration::from_secs(20)).await);
        let client = receiver.client(&sender.endpoint_id()).unwrap();
        let unknown = ContentId::compute(b"nothing", &params().to_param_bytes());
        assert!(client
            .fetch_record(*unknown.as_bytes())
            .await
            .unwrap()
            .is_none());
        sender.shutdown().await;
        receiver.shutdown().await;

        // Without it: the certificate is not trusted and the endpoint says so.
        let (dir, store) = empty_store();
        let _keep = dir;
        let s = settings(&relay.url, Duration::from_secs(5));
        let node = IrohNode::start(&rand::random(), s, store, None)
            .await
            .unwrap();
        assert!(!node.wait_online(Duration::from_secs(6)).await);
        assert!(!node.status().relay_connected);
        // A dial through it fails, and the message names the likely TLS cause.
        let peer = iroh::SecretKey::from_bytes(&rand::random()).public();
        let client = node.client(&peer).unwrap();
        let e = client
            .fetch_record([7u8; 32])
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("relay TLS certificate not trusted"), "{e}");
        assert!(e.contains("--ca-cert"), "{e}");
        node.shutdown().await;
    })
    .await
    .expect("timed out");
}

/// Manual, like the n0 discovery test above: the same scenario,
/// but with every IP transport removed on both ends, so the relay carries the
/// connection (and the relay's TLS certificate is verified by the OS store).
///
/// ```text
/// cargo test -p miasma-core --test iroh_direct_test n0_public_relay_only -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: contacts n0's public discovery service and relays"]
async fn n0_public_relay_only_connects_through_the_relay_with_the_os_trust_store() {
    timeout(Duration::from_secs(120), async {
        let n0 = IrohSettings {
            mode: IrohMode::N0,
            relay_urls: Vec::new(),
            discovery: true,
            connect_timeout: Duration::from_secs(40),
            ca_pem: None,
            proxy_from_env: false,
        };
        let limits = IrohServerLimits::default;
        let (sdir, sstore) = empty_store();
        let (rdir, rstore) = empty_store();
        let _keep = (sdir, rdir);
        let seed: [u8; 32] = rand::random();
        let sb = endpoint_builder(Some(&seed), &n0, true)
            .unwrap()
            .clear_ip_transports();
        let sender = IrohNode::start_from_builder(sb, n0.clone(), sstore, None, limits())
            .await
            .unwrap();
        let rseed: [u8; 32] = rand::random();
        let rb = endpoint_builder(Some(&rseed), &n0, true)
            .unwrap()
            .clear_ip_transports();
        let receiver = IrohNode::start_from_builder(rb, n0, rstore, None, limits())
            .await
            .unwrap();
        assert!(sender.wait_online(Duration::from_secs(30)).await);
        assert!(receiver.wait_online(Duration::from_secs(30)).await);
        eprintln!("sender status: {:?}", sender.status());
        let client = receiver.client(&sender.endpoint_id()).unwrap();
        let unknown = ContentId::compute(b"never published", &params().to_param_bytes());
        let got = client.fetch_record(*unknown.as_bytes()).await;
        eprintln!(
            "relay-only dial: {:?}; path={:?}",
            got.as_ref().map(|v| v.is_some()),
            client.path_kind()
        );
        assert!(got.unwrap().is_none());
        assert_eq!(client.path_kind(), Some("relay"));
        sender.shutdown().await;
        receiver.shutdown().await;
    })
    .await
    .expect("timed out");
}
