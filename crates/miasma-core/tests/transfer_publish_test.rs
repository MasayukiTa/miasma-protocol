//! Phase 2 of docs/tasks/protected-resumable-transfer-plan.md: what a file
//! publish now puts on the DHT, checked through a second real node.
//!
//! Two libp2p nodes on loopback. A publishes a file; B reads the record back
//! over the DHT and must see the transfer manifest, and the manifest must
//! describe exactly what A actually stored.

use std::{sync::Arc, time::Duration};

use miasma_core::{
    dissolution::{segment::retrieve_segment_with, SegmentMeta},
    transfer::{
        publish::{PublishOutcome, PublishSpec},
        PieceSource, Protection, ReceiveOutcome, TransferProgress, TransferState,
    },
    DissolutionParams, LocalShareStore, MiasmaCoordinator, MiasmaError, MiasmaNode, Multiaddr,
    NodeType, PublishOptions,
};
use tokio::time::timeout;

/// `max_segment_size_for(2)` in `network/coordinator.rs`:
/// `(SHARE_MSG_MAX - SHARE_WIRE_OVERHEAD_BYTES) * k` = `(8 MiB - 4096) * 2`.
/// A file one 64 KiB block longer than this dissolves into exactly two segments
/// at `k = 2` without needing a 64 MiB fixture.
const MAX_SEGMENT_K2: usize = (8 * 1024 * 1024 - 4096) * 2;
const TWO_SEGMENT_LEN: usize = MAX_SEGMENT_K2 + 64 * 1024;
/// Two segments where the second is big enough (4 MiB) that a cancel requested when
/// the first finishes is always seen before the second does: with a 64 KiB second
/// segment the whole run can finish inside one polling interval.
const SEND_TEST_LEN: usize = MAX_SEGMENT_K2 + 4 * 1024 * 1024;

fn params() -> DissolutionParams {
    DissolutionParams {
        data_shards: 2,
        total_shards: 3,
    }
}

/// Deterministic, non-repeating-looking content so a segment mix-up is visible.
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

async fn spawn_node(key_byte: u8) -> (MiasmaCoordinator, Arc<LocalShareStore>) {
    let dir = tempfile::tempdir().unwrap().keep();
    let store = Arc::new(LocalShareStore::open(&dir, 1000).unwrap());
    let key = [key_byte; 32];
    let mut node = MiasmaNode::new(&key, NodeType::Full, "/ip4/127.0.0.1/tcp/0").unwrap();
    let addrs = node.collect_listen_addrs(400).await;
    let coord = MiasmaCoordinator::start(node, store.clone(), vec![addrs[0].to_string()]).await;
    (coord, store)
}

/// B bootstrapped to A and connected; A is the publisher.
async fn connected_pair(
    a_key: u8,
    b_key: u8,
) -> (MiasmaCoordinator, Arc<LocalShareStore>, MiasmaCoordinator) {
    let (a, store_a) = spawn_node(a_key).await;
    let (b, _store_b) = spawn_node(b_key).await;
    let addr_a: Multiaddr = a.listen_addrs()[0].parse().unwrap();
    b.add_bootstrap_peer(*a.peer_id(), addr_a).await.unwrap();
    b.bootstrap_dht().await.unwrap();
    b.wait_until_peer_connected(*a.peer_id(), Duration::from_secs(10))
        .await
        .unwrap();
    (a, store_a, b)
}

fn write_temp(bytes: &[u8]) -> std::path::PathBuf {
    let path = tempfile::tempdir().unwrap().keep().join("payload.bin");
    std::fs::write(&path, bytes).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn a_published_file_carries_a_manifest_that_matches_what_was_stored() {
    timeout(Duration::from_secs(120), async {
        let (a, store_a, b) = connected_pair(0xA7, 0xB7).await;
        let data = content(TWO_SEGMENT_LEN);
        let path = write_temp(&data);

        let report = a
            .dissolve_and_publish_file_with_options(&path, params(), PublishOptions::default())
            .await
            .unwrap();

        // B reads it back over the DHT, not from A's memory.
        let (record, manifest) = b
            .dht_handle()
            .get_record_with_manifest(*report.mid.as_bytes())
            .await
            .unwrap()
            .expect("record must be readable from the second node");
        let manifest = manifest.expect("a file publish must carry a manifest");

        assert_eq!(manifest.mid, record.mid_digest);
        assert_eq!(manifest.data_shards, 2);
        assert_eq!(manifest.total_shards, 3);
        assert_eq!(manifest.total_bytes, TWO_SEGMENT_LEN as u64);
        assert_eq!(manifest.segments.len(), 2, "two segments expected");
        assert_eq!(manifest.protection, Protection::None);
        manifest.validate().unwrap();

        // Every listed piece ID must be the shard hash of a share A actually holds.
        let mut checked = 0;
        for addr in store_a.list() {
            let share = store_a.get(&addr).unwrap();
            let expected = manifest
                .expected_piece(share.segment_index, share.slot_index)
                .expect("every stored share must be listed in the manifest");
            assert_eq!(
                *expected, share.shard_hash,
                "piece ID for segment {} slot {} does not match the stored shard",
                share.segment_index, share.slot_index
            );
            checked += 1;
        }
        assert_eq!(checked, 2 * 3, "2 segments x 3 shards");

        // The old read path is undisturbed by the trailer.
        let legacy = b
            .dht_handle()
            .get_record(*report.mid.as_bytes())
            .await
            .unwrap()
            .expect("a pre-manifest reader must still decode the record");
        assert_eq!(legacy.mid_digest, record.mid_digest);
        assert_eq!(legacy.locations.len(), record.locations.len());
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_protected_publish_needs_the_password_and_the_manifest_carries_no_secret() {
    timeout(Duration::from_secs(120), async {
        let (a, store_a, b) = connected_pair(0xA8, 0xB8).await;
        let data = content(TWO_SEGMENT_LEN);
        let path = write_temp(&data);
        let password = "correct-horse-battery-staple";

        let report = a
            .dissolve_and_publish_file_protected(
                &path,
                params(),
                PublishOptions::default(),
                password,
            )
            .await
            .unwrap();

        let (_record, manifest) = b
            .dht_handle()
            .get_record_with_manifest(*report.mid.as_bytes())
            .await
            .unwrap()
            .expect("record must be readable");
        let manifest = manifest.expect("manifest");
        let prot = match &manifest.protection {
            Protection::Password(p) => p.clone(),
            Protection::None => panic!("a protected publish must say so in the manifest"),
        };

        // The password appears nowhere in what went to the DHT.
        let encoded = manifest.to_bytes().unwrap();
        assert!(!encoded
            .windows(password.len())
            .any(|w| w == password.as_bytes()));

        // Wrong password is caught from the manifest alone, before any data.
        assert!(matches!(
            prot.unlock("not-the-password"),
            Err(MiasmaError::WrongPassword)
        ));

        // The ordinary network read (no password) cannot decrypt it.
        let plain_read = b.retrieve_from_network(&report.mid, params()).await;
        assert!(
            plain_read.is_err(),
            "content published with a password must not be readable without it"
        );

        // With the password, the shares A holds reassemble the exact file.
        let key = prot.unlock(password).unwrap();
        let mut shares_by_segment: Vec<Vec<_>> = vec![Vec::new(); manifest.segments.len()];
        for addr in store_a.list() {
            let s = store_a.get(&addr).unwrap();
            shares_by_segment[s.segment_index as usize].push(s);
        }
        let mid = miasma_core::ContentId::from_str(&report.mid.to_string()).unwrap();
        let mut rebuilt = Vec::new();
        for (i, seg) in manifest.segments.iter().enumerate() {
            let meta = SegmentMeta {
                index: seg.index,
                offset_bytes: 0,
                plaintext_len: seg.plaintext_len,
                share_count: 3,
            };
            let bytes =
                retrieve_segment_with(&mid, &shares_by_segment[i], &meta, params(), Some(&key))
                    .unwrap();
            assert_eq!(
                *blake3::hash(&bytes).as_bytes(),
                seg.plain_hash,
                "segment {i} must match its manifest hash"
            );
            rebuilt.extend_from_slice(&bytes);
        }
        assert_eq!(rebuilt, data, "reassembled file must be byte-identical");
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_password_is_refused_rather_than_protecting_nothing() {
    timeout(Duration::from_secs(60), async {
        let (a, _store, _b) = connected_pair(0xA9, 0xB9).await;
        let path = write_temp(&content(1024));
        let err = a
            .dissolve_and_publish_file_protected(&path, params(), PublishOptions::default(), "")
            .await
            .unwrap_err();
        assert!(
            matches!(err, MiasmaError::InvalidManifest(_)),
            "got {err:?}"
        );
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unprotected_publish_still_round_trips_through_the_existing_read_path() {
    timeout(Duration::from_secs(120), async {
        let (a, _store, b) = connected_pair(0xAA, 0xBA).await;
        let data = content(200_000);
        let path = write_temp(&data);
        let report = a
            .dissolve_and_publish_file_with_options(&path, params(), PublishOptions::default())
            .await
            .unwrap();
        let got = b
            .retrieve_from_network(&report.mid, params())
            .await
            .unwrap();
        assert_eq!(got, data);
    })
    .await
    .expect("timed out");
}

// ─── Receiving over the real network ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_protected_transfer_is_received_over_the_network_and_resumes_after_a_cancel() {
    timeout(Duration::from_secs(400), async {
        let (a, _store_a, b) = connected_pair(0xC1, 0xD1).await;
        let data = content(TWO_SEGMENT_LEN);
        let path = write_temp(&data);
        let password = "over-the-wire";

        let report = a
            .dissolve_and_publish_file_protected(
                &path,
                params(),
                PublishOptions::default(),
                password,
            )
            .await
            .unwrap();
        let mid = report.mid.clone();

        let dir = tempfile::tempdir().unwrap().keep();
        let out = dir.join("received").join("payload.bin");
        let journals = dir.join("transfers");

        // A wrong password is refused before any piece crosses the network.
        let wrong = b
            .receive_file(
                &mid,
                &out,
                Some(zeroize::Zeroizing::new("nope".to_owned())),
                &journals,
                false,
                TransferProgress::new(mid.to_string()),
            )
            .await;
        assert!(
            matches!(wrong, Err(MiasmaError::WrongPassword)),
            "{wrong:?}"
        );
        assert!(!out.exists());

        // First attempt: cancel as soon as segment 0 is safely on disk.
        let progress = TransferProgress::new(mid.to_string());
        progress.stop_after_segments(1);
        let first = b
            .receive_file(
                &mid,
                &out,
                Some(zeroize::Zeroizing::new(password.to_owned())),
                &journals,
                false,
                progress.clone(),
            )
            .await
            .unwrap();
        assert_eq!(first, ReceiveOutcome::Cancelled { next_segment: 1 });
        assert_eq!(progress.snapshot().state, TransferState::Cancelled);
        assert!(!out.exists(), "no output name until the file is whole");

        // Second attempt resumes from segment 1 and finishes.
        let progress = TransferProgress::new(mid.to_string());
        let second = b
            .receive_file(
                &mid,
                &out,
                Some(zeroize::Zeroizing::new(password.to_owned())),
                &journals,
                false,
                progress.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            second,
            ReceiveOutcome::Complete {
                bytes: TWO_SEGMENT_LEN as u64
            }
        );
        let s = progress.snapshot();
        assert_eq!(
            s.resumed_from_segment, 1,
            "segment 0 must not be fetched again"
        );
        assert_eq!(s.segments_done, 2);
        assert_eq!(
            std::fs::read(&out).unwrap(),
            data,
            "byte-identical after resume"
        );
        println!(
            "resumed transfer: fetch {} ms, decode {} ms, write {} ms, {:.1} MB/s this session",
            s.fetch_ms,
            s.decode_ms,
            s.write_ms,
            s.rate_bps / 1e6
        );
    })
    .await
    .expect("timed out");
}

// ─── Measurement (not a correctness test) ───────────────────────────────────

/// Times single operations on the real transport so the per-fetch fixed cost can
/// be told apart from per-byte cost. Run with:
/// `cargo test -p miasma-core --test transfer_publish_test -- --ignored --nocapture measure_`
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn measure_single_piece_fetch_latency_on_loopback() {
    use std::time::Instant;

    let (a, _store_a, b) = connected_pair(0xE1, 0xF1).await;
    let data = content(TWO_SEGMENT_LEN);
    let path = write_temp(&data);
    let report = a
        .dissolve_and_publish_file_with_options(&path, params(), PublishOptions::default())
        .await
        .unwrap();
    let mid = report.mid.clone();

    let t = Instant::now();
    let (record, _manifest) = b
        .dht_handle()
        .get_record_with_manifest(*mid.as_bytes())
        .await
        .unwrap()
        .unwrap();
    println!("[measure] record lookup (first, from B): {:?}", t.elapsed());

    let source = b.piece_source();
    let probe = |seg: u32, slot: u16| {
        let loc = record
            .locations
            .iter()
            .find(|l| l.segment_index == seg && l.shard_index == slot)
            .unwrap()
            .clone();
        (seg, slot, loc)
    };
    // Segment 1 is tiny (64 KiB -> 32 KiB shards); segment 0 is ~16 MB (8 MiB shards).
    for (seg, slot) in [(1u32, 0u16), (1, 1), (1, 0), (0, 0), (0, 1), (0, 0)] {
        let (seg, slot, loc) = probe(seg, slot);
        let t = Instant::now();
        let got = source.fetch_piece(&mid, seg, slot, &loc).await.unwrap();
        let bytes = got.as_ref().map_or(0, |s| s.shard_data.len());
        let dt = t.elapsed();
        let mbps = if dt.as_secs_f64() > 0.0 {
            bytes as f64 / dt.as_secs_f64() / 1e6
        } else {
            0.0
        };
        println!(
            "[measure] fetch seg {seg} slot {slot}: {:>8.1} ms, {bytes:>9} bytes, {mbps:>7.2} MB/s, got={}",
            dt.as_secs_f64() * 1e3,
            got.is_some()
        );
    }
}

// ─── Not pushing to a peer that has said "no room" ──────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_with_no_hosted_quota_is_refused_once_not_once_per_share() {
    timeout(Duration::from_secs(180), async {
        // B is connected to A and has the default hosted quota of zero, so it
        // refuses every pushed share. 2 segments x 3 shares = 6 shares in all.
        let (a, _store_a, b) = connected_pair(0x71, 0x72).await;
        // Give A time to see B as an admitted, connected peer: pushes only go to those.
        b.wait_until_peer_connected(*a.peer_id(), Duration::from_secs(10))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;

        let data = content(TWO_SEGMENT_LEN);
        let path = write_temp(&data);
        let report = a
            .dissolve_and_publish_file_with_options(&path, params(), PublishOptions::default())
            .await
            .unwrap();

        let (attempted, refused) = a.push_counts();
        println!("pushes attempted {attempted}, refused {refused}");
        assert!(
            refused <= 1,
            "a peer that refused for lack of quota must not be offered every share again              (attempted {attempted}, refused {refused})"
        );
        assert!(
            attempted <= 2,
            "at most the refused push plus one raced in flight (attempted {attempted})"
        );

        // The publish itself is unaffected: the publisher keeps every share.
        let (_rec, manifest) = b
            .dht_handle()
            .get_record_with_manifest(*report.mid.as_bytes())
            .await
            .unwrap()
            .unwrap();
        assert!(manifest.is_some());
    })
    .await
    .expect("timed out");
}

// ─── Publishing with progress, cancel and resume ────────────────────────────

fn send_spec(
    path: &std::path::Path,
    password: Option<&str>,
    journal_dir: &std::path::Path,
) -> PublishSpec {
    PublishSpec {
        file_path: path.to_path_buf(),
        params: params(),
        options: PublishOptions::default(),
        password: password.map(|p| zeroize::Zeroizing::new(p.to_owned())),
        journal_dir: Some(journal_dir.to_path_buf()),
        restart: false,
    }
}

fn no_send_journal_left(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .all(|e| !e.file_name().to_string_lossy().starts_with("send-"))
        })
        .unwrap_or(true)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_publish_resumes_and_the_result_is_a_working_transfer() {
    timeout(Duration::from_secs(600), async {
        let (a, store_a, b) = connected_pair(0x81, 0x82).await;
        let data = content(SEND_TEST_LEN);
        let path = write_temp(&data);
        let journals = tempfile::tempdir().unwrap().keep();
        let password = "send-side-secret";

        // First run: stop as soon as segment 0 is on disk.
        let p1 = TransferProgress::for_send(path.to_string_lossy());
        p1.stop_after_segments(1);
        let first = a
            .publish_file_job(
                send_spec(&path, Some(password), &journals),
                Some(p1.clone()),
            )
            .await
            .unwrap();
        assert!(
            matches!(first, PublishOutcome::Cancelled { next_segment: 1 }),
            "expected Cancelled at segment 1, got {first:?}"
        );
        let s1 = p1.snapshot();
        assert_eq!(s1.state, TransferState::Cancelled);
        assert!(s1.resumable, "a cancelled publish keeps its journal");
        assert!(
            !s1.mid.is_empty(),
            "the MID is known once the file is hashed"
        );
        let stored_before: std::collections::HashSet<String> = store_a.list().into_iter().collect();
        assert_eq!(stored_before.len(), 3, "segment 0 = 3 shares");

        // A wrong password on resume fails before any work is redone.
        let wrong = a
            .publish_file_job(send_spec(&path, Some("nope"), &journals), None)
            .await;
        assert!(
            matches!(wrong, Err(MiasmaError::WrongPassword)),
            "{wrong:?}"
        );

        // Second run, right password: finishes, without redoing segment 0.
        let p2 = TransferProgress::for_send(path.to_string_lossy());
        let second = a
            .publish_file_job(
                send_spec(&path, Some(password), &journals),
                Some(p2.clone()),
            )
            .await
            .unwrap();
        let report = match second {
            PublishOutcome::Complete(r) => r,
            _ => panic!("the resumed publish must complete"),
        };
        let s2 = p2.snapshot();
        assert_eq!(s2.state, TransferState::Complete);
        assert_eq!(s2.resumed_from_segment, 1, "segment 0 must not be redone");
        assert_eq!(s2.segments_done, 2);
        assert_eq!(s2.bytes_done, SEND_TEST_LEN as u64);
        // Segment 0's shares are exactly the ones the first run stored.
        let stored_after: std::collections::HashSet<String> = store_a.list().into_iter().collect();
        assert!(stored_before.is_subset(&stored_after));
        assert_eq!(stored_after.len(), 6);
        assert!(
            no_send_journal_left(&journals),
            "a finished publish removes its journal"
        );

        // The record and manifest are complete and consistent...
        let (_rec, manifest) = b
            .dht_handle()
            .get_record_with_manifest(*report.mid.as_bytes())
            .await
            .unwrap()
            .unwrap();
        let manifest = manifest.unwrap();
        manifest.validate().unwrap();
        assert_eq!(manifest.segments.len(), 2);
        assert_eq!(
            manifest.segments[0].plain_hash,
            *blake3::hash(&data[..MAX_SEGMENT_K2]).as_bytes()
        );

        // ...and the other node can actually receive the file, byte for byte.
        let dir = tempfile::tempdir().unwrap().keep();
        let out = dir.join("payload.bin");
        let outcome = b
            .receive_file(
                &report.mid,
                &out,
                Some(zeroize::Zeroizing::new(password.to_owned())),
                &dir.join("transfers"),
                false,
                TransferProgress::new(report.mid.to_string()),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, ReceiveOutcome::Complete { .. }));
        assert_eq!(std::fs::read(&out).unwrap(), data);
    })
    .await
    .expect("timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publish_is_not_resumed_if_the_source_changed_or_a_share_went_missing() {
    timeout(Duration::from_secs(600), async {
        let (a, store_a, _b) = connected_pair(0x91, 0x92).await;
        let data = content(SEND_TEST_LEN);
        let path = write_temp(&data);

        // ── The source file changes between runs. ───────────────────────────
        let journals = tempfile::tempdir().unwrap().keep();
        let p1 = TransferProgress::for_send(path.to_string_lossy());
        p1.stop_after_segments(1);
        let first = a
            .publish_file_job(send_spec(&path, None, &journals), Some(p1.clone()))
            .await
            .unwrap();
        assert!(
            matches!(first, PublishOutcome::Cancelled { next_segment: 1 }),
            "the first run must stop after segment 0, got {first:?}"
        );
        let first_mid = p1.snapshot().mid;
        assert!(
            !no_send_journal_left(&journals),
            "the stopped publish must have left a journal to (not) resume from"
        );

        // Same length, different bytes (and a new modification time).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut changed = data.clone();
        changed[10] ^= 0xFF;
        std::fs::write(&path, &changed).unwrap();

        let p2 = TransferProgress::for_send(path.to_string_lossy());
        let outcome = a
            .publish_file_job(send_spec(&path, None, &journals), Some(p2.clone()))
            .await
            .unwrap();
        assert!(matches!(outcome, PublishOutcome::Complete(_)));
        let s2 = p2.snapshot();
        assert_eq!(
            s2.resumed_from_segment, 0,
            "a changed source must start over"
        );
        assert_ne!(s2.mid, first_mid, "the MID follows the new content");

        // ── A share of a finished segment is gone from the local store. ─────
        let path2 = write_temp(&content(SEND_TEST_LEN + 4096));
        let journals2 = tempfile::tempdir().unwrap().keep();
        let p3 = TransferProgress::for_send(path2.to_string_lossy());
        p3.stop_after_segments(1);
        let third = a
            .publish_file_job(send_spec(&path2, None, &journals2), Some(p3.clone()))
            .await
            .unwrap();
        assert!(
            matches!(third, PublishOutcome::Cancelled { next_segment: 1 }),
            "got {third:?}"
        );
        let mid3 = miasma_core::ContentId::from_str(&p3.snapshot().mid).unwrap();
        let victim = store_a
            .find_piece(&mid3.prefix(), 0, 1)
            .expect("segment 0 slot 1 was stored");
        store_a.delete(&victim).unwrap();

        let p4 = TransferProgress::for_send(path2.to_string_lossy());
        let outcome = a
            .publish_file_job(send_spec(&path2, None, &journals2), Some(p4.clone()))
            .await
            .unwrap();
        assert!(matches!(outcome, PublishOutcome::Complete(_)));
        assert_eq!(
            p4.snapshot().resumed_from_segment,
            0,
            "a segment with a missing share must be redone, not trusted"
        );
    })
    .await
    .expect("timed out");
}
