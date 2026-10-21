//! A running node bounds the retention window a private share arrives with.
//!
//! The window (`expires_at`, `retention_secs`) is chosen by the sender. A node
//! caps it to what it is willing to keep (`MAX_RETENTION_SECS`) and refuses one
//! that ends before it starts. An envelope whose window is already in the past
//! is still taken in: the frozen v1 fixtures have one.
//!
//! All key material is generated at run time.

use std::sync::Arc;
use std::time::Duration;

use miasma_core::directed::{
    DirectedEnvelope, DirectedRequest, DirectedResponse, EnvelopeState, MAX_RETENTION_SECS,
};
use miasma_core::network::types::TopologyEvent;
use miasma_core::{LocalShareStore, MiasmaCoordinator, MiasmaNode, NodeType};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn envelope(recipient_pubkey: [u8; 32], created_at: u64, expires_at: u64) -> DirectedEnvelope {
    DirectedEnvelope {
        envelope_id: rand::random(),
        version: 1,
        sender_pubkey: rand::random(),
        recipient_pubkey,
        ephemeral_pubkey: rand::random(),
        encrypted_payload: vec![7u8; 64],
        payload_nonce: rand::random(),
        password_salt: rand::random(),
        expires_at,
        created_at,
        state: EnvelopeState::Pending,
        challenge_hash: None,
        password_attempts_remaining: 3,
        challenge_attempts_remaining: 3,
        challenge_expires_at: 0,
        retention_secs: expires_at.saturating_sub(created_at),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_caps_an_unbounded_retention_and_refuses_a_nonsensical_one() {
    let outcome = tokio::time::timeout(Duration::from_secs(90), async {
        let recipient_pub: [u8; 32] = rand::random();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let data_b = tempfile::tempdir().unwrap();

        let mut node_b = MiasmaNode::new(
            &rand::random::<[u8; 32]>(),
            NodeType::Full,
            "/ip4/127.0.0.1/tcp/0",
        )
        .unwrap();
        node_b.set_directed_data_dir(data_b.path().to_path_buf());
        node_b.set_directed_recipient_pubkey(recipient_pub);
        let (topology_tx, mut topology_rx) = tokio::sync::mpsc::channel(8);
        node_b.set_topology_notifier(topology_tx);
        let peer_b = node_b.local_peer_id;
        let addrs_b: Vec<String> = node_b
            .collect_listen_addrs(400)
            .await
            .iter()
            .map(|a| a.to_string())
            .collect();
        assert!(!addrs_b.is_empty(), "receiver has no listen address");

        let mut node_a = MiasmaNode::new(
            &rand::random::<[u8; 32]>(),
            NodeType::Full,
            "/ip4/127.0.0.1/tcp/0",
        )
        .unwrap();
        let addrs_a: Vec<String> = node_a
            .collect_listen_addrs(400)
            .await
            .iter()
            .map(|a| a.to_string())
            .collect();

        let store_a = Arc::new(LocalShareStore::open(dir_a.path(), 100).unwrap());
        let store_b = Arc::new(LocalShareStore::open(dir_b.path(), 100).unwrap());
        let coord_a = MiasmaCoordinator::start(node_a, store_a, addrs_a).await;
        let _coord_b = MiasmaCoordinator::start(node_b, store_b, vec![]).await;

        let addr_b: libp2p::Multiaddr = addrs_b[0].parse().unwrap();
        coord_a.add_bootstrap_peer(peer_b, addr_b).await.unwrap();
        coord_a.bootstrap_dht().await.unwrap();
        coord_a
            .wait_until_peer_connected(peer_b, Duration::from_secs(10))
            .await
            .expect("the sender never connected to the receiver");

        let send = |env: DirectedEnvelope| {
            let coord_a = &coord_a;
            let addrs_b = addrs_b.clone();
            async move {
                coord_a
                    .send_directed_request(
                        peer_b,
                        addrs_b,
                        DirectedRequest::Invite { envelope: env },
                    )
                    .await
                    .expect("the request should get a response")
            }
        };

        let now = now_secs();

        // 1. An unlimited window and a near-maximum one are taken in and capped.
        let mut want_ids = Vec::new();
        for expires_at in [u64::MAX, u64::MAX - 1, now + MAX_RETENTION_SECS + 1] {
            let env = envelope(recipient_pub, now, expires_at);
            want_ids.push(env.envelope_id);
            let resp = send(env).await;
            assert!(
                matches!(resp, DirectedResponse::InviteAccepted { .. }),
                "expires_at {expires_at}: expected the invite to be accepted, got {resp:?}"
            );
        }

        // 2. A window that ends before it starts is refused with a clear error.
        for (created_at, expires_at) in [(now, now), (now, now - 1), (u64::MAX, u64::MAX)] {
            let env = envelope(recipient_pub, created_at, expires_at);
            let resp = send(env).await;
            match resp {
                DirectedResponse::Error(m) => assert!(
                    m.contains("retention window"),
                    "the error should name the retention window, got {m:?}"
                ),
                other => panic!("({created_at}, {expires_at}): expected an error, got {other:?}"),
            }
        }

        // 3. A window already in the past is kept as is (the frozen fixtures have one).
        let past = envelope(recipient_pub, 1_700_000_000, 1_700_086_400);
        want_ids.push(past.envelope_id);
        let resp = send(past).await;
        assert!(
            matches!(resp, DirectedResponse::InviteAccepted { .. }),
            "an expired but well-formed invite is still accepted, got {resp:?}"
        );

        // What was handed on to the daemon is bounded; the refused ones were not handed on.
        let latest_allowed = now_secs() + MAX_RETENTION_SECS;
        let mut seen = 0;
        while let Ok(ev) = topology_rx.try_recv() {
            if let TopologyEvent::DirectedEnvelopeReceived { envelope, .. } = ev {
                assert!(want_ids.contains(&envelope.envelope_id));
                assert!(
                    envelope.expires_at <= latest_allowed,
                    "expires_at {} is past the cap {latest_allowed}",
                    envelope.expires_at
                );
                assert!(envelope.retention_secs <= MAX_RETENTION_SECS);
                if envelope.created_at == 1_700_000_000 {
                    assert_eq!(envelope.expires_at, 1_700_086_400);
                    assert_eq!(envelope.retention_secs, 86_400);
                }
                seen += 1;
            }
        }
        assert_eq!(seen, want_ids.len(), "every accepted invite is handed on");
    })
    .await;
    outcome.expect("the node test timed out");
}
