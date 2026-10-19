//! Chaos tests for adaptive payload-transport selection.
//!
//! Scripted transports go up and down while requests keep flowing. The tests
//! check that the selector falls back, demotes a failing primary, recovers it
//! through the periodic probe, and that a required-anonymity request never
//! reaches a transport the policy forbids, even when every permitted one fails.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use miasma_core::{
    AnonymityPolicy, MiasmaShare, PayloadTransport, PayloadTransportError, PayloadTransportKind,
    PayloadTransportSelector, PolicyFetchError, TransportPhase, TransportPrivacyClass,
};

/// A transport whose availability the test flips at will.
#[derive(Clone)]
struct Scripted {
    kind: PayloadTransportKind,
    up: Arc<AtomicBool>,
    calls: Arc<AtomicU64>,
}

impl Scripted {
    fn new(kind: PayloadTransportKind, up: bool) -> Self {
        Self {
            kind,
            up: Arc::new(AtomicBool::new(up)),
            calls: Arc::new(AtomicU64::new(0)),
        }
    }
    fn set(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
    }
    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl PayloadTransport for Scripted {
    fn kind(&self) -> PayloadTransportKind {
        self.kind
    }

    async fn fetch_share(
        &self,
        _peer_addr: &str,
        _mid_digest: [u8; 32],
        slot_index: u16,
        segment_index: u32,
    ) -> Result<Option<MiasmaShare>, PayloadTransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.up.load(Ordering::SeqCst) {
            return Err(PayloadTransportError {
                phase: TransportPhase::Session,
                message: format!("{} is down", self.kind),
            });
        }
        Ok(Some(MiasmaShare {
            version: 1,
            mid_prefix: [0; 8],
            segment_index,
            slot_index,
            shard_data: vec![0xAA; 16],
            key_share: vec![0xBB; 32],
            shard_hash: [0; 32],
            nonce: [0; 12],
            original_len: 16,
            timestamp: 0,
        }))
    }
}

fn selector(transports: &[&Scripted]) -> PayloadTransportSelector {
    PayloadTransportSelector::new(
        transports
            .iter()
            .map(|t| Box::new((*t).clone()) as Box<dyn PayloadTransport>)
            .collect(),
    )
}

async fn fetch(
    sel: &PayloadTransportSelector,
    n: u16,
) -> Result<miasma_core::TransportedShare, miasma_core::TransportExhaustedError> {
    sel.fetch_share("peer", [0u8; 32], n, 0).await
}

#[tokio::test]
async fn failure_fallback_recovery_across_three_transports() {
    let a = Scripted::new(PayloadTransportKind::DirectLibp2p, true);
    let b = Scripted::new(PayloadTransportKind::WssTunnel, true);
    let c = Scripted::new(PayloadTransportKind::TcpDirect, true);
    let sel = selector(&[&a, &b, &c]);

    // Healthy: the configured primary carries everything.
    for n in 0..4 {
        let got = fetch(&sel, n).await.unwrap();
        assert_eq!(got.transport_used, PayloadTransportKind::DirectLibp2p);
        assert_eq!(got.attempts.len(), 1);
    }

    // Primary fails: every request still succeeds through the next transport,
    // and after repeated failures the primary stops being tried first.
    a.set(false);
    let mut single_attempt_requests = 0;
    for n in 0..12 {
        let got = fetch(&sel, 10 + n).await.expect("fallback must succeed");
        assert_eq!(got.transport_used, PayloadTransportKind::WssTunnel);
        if got.attempts.len() == 1 {
            single_attempt_requests += 1;
        }
    }
    assert!(
        single_attempt_requests >= 6,
        "demoted primary should stop costing an attempt per request (got {single_attempt_requests})"
    );
    assert!(
        sel.stats().adaptive_selection_stats().0 >= 1,
        "no reorder recorded"
    );
    assert!(
        sel.stats()
            .consecutive_failures(PayloadTransportKind::DirectLibp2p)
            >= 2
    );

    // Secondary fails too: the third transport carries the traffic.
    b.set(false);
    for n in 0..6 {
        let got = fetch(&sel, 30 + n)
            .await
            .expect("third transport must succeed");
        assert_eq!(got.transport_used, PayloadTransportKind::TcpDirect);
    }

    // Everything down: one error carrying one attempt per transport.
    c.set(false);
    let err = fetch(&sel, 40).await.unwrap_err();
    assert_eq!(err.attempts.len(), 3);
    assert!(err.attempts.iter().all(|a| !a.succeeded));

    // The primary comes back. The periodic probe must find it within one probe
    // interval and then keep it first.
    a.set(true);
    b.set(true);
    c.set(true);
    let mut recovered_at = None;
    for n in 0..9u16 {
        let got = fetch(&sel, 50 + n).await.unwrap();
        if got.transport_used == PayloadTransportKind::DirectLibp2p {
            recovered_at = Some(n);
            break;
        }
    }
    assert!(recovered_at.is_some(), "primary was never re-probed");
    for n in 0..5 {
        let got = fetch(&sel, 70 + n).await.unwrap();
        assert_eq!(got.transport_used, PayloadTransportKind::DirectLibp2p);
        assert_eq!(got.attempts.len(), 1);
    }
    assert_eq!(
        sel.stats()
            .consecutive_failures(PayloadTransportKind::DirectLibp2p),
        0
    );
}

/// Deterministic xorshift so the flapping schedule is reproducible.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[tokio::test]
async fn flapping_transports_never_lose_a_request_while_one_stays_up() {
    let a = Scripted::new(PayloadTransportKind::DirectLibp2p, true);
    let b = Scripted::new(PayloadTransportKind::WssTunnel, true);
    let c = Scripted::new(PayloadTransportKind::TcpDirect, true);
    let sel = selector(&[&a, &b, &c]);
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;

    let mut served = 0u64;
    for n in 0..300u16 {
        let bits = next(&mut rng);
        a.set(bits & 1 == 0);
        b.set(bits & 2 == 0);
        // c is the transport that stays up, so a loss would be a selector bug.
        c.set(true);
        let got = fetch(&sel, n).await.expect("one transport is always up");
        served += 1;
        assert!(got.attempts.last().unwrap().succeeded);
    }
    assert_eq!(served, 300);
    let (ok_a, _) = sel.stats().kind_stats(PayloadTransportKind::DirectLibp2p);
    let (ok_b, _) = sel.stats().kind_stats(PayloadTransportKind::WssTunnel);
    let (ok_c, _) = sel.stats().kind_stats(PayloadTransportKind::TcpDirect);
    assert_eq!(ok_a + ok_b + ok_c, 300, "exactly one success per request");
}

#[tokio::test]
async fn required_anonymity_never_downgrades_to_a_direct_transport() {
    assert_eq!(
        PayloadTransportKind::RelayHop.privacy_class(),
        TransportPrivacyClass::Relayed
    );
    for kind in [
        PayloadTransportKind::DirectLibp2p,
        PayloadTransportKind::TcpDirect,
        PayloadTransportKind::WssTunnel,
        PayloadTransportKind::ObfuscatedQuic,
    ] {
        assert_eq!(kind.privacy_class(), TransportPrivacyClass::Direct);
        assert!(!kind.permitted_under(AnonymityPolicy::Required { min_hops: 1 }));
        assert!(kind.permitted_under(AnonymityPolicy::Direct));
        assert!(kind.permitted_under(AnonymityPolicy::Opportunistic));
    }

    let direct = Scripted::new(PayloadTransportKind::DirectLibp2p, true);
    let tcp = Scripted::new(PayloadTransportKind::TcpDirect, true);
    let relay = Scripted::new(PayloadTransportKind::RelayHop, true);
    let sel = selector(&[&direct, &tcp, &relay]);
    let required = AnonymityPolicy::Required { min_hops: 2 };

    // Relay healthy: it carries the request even though it is configured last.
    let got = sel
        .fetch_share_with_policy(required, "peer", [0; 32], 0, 0)
        .await
        .unwrap();
    assert_eq!(got.transport_used, PayloadTransportKind::RelayHop);

    // Relay down while both direct transports are healthy: the request fails
    // with only the relay attempted. Repeating it must not wear down the
    // policy either (the relay becomes demoted, the direct ones stay unused).
    relay.set(false);
    for n in 0..20u16 {
        let err = sel
            .fetch_share_with_policy(required, "peer", [0; 32], n, 0)
            .await
            .expect_err("a forbidden direct transport must not rescue the request");
        match err {
            PolicyFetchError::Exhausted(e) => {
                assert!(e
                    .attempts
                    .iter()
                    .all(|a| a.transport == PayloadTransportKind::RelayHop));
            }
            other => panic!("unexpected error: {other}"),
        }
    }
    assert_eq!(
        direct.calls(),
        0,
        "direct transport was used under Required"
    );
    assert_eq!(tcp.calls(), 0, "tcp transport was used under Required");

    // The same transports under a policy that allows direct do fall back.
    let got = sel
        .fetch_share_with_policy(AnonymityPolicy::Opportunistic, "peer", [0; 32], 1, 0)
        .await
        .unwrap();
    assert_ne!(got.transport_used, PayloadTransportKind::RelayHop);

    // Recovery inside the policy: the relay returns and is used again.
    relay.set(true);
    let mut used_relay = false;
    for n in 0..9u16 {
        if let Ok(got) = sel
            .fetch_share_with_policy(required, "peer", [0; 32], n, 0)
            .await
        {
            assert_eq!(got.transport_used, PayloadTransportKind::RelayHop);
            used_relay = true;
            break;
        }
    }
    assert!(used_relay, "relay was not re-probed after recovery");
}

#[tokio::test]
async fn required_anonymity_with_no_relay_configured_is_an_error_not_a_fallback() {
    let direct = Scripted::new(PayloadTransportKind::DirectLibp2p, true);
    let wss = Scripted::new(PayloadTransportKind::WssTunnel, true);
    let sel = selector(&[&direct, &wss]);

    let err = sel
        .fetch_share_with_policy(
            AnonymityPolicy::Required { min_hops: 1 },
            "peer",
            [0; 32],
            0,
            0,
        )
        .await
        .expect_err("no permitted transport must be an error");
    match &err {
        PolicyFetchError::NoPermittedTransport { policy, configured } => {
            assert_eq!(*policy, AnonymityPolicy::Required { min_hops: 1 });
            assert_eq!(
                configured,
                &vec![
                    PayloadTransportKind::DirectLibp2p,
                    PayloadTransportKind::WssTunnel
                ]
            );
        }
        other => panic!("unexpected error: {other}"),
    }
    assert!(err.to_string().contains("refusing to fall back"));
    assert_eq!(direct.calls() + wss.calls(), 0, "nothing may be attempted");
}
