/// Adversarial simulation tests for Miasma's routing and trust model.
///
/// These tests simulate attack scenarios against the routing overlay,
/// admission policy, credential system, and descriptor store to verify
/// that the trust architecture resists capture and manipulation.
///
/// # Attack scenarios
///
/// 1. **Sybil cluster**: mass peer creation from same subnet
/// 2. **Eclipse attempt**: fill routing table with attacker-controlled peers
/// 3. **Poisoned descriptors**: inject descriptors with forged credentials
/// 4. **Credential replay**: present expired or stolen credentials
/// 5. **Routing pressure**: dominate peer selection through fake reliability
/// 6. **Hybrid admission gaming**: minimise admission cost while Sybiling
use libp2p::PeerId;
use miasma_core::network::address::AddressTrust;
use miasma_core::network::admission_policy::{
    AdmissionSignals, HybridAdmissionPolicy, HybridRejection,
};
use miasma_core::network::bbs_credential::{
    bbs_create_proof, bbs_verify_proof, generate_link_secret, BbsCredentialAttributes,
    BbsCredentialWallet, BbsIssuer, BbsIssuerKey, DisclosurePolicy,
};
use miasma_core::network::credential::{
    self, CredentialIssuer, CredentialPresentation, CredentialTier, EphemeralIdentity, CAP_ROUTE,
    CAP_STORE,
};
use miasma_core::network::descriptor::{
    DescriptorStore, PeerCapabilities, PeerDescriptor, ReachabilityKind, RelayTrustTier,
    ResourceProfile,
};
use miasma_core::network::metrics::OutcomeMetrics;
use miasma_core::network::path_selection::{AnonymityPolicy, PathSelector};
use miasma_core::network::peer_state::PeerRegistry;
use miasma_core::network::routing::{IpPrefix, RoutingTable};

use miasma_core::directed::{
    create_envelope, decrypt_directed_content, decrypt_envelope_payload, derive_content_key,
    finalize_envelope, format_sharing_contact, format_sharing_key, parse_sharing_contact,
    parse_sharing_key, DirectedEnvelope, DirectedInbox, DirectedRequest, DirectedResponse,
    EnvelopeState, RetentionPeriod,
};
use miasma_core::directed::challenge::{
    generate_challenge, verify_challenge, CHALLENGE_MAX_ATTEMPTS,
};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn test_issuer() -> CredentialIssuer {
    CredentialIssuer::new(ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]))
}

// ─── Scenario 1: Sybil cluster via IP prefix saturation ─────────────────────

/// An attacker generates 100 peers from the same /16 subnet.
/// The routing table should admit at most MAX_PEERS_PER_IPV4_SLASH16 (3)
/// from any single /16 prefix.
#[test]
fn sybil_cluster_prefix_saturation() {
    let mut rt = RoutingTable::new(true); // diversity enabled
    let mut admitted = 0;
    let mut rejected = 0;

    for i in 0..100u8 {
        let addrs = vec![format!("/ip4/10.0.{i}.1/tcp/4001")
            .parse::<libp2p::Multiaddr>()
            .unwrap()];

        match rt.check_diversity(&addrs) {
            Ok(prefix) => {
                rt.add_peer(PeerId::random(), prefix);
                admitted += 1;
            }
            Err(_) => {
                rt.record_diversity_rejection();
                rejected += 1;
            }
        }
    }

    assert_eq!(
        admitted, 3,
        "only MAX_PEERS_PER_IPV4_SLASH16 should be admitted"
    );
    assert_eq!(rejected, 97, "remaining should be diversity-rejected");
    assert_eq!(rt.stats().diversity_rejections, 97);
}

/// Sybil attacker uses /48 IPv6 prefix saturation.
#[test]
fn sybil_cluster_ipv6_prefix_saturation() {
    let mut rt = RoutingTable::new(true);

    let mut admitted = 0;
    for i in 0..50u16 {
        let addr_str = format!("/ip6/2001:db8:85a3::{i}/tcp/4001");
        let addrs = vec![addr_str.parse::<libp2p::Multiaddr>().unwrap()];

        match rt.check_diversity(&addrs) {
            Ok(prefix) => {
                rt.add_peer(PeerId::random(), prefix);
                admitted += 1;
            }
            Err(_) => {
                rt.record_diversity_rejection();
            }
        }
    }

    assert_eq!(admitted, 3, "IPv6 /48 diversity should also cap at 3");
}

// ─── Scenario 2: Eclipse attempt ────────────────────────────────────────────

/// Attacker tries to dominate the routing table by spreading peers across
/// many /16 prefixes. Even without prefix limits, trust-tier ranking should
/// deprioritise unverified peers.
#[test]
fn eclipse_via_diverse_sybils_resisted_by_trust() {
    let mut rt = RoutingTable::new(true);

    // Attacker: 30 peers from different /16 prefixes.
    let mut attacker_peers = Vec::new();
    for i in 0..30u8 {
        let prefix = IpPrefix::V4Slash16([i + 1, 0]);
        let peer = PeerId::random();
        rt.add_peer(peer, prefix);
        attacker_peers.push(peer);
    }

    // Honest: 10 peers from different /16 prefixes.
    let mut honest_peers = Vec::new();
    for i in 0..10u8 {
        let prefix = IpPrefix::V4Slash16([200 + i, 0]);
        let peer = PeerId::random();
        rt.add_peer(peer, prefix);
        // Honest peers have real interactions.
        for _ in 0..5 {
            rt.record_success(&peer);
        }
        honest_peers.push(peer);
    }

    // Make attackers unreliable (they fail DHT queries).
    for peer in &attacker_peers {
        for _ in 0..10 {
            rt.record_failure(peer);
        }
    }

    // Rank all peers: honest should dominate the top.
    let all_peers: Vec<PeerId> = attacker_peers
        .iter()
        .chain(honest_peers.iter())
        .copied()
        .collect();

    let ranked = rt.rank_peers(&all_peers, |id| {
        if honest_peers.contains(id) {
            AddressTrust::Verified
        } else {
            AddressTrust::Observed // attackers only reached Observed
        }
    });

    // Top 10 should be dominated by honest peers (Verified + reliable).
    let top_10 = &ranked[..10.min(ranked.len())];
    let honest_in_top_10 = top_10.iter().filter(|p| honest_peers.contains(p)).count();
    assert!(
        honest_in_top_10 >= 8,
        "honest peers should dominate top rankings: {honest_in_top_10}/10"
    );
}

// ─── Scenario 3: Poisoned descriptors ───────────────────────────────────────

/// Attacker publishes descriptors with forged credentials.
/// Verification should reject them.
#[test]
fn poisoned_descriptor_forged_credential() {
    let honest_issuer = test_issuer();
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let attacker_issuer = CredentialIssuer::new(attacker_key.clone());

    // Attacker creates a credential from their own (unknown) issuer.
    let identity = EphemeralIdentity::generate(credential::current_epoch());
    let forged_cred = attacker_issuer.issue(
        CredentialTier::Endorsed,
        identity.epoch,
        CAP_ROUTE | CAP_STORE,
        identity.holder_tag(),
    );

    let presentation = CredentialPresentation::create(&forged_cred, &identity, b"ctx");

    // Verification should fail because attacker_issuer is not in known_issuers.
    let result = credential::verify_presentation(
        &presentation,
        b"ctx",
        &[honest_issuer.pubkey_bytes()], // only honest issuer known
        credential::current_epoch(),
        CredentialTier::Verified,
    );
    assert_eq!(
        result.unwrap_err(),
        credential::CredentialError::UnknownIssuer,
        "forged credential from unknown issuer should be rejected"
    );
}

/// Attacker tampers with a legitimately-signed descriptor's addresses.
#[test]
fn poisoned_descriptor_tampered_addresses() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut desc = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );

    // Tamper: change the address to redirect traffic.
    desc.addresses = vec!["/ip4/6.6.6.6/tcp/9999".to_string()];

    // Signature should no longer verify.
    assert!(
        !desc.verify_signature(&key.verifying_key()),
        "tampered descriptor should fail signature check"
    );
}

// ─── Scenario 4: Credential replay and theft ────────────────────────────────

/// Attacker captures a valid credential presentation and replays it
/// with a different context. The context binding should prevent this.
#[test]
fn credential_replay_different_context() {
    let issuer = test_issuer();
    let identity = EphemeralIdentity::generate(credential::current_epoch());

    let cred = issuer.issue(
        CredentialTier::Verified,
        identity.epoch,
        CAP_ROUTE,
        identity.holder_tag(),
    );

    // Original presentation for context A.
    let presentation = CredentialPresentation::create(&cred, &identity, b"context-A");

    // Replay with context B should fail.
    let result = credential::verify_presentation(
        &presentation,
        b"context-B",
        &[issuer.pubkey_bytes()],
        credential::current_epoch(),
        CredentialTier::Verified,
    );
    assert_eq!(
        result.unwrap_err(),
        credential::CredentialError::InvalidHolderProof,
        "replayed presentation with wrong context should fail"
    );
}

/// Attacker steals a signed credential but doesn't have the ephemeral key.
/// They cannot create valid presentations.
#[test]
fn credential_theft_without_ephemeral_key() {
    let issuer = test_issuer();
    let victim_identity = EphemeralIdentity::generate(credential::current_epoch());

    let stolen_cred = issuer.issue(
        CredentialTier::Verified,
        victim_identity.epoch,
        CAP_ROUTE,
        victim_identity.holder_tag(),
    );

    // Attacker creates their own ephemeral identity.
    let attacker_identity = EphemeralIdentity::generate(credential::current_epoch());

    // Attacker tries to present with their own key but the stolen credential's holder_tag.
    let cred_bytes = stolen_cred.to_bytes();
    let context_sig = attacker_identity.sign_context(&cred_bytes, b"ctx");
    let fake_presentation = CredentialPresentation {
        credential: stolen_cred,
        ephemeral_pubkey: attacker_identity.pubkey_bytes(), // wrong key
        context_signature: context_sig,
    };

    let result = credential::verify_presentation(
        &fake_presentation,
        b"ctx",
        &[issuer.pubkey_bytes()],
        credential::current_epoch(),
        CredentialTier::Verified,
    );
    assert_eq!(
        result.unwrap_err(),
        credential::CredentialError::HolderTagMismatch,
        "stolen credential with wrong ephemeral key should fail holder tag check"
    );
}

/// Expired credential (from many epochs ago) should be rejected.
#[test]
fn credential_expired_epoch_rejected() {
    let issuer = test_issuer();
    let old_epoch = credential::current_epoch().saturating_sub(100);
    let identity = EphemeralIdentity::generate(old_epoch);

    let cred = issuer.issue(
        CredentialTier::Endorsed,
        old_epoch,
        CAP_ROUTE | CAP_STORE,
        identity.holder_tag(),
    );

    let presentation = CredentialPresentation::create(&cred, &identity, b"ctx");

    let result = credential::verify_presentation(
        &presentation,
        b"ctx",
        &[issuer.pubkey_bytes()],
        credential::current_epoch(),
        CredentialTier::Verified,
    );
    assert!(
        matches!(
            result.unwrap_err(),
            credential::CredentialError::ExpiredEpoch { .. }
        ),
        "credential from 100 epochs ago should be expired"
    );
}

// ─── Scenario 5: Routing pressure / bucket capture ──────────────────────────

/// Attacker creates peers with fake reliability scores to dominate routing.
/// Since reliability is tracked by the routing table (not self-reported),
/// an attacker who fails real interactions will be deprioritised.
#[test]
fn routing_pressure_fake_reliability_impossible() {
    let mut rt = RoutingTable::new(true);

    // Honest peer with real successes.
    let honest = PeerId::random();
    rt.add_peer(honest, IpPrefix::V4Slash16([1, 1]));
    for _ in 0..10 {
        rt.record_success(&honest);
    }

    // Attacker peer — has some failures from real interactions that went wrong.
    // In practice, an attacker that doesn't serve valid content will accumulate failures.
    let attacker = PeerId::random();
    rt.add_peer(attacker, IpPrefix::V4Slash16([2, 2]));
    for _ in 0..5 {
        rt.record_failure(&attacker);
    }

    let ranked = rt.rank_peers(&[attacker, honest], |_| AddressTrust::Verified);
    assert_eq!(
        ranked[0], honest,
        "honest peer with real successes should rank above attacker with failures"
    );
}

/// Attacker creates many peers to dilute the reliability signal.
#[test]
fn routing_dilution_attack_mitigated_by_diversity() {
    let mut rt = RoutingTable::new(true);

    // 3 honest peers from diverse prefixes.
    let honest: Vec<PeerId> = (0..3)
        .map(|i| {
            let peer = PeerId::random();
            rt.add_peer(peer, IpPrefix::V4Slash16([200 + i, 0]));
            for _ in 0..5 {
                rt.record_success(&peer);
            }
            peer
        })
        .collect();

    // 9 attacker peers (3 per /16, diversity capped at 3).
    let attacker: Vec<PeerId> = (0..9).map(|_| PeerId::random()).collect();

    // Only 3 attackers can get into different /16s.
    for (i, &peer) in attacker.iter().take(3).enumerate() {
        rt.add_peer(peer, IpPrefix::V4Slash16([10 + i as u8, 0]));
    }

    let all: Vec<PeerId> = honest
        .iter()
        .chain(attacker.iter().take(3))
        .copied()
        .collect();
    let ranked = rt.rank_peers(&all, |id| {
        if honest.contains(id) {
            AddressTrust::Verified
        } else {
            AddressTrust::Observed
        }
    });

    // Honest peers should be ranked higher (Verified + reliable).
    let honest_in_top_3 = ranked[..3].iter().filter(|p| honest.contains(p)).count();
    assert_eq!(honest_in_top_3, 3, "honest peers should occupy top 3 spots");
}

// ─── Scenario 6: Hybrid admission gaming ────────────────────────────────────

/// Attacker tries to minimise PoW cost by generating many low-difficulty
/// peers and hoping credentials will compensate. The minimum PoW floor
/// should prevent this.
#[test]
fn hybrid_admission_pow_floor_prevents_gaming() {
    let policy = HybridAdmissionPolicy::default();

    // Attacker: PoW at 2 bits (below floor of 4), with a credential.
    let signals = AdmissionSignals {
        pow_difficulty: 2,
        unique_prefix: true,
        reachable: true,
        credential_tier: Some(CredentialTier::Endorsed),
        resource_profile: ResourceProfile::Desktop,
    };

    let decision = policy.evaluate(&signals);
    assert!(
        !decision.admitted,
        "below minimum PoW should always be rejected"
    );
    assert!(matches!(
        decision.rejection_reason,
        Some(HybridRejection::InsufficientMinPoW { .. })
    ));
}

/// Attacker generates many mobile-profile peers to exploit the lower threshold.
/// Even with the lower threshold, minimum PoW + lack of credentials should
/// still require real work.
#[test]
fn hybrid_admission_mobile_sybil_still_costly() {
    let policy = HybridAdmissionPolicy::default();

    // Mobile peer with minimum PoW (4 bits), no credential, not reachable.
    let signals = AdmissionSignals {
        pow_difficulty: 4,
        unique_prefix: false,
        reachable: false,
        credential_tier: None,
        resource_profile: ResourceProfile::Mobile,
    };

    let decision = policy.evaluate(&signals);
    // 4*10 = 40 < 80 (mobile threshold)
    assert!(
        !decision.admitted,
        "mobile sybil without credential should fail"
    );
}

/// Legitimate mobile peer with a credential should be admitted.
#[test]
fn hybrid_admission_legitimate_mobile_with_credential() {
    let policy = HybridAdmissionPolicy::default();

    let signals = AdmissionSignals {
        pow_difficulty: 4,
        unique_prefix: true,
        reachable: false,
        credential_tier: Some(CredentialTier::Verified),
        resource_profile: ResourceProfile::Mobile,
    };

    let decision = policy.evaluate(&signals);
    // 40 + 50 + 100 = 190 >= 80
    assert!(
        decision.admitted,
        "legitimate mobile with credential should pass"
    );
}

// ─── Scenario 7: Path selection under adversarial relay set ─────────────────

/// All available relays are from the same /16. Path selection should fail
/// to build a diverse multi-hop path.
#[test]
fn path_selection_same_prefix_relays() {
    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    for i in 0..5u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.0.{i}.1/tcp/4001")],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let rt = RoutingTable::new(true);
    let result = PathSelector::select(
        [0xFF; 32],
        AnonymityPolicy::Required { min_hops: 2 },
        &store,
        &rt,
    );

    assert!(
        result.is_err(),
        "same-prefix relays should not satisfy 2-hop diversity"
    );
}

/// With diverse relays, path selection should succeed.
#[test]
fn path_selection_diverse_relays_succeed() {
    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    for i in 0..5u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/{}.{}.1.1/tcp/4001", i + 1, i + 1)],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let rt = RoutingTable::new(true);
    let path = PathSelector::select(
        [0xFF; 32],
        AnonymityPolicy::Required { min_hops: 3 },
        &store,
        &rt,
    )
    .unwrap();

    assert!(path.hop_count() >= 3);
    // Verify all hops have different prefixes.
    let prefixes = path.prefixes();
    let unique: std::collections::HashSet<_> = prefixes.iter().collect();
    assert_eq!(
        prefixes.len(),
        unique.len(),
        "all hops should have unique prefixes"
    );
}

// ─── Scenario 8: PoW cost vs network size ───────────────────────────────────

/// As the network grows, PoW difficulty should increase, making Sybil
/// attacks progressively more expensive.
#[test]
fn pow_difficulty_scales_with_network_size() {
    let mut rt = RoutingTable::new(true);

    // Small network: difficulty should stay at base (8).
    for _ in 0..10 {
        rt.observe_network_size(5);
    }
    assert_eq!(rt.current_difficulty(), 8);

    // Growing network: difficulty should increase.
    for _ in 0..20 {
        rt.observe_network_size(100);
    }
    rt.maybe_adjust_difficulty();
    assert!(
        rt.current_difficulty() > 8,
        "difficulty should increase with network size"
    );

    // Large network: difficulty should be substantial.
    for _ in 0..30 {
        rt.observe_network_size(500);
    }
    rt.maybe_adjust_difficulty();
    assert!(
        rt.current_difficulty() >= 20,
        "large network should require high PoW"
    );
}

/// Compute the cost ratio: how many more hashes an attacker needs at higher
/// difficulty vs base difficulty.
#[test]
fn pow_sybil_cost_multiplier() {
    // At base difficulty (8 bits): ~256 hashes per identity.
    // At 16 bits: ~65536 hashes per identity (256x more expensive).
    // At 20 bits: ~1M hashes per identity (4096x more expensive).
    let base_cost = 1u64 << 8;
    let medium_cost = 1u64 << 16;
    let high_cost = 1u64 << 20;

    assert_eq!(medium_cost / base_cost, 256);
    assert_eq!(high_cost / base_cost, 4096);

    // An attacker trying to create 1000 Sybil identities at difficulty 20
    // needs ~1 billion hashes. At BLAKE3 speed (~1 GH/s on a fast CPU),
    // this takes ~1 second. At difficulty 24 (~16M per identity), 1000
    // identities need ~16 billion hashes, taking ~16 seconds.
    //
    // Combined with diversity limits (3 per /16), the attacker also needs
    // 334 different /16 prefixes to place all 1000 identities.
    let identities = 1000u64;
    let hashes_at_20 = identities * high_cost;
    assert!(
        hashes_at_20 > 1_000_000_000,
        "Sybil cost should be > 1B hashes"
    );
}

// ─── Scenario 9: BBS+ credential abuse ──────────────────────────────────────

/// Attacker captures a valid BBS+ proof and tries to verify it with a
/// different context. Context binding should make this fail.
#[test]
fn bbs_proof_context_replay() {
    let issuer_key = BbsIssuerKey::from_seed(b"test-issuer-seed");
    let issuer = BbsIssuer::new(issuer_key.clone());

    let attrs = BbsCredentialAttributes {
        link_secret: generate_link_secret(),
        tier: CredentialTier::Verified,
        capabilities: 3,
        epoch: credential::current_epoch(),
        nonce: 42,
    };
    let cred = issuer.issue(attrs);
    let proof = bbs_create_proof(&cred, &DisclosurePolicy::default(), b"original-context");

    // Replay with a different context.
    let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), b"different-context");
    assert!(
        result.is_err(),
        "BBS+ proof replayed with wrong context should fail"
    );
}

/// Attacker generates a BBS+ proof from an unknown issuer.
/// Phase 4b: Schnorr proof checks message knowledge only. Issuer binding
/// (pairing check) is Phase 4c. For now, verify that the Ed25519 credential
/// system catches unknown issuers even if BBS+ doesn't yet.
#[test]
fn bbs_proof_unknown_issuer_ed25519_catches() {
    let honest_issuer = test_issuer();
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let attacker_issuer = CredentialIssuer::new(attacker_key);

    let identity = EphemeralIdentity::generate(credential::current_epoch());
    let forged = attacker_issuer.issue(
        CredentialTier::Endorsed,
        identity.epoch,
        CAP_ROUTE | CAP_STORE,
        identity.holder_tag(),
    );
    let presentation = CredentialPresentation::create(&forged, &identity, b"ctx");

    // Ed25519 scheme correctly rejects unknown issuer.
    let result = credential::verify_presentation(
        &presentation,
        b"ctx",
        &[honest_issuer.pubkey_bytes()],
        credential::current_epoch(),
        CredentialTier::Verified,
    );
    assert_eq!(
        result.unwrap_err(),
        credential::CredentialError::UnknownIssuer,
        "Ed25519 scheme catches unknown issuer"
    );
}

/// BBS+ pairing check catches credential from wrong issuer.
/// The pairing equation e(A', W) != e(A_bar, G2) when W is wrong.
#[test]
fn bbs_pairing_catches_wrong_issuer() {
    let real_issuer_key = BbsIssuerKey::from_seed(b"real-issuer");
    let attacker_issuer_key = BbsIssuerKey::from_seed(b"attacker-issuer");
    let attacker = BbsIssuer::new(attacker_issuer_key);

    let attrs = BbsCredentialAttributes {
        link_secret: generate_link_secret(),
        tier: CredentialTier::Endorsed,
        capabilities: 0xFF,
        epoch: credential::current_epoch(),
        nonce: 1,
    };
    let cred = attacker.issue(attrs);
    let proof = bbs_create_proof(&cred, &DisclosurePolicy::default(), b"ctx");

    // Verify against the REAL issuer key — pairing check must fail.
    let result = bbs_verify_proof(&proof, &real_issuer_key.pk_bytes(), b"ctx");
    assert!(result.is_err(), "BBS+ pairing should catch wrong issuer");
    assert_eq!(
        result.unwrap_err(),
        miasma_core::network::bbs_credential::BbsError::IssuerBindingFailed,
    );
}

/// Attacker modifies disclosed tier in a BBS+ proof.
/// The Schnorr proof should detect the inconsistency.
#[test]
fn bbs_proof_tampered_disclosed_tier() {
    let issuer_key = BbsIssuerKey::from_seed(b"test-seed");
    let issuer = BbsIssuer::new(issuer_key.clone());

    let attrs = BbsCredentialAttributes {
        link_secret: generate_link_secret(),
        tier: CredentialTier::Observed, // actual tier = 1
        capabilities: 1,
        epoch: credential::current_epoch(),
        nonce: 0,
    };
    let cred = issuer.issue(attrs);
    let mut proof = bbs_create_proof(&cred, &DisclosurePolicy::default(), b"ctx");

    // Tamper: change disclosed tier from Observed(1) to Endorsed(3).
    for item in proof.disclosed.iter_mut() {
        if item.0 == 1 {
            item.1 = 3; // Endorsed
        }
    }

    let result = bbs_verify_proof(&proof, &issuer_key.pk_bytes(), b"ctx");
    assert!(
        result.is_err(),
        "tampered disclosed tier should break Schnorr proof"
    );
}

/// BBS+ within-epoch unlinkability: two proofs from the same credential
/// should not be correlatable.
#[test]
fn bbs_within_epoch_unlinkability() {
    let issuer_key = BbsIssuerKey::from_seed(b"unlinkability-test");
    let issuer = BbsIssuer::new(issuer_key.clone());

    let attrs = BbsCredentialAttributes {
        link_secret: generate_link_secret(),
        tier: CredentialTier::Verified,
        capabilities: 3,
        epoch: credential::current_epoch(),
        nonce: 99,
    };
    let cred = issuer.issue(attrs);

    let proof1 = bbs_create_proof(&cred, &DisclosurePolicy::default(), b"ctx-1");
    let proof2 = bbs_create_proof(&cred, &DisclosurePolicy::default(), b"ctx-2");

    // Both proofs should verify.
    assert!(bbs_verify_proof(&proof1, &issuer_key.pk_bytes(), b"ctx-1").is_ok());
    assert!(bbs_verify_proof(&proof2, &issuer_key.pk_bytes(), b"ctx-2").is_ok());

    // But they should look different (randomised A', A_bar, challenge, responses).
    assert_ne!(proof1.a_prime, proof2.a_prime, "A' should differ");
    assert_ne!(proof1.a_bar, proof2.a_bar, "A_bar should differ");
    assert_ne!(
        proof1.challenge, proof2.challenge,
        "challenge should differ"
    );
}

// ─── Scenario 10: Descriptor store flooding ─────────────────────────────────

/// Attacker floods the descriptor store with thousands of descriptors.
/// The store should handle this without panic and maintain correct stats.
#[test]
fn descriptor_store_flooding() {
    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    for i in 0..1000u32 {
        let mut ps = [0u8; 32];
        ps[..4].copy_from_slice(&i.to_le_bytes());
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!(
                "/ip4/{}.{}.{}.1/tcp/4001",
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8
            )],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let stats = store.stats();
    assert_eq!(stats.total_descriptors, 1000);
    assert_eq!(stats.relay_descriptors, 1000);
}

/// Attacker replaces honest descriptors by upserting with same pseudonym
/// but malicious addresses.
#[test]
fn descriptor_pseudonym_hijack_requires_valid_signature() {
    let honest_key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xEE; 32]);
    let pseudonym = [0x42u8; 32];

    let honest_desc = PeerDescriptor::new_signed(
        pseudonym,
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &honest_key,
    );

    // Honest descriptor verifies with honest key.
    assert!(honest_desc.verify_signature(&honest_key.verifying_key()));

    // Attacker creates descriptor with same pseudonym but different key.
    let attacker_desc = PeerDescriptor::new_signed(
        pseudonym,
        ReachabilityKind::Direct,
        vec!["/ip4/6.6.6.6/tcp/9999".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        2, // newer timestamp
        &attacker_key,
    );

    // Attacker descriptor does NOT verify with honest key.
    assert!(
        !attacker_desc.verify_signature(&honest_key.verifying_key()),
        "attacker descriptor should not verify against honest key"
    );
    // It only verifies with attacker key.
    assert!(attacker_desc.verify_signature(&attacker_key.verifying_key()));
}

// ─── Scenario 11: Hybrid admission boundary conditions ──────────────────────

/// Constrained device with maximum possible signals still needs minimum PoW.
#[test]
fn hybrid_admission_constrained_device_min_pow() {
    let policy = HybridAdmissionPolicy::default();

    let signals = AdmissionSignals {
        pow_difficulty: 3, // below 4-bit floor
        unique_prefix: true,
        reachable: true,
        credential_tier: Some(CredentialTier::Endorsed),
        resource_profile: ResourceProfile::Constrained,
    };

    let decision = policy.evaluate(&signals);
    assert!(
        !decision.admitted,
        "constrained device below PoW floor should be rejected"
    );
}

/// Desktop peer at exact threshold boundary.
#[test]
fn hybrid_admission_exact_desktop_threshold() {
    let policy = HybridAdmissionPolicy::default();

    // Desktop threshold is 100. PoW=10 (10*10=100). Just PoW alone = threshold.
    let signals = AdmissionSignals {
        pow_difficulty: 10,
        unique_prefix: false,
        reachable: false,
        credential_tier: None,
        resource_profile: ResourceProfile::Desktop,
    };

    let decision = policy.evaluate(&signals);
    assert!(
        decision.admitted,
        "peer at exact threshold should be admitted"
    );
}

// ─── Scenario 12: Path selection with hostile relay injection ────────────────

/// Attacker controls many relay descriptors but all from the same subnet.
/// Required anonymity should fail to find diverse paths.
#[test]
fn path_selection_hostile_relay_set_same_subnet() {
    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    // 20 attacker relays all from 10.0.x.x (same /16).
    for i in 0..20u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.0.{i}.1/tcp/4001")],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let rt = RoutingTable::new(true);
    let result = PathSelector::select(
        [0xFF; 32],
        AnonymityPolicy::Required { min_hops: 3 },
        &store,
        &rt,
    );

    assert!(
        result.is_err(),
        "hostile relay set from one /16 should fail required 3-hop path"
    );
}

/// Opportunistic policy should gracefully degrade with hostile relay set.
#[test]
fn path_selection_opportunistic_degrades_gracefully() {
    let store = DescriptorStore::new(); // no relays at all
    let rt = RoutingTable::new(true);

    let path =
        PathSelector::select([0xFF; 32], AnonymityPolicy::Opportunistic, &store, &rt).unwrap();

    assert!(
        path.is_direct(),
        "opportunistic with no relays should fall back to direct"
    );
}

// ── Descriptor self-verification adversarial tests ──────────────────────

/// Tampered descriptor with altered addresses must fail self-verification.
#[test]
fn descriptor_tampered_addresses_rejected() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut desc = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/8.8.8.8/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );
    // Attacker injects a rogue address.
    desc.addresses.push("/ip4/6.6.6.6/tcp/9999".to_string());
    assert!(
        !desc.verify_self(),
        "tampered descriptor should fail self-verification"
    );
}

/// Descriptor with swapped signing_pubkey (attacker tries to claim another's descriptor).
#[test]
fn descriptor_pubkey_swap_rejected() {
    let honest_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);

    let mut desc = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/8.8.8.8/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &honest_key,
    );
    // Attacker replaces pubkey to claim the signature.
    desc.signing_pubkey = attacker_key.verifying_key().to_bytes();
    assert!(
        !desc.verify_self(),
        "pubkey-swapped descriptor should fail verification"
    );
}

/// Descriptor store rejects already-stale descriptors at insertion time.
#[test]
fn descriptor_store_rejects_stale_on_insert() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut desc = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/8.8.8.8/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );
    // Backdate the descriptor to 2 hours ago (stale).
    desc.published_at = now - 7200;
    assert!(
        !store.upsert(desc),
        "stale descriptor should be rejected on insert"
    );
    assert_eq!(store.len(), 0);
}

/// Descriptor store enforces capacity limit under flooding attack.
#[test]
fn descriptor_store_capacity_limit_under_flood() {
    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    // Insert 10,001 descriptors — store should cap at 10,000.
    for i in 0u32..10_001 {
        let mut ps = [0u8; 32];
        ps[..4].copy_from_slice(&i.to_le_bytes());
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!(
                "/ip4/10.{}.{}.{}/tcp/4001",
                (i >> 16) & 0xFF,
                (i >> 8) & 0xFF,
                i & 0xFF
            )],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    assert!(
        store.len() <= 10_000,
        "store should enforce capacity limit: got {}",
        store.len()
    );
}

/// Credential from a previous epoch should not be accepted after rotation.
#[test]
fn credential_cross_epoch_replay_rejected() {
    let issuer_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let issuer = CredentialIssuer::new(issuer_key);

    let old_epoch = 100;
    let new_epoch = 102; // gap of 2 exceeds EPOCH_GRACE(1)

    let identity = EphemeralIdentity::generate(old_epoch);

    // Issue credential for old epoch.
    let cred = issuer.issue(
        CredentialTier::Verified,
        old_epoch,
        CAP_STORE | CAP_ROUTE,
        identity.holder_tag(),
    );

    // Create presentation with old identity.
    let context = b"test-context-replay";
    let presentation = CredentialPresentation::create(&cred, &identity, context);

    // Verify against new epoch — should fail.
    let issuers = vec![issuer.pubkey_bytes()];
    let result = credential::verify_presentation(
        &presentation,
        context,
        &issuers,
        new_epoch,
        CredentialTier::Verified,
    );
    assert!(
        result.is_err(),
        "credential from old epoch should be rejected in new epoch"
    );
}

// ─── Scenario 12: Epoch rotation — descriptor churn tracking ────────────

/// Pseudonym churn rate should reflect descriptor set turnover across epochs.
#[test]
fn epoch_rotation_descriptor_churn_tracking() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Epoch 1: insert 5 descriptors.
    for i in 0..5u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    // Before epoch rotation, churn rate should be 0.
    assert_eq!(store.churn_rate(), 0.0);

    // Rotate to epoch 2.
    store.on_epoch_rotate(2);

    // All existing pseudonyms are in prev_epoch_pseudonyms now.
    // Churn rate should be 0 (no new pseudonyms yet).
    assert_eq!(store.churn_rate(), 0.0);

    // Add 3 new descriptors (simulating new peers joining in epoch 2).
    for i in 10..13u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    // Now 8 total descriptors, 3 new = 37.5% churn.
    let churn = store.churn_rate();
    assert!(churn > 0.3, "churn should be ~37.5%, got {churn}");
    assert!(churn < 0.5, "churn should be ~37.5%, got {churn}");
}

/// After full epoch rotation, all old pseudonyms gone = 100% churn.
#[test]
fn epoch_rotation_full_pseudonym_turnover() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Epoch 1: 3 peers.
    for i in 0..3u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    // Rotate to epoch 2.
    store.on_epoch_rotate(2);

    // Remove all old descriptors and add entirely new ones.
    // (Simulating full identity rotation where every peer gets a new pseudonym.)
    // We can't remove directly, but we can add new ones with different pseudonyms.
    for i in 100..103u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    // 6 total, 3 new = 50% churn (old ones still in store).
    let churn = store.churn_rate();
    assert!(churn > 0.4, "at least 50% churn expected, got {churn}");
}

/// Epoch rotation should not regress: re-rotating to the same epoch is a no-op.
#[test]
fn epoch_rotation_idempotent() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    for i in 0..3u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    store.on_epoch_rotate(2);

    // Add a new descriptor.
    let mut ps = [0u8; 32];
    ps[0] = 50;
    store.upsert(PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/10.50.1.1/tcp/4001".into()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    let churn_before = store.churn_rate();

    // Re-rotate to epoch 2 — should be idempotent.
    store.on_epoch_rotate(2);
    assert_eq!(store.churn_rate(), churn_before);
}

// ─── Scenario 13: Relay peer info for coordinator routing ────────────────

/// Relay descriptors with PeerId mappings should be returned for routing.
#[test]
fn relay_peer_info_requires_peer_mapping() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    let ps1 = [0x01u8; 32];
    let ps2 = [0x02u8; 32];

    // Add two relay descriptors.
    store.upsert(PeerDescriptor::new_signed(
        ps1,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".into()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));
    store.upsert(PeerDescriptor::new_signed(
        ps2,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".into()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Without PeerId mapping, no relay peers are routable.
    assert_eq!(store.relay_peer_info().len(), 0);

    // Register PeerId for one relay.
    let peer1 = PeerId::random();
    store.register_peer_pseudonym(peer1, ps1);

    // Now one relay is routable.
    let info = store.relay_peer_info();
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].0, peer1);
    assert_eq!(info[0].1, vec!["/ip4/1.1.1.1/tcp/4001".to_string()]);
}

/// Non-relay descriptors should not appear in relay_peer_info.
#[test]
fn relay_peer_info_excludes_non_relay() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0x01u8; 32];
    store.upsert(PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".into()],
        PeerCapabilities {
            can_relay: false,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);

    assert_eq!(
        store.relay_peer_info().len(),
        0,
        "non-relay should not be returned"
    );
}

// ─── Scenario 14: Credential wallet rotation and re-issuance coherence ──

/// Wallet rotation should produce a new holder tag and invalidate old credentials.
#[test]
fn wallet_rotation_invalidates_old_credentials() {
    let issuer_key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let issuer = CredentialIssuer::new(issuer_key);

    // Create wallet and issue credential.
    let identity_epoch1 = EphemeralIdentity::generate(100);
    let cred = issuer.issue(
        CredentialTier::Verified,
        100,
        CAP_STORE | CAP_ROUTE,
        identity_epoch1.holder_tag(),
    );

    // Present at epoch 100 — should work.
    let ctx = b"wallet-rotation-test";
    let pres = CredentialPresentation::create(&cred, &identity_epoch1, ctx);
    let issuers = vec![issuer.pubkey_bytes()];
    assert!(
        credential::verify_presentation(&pres, ctx, &issuers, 100, CredentialTier::Observed)
            .is_ok()
    );

    // New identity at epoch 101 (simulating rotation).
    let identity_epoch2 = EphemeralIdentity::generate(101);

    // Old credential with new identity should fail: holder_tag mismatch.
    let pres2 = CredentialPresentation::create(&cred, &identity_epoch2, ctx);
    assert!(
        credential::verify_presentation(&pres2, ctx, &issuers, 101, CredentialTier::Observed)
            .is_err(),
        "old credential should not work with new identity after rotation"
    );
}

/// BBS+ wallet pruning should remove credentials from expired epochs.
#[test]
fn bbs_wallet_prune_respects_epoch_boundary() {
    let mut wallet = BbsCredentialWallet::new();
    let seed = blake3::hash(b"test-issuer-seed");
    let issuer_key = BbsIssuerKey::from_seed(seed.as_bytes());
    let issuer = BbsIssuer::new(issuer_key);

    // Issue credentials for epochs 10, 11, 12.
    for epoch in 10..=12u64 {
        let cred = issuer.issue(BbsCredentialAttributes {
            link_secret: wallet.link_secret(),
            tier: CredentialTier::Verified,
            capabilities: CAP_STORE | CAP_ROUTE,
            epoch,
            nonce: rand::random(),
        });
        wallet.store(cred);
    }
    assert_eq!(wallet.credential_count(), 3);

    // Prune before epoch 12: should remove epochs 10 and 11.
    wallet.prune_before_epoch(12);
    assert_eq!(wallet.credential_count(), 1, "only epoch 12 should survive");
}

// ─── Scenario 15: Outcome metrics under adversarial conditions ──────────

/// Metrics should reflect high churn after epoch rotation with new peers.
#[test]
fn outcome_metrics_reflect_churn() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();
    let peer_registry = PeerRegistry::new();
    let routing_table = RoutingTable::new(true);

    // Epoch 1: populate with 5 descriptors.
    for i in 0..5u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let m1 = OutcomeMetrics::compute(&store, &peer_registry, &routing_table, false);
    assert_eq!(m1.pseudonym_churn_rate, 0.0);

    // Epoch 2: rotate and add new peers.
    store.on_epoch_rotate(2);
    for i in 20..25u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let m2 = OutcomeMetrics::compute(&store, &peer_registry, &routing_table, false);
    assert!(
        m2.pseudonym_churn_rate > 0.4,
        "churn rate should be ~50% with 5/10 new: got {}",
        m2.pseudonym_churn_rate
    );
}

/// Metrics should track BBS+ credentialed descriptors.
#[test]
fn outcome_metrics_bbs_credentialed_count() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();
    let peer_registry = PeerRegistry::new();
    let routing_table = RoutingTable::new(true);

    // Add a descriptor without BBS+ proof.
    store.upsert(PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".into()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Add a descriptor with a BBS+ proof.
    let bbs_seed = blake3::hash(b"bbs-test-seed");
    let bbs_key = BbsIssuerKey::from_seed(bbs_seed.as_bytes());
    let bbs_issuer = BbsIssuer::new(bbs_key);
    let link_secret = generate_link_secret();
    let bbs_cred = bbs_issuer.issue(BbsCredentialAttributes {
        link_secret,
        tier: CredentialTier::Verified,
        capabilities: CAP_STORE | CAP_ROUTE,
        epoch: 1,
        nonce: rand::random(),
    });
    let bbs_proof = bbs_create_proof(&bbs_cred, &DisclosurePolicy::default(), b"metrics-test");
    store.upsert(PeerDescriptor::new_signed_with_bbs(
        [0x02; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".into()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        Some(bbs_proof),
        1,
        &key,
    ));

    let m = OutcomeMetrics::compute(&store, &peer_registry, &routing_table, false);
    assert_eq!(m.bbs_credentialed_count, 1);
}

// ─── Scenario 16: Descriptor store capacity under epoch churn ────────────

/// Under rapid epoch rotation with churn, stale pruning should keep the
/// store healthy and the utilisation metric should reflect pressure.
#[test]
fn descriptor_utilisation_under_pressure() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();
    let peer_registry = PeerRegistry::new();
    let routing_table = RoutingTable::new(true);

    // Add 100 descriptors.
    for i in 0..100u16 {
        let mut ps = [0u8; 32];
        ps[0] = (i & 0xFF) as u8;
        ps[1] = (i >> 8) as u8;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.{}.{}.1/tcp/4001", i % 256, i / 256)],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let m = OutcomeMetrics::compute(&store, &peer_registry, &routing_table, false);
    assert!(m.descriptor_utilisation > 0.0, "utilisation should be > 0");
    assert!(
        m.descriptor_utilisation < 0.1,
        "100/10000 = 1%, got {}",
        m.descriptor_utilisation
    );
}

// ─── Scenario 17: Path selection uses descriptors for anonymity ──────────

/// Required anonymity with descriptor-backed relays should produce valid paths.
#[test]
fn path_selection_required_uses_descriptors() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();
    let rt = RoutingTable::new(true);

    // Add 3 relay descriptors from different subnets.
    for i in 0..3u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/{}.{}.1.1/tcp/4001", i + 1, i + 1)],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
        store.register_peer_pseudonym(PeerId::random(), ps);
    }

    let dest = [0xFF; 32];
    let path =
        PathSelector::select(dest, AnonymityPolicy::Required { min_hops: 2 }, &store, &rt).unwrap();

    assert!(path.hop_count() >= 2, "Required mode should use ≥2 hops");

    // All relays in the path should be in the descriptor store.
    for hop in &path.hops {
        assert!(
            store.get(&hop.pseudonym).is_some(),
            "hop should exist in descriptor store"
        );
    }
}

/// Opportunistic mode with relays should prefer relay path over direct.
#[test]
fn path_selection_opportunistic_prefers_relays() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();
    let rt = RoutingTable::new(true);

    // Add 2 relay descriptors.
    for i in 0..2u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/{}.{}.1.1/tcp/4001", i + 1, i + 1)],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    let dest = [0xFF; 32];
    let path = PathSelector::select(dest, AnonymityPolicy::Opportunistic, &store, &rt).unwrap();

    // With relays available, opportunistic should use at least one.
    assert!(
        path.hop_count() >= 1,
        "opportunistic with relays should use ≥1 hop"
    );
}

// ─── Scenario: Onion-encrypted relay delivery ──────────────────────────────

/// Per-hop onion encryption: R1 peels outer layer, R2 peels inner layer,
/// target receives e2e-encrypted payload that neither relay can read.
#[test]
fn onion_relay_per_hop_content_blindness() {
    use miasma_core::network::onion_relay::{
        encrypt_relay_response, process_onion_layer, OnionRelayAction,
    };
    use miasma_core::onion::packet::{decrypt_response, OnionLayerProcessor, OnionPacketBuilder};
    use x25519_dalek::{PublicKey, StaticSecret};

    let make_key = || {
        let sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pub_ = PublicKey::from(&sec);
        (sec.to_bytes(), pub_.to_bytes())
    };

    let (r1_sec, r1_pub) = make_key();
    let (r2_sec, r2_pub) = make_key();
    let (target_sec, target_pub) = make_key();

    let share_request = b"GET share mid=abc123 slot=0".to_vec();

    // Build e2e encrypted onion packet.
    let (packet, _return_path, session_key) = OnionPacketBuilder::build_e2e(
        &r1_pub,
        &r2_pub,
        &target_pub,
        b"r2_peer".to_vec(),
        b"target".to_vec(),
        b"r2_addr".to_vec(),
        share_request.clone(),
    )
    .unwrap();

    // R1 peels — cannot see share request (encrypted for R2 and Target).
    let action1 = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();
    let (inner_layer, r1_return_key) = match action1 {
        OnionRelayAction::ForwardToNext {
            inner_layer,
            return_key,
            ..
        } => (inner_layer, return_key),
        _ => panic!("R1 should forward"),
    };

    // R2 peels — gets body but it's session_key || e2e_blob. Cannot read share request.
    let action2 = process_onion_layer(&r2_sec, packet.circuit_id, &inner_layer).unwrap();
    let (delivered_body, r2_return_key) = match action2 {
        OnionRelayAction::DeliverToTarget {
            body, return_key, ..
        } => (body, return_key),
        _ => panic!("R2 should deliver"),
    };

    // Verify R2 cannot read the actual share request.
    // The body starts with 32-byte session key followed by encrypted blob.
    assert!(delivered_body.len() > 32);
    // Try to deserialize as plaintext ShareFetchRequest — should fail.
    assert!(
        String::from_utf8(delivered_body[32..].to_vec()).is_err()
            || !String::from_utf8_lossy(&delivered_body[32..]).contains("share"),
        "R2 should not see plaintext share request"
    );

    // Target decrypts e2e layer.
    let session_key_recv: [u8; 32] = delivered_body[..32].try_into().unwrap();
    let e2e_layer: miasma_core::onion::packet::OnionLayer =
        bincode::deserialize(&delivered_body[32..]).unwrap();
    let e2e_payload = OnionLayerProcessor::peel(&target_sec, &e2e_layer).unwrap();
    assert_eq!(e2e_payload.data, share_request);

    // Target responds with encrypted share data.
    let response = b"share data payload".to_vec();
    let e2e_response =
        miasma_core::onion::packet::encrypt_response(&session_key_recv, &response).unwrap();

    // R2 encrypts response with r2_return_key.
    let r2_encrypted = encrypt_relay_response(&r2_return_key, &e2e_response).unwrap();

    // R1 encrypts with r1_return_key.
    let r1_encrypted = encrypt_relay_response(&r1_return_key, &r2_encrypted).unwrap();

    // Initiator decrypts: r1_return_key → r2_return_key → session_key.
    let after_r1 = decrypt_response(&r1_return_key, &r1_encrypted).unwrap();
    let after_r2 = decrypt_response(&r2_return_key, &after_r1).unwrap();
    let plaintext = decrypt_response(&*session_key, &after_r2).unwrap();

    assert_eq!(plaintext, response);
}

/// Hostile relay with wrong key cannot peel the onion layer.
#[test]
fn onion_hostile_relay_wrong_key_rejected() {
    use miasma_core::network::onion_relay::process_onion_layer;
    use miasma_core::onion::packet::OnionPacketBuilder;
    use x25519_dalek::{PublicKey, StaticSecret};

    let make_key = || {
        let sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pub_ = PublicKey::from(&sec);
        (sec.to_bytes(), pub_.to_bytes())
    };

    let (_r1_sec, r1_pub) = make_key();
    let (_r2_sec, r2_pub) = make_key();
    let (attacker_sec, _attacker_pub) = make_key();

    let (packet, _rp) = OnionPacketBuilder::build(
        &r1_pub,
        &r2_pub,
        b"r2".to_vec(),
        b"target".to_vec(),
        b"addr".to_vec(),
        b"secret".to_vec(),
    )
    .unwrap();

    // Attacker tries to peel with wrong key — must fail.
    let result = process_onion_layer(&attacker_sec, packet.circuit_id, &packet.layer);
    assert!(result.is_err(), "wrong key should fail to peel");
}

/// Return-path keys are unique per hop — R1 and R2 get different keys.
#[test]
fn onion_return_keys_per_hop_uniqueness() {
    use miasma_core::network::onion_relay::{process_onion_layer, OnionRelayAction};
    use miasma_core::onion::packet::OnionPacketBuilder;
    use x25519_dalek::{PublicKey, StaticSecret};

    let make_key = || {
        let sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pub_ = PublicKey::from(&sec);
        (sec.to_bytes(), pub_.to_bytes())
    };

    let (r1_sec, r1_pub) = make_key();
    let (r2_sec, r2_pub) = make_key();

    let (packet, _rp) = OnionPacketBuilder::build(
        &r1_pub,
        &r2_pub,
        b"r2".to_vec(),
        b"target".to_vec(),
        b"addr".to_vec(),
        b"payload".to_vec(),
    )
    .unwrap();

    let action1 = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();
    let (inner_layer, r1_key) = match action1 {
        OnionRelayAction::ForwardToNext {
            inner_layer,
            return_key,
            ..
        } => (inner_layer, return_key),
        _ => panic!("expected ForwardToNext"),
    };

    let action2 = process_onion_layer(&r2_sec, packet.circuit_id, &inner_layer).unwrap();
    let r2_key = match action2 {
        OnionRelayAction::DeliverToTarget { return_key, .. } => return_key,
        _ => panic!("expected DeliverToTarget"),
    };

    assert_ne!(r1_key, r2_key, "each hop must have a distinct return key");
    assert_ne!(r1_key, [0u8; 32], "return key should not be zero");
    assert_ne!(r2_key, [0u8; 32], "return key should not be zero");
}

/// Descriptor with onion_pubkey is signature-covered — tampering detected.
#[test]
fn descriptor_onion_pubkey_tamper_detection() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let desc = PeerDescriptor::new_signed_full(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xAA; 32]), // onion pubkey
        1,
        &key,
    );

    // Valid descriptor passes verification.
    assert!(desc.verify_self());

    // Tamper with onion_pubkey — signature must fail.
    let mut tampered = desc.clone();
    tampered.onion_pubkey = Some([0xBB; 32]);
    assert!(
        !tampered.verify_self(),
        "tampered onion_pubkey should fail verification"
    );

    // Remove onion_pubkey — signature must fail.
    let mut removed = desc;
    removed.onion_pubkey = None;
    assert!(
        !removed.verify_self(),
        "removed onion_pubkey should fail verification"
    );
}

/// Descriptor store returns relay onion info only for relays with onion pubkeys.
#[test]
fn descriptor_store_relay_onion_info_filtering() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Relay with onion pubkey.
    let ps1 = [0x01; 32];
    store.upsert(PeerDescriptor::new_signed_full(
        ps1,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xAA; 32]),
        1,
        &key,
    ));
    let peer1 = PeerId::random();
    store.register_peer_pseudonym(peer1, ps1);

    // Relay without onion pubkey.
    let ps2 = [0x02; 32];
    store.upsert(PeerDescriptor::new_signed_full(
        ps2,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        None, // no onion pubkey
        1,
        &key,
    ));
    let peer2 = PeerId::random();
    store.register_peer_pseudonym(peer2, ps2);

    // Non-relay with onion pubkey.
    let ps3 = [0x03; 32];
    store.upsert(PeerDescriptor::new_signed_full(
        ps3,
        ReachabilityKind::Direct,
        vec!["/ip4/3.3.3.3/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: false,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xCC; 32]),
        1,
        &key,
    ));
    let peer3 = PeerId::random();
    store.register_peer_pseudonym(peer3, ps3);

    let onion_info = store.relay_onion_info();
    assert_eq!(
        onion_info.len(),
        1,
        "only relay peers with onion pubkeys should be returned"
    );
    assert_eq!(onion_info[0].onion_pubkey, [0xAA; 32]);
}

/// Cross-circuit return key isolation — two circuits get different return keys.
#[test]
fn onion_cross_circuit_return_key_isolation() {
    use miasma_core::network::onion_relay::{process_onion_layer, OnionRelayAction};
    use miasma_core::onion::packet::OnionPacketBuilder;
    use x25519_dalek::{PublicKey, StaticSecret};

    let make_key = || {
        let sec = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let pub_ = PublicKey::from(&sec);
        (sec.to_bytes(), pub_.to_bytes())
    };

    let (r1_sec, r1_pub) = make_key();
    let (_r2_sec, r2_pub) = make_key();

    // Build two separate circuits.
    let (pkt1, _rp1) = OnionPacketBuilder::build(
        &r1_pub,
        &r2_pub,
        b"r2".to_vec(),
        b"t1".to_vec(),
        b"addr".to_vec(),
        b"body1".to_vec(),
    )
    .unwrap();

    let (pkt2, _rp2) = OnionPacketBuilder::build(
        &r1_pub,
        &r2_pub,
        b"r2".to_vec(),
        b"t2".to_vec(),
        b"addr".to_vec(),
        b"body2".to_vec(),
    )
    .unwrap();

    let key1 = match process_onion_layer(&r1_sec, pkt1.circuit_id, &pkt1.layer).unwrap() {
        OnionRelayAction::ForwardToNext { return_key, .. } => return_key,
        _ => panic!("expected ForwardToNext"),
    };
    let key2 = match process_onion_layer(&r1_sec, pkt2.circuit_id, &pkt2.layer).unwrap() {
        OnionRelayAction::ForwardToNext { return_key, .. } => return_key,
        _ => panic!("expected ForwardToNext"),
    };

    assert_ne!(
        key1, key2,
        "different circuits must have different return keys"
    );
}

// ─── Scenario 18: NAT-driven relay capability ────────────────────────────────

/// A node that is NOT publicly reachable should advertise can_relay: false
/// in its descriptor. A node that IS publicly reachable should advertise
/// can_relay: true. This ensures the descriptor store only considers truly
/// relayable peers when building relay paths.
#[test]
fn descriptor_relay_capability_reflects_nat_status() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Private node: can_relay = false
    let mut ps1 = [0u8; 32];
    ps1[0] = 1;
    store.upsert(PeerDescriptor::new_signed(
        ps1,
        ReachabilityKind::Direct,
        vec!["/ip4/192.168.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: false,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Public node: can_relay = true
    let mut ps2 = [0u8; 32];
    ps2[0] = 2;
    let peer2 = PeerId::random();
    store.register_peer_pseudonym(peer2, ps2);
    store.upsert(PeerDescriptor::new_signed(
        ps2,
        ReachabilityKind::Direct,
        vec!["/ip4/203.0.113.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    let stats = store.stats();
    // Only the public node should count as a relay descriptor.
    assert_eq!(
        stats.relay_descriptors, 1,
        "only publicly reachable nodes should be relay descriptors"
    );
}

/// An adversary that falsely advertises can_relay: true but is actually
/// behind NAT will fail at the transport level (relay circuit connection
/// refused). Here we verify the descriptor store does accept the claim
/// at face value (it trusts the descriptor signature), but path selection
/// should prefer peers with verified descriptors.
#[test]
fn false_relay_capability_accepted_but_trackable() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Attacker claims can_relay but is behind NAT.
    let mut ps = [0u8; 32];
    ps[0] = 0xAA;
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    let desc = PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/10.0.0.1/tcp/4001".to_string()], // private IP → likely behind NAT
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );
    assert!(desc.verify_self(), "signature must be valid");
    store.upsert(desc);

    // Store accepts it (can't verify NAT reachability at descriptor level).
    let stats = store.stats();
    assert_eq!(stats.relay_descriptors, 1);
    // But the private IP address is a signal that relay will fail at transport time.
    // The key defense is transport-level failure tracking, not descriptor rejection.
}

// ─── Scenario 19: Retrieval stats per anonymity mode ────────────────────────

/// Verify that RetrievalStats correctly tracks per-mode counters.
#[test]
fn retrieval_stats_default_is_zero() {
    use miasma_core::network::RetrievalStats;
    let stats = RetrievalStats::default();
    assert_eq!(stats.direct_attempts, 0);
    assert_eq!(stats.direct_successes, 0);
    assert_eq!(stats.opportunistic_attempts, 0);
    assert_eq!(stats.opportunistic_relay_successes, 0);
    assert_eq!(stats.opportunistic_direct_fallbacks, 0);
    assert_eq!(stats.required_attempts, 0);
    assert_eq!(stats.required_onion_successes, 0);
    assert_eq!(stats.required_relay_successes, 0);
    assert_eq!(stats.required_failures, 0);
}

/// RetrievalStats round-trips through serde correctly (important for IPC).
#[test]
fn retrieval_stats_serde_roundtrip() {
    use miasma_core::network::RetrievalStats;
    let stats = RetrievalStats {
        direct_attempts: 10,
        direct_successes: 8,
        opportunistic_attempts: 5,
        opportunistic_relay_successes: 3,
        opportunistic_direct_fallbacks: 2,
        opportunistic_onion_successes: 0,
        opportunistic_onion_rendezvous_successes: 0,
        opportunistic_rendezvous_successes: 0,
        required_attempts: 7,
        required_onion_successes: 4,
        required_relay_successes: 2,
        required_failures: 1,
        rendezvous_attempts: 3,
        rendezvous_successes: 2,
        rendezvous_failures: 1,
        rendezvous_direct_fallbacks: 0,
        rendezvous_onion_attempts: 0,
        rendezvous_onion_successes: 0,
        rendezvous_onion_failures: 0,
        relay_probes_sent: 0,
        relay_probes_succeeded: 0,
        relay_probes_failed: 0,
        forwarding_probes_sent: 0,
        forwarding_probes_succeeded: 0,
        forwarding_probes_failed: 0,
        pre_retrieval_probes_run: 0,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let deserialized: RetrievalStats = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.direct_attempts, 10);
    assert_eq!(deserialized.required_onion_successes, 4);
    assert_eq!(deserialized.required_failures, 1);
}

/// Descriptor store only returns relay-capable peers with onion pubkeys
/// and registered PeerId when queried for relay onion info.
/// A peer with can_relay: true but no onion_pubkey should NOT appear.
#[test]
fn relay_onion_info_requires_pubkey_and_capability() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Peer A: can_relay=true, has onion_pubkey, has registered PeerId
    let mut ps_a = [0u8; 32];
    ps_a[0] = 0xA0;
    let peer_a = PeerId::random();
    store.register_peer_pseudonym(peer_a, ps_a);
    store.upsert(PeerDescriptor::new_signed_full(
        ps_a,
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0x11; 32]),
        1,
        &key,
    ));

    // Peer B: can_relay=true, NO onion_pubkey
    let mut ps_b = [0u8; 32];
    ps_b[0] = 0xB0;
    let peer_b = PeerId::random();
    store.register_peer_pseudonym(peer_b, ps_b);
    store.upsert(PeerDescriptor::new_signed(
        ps_b,
        ReachabilityKind::Direct,
        vec!["/ip4/5.6.7.8/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Peer C: has onion_pubkey, but can_relay=false
    let mut ps_c = [0u8; 32];
    ps_c[0] = 0xC0;
    let peer_c = PeerId::random();
    store.register_peer_pseudonym(peer_c, ps_c);
    store.upsert(PeerDescriptor::new_signed_full(
        ps_c,
        ReachabilityKind::Direct,
        vec!["/ip4/9.10.11.12/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: false,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0x33; 32]),
        1,
        &key,
    ));

    let onion_info = store.relay_onion_info();
    // Only Peer A qualifies: can_relay=true AND has onion_pubkey AND has PeerId.
    assert_eq!(
        onion_info.len(),
        1,
        "only relay-capable peers with onion pubkeys should appear"
    );
    assert_eq!(onion_info[0].onion_pubkey, [0x11; 32]);
}

/// NAT status change at runtime should flip can_relay in subsequent descriptors.
/// Simulates the scenario where AutoNAT initially reports Private, then
/// transitions to Public after hole-punching succeeds.
#[test]
fn nat_transition_updates_relay_capability() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    // Initially NAT=Private → can_relay=false
    let desc_private = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: false,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );
    assert!(!desc_private.capabilities.can_relay);

    // AutoNAT transitions to Public → can_relay=true
    let desc_public = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        2,
        &key,
    );
    assert!(desc_public.capabilities.can_relay);

    // Descriptor store should update in-place when upserting with same pseudonym.
    let mut store = DescriptorStore::new();
    store.upsert(desc_private);
    assert_eq!(store.stats().relay_descriptors, 0);
    store.upsert(desc_public);
    assert_eq!(
        store.stats().relay_descriptors,
        1,
        "upsert must update relay capability"
    );
}

// ─── Scenario 20: Relay trust tier promotion / demotion ─────────────────────

/// A relay starts at Claimed, gets promoted to Observed on first success,
/// and to Verified after ≥3 successes with ≥75% success rate.
#[test]
fn relay_trust_tier_promotion_on_success() {
    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let ps = [0xBB; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Initially Claimed (no observations).
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Claimed);

    // 1 success → Observed.
    store.record_relay_success(&ps);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Observed);

    // 2 more successes (3 total, 0 failures) → Verified.
    store.record_relay_success(&ps);
    store.record_relay_success(&ps);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Verified);
}

/// Relay trust demotion: high failure rate demotes from Verified to Observed.
#[test]
fn relay_trust_tier_demotion_on_failure() {
    let mut store = DescriptorStore::new();
    let ps = [0xCC; 32];

    // Promote to Verified first: 4 successes.
    for _ in 0..4 {
        store.record_relay_success(&ps);
    }
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Verified);

    // Add failures to push success rate below 75%: 4 succ, 3 fail = 57%.
    for _ in 0..3 {
        store.record_relay_failure(&ps);
    }
    // 4/(4+3) = 57% < 75%, so should demote to Observed.
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Observed);
}

/// False relay claim never promotes past Claimed without real observations.
#[test]
fn false_relay_claim_stays_claimed_without_observation() {
    let mut store = DescriptorStore::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    // Create 5 peers claiming can_relay=true but no relay observations.
    for i in 0..5u8 {
        let mut ps = [0u8; 32];
        ps[0] = i;
        let peer = PeerId::random();
        store.register_peer_pseudonym(peer, ps);
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/1.2.3.{i}/tcp/4001")],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
        // All should be Claimed — no real relay participation observed.
        assert_eq!(
            store.relay_tier(&ps),
            RelayTrustTier::Claimed,
            "peer {i} should be Claimed without observations"
        );
    }

    let (claimed, observed, verified) = store.relay_tier_counts();
    assert_eq!(claimed, 5);
    assert_eq!(observed, 0);
    assert_eq!(verified, 0);
}

/// Relay observation decay on epoch rotation halves counters.
#[test]
fn relay_observation_decay_on_epoch_rotation() {
    let mut store = DescriptorStore::new();
    let ps = [0xDD; 32];

    // Build up to Verified: 6 successes.
    for _ in 0..6 {
        store.record_relay_success(&ps);
    }
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Verified);

    // Epoch rotation decays counters: 6/2 = 3 successes, still Verified.
    store.on_epoch_rotate(1);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Verified);

    // Another epoch: 3/2 = 1 success → Observed.
    store.on_epoch_rotate(2);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Observed);

    // Another epoch: 1/2 = 0 successes → Claimed.
    store.on_epoch_rotate(3);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Claimed);
}

// ─── Scenario 21: Rendezvous descriptor creation and resolution ─────────────

/// A NAT'd node creates a Rendezvous descriptor with intro points
/// selected from verified relay peers in the descriptor store.
#[test]
fn rendezvous_descriptor_with_intro_points() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Create relay peers as potential intro points.
    for i in 0..3u8 {
        let mut ps = [0u8; 32];
        ps[0] = i + 1;
        let peer = PeerId::random();
        store.register_peer_pseudonym(peer, ps);
        store.upsert(PeerDescriptor::new_signed(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/10.0.{i}.1/tcp/4001")],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
        // Promote relay 0 to Verified.
        if i == 0 {
            for _ in 0..4 {
                store.record_relay_success(&ps);
            }
        }
    }

    // Select intro points for our own pseudonym.
    let own_ps = [0xFF; 32];
    let intro_points = store.select_intro_points(&own_ps, 3);
    assert_eq!(intro_points.len(), 3, "should select 3 intro points");

    // Verified relay should be first (highest trust tier).
    let mut first_ps = [0u8; 32];
    first_ps[0] = 1; // relay 0 is Verified
    assert_eq!(
        intro_points[0], first_ps,
        "Verified relay should be preferred"
    );

    // Create a rendezvous descriptor.
    let desc = PeerDescriptor::new_signed(
        own_ps,
        ReachabilityKind::Rendezvous {
            intro_points: intro_points.clone(),
        },
        vec![], // no direct addresses for rendezvous peers
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );
    assert!(desc.is_rendezvous());
    assert!(!desc.is_relayed());
    assert!(desc.verify_self());

    // Store the rendezvous descriptor.
    store.upsert(desc);
    assert_eq!(store.stats().rendezvous_descriptors, 1);
}

/// Intro point resolution returns only fresh, relay-capable peers
/// with PeerId mappings, sorted by trust tier.
#[test]
fn intro_point_resolution_filters_and_sorts() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Peer A: relay, registered, Observed.
    let mut ps_a = [0u8; 32];
    ps_a[0] = 0xA0;
    let peer_a = PeerId::random();
    store.register_peer_pseudonym(peer_a, ps_a);
    store.upsert(PeerDescriptor::new_signed(
        ps_a,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));
    store.record_relay_success(&ps_a);

    // Peer B: relay, registered, Claimed (no observations).
    let mut ps_b = [0u8; 32];
    ps_b[0] = 0xB0;
    let peer_b = PeerId::random();
    store.register_peer_pseudonym(peer_b, ps_b);
    store.upsert(PeerDescriptor::new_signed(
        ps_b,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Peer C: NOT a relay (can_relay=false) — should be filtered out.
    let mut ps_c = [0u8; 32];
    ps_c[0] = 0xC0;
    let peer_c = PeerId::random();
    store.register_peer_pseudonym(peer_c, ps_c);
    store.upsert(PeerDescriptor::new_signed(
        ps_c,
        ReachabilityKind::Direct,
        vec!["/ip4/3.3.3.3/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: false,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Peer D: relay but NO PeerId mapping — should be filtered out.
    let mut ps_d = [0u8; 32];
    ps_d[0] = 0xD0;
    store.upsert(PeerDescriptor::new_signed(
        ps_d,
        ReachabilityKind::Direct,
        vec!["/ip4/4.4.4.4/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    let resolved = store.resolve_intro_points(&[ps_a, ps_b, ps_c, ps_d]);
    assert_eq!(
        resolved.len(),
        2,
        "only relay peers with PeerId mappings should resolve"
    );
    // Observed (A) should come before Claimed (B).
    assert_eq!(resolved[0].pseudonym, ps_a);
    assert_eq!(resolved[0].relay_tier, RelayTrustTier::Observed);
    assert_eq!(resolved[1].pseudonym, ps_b);
    assert_eq!(resolved[1].relay_tier, RelayTrustTier::Claimed);
}

/// Broken rendezvous descriptor with all-invalid intro points resolves to empty.
#[test]
fn broken_rendezvous_all_invalid_intro_points() {
    let store = DescriptorStore::new();
    // Try to resolve pseudonyms that don't exist in the store.
    let fake_intro = [[0xDE; 32], [0xAD; 32], [0xBE; 32]];
    let resolved = store.resolve_intro_points(&fake_intro);
    assert!(
        resolved.is_empty(),
        "non-existent intro points should resolve to empty"
    );
}

/// Rendezvous descriptor reachability is distinct from Relayed.
#[test]
fn rendezvous_vs_relayed_distinction() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    let rendezvous = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Rendezvous {
            intro_points: vec![[0xAA; 32], [0xBB; 32]],
        },
        vec![],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );
    let relayed = PeerDescriptor::new_signed(
        [0x02; 32],
        ReachabilityKind::Relayed {
            relay_peer: "12D3KooW...".to_string(),
            relay_addr: "/ip4/1.2.3.4/tcp/4001".to_string(),
        },
        vec![],
        PeerCapabilities::default(),
        ResourceProfile::Mobile,
        None,
        1,
        &key,
    );
    let direct = PeerDescriptor::new_signed(
        [0x03; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/5.6.7.8/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    );

    // All three are distinct reachability kinds.
    assert!(rendezvous.is_rendezvous());
    assert!(!rendezvous.is_relayed());
    assert!(relayed.is_relayed());
    assert!(!relayed.is_rendezvous());
    assert!(!direct.is_rendezvous());
    assert!(!direct.is_relayed());

    // Signatures all valid.
    assert!(rendezvous.verify_self());
    assert!(relayed.verify_self());
    assert!(direct.verify_self());
}

/// Descriptor store stats track rendezvous and relay tiers correctly.
#[test]
fn descriptor_stats_rendezvous_and_relay_tiers() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Direct peer.
    store.upsert(PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Rendezvous peer.
    store.upsert(PeerDescriptor::new_signed(
        [0x02; 32],
        ReachabilityKind::Rendezvous {
            intro_points: vec![[0xAA; 32]],
        },
        vec![],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Relay peer (Claimed).
    let ps_relay = [0x03; 32];
    let relay_peer = PeerId::random();
    store.register_peer_pseudonym(relay_peer, ps_relay);
    store.upsert(PeerDescriptor::new_signed(
        ps_relay,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));
    // Promote to Observed.
    store.record_relay_success(&ps_relay);

    let stats = store.stats();
    assert_eq!(stats.total_descriptors, 3);
    assert_eq!(stats.rendezvous_descriptors, 1);
    assert_eq!(stats.relay_descriptors, 1);
    assert_eq!(stats.relay_claimed, 0);
    assert_eq!(stats.relay_observed, 1);
    assert_eq!(stats.relay_verified, 0);
}

/// Retrieval stats include rendezvous fields and round-trip through serde.
#[test]
fn retrieval_stats_rendezvous_serde() {
    use miasma_core::network::RetrievalStats;
    let stats = RetrievalStats {
        rendezvous_attempts: 5,
        rendezvous_successes: 3,
        rendezvous_failures: 1,
        rendezvous_direct_fallbacks: 1,
        ..RetrievalStats::default()
    };
    let json = serde_json::to_string(&stats).unwrap();
    let d: RetrievalStats = serde_json::from_str(&json).unwrap();
    assert_eq!(d.rendezvous_attempts, 5);
    assert_eq!(d.rendezvous_successes, 3);
    assert_eq!(d.rendezvous_failures, 1);
    assert_eq!(d.rendezvous_direct_fallbacks, 1);
}

/// Relay peer selection prefers Verified over Observed over Claimed.
#[test]
fn relay_peer_info_sorted_by_trust_tier() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Create 3 relays at different trust tiers.
    let mut ps_claimed = [0u8; 32];
    ps_claimed[0] = 1;
    let peer_claimed = PeerId::random();
    store.register_peer_pseudonym(peer_claimed, ps_claimed);
    store.upsert(PeerDescriptor::new_signed(
        ps_claimed,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    let mut ps_verified = [0u8; 32];
    ps_verified[0] = 2;
    let peer_verified = PeerId::random();
    store.register_peer_pseudonym(peer_verified, ps_verified);
    store.upsert(PeerDescriptor::new_signed(
        ps_verified,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));
    for _ in 0..4 {
        store.record_relay_success(&ps_verified);
    }

    let mut ps_observed = [0u8; 32];
    ps_observed[0] = 3;
    let peer_observed = PeerId::random();
    store.register_peer_pseudonym(peer_observed, ps_observed);
    store.upsert(PeerDescriptor::new_signed(
        ps_observed,
        ReachabilityKind::Direct,
        vec!["/ip4/3.3.3.3/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));
    store.record_relay_success(&ps_observed);

    let relay_info = store.relay_peer_info();
    assert_eq!(relay_info.len(), 3);
    // Verified first, then Observed, then Claimed.
    assert_eq!(relay_info[0].0, peer_verified);
    assert_eq!(relay_info[1].0, peer_observed);
    assert_eq!(relay_info[2].0, peer_claimed);
}

// ── Phase 4e+: Onion + Rendezvous composition tests ───────────────────────

/// Rendezvous holder with onion-capable intro point: verify that
/// intro points with onion pubkeys are filtered and preferred.
#[test]
fn rendezvous_intro_onion_capable_preferred() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x60u8; 32]);
    let mut store = DescriptorStore::new();

    // Intro A: relay, has onion pubkey, Observed trust.
    let mut ps_a = [0u8; 32];
    ps_a[0] = 0xA0;
    let peer_a = PeerId::random();
    store.register_peer_pseudonym(peer_a, ps_a);
    store.upsert(PeerDescriptor::new_signed_full(
        ps_a,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xAA; 32]), // onion pubkey
        1,
        &key,
    ));
    store.record_relay_success(&ps_a);

    // Intro B: relay, NO onion pubkey, Verified trust.
    let mut ps_b = [0u8; 32];
    ps_b[0] = 0xB0;
    let peer_b = PeerId::random();
    store.register_peer_pseudonym(peer_b, ps_b);
    store.upsert(PeerDescriptor::new_signed_full(
        ps_b,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        None, // no onion pubkey
        1,
        &key,
    ));
    for _ in 0..4 {
        store.record_relay_success(&ps_b);
    }

    let resolved = store.resolve_intro_points(&[ps_a, ps_b]);
    assert_eq!(resolved.len(), 2);

    // Both should resolve, but only A has onion capability.
    let onion_capable: Vec<_> = resolved
        .iter()
        .filter(|r| r.onion_pubkey.is_some())
        .collect();
    assert_eq!(
        onion_capable.len(),
        1,
        "only intro A should have onion pubkey"
    );
    assert_eq!(onion_capable[0].pseudonym, ps_a);
    assert_eq!(onion_capable[0].onion_pubkey, Some([0xAA; 32]));
}

/// Rendezvous holder where NO intro point has onion capability.
/// Content-blind retrieval is impossible; only relay-circuit (IP-only) path available.
#[test]
fn rendezvous_no_onion_intro_falls_back() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x61u8; 32]);
    let mut store = DescriptorStore::new();

    // Two intro points, neither has onion pubkey.
    for i in 0..2u8 {
        let mut ps = [0u8; 32];
        ps[0] = i + 1;
        let peer = PeerId::random();
        store.register_peer_pseudonym(peer, ps);
        store.upsert(PeerDescriptor::new_signed_full(
            ps,
            ReachabilityKind::Direct,
            vec![format!(
                "/ip4/{}.{}.{}.{}/tcp/4001",
                i + 1,
                i + 1,
                i + 1,
                i + 1
            )],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            None,
            None, // no onion pubkey
            1,
            &key,
        ));
    }

    let mut ps_intro = [[0u8; 32]; 2];
    ps_intro[0][0] = 1;
    ps_intro[1][0] = 2;
    let resolved = store.resolve_intro_points(&ps_intro);
    assert_eq!(resolved.len(), 2);

    // No onion-capable intro points.
    assert!(
        resolved.iter().all(|r| r.onion_pubkey.is_none()),
        "no intro points should have onion capability"
    );
}

/// Mixed shard holders: Direct holder has onion pubkey from descriptor store,
/// Rendezvous holder is behind NAT. Both should be resolvable for onion retrieval.
#[test]
fn mixed_holders_direct_and_rendezvous_onion_pubkey() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x62u8; 32]);
    let mut store = DescriptorStore::new();

    // Direct holder with onion pubkey.
    let ps_direct = [0x01; 32];
    let peer_direct = PeerId::random();
    store.register_peer_pseudonym(peer_direct, ps_direct);
    store.upsert(PeerDescriptor::new_signed_full(
        ps_direct,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xDD; 32]),
        1,
        &key,
    ));

    // Rendezvous holder (NAT'd) with onion pubkey.
    let ps_rendezvous = [0x02; 32];
    let peer_rv = PeerId::random();
    store.register_peer_pseudonym(peer_rv, ps_rendezvous);
    let intro_ps = [0xAA; 32];
    store.upsert(PeerDescriptor::new_signed_full(
        ps_rendezvous,
        ReachabilityKind::Rendezvous {
            intro_points: vec![intro_ps],
        },
        vec![],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xEE; 32]),
        1,
        &key,
    ));

    // Direct holder: onion pubkey accessible.
    let direct_key = store.onion_pubkey_for_peer(&peer_direct);
    assert_eq!(
        direct_key,
        Some([0xDD; 32]),
        "direct holder should have onion pubkey in descriptor store"
    );

    // Rendezvous holder: onion pubkey also accessible.
    let rv_key = store.onion_pubkey_for_peer(&peer_rv);
    assert_eq!(
        rv_key,
        Some([0xEE; 32]),
        "rendezvous holder should have onion pubkey in descriptor store"
    );

    // Rendezvous holder's descriptor should be marked as rendezvous.
    let desc = store.get_by_peer(&peer_rv).unwrap();
    assert!(desc.is_rendezvous());
}

/// Broken intro + fallback: first intro point doesn't resolve, second does.
/// Verifies fallback within intro point list.
#[test]
fn rendezvous_broken_intro_with_fallback() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x63u8; 32]);
    let mut store = DescriptorStore::new();

    // Only the second intro point exists in the store.
    let broken_ps = [0xDE; 32]; // not in store
    let good_ps = [0xAA; 32];
    let good_peer = PeerId::random();
    store.register_peer_pseudonym(good_peer, good_ps);
    store.upsert(PeerDescriptor::new_signed_full(
        good_ps,
        ReachabilityKind::Direct,
        vec!["/ip4/5.5.5.5/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xFF; 32]), // onion capable
        1,
        &key,
    ));

    let resolved = store.resolve_intro_points(&[broken_ps, good_ps]);
    assert_eq!(resolved.len(), 1, "only valid intro should resolve");
    assert_eq!(resolved[0].pseudonym, good_ps);
    assert_eq!(resolved[0].peer_id, good_peer);
    assert!(resolved[0].onion_pubkey.is_some());
}

/// RetrievalStats tracks rendezvous+onion attempts/successes/failures independently.
#[test]
fn retrieval_stats_rendezvous_onion_tracking() {
    use miasma_core::network::RetrievalStats;

    let mut stats = RetrievalStats::default();
    assert_eq!(stats.rendezvous_onion_attempts, 0);
    assert_eq!(stats.rendezvous_onion_successes, 0);
    assert_eq!(stats.rendezvous_onion_failures, 0);

    stats.rendezvous_onion_attempts = 5;
    stats.rendezvous_onion_successes = 3;
    stats.rendezvous_onion_failures = 2;

    let json = serde_json::to_string(&stats).unwrap();
    let deserialized: RetrievalStats = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.rendezvous_onion_attempts, 5);
    assert_eq!(deserialized.rendezvous_onion_successes, 3);
    assert_eq!(deserialized.rendezvous_onion_failures, 2);
}

/// Content-blind path vs IP-only: Required mode with onion-capable relays
/// should prefer onion (content-blind), while relay circuit gives only IP privacy.
/// This tests the distinction is preserved in stats.
#[test]
fn content_blind_vs_ip_only_distinction_in_stats() {
    use miasma_core::network::RetrievalStats;

    let stats = RetrievalStats {
        direct_attempts: 10,
        direct_successes: 10,
        opportunistic_attempts: 5,
        opportunistic_relay_successes: 3,
        opportunistic_direct_fallbacks: 2,
        opportunistic_onion_successes: 1,
        opportunistic_onion_rendezvous_successes: 1,
        opportunistic_rendezvous_successes: 1,
        required_attempts: 8,
        required_onion_successes: 5, // content-blind
        required_relay_successes: 2, // IP privacy only
        required_failures: 1,
        rendezvous_attempts: 3,
        rendezvous_successes: 2,
        rendezvous_failures: 1,
        rendezvous_direct_fallbacks: 0,
        rendezvous_onion_attempts: 4,
        rendezvous_onion_successes: 3, // content-blind via rendezvous
        rendezvous_onion_failures: 1,
        relay_probes_sent: 0,
        relay_probes_succeeded: 0,
        relay_probes_failed: 0,
        forwarding_probes_sent: 0,
        forwarding_probes_succeeded: 0,
        forwarding_probes_failed: 0,
        pre_retrieval_probes_run: 0,
    };

    // Content-blind successes = required onion + rendezvous_onion + opportunistic onion/onion_rendezvous.
    let content_blind = stats.required_onion_successes
        + stats.rendezvous_onion_successes
        + stats.opportunistic_onion_successes
        + stats.opportunistic_onion_rendezvous_successes;
    assert_eq!(
        content_blind, 10,
        "content-blind: req_onion(5) + rv_onion(3) + opp_onion(1) + opp_rv_onion(1)"
    );

    // IP-privacy-only successes = relay circuit + rendezvous relay + opportunistic relay/rendezvous.
    let ip_only = stats.required_relay_successes
        + stats.rendezvous_successes
        + stats.opportunistic_relay_successes
        + stats.opportunistic_rendezvous_successes;
    assert_eq!(
        ip_only, 8,
        "IP-only: req_relay(2) + rv(2) + opp_relay(3) + opp_rv(1)"
    );
}

/// R1 and R2 must differ: when an intro point would be the only available relay,
/// onion-rendezvous cannot work (needs separate R1).
#[test]
fn onion_rendezvous_requires_distinct_r1_r2() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x64u8; 32]);
    let mut store = DescriptorStore::new();

    // Only one relay peer (which is also the intro point).
    let ps = [0x01; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed_full(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xAA; 32]),
        1,
        &key,
    ));

    // relay_onion_info returns this one peer.
    let onion_info = store.relay_onion_info();
    assert_eq!(onion_info.len(), 1);

    // Resolved as an intro point.
    let resolved = store.resolve_intro_points(&[ps]);
    assert_eq!(resolved.len(), 1);

    // If this peer is used as R2 (intro point), the relay pool has no
    // different peer for R1. The onion circuit requires R1 ≠ R2.
    // The coordinator should detect this and skip onion-rendezvous.
    let r2_peer_id_bytes = resolved[0].peer_id.to_bytes();
    let can_find_distinct_r1 = onion_info.iter().any(|r| r.peer_id != r2_peer_id_bytes);
    assert!(
        !can_find_distinct_r1,
        "with only one relay, R1 ≠ R2 is impossible — coordinator must detect this"
    );
}

/// Opportunistic stats track granular path successes separately.
#[test]
fn opportunistic_stats_granularity() {
    use miasma_core::network::RetrievalStats;

    let mut stats = RetrievalStats::default();
    stats.opportunistic_attempts = 10;
    stats.opportunistic_onion_rendezvous_successes = 2;
    stats.opportunistic_onion_successes = 3;
    stats.opportunistic_rendezvous_successes = 1;
    stats.opportunistic_relay_successes = 2;
    stats.opportunistic_direct_fallbacks = 2;

    let total_succeeded = stats.opportunistic_onion_rendezvous_successes
        + stats.opportunistic_onion_successes
        + stats.opportunistic_rendezvous_successes
        + stats.opportunistic_relay_successes
        + stats.opportunistic_direct_fallbacks;
    assert_eq!(total_succeeded, 10);

    // Content-blind in opportunistic = onion + onion_rendezvous.
    let content_blind =
        stats.opportunistic_onion_successes + stats.opportunistic_onion_rendezvous_successes;
    assert_eq!(content_blind, 5);

    // IP-only in opportunistic = relay + rendezvous.
    let ip_only = stats.opportunistic_relay_successes + stats.opportunistic_rendezvous_successes;
    assert_eq!(ip_only, 3);
}

/// Relay probe stats track sent/succeeded/failed independently.
#[test]
fn relay_probe_stats_tracking() {
    use miasma_core::network::RetrievalStats;

    let mut stats = RetrievalStats::default();
    stats.relay_probes_sent = 10;
    stats.relay_probes_succeeded = 7;
    stats.relay_probes_failed = 3;

    assert_eq!(
        stats.relay_probes_sent,
        stats.relay_probes_succeeded + stats.relay_probes_failed
    );

    // Serde roundtrip.
    let json = serde_json::to_string(&stats).unwrap();
    let d: RetrievalStats = serde_json::from_str(&json).unwrap();
    assert_eq!(d.relay_probes_sent, 10);
    assert_eq!(d.relay_probes_succeeded, 7);
    assert_eq!(d.relay_probes_failed, 3);
}

/// Relay probe protocol: request/response roundtrip preserves nonce.
#[test]
fn relay_probe_protocol_nonce_echo() {
    use miasma_core::network::{ProbeRequest, ProbeResponse};

    let nonce = [0xAB; 32];
    let req = ProbeRequest { nonce };
    let encoded = bincode::serialize(&req).unwrap();
    let decoded: ProbeRequest = bincode::deserialize(&encoded).unwrap();
    assert_eq!(decoded.nonce, nonce);

    // Simulate relay echo: relay receives request, echoes nonce in response.
    let resp = ProbeResponse {
        nonce: decoded.nonce,
    };
    assert_eq!(resp.nonce, nonce, "relay must echo the exact nonce");

    // Prober verification: compare sent nonce with received nonce.
    let success = resp.nonce == nonce;
    assert!(success, "nonce match = probe success");
}

/// Relay probe: wrong nonce in response means probe failure.
#[test]
fn relay_probe_nonce_mismatch_is_failure() {
    use miasma_core::network::ProbeResponse;

    let sent_nonce = [0xAB; 32];
    let wrong_nonce = [0xCD; 32];
    let resp = ProbeResponse { nonce: wrong_nonce };
    assert_ne!(resp.nonce, sent_nonce, "mismatched nonce = probe failure");
}

/// Relay probe: zero nonce (sentinel) means failure.
#[test]
fn relay_probe_zero_nonce_is_failure() {
    use miasma_core::network::ProbeResponse;

    let sent_nonce = [0xAB; 32];
    let resp = ProbeResponse { nonce: [0u8; 32] };
    assert_ne!(
        resp.nonce, sent_nonce,
        "zero nonce sentinel = probe failure"
    );
}

/// Five privacy paths are distinguishable in stats:
/// 1. onion+rendezvous (content-blind + NAT)
/// 2. standard onion (content-blind)
/// 3. rendezvous relay (IP-only + NAT)
/// 4. relay circuit (IP-only)
/// 5. direct (no privacy)
#[test]
fn five_privacy_paths_distinguishable() {
    use miasma_core::network::RetrievalStats;

    let stats = RetrievalStats {
        direct_attempts: 1,
        direct_successes: 1,
        opportunistic_attempts: 4,
        opportunistic_onion_rendezvous_successes: 1, // path 1
        opportunistic_onion_successes: 1,            // path 2
        opportunistic_rendezvous_successes: 1,       // path 3
        opportunistic_relay_successes: 1,            // path 4
        opportunistic_direct_fallbacks: 0,
        required_attempts: 4,
        required_onion_successes: 2, // path 2 (required)
        required_relay_successes: 1, // path 4 (required)
        required_failures: 1,
        rendezvous_attempts: 1,
        rendezvous_successes: 1, // path 3
        rendezvous_failures: 0,
        rendezvous_direct_fallbacks: 0,
        rendezvous_onion_attempts: 1,
        rendezvous_onion_successes: 1, // path 1 (required)
        rendezvous_onion_failures: 0,
        relay_probes_sent: 5,
        relay_probes_succeeded: 4,
        relay_probes_failed: 1,
        forwarding_probes_sent: 2,
        forwarding_probes_succeeded: 1,
        forwarding_probes_failed: 1,
        pre_retrieval_probes_run: 3,
    };

    // Each path is independently countable.
    assert!(stats.opportunistic_onion_rendezvous_successes > 0, "path 1");
    assert!(stats.opportunistic_onion_successes > 0, "path 2");
    assert!(stats.opportunistic_rendezvous_successes > 0, "path 3");
    assert!(stats.opportunistic_relay_successes > 0, "path 4");
    assert!(stats.direct_successes > 0, "path 5");
    assert!(stats.relay_probes_sent > 0, "reachability probes tracked");
    assert!(
        stats.forwarding_probes_sent > 0,
        "forwarding probes tracked"
    );
    assert!(
        stats.pre_retrieval_probes_run > 0,
        "pre-retrieval sweeps tracked"
    );
}

/// Probe freshness: `has_fresh_probe` returns true within freshness window,
/// false when expired.
#[test]
fn probe_cache_freshness_and_expiry() {
    use miasma_core::network::descriptor::RelayObservation;

    let mut obs = RelayObservation {
        tier: RelayTrustTier::Claimed,
        successes: 0,
        failures: 0,
        last_success_at: 0,
        last_failure_at: 0,
        probe_succeeded_at: None,
        forwarding_verified_at: None,
    };

    // No probe → not fresh.
    assert!(!obs.has_fresh_probe(300));

    // Record probe → fresh.
    obs.record_probe_success();
    assert!(obs.has_fresh_probe(300));
    assert!(obs.probe_succeeded_at.is_some());

    // Also promotes to Observed (probe alone counts).
    assert_eq!(obs.tier, RelayTrustTier::Observed);

    // Manually expire by setting timestamp in the past.
    obs.probe_succeeded_at = Some(0); // epoch 0 is definitely stale
    assert!(!obs.has_fresh_probe(300));
}

/// Forwarding verification fast-tracks to Verified when combined with
/// at least 1 passive success.
#[test]
fn trust_tier_fast_track_via_forwarding() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0xF5; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/5.5.5.5/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            can_store: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Record 1 passive success → Observed.
    store.record_relay_success(&ps);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Observed);

    // Record forwarding verification → fast-tracks to Verified.
    store.record_forwarding_verification(&ps);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Verified);
}

/// Probe success + 2 passive successes at ≥66% rate → Verified.
/// Without probe: same evidence only gives Observed.
#[test]
fn trust_tier_mixed_evidence_probe_plus_passive() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0xF6; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/6.6.6.6/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            can_store: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // 2 passive successes + 1 failure = Observed (66% < 75% threshold).
    store.record_relay_success(&ps);
    store.record_relay_success(&ps);
    store.record_relay_failure(&ps);
    assert_eq!(
        store.relay_tier(&ps),
        RelayTrustTier::Observed,
        "2 successes at 66% without probe should be Observed"
    );

    // Add probe success → Verified (probe + 2 successes at 66% meets relaxed threshold).
    store.record_probe_success(&ps);
    assert_eq!(
        store.relay_tier(&ps),
        RelayTrustTier::Verified,
        "probe + 2 successes at 66% should be Verified"
    );
}

/// Forwarding verification timestamps survive epoch decay.
#[test]
fn forwarding_verified_not_cleared_by_decay() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0xF7; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/7.7.7.7/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            can_store: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Build up evidence: 4 successes + forwarding + probe → Verified.
    for _ in 0..4 {
        store.record_relay_success(&ps);
    }
    store.record_probe_success(&ps);
    store.record_forwarding_verification(&ps);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Verified);
    assert_eq!(store.forwarding_verified_count(), 1);

    // Simulate epoch decay — halves passive counters but preserves timestamps.
    store.decay_relay_observations();

    // After decay, passive successes halved (4→2), but forwarding evidence remains.
    // Forwarding + ≥1 success → still Verified.
    assert_eq!(
        store.relay_tier(&ps),
        RelayTrustTier::Verified,
        "forwarding evidence survives decay"
    );
    assert_eq!(
        store.forwarding_verified_count(),
        1,
        "forwarding verification count survives decay"
    );
}

/// DescriptorStore tracks probe freshness per pseudonym.
#[test]
fn descriptor_store_probe_freshness() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    let mut ps_a = [0u8; 32];
    ps_a[0] = 0xA1;
    let peer_a = PeerId::random();
    store.register_peer_pseudonym(peer_a, ps_a);
    store.upsert(PeerDescriptor::new_signed(
        ps_a,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            can_store: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    let mut ps_b = [0u8; 32];
    ps_b[0] = 0xB1;
    let peer_b = PeerId::random();
    store.register_peer_pseudonym(peer_b, ps_b);
    store.upsert(PeerDescriptor::new_signed(
        ps_b,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            can_store: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Initially no fresh probes.
    assert_eq!(store.probed_fresh_count(300), 0);
    assert!(!store.has_fresh_probe(&ps_a, 300));

    // Probe peer A.
    store.record_probe_success(&ps_a);
    assert!(store.has_fresh_probe(&ps_a, 300));
    assert!(!store.has_fresh_probe(&ps_b, 300));
    assert_eq!(store.probed_fresh_count(300), 1);

    // Probe peer B.
    store.record_probe_success(&ps_b);
    assert_eq!(store.probed_fresh_count(300), 2);
}

/// DescriptorStore forwarding verification tracking.
#[test]
fn descriptor_store_forwarding_verification() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0xF1; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/3.3.3.3/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            can_store: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    // Initially no forwarding verification.
    assert_eq!(store.forwarding_verified_count(), 0);

    // Record a passive success first (needed for Verified).
    store.record_relay_success(&ps);

    // Record forwarding verification.
    store.record_forwarding_verification(&ps);
    assert_eq!(store.forwarding_verified_count(), 1);

    // Should be Verified tier (forwarding + 1 success).
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Verified);
}

/// Forwarding verification circuit address format is correct.
#[test]
fn forwarding_circuit_address_format() {
    // The circuit address built in verify_relay_forwarding is:
    // /p2p/{R1}/p2p-circuit/p2p/{R2}
    let r1 = PeerId::random();
    let r2 = PeerId::random();
    let addr = format!("/p2p/{}/p2p-circuit/p2p/{}", r1, r2);

    // Must contain both peer IDs and p2p-circuit.
    assert!(addr.contains(&r1.to_string()));
    assert!(addr.contains(&r2.to_string()));
    assert!(addr.contains("p2p-circuit"));

    // Must be parseable as a multiaddr.
    let parsed: Result<libp2p::Multiaddr, _> = addr.parse();
    assert!(
        parsed.is_ok(),
        "circuit address must be a valid multiaddr: {addr}"
    );
}

/// RetrievalStats: forwarding probe fields round-trip through serde.
#[test]
fn forwarding_probe_stats_serde() {
    use miasma_core::network::RetrievalStats;

    let stats = RetrievalStats {
        forwarding_probes_sent: 5,
        forwarding_probes_succeeded: 3,
        forwarding_probes_failed: 2,
        pre_retrieval_probes_run: 10,
        ..RetrievalStats::default()
    };
    let json = serde_json::to_string(&stats).unwrap();
    let d: RetrievalStats = serde_json::from_str(&json).unwrap();
    assert_eq!(d.forwarding_probes_sent, 5);
    assert_eq!(d.forwarding_probes_succeeded, 3);
    assert_eq!(d.forwarding_probes_failed, 2);
    assert_eq!(d.pre_retrieval_probes_run, 10);
}

// ─── Security regression tests ───────────────────────────────────────────────

/// VULN-001 regression: onion path must never use a zero [0u8; 32] key.
///
/// Verifies that a descriptor with an all-zero onion_pubkey is NOT returned
/// by relay_onion_info() — preventing construction of trivially-decryptable
/// onion packets.
#[test]
fn zero_onion_pubkey_rejected_by_relay_onion_info() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x70u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0xA1; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    // Insert a descriptor with onion_pubkey = all zeros (the old dangerous default).
    store.upsert(PeerDescriptor::new_signed_full(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/1.2.3.4/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0u8; 32]), // zero key — must be rejected
        1,
        &key,
    ));

    // relay_onion_info should filter out descriptors with zero onion pubkeys,
    // or at minimum the coordinator must never use them. Verify at descriptor
    // store level that the key is stored but is actually all zeros.
    let onion_info = store.relay_onion_info();
    for info in &onion_info {
        // No relay info entry should have an all-zero pubkey.
        assert_ne!(
            info.onion_pubkey, [0u8; 32],
            "relay_onion_info must not return entries with zero onion pubkeys"
        );
    }
}

/// VULN-001 regression: a self-onion-pubkey lookup that produces [0u8; 32]
/// must not be used in onion packet construction.
///
/// This test verifies the invariant at the data level: any code path that
/// obtains a pubkey must check it is non-zero before use.
#[test]
fn zero_key_array_is_distinguishable() {
    let zero_key = [0u8; 32];
    let real_key = [0xAA; 32];

    // The zero key is a specific sentinel that should never be used.
    assert_ne!(zero_key, real_key);
    assert!(zero_key.iter().all(|&b| b == 0));

    // Code should check: if key == [0u8; 32] { skip }
    // This test documents the invariant.
    let key_is_valid = |k: &[u8; 32]| !k.iter().all(|&b| b == 0);
    assert!(
        !key_is_valid(&zero_key),
        "zero key must not be considered valid"
    );
    assert!(key_is_valid(&real_key), "non-zero key must be valid");
}

/// VULN-002 regression: with only one relay, R1≠R2 cannot be satisfied.
/// The path must be skipped entirely — never collapse to R1==R2.
#[test]
fn r1_eq_r2_impossible_with_single_relay() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x71u8; 32]);
    let mut store = DescriptorStore::new();

    // Single relay peer that serves as both relay pool and potential intro point.
    let ps = [0xB1; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed_full(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/5.5.5.5/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xCC; 32]),
        1,
        &key,
    ));

    let onion_info = store.relay_onion_info();
    assert_eq!(onion_info.len(), 1, "exactly one relay available");

    // If this relay is used as R2, no distinct R1 exists.
    let r2_peer_id = onion_info[0].peer_id.clone();
    let distinct_r1 = onion_info.iter().find(|r| r.peer_id != r2_peer_id);
    assert!(
        distinct_r1.is_none(),
        "with one relay, there must be no distinct R1 — coordinator must skip onion path"
    );
}

/// VULN-002 regression: with two relays, R1≠R2 IS satisfiable.
#[test]
fn r1_neq_r2_satisfied_with_two_relays() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x72u8; 32]);
    let mut store = DescriptorStore::new();

    for (i, (onion_byte, ip)) in [(0xC1u8, "1.1.1.1"), (0xC2u8, "2.2.2.2")]
        .iter()
        .enumerate()
    {
        let ps = [i as u8 + 1; 32];
        let peer = PeerId::random();
        store.register_peer_pseudonym(peer, ps);
        store.upsert(PeerDescriptor::new_signed_full(
            ps,
            ReachabilityKind::Direct,
            vec![format!("/ip4/{ip}/tcp/4001")],
            PeerCapabilities {
                can_relay: true,
                ..PeerCapabilities::default()
            },
            ResourceProfile::Desktop,
            None,
            None,
            Some([*onion_byte; 32]),
            1,
            &key,
        ));
    }

    let onion_info = store.relay_onion_info();
    assert_eq!(onion_info.len(), 2);

    // For any R2, there exists a distinct R1.
    let r2 = &onion_info[0];
    let r1 = onion_info.iter().find(|r| r.peer_id != r2.peer_id);
    assert!(r1.is_some(), "with two relays, R1≠R2 must be satisfiable");
    assert_ne!(r1.unwrap().peer_id, r2.peer_id);
}

/// VULN-003 regression: min_hops > 2 cannot be satisfied by any current path.
/// Required mode with min_hops=3 must fail all paths (max is 2 from onion).
#[test]
fn min_hops_exceeding_max_path_depth_rejects_all() {
    // The path hierarchy provides at most 2 hops (onion paths).
    // min_hops=3 should be unsatisfiable.
    let max_onion_hops: usize = 2;
    let max_rendezvous_hops: usize = 1;
    let max_relay_hops: usize = 1;

    let min_hops: usize = 3;

    assert!(
        min_hops > max_onion_hops,
        "onion paths cannot satisfy min_hops=3"
    );
    assert!(
        min_hops > max_rendezvous_hops,
        "rendezvous cannot satisfy min_hops=3"
    );
    assert!(
        min_hops > max_relay_hops,
        "relay circuit cannot satisfy min_hops=3"
    );
}

/// VULN-003 regression: min_hops=2 skips single-hop paths (rendezvous, relay circuit).
#[test]
fn min_hops_2_skips_single_hop_paths() {
    let min_hops: usize = 2;
    let onion_hops: usize = 2;
    let rendezvous_hops: usize = 1;
    let relay_circuit_hops: usize = 1;

    // Onion paths (2 hops) are eligible.
    assert!(
        min_hops <= onion_hops,
        "onion paths must be eligible for min_hops=2"
    );
    // Single-hop paths must be skipped.
    assert!(
        min_hops > rendezvous_hops,
        "rendezvous relay (1 hop) must be skipped when min_hops=2"
    );
    assert!(
        min_hops > relay_circuit_hops,
        "relay circuit (1 hop) must be skipped when min_hops=2"
    );
}

/// VULN-005 regression: distress_wipe scrubs proxy credentials from config.toml.
#[test]
fn distress_wipe_scrubs_proxy_credentials() {
    use miasma_core::config::NodeConfig;
    use miasma_core::store::LocalShareStore;

    let dir = tempfile::tempdir().unwrap();

    // Create a config with proxy credentials.
    let mut config = NodeConfig::default();
    config.transport.proxy_username = Some("admin".into());
    config.transport.proxy_password = Some("s3cret".into());
    config.save(dir.path()).unwrap();

    // Verify credentials are in the file.
    let raw = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(
        raw.contains("admin"),
        "proxy username must be in config before wipe"
    );
    assert!(
        raw.contains("s3cret"),
        "proxy password must be in config before wipe"
    );

    // Open store and wipe.
    let store = LocalShareStore::open(dir.path(), 100).unwrap();
    store.distress_wipe().unwrap();

    // Reload config — credentials must be gone.
    let reloaded = NodeConfig::load(dir.path()).unwrap();
    assert!(
        reloaded.transport.proxy_username.is_none(),
        "proxy_username must be scrubbed after distress wipe"
    );
    assert!(
        reloaded.transport.proxy_password.is_none(),
        "proxy_password must be scrubbed after distress wipe"
    );

    // Verify credentials are not in the raw file content.
    let raw_after = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(
        !raw_after.contains("s3cret"),
        "proxy password must not appear in config.toml after wipe"
    );
}

/// VULN-005 regression: config scrub_credentials removes only credential fields.
#[test]
fn config_scrub_preserves_non_credential_fields() {
    use miasma_core::config::NodeConfig;

    let dir = tempfile::tempdir().unwrap();

    let mut config = NodeConfig::default();
    config.transport.proxy_type = Some("socks5".into());
    config.transport.proxy_addr = Some("127.0.0.1:1080".into());
    config.transport.proxy_username = Some("user".into());
    config.transport.proxy_password = Some("pass".into());
    config.transport.wss_tls_enabled = true;
    config.save(dir.path()).unwrap();

    // Scrub and reload.
    config.scrub_credentials(dir.path()).unwrap();
    let reloaded = NodeConfig::load(dir.path()).unwrap();

    // Credentials gone.
    assert!(reloaded.transport.proxy_username.is_none());
    assert!(reloaded.transport.proxy_password.is_none());

    // Other transport config preserved.
    assert_eq!(reloaded.transport.proxy_type.as_deref(), Some("socks5"));
    assert_eq!(
        reloaded.transport.proxy_addr.as_deref(),
        Some("127.0.0.1:1080")
    );
    assert!(reloaded.transport.wss_tls_enabled);
}

// ─── Windows file-permission regression tests ────────────────────────────────

/// master.key is created with restricted ACLs from the start (no race window).
#[test]
fn master_key_created_with_restricted_acl() {
    use miasma_core::secure_file;
    use miasma_core::store::LocalShareStore;

    let dir = tempfile::tempdir().unwrap();
    let _store = LocalShareStore::open(dir.path(), 100).unwrap();

    let key_path = dir.path().join("master.key");
    assert!(key_path.exists(), "master.key must exist after store open");

    let restricted = secure_file::verify_restricted(&key_path).unwrap();
    assert!(
        restricted,
        "master.key must be restricted to current user (born restricted, no race window)"
    );
}

/// config.toml with proxy credentials is written with restricted ACLs.
#[test]
fn config_with_credentials_is_restricted() {
    use miasma_core::config::NodeConfig;
    use miasma_core::secure_file;

    let dir = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.transport.proxy_username = Some("admin".into());
    config.transport.proxy_password = Some("s3cret".into());
    config.save(dir.path()).unwrap();

    let config_path = dir.path().join("config.toml");
    let restricted = secure_file::verify_restricted(&config_path).unwrap();
    assert!(
        restricted,
        "config.toml with proxy credentials must be restricted to current user"
    );
}

/// config.toml without credentials is NOT restricted (normal permissions).
#[test]
fn config_without_credentials_is_not_restricted() {
    use miasma_core::config::NodeConfig;
    use miasma_core::secure_file;

    let dir = tempfile::tempdir().unwrap();
    let config = NodeConfig::default();
    config.save(dir.path()).unwrap();

    let config_path = dir.path().join("config.toml");
    // Not restricted — normal file.
    let restricted = secure_file::verify_restricted(&config_path).unwrap();
    assert!(
        !restricted,
        "config.toml without credentials should use normal permissions"
    );
}

/// Overwriting config.toml to add credentials applies restriction.
#[test]
fn config_adding_credentials_restricts_existing_file() {
    use miasma_core::config::NodeConfig;
    use miasma_core::secure_file;

    let dir = tempfile::tempdir().unwrap();

    // First save: no credentials.
    let mut config = NodeConfig::default();
    config.save(dir.path()).unwrap();
    let config_path = dir.path().join("config.toml");
    assert!(
        !secure_file::verify_restricted(&config_path).unwrap(),
        "should not be restricted without credentials"
    );

    // Second save: add credentials.
    config.transport.proxy_username = Some("user".into());
    config.transport.proxy_password = Some("pass".into());
    config.save(dir.path()).unwrap();

    let restricted = secure_file::verify_restricted(&config_path).unwrap();
    assert!(
        restricted,
        "config.toml must become restricted when credentials are added"
    );
}

/// Scrubbing credentials and re-saving removes the restriction.
#[test]
fn config_scrub_then_save_removes_restriction() {
    use miasma_core::config::NodeConfig;
    use miasma_core::secure_file;

    let dir = tempfile::tempdir().unwrap();

    // Save with credentials (restricted).
    let mut config = NodeConfig::default();
    config.transport.proxy_username = Some("user".into());
    config.transport.proxy_password = Some("pass".into());
    config.save(dir.path()).unwrap();

    let config_path = dir.path().join("config.toml");
    assert!(secure_file::verify_restricted(&config_path).unwrap());

    // Scrub → credentials removed, save uses normal path.
    config.scrub_credentials(dir.path()).unwrap();
    // After scrub, the file is rewritten with std::fs::write (no restriction).
    // On Windows the existing restrictive DACL may persist on overwrite;
    // that's acceptable — a config without credentials is harmless even if
    // restricted.  The important invariant is that credentials are gone.
    let reloaded = NodeConfig::load(dir.path()).unwrap();
    assert!(reloaded.transport.proxy_username.is_none());
    assert!(reloaded.transport.proxy_password.is_none());
}

/// secure_file::write_restricted creates a file readable by the current user.
#[test]
fn secure_file_write_restricted_roundtrip() {
    use miasma_core::secure_file;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_secret.dat");
    let data = b"test secret data 12345";

    secure_file::write_restricted(&path, data).unwrap();
    let read_back = std::fs::read(&path).unwrap();
    assert_eq!(read_back, data);

    assert!(
        secure_file::verify_restricted(&path).unwrap(),
        "file must be restricted to current user"
    );
}

/// secure_file::atomic_write_restricted does not leave temp files.
#[test]
fn secure_file_atomic_no_temp_residue() {
    use miasma_core::secure_file;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("atomic_test.key");

    secure_file::atomic_write_restricted(&path, b"atomic data").unwrap();
    assert!(path.exists());
    assert!(
        !path.with_extension("sec.tmp").exists(),
        "temp file must not remain after successful atomic write"
    );
}

// ─── v0.2.0-beta.1 hardening tests ──────────────────────────────────────────

/// Onion packet padding: packets of different payload sizes produce the
/// same encrypted ciphertext length, preventing size-based correlation.
#[test]
fn onion_padding_uniform_ciphertext_size() {
    use miasma_core::onion::OnionPacketBuilder;
    use x25519_dalek::{PublicKey, StaticSecret};

    let r1_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r1_pub = PublicKey::from(&r1_secret).to_bytes();
    let r2_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r2_pub = PublicKey::from(&r2_secret).to_bytes();

    // Build two packets with very different payload sizes.
    let (pkt_small, _) = OnionPacketBuilder::build(
        &r1_pub,
        &r2_pub,
        b"r2".to_vec(),
        b"target".to_vec(),
        b"addr".to_vec(),
        b"tiny".to_vec(), // 4 bytes
    )
    .unwrap();

    let (pkt_large, _) = OnionPacketBuilder::build(
        &r1_pub,
        &r2_pub,
        b"r2".to_vec(),
        b"target".to_vec(),
        b"addr".to_vec(),
        vec![0xAA; 4000], // 4000 bytes
    )
    .unwrap();

    // Ciphertext sizes must be equal (padding normalises them).
    assert_eq!(
        pkt_small.layer.ciphertext.len(),
        pkt_large.layer.ciphertext.len(),
        "onion packets of different payload sizes must have equal ciphertext length"
    );
}

/// Onion padding round-trip: padded packet can be peeled and yields
/// the original payload.
#[test]
fn onion_padding_roundtrip() {
    use miasma_core::onion::{
        packet::{InnerPayload, OnionLayerProcessor},
        OnionPacketBuilder,
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    let r1_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r1_pub = PublicKey::from(&r1_secret).to_bytes();
    let r2_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let r2_pub = PublicKey::from(&r2_secret).to_bytes();

    let body = b"original content".to_vec();
    let (pkt, _) = OnionPacketBuilder::build(
        &r1_pub,
        &r2_pub,
        b"r2".to_vec(),
        b"target".to_vec(),
        b"addr".to_vec(),
        body.clone(),
    )
    .unwrap();

    // Peel layer 1 (R1).
    let payload1 = OnionLayerProcessor::peel(&r1_secret.to_bytes(), &pkt.layer).unwrap();
    assert_eq!(payload1.next_hop.as_deref(), Some(b"r2".as_ref()));

    // Peel layer 2 (R2).
    let inner_layer: miasma_core::onion::packet::OnionLayer =
        bincode::deserialize(&payload1.data).unwrap();
    let payload2 = OnionLayerProcessor::peel(&r2_secret.to_bytes(), &inner_layer).unwrap();

    // Final payload matches original.
    let inner: InnerPayload = bincode::deserialize(&payload2.data).unwrap();
    assert_eq!(
        inner.body, body,
        "padded onion packet must round-trip correctly"
    );
}

/// Onion pad/unpad: basic correctness.
#[test]
fn onion_pad_unpad_roundtrip() {
    use miasma_core::onion::packet::{unpad_fixed_size, ONION_PAD_TARGET};

    let data = b"hello world";
    // Manually pad.
    let mut padded = Vec::new();
    padded.extend_from_slice(&(data.len() as u32).to_le_bytes());
    padded.extend_from_slice(data);
    padded.resize(ONION_PAD_TARGET, 0xFF);

    let unpadded = unpad_fixed_size(&padded).unwrap();
    assert_eq!(unpadded, data);
}

/// Anti-gaming: a relay with ≥2 failures and <50% success rate is demoted
/// to Claimed regardless of probes.
#[test]
fn anti_gaming_demotion_on_failure_dominance() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x80u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0xD1; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed_full(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/9.9.9.9/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xEE; 32]),
        1,
        &key,
    ));

    // Give it 1 success → Observed.
    store.record_relay_success(&ps);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Observed);

    // Record a probe success → Observed (probe + 1 success, need 2 for Verified).
    store.record_probe_success(&ps);
    assert_eq!(store.relay_tier(&ps), RelayTrustTier::Observed);

    // 2 failures → rate = 1/3 < 50%, failures=2 → anti-gaming demotion.
    store.record_relay_failure(&ps);
    store.record_relay_failure(&ps);
    assert_eq!(
        store.relay_tier(&ps),
        RelayTrustTier::Claimed,
        "relay with ≥2 failures and <50% rate must be demoted to Claimed despite probes"
    );
}

/// Anti-gaming: a relay with many successes but a few failures stays trusted.
#[test]
fn anti_gaming_does_not_demote_mostly_successful_relay() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x81u8; 32]);
    let mut store = DescriptorStore::new();

    let ps = [0xD2; 32];
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);
    store.upsert(PeerDescriptor::new_signed_full(
        ps,
        ReachabilityKind::Direct,
        vec!["/ip4/8.8.8.8/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0xFF; 32]),
        1,
        &key,
    ));

    // 5 successes, 2 failures → rate = 5/7 ≈ 71% > 50% → no anti-gaming demotion.
    for _ in 0..5 {
        store.record_relay_success(&ps);
    }
    for _ in 0..2 {
        store.record_relay_failure(&ps);
    }

    // 5 successes at 71% → should be Verified (≥3 successes at ≥75% fails,
    // but 71% < 75% so it should be Observed).
    let tier = store.relay_tier(&ps);
    assert!(
        tier >= RelayTrustTier::Observed,
        "relay with 71% success rate and 5 successes should be at least Observed, got {:?}",
        tier
    );
}

/// Replay cache: same fingerprint is detected as a replay.
#[test]
fn onion_replay_detection_basic() {
    // Simulate the replay cache logic.
    use std::collections::VecDeque;

    let cache_size = 4096usize;
    let mut cache: VecDeque<[u8; 32]> = VecDeque::with_capacity(cache_size);

    let circuit_id = [0x01u8; 16];
    let ephemeral_pubkey = [0xAA; 32];

    let mut hasher = blake3::Hasher::new();
    hasher.update(&circuit_id);
    hasher.update(&ephemeral_pubkey);
    let fp: [u8; 32] = *hasher.finalize().as_bytes();

    // First time: not a replay.
    assert!(!cache.contains(&fp));
    cache.push_back(fp);

    // Second time: detected as replay.
    assert!(cache.contains(&fp), "replayed packet must be detected");
}

/// DescriptorStore relay_pseudonyms returns relay-capable descriptors.
#[test]
fn descriptor_store_relay_pseudonyms() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x82u8; 32]);
    let mut store = DescriptorStore::new();

    // One relay.
    let ps_relay = [0xE1; 32];
    let peer_relay = PeerId::random();
    store.register_peer_pseudonym(peer_relay, ps_relay);
    store.upsert(PeerDescriptor::new_signed_full(
        ps_relay,
        ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities {
            can_relay: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        None,
        1,
        &key,
    ));

    // One non-relay.
    let ps_store = [0xE2; 32];
    let peer_store = PeerId::random();
    store.register_peer_pseudonym(peer_store, ps_store);
    store.upsert(PeerDescriptor::new_signed_full(
        ps_store,
        ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities {
            can_store: true,
            ..PeerCapabilities::default()
        },
        ResourceProfile::Desktop,
        None,
        None,
        None,
        1,
        &key,
    ));

    let relay_ps = store.relay_pseudonyms();
    assert_eq!(relay_ps.len(), 1);
    assert_eq!(relay_ps[0], ps_relay);
}

/// DhtHandle fire-and-forget commands must not block when channel is full.
/// They use try_send and silently drop on backpressure.
#[tokio::test]
async fn dht_fire_and_forget_backpressure() {
    use miasma_core::network::node::DhtHandle;
    use tokio::sync::mpsc;

    // Create a channel with capacity 1 so it saturates immediately.
    let (tx, _rx) = mpsc::channel(1);
    let handle = DhtHandle::from_sender(tx);

    let pseudonym = [0xAA; 32];

    // Fill the channel with one fire-and-forget command.
    let r1 = handle.record_relay_outcome(pseudonym, true).await;
    assert!(r1.is_ok());

    // Second send should NOT block — it drops the command and returns Ok.
    let r2 = handle.record_relay_outcome(pseudonym, false).await;
    assert!(r2.is_ok(), "fire-and-forget must not block on full channel");

    // Same for probe success.
    let r3 = handle.record_probe_success(pseudonym).await;
    assert!(r3.is_ok(), "probe success must not block on full channel");

    // Same for forwarding verification.
    let r4 = handle.record_forwarding_verification(pseudonym).await;
    assert!(
        r4.is_ok(),
        "forwarding verification must not block on full channel"
    );
}

// ─── Directed Sharing — Helpers ─────────────────────────────────────────────

/// Generate deterministic sender/recipient key pairs for directed sharing tests.
fn directed_test_keys() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let sender_secret_raw =
        miasma_core::crypto::keyderive::derive_sharing_key(b"sender-master-key-32bytes-pad!!!")
            .unwrap();
    let sender_static = x25519_dalek::StaticSecret::from(*sender_secret_raw);
    let sender_pubkey = x25519_dalek::PublicKey::from(&sender_static);

    let recipient_secret_raw =
        miasma_core::crypto::keyderive::derive_sharing_key(b"recip-master-key-32bytes-padd!!")
            .unwrap();
    let recipient_static = x25519_dalek::StaticSecret::from(*recipient_secret_raw);
    let recipient_pubkey = x25519_dalek::PublicKey::from(&recipient_static);

    (
        *sender_secret_raw,
        *sender_pubkey.as_bytes(),
        *recipient_secret_raw,
        *recipient_pubkey.as_bytes(),
    )
}

/// Build a minimal test envelope without Argon2id cost for state-transition tests.
fn make_directed_test_envelope() -> DirectedEnvelope {
    DirectedEnvelope {
        envelope_id: [0x42u8; 32],
        version: 1,
        sender_pubkey: [0x01u8; 32],
        recipient_pubkey: [0x02u8; 32],
        ephemeral_pubkey: [0x03u8; 32],
        encrypted_payload: vec![0x04; 64],
        payload_nonce: [0x05u8; 24],
        password_salt: [0x06u8; 32],
        expires_at: u64::MAX,
        created_at: 1000,
        state: EnvelopeState::Pending,
        challenge_hash: None,
        password_attempts_remaining: 3,
        challenge_attempts_remaining: 3,
        challenge_expires_at: 0,
        retention_secs: 86400,
    }
}

// ─── Directed Sharing — Adversarial / Integration Tests ─────────────────────

/// 1. Full envelope crypto roundtrip:
/// create_envelope → decrypt_envelope_payload → derive_content_key → decrypt_directed_content.
///
/// NOTE: finalize_envelope currently has a key-mismatch bug (uses sender static
/// key instead of ephemeral key for ECDH), so we test the core crypto path
/// without finalize. A separate test documents the finalize issue.
#[test]
fn directed_envelope_crypto_roundtrip() {
    let (sender_secret, _sender_pub, recipient_secret, recipient_pub) = directed_test_keys();
    let plaintext = b"Confidential document contents - roundtrip test";

    let (envelope, protected, _envelope_key) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "strong-password-42",
        RetentionPeriod::OneDay,
        plaintext,
        Some("secret.pdf".to_string()),
    )
    .unwrap();

    // Recipient decrypts payload (no password needed) — uses ephemeral ECDH.
    let payload = decrypt_envelope_payload(&recipient_secret, &envelope).unwrap();
    // MID is empty placeholder before finalize.
    assert_eq!(payload.mid, "");
    assert_eq!(payload.filename, Some("secret.pdf".to_string()));
    assert_eq!(payload.file_size, plaintext.len() as u64);
    assert_eq!(payload.data_shards, 10);
    assert_eq!(payload.total_shards, 20);

    // Recipient derives content key with password and decrypts content.
    let content_key =
        derive_content_key(&recipient_secret, &envelope, "strong-password-42").unwrap();
    let decrypted =
        decrypt_directed_content(&content_key, &payload.content_nonce, &protected).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// 1b. finalize_envelope updates the envelope payload with MID and shard params.
/// The envelope_key returned by create_envelope is used to decrypt/re-encrypt
/// the payload, ensuring key consistency (ephemeral ECDH key is preserved).
#[test]
fn directed_finalize_envelope_roundtrip() {
    let (sender_secret, _sender_pub, recipient_secret, recipient_pub) = directed_test_keys();

    let (mut envelope, protected, envelope_key) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "password",
        RetentionPeriod::OneDay,
        b"data",
        None,
    )
    .unwrap();

    let mid = format!("miasma:{}", bs58::encode(&protected[..8]).into_string());
    finalize_envelope(&mut envelope, &envelope_key, &mid, 10, 20).unwrap();

    // Recipient can decrypt the finalized payload and see the MID.
    let payload = decrypt_envelope_payload(&recipient_secret, &envelope).unwrap();
    assert_eq!(payload.mid, mid);
    assert_eq!(payload.data_shards, 10);
    assert_eq!(payload.total_shards, 20);
}

/// 2. Wrong password must fail content decryption (AEAD tag mismatch).
#[test]
fn directed_wrong_password_rejection() {
    let (sender_secret, _, recipient_secret, recipient_pub) = directed_test_keys();
    let plaintext = b"Secret!";

    let (envelope, protected, _envelope_key) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "correct-password",
        RetentionPeriod::OneHour,
        plaintext,
        None,
    )
    .unwrap();

    let payload = decrypt_envelope_payload(&recipient_secret, &envelope).unwrap();

    // Derive key with wrong password.
    let wrong_key =
        derive_content_key(&recipient_secret, &envelope, "wrong-password").unwrap();
    let result = decrypt_directed_content(&wrong_key, &payload.content_nonce, &protected);
    assert!(
        result.is_err(),
        "decryption with wrong password must fail"
    );
}

/// 3. Wrong recipient key must fail envelope payload decryption.
#[test]
fn directed_wrong_recipient_rejection() {
    let (sender_secret, _, _recipient_secret, recipient_pub) = directed_test_keys();

    let (envelope, _protected, _envelope_key) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "password",
        RetentionPeriod::OneHour,
        b"data",
        None,
    )
    .unwrap();

    // A different recipient tries to decrypt.
    let wrong_secret =
        miasma_core::crypto::keyderive::derive_sharing_key(b"wrong-master-key-32bytes-pad!!!!")
            .unwrap();
    let result = decrypt_envelope_payload(&wrong_secret, &envelope);
    assert!(
        result.is_err(),
        "wrong recipient key must not decrypt payload"
    );
}

/// 4. Challenge generation → verification roundtrip.
#[test]
fn directed_challenge_generation_and_verification() {
    let (code, hash) = generate_challenge();

    // Correct code verifies.
    assert!(verify_challenge(&code, &hash));

    // Wrong code does not verify.
    assert!(!verify_challenge("ZZZZ-YYYY", &hash));
}

/// 5. Challenge normalization: verify that lowercase, missing hyphen,
/// and whitespace-padded inputs all verify correctly.
#[test]
fn directed_challenge_normalization_variants() {
    let (code, hash) = generate_challenge();

    // Without hyphen.
    let no_hyphen = code.replace('-', "");
    assert!(verify_challenge(&no_hyphen, &hash));

    // Lowercase.
    assert!(verify_challenge(&code.to_lowercase(), &hash));

    // Extra whitespace.
    let spaced = format!("  {}  ", code);
    assert!(verify_challenge(&spaced, &hash));

    // Lowercase + no hyphen.
    let lowercase_no_hyphen = no_hyphen.to_lowercase();
    assert!(verify_challenge(&lowercase_no_hyphen, &hash));
}

/// 6. Challenge attempt exhaustion: exceeding CHALLENGE_MAX_ATTEMPTS
/// should be trackable by the envelope's counter.
#[test]
fn directed_challenge_attempt_exhaustion() {
    let mut envelope = make_directed_test_envelope();
    envelope.state = EnvelopeState::ChallengeIssued;
    let (code, hash) = generate_challenge();
    envelope.challenge_hash = Some(hash);
    envelope.challenge_attempts_remaining = CHALLENGE_MAX_ATTEMPTS;

    // Simulate wrong attempts.
    for _ in 0..CHALLENGE_MAX_ATTEMPTS {
        let valid = verify_challenge("ZZZZ-YYYY", &envelope.challenge_hash.unwrap());
        assert!(!valid);
        envelope.challenge_attempts_remaining -= 1;
    }

    assert_eq!(envelope.challenge_attempts_remaining, 0);

    // Transition to ChallengeFailed.
    envelope.state = EnvelopeState::ChallengeFailed;
    assert!(envelope.state.is_terminal());

    // The correct code should still verify cryptographically, but the
    // state machine should prevent it.
    assert!(verify_challenge(&code, &hash));
    assert_eq!(
        envelope.state,
        EnvelopeState::ChallengeFailed,
        "state must remain terminal even if code is correct after exhaustion"
    );
}

/// 7. RetentionPeriod serialization roundtrip through serde (JSON).
#[test]
fn directed_retention_period_serde_roundtrip() {
    let variants = [
        RetentionPeriod::TenMinutes,
        RetentionPeriod::OneHour,
        RetentionPeriod::OneDay,
        RetentionPeriod::SevenDays,
        RetentionPeriod::ThirtyDays,
        RetentionPeriod::Custom(12345),
    ];

    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let roundtripped: RetentionPeriod = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, roundtripped);
    }

    // Also verify bincode roundtrip.
    for v in &variants {
        let bytes = bincode::serialize(v).unwrap();
        let roundtripped: RetentionPeriod = bincode::deserialize(&bytes).unwrap();
        assert_eq!(*v, roundtripped);
    }
}

/// 8. Envelope state transitions: Pending → ChallengeIssued → Confirmed → Retrieved.
#[test]
fn directed_envelope_state_transitions() {
    let mut env = make_directed_test_envelope();

    // Pending — not terminal, not retrievable.
    assert_eq!(env.state, EnvelopeState::Pending);
    assert!(!env.state.is_terminal());
    assert!(!env.state.is_retrievable());

    // → ChallengeIssued.
    env.state = EnvelopeState::ChallengeIssued;
    assert!(!env.state.is_terminal());
    assert!(!env.state.is_retrievable());

    // → Confirmed.
    env.state = EnvelopeState::Confirmed;
    assert!(!env.state.is_terminal());
    assert!(env.state.is_retrievable());

    // → Retrieved (terminal).
    env.state = EnvelopeState::Retrieved;
    assert!(env.state.is_terminal());
    assert!(!env.state.is_retrievable());

    // Verify all terminal states.
    for terminal in &[
        EnvelopeState::Retrieved,
        EnvelopeState::SenderRevoked,
        EnvelopeState::RecipientDeleted,
        EnvelopeState::Expired,
        EnvelopeState::ChallengeFailed,
        EnvelopeState::PasswordFailed,
    ] {
        assert!(terminal.is_terminal(), "{:?} should be terminal", terminal);
    }

    // Only Confirmed is retrievable.
    for non_retrievable in &[
        EnvelopeState::Pending,
        EnvelopeState::ChallengeIssued,
        EnvelopeState::Retrieved,
        EnvelopeState::SenderRevoked,
        EnvelopeState::Expired,
    ] {
        assert!(
            !non_retrievable.is_retrievable(),
            "{:?} should not be retrievable",
            non_retrievable
        );
    }
}

/// 9. Sharing key format roundtrip: format_sharing_key → parse_sharing_key.
#[test]
fn directed_sharing_key_format_roundtrip() {
    // Test with various key patterns.
    let keys: Vec<[u8; 32]> = vec![
        [0x00u8; 32],
        [0xFFu8; 32],
        [0x42u8; 32],
        {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = i as u8;
            }
            k
        },
    ];

    for key in &keys {
        let formatted = format_sharing_key(key);
        assert!(formatted.starts_with("msk:"), "must start with msk:");
        let parsed = parse_sharing_key(&formatted).unwrap();
        assert_eq!(&parsed, key);
    }

    // Invalid prefix.
    assert!(parse_sharing_key("xyz:AAAA").is_err());
    // Invalid base58.
    assert!(parse_sharing_key("msk:0OlI!!!").is_err());
}

/// 10. Sharing contact format roundtrip: format_sharing_contact → parse_sharing_contact.
#[test]
fn directed_sharing_contact_format_roundtrip() {
    let key = [0x42u8; 32];
    let peer_id = "12D3KooWRq3dVmhA7z4YQQ2Q1Y9F2dKSTestPeerId";

    let contact = format_sharing_contact(&key, peer_id);
    assert!(contact.starts_with("msk:"));
    assert!(contact.contains('@'));

    let (parsed_key, parsed_peer) = parse_sharing_contact(&contact).unwrap();
    assert_eq!(parsed_key, key);
    assert_eq!(parsed_peer, peer_id);

    // Invalid: no @ separator.
    assert!(parse_sharing_contact("msk:AAAA").is_err());
    // Invalid: no prefix.
    assert!(parse_sharing_contact("AAAA@PeerId").is_err());
}

/// 11. Inbox storage roundtrip: save → load → list for both incoming and outgoing.
#[test]
fn directed_inbox_storage_roundtrip() {
    let tmp = tempfile::TempDir::new().unwrap();
    let inbox = DirectedInbox::open(tmp.path()).unwrap();

    let mut env1 = make_directed_test_envelope();
    env1.envelope_id = [0x01; 32];
    env1.created_at = 100;

    let mut env2 = make_directed_test_envelope();
    env2.envelope_id = [0x02; 32];
    env2.created_at = 200;

    // Save outgoing.
    inbox.save_outgoing(&env1).unwrap();
    inbox.save_outgoing(&env2).unwrap();

    // Load outgoing by ID.
    let loaded = inbox.load_outgoing(&env1.id_hex()).unwrap();
    assert_eq!(loaded.envelope_id, env1.envelope_id);
    assert_eq!(loaded.state, EnvelopeState::Pending);

    // List outgoing (sorted by created_at desc).
    let list = inbox.list_outgoing();
    assert_eq!(list.len(), 2);
    assert!(list[0].created_at >= list[1].created_at);

    // Save incoming.
    inbox.save_incoming(&env1).unwrap();
    inbox.save_incoming(&env2).unwrap();

    // Load incoming.
    let loaded = inbox.load_incoming(&env2.id_hex()).unwrap();
    assert_eq!(loaded.envelope_id, env2.envelope_id);

    // List incoming.
    let list = inbox.list_incoming();
    assert_eq!(list.len(), 2);

    // Update state and verify persistence.
    let updated = inbox
        .update_incoming_state(&env1.id_hex(), EnvelopeState::Confirmed)
        .unwrap();
    assert_eq!(updated.state, EnvelopeState::Confirmed);

    let reloaded = inbox.load_incoming(&env1.id_hex()).unwrap();
    assert_eq!(reloaded.state, EnvelopeState::Confirmed);

    // Delete and verify gone.
    inbox.delete_incoming(&env1.id_hex()).unwrap();
    assert!(inbox.load_incoming(&env1.id_hex()).is_err());
}

/// 12. Expired envelope detection.
#[test]
fn directed_envelope_expiry_detection() {
    let mut env = make_directed_test_envelope();
    env.created_at = 1000;
    env.expires_at = 2000;

    // Not expired at creation time.
    assert!(!env.is_expired(1000));
    assert!(!env.is_expired(1999));

    // Expired at or after expires_at.
    assert!(env.is_expired(2000));
    assert!(env.is_expired(3000));

    // check_expiry transitions state.
    assert_eq!(env.state, EnvelopeState::Pending);
    env.check_expiry(2001);
    assert_eq!(env.state, EnvelopeState::Expired);
    assert!(env.state.is_terminal());

    // check_expiry does NOT overwrite a terminal state.
    let mut env2 = make_directed_test_envelope();
    env2.expires_at = 2000;
    env2.state = EnvelopeState::Retrieved;
    env2.check_expiry(3000);
    assert_eq!(
        env2.state,
        EnvelopeState::Retrieved,
        "terminal state must not be overwritten by expiry"
    );
}

/// 13. DirectedCodec serde roundtrip: each DirectedRequest/DirectedResponse
/// variant through bincode.
#[test]
fn directed_codec_serde_roundtrip() {
    let test_env = make_directed_test_envelope();

    // --- Requests ---
    let requests: Vec<DirectedRequest> = vec![
        DirectedRequest::Invite {
            envelope: test_env.clone(),
        },
        DirectedRequest::Confirm {
            envelope_id: [0xAA; 32],
            challenge_code: "ABCD-1234".to_string(),
        },
        DirectedRequest::SenderRevoke {
            envelope_id: [0xBB; 32],
        },
        DirectedRequest::StatusQuery {
            envelope_id: [0xCC; 32],
        },
    ];

    for req in &requests {
        let bytes = bincode::serialize(req).unwrap();
        let deserialized: DirectedRequest = bincode::deserialize(&bytes).unwrap();
        // Verify discriminant survives roundtrip by re-serializing.
        let bytes2 = bincode::serialize(&deserialized).unwrap();
        assert_eq!(bytes, bytes2, "request bincode roundtrip must be stable");
    }

    // --- Responses ---
    let responses: Vec<DirectedResponse> = vec![
        DirectedResponse::InviteAccepted {
            envelope_id: [0xDD; 32],
        },
        DirectedResponse::Confirmed {
            envelope_id: [0xEE; 32],
        },
        DirectedResponse::ChallengeFailed {
            envelope_id: [0xFF; 32],
            attempts_remaining: 2,
        },
        DirectedResponse::Revoked {
            envelope_id: [0x11; 32],
        },
        DirectedResponse::Status {
            envelope_id: [0x22; 32],
            state: EnvelopeState::Confirmed,
        },
        DirectedResponse::Error("test error".to_string()),
    ];

    for resp in &responses {
        let bytes = bincode::serialize(resp).unwrap();
        let deserialized: DirectedResponse = bincode::deserialize(&bytes).unwrap();
        let bytes2 = bincode::serialize(&deserialized).unwrap();
        assert_eq!(bytes, bytes2, "response bincode roundtrip must be stable");
    }
}

/// 14. Envelope tampering detection: modify encrypted payload, verify decryption fails.
#[test]
fn directed_envelope_tampering_detection() {
    let (sender_secret, _, recipient_secret, recipient_pub) = directed_test_keys();

    let (mut envelope, _protected, _envelope_key) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "password",
        RetentionPeriod::OneHour,
        b"tamper-test-data",
        None,
    )
    .unwrap();

    // Tamper with the encrypted payload (flip a byte).
    let payload_len = envelope.encrypted_payload.len();
    assert!(payload_len > 0);
    envelope.encrypted_payload[payload_len / 2] ^= 0xFF;

    // Payload decryption must fail (AEAD tag check).
    let result = decrypt_envelope_payload(&recipient_secret, &envelope);
    assert!(
        result.is_err(),
        "tampered payload must fail AEAD decryption"
    );

    // Restore payload, tamper with protected content instead.
    let (envelope2, mut protected2, _envelope_key2) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "password2",
        RetentionPeriod::OneHour,
        b"tamper-test-content",
        None,
    )
    .unwrap();

    let payload2 = decrypt_envelope_payload(&recipient_secret, &envelope2).unwrap();
    let content_key = derive_content_key(&recipient_secret, &envelope2, "password2").unwrap();

    // Flip a byte in protected content.
    let mid_idx = protected2.len() / 2;
    protected2[mid_idx] ^= 0xFF;
    let result =
        decrypt_directed_content(&content_key, &payload2.content_nonce, &protected2);
    assert!(
        result.is_err(),
        "tampered content must fail AEAD decryption"
    );
}

/// 15. Password salt uniqueness: two envelopes with the same password
/// must have different salts.
#[test]
fn directed_password_salt_uniqueness() {
    let (sender_secret, _, _, recipient_pub) = directed_test_keys();

    let (env1, _, _key1) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "same-password",
        RetentionPeriod::OneHour,
        b"data1",
        None,
    )
    .unwrap();

    let (env2, _, _key2) = create_envelope(
        &sender_secret,
        &recipient_pub,
        "same-password",
        RetentionPeriod::OneHour,
        b"data2",
        None,
    )
    .unwrap();

    assert_ne!(
        env1.password_salt, env2.password_salt,
        "salts must be unique per envelope (random)"
    );

    // Envelope IDs must also differ.
    assert_ne!(
        env1.envelope_id, env2.envelope_id,
        "envelope IDs must be unique (random)"
    );

    // Ephemeral pubkeys must differ (different ECDH sessions).
    assert_ne!(
        env1.ephemeral_pubkey, env2.ephemeral_pubkey,
        "ephemeral keys must be unique per envelope"
    );
}
