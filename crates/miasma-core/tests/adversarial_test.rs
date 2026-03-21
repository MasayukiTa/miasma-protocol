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
use miasma_core::network::credential::{
    self, CredentialIssuer, CredentialPresentation, CredentialTier,
    EphemeralIdentity, CAP_ROUTE, CAP_STORE,
};
use miasma_core::network::descriptor::{
    DescriptorStore, PeerCapabilities, PeerDescriptor, ReachabilityKind,
    RelayTrustTier, ResourceProfile,
};
use miasma_core::network::bbs_credential::{
    bbs_create_proof, bbs_verify_proof, BbsCredentialWallet, BbsIssuer, BbsIssuerKey,
    BbsCredentialAttributes, DisclosurePolicy, generate_link_secret,
};
use miasma_core::network::metrics::OutcomeMetrics;
use miasma_core::network::path_selection::{AnonymityPolicy, PathSelector};
use miasma_core::network::peer_state::PeerRegistry;
use miasma_core::network::routing::{IpPrefix, RoutingTable};

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

    assert_eq!(admitted, 3, "only MAX_PEERS_PER_IPV4_SLASH16 should be admitted");
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
    let all_peers: Vec<PeerId> = attacker_peers.iter()
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
        matches!(result.unwrap_err(), credential::CredentialError::ExpiredEpoch { .. }),
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
    assert_eq!(ranked[0], honest, "honest peer with real successes should rank above attacker with failures");
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
            for _ in 0..5 { rt.record_success(&peer); }
            peer
        })
        .collect();

    // 9 attacker peers (3 per /16, diversity capped at 3).
    let attacker: Vec<PeerId> = (0..9)
        .map(|_| PeerId::random())
        .collect();

    // Only 3 attackers can get into different /16s.
    for (i, &peer) in attacker.iter().take(3).enumerate() {
        rt.add_peer(peer, IpPrefix::V4Slash16([10 + i as u8, 0]));
    }

    let all: Vec<PeerId> = honest.iter().chain(attacker.iter().take(3)).copied().collect();
    let ranked = rt.rank_peers(&all, |id| {
        if honest.contains(id) { AddressTrust::Verified } else { AddressTrust::Observed }
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
    assert!(!decision.admitted, "below minimum PoW should always be rejected");
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
    assert!(!decision.admitted, "mobile sybil without credential should fail");
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
    assert!(decision.admitted, "legitimate mobile with credential should pass");
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
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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

    assert!(result.is_err(), "same-prefix relays should not satisfy 2-hop diversity");
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
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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
    ).unwrap();

    assert!(path.hop_count() >= 3);
    // Verify all hops have different prefixes.
    let prefixes = path.prefixes();
    let unique: std::collections::HashSet<_> = prefixes.iter().collect();
    assert_eq!(prefixes.len(), unique.len(), "all hops should have unique prefixes");
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
    assert!(rt.current_difficulty() > 8, "difficulty should increase with network size");

    // Large network: difficulty should be substantial.
    for _ in 0..30 {
        rt.observe_network_size(500);
    }
    rt.maybe_adjust_difficulty();
    assert!(rt.current_difficulty() >= 20, "large network should require high PoW");
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
    assert!(hashes_at_20 > 1_000_000_000, "Sybil cost should be > 1B hashes");
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
    assert!(result.is_err(), "BBS+ proof replayed with wrong context should fail");
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
    assert!(result.is_err(), "tampered disclosed tier should break Schnorr proof");
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
    assert_ne!(proof1.challenge, proof2.challenge, "challenge should differ");
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
            vec![format!("/ip4/{}.{}.{}.1/tcp/4001", (i >> 16) as u8, (i >> 8) as u8, i as u8)],
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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
    assert!(!decision.admitted, "constrained device below PoW floor should be rejected");
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
    assert!(decision.admitted, "peer at exact threshold should be admitted");
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
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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

    assert!(result.is_err(), "hostile relay set from one /16 should fail required 3-hop path");
}

/// Opportunistic policy should gracefully degrade with hostile relay set.
#[test]
fn path_selection_opportunistic_degrades_gracefully() {
    let store = DescriptorStore::new(); // no relays at all
    let rt = RoutingTable::new(true);

    let path = PathSelector::select(
        [0xFF; 32],
        AnonymityPolicy::Opportunistic,
        &store,
        &rt,
    ).unwrap();

    assert!(path.is_direct(), "opportunistic with no relays should fall back to direct");
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
    assert!(!desc.verify_self(), "tampered descriptor should fail self-verification");
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
    assert!(!desc.verify_self(), "pubkey-swapped descriptor should fail verification");
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
    assert!(!store.upsert(desc), "stale descriptor should be rejected on insert");
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
            vec![format!("/ip4/10.{}.{}.{}/tcp/4001", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)],
            PeerCapabilities::default(),
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
    }

    assert!(store.len() <= 10_000, "store should enforce capacity limit: got {}", store.len());
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
    let presentation = CredentialPresentation::create(
        &cred,
        &identity,
        context,
    );

    // Verify against new epoch — should fail.
    let issuers = vec![issuer.pubkey_bytes()];
    let result = credential::verify_presentation(
        &presentation,
        context,
        &issuers,
        new_epoch,
        CredentialTier::Verified,
    );
    assert!(result.is_err(), "credential from old epoch should be rejected in new epoch");
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
            ps, ReachabilityKind::Direct, vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
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
            ps, ReachabilityKind::Direct, vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
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
            ps, ReachabilityKind::Direct, vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
        ));
    }

    store.on_epoch_rotate(2);

    // Add a new descriptor.
    let mut ps = [0u8; 32];
    ps[0] = 50;
    store.upsert(PeerDescriptor::new_signed(
        ps, ReachabilityKind::Direct, vec!["/ip4/10.50.1.1/tcp/4001".into()],
        PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
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
        ps1, ReachabilityKind::Direct, vec!["/ip4/1.1.1.1/tcp/4001".into()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));
    store.upsert(PeerDescriptor::new_signed(
        ps2, ReachabilityKind::Direct, vec!["/ip4/2.2.2.2/tcp/4001".into()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
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
        ps, ReachabilityKind::Direct, vec!["/ip4/1.1.1.1/tcp/4001".into()],
        PeerCapabilities { can_relay: false, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));
    let peer = PeerId::random();
    store.register_peer_pseudonym(peer, ps);

    assert_eq!(store.relay_peer_info().len(), 0, "non-relay should not be returned");
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
        CredentialTier::Verified, 100, CAP_STORE | CAP_ROUTE,
        identity_epoch1.holder_tag(),
    );

    // Present at epoch 100 — should work.
    let ctx = b"wallet-rotation-test";
    let pres = CredentialPresentation::create(&cred, &identity_epoch1, ctx);
    let issuers = vec![issuer.pubkey_bytes()];
    assert!(credential::verify_presentation(&pres, ctx, &issuers, 100, CredentialTier::Observed).is_ok());

    // New identity at epoch 101 (simulating rotation).
    let identity_epoch2 = EphemeralIdentity::generate(101);

    // Old credential with new identity should fail: holder_tag mismatch.
    let pres2 = CredentialPresentation::create(&cred, &identity_epoch2, ctx);
    assert!(
        credential::verify_presentation(&pres2, ctx, &issuers, 101, CredentialTier::Observed).is_err(),
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
            ps, ReachabilityKind::Direct, vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
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
            ps, ReachabilityKind::Direct, vec![format!("/ip4/10.{i}.1.1/tcp/4001")],
            PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
        ));
    }

    let m2 = OutcomeMetrics::compute(&store, &peer_registry, &routing_table, false);
    assert!(m2.pseudonym_churn_rate > 0.4, "churn rate should be ~50% with 5/10 new: got {}", m2.pseudonym_churn_rate);
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
        [0x01; 32], ReachabilityKind::Direct, vec!["/ip4/1.1.1.1/tcp/4001".into()],
        PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
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
        [0x02; 32], ReachabilityKind::Direct, vec!["/ip4/2.2.2.2/tcp/4001".into()],
        PeerCapabilities::default(), ResourceProfile::Desktop, None,
        Some(bbs_proof), 1, &key,
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
            ps, ReachabilityKind::Direct,
            vec![format!("/ip4/10.{}.{}.1/tcp/4001", i % 256, i / 256)],
            PeerCapabilities::default(), ResourceProfile::Desktop, None, 1, &key,
        ));
    }

    let m = OutcomeMetrics::compute(&store, &peer_registry, &routing_table, false);
    assert!(m.descriptor_utilisation > 0.0, "utilisation should be > 0");
    assert!(m.descriptor_utilisation < 0.1, "100/10000 = 1%, got {}", m.descriptor_utilisation);
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
            ps, ReachabilityKind::Direct,
            vec![format!("/ip4/{}.{}.1.1/tcp/4001", i + 1, i + 1)],
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
            ResourceProfile::Desktop, None, 1, &key,
        ));
        store.register_peer_pseudonym(PeerId::random(), ps);
    }

    let dest = [0xFF; 32];
    let path = PathSelector::select(
        dest, AnonymityPolicy::Required { min_hops: 2 }, &store, &rt,
    ).unwrap();

    assert!(path.hop_count() >= 2, "Required mode should use ≥2 hops");

    // All relays in the path should be in the descriptor store.
    for hop in &path.hops {
        assert!(store.get(&hop.pseudonym).is_some(), "hop should exist in descriptor store");
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
            ps, ReachabilityKind::Direct,
            vec![format!("/ip4/{}.{}.1.1/tcp/4001", i + 1, i + 1)],
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
            ResourceProfile::Desktop, None, 1, &key,
        ));
    }

    let dest = [0xFF; 32];
    let path = PathSelector::select(
        dest, AnonymityPolicy::Opportunistic, &store, &rt,
    ).unwrap();

    // With relays available, opportunistic should use at least one.
    assert!(path.hop_count() >= 1, "opportunistic with relays should use ≥1 hop");
}

// ─── Scenario: Onion-encrypted relay delivery ──────────────────────────────

/// Per-hop onion encryption: R1 peels outer layer, R2 peels inner layer,
/// target receives e2e-encrypted payload that neither relay can read.
#[test]
fn onion_relay_per_hop_content_blindness() {
    use miasma_core::network::onion_relay::{
        process_onion_layer, encrypt_relay_response, OnionRelayAction,
    };
    use miasma_core::onion::packet::{
        OnionPacketBuilder, OnionLayerProcessor, decrypt_response,
    };
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
        &r1_pub, &r2_pub, &target_pub,
        b"r2_peer".to_vec(), b"target".to_vec(), b"r2_addr".to_vec(),
        share_request.clone(),
    ).unwrap();

    // R1 peels — cannot see share request (encrypted for R2 and Target).
    let action1 = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();
    let (inner_layer, r1_return_key) = match action1 {
        OnionRelayAction::ForwardToNext { inner_layer, return_key, .. } => (inner_layer, return_key),
        _ => panic!("R1 should forward"),
    };

    // R2 peels — gets body but it's session_key || e2e_blob. Cannot read share request.
    let action2 = process_onion_layer(&r2_sec, packet.circuit_id, &inner_layer).unwrap();
    let (delivered_body, r2_return_key) = match action2 {
        OnionRelayAction::DeliverToTarget { body, return_key, .. } => (body, return_key),
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
    let e2e_response = miasma_core::onion::packet::encrypt_response(
        &session_key_recv, &response,
    ).unwrap();

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
        &r1_pub, &r2_pub,
        b"r2".to_vec(), b"target".to_vec(), b"addr".to_vec(),
        b"secret".to_vec(),
    ).unwrap();

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
        &r1_pub, &r2_pub,
        b"r2".to_vec(), b"target".to_vec(), b"addr".to_vec(),
        b"payload".to_vec(),
    ).unwrap();

    let action1 = process_onion_layer(&r1_sec, packet.circuit_id, &packet.layer).unwrap();
    let (inner_layer, r1_key) = match action1 {
        OnionRelayAction::ForwardToNext { inner_layer, return_key, .. } => (inner_layer, return_key),
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
    assert!(!tampered.verify_self(), "tampered onion_pubkey should fail verification");

    // Remove onion_pubkey — signature must fail.
    let mut removed = desc;
    removed.onion_pubkey = None;
    assert!(!removed.verify_self(), "removed onion_pubkey should fail verification");
}

/// Descriptor store returns relay onion info only for relays with onion pubkeys.
#[test]
fn descriptor_store_relay_onion_info_filtering() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
    let mut store = DescriptorStore::new();

    // Relay with onion pubkey.
    let ps1 = [0x01; 32];
    store.upsert(PeerDescriptor::new_signed_full(
        ps1, ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, None,
        Some([0xAA; 32]),
        1, &key,
    ));
    let peer1 = PeerId::random();
    store.register_peer_pseudonym(peer1, ps1);

    // Relay without onion pubkey.
    let ps2 = [0x02; 32];
    store.upsert(PeerDescriptor::new_signed_full(
        ps2, ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, None,
        None, // no onion pubkey
        1, &key,
    ));
    let peer2 = PeerId::random();
    store.register_peer_pseudonym(peer2, ps2);

    // Non-relay with onion pubkey.
    let ps3 = [0x03; 32];
    store.upsert(PeerDescriptor::new_signed_full(
        ps3, ReachabilityKind::Direct,
        vec!["/ip4/3.3.3.3/tcp/4001".to_string()],
        PeerCapabilities { can_relay: false, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, None,
        Some([0xCC; 32]),
        1, &key,
    ));
    let peer3 = PeerId::random();
    store.register_peer_pseudonym(peer3, ps3);

    let onion_info = store.relay_onion_info();
    assert_eq!(onion_info.len(), 1, "only relay peers with onion pubkeys should be returned");
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
        &r1_pub, &r2_pub,
        b"r2".to_vec(), b"t1".to_vec(), b"addr".to_vec(),
        b"body1".to_vec(),
    ).unwrap();

    let (pkt2, _rp2) = OnionPacketBuilder::build(
        &r1_pub, &r2_pub,
        b"r2".to_vec(), b"t2".to_vec(), b"addr".to_vec(),
        b"body2".to_vec(),
    ).unwrap();

    let key1 = match process_onion_layer(&r1_sec, pkt1.circuit_id, &pkt1.layer).unwrap() {
        OnionRelayAction::ForwardToNext { return_key, .. } => return_key,
        _ => panic!("expected ForwardToNext"),
    };
    let key2 = match process_onion_layer(&r1_sec, pkt2.circuit_id, &pkt2.layer).unwrap() {
        OnionRelayAction::ForwardToNext { return_key, .. } => return_key,
        _ => panic!("expected ForwardToNext"),
    };

    assert_ne!(key1, key2, "different circuits must have different return keys");
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
        PeerCapabilities { can_relay: false, ..PeerCapabilities::default() },
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
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop,
        None,
        1,
        &key,
    ));

    let stats = store.stats();
    // Only the public node should count as a relay descriptor.
    assert_eq!(stats.relay_descriptors, 1, "only publicly reachable nodes should be relay descriptors");
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
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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
        required_attempts: 7,
        required_onion_successes: 4,
        required_relay_successes: 2,
        required_failures: 1,
        rendezvous_attempts: 3,
        rendezvous_successes: 2,
        rendezvous_failures: 1,
        rendezvous_direct_fallbacks: 0,
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
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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
        PeerCapabilities { can_relay: false, ..PeerCapabilities::default() },
        ResourceProfile::Desktop,
        None,
        None,
        Some([0x33; 32]),
        1,
        &key,
    ));

    let onion_info = store.relay_onion_info();
    // Only Peer A qualifies: can_relay=true AND has onion_pubkey AND has PeerId.
    assert_eq!(onion_info.len(), 1, "only relay-capable peers with onion pubkeys should appear");
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
        PeerCapabilities { can_relay: false, ..PeerCapabilities::default() },
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
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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
    assert_eq!(store.stats().relay_descriptors, 1, "upsert must update relay capability");
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
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
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
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
        // All should be Claimed — no real relay participation observed.
        assert_eq!(store.relay_tier(&ps), RelayTrustTier::Claimed,
            "peer {i} should be Claimed without observations");
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
            PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
            ResourceProfile::Desktop,
            None,
            1,
            &key,
        ));
        // Promote relay 0 to Verified.
        if i == 0 {
            for _ in 0..4 { store.record_relay_success(&ps); }
        }
    }

    // Select intro points for our own pseudonym.
    let own_ps = [0xFF; 32];
    let intro_points = store.select_intro_points(&own_ps, 3);
    assert_eq!(intro_points.len(), 3, "should select 3 intro points");

    // Verified relay should be first (highest trust tier).
    let mut first_ps = [0u8; 32];
    first_ps[0] = 1; // relay 0 is Verified
    assert_eq!(intro_points[0], first_ps, "Verified relay should be preferred");

    // Create a rendezvous descriptor.
    let desc = PeerDescriptor::new_signed(
        own_ps,
        ReachabilityKind::Rendezvous { intro_points: intro_points.clone() },
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
    let mut ps_a = [0u8; 32]; ps_a[0] = 0xA0;
    let peer_a = PeerId::random();
    store.register_peer_pseudonym(peer_a, ps_a);
    store.upsert(PeerDescriptor::new_signed(
        ps_a, ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));
    store.record_relay_success(&ps_a);

    // Peer B: relay, registered, Claimed (no observations).
    let mut ps_b = [0u8; 32]; ps_b[0] = 0xB0;
    let peer_b = PeerId::random();
    store.register_peer_pseudonym(peer_b, ps_b);
    store.upsert(PeerDescriptor::new_signed(
        ps_b, ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));

    // Peer C: NOT a relay (can_relay=false) — should be filtered out.
    let mut ps_c = [0u8; 32]; ps_c[0] = 0xC0;
    let peer_c = PeerId::random();
    store.register_peer_pseudonym(peer_c, ps_c);
    store.upsert(PeerDescriptor::new_signed(
        ps_c, ReachabilityKind::Direct,
        vec!["/ip4/3.3.3.3/tcp/4001".to_string()],
        PeerCapabilities { can_relay: false, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));

    // Peer D: relay but NO PeerId mapping — should be filtered out.
    let mut ps_d = [0u8; 32]; ps_d[0] = 0xD0;
    store.upsert(PeerDescriptor::new_signed(
        ps_d, ReachabilityKind::Direct,
        vec!["/ip4/4.4.4.4/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));

    let resolved = store.resolve_intro_points(&[ps_a, ps_b, ps_c, ps_d]);
    assert_eq!(resolved.len(), 2, "only relay peers with PeerId mappings should resolve");
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
    assert!(resolved.is_empty(), "non-existent intro points should resolve to empty");
}

/// Rendezvous descriptor reachability is distinct from Relayed.
#[test]
fn rendezvous_vs_relayed_distinction() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);

    let rendezvous = PeerDescriptor::new_signed(
        [0x01; 32],
        ReachabilityKind::Rendezvous { intro_points: vec![[0xAA; 32], [0xBB; 32]] },
        vec![],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None, 1, &key,
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
        None, 1, &key,
    );
    let direct = PeerDescriptor::new_signed(
        [0x03; 32],
        ReachabilityKind::Direct,
        vec!["/ip4/5.6.7.8/tcp/4001".to_string()],
        PeerCapabilities::default(),
        ResourceProfile::Desktop,
        None, 1, &key,
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
        [0x01; 32], ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities::default(), ResourceProfile::Desktop,
        None, 1, &key,
    ));

    // Rendezvous peer.
    store.upsert(PeerDescriptor::new_signed(
        [0x02; 32],
        ReachabilityKind::Rendezvous { intro_points: vec![[0xAA; 32]] },
        vec![], PeerCapabilities::default(), ResourceProfile::Desktop,
        None, 1, &key,
    ));

    // Relay peer (Claimed).
    let ps_relay = [0x03; 32];
    let relay_peer = PeerId::random();
    store.register_peer_pseudonym(relay_peer, ps_relay);
    store.upsert(PeerDescriptor::new_signed(
        ps_relay, ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
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
    let mut ps_claimed = [0u8; 32]; ps_claimed[0] = 1;
    let peer_claimed = PeerId::random();
    store.register_peer_pseudonym(peer_claimed, ps_claimed);
    store.upsert(PeerDescriptor::new_signed(
        ps_claimed, ReachabilityKind::Direct,
        vec!["/ip4/1.1.1.1/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));

    let mut ps_verified = [0u8; 32]; ps_verified[0] = 2;
    let peer_verified = PeerId::random();
    store.register_peer_pseudonym(peer_verified, ps_verified);
    store.upsert(PeerDescriptor::new_signed(
        ps_verified, ReachabilityKind::Direct,
        vec!["/ip4/2.2.2.2/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));
    for _ in 0..4 { store.record_relay_success(&ps_verified); }

    let mut ps_observed = [0u8; 32]; ps_observed[0] = 3;
    let peer_observed = PeerId::random();
    store.register_peer_pseudonym(peer_observed, ps_observed);
    store.upsert(PeerDescriptor::new_signed(
        ps_observed, ReachabilityKind::Direct,
        vec!["/ip4/3.3.3.3/tcp/4001".to_string()],
        PeerCapabilities { can_relay: true, ..PeerCapabilities::default() },
        ResourceProfile::Desktop, None, 1, &key,
    ));
    store.record_relay_success(&ps_observed);

    let relay_info = store.relay_peer_info();
    assert_eq!(relay_info.len(), 3);
    // Verified first, then Observed, then Claimed.
    assert_eq!(relay_info[0].0, peer_verified);
    assert_eq!(relay_info[1].0, peer_observed);
    assert_eq!(relay_info[2].0, peer_claimed);
}
