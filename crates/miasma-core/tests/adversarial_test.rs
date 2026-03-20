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
    DescriptorStore, PeerCapabilities, PeerDescriptor, ReachabilityKind, ResourceProfile,
};
use miasma_core::network::bbs_credential::{
    bbs_create_proof, bbs_verify_proof, BbsIssuer, BbsIssuerKey,
    BbsCredentialAttributes, DisclosurePolicy, generate_link_secret,
};
use miasma_core::network::path_selection::{AnonymityPolicy, PathSelector};
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
        "Ed25519 scheme catches unknown issuer (BBS+ pairing check is Phase 4c)"
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
