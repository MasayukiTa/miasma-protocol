//! Cross-implementation known-answer tests (native build of this crate).
//!
//! `miasma-wasm` re-implements AES-256-GCM segment encryption, Shamir sharing,
//! Reed-Solomon coding and the share formats independently of `miasma-core`.
//! These tests feed the same fixed inputs to both implementations and require
//! the same bytes (or the same accept/reject decision and error class), in both
//! directions. Where an output is deterministic its BLAKE3 digest is also
//! frozen here, so a change that moves both implementations together is still
//! noticed.
//!
//! Test-only key material: no key, nonce or password literal appears in this
//! file. Every byte string below is derived at run time from the documented seed
//! `KAT_SEED` with BLAKE3 `derive_key` (domain `KAT_DOMAIN`) and a per-use label,
//! the same derive-at-runtime pattern the other frozen tests use. The values are
//! for tests only and protect nothing.
//!
//! Known, intended differences are pinned by their own tests instead of being
//! hidden (see `plain_split_is_accepted_by_core_only` and
//! `nonce_mismatch_is_classified_differently`).

use super::*;

use miasma_core::crypto::{aead as core_aead, rs as core_rs, sss as core_sss};
use miasma_core::{
    crypto::hash::ContentId as CoreMid,
    pipeline::{self as core_pipeline, DissolutionParams as CoreParams},
    share::{MiasmaShare as CoreShare, ShareVerification},
};

/// Documented seed for every derived test value in this file.
const KAT_SEED: &str = "miasma wasm/core known-answer tests, seed 1";
/// BLAKE3 `derive_key` domain for the values above.
const KAT_DOMAIN: &str = "miasma-wasm-core-kat-v1";

/// `len` bytes derived from `KAT_SEED` and `label`.
fn kat(label: &str, len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key(KAT_DOMAIN);
    h.update(KAT_SEED.as_bytes());
    h.update(&[0]);
    h.update(label.as_bytes());
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

fn kat_key() -> [u8; KEY_LEN] {
    kat("aes-key", KEY_LEN).try_into().unwrap()
}

fn kat_nonce(label: &str) -> [u8; NONCE_LEN] {
    kat(label, NONCE_LEN).try_into().unwrap()
}

/// Error class: the variant name, which both crates spell the same way.
fn class<E: std::fmt::Debug>(e: &E) -> String {
    format!("{e:?}")
        .chars()
        .take_while(|c| c.is_alphanumeric())
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn assert_frozen(name: &str, bytes: &[u8], expected: &str) {
    assert_eq!(
        digest(bytes),
        expected,
        "frozen digest for {name} changed: the output of this primitive moved"
    );
}

// ── AES-256-GCM ───────────────────────────────────────────────────────

#[test]
fn aes_gcm_core_ciphertext_is_accepted_by_wasm() {
    let key = kat_key();
    let nonce = kat_nonce("aes-nonce");
    for len in [1usize, 15, 16, 17, 1000] {
        let plain = kat("aes-plain", len);
        let ct = core_aead::encrypt_with_key(&plain, &key, &nonce).unwrap();
        assert_eq!(ct.len(), len + 16);
        assert_eq!(decrypt(&ct, &key, &nonce).unwrap(), plain, "len {len}");
        if len == 1000 {
            assert_frozen("aes-gcm ciphertext", &ct, AES_CT_DIGEST);
        }
    }
}

#[test]
fn aes_gcm_wasm_ciphertext_is_accepted_by_core() {
    for len in [1usize, 15, 16, 17, 1000] {
        let plain = kat("aes-plain", len);
        let (ct, key, nonce) = encrypt(&plain).unwrap();
        assert_eq!(ct.len(), len + 16);
        assert_eq!(core_aead::decrypt(&ct, &key, &nonce).unwrap(), plain);
        // The same key and nonce through core give the same ciphertext.
        assert_eq!(core_aead::encrypt_with_key(&plain, &key, &nonce).unwrap(), ct);
    }
}

#[test]
fn aes_gcm_rejections_match() {
    let key = kat_key();
    let nonce = kat_nonce("aes-nonce");
    let other_key: [u8; KEY_LEN] = kat("aes-other-key", KEY_LEN).try_into().unwrap();
    let other_nonce = kat_nonce("aes-other-nonce");
    let plain = kat("aes-plain", 64);
    let ct = core_aead::encrypt_with_key(&plain, &key, &nonce).unwrap();

    let mut flipped_body = ct.clone();
    flipped_body[0] ^= 1;
    let mut flipped_tag = ct.clone();
    *flipped_tag.last_mut().unwrap() ^= 0x80;
    let mut cases: Vec<(&str, Vec<u8>, [u8; KEY_LEN], [u8; NONCE_LEN])> = vec![
        ("flipped body", flipped_body, key, nonce),
        ("flipped tag", flipped_tag, key, nonce),
        ("wrong key", ct.clone(), other_key, nonce),
        ("wrong nonce", ct.clone(), key, other_nonce),
        ("truncated", ct[..ct.len() - 1].to_vec(), key, nonce),
        ("shorter than a tag", ct[..8].to_vec(), key, nonce),
        ("empty", Vec::new(), key, nonce),
    ];
    let mut extended = ct.clone();
    extended.push(0);
    cases.push(("extended", extended, key, nonce));
    for (name, input, k, n) in cases {
        let w = decrypt(&input, &k, &n).expect_err(name);
        let c = core_aead::decrypt(&input, &k, &n).expect_err(name);
        assert_eq!(class(&w), "Decryption", "{name}");
        assert_eq!(class(&w), class(&c), "{name}");
    }
}

// ── Shamir sharing ────────────────────────────────────────────────────

#[test]
fn shamir_shares_cross_combine_in_both_directions() {
    let secret = kat("sss-secret", KEY_LEN);
    for (k, n) in [(2u8, 3u8), (3, 5), (10, 20)] {
        let from_core = core_sss::sss_split(&secret, k, n).unwrap();
        let from_wasm = sss_split(&secret, k, n).unwrap();
        for shares in [&from_core, &from_wasm] {
            assert_eq!(shares.len(), n as usize);
            // A share is the x coordinate plus one byte per secret byte.
            assert!(shares.iter().all(|s| s.len() == secret.len() + 1));
        }
        let k = k as usize;
        for set in [&from_core, &from_wasm] {
            let first: Vec<Vec<u8>> = set[..k].to_vec();
            let last: Vec<Vec<u8>> = set[set.len() - k..].to_vec();
            for pick in [first, last] {
                assert_eq!(sss_combine(&pick, k as u8).unwrap().as_slice(), secret);
                assert_eq!(
                    core_sss::sss_combine(&pick, k as u8).unwrap().as_slice(),
                    secret
                );
            }
        }
    }
}

#[test]
fn shamir_rejections_match() {
    let secret = kat("sss-secret", KEY_LEN);
    for (k, n) in [(0u8, 3u8), (4, 3), (3, 0), (0, 0)] {
        let w = sss_split(&secret, k, n).expect_err("wasm split");
        let c = core_sss::sss_split(&secret, k, n).expect_err("core split");
        assert_eq!(class(&w), "Sss");
        assert_eq!(class(&w), class(&c), "split k={k} n={n}");
    }

    let shares = core_sss::sss_split(&secret, 3, 5).unwrap();
    // Fewer than k shares.
    let few = shares[..2].to_vec();
    let w = sss_combine(&few, 3).expect_err("wasm few");
    let c = core_sss::sss_combine(&few, 3).expect_err("core few");
    assert_eq!(class(&w), "InsufficientShares");
    assert_eq!(class(&w), class(&c));

    // Malformed share bytes: empty, and a lone x coordinate.
    for bad in [Vec::new(), vec![shares[0][0]]] {
        let mut set = shares[..2].to_vec();
        set.push(bad);
        let w = sss_combine(&set, 3).expect_err("wasm malformed");
        let c = core_sss::sss_combine(&set, 3).expect_err("core malformed");
        assert_eq!(class(&w), class(&c));
    }

    // A modified share does not fail: both return the same wrong secret.
    let mut set = shares[..3].to_vec();
    set[1][5] ^= 0x55;
    let w = sss_combine(&set, 3).map(|v| v.to_vec());
    let c = core_sss::sss_combine(&set, 3).map(|v| v.to_vec());
    match (w, c) {
        (Ok(w), Ok(c)) => {
            assert_eq!(w, c);
            assert_ne!(w, secret);
        }
        (Err(w), Err(c)) => assert_eq!(class(&w), class(&c)),
        (w, c) => panic!("accept/reject differs: wasm {w:?} core {c:?}"),
    }
}

// ── Reed-Solomon ──────────────────────────────────────────────────────

#[test]
fn reed_solomon_encoding_is_byte_identical() {
    for (len, k, n) in [
        (1usize, 2usize, 3usize),
        (17, 10, 20),
        (33, 4, 9),
        (1000, 3, 5),
        (4096, 10, 20),
    ] {
        let data = kat("rs-data", len);
        let w = rs_encode(&data, k, n).unwrap();
        let c = core_rs::rs_encode(&data, k, n).unwrap();
        assert_eq!(w, c, "len {len} k {k} n {n}");
        assert_eq!(w.len(), n);
        assert!(w.iter().all(|s| s.len() % 2 == 0 && s.len() == w[0].len()));
        if (len, k, n) == (17, 10, 20) {
            assert_frozen("reed-solomon shards 17/10/20", &w.concat(), RS_SHARDS_DIGEST);
        }
    }
}

#[test]
fn reed_solomon_cross_decodes_from_parity_heavy_sets() {
    for (len, k, n) in [(1usize, 2usize, 3usize), (17, 10, 20), (33, 4, 9), (1000, 3, 5)] {
        let data = kat("rs-data", len);
        let shards = core_rs::rs_encode(&data, k, n).unwrap();
        // The last k shards: every parity shard first, as few data shards as possible.
        let available: Vec<(usize, Vec<u8>)> =
            (n - k..n).map(|i| (i, shards[i].clone())).collect();
        assert_eq!(rs_decode(&available, k, n, len).unwrap(), data, "wasm {len}");
        assert_eq!(
            core_rs::rs_decode(&available, k, n, len).unwrap(),
            data,
            "core {len}"
        );

        let from_wasm = rs_encode(&data, k, n).unwrap();
        let available: Vec<(usize, Vec<u8>)> =
            (n - k..n).map(|i| (i, from_wasm[i].clone())).collect();
        assert_eq!(core_rs::rs_decode(&available, k, n, len).unwrap(), data);
    }
}

#[test]
fn reed_solomon_rejections_match() {
    let (k, n, len) = (4usize, 9usize, 40usize);
    let data = kat("rs-data", len);
    let shards = core_rs::rs_encode(&data, k, n).unwrap();
    let take = |idx: &[usize]| -> Vec<(usize, Vec<u8>)> {
        idx.iter().map(|&i| (i, shards[i].clone())).collect()
    };

    let mut cases: Vec<(&str, Vec<(usize, Vec<u8>)>, usize, usize)> = vec![
        ("no shards", Vec::new(), k, n),
        ("one short", take(&[1, 5, 7]), k, n),
        ("zero data shards", take(&[0, 1, 2, 3]), 0, n),
        ("total below data", take(&[0, 1, 2, 3]), k, k - 1),
    ];
    let mut odd = take(&[1, 5, 7, 8]);
    odd[0].1.pop();
    cases.push(("odd shard length", odd, k, n));
    let mut empty = take(&[1, 5, 7, 8]);
    empty[0].1.clear();
    cases.push(("empty shard", empty, k, n));
    let mut uneven = take(&[1, 5, 7, 8]);
    uneven[3].1.truncate(2);
    cases.push(("uneven shard lengths", uneven, k, n));

    for (name, available, kk, nn) in cases {
        let w = rs_decode(&available, kk, nn, len).expect_err(name);
        let c = core_rs::rs_decode(&available, kk, nn, len).expect_err(name);
        assert_eq!(class(&w), class(&c), "{name}: wasm {w:?} core {c:?}");
    }

    // Encoding parameters.
    for (kk, nn) in [(0usize, 5usize), (5, 3)] {
        let w = rs_encode(&data, kk, nn).expect_err("wasm encode");
        let c = core_rs::rs_encode(&data, kk, nn).expect_err("core encode");
        assert_eq!(class(&w), "ReedSolomon");
        assert_eq!(class(&w), class(&c), "encode k={kk} n={nn}");
    }
}

/// Core accepts `total_shards == data_shards` (a plain split with no parity, used
/// for transfers); the browser kernel refuses it. Pinned so that a change on
/// either side is a deliberate one. Browser shares never use this setting
/// (`validate_params` requires `k < n`).
#[test]
fn plain_split_is_accepted_by_core_only() {
    let data = kat("rs-data", 40);
    assert!(core_rs::rs_encode(&data, 4, 4).is_ok());
    assert_eq!(class(&rs_encode(&data, 4, 4).unwrap_err()), "ReedSolomon");
    assert_eq!(class(&validate_params(4, 4).unwrap_err()), "Sss");
}

// ── Share format and the browser bundles ──────────────────────────────

const KAT_PARAMS: DissolutionParams = DissolutionParams {
    data_shards: 3,
    total_shards: 5,
};

fn core_params() -> CoreParams {
    CoreParams {
        data_shards: KAT_PARAMS.data_shards,
        total_shards: KAT_PARAMS.total_shards,
    }
}

/// Five shares built from derived fields on both sides: the same bytes.
fn fixed_shares() -> (CoreMid, Vec<CoreShare>, ContentId, Vec<MiasmaShare>) {
    let plain = kat("share-plain", 32);
    let params = KAT_PARAMS.to_param_bytes();
    let core_mid = CoreMid::compute(&plain, &params);
    let wasm_mid = ContentId::compute(&plain, &params);
    let nonce = kat_nonce("share-nonce");
    let mut core_shares = Vec::new();
    let mut wasm_shares = Vec::new();
    for slot in 0u16..5 {
        let shard = kat(&format!("shard-{slot}"), 48);
        let key_share = kat(&format!("key-share-{slot}"), 33);
        core_shares.push(CoreShare::new(
            &core_mid,
            0,
            slot,
            shard.clone(),
            key_share.clone(),
            nonce,
            32,
            1_700_000_000,
        ));
        wasm_shares.push(MiasmaShare::new(
            &wasm_mid,
            0,
            slot,
            shard,
            key_share,
            nonce,
            32,
            1_700_000_000,
        ));
    }
    (core_mid, core_shares, wasm_mid, wasm_shares)
}

/// The browser's share bundle (`MSB1`): magic, u16 count, then u32 length and
/// bytes for each share, little-endian. Written here from the format, not from
/// the encoder, so the decoder is checked against the description.
fn bundle_of(share_bytes: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"MSB1".to_vec();
    out.extend_from_slice(&(share_bytes.len() as u16).to_le_bytes());
    for s in share_bytes {
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(s);
    }
    out
}

#[test]
fn share_bytes_and_mid_are_identical() {
    let (core_mid, core_shares, wasm_mid, wasm_shares) = fixed_shares();
    assert_eq!(core_mid.to_string(), wasm_mid.to_mid_string());
    assert_eq!(core_mid.prefix(), wasm_mid.prefix());
    let mut all = Vec::new();
    for (c, w) in core_shares.iter().zip(&wasm_shares) {
        let cb = c.to_bytes().unwrap();
        assert_eq!(cb, w.to_bytes().unwrap());
        // And each reads the other's bytes back to the same fields.
        let back = MiasmaShare::from_bytes(&cb).unwrap();
        assert_eq!(back.to_bytes().unwrap(), cb);
        let back = CoreShare::from_bytes(&w.to_bytes().unwrap()).unwrap();
        assert_eq!(back.to_bytes().unwrap(), cb);
        all.extend_from_slice(&cb);
    }
    assert_frozen("five share bincode records", &all, SHARES_DIGEST);
}

#[test]
fn share_bundle_built_from_core_bytes_is_accepted() {
    let (_, core_shares, _, wasm_shares) = fixed_shares();
    let bytes: Vec<Vec<u8>> = core_shares.iter().map(|s| s.to_bytes().unwrap()).collect();
    let bundle = bundle_of(&bytes);
    assert_frozen("share bundle MSB1", &bundle, BUNDLE_DIGEST);
    let decoded = decode_share_bundle(&bundle).unwrap();
    assert_eq!(decoded.len(), 5);
    for (d, w) in decoded.iter().zip(&wasm_shares) {
        assert_eq!(d.to_bytes().unwrap(), w.to_bytes().unwrap());
    }
}

#[test]
fn core_dissolution_is_retrieved_from_a_bundle_by_wasm() {
    let plain = kat("pipeline-plain", 5000);
    let (mid, shares) = core_pipeline::dissolve_at(&plain, core_params(), 1_700_000_000).unwrap();
    let bytes: Vec<Vec<u8>> = shares.iter().map(|s| s.to_bytes().unwrap()).collect();
    // Any three of the five shares, in a different order from how they were made.
    let picked = vec![bytes[4].clone(), bytes[1].clone(), bytes[2].clone()];
    let out = retrieve_from_share_bundle(&mid.to_string(), &bundle_of(&picked), 3, 5)
        .unwrap_or_else(|_| panic!("wasm did not accept the bundle"));
    assert_eq!(out, plain);
}

/// Reads the dissolve bundle (`MDB1`) from its description: magic, u16 length and
/// text of the MID, u16 k, u16 n, u16 count, then u32 length and bytes per share.
fn parse_dissolve_bundle(b: &[u8]) -> (String, u16, u16, Vec<Vec<u8>>) {
    assert_eq!(&b[..4], b"MDB1");
    let mut p = 4;
    let u16_at = |p: usize| u16::from_le_bytes([b[p], b[p + 1]]);
    let mid_len = u16_at(p) as usize;
    p += 2;
    let mid = String::from_utf8(b[p..p + mid_len].to_vec()).unwrap();
    p += mid_len;
    let (k, n, count) = (u16_at(p), u16_at(p + 2), u16_at(p + 4) as usize);
    p += 6;
    let mut shares = Vec::new();
    for _ in 0..count {
        let len = u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        shares.push(b[p..p + len].to_vec());
        p += len;
    }
    assert_eq!(p, b.len(), "trailing bytes in the dissolve bundle");
    (mid, k, n, shares)
}

#[test]
fn wasm_dissolution_is_retrieved_by_core() {
    let plain = kat("pipeline-plain", 5000);
    let (mid, shares) = dissolve_inner_at(&plain, KAT_PARAMS, 1_700_000_000).unwrap();
    let bundle = encode_dissolve_bundle(&mid, &shares, KAT_PARAMS).unwrap();
    let (mid_text, k, n, share_bytes) = parse_dissolve_bundle(&bundle);
    assert_eq!((k, n), (3, 5));
    assert_eq!(share_bytes.len(), 5);

    let core_mid = CoreMid::from_str(&mid_text).unwrap();
    assert_eq!(core_mid.to_string(), mid.to_mid_string());
    // Same MID as core computes for the same content and parameters.
    assert_eq!(
        core_mid,
        CoreMid::compute(&plain, &KAT_PARAMS.to_param_bytes())
    );
    let core_shares: Vec<CoreShare> = share_bytes
        .iter()
        .rev()
        .take(3)
        .map(|b| CoreShare::from_bytes(b).unwrap())
        .collect();
    assert!(core_shares
        .iter()
        .all(|s| ShareVerification::coarse_verify(s, &core_mid)));
    assert_eq!(
        core_pipeline::retrieve(&core_mid, &core_shares, core_params()).unwrap(),
        plain
    );
}

#[test]
fn malformed_share_bundles_are_rejected() {
    let (_, core_shares, _, _) = fixed_shares();
    let bytes: Vec<Vec<u8>> = core_shares.iter().map(|s| s.to_bytes().unwrap()).collect();
    let good = bundle_of(&bytes);
    assert!(decode_share_bundle(&good).is_ok());

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("magic only", b"MSB1".to_vec()),
        ("wrong magic", {
            let mut b = good.clone();
            b[3] = b'2';
            b
        }),
        ("dissolve magic", {
            let mut b = good.clone();
            b[..4].copy_from_slice(b"MDB1");
            b
        }),
        ("count zero", b"MSB1\x00\x00".to_vec()),
        ("count over the limit", {
            let mut b = b"MSB1".to_vec();
            b.extend_from_slice(&(MAX_SHARE_COUNT as u16 + 1).to_le_bytes());
            b
        }),
        ("count larger than the data", {
            let mut b = good.clone();
            b[4] = 9;
            b
        }),
        ("truncated length field", good[..8].to_vec()),
        ("truncated share", good[..good.len() - 1].to_vec()),
        ("trailing byte", {
            let mut b = good.clone();
            b.push(0);
            b
        }),
        ("zero length share", {
            let mut b = b"MSB1\x01\x00".to_vec();
            b.extend_from_slice(&0u32.to_le_bytes());
            b
        }),
        ("share length over the limit", {
            let mut b = b"MSB1\x01\x00".to_vec();
            b.extend_from_slice(&(MAX_BINCODE_SIZE as u32 + 1).to_le_bytes());
            b
        }),
        ("share length past the end", {
            let mut b = b"MSB1\x01\x00".to_vec();
            b.extend_from_slice(&u32::MAX.to_le_bytes());
            b.extend_from_slice(&bytes[0]);
            b
        }),
        ("garbage share", {
            let junk = kat("junk", 40);
            bundle_of(&[junk])
        }),
    ];
    // Every proper prefix of a valid bundle is rejected.
    for cut in 0..good.len() {
        cases.push(("prefix", good[..cut].to_vec()));
    }
    for (name, input) in cases {
        let err = decode_share_bundle(&input);
        assert!(err.is_err(), "{name} (len {}) was accepted", input.len());
        assert_eq!(class(&err.unwrap_err()), "Serialization", "{name}");
    }
}

#[test]
fn malformed_share_records_are_judged_alike() {
    let (_, core_shares, _, _) = fixed_shares();
    let good = core_shares[0].to_bytes().unwrap();
    let mut inputs: Vec<(String, Vec<u8>)> = vec![
        ("empty".into(), Vec::new()),
        ("junk".into(), kat("junk", 120)),
        ("trailing bytes".into(), {
            let mut b = good.clone();
            b.extend_from_slice(&[1, 2, 3]);
            b
        }),
    ];
    for cut in 0..good.len() {
        inputs.push((format!("prefix {cut}"), good[..cut].to_vec()));
    }
    for (name, input) in inputs {
        let w = MiasmaShare::from_bytes(&input);
        let c = CoreShare::from_bytes(&input);
        assert_eq!(w.is_ok(), c.is_ok(), "{name}: wasm {w:?} core {c:?}");
        if let (Ok(w), Ok(c)) = (&w, &c) {
            assert_eq!(w.to_bytes().unwrap(), c.to_bytes().unwrap(), "{name}");
        }
    }
}

#[test]
fn tampered_shares_and_wrong_inputs_fail_alike() {
    let plain = kat("pipeline-plain", 700);
    let (mid, shares) = core_pipeline::dissolve_at(&plain, core_params(), 1_700_000_000).unwrap();
    let wasm_mid = ContentId::from_mid_str(&mid.to_string()).unwrap();
    let to_wasm = |s: &CoreShare| MiasmaShare::from_bytes(&s.to_bytes().unwrap()).unwrap();
    let wasm_shares: Vec<MiasmaShare> = shares.iter().map(to_wasm).collect();

    // A flipped bit in the stored shard fails the per-share check on both sides.
    let mut bad_core = shares[0].clone();
    bad_core.shard_data[0] ^= 1;
    let bad_wasm = to_wasm(&bad_core);
    assert!(!ShareVerification::coarse_verify(&bad_core, &mid));
    assert!(!coarse_verify(&bad_wasm, &wasm_mid));

    // With two good shares and one bad one, there are not enough valid shares.
    let core_set = vec![bad_core.clone(), shares[1].clone(), shares[2].clone()];
    let wasm_set = vec![bad_wasm.clone(), wasm_shares[1].clone(), wasm_shares[2].clone()];
    let c = core_pipeline::retrieve(&mid, &core_set, core_params()).unwrap_err();
    let w = retrieve_inner(&wasm_mid, &wasm_set, KAT_PARAMS).unwrap_err();
    assert_eq!(class(&w), "InsufficientShares");
    assert_eq!(class(&w), class(&c));

    // Fewer shares than k.
    let c = core_pipeline::retrieve(&mid, &shares[..2], core_params()).unwrap_err();
    let w = retrieve_inner(&wasm_mid, &wasm_shares[..2], KAT_PARAMS).unwrap_err();
    assert_eq!(class(&w), "InsufficientShares");
    assert_eq!(class(&w), class(&c));

    // Another MID: no share passes the per-share check.
    let other = CoreMid::compute(b"another content", &KAT_PARAMS.to_param_bytes());
    let other_wasm = ContentId::from_mid_str(&other.to_string()).unwrap();
    let c = core_pipeline::retrieve(&other, &shares, core_params()).unwrap_err();
    let w = retrieve_inner(&other_wasm, &wasm_shares, KAT_PARAMS).unwrap_err();
    assert_eq!(class(&w), class(&c));

    // Parameters that do not match what the shares were made with fail on both
    // sides (not necessarily with the same class; both refuse).
    let wrong = DissolutionParams {
        data_shards: 4,
        total_shards: 5,
    };
    let wrong_core = CoreParams {
        data_shards: 4,
        total_shards: 5,
    };
    assert!(core_pipeline::retrieve(&mid, &shares, wrong_core).is_err());
    assert!(retrieve_inner(&wasm_mid, &wasm_shares, wrong).is_err());

    // Garbage MID text.
    assert_eq!(class(&ContentId::from_mid_str("not a mid").unwrap_err()), "InvalidMid");
    assert!(CoreMid::from_str("not a mid").is_err());
}

/// Shares that disagree on the nonce: the browser kernel refuses before
/// decrypting (`ShareIntegrity`); core goes on and fails authentication
/// (`Decryption`). Both refuse; the class differs. Pinned so the difference stays
/// a known one.
#[test]
fn nonce_mismatch_is_classified_differently() {
    let plain = kat("pipeline-plain", 700);
    let (mid, shares) = core_pipeline::dissolve_at(&plain, core_params(), 1_700_000_000).unwrap();
    let wasm_mid = ContentId::from_mid_str(&mid.to_string()).unwrap();

    let mut core_set: Vec<CoreShare> = shares[..3].to_vec();
    core_set[0].nonce[0] ^= 1;
    let wasm_set: Vec<MiasmaShare> = core_set
        .iter()
        .map(|s| MiasmaShare::from_bytes(&s.to_bytes().unwrap()).unwrap())
        .collect();

    let w = retrieve_inner(&wasm_mid, &wasm_set, KAT_PARAMS).unwrap_err();
    assert_eq!(class(&w), "ShareIntegrity");
    let c = core_pipeline::retrieve(&mid, &core_set, core_params()).unwrap_err();
    assert_eq!(class(&c), "Decryption");
}

// ── Randomness fails closed ───────────────────────────────────────────

/// The shipped code (everything before the unit tests of `lib.rs`) draws random
/// numbers only from the operating system / browser source, through `OsRng` and
/// the `blahaj` dealer, both of which stop (panic) when `getrandom` cannot
/// supply bytes. There is no seeded or fallback generator.
///
/// This is a source check. The run-time check, with the browser random source
/// removed, is `web/tests/wasm_rng.test.mjs`, which runs the committed package.
#[test]
fn no_fallback_random_generator_in_shipped_code() {
    let lib = include_str!("lib.rs").replace("\r\n", "\n");
    let shipped = &lib[..lib
        .find("#[cfg(test)]\nmod tests {")
        .expect("unit test module marker")];

    for forbidden in [
        "thread_rng",
        "StdRng",
        "SmallRng",
        "ChaCha",
        "seed_from_u64",
        "from_seed",
        "from_entropy",
        "fastrand",
        "Math.random",
        "random_u64",
        "rand::",
        "register_custom_getrandom",
    ] {
        assert!(
            !shipped.contains(forbidden),
            "shipped code mentions `{forbidden}`: no generator other than OsRng may be used"
        );
    }
    assert!(shipped.contains("&mut OsRng"), "key and nonce come from OsRng");

    let manifest = include_str!("../Cargo.toml").replace("\r\n", "\n");
    assert!(
        manifest.contains("getrandom = { version = \"0.2\", features = [\"js\"] }"),
        "the browser random source is getrandom's `js` backend"
    );
    assert!(
        !manifest.contains("\"custom\""),
        "a custom getrandom backend could supply a fallback"
    );
}

// ── Frozen digests (BLAKE3 of the deterministic outputs above) ────────

const AES_CT_DIGEST: &str = "694659efdeabc55113bc154dc0ca0775b51667488d1e008c0cfd07e8f016793e";
const RS_SHARDS_DIGEST: &str = "692fb1ad378bcc709e6543f95809e20b73a7a698ce6e2d27a156ce8688b4c020";
const SHARES_DIGEST: &str = "8132ea001f64e18995a504bf4272d5065881659cccb0250d864b295e2257314a";
const BUNDLE_DIGEST: &str = "9e676be210c3e8af54205de849d3aecd9d151fb805a0f3e279d0c16c2a16eb6e";
