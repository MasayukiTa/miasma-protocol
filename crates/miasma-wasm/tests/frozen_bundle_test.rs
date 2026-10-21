//! The browser bundle formats, frozen byte for byte, read by the native code.
//!
//! The fixture `fixtures/web_bundle_v1/frozen.hex` was produced once by the
//! checked-in `web/pkg` build (`dissolve_bytes_bundle`, then `packShareBundle`
//! from `web/js/storage.js`). `web/tests/frozen_bundle.test.mjs` reads the same
//! file with the JavaScript reader and the shipped WASM; this file reads it with
//! the Rust build of `miasma-wasm` and with `miasma-core`, so a bundle made by
//! the shipped web build is read by the native side, and shares made by the
//! native side are read by the web side.
//!
//! Layouts (all integers little-endian):
//!
//! ```text
//! MDB1 dissolve bundle: "MDB1" || mid_len:u16 || mid || k:u16 || n:u16 || count:u16
//!                       || count * ( len:u32 || bincode(MiasmaShare) )
//! MSB1 share bundle:    "MSB1" || count:u16 || count * ( len:u32 || bincode(MiasmaShare) )
//! ```
//!
//! The bundle is local to the browser boundary, not the network protocol, but
//! the stored bundles outlive a page reload and an upgrade of the web build. A
//! change to the layout needs a new magic and new fixture lines; the existing
//! ones are never regenerated to make a test pass.

use miasma_core::{retrieve, ContentId, DissolutionParams, MiasmaShare};

const FIXTURES: &str = include_str!("fixtures/web_bundle_v1/frozen.hex");

fn frozen(name: &str) -> Vec<u8> {
    for line in FIXTURES.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some((n, h)) = line.split_once(' ') {
            if n == name {
                let h = h.trim();
                return (0..h.len() / 2)
                    .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("fixture is hex"))
                    .collect();
            }
        }
    }
    panic!("no fixture {name}");
}

struct Dissolved {
    mid: String,
    k: usize,
    n: usize,
    shares: Vec<Vec<u8>>,
}

/// The reader the browser uses (`parseDissolveBundle`), written again in Rust.
fn parse_dissolve_bundle(b: &[u8]) -> Dissolved {
    assert!(b.len() >= 12);
    assert_eq!(&b[..4], b"MDB1");
    let mid_len = u16::from_le_bytes([b[4], b[5]]) as usize;
    let mid = String::from_utf8(b[6..6 + mid_len].to_vec()).unwrap();
    let mut off = 6 + mid_len;
    let k = u16::from_le_bytes([b[off], b[off + 1]]) as usize;
    let n = u16::from_le_bytes([b[off + 2], b[off + 3]]) as usize;
    let count = u16::from_le_bytes([b[off + 4], b[off + 5]]) as usize;
    off += 6;
    assert_eq!(count, n);
    let mut shares = Vec::new();
    for _ in 0..count {
        let len = u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        shares.push(b[off..off + len].to_vec());
        off += len;
    }
    assert_eq!(off, b.len(), "trailing bytes in the dissolve bundle");
    Dissolved { mid, k, n, shares }
}

/// The writer the browser uses (`packShareBundle`), written again in Rust.
fn pack_share_bundle(shares: &[&[u8]]) -> Vec<u8> {
    let mut out = b"MSB1".to_vec();
    out.extend_from_slice(&(shares.len() as u16).to_le_bytes());
    for s in shares {
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(s);
    }
    out
}

fn retrieve_bundle(mid: &str, bundle: &[u8], k: usize, n: usize) -> Vec<u8> {
    miasma_wasm::retrieve_from_share_bundle(mid, bundle, k, n)
        .ok()
        .expect("the bundle should reconstruct")
}

#[test]
fn the_frozen_dissolve_bundle_has_the_documented_layout() {
    let d = parse_dissolve_bundle(&frozen("dissolve_bundle"));
    assert!(d.mid.starts_with("miasma:"));
    assert_eq!((d.k, d.n), (3, 5));
    assert_eq!(d.shares.len(), 5);
    // Each bundled share is a bincode MiasmaShare: version 1, then the MID
    // prefix (the first 8 bytes of the MID digest), the segment index and the slot.
    let digest = bs58::decode(&d.mid["miasma:".len()..]).into_vec().unwrap();
    for (slot, s) in d.shares.iter().enumerate() {
        assert_eq!(s[0], 1, "share version");
        assert_eq!(&s[1..9], &digest[..8], "MID prefix");
        assert_eq!(u32::from_le_bytes(s[9..13].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(s[13..15].try_into().unwrap()) as usize, slot);
    }
}

#[test]
fn the_native_writer_layout_matches_the_frozen_share_bundle() {
    let d = parse_dissolve_bundle(&frozen("dissolve_bundle"));
    let packed = pack_share_bundle(&[&d.shares[1], &d.shares[2], &d.shares[3]]);
    assert_eq!(packed, frozen("share_bundle_slots_1_to_3"));
}

#[test]
fn the_native_wasm_build_verifies_and_reconstructs_from_the_frozen_bytes() {
    let plain = frozen("plaintext");
    let d = parse_dissolve_bundle(&frozen("dissolve_bundle"));
    for s in &d.shares {
        assert!(miasma_wasm::verify_share_bytes(s, &d.mid)
            .ok()
            .expect("verify"));
    }
    assert_eq!(
        retrieve_bundle(&d.mid, &frozen("share_bundle_slots_1_to_3"), d.k, d.n),
        plain
    );
    let other = pack_share_bundle(&[&d.shares[0], &d.shares[2], &d.shares[4]]);
    assert_eq!(retrieve_bundle(&d.mid, &other, d.k, d.n), plain);
}

#[test]
fn miasma_core_reads_the_shares_made_by_the_shipped_web_build() {
    let plain = frozen("plaintext");
    let d = parse_dissolve_bundle(&frozen("dissolve_bundle"));
    let mid = ContentId::from_str(&d.mid).unwrap();
    let params = DissolutionParams {
        data_shards: d.k,
        total_shards: d.n,
    };
    // The MID is the one core computes for this plaintext and these parameters.
    assert_eq!(mid, ContentId::compute(&plain, &params.to_param_bytes()));
    let shares: Vec<MiasmaShare> = d
        .shares
        .iter()
        .map(|s| MiasmaShare::from_bytes(s).expect("core reads the web share"))
        .collect();
    for (a, b, c) in [(0, 1, 2), (1, 2, 3), (0, 2, 4), (2, 3, 4)] {
        let pick = vec![shares[a].clone(), shares[b].clone(), shares[c].clone()];
        assert_eq!(retrieve(&mid, &pick, params).unwrap(), plain);
    }
}

#[test]
fn the_web_build_reads_the_shares_made_by_miasma_core() {
    let plain = b"made by miasma-core, read by the web bundle reader".to_vec();
    let params = DissolutionParams {
        data_shards: 3,
        total_shards: 5,
    };
    let (mid, shares) = miasma_core::dissolve(&plain, params).unwrap();
    let blobs: Vec<Vec<u8>> = shares.iter().map(|s| s.to_bytes().unwrap()).collect();
    let mid = mid.to_string();
    for s in &blobs {
        assert!(miasma_wasm::verify_share_bytes(s, &mid).ok().expect("verify"));
    }
    let bundle = pack_share_bundle(&[&blobs[0], &blobs[3], &blobs[4]]);
    assert_eq!(retrieve_bundle(&mid, &bundle, 3, 5), plain);
}

#[test]
fn a_bundle_made_now_by_the_native_wasm_code_is_read_by_miasma_core() {
    let plain = b"made now by miasma-wasm".to_vec();
    let bundle = miasma_wasm::dissolve_bytes_bundle(&plain, 3, 5)
        .ok()
        .expect("dissolve");
    let d = parse_dissolve_bundle(&bundle);
    let mid = ContentId::from_str(&d.mid).unwrap();
    let params = DissolutionParams {
        data_shards: d.k,
        total_shards: d.n,
    };
    let shares: Vec<MiasmaShare> = d
        .shares
        .iter()
        .take(3)
        .map(|s| MiasmaShare::from_bytes(s).unwrap())
        .collect();
    assert_eq!(retrieve(&mid, &shares, params).unwrap(), plain);
}
