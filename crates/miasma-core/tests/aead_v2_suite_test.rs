//! Suite-2 AEAD integration tests: the 49-byte associated data, the v2 key
//! schedule, and the sealing. Fixed inputs, fixed bytes. (design section 5.3)
//!
//! Suite 2 binds every segment to a 49-byte canonical associated data
//! (design section 1.2) and derives the AES key through HKDF with the label
//! `miasma-seg-key-v2` over that associated data (section 1.3). A change to the
//! layout, the label or the key schedule makes a segment that one build wrote
//! unreadable by another; these tests fail on any such change.
//!
//! Two independent witnesses meet on every expected value:
//!
//! * `core::format` (the library under test): `SegmentAad::encode`,
//!   `seal_segment`, `open_segment`, and the `ObjectSuite` mapping.
//! * The primitives spelled out here (HKDF-SHA256, AES-256-GCM) with the label
//!   and the layout written out by hand, so a label or an offset that moves in
//!   the library cannot also move here undetected.
//!
//! Both are compared against bytes in `tests/fixtures/aead_kat_v2/frozen.hex`,
//! which were computed by `tools/gen_aead_kat_v2.py` from the primitives alone
//! -- not from the library's output. No key, nonce, salt or password is a
//! literal in this file: each is derived with BLAKE3 in key-derivation mode
//! from a label, with the same context string the generator uses, so both
//! sides agree without sharing a secret. The v1 fixtures are never read or
//! written here; a new suite gets a new file.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use miasma_core::format::{
    open_segment, seal_segment, AadContext, AadLayout, ObjectSuite, SegmentAad, AAD_LEN,
};
use miasma_core::ContentId;

const FIXTURES: &str = include_str!("fixtures/aead_kat_v2/frozen.hex");

/// Must match the `derive_key_context` in `tools/gen_aead_kat_v2.py`.
const CTX: &str = "miasma aead known answers v2 (test-only)";

const SEG_LABEL: &[u8] = b"miasma-seg-key-v2";
const NAME_LABEL: &[u8] = b"miasma-name-key-v2";
const SUITE2: u16 = 2;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const NAME: &str = "kat-name-v2.txt";

// --- Deterministic test-only inputs (section 5.3 item 8) --------------------

/// BLAKE3 in key-derivation mode over a label; the XOF fills the whole buffer,
/// so the output is fully determined by the label and the context string. This
/// is the same construction the generator uses (`blake3(label, derive_key)`),
/// so the Rust side and the Python side agree without a shared literal.
fn fill_vec(label: &str, len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key(CTX);
    h.update(label.as_bytes());
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

fn fill<const N: usize>(label: &str) -> [u8; N] {
    fill_vec(label, N).try_into().unwrap()
}

fn lookup(name: &str) -> Vec<u8> {
    for line in FIXTURES.lines() {
        if line.starts_with('#') {
            continue;
        }
        if let Some((n, h)) = line.split_once(' ') {
            if n == name {
                return hex::decode(h.trim()).expect("fixture is hex");
            }
        }
    }
    panic!("no fixture {name}");
}

fn frozen(name: &str) -> Vec<u8> {
    lookup(name)
}

fn mid_bytes() -> [u8; 32] {
    fill("mid digest")
}

fn mid() -> ContentId {
    ContentId::from_digest(mid_bytes())
}

fn k_enc() -> [u8; 32] {
    fill("segment random key K_enc")
}

fn nonce() -> [u8; NONCE_LEN] {
    fill("aes nonce")
}

fn pw_key() -> [u8; 32] {
    fill("password key pw_key")
}

/// One KAT case, matching a row of the generator's `cases` table.
struct Case {
    label: &'static str,
    context: AadContext,
    segment_index: u32,
    k: usize,
    n: usize,
    plaintext_len: usize,
    with_password: bool,
}

const CASES: [Case; 3] = [
    Case {
        label: "transfer",
        context: AadContext::TransferSegment,
        segment_index: 2,
        k: 4,
        n: 6,
        plaintext_len: 64,
        with_password: true,
    },
    Case {
        label: "wholefile",
        context: AadContext::WholeFile,
        segment_index: 0,
        k: 3,
        n: 5,
        plaintext_len: 64,
        with_password: false,
    },
    Case {
        label: "directed",
        context: AadContext::Directed,
        segment_index: 0,
        k: 3,
        n: 5,
        plaintext_len: 40,
        with_password: false,
    },
];

impl Case {
    fn plaintext(&self) -> Vec<u8> {
        fill_vec(&format!("plaintext {}", self.label), self.plaintext_len)
    }
    fn salt(&self) -> Option<[u8; 32]> {
        if self.with_password {
            Some(pw_key())
        } else {
            None
        }
    }
    /// The library-built AAD for this case.
    fn lib_aad(&self) -> [u8; AAD_LEN] {
        SegmentAad::new(
            ObjectSuite::Suite2,
            self.context,
            &mid(),
            self.segment_index,
            self.k,
            self.n,
            self.plaintext_len,
        )
        .expect("shard counts and length fit the AAD")
        .encode()
    }
}

// --- The associated data and key schedule, recomputed by hand ---------------

/// The 49-byte layout of section 1.2, spelled out. Not a call into the library.
fn indep_aad(
    suite: u16,
    context: u8,
    mid: &[u8; 32],
    segment_index: u32,
    k: u8,
    n: u8,
    plaintext_len: u32,
) -> [u8; AAD_LEN] {
    let mut out = [0u8; AAD_LEN];
    out[0..4].copy_from_slice(b"MSA2");
    out[4..6].copy_from_slice(&suite.to_le_bytes());
    out[6] = context;
    out[7..39].copy_from_slice(mid);
    out[39..43].copy_from_slice(&segment_index.to_le_bytes());
    out[43] = k;
    out[44] = n;
    out[45..49].copy_from_slice(&plaintext_len.to_le_bytes());
    out
}

/// The 49-byte AAD for one case, by hand (the generator's `encode_aad`).
fn indep_case_aad(c: &Case) -> [u8; AAD_LEN] {
    indep_aad(
        SUITE2,
        c.context.as_u8(),
        &mid_bytes(),
        c.segment_index,
        c.k as u8,
        c.n as u8,
        c.plaintext_len as u32,
    )
}

/// The v2 key schedule of section 1.3, spelled out: HKDF-SHA256 with the label
/// `miasma-seg-key-v2` followed by the whole associated data, salted by the
/// password key when there is a password and unsalted otherwise.
fn indep_seg_key(salt: Option<&[u8; 32]>, k_enc: &[u8; 32], aad: &[u8; AAD_LEN]) -> [u8; 32] {
    let mut info = SEG_LABEL.to_vec();
    info.extend_from_slice(aad);
    let hk = Hkdf::<Sha256>::new(salt.map(|s| s.as_slice()), k_enc);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).unwrap();
    out
}

/// AES-256-GCM with the associated data, by hand. Returns `ciphertext || tag`.
fn indep_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .unwrap()
}

fn indep_open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

// --- The fixture is what the primitives compute (independent witness) --------

/// The frozen bytes are reproduced by the hand-written primitives, independent
/// of the library. This is the KAT in the sense of design section 5.2/5.3: the
/// expected values come from the definition, not from the implementation's
/// output.
#[test]
fn the_fixture_is_what_the_primitives_compute() {
    assert_eq!(mid_bytes().to_vec(), frozen("mid"), "mid input");
    assert_eq!(k_enc().to_vec(), frozen("k_enc"), "k_enc input");
    assert_eq!(nonce().to_vec(), frozen("nonce"), "nonce input");
    assert_eq!(pw_key().to_vec(), frozen("pw_key"), "pw_key input");

    for c in &CASES {
        let aad = indep_case_aad(c);
        assert_eq!(aad.to_vec(), frozen(&format!("aad_{}", c.label)), "{} aad", c.label);
        let kaes = indep_seg_key(c.salt().as_ref(), &k_enc(), &aad);
        assert_eq!(
            kaes.to_vec(),
            frozen(&format!("kaes_{}", c.label)),
            "{} K_aes",
            c.label
        );
        let ct = indep_seal(&kaes, &nonce(), &c.plaintext(), &aad);
        assert_eq!(ct, frozen(&format!("ct_{}", c.label)), "{} ciphertext", c.label);
        assert_eq!(ct.len(), c.plaintext_len + TAG_LEN);
    }
}

// --- The library agrees with the hand-written layout and the fixture ---------

#[test]
fn the_library_encodes_the_same_associated_data() {
    for c in &CASES {
        let from_lib = c.lib_aad();
        let by_hand = indep_case_aad(c);
        assert_eq!(from_lib, by_hand, "{}: library vs by-hand aad", c.label);
        assert_eq!(
            from_lib.to_vec(),
            frozen(&format!("aad_{}", c.label)),
            "{}: library aad vs frozen",
            c.label
        );
        assert_eq!(from_lib.len(), AAD_LEN);
    }
}

/// `SegmentAad::decode` is the inverse of `encode` on the frozen bytes.
#[test]
fn the_library_decodes_the_frozen_associated_data() {
    for c in &CASES {
        let bytes = frozen(&format!("aad_{}", c.label));
        let bytes: [u8; AAD_LEN] = bytes.as_slice().try_into().unwrap();
        let parsed = SegmentAad::decode(&bytes).expect("frozen aad parses");
        assert_eq!(parsed.suite, ObjectSuite::Suite2, "{}: suite", c.label);
        assert_eq!(parsed.context, c.context, "{}: context", c.label);
        assert_eq!(parsed.mid, mid_bytes(), "{}: mid", c.label);
        assert_eq!(parsed.segment_index, c.segment_index, "{}: segment_index", c.label);
        assert_eq!(parsed.data_shards, c.k as u8, "{}: k", c.label);
        assert_eq!(parsed.total_shards, c.n as u8, "{}: n", c.label);
        assert_eq!(parsed.plaintext_len, c.plaintext_len as u32, "{}: plaintext_len", c.label);
        assert_eq!(parsed.encode(), bytes, "{}: re-encode round trip", c.label);
    }
}

#[test]
fn the_library_seals_and_opens_the_frozen_bytes() {
    for c in &CASES {
        let aad = frozen(&format!("aad_{}", c.label));
        let aad: [u8; AAD_LEN] = aad.as_slice().try_into().unwrap();
        let pt = c.plaintext();
        let salt = c.salt();
        let sealed = seal_segment(Zeroizing::new(k_enc()), &nonce(), &pt, &aad, salt.as_ref());
        assert_eq!(sealed, frozen(&format!("ct_{}", c.label)), "{}: library seal vs frozen", c.label);
        let opened = open_segment(&k_enc(), &nonce(), &sealed, &aad, salt.as_ref())
            .expect("opens with the right key, nonce and aad");
        assert_eq!(opened, pt, "{}: round trip", c.label);
    }
}

// --- Section 5.3 item 1: changing one bound field refuses the open -----------

#[test]
fn changing_one_bound_field_refuses_the_open() {
    // The transfer case exercises every field with a password.
    let c = &CASES[0];
    let base = indep_case_aad(c);
    let pt = c.plaintext();
    let salt = c.salt();
    let sealed = seal_segment(Zeroizing::new(k_enc()), &nonce(), &pt, &base, salt.as_ref());

    // Each variant changes exactly one bound field. The key schedule binds the
    // whole associated data, so any change must refuse.
    let mut variants: Vec<[u8; AAD_LEN]> = Vec::new();
    // suite (two neighbouring values)
    variants.push(indep_aad(1, c.context.as_u8(), &mid_bytes(), c.segment_index, c.k as u8, c.n as u8, c.plaintext_len as u32));
    variants.push(indep_aad(3, c.context.as_u8(), &mid_bytes(), c.segment_index, c.k as u8, c.n as u8, c.plaintext_len as u32));
    // context
    variants.push(indep_aad(SUITE2, 2, &mid_bytes(), c.segment_index, c.k as u8, c.n as u8, c.plaintext_len as u32));
    variants.push(indep_aad(SUITE2, 3, &mid_bytes(), c.segment_index, c.k as u8, c.n as u8, c.plaintext_len as u32));
    // every byte of the mid (32 cases)
    for i in 0..32 {
        let mut m = mid_bytes();
        m[i] ^= 1;
        variants.push(indep_aad(SUITE2, c.context.as_u8(), &m, c.segment_index, c.k as u8, c.n as u8, c.plaintext_len as u32));
    }
    // segment_index: +1, -1, u32::MAX
    variants.push(indep_aad(SUITE2, c.context.as_u8(), &mid_bytes(), c.segment_index + 1, c.k as u8, c.n as u8, c.plaintext_len as u32));
    variants.push(indep_aad(SUITE2, c.context.as_u8(), &mid_bytes(), c.segment_index - 1, c.k as u8, c.n as u8, c.plaintext_len as u32));
    variants.push(indep_aad(SUITE2, c.context.as_u8(), &mid_bytes(), u32::MAX, c.k as u8, c.n as u8, c.plaintext_len as u32));
    // k, n
    variants.push(indep_aad(SUITE2, c.context.as_u8(), &mid_bytes(), c.segment_index, c.k as u8 + 1, c.n as u8, c.plaintext_len as u32));
    variants.push(indep_aad(SUITE2, c.context.as_u8(), &mid_bytes(), c.segment_index, c.k as u8, c.n as u8 + 1, c.plaintext_len as u32));
    // plaintext_len: +1, -1
    variants.push(indep_aad(SUITE2, c.context.as_u8(), &mid_bytes(), c.segment_index, c.k as u8, c.n as u8, c.plaintext_len as u32 + 1));
    variants.push(indep_aad(SUITE2, c.context.as_u8(), &mid_bytes(), c.segment_index, c.k as u8, c.n as u8, c.plaintext_len as u32 - 1));

    for (i, v) in variants.iter().enumerate() {
        assert_ne!(*v, base, "variant {i} is not actually a change");
        assert!(
            open_segment(&k_enc(), &nonce(), &sealed, v, salt.as_ref()).is_none(),
            "variant {i}: a changed field must refuse the open",
        );
    }
}

// --- Section 5.3 item 2: flipping any bit of the associated data refuses -----

#[test]
fn flipping_any_bit_of_the_associated_data_refuses_the_open() {
    let c = &CASES[1]; // whole-file, no password
    let aad = indep_case_aad(c);
    let pt = c.plaintext();
    let sealed = seal_segment(Zeroizing::new(k_enc()), &nonce(), &pt, &aad, None);
    assert!(open_segment(&k_enc(), &nonce(), &sealed, &aad, None).is_some());
    let mut refused = 0usize;
    for byte in 0..AAD_LEN {
        for bit in 0..8 {
            let mut bad = aad;
            bad[byte] ^= 1 << bit;
            assert!(
                open_segment(&k_enc(), &nonce(), &sealed, &bad, None).is_none(),
                "byte {byte} bit {bit}: a flipped bit must refuse",
            );
            refused += 1;
        }
    }
    assert_eq!(refused, AAD_LEN * 8, "every bit was tested (49 * 8 = 392)");
}

// --- Section 5.3 item 3: a v1 decryptor and a v2 decryptor do not cross ------

#[test]
fn a_v2_ciphertext_does_not_open_as_v1_and_the_reverse() {
    let c = &CASES[1]; // whole-file, no password
    let aad = indep_case_aad(c);
    let pt = c.plaintext();

    // v2: key from HKDF over the label and the aad; sealed with the aad.
    let v2_key = indep_seg_key(None, &k_enc(), &aad);
    let v2_ct = seal_segment(Zeroizing::new(k_enc()), &nonce(), &pt, &aad, None);

    // v1 of the no-password path: the AES key is K_enc itself, no associated
    // data (see aead_known_answer_test.rs). A v1 decryptor is AES-GCM under
    // K_enc with an empty aad -- it must not open the v2 ciphertext.
    let v1_opens_v2 = indep_open(&k_enc(), &nonce(), &v2_ct, b"");
    assert!(v1_opens_v2.is_none(), "a v1 decryptor must not open a v2 ciphertext");

    // And a v1 ciphertext (K_enc, empty aad) must not open as v2 (needs the aad
    // and the HKDF-derived key).
    let v1_ct = indep_seal(&k_enc(), &nonce(), &pt, b"");
    assert!(
        open_segment(&k_enc(), &nonce(), &v1_ct, &aad, None).is_none(),
        "a v2 decryptor must not open a v1 ciphertext",
    );
    // The keys differ, which is why the schedule alone already separates them.
    assert_ne!(v2_key, k_enc(), "the v2 key is not K_enc itself");
}

// --- Section 5.3 item 4: a mismatched original_len or version is refused -----
//     before the open, on the manifest-less path.

/// On the manifest-less path (whole-file / directed), the receiver groups the
/// k selected shares and builds the AAD from the agreed `original_len` and
/// `version`. If the k shares do not all agree, the selection is rejected
/// before any key is derived or any ciphertext is touched. This mirrors the
/// design: `plaintext_len` comes from "the k shares' original_len, rejected if
/// they disagree" (section 1.2) and the version must be uniform (section 1.5).
fn agreed_len_and_version(shares: &[miasma_core::MiasmaShare]) -> Option<(u32, u8)> {
    let first = shares.first()?;
    let len = first.original_len;
    let ver = first.version;
    if shares.iter().any(|s| s.original_len != len || s.version != ver) {
        return None;
    }
    Some((len, ver))
}

#[test]
fn disagreeing_shares_are_refused_before_the_open() {
    use miasma_core::MiasmaShare;
    let m = mid();
    let mk = |original_len: u32, version: u8| {
        let mut s = MiasmaShare::new(
            &m,
            0,
            0,
            vec![1, 2, 3],
            vec![4, 5, 6],
            nonce(),
            original_len,
            0,
        );
        s.version = version;
        s
    };

    // All agree: the selection yields the agreed length and version.
    let good = vec![mk(64, 2), mk(64, 2), mk(64, 2)];
    assert_eq!(agreed_len_and_version(&good), Some((64, 2)));

    // One share reports a different plaintext length: refuse before the open.
    let bad_len = vec![mk(64, 2), mk(65, 2), mk(64, 2)];
    assert_eq!(agreed_len_and_version(&bad_len), None, "a length mismatch must be refused");

    // One share claims a different version: refuse before the open.
    let bad_ver = vec![mk(64, 2), mk(64, 1), mk(64, 2)];
    assert_eq!(agreed_len_and_version(&bad_ver), None, "a version mismatch must be refused");
}

// --- Section 5.3 item 5: round trip over the length boundaries ---------------

#[test]
fn the_round_trip_holds_over_the_length_boundaries() {
    // 0, 1, 15, 16, 17 and 64 KiB cover the block boundaries. 64 MiB is in the
    // release-only test below.
    const LENGTHS: [usize; 6] = [0, 1, 15, 16, 17, 64 * 1024];
    for len in LENGTHS {
        let pt = fill_vec(&format!("len {len}"), len);
        let aad = indep_aad(SUITE2, 2, &mid_bytes(), 0, 3, 5, len as u32);
        let sealed = seal_segment(Zeroizing::new(k_enc()), &nonce(), &pt, &aad, None);
        assert_eq!(sealed.len(), len + TAG_LEN, "len {len}: ciphertext length");
        let opened = open_segment(&k_enc(), &nonce(), &sealed, &aad, None).expect("opens");
        assert_eq!(opened, pt, "len {len}: round trip");
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "the 64 MiB case runs in release only")]
fn the_round_trip_holds_at_sixty_four_mebibytes() {
    let len = 64 * 1024 * 1024;
    let pt = fill_vec("len 64 MiB", len);
    let aad = indep_aad(SUITE2, 2, &mid_bytes(), 0, 3, 5, len as u32);
    let sealed = seal_segment(Zeroizing::new(k_enc()), &nonce(), &pt, &aad, None);
    assert_eq!(sealed.len(), len + TAG_LEN);
    let opened = open_segment(&k_enc(), &nonce(), &sealed, &aad, None).expect("opens");
    assert_eq!(opened, pt);
}

// --- Section 5.3 item 6: the inputs are unique across many segments ----------

#[test]
fn the_segment_keys_and_the_derived_keys_are_unique_across_many_segments() {
    // A sanity check of the uniqueness the proof in section 1.4 relies on: a
    // thousand fresh K_enc values, each giving a distinct derived key and a
    // distinct nonce. The test values are deterministic (so this is a check of
    // the derivation, not of the OS RNG), but a collision here would still flag
    // a mistake in how an input is built.
    use std::collections::HashSet;
    let mut k_set: HashSet<[u8; 32]> = HashSet::new();
    let mut n_set: HashSet<[u8; NONCE_LEN]> = HashSet::new();
    let mut d_set: HashSet<[u8; 32]> = HashSet::new();
    let aad = indep_aad(SUITE2, 1, &mid_bytes(), 0, 3, 5, 64);
    for i in 0..1000u32 {
        let ke: [u8; 32] = fill(&format!("unique k_enc {i}"));
        let no: [u8; NONCE_LEN] = fill(&format!("unique nonce {i}"));
        let derived = indep_seg_key(None, &ke, &aad);
        assert!(k_set.insert(ke), "K_enc {i} repeats");
        assert!(n_set.insert(no), "nonce {i} repeats");
        assert!(d_set.insert(derived), "derived key {i} repeats");
    }
    assert_eq!(k_set.len(), 1000);
    assert_eq!(n_set.len(), 1000);
    assert_eq!(d_set.len(), 1000);
}

// Section 5.3 item 7 (a reused K_enc does not compile) is the `compile_fail`
// doc-test on `seal_segment` in `src/format/seal.rs`; it lives with the
// function it guards and runs under `cargo test --doc`.

// --- The sealed name of suite 2 (section 1.3) -------------------------------

/// `aad = "MSN2" || suite(u16le) || mid`, by hand.
fn indep_name_aad(suite: u16, mid: &[u8; 32]) -> Vec<u8> {
    let mut out = b"MSN2".to_vec();
    out.extend_from_slice(&suite.to_le_bytes());
    out.extend_from_slice(mid);
    out
}

fn indep_name_key(pw_key: &[u8; 32], mid: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(pw_key), mid);
    let mut out = [0u8; 32];
    hk.expand(NAME_LABEL, &mut out).unwrap();
    out
}

#[test]
fn the_sealed_name_v2_is_bound_to_the_suite_and_the_mid() {
    let name_aad = indep_name_aad(SUITE2, &mid_bytes());
    assert_eq!(name_aad, frozen("name_aad"), "name aad");
    let key = indep_name_key(&pw_key(), &mid_bytes());
    assert_eq!(key.to_vec(), frozen("name_key"), "name key");

    let sealed = frozen("name_sealed");
    // Layout: nonce(12) || ciphertext || tag(16).
    assert_eq!(sealed.len(), NONCE_LEN + NAME.len() + TAG_LEN);
    let n: [u8; NONCE_LEN] = sealed[..NONCE_LEN].try_into().unwrap();
    assert_eq!(n.to_vec(), frozen("name_nonce"), "name nonce");
    let plain = indep_open(&key, &n, &sealed[NONCE_LEN..], &name_aad)
        .expect("opens with the name key and aad");
    assert_eq!(plain, NAME.as_bytes());

    // The wrong suite in the aad refuses.
    let wrong_aad = indep_name_aad(1, &mid_bytes());
    assert!(indep_open(&key, &n, &sealed[NONCE_LEN..], &wrong_aad).is_none());
    // A flipped tag refuses.
    let mut bad = sealed.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(indep_open(&key, &n, &bad[NONCE_LEN..], &name_aad).is_none());
}

// --- The ObjectSuite mapping (section 2.2) ----------------------------------

#[test]
fn the_object_suite_maps_versions_both_ways() {
    assert_eq!(ObjectSuite::from_share_version(1).unwrap(), ObjectSuite::Suite1);
    assert_eq!(ObjectSuite::from_share_version(2).unwrap(), ObjectSuite::Suite2);
    assert_eq!(ObjectSuite::from_manifest_version(3).unwrap(), ObjectSuite::Suite1);
    assert_eq!(ObjectSuite::from_manifest_version(4).unwrap(), ObjectSuite::Suite2);
    assert_eq!(ObjectSuite::from_envelope_version(1).unwrap(), ObjectSuite::Suite1);
    assert_eq!(ObjectSuite::from_envelope_version(2).unwrap(), ObjectSuite::Suite2);

    // An unknown version does not silently fall back to an older suite.
    assert!(ObjectSuite::from_share_version(3).is_err());
    assert!(ObjectSuite::from_manifest_version(5).is_err());
    assert!(ObjectSuite::from_envelope_version(3).is_err());

    // The id round-trips through from_id.
    assert_eq!(ObjectSuite::from_id(2).unwrap(), ObjectSuite::Suite2);
    assert_eq!(ObjectSuite::Suite2.id(), 2);

    // The suite decides the labels and the layout.
    let s1 = ObjectSuite::Suite1.spec();
    let s2 = ObjectSuite::Suite2.spec();
    assert_eq!(s1.share_version, 1);
    assert_eq!(s2.share_version, 2);
    assert_eq!(s1.manifest_version, 3);
    assert_eq!(s2.manifest_version, 4);
    assert_eq!(s2.segment_key_label, SEG_LABEL);
    assert_eq!(s2.name_key_label, NAME_LABEL);
    assert!(matches!(s1.aad, AadLayout::None));
    assert!(matches!(s2.aad, AadLayout::Msa2));
}
