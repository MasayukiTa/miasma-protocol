//! The group chat (v1) wire format, frozen byte for byte.
//!
//! These bytes are the contract with already-released builds; changing them is
//! a breaking change. A release that has group chat reads and writes exactly
//! these layouts, so a build that encodes something else for the same values,
//! or stops reading one of these byte strings, splits the group in two.
//!
//! Every fixture is a hex file under `tests/fixtures/group_v1/`, produced from
//! fixed inputs (Ed25519 seeds `[n; 32]`, fixed timestamps, fixed ids). Ed25519
//! signatures are deterministic, so the signed descriptors are reproducible.
//! The tests check that
//!
//! * (a) the current encoder produces exactly these bytes,
//! * (b) the current decoder accepts them and gives the original values back,
//! * (c) what an old build rejects is rejected with the specific error (more
//!   than 32 members, descriptor version other than 1, over-long name or
//!   hint, ...), which documents what an old build does with a newer peer's
//!   descriptor,
//! * (d) which trailing bytes are tolerated (an `Ack` frame) and which are
//!   refused (descriptors and group records).
//!
//! Not covered here: the sealed envelope itself (that is the pairwise cipher
//! of the one-to-one chat, frozen in `wire_compat_test.rs`) and its padding.
//! The group service sends the same `Deliver` / `Ack` frames as the private
//! chat, so only the group-specific plaintext layouts and the `Ack` use are
//! frozen below.
//!
//! The files were written once by `regenerate_fixtures` (run with
//! `MIASMA_WRITE_GROUP_FIXTURES=1`). Regenerating the existing v1 files after
//! a failing test would hide a break instead of fixing it; a new format gets
//! new files and a new version.

use ed25519_dalek::SigningKey;
use miasma_core::chat::group::membership::{
    Chain, DescError, Descriptor, Member, Pushed, Role, DESCRIPTOR_VERSION, MAX_HINT_BYTES,
    MAX_MEMBERS, MAX_NAME_BYTES,
};
use miasma_core::chat::group::record::{
    encode_descs, encode_sync, GroupText, Record, RecordError, KIND_DESCS, KIND_SYNC, KIND_TEXT,
};
use miasma_core::chat::proto::{decode_frame, encode_frame, Ack, AckStatus, Frame};

const GID: [u8; 16] = [0xA1; 16];
const CREATED_MS: u64 = 1_700_000_000_000;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn id(n: u8) -> [u8; 32] {
    key(n).verifying_key().to_bytes()
}

fn member(n: u8, role: Role, hint: &str) -> Member {
    Member {
        id: id(n),
        role,
        hint: hint.to_owned(),
    }
}

fn desc(epoch: u32, prev: [u8; 32], name: &str, members: Vec<Member>, signer: u8) -> Descriptor {
    Descriptor {
        gid: GID,
        epoch,
        name: name.to_owned(),
        created_ms: CREATED_MS,
        prev_hash: prev,
        members,
        signer: [0; 32],
        sig: [0; 64],
    }
    .signed(&key(signer))
}

fn d1() -> Descriptor {
    desc(1, [0; 32], "solo", vec![member(1, Role::Admin, "")], 1)
}

fn d2() -> Descriptor {
    desc(
        1,
        [0; 32],
        "pair",
        vec![
            member(1, Role::Admin, "alice"),
            member(2, Role::Member, "bob"),
        ],
        1,
    )
}

/// 32 members, the longest name and the longest hints.
fn d32() -> Descriptor {
    let name = "n".repeat(MAX_NAME_BYTES);
    let hint = "h".repeat(MAX_HINT_BYTES);
    let members = (1..=MAX_MEMBERS as u8)
        .map(|n| {
            member(
                n,
                if n % 2 == 1 {
                    Role::Admin
                } else {
                    Role::Member
                },
                &hint,
            )
        })
        .collect();
    desc(1, [0; 32], &name, members, 1)
}

/// Three consecutive descriptors: creation, an addition by an admin, and a
/// member leaving by its own signature.
fn chain3() -> Vec<Descriptor> {
    let c1 = desc(
        1,
        [0; 32],
        "team",
        vec![
            member(1, Role::Admin, "alice"),
            member(2, Role::Member, "bob"),
        ],
        1,
    );
    let c2 = desc(
        2,
        c1.hash(),
        "team",
        vec![
            member(1, Role::Admin, "alice"),
            member(2, Role::Member, "bob"),
            member(3, Role::Admin, "carol"),
        ],
        1,
    );
    let c3 = desc(
        3,
        c2.hash(),
        "team",
        vec![
            member(1, Role::Admin, "alice"),
            member(3, Role::Admin, "carol"),
        ],
        2,
    );
    vec![c1, c2, c3]
}

fn text_ascii() -> GroupText {
    GroupText {
        gid: GID,
        epoch: 3,
        counter: 9,
        id: [0x5C; 16],
        sent_ms: 1_700_000_123_456,
        text: "hello group".to_owned(),
    }
}

fn text_utf8() -> GroupText {
    GroupText {
        gid: GID,
        epoch: 0x0102_0304,
        counter: u64::MAX,
        id: [0x07; 16],
        sent_ms: 1,
        text: "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1f600}".to_owned(),
    }
}

const SYNC_HAVE: u32 = 7;

fn ack(status: AckStatus) -> Vec<u8> {
    encode_frame(&Frame::Ack(Ack {
        status,
        envelope_id: [0xE0; 16],
    }))
}

/// Every fixture: file name and the bytes the current encoder produces.
fn all() -> Vec<(&'static str, Vec<u8>)> {
    let c = chain3();
    vec![
        ("desc_1member", d1().encode()),
        ("desc_1member_hash", d1().hash().to_vec()),
        ("desc_2members", d2().encode()),
        ("desc_2members_hash", d2().hash().to_vec()),
        ("desc_32members_max", d32().encode()),
        ("desc_32members_max_hash", d32().hash().to_vec()),
        ("chain_descs_record", encode_descs(&c).unwrap()),
        ("record_text_ascii", text_ascii().encode().unwrap()),
        ("record_text_utf8", text_utf8().encode().unwrap()),
        ("record_sync", encode_sync(&GID, SYNC_HAVE)),
        ("frame_ack_stored", ack(AckStatus::Stored)),
        ("frame_ack_duplicate", ack(AckStatus::Duplicate)),
        ("frame_ack_no_session", ack(AckStatus::NoSession)),
        ("frame_ack_not_allowed", ack(AckStatus::NotAllowed)),
        ("frame_ack_too_big", ack(AckStatus::TooBig)),
        ("frame_ack_rate", ack(AckStatus::Rate)),
        ("frame_ack_busy", ack(AckStatus::Busy)),
        ("frame_ack_bad_request", ack(AckStatus::BadRequest)),
        ("frame_ack_unsupported", ack(AckStatus::Unsupported)),
        ("frame_ack_failed", ack(AckStatus::Failed)),
    ]
}

macro_rules! fixture {
    ($name:literal) => {
        hex::decode(
            include_str!(concat!("fixtures/group_v1/", $name, ".hex"))
                .split_whitespace()
                .collect::<String>(),
        )
        .expect("fixture is hex")
    };
}

fn frozen(name: &str) -> Vec<u8> {
    match name {
        "desc_1member" => fixture!("desc_1member"),
        "desc_1member_hash" => fixture!("desc_1member_hash"),
        "desc_2members" => fixture!("desc_2members"),
        "desc_2members_hash" => fixture!("desc_2members_hash"),
        "desc_32members_max" => fixture!("desc_32members_max"),
        "desc_32members_max_hash" => fixture!("desc_32members_max_hash"),
        "chain_descs_record" => fixture!("chain_descs_record"),
        "record_text_ascii" => fixture!("record_text_ascii"),
        "record_text_utf8" => fixture!("record_text_utf8"),
        "record_sync" => fixture!("record_sync"),
        "frame_ack_stored" => fixture!("frame_ack_stored"),
        "frame_ack_duplicate" => fixture!("frame_ack_duplicate"),
        "frame_ack_no_session" => fixture!("frame_ack_no_session"),
        "frame_ack_not_allowed" => fixture!("frame_ack_not_allowed"),
        "frame_ack_too_big" => fixture!("frame_ack_too_big"),
        "frame_ack_rate" => fixture!("frame_ack_rate"),
        "frame_ack_busy" => fixture!("frame_ack_busy"),
        "frame_ack_bad_request" => fixture!("frame_ack_bad_request"),
        "frame_ack_unsupported" => fixture!("frame_ack_unsupported"),
        "frame_ack_failed" => fixture!("frame_ack_failed"),
        other => panic!("no fixture {other}"),
    }
}

/// Does nothing unless `MIASMA_WRITE_GROUP_FIXTURES` is set; see the header.
#[test]
fn regenerate_fixtures() {
    if std::env::var("MIASMA_WRITE_GROUP_FIXTURES").is_err() {
        return;
    }
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/group_v1");
    std::fs::create_dir_all(dir).unwrap();
    for (name, bytes) in all() {
        std::fs::write(
            format!("{dir}/{name}.hex"),
            format!("{}\n", hex::encode(bytes)),
        )
        .unwrap();
    }
}

// ─── (a) the encoder writes exactly the frozen bytes ─────────────────────────

#[test]
fn encoder_writes_the_frozen_bytes() {
    for (name, bytes) in all() {
        assert_eq!(hex::encode(&bytes), hex::encode(frozen(name)), "{name}");
    }
}

#[test]
fn descriptor_layout_is_as_documented() {
    // version | gid | epoch | created_ms | prev_hash | name len | name |
    // member count | (id | role | hint len | hint)* | signer | signature
    let b = frozen("desc_1member");
    assert_eq!(b[0], 1);
    assert_eq!(&b[1..17], &GID);
    assert_eq!(&b[17..21], &1u32.to_be_bytes());
    assert_eq!(&b[21..29], &CREATED_MS.to_be_bytes());
    assert_eq!(&b[29..61], &[0u8; 32]);
    assert_eq!(&b[61..63], &4u16.to_be_bytes());
    assert_eq!(&b[63..67], b"solo");
    assert_eq!(b[67], 1);
    assert_eq!(&b[68..100], &id(1));
    assert_eq!(b[100], 1); // admin
    assert_eq!(b[101], 0); // empty hint
    assert_eq!(&b[102..134], &id(1)); // signer
    assert_eq!(b.len(), 134 + 64);
    // Member role codes: 0 = member, 1 = admin.
    let b2 = frozen("desc_2members");
    assert_eq!(b2[67], 2); // count, right after the name "pair"
    assert_eq!(&b2[68..100], &id(1));
    assert_eq!(b2[100], 1); // admin
    assert_eq!(b2[101], 5); // hint "alice"
    assert_eq!(&b2[102..107], b"alice");
    assert_eq!(&b2[107..139], &id(2));
    assert_eq!(b2[139], 0); // member
}

// ─── (b) the decoder accepts them ────────────────────────────────────────────

#[test]
fn decoder_accepts_the_frozen_descriptors() {
    for (name, want) in [
        ("desc_1member", d1()),
        ("desc_2members", d2()),
        ("desc_32members_max", d32()),
    ] {
        let got = Descriptor::decode(&frozen(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(got, want, "{name}");
        got.verify_signature().unwrap();
        assert_eq!(got.encode(), frozen(name), "{name} re-encodes identically");
    }
    let big = Descriptor::decode(&frozen("desc_32members_max")).unwrap();
    assert_eq!(big.members.len(), 32);
    assert_eq!(big.name.len(), MAX_NAME_BYTES);
    assert!(big.members.iter().all(|m| m.hint.len() == MAX_HINT_BYTES));
    assert!(big.is_admin(&id(1)) && !big.is_admin(&id(2)));
    for (name, h) in [
        ("desc_1member_hash", d1().hash()),
        ("desc_2members_hash", d2().hash()),
        ("desc_32members_max_hash", d32().hash()),
    ] {
        assert_eq!(frozen(name), h.to_vec(), "{name}");
    }
}

#[test]
fn decoder_accepts_the_frozen_chain() {
    let rec = Record::decode(&frozen("chain_descs_record")).unwrap();
    let Record::Descs(ds) = rec else {
        panic!("not a descriptor record")
    };
    assert_eq!(ds, chain3());
    // The chain rules accept it: creation, addition by an admin, and a leave
    // signed by the leaving member.
    let chain = Chain::from_items(ds.clone()).unwrap();
    assert_eq!(chain.epoch(), 3);
    assert_eq!(chain.items().len(), 3);
    // An invited person starts from the newest descriptor only.
    let mut late = Chain::from_root(ds[1].clone()).unwrap();
    assert_eq!(late.push(ds[2].clone()), Ok(Pushed::Advanced));
    // Layout: kind | count | (u16 len | descriptor)*
    let raw = frozen("chain_descs_record");
    assert_eq!(raw[0], KIND_DESCS);
    assert_eq!(raw[1], 3);
    let len0 = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    assert_eq!(&raw[4..4 + len0], ds[0].encode().as_slice());
}

#[test]
fn decoder_accepts_the_frozen_records() {
    assert_eq!(
        Record::decode(&frozen("record_text_ascii")).unwrap(),
        Record::Text(text_ascii())
    );
    assert_eq!(
        Record::decode(&frozen("record_text_utf8")).unwrap(),
        Record::Text(text_utf8())
    );
    assert_eq!(
        Record::decode(&frozen("record_sync")).unwrap(),
        Record::Sync {
            gid: GID,
            have_epoch: SYNC_HAVE
        }
    );
    // Kind bytes: the private chat uses 1 and 2, group records 0x10..0x12.
    assert_eq!(frozen("record_text_ascii")[0], KIND_TEXT);
    assert_eq!(frozen("chain_descs_record")[0], KIND_DESCS);
    assert_eq!(frozen("record_sync")[0], KIND_SYNC);
    assert_eq!((KIND_TEXT, KIND_DESCS, KIND_SYNC), (0x10, 0x11, 0x12));
    // Text layout: kind | gid | epoch | counter | id | sent_ms | u16 len | utf-8
    let t = frozen("record_text_ascii");
    assert_eq!(t.len(), 1 + 16 + 4 + 8 + 16 + 8 + 2 + 11);
    assert_eq!(&t[t.len() - 11..], b"hello group");
}

#[test]
fn decoder_accepts_the_frozen_ack_frames() {
    let all_status = [
        ("frame_ack_stored", AckStatus::Stored, 0u8),
        ("frame_ack_duplicate", AckStatus::Duplicate, 1),
        ("frame_ack_no_session", AckStatus::NoSession, 2),
        ("frame_ack_not_allowed", AckStatus::NotAllowed, 3),
        ("frame_ack_too_big", AckStatus::TooBig, 4),
        ("frame_ack_rate", AckStatus::Rate, 5),
        ("frame_ack_busy", AckStatus::Busy, 6),
        ("frame_ack_bad_request", AckStatus::BadRequest, 7),
        ("frame_ack_unsupported", AckStatus::Unsupported, 8),
        ("frame_ack_failed", AckStatus::Failed, 9),
    ];
    for (name, status, code) in all_status {
        let b = frozen(name);
        // u32 body length (18) | type 0x02 | status | 16-byte envelope id
        assert_eq!(&b[..5], &[0, 0, 0, 18, 0x02], "{name}");
        assert_eq!(b[5], code, "{name}");
        assert_eq!(b.len(), 22);
        let (f, used) = decode_frame(&b).unwrap();
        assert_eq!(used, b.len());
        assert_eq!(
            f,
            Frame::Ack(Ack {
                status,
                envelope_id: [0xE0; 16]
            }),
            "{name}"
        );
    }
}

// ─── (c) what an old build refuses, and with which error ─────────────────────

#[test]
fn thirty_three_members_are_refused_as_malformed() {
    let members = (1..=33u8).map(|n| member(n, Role::Admin, "")).collect();
    let d = desc(1, [0; 32], "big", members, 1);
    let bytes = d.encode(); // the encoder itself does not stop at 32
    assert_eq!(bytes[66], 33); // count byte, right after the 3-byte name
                               // The decoder refuses the count before reading any member.
    assert_eq!(Descriptor::decode(&bytes), Err(DescError::Malformed));
    // A one-byte count: 255 cannot even be written for 256 members.
    let mut b = frozen("desc_32members_max");
    let count_at = 1 + 16 + 4 + 8 + 32 + 2 + MAX_NAME_BYTES;
    assert_eq!(b[count_at], 32);
    b[count_at] = 33;
    assert_eq!(Descriptor::decode(&b), Err(DescError::Malformed));
    b[count_at] = 0;
    assert_eq!(Descriptor::decode(&b), Err(DescError::Malformed));
}

#[test]
fn other_descriptor_versions_are_refused_as_malformed() {
    for v in [0u8, 2, 3, 255] {
        let mut b = frozen("desc_2members");
        b[0] = v;
        assert_eq!(Descriptor::decode(&b), Err(DescError::Malformed), "v{v}");
    }
    assert_eq!(DESCRIPTOR_VERSION, 1);
    // Inside a descriptor record the same descriptor makes the record malformed.
    let mut rec = frozen("chain_descs_record");
    rec[4] = 2; // version byte of the first descriptor
    assert_eq!(Record::decode(&rec), Err(RecordError::Malformed));
}

#[test]
fn limits_of_the_descriptor_are_enforced_at_decode() {
    // Name one byte too long (193): the length field is checked first.
    let long_name = "n".repeat(MAX_NAME_BYTES + 1);
    let d = desc(1, [0; 32], &long_name, vec![member(1, Role::Admin, "")], 1);
    assert_eq!(Descriptor::decode(&d.encode()), Err(DescError::Malformed));
    // Hint one byte too long (25).
    let h = "h".repeat(MAX_HINT_BYTES + 1);
    let d = desc(1, [0; 32], "x", vec![member(1, Role::Admin, &h)], 1);
    assert_eq!(Descriptor::decode(&d.encode()), Err(DescError::Malformed));
    // Epoch 0.
    let d = desc(0, [0; 32], "x", vec![member(1, Role::Admin, "")], 1);
    assert_eq!(Descriptor::decode(&d.encode()), Err(DescError::Malformed));
    // Unknown role code.
    let mut b = frozen("desc_1member");
    b[100] = 2;
    assert_eq!(Descriptor::decode(&b), Err(DescError::Malformed));
    // Duplicate member.
    let d = desc(
        1,
        [0; 32],
        "x",
        vec![member(1, Role::Admin, ""), member(1, Role::Member, "")],
        1,
    );
    assert_eq!(Descriptor::decode(&d.encode()), Err(DescError::Malformed));
    // No admin.
    let d = desc(1, [0; 32], "x", vec![member(1, Role::Member, "")], 1);
    assert_eq!(Descriptor::decode(&d.encode()), Err(DescError::NoAdmin));
    // Empty name.
    let d = desc(1, [0; 32], "", vec![member(1, Role::Admin, "")], 1);
    assert_eq!(Descriptor::decode(&d.encode()), Err(DescError::Malformed));
    // Truncated anywhere.
    let b = frozen("desc_2members");
    for n in [0, 1, 17, 66, b.len() - 1] {
        assert_eq!(
            Descriptor::decode(&b[..n]),
            Err(DescError::Malformed),
            "{n}"
        );
    }
}

#[test]
fn a_changed_byte_breaks_the_signature_not_the_shape() {
    let mut b = frozen("desc_2members");
    b[63] ^= 0x01; // a letter of the name
    let d = Descriptor::decode(&b).unwrap();
    assert_eq!(d.verify_signature(), Err(DescError::BadSignature));
}

#[test]
fn unknown_record_kinds_and_bad_shapes_are_refused() {
    assert_eq!(Record::decode(&[]), Err(RecordError::Malformed));
    for k in [0x00u8, 0x01, 0x02, 0x0F, 0x13, 0x20, 0xFF] {
        let mut b = frozen("record_sync");
        b[0] = k;
        assert_eq!(
            Record::decode(&b),
            Err(RecordError::UnknownKind(k)),
            "{k:#x}"
        );
    }
    // Text: zero counter, empty text, bad UTF-8.
    let mut t = frozen("record_text_ascii");
    t[21..29].fill(0);
    assert_eq!(Record::decode(&t), Err(RecordError::Malformed));
    let mut t = frozen("record_text_ascii");
    let n = t.len();
    t[n - 1] = 0xFF;
    assert_eq!(Record::decode(&t), Err(RecordError::Malformed));
    // Descs: zero descriptors.
    assert_eq!(
        Record::decode(&[KIND_DESCS, 0]),
        Err(RecordError::Malformed)
    );
}

// ─── (d) trailing bytes ──────────────────────────────────────────────────────

#[test]
fn trailing_bytes_are_refused_in_descriptors_and_group_records() {
    for name in [
        "desc_1member",
        "desc_2members",
        "chain_descs_record",
        "record_text_ascii",
        "record_sync",
    ] {
        let mut b = frozen(name);
        b.push(0);
        let res = if name.starts_with("desc_") {
            Descriptor::decode(&b).map(|_| ()).map_err(|_| ())
        } else {
            Record::decode(&b).map(|_| ()).map_err(|_| ())
        };
        assert_eq!(res, Err(()), "{name}: one extra byte must be refused");
    }
}

#[test]
fn trailing_bytes_are_tolerated_in_an_ack_frame() {
    // A newer build may append fields after the envelope id; the length prefix
    // covers them and an old reader ignores them.
    let mut b = frozen("frame_ack_stored");
    b.extend_from_slice(&[0xAA, 0xBB]);
    let new_len = (b.len() - 4) as u32;
    b[..4].copy_from_slice(&new_len.to_be_bytes());
    let (f, used) = decode_frame(&b).unwrap();
    assert_eq!(used, b.len());
    assert_eq!(
        f,
        Frame::Ack(Ack {
            status: AckStatus::Stored,
            envelope_id: [0xE0; 16]
        })
    );
    // A status code this build does not know is kept as Unknown, not an error.
    let mut b = frozen("frame_ack_stored");
    b[5] = 200;
    let (f, _) = decode_frame(&b).unwrap();
    assert_eq!(
        f,
        Frame::Ack(Ack {
            status: AckStatus::Unknown,
            envelope_id: [0xE0; 16]
        })
    );
}
