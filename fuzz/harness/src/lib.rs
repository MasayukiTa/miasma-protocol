//! Decoder entry points for the fuzz targets.
//!
//! Every function takes arbitrary bytes and must return without panicking,
//! overflowing or allocating without bound; the result of the decoder is
//! deliberately ignored. The functions live here (and not in the fuzz binaries)
//! so that the same code runs under libFuzzer, and, as a plain test on stable,
//! over the committed seed corpus (see `tests/corpus_replay.rs`).

use std::sync::OnceLock;

use miasma_core::state_crypto::{doc, log::LogReader, Label, StateKeys};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Split the input into a list of pieces, each introduced by a 2-byte
/// big-endian length (clamped to what is left). Gives the stateful targets a
/// whole sequence of messages from one input. At most 64 pieces.
fn pieces(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while rest.len() >= 2 && out.len() < 64 {
        let n = (u16::from_be_bytes([rest[0], rest[1]]) as usize).min(rest.len() - 2);
        let (piece, tail) = rest[2..].split_at(n);
        out.push(piece);
        rest = tail;
    }
    out
}

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

/// Chat wire frames and the records inside them.
pub fn chat_frame(data: &[u8]) {
    use miasma_core::chat::crypto::Envelope;
    use miasma_core::chat::proto::{decode_body, decode_frame, Message, ReadReceipt, Record};
    let _ = decode_frame(data);
    let _ = decode_body(data);
    let _ = Message::decode(data);
    let _ = ReadReceipt::decode(data);
    let _ = Record::decode(data);
    let _ = Envelope::decode(data);
}

/// Persisted conversation state. A state that parses must serialise to
/// something that parses again.
pub fn chat_state(data: &[u8]) {
    use miasma_core::chat::crypto::Session;
    if let Ok(session) = Session::from_bytes(data) {
        let again = session.to_bytes();
        assert!(
            Session::from_bytes(&again).is_ok(),
            "a parsed session state no longer parses after to_bytes"
        );
    }
    #[cfg(fuzzing)]
    miasma_core::chat::store::fuzz_peer_state(data);
}

/// Group descriptors, records and state.
pub fn group_decoders(data: &[u8]) {
    use miasma_core::chat::group::{membership, record, state, store};
    let _ = membership::Descriptor::decode(data);
    let _ = record::Record::decode(data);
    let _ = state::GroupState::decode(data);
    let _ = store::GroupMsg::decode(data);
}

/// Capability messages, handshake fragments and the reassembler.
pub fn capability_fragment(data: &[u8]) {
    use miasma_core::protocol::capability::Capabilities;
    use miasma_core::protocol::fragment::{HandshakeFragment, Reassembler, ReassemblyLimits};
    let _ = Capabilities::decode(data);
    let _ = HandshakeFragment::decode(data);
    let mut re = Reassembler::new(ReassemblyLimits::default());
    for (i, p) in pieces(data).into_iter().enumerate() {
        if let Ok(frag) = HandshakeFragment::decode(p) {
            let _ = re.push(frag, i as u64);
        }
    }
}

/// Hybrid key exchange messages: responder input, initiator reply, and the
/// fragment reassembly in front of them.
pub fn hybrid_kex(data: &[u8]) {
    use miasma_core::protocol::capability::Capabilities;
    use miasma_core::protocol::hybrid::{
        Config, Initiator, MessageReassembler, Mode, ReplayGuard, Responder,
    };
    let mode = match data.first() {
        Some(b) if b & 1 == 1 => Mode::Strict,
        _ => Mode::Compatibility,
    };
    let cfg = || Config {
        mode,
        local: Capabilities::current(),
        remote: Capabilities::current(),
        initiator_id: b"fuzz-initiator".to_vec(),
        responder_id: b"fuzz-responder".to_vec(),
    };
    let mut guard = ReplayGuard::new(16);
    let _ = Responder::accept(cfg(), data, &mut guard, &mut StdRng::seed_from_u64(1));
    if let Ok((init, _msg1)) = Initiator::start(cfg(), &mut StdRng::seed_from_u64(2)) {
        let _ = init.finish(data);
    }
    let mut re = MessageReassembler::new();
    for (i, p) in pieces(data).into_iter().enumerate() {
        let _ = re.push_frame(p, i as u64);
    }
}

/// DHT record values (a record followed by an optional manifest trailer) and
/// the signed record wrapper.
pub fn record_value(data: &[u8]) {
    use miasma_core::network::sybil::SignedDhtRecord;
    use miasma_core::transfer::manifest::decode_record_value;
    let _ = decode_record_value(data);
    let _ = bincode::deserialize::<SignedDhtRecord>(data);
}

/// Stored shares and manifests.
pub fn share_bytes(data: &[u8]) {
    use miasma_core::dissolution::DissolutionManifest;
    use miasma_core::share::MiasmaShare;
    use miasma_core::transfer::manifest::TransferManifest;
    let _ = MiasmaShare::from_bytes(data);
    let _ = DissolutionManifest::from_bytes(data);
    let _ = TransferManifest::from_bytes(data);
}

/// Directed-transfer wire messages, envelopes and sharing contacts.
pub fn directed_wire(data: &[u8]) {
    use miasma_core::directed::protocol::{DirectedRequest, DirectedResponse};
    use miasma_core::directed::{parse_sharing_contact, parse_sharing_key, DirectedEnvelope};
    let _ = bincode::deserialize::<DirectedRequest>(data);
    let _ = bincode::deserialize::<DirectedResponse>(data);
    let _ = bincode::deserialize::<DirectedEnvelope>(data);
    let s = text(data);
    let _ = parse_sharing_key(&s);
    let _ = parse_sharing_contact(&s);
}

/// Direct-transport messages (version byte, bincode body, bounded length).
pub fn ws_wire(data: &[u8]) {
    use miasma_core::transport::websocket::{
        decode_ws_message, WsRequest, WsResponse, WS_REQUEST_MAX_BYTES,
    };
    let _ = decode_ws_message::<WsRequest>(data, WS_REQUEST_MAX_BYTES);
    let _ = decode_ws_message::<WsResponse>(data, 1 << 20);
}

/// Text forms: contact codes, content ids, share ids, transfer ids.
pub fn contact_codes(data: &[u8]) {
    use miasma_core::crypto::hash::ContentId;
    use miasma_core::push::contact::ContactCode;
    use miasma_core::transfer::share_id::{parse_transfer_id, ShareId};
    let s = text(data);
    let _ = ContactCode::parse(&s);
    let _ = ContentId::from_str(&s);
    let _ = ShareId::parse(&s);
    let _ = parse_transfer_id(&s);
}

fn state_keys() -> &'static StateKeys {
    static KEYS: OnceLock<StateKeys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let master = blake3::hash(b"miasma fuzz harness master");
        StateKeys::from_master_key(master.as_bytes()).expect("derive state keys")
    })
}

/// Encrypted state documents and append-only logs read from arbitrary bytes.
/// The first byte picks the label; the rest is the file.
pub fn state_doc_log(data: &[u8]) {
    let Some((&sel, file)) = data.split_first() else {
        return;
    };
    let label = Label::ALL[sel as usize % Label::ALL.len()];
    let keys = state_keys();
    let _ = doc::open(keys, label, b"fuzz", file.to_vec());

    let path = std::env::temp_dir().join(format!("miasma-fuzz-log-{}.bin", std::process::id()));
    if std::fs::write(&path, file).is_ok() {
        if let Ok(Some(mut reader)) = LogReader::open(keys, label, &path) {
            for _ in 0..10_000 {
                match reader.next_record() {
                    Ok(Some(_)) => {}
                    _ => break,
                }
            }
        }
        let _ = std::fs::remove_file(&path);
    }
}

/// Update inputs: checksum lists, signatures and the release listing.
pub fn update_files(data: &[u8]) {
    use miasma_core::update::release::parse_releases;
    use miasma_core::update::verify::{decode_signature, parse_sums};
    let _ = parse_sums(data);
    let _ = decode_signature(data);
    let _ = parse_releases(data);
}

/// Onion packets and layers, and the return-path helpers.
pub fn onion_packet(data: &[u8]) {
    use miasma_core::onion::packet::{
        decrypt_response, unpad_fixed_size, LayerPayload, OnionLayer, OnionPacket,
    };
    let _ = bincode::deserialize::<OnionPacket>(data);
    let _ = bincode::deserialize::<OnionLayer>(data);
    let _ = bincode::deserialize::<LayerPayload>(data);
    let _ = unpad_fixed_size(data);
    let key = *blake3::hash(b"miasma fuzz harness response").as_bytes();
    let _ = decrypt_response(&key, data);
}

/// Name and entry point of every target, for the corpus replay test.
pub const TARGETS: &[(&str, fn(&[u8]))] = &[
    ("chat_frame", chat_frame),
    ("chat_state", chat_state),
    ("group_decoders", group_decoders),
    ("capability_fragment", capability_fragment),
    ("hybrid_kex", hybrid_kex),
    ("record_value", record_value),
    ("share_bytes", share_bytes),
    ("directed_wire", directed_wire),
    ("ws_wire", ws_wire),
    ("contact_codes", contact_codes),
    ("state_doc_log", state_doc_log),
    ("update_files", update_files),
    ("onion_packet", onion_packet),
];
