//! History hand-over wire format (ADR-012), exercised through the public
//! `chat::group::record` API only. No network and no platform-specific code:
//! the test encodes a `HistOffer`, decodes it back, and checks that the
//! attributed fields (the original author and the message body) survive a
//! round trip, that multibyte text is preserved, and that the group id can be
//! read straight from the bytes. It is placed in its own file so it is listed
//! explicitly in the CI core-test set.

use miasma_core::chat::group::record::{hist_gid, HistOffer, Record, KIND_HIST_OFFER};

fn offer(text: &str) -> HistOffer {
    HistOffer {
        gid: [7u8; 16],
        origin_epoch: 2,
        original_sender: [9u8; 32],
        original_counter: 5,
        original_id: [3u8; 16],
        original_sent_ms: 1_700_000_000_000,
        text: text.to_owned(),
    }
}

#[test]
fn a_hist_offer_round_trips_and_keeps_its_attribution_and_body() {
    for text in [
        "hello from before you joined",
        "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{5c65}\u{6b74}", // multibyte body
        "emoji \u{1f680} and ascii",
    ] {
        let original = offer(text);
        let bytes = original.encode().expect("a non-empty offer encodes");
        let decoded = Record::decode(&bytes).expect("its own bytes decode");
        assert_eq!(
            decoded,
            Record::HistOffer(original.clone()),
            "the original author, counter, id and body all survive the round trip"
        );
        if let Record::HistOffer(got) = decoded {
            assert_eq!(got.original_sender, original.original_sender);
            assert_eq!(got.text, text, "the body is preserved byte for byte");
        } else {
            panic!("a hand-over offer must decode as a hand-over offer");
        }
    }
}

#[test]
fn an_empty_body_is_refused() {
    assert!(
        offer("").encode().is_err(),
        "an offer with no text is malformed and never put on the wire"
    );
}

#[test]
fn the_group_id_can_be_read_straight_from_a_real_offer() {
    let o = offer("catch-up");
    let bytes = o.encode().unwrap();
    assert_eq!(hist_gid(&bytes), Some(o.gid));
    // Anything that is not a well-formed hand-over header yields no id, so a
    // caller never routes on a mislabelled record.
    assert_eq!(hist_gid(&[KIND_HIST_OFFER]), None);
    assert_eq!(hist_gid(&[]), None);
}

#[test]
fn the_wire_kind_is_pinned() {
    // The on-wire number must not drift: an older peer recognises 0x13 as an
    // unknown kind and is otherwise unaffected.
    assert_eq!(KIND_HIST_OFFER, 0x13);
}
