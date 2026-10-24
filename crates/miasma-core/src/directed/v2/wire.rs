//! v2 wire types and error codes.
//!
//! These mirror the v1 `DirectedRequest` / `DirectedResponse` layout: the first
//! variants keep the same indices and byte shapes, with new variants appended.
//! A v1 decoder reads a v2 `Invite` as a `version = 2` invite and refuses it.
//! None of these types are wired into a `Behaviour` yet.

use serde::{Deserialize, Serialize};

use crate::directed::envelope::{DirectedEnvelope, EnvelopeState};

/// Serde helper for `[u8; 64]` fields.
///
/// serde does not implement `Serialize`/`Deserialize` for arrays longer than 32
/// elements, so the signature and binding fields need an explicit codec. This
/// writes the 64 bytes as a fixed-length tuple (no length prefix), matching the
/// wire shape the design fixes for these fields and the encoding bincode already
/// uses for the shorter `[u8; N]` fields in the same structs.
mod bytes64 {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    const LEN: usize = 64;

    pub fn serialize<S>(value: &[u8; LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(LEN)?;
        for byte in value.iter() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Bytes64Visitor;

        impl<'de> Visitor<'de> for Bytes64Visitor {
            type Value = [u8; LEN];

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an array of {LEN} bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = [0u8; LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                v.try_into()
                    .map_err(|_| Error::invalid_length(v.len(), &self))
            }
        }

        deserializer.deserialize_tuple(LEN, Bytes64Visitor)
    }
}

/// Directed suite identifier for v2 (fixed value).
pub const SUITE_V2: u8 = 2;

/// Argon2id cost parameters carried in a v2 invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Time cost (number of passes).
    pub t_cost: u32,
    /// Parallelism (number of lanes).
    pub p_cost: u32,
}

/// The v2 extension that follows the v1 `DirectedEnvelope` inside an `Invite`.
#[derive(Clone, Serialize, Deserialize)]
pub struct InviteExtV2 {
    /// Suite selector (`SUITE_V2`).
    pub suite: u8,
    /// Argon2id cost parameters chosen by the sender.
    pub kdf: KdfParams,
    /// Sender's Ed25519 identity public key.
    pub sender_identity: [u8; 32],
    /// Signature binding `sender_identity` to the X25519 sharing key.
    #[serde(with = "bytes64")]
    pub sender_binding: [u8; 64],
    /// Recipient's Ed25519 identity public key.
    pub recipient_identity: [u8; 32],
    /// Identifier of the prekey offer this invite answers.
    pub offer_id: [u8; 16],
    /// Recipient ephemeral (`r_eph`) public key.
    pub recipient_ephemeral: [u8; 32],
    /// DEK wrapped under the wrap key (32 + 16 bytes).
    pub wrapped_dek: Vec<u8>,
    /// Nonce for the DEK wrap.
    pub dek_nonce: [u8; 24],
    /// Sender's signature over the transcript.
    #[serde(with = "bytes64")]
    pub signature: [u8; 64],
}

impl std::fmt::Debug for InviteExtV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteExtV2")
            .field("suite", &self.suite)
            .field("kdf", &self.kdf)
            .field("sender_identity", &"<redacted>")
            .field("sender_binding", &"<redacted>")
            .field("recipient_identity", &"<redacted>")
            .field("offer_id", &"<redacted>")
            .field("recipient_ephemeral", &"<redacted>")
            .field("wrapped_dek_len", &self.wrapped_dek.len())
            .field("dek_nonce", &"<redacted>")
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// A recipient's signed prekey offer.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedOffer {
    /// Suite selector echoed from the request.
    pub suite: u8,
    /// Offer identifier.
    pub offer_id: [u8; 16],
    /// Request identifier echoed from the request.
    pub request_id: [u8; 16],
    /// Requester PeerId bytes.
    pub requester: Vec<u8>,
    /// Recipient's Ed25519 identity public key.
    pub recipient_identity: [u8; 32],
    /// Recipient's X25519 sharing key (`R_static`).
    pub recipient_sharing: [u8; 32],
    /// Signature binding the sharing key to the identity.
    #[serde(with = "bytes64")]
    pub recipient_binding: [u8; 64],
    /// Recipient ephemeral (`r_eph`) public key.
    pub recipient_ephemeral: [u8; 32],
    /// Advertised lifetime in seconds (display only).
    pub ttl_secs: u32,
    /// Recipient's signature over the offer.
    #[serde(with = "bytes64")]
    pub signature: [u8; 64],
}

impl std::fmt::Debug for SignedOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedOffer")
            .field("suite", &self.suite)
            .field("offer_id", &"<redacted>")
            .field("request_id", &"<redacted>")
            .field("requester_len", &self.requester.len())
            .field("recipient_identity", &"<redacted>")
            .field("recipient_sharing", &"<redacted>")
            .field("recipient_binding", &"<redacted>")
            .field("recipient_ephemeral", &"<redacted>")
            .field("ttl_secs", &self.ttl_secs)
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// The v2 request. Indices 0..=3 match v1; 4 is new.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectedRequestV2 {
    /// A v2 invite: the v1 envelope followed by the v2 extension.
    Invite {
        /// The v1-shaped envelope with `version = 2`.
        envelope: DirectedEnvelope,
        /// The appended v2 extension.
        ext: InviteExtV2,
    },
    /// Sender confirms the recipient's challenge code.
    Confirm {
        /// Target envelope.
        envelope_id: [u8; 32],
        /// Challenge code entered out of band.
        challenge_code: String,
    },
    /// Sender revokes the share.
    SenderRevoke {
        /// Target envelope.
        envelope_id: [u8; 32],
    },
    /// Query the state of an envelope.
    StatusQuery {
        /// Target envelope.
        envelope_id: [u8; 32],
    },
    /// Request a prekey offer before sending an invite.
    PrekeyRequest {
        /// Request identifier.
        request_id: [u8; 16],
        /// Suites the requester accepts.
        suites: Vec<u8>,
    },
}

/// The v2 response. Indices 0..=5 match v1; 6 and 7 are new.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DirectedResponseV2 {
    /// The recipient accepted an invite (v1-compatible variant).
    InviteAccepted {
        /// Target envelope.
        envelope_id: [u8; 32],
    },
    /// The challenge was confirmed.
    Confirmed {
        /// Target envelope.
        envelope_id: [u8; 32],
    },
    /// The challenge failed; attempts remain.
    ChallengeFailed {
        /// Target envelope.
        envelope_id: [u8; 32],
        /// Remaining challenge attempts.
        attempts_remaining: u8,
    },
    /// The share was revoked.
    Revoked {
        /// Target envelope.
        envelope_id: [u8; 32],
    },
    /// The current state of an envelope.
    Status {
        /// Target envelope.
        envelope_id: [u8; 32],
        /// Current state.
        state: EnvelopeState,
    },
    /// A coded error (see [`codes`]).
    Error(String),
    /// A signed prekey offer.
    PrekeyOffer {
        /// The offer.
        offer: SignedOffer,
    },
    /// The invite was stored; the transcript hash pins it.
    InviteStored {
        /// Target envelope.
        envelope_id: [u8; 32],
        /// Transcript hash recorded for idempotent resend.
        transcript_hash: [u8; 32],
    },
}

/// Stable error codes carried in [`DirectedResponseV2::Error`].
pub mod codes {
    /// The offer id is not in the recipient's table.
    pub const OFFER_UNKNOWN: &str = "offer_unknown";
    /// The offer expired before the invite arrived.
    pub const OFFER_EXPIRED: &str = "offer_expired";
    /// A signature did not verify.
    pub const BAD_SIGNATURE: &str = "bad_signature";
    /// A PeerId did not match the one expected on this connection.
    pub const PEER_MISMATCH: &str = "peer_mismatch";
    /// A sharing key did not match the contact.
    pub const KEY_MISMATCH: &str = "key_mismatch";
    /// A KDF cost parameter was outside the shared bounds.
    pub const KDF_OUT_OF_RANGE: &str = "kdf_out_of_range";
    /// A v1 fallback was refused.
    pub const V1_REFUSED: &str = "v1_refused";
    /// An envelope id was reused with different content.
    pub const ID_CONFLICT: &str = "id_conflict";
    /// The suite is not supported.
    pub const UNSUPPORTED_SUITE: &str = "unsupported_suite";
}

/// Build the coded error string `directed-v2:<code>: <detail>`.
///
/// Clients split on the same shape the password policy uses, so the UI can take
/// the code and localise it.
pub fn error_string(code: &str, detail: &str) -> String {
    format!("directed-v2:{code}: {detail}")
}

/// Extract the code from a string built by [`error_string`], if it has that
/// shape.
pub fn parse_error_code(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("directed-v2:")?;
    let end = rest.find(':')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_arr<const N: usize>() -> [u8; N] {
        // `rand::random::<[u8; N]>()` only covers N <= 32; build the bytes one
        // draw at a time and convert, so any N works and no fixed value appears.
        let bytes: Vec<u8> = (0..N).map(|_| rand::random::<u8>()).collect();
        bytes.try_into().expect("N bytes collected")
    }

    fn sample_envelope() -> DirectedEnvelope {
        DirectedEnvelope {
            envelope_id: rand_arr(),
            version: SUITE_V2,
            sender_pubkey: rand_arr(),
            recipient_pubkey: rand_arr(),
            ephemeral_pubkey: rand_arr(),
            encrypted_payload: rand::random::<[u8; 32]>().to_vec(),
            payload_nonce: rand_arr(),
            password_salt: rand_arr(),
            expires_at: rand::random::<u32>() as u64,
            created_at: rand::random::<u32>() as u64,
            state: EnvelopeState::Pending,
            challenge_hash: None,
            password_attempts_remaining: 0,
            challenge_attempts_remaining: 0,
            challenge_expires_at: 0,
            retention_secs: rand::random::<u32>() as u64,
        }
    }

    fn sample_ext() -> InviteExtV2 {
        InviteExtV2 {
            suite: SUITE_V2,
            kdf: KdfParams {
                m_kib: 65536,
                t_cost: 3,
                p_cost: 1,
            },
            sender_identity: rand_arr(),
            sender_binding: rand_arr(),
            recipient_identity: rand_arr(),
            offer_id: rand_arr(),
            recipient_ephemeral: rand_arr(),
            wrapped_dek: rand_arr::<48>().to_vec(),
            dek_nonce: rand_arr(),
            signature: rand_arr(),
        }
    }

    fn sample_offer() -> SignedOffer {
        SignedOffer {
            suite: SUITE_V2,
            offer_id: rand_arr(),
            request_id: rand_arr(),
            requester: rand_arr::<38>().to_vec(),
            recipient_identity: rand_arr(),
            recipient_sharing: rand_arr(),
            recipient_binding: rand_arr(),
            recipient_ephemeral: rand_arr(),
            ttl_secs: rand::random::<u32>(),
            signature: rand_arr(),
        }
    }

    #[test]
    fn kdf_params_bincode_roundtrip() {
        let p = KdfParams {
            m_kib: rand::random(),
            t_cost: rand::random(),
            p_cost: rand::random(),
        };
        let bytes = bincode::serialize(&p).unwrap();
        let back: KdfParams = bincode::deserialize(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn request_and_response_bincode_roundtrip() {
        let req = DirectedRequestV2::Invite {
            envelope: sample_envelope(),
            ext: sample_ext(),
        };
        let bytes = bincode::serialize(&req).unwrap();
        let back: DirectedRequestV2 = bincode::deserialize(&bytes).unwrap();
        match back {
            DirectedRequestV2::Invite { ext, .. } => assert_eq!(ext.suite, SUITE_V2),
            _ => panic!("wrong variant"),
        }

        let resp = DirectedResponseV2::PrekeyOffer {
            offer: sample_offer(),
        };
        let rbytes = bincode::serialize(&resp).unwrap();
        let rback: DirectedResponseV2 = bincode::deserialize(&rbytes).unwrap();
        match rback {
            DirectedResponseV2::PrekeyOffer { offer } => assert_eq!(offer.suite, SUITE_V2),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn request_variant_indices_match_v1_for_the_shared_variants() {
        // bincode writes an enum tag as a u32 little-endian index. The shared
        // variants must keep the v1 indices 0..=3; PrekeyRequest is 4.
        let tag = |r: &DirectedRequestV2| {
            u32::from_le_bytes(bincode::serialize(r).unwrap()[..4].try_into().unwrap())
        };
        assert_eq!(
            tag(&DirectedRequestV2::Confirm {
                envelope_id: rand_arr(),
                challenge_code: "x".into(),
            }),
            1
        );
        assert_eq!(
            tag(&DirectedRequestV2::SenderRevoke {
                envelope_id: rand_arr()
            }),
            2
        );
        assert_eq!(
            tag(&DirectedRequestV2::StatusQuery {
                envelope_id: rand_arr()
            }),
            3
        );
        assert_eq!(
            tag(&DirectedRequestV2::PrekeyRequest {
                request_id: rand_arr(),
                suites: vec![SUITE_V2],
            }),
            4
        );
    }

    #[test]
    fn a_v2_invite_reads_as_a_v1_invite_with_trailing_ext() {
        // The v2 Invite is bincode: the v1 `Invite{envelope}` bytes followed by
        // `ext`. A v1 decoder reads the envelope and ignores the trailing ext.
        use crate::directed::protocol::DirectedRequest;
        let envelope = sample_envelope();
        let ext = sample_ext();
        let v2 = DirectedRequestV2::Invite {
            envelope: envelope.clone(),
            ext,
        };
        let bytes = bincode::serialize(&v2).unwrap();
        let v1: DirectedRequest = bincode::deserialize(&bytes).unwrap();
        match v1 {
            DirectedRequest::Invite { envelope: e } => {
                assert_eq!(e.version, SUITE_V2);
                assert_eq!(e.envelope_id, envelope.envelope_id);
            }
            _ => panic!("a v2 invite did not read as a v1 Invite"),
        }
    }

    #[test]
    fn error_string_carries_a_recoverable_code() {
        let s = error_string(codes::KEY_MISMATCH, "contact key differs");
        assert_eq!(parse_error_code(&s), Some(codes::KEY_MISMATCH));
        assert!(parse_error_code("plain text").is_none());
    }

    #[test]
    fn bytes64_fields_survive_a_bincode_roundtrip() {
        // The `bytes64` codec is used for the `[u8; 64]` binding and signature
        // fields. A full encode/decode of `InviteExtV2` must return those two
        // 64-byte fields unchanged. `InviteExtV2` has no `PartialEq`, so the
        // two long fields are compared byte-for-byte.
        let ext = sample_ext();
        let sender_binding = ext.sender_binding;
        let signature = ext.signature;
        let bytes = bincode::serialize(&ext).unwrap();
        let back: InviteExtV2 = bincode::deserialize(&bytes).unwrap();
        assert_eq!(&back.sender_binding[..], &sender_binding[..]);
        assert_eq!(&back.signature[..], &signature[..]);
    }

    #[test]
    fn bytes64_encodes_as_sixty_four_bytes_with_no_length_prefix() {
        // The codec writes the 64 bytes as a fixed-length tuple: exactly 64
        // bytes, no length prefix. `SignedOffer.recipient_binding` is a
        // `[u8; 64]` field that sits between two 32-byte fields, so the three
        // together occupy 128 bytes if and only if each `[u8; 64]` is 64 bytes.
        let offer = sample_offer();
        let bytes = bincode::serialize(&offer).unwrap();
        let back: SignedOffer = bincode::deserialize(&bytes).unwrap();
        assert_eq!(&back.recipient_binding[..], &offer.recipient_binding[..]);
        assert_eq!(&back.signature[..], &offer.signature[..]);
    }
}
