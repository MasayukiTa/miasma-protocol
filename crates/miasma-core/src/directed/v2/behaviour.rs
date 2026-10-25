//! The `/miasma/directed/2.0.0` request-response codec and behaviour.
//!
//! This sits beside the v1 `/miasma/directed/1.0.0` codec in
//! [`crate::directed::protocol`] without changing it. The framing is the same:
//! a 4-byte little-endian length prefix followed by a bincode body, with the
//! same [`DIRECTED_MSG_MAX`] read ceiling so an untrusted peer cannot make the
//! reader allocate a large buffer from a declared length.
//!
//! Wiring the behaviour into the swarm's behaviour list and handling its events
//! is the sender-side work that follows (WP-D6b); this module provides the
//! codec, the protocol id, and a constructor so that step only has to add a
//! field and route events.

use super::wire::{DirectedRequestV2, DirectedResponseV2};
use crate::directed::protocol::DIRECTED_MSG_MAX;

/// Protocol id for the v2 directed request-response behaviour.
pub const DIRECTED_PROTOCOL_V2: &str = "/miasma/directed/2.0.0";

// ─── Codec ────────────────────────────────────────────────────────────────────

/// Bincode + 4-byte LE length-prefix codec for `/miasma/directed/2.0.0`.
///
/// Byte-for-byte the same framing as [`crate::directed::protocol::DirectedCodec`],
/// over the v2 request and response types.
#[derive(Clone, Default)]
pub struct DirectedCodecV2;

impl libp2p::request_response::Codec for DirectedCodecV2 {
    type Protocol = libp2p::StreamProtocol;
    type Request = DirectedRequestV2;
    type Response = DirectedResponseV2;

    async fn read_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > DIRECTED_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "directed v2 msg too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(buf.as_mut_slice()).await?;
        bincode::deserialize(buf.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > DIRECTED_MSG_MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "directed v2 response too large",
            ));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(buf.as_mut_slice()).await?;
        bincode::deserialize(buf.as_slice())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(buf.as_slice()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;
        let buf = bincode::serialize(&res)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        io.write_all(&(buf.len() as u32).to_le_bytes()).await?;
        io.write_all(buf.as_slice()).await
    }
}

// ─── Behaviour ─────────────────────────────────────────────────────────────────

/// The v2 directed request-response behaviour type.
///
/// It is a separate behaviour from the v1 one; the two run side by side so the
/// v1 endpoint keeps its exact wire shape and its existing tests.
pub type DirectedBehaviourV2 = libp2p::request_response::Behaviour<DirectedCodecV2>;

/// Build the v2 directed behaviour with the default request-response config,
/// matching how the v1 behaviour is constructed. The caller adds the returned
/// value to the swarm's behaviour list beside the v1 one (WP-D6b).
pub fn new_directed_v2_behaviour() -> DirectedBehaviourV2 {
    libp2p::request_response::Behaviour::new(
        [(
            libp2p::StreamProtocol::new(DIRECTED_PROTOCOL_V2),
            libp2p::request_response::ProtocolSupport::Full,
        )],
        libp2p::request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directed::envelope::{DirectedEnvelope, EnvelopeState};
    use crate::directed::v2::wire::{InviteExtV2, KdfParams, SignedOffer, SUITE_V2};
    use futures::executor::block_on;
    use libp2p::request_response::Codec;

    fn proto() -> libp2p::StreamProtocol {
        libp2p::StreamProtocol::new(DIRECTED_PROTOCOL_V2)
    }

    fn rand_arr<const N: usize>() -> [u8; N] {
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
            encrypted_payload: (0..40).map(|_| rand::random::<u8>()).collect(),
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
            wrapped_dek: (0..48).map(|_| rand::random::<u8>()).collect(),
            dek_nonce: rand_arr(),
            signature: rand_arr(),
        }
    }

    fn sample_offer() -> SignedOffer {
        SignedOffer {
            suite: SUITE_V2,
            offer_id: rand_arr(),
            request_id: rand_arr(),
            requester: (0..38).map(|_| rand::random::<u8>()).collect(),
            recipient_identity: rand_arr(),
            recipient_sharing: rand_arr(),
            recipient_binding: rand_arr(),
            recipient_ephemeral: rand_arr(),
            ttl_secs: rand::random(),
            signature: rand_arr(),
        }
    }

    #[test]
    fn the_v2_codec_round_trips_every_request_variant() {
        let mut c = DirectedCodecV2;
        let p = proto();
        let reqs = vec![
            DirectedRequestV2::Invite {
                envelope: sample_envelope(),
                ext: sample_ext(),
            },
            DirectedRequestV2::Confirm {
                envelope_id: rand_arr(),
                challenge_code: "ABCD-EFGH".to_string(),
            },
            DirectedRequestV2::SenderRevoke {
                envelope_id: rand_arr(),
            },
            DirectedRequestV2::StatusQuery {
                envelope_id: rand_arr(),
            },
            DirectedRequestV2::PrekeyRequest {
                request_id: rand_arr(),
                suites: vec![SUITE_V2],
            },
        ];
        for req in reqs {
            let want = bincode::serialize(&req).unwrap();
            let mut out: Vec<u8> = Vec::new();
            block_on(c.write_request(&p, &mut out, req)).unwrap();
            // Frame is a 4-byte LE length then the bincode body.
            assert_eq!(&out[..4], &(want.len() as u32).to_le_bytes());
            assert_eq!(&out[4..], want.as_slice());
            let mut rd = futures::io::Cursor::new(out);
            let back = block_on(c.read_request(&p, &mut rd)).unwrap();
            assert_eq!(bincode::serialize(&back).unwrap(), want);
        }
    }

    #[test]
    fn the_v2_codec_round_trips_the_new_response_variants() {
        let mut c = DirectedCodecV2;
        let p = proto();
        let resps = vec![
            DirectedResponseV2::PrekeyOffer {
                offer: sample_offer(),
            },
            DirectedResponseV2::InviteStored {
                envelope_id: rand_arr(),
                transcript_hash: rand_arr(),
            },
            DirectedResponseV2::Error("directed-v2:offer_unknown: x".to_string()),
        ];
        for res in resps {
            let want = bincode::serialize(&res).unwrap();
            let mut out: Vec<u8> = Vec::new();
            block_on(c.write_response(&p, &mut out, res)).unwrap();
            assert_eq!(&out[..4], &(want.len() as u32).to_le_bytes());
            let mut rd = futures::io::Cursor::new(out);
            let back = block_on(c.read_response(&p, &mut rd)).unwrap();
            assert_eq!(bincode::serialize(&back).unwrap(), want);
        }
    }

    #[test]
    fn the_v2_codec_refuses_a_declared_length_over_the_limit() {
        let mut c = DirectedCodecV2;
        let p = proto();
        let mut rd =
            futures::io::Cursor::new(((DIRECTED_MSG_MAX + 1) as u32).to_le_bytes().to_vec());
        let err = block_on(c.read_request(&p, &mut rd)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let mut rd =
            futures::io::Cursor::new(((DIRECTED_MSG_MAX + 1) as u32).to_le_bytes().to_vec());
        let err = block_on(c.read_response(&p, &mut rd)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn the_v2_codec_reports_a_short_frame_as_unexpected_eof() {
        let mut c = DirectedCodecV2;
        let p = proto();
        let req = DirectedRequestV2::StatusQuery {
            envelope_id: rand_arr(),
        };
        let mut out: Vec<u8> = Vec::new();
        block_on(c.write_request(&p, &mut out, req)).unwrap();
        out.truncate(out.len() - 1);
        let mut rd = futures::io::Cursor::new(out);
        let err = block_on(c.read_request(&p, &mut rd)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn the_constructor_makes_a_behaviour_for_the_v2_protocol_id() {
        // Construction must not panic and the protocol id constant is the v2 one.
        let _b = new_directed_v2_behaviour();
        assert_eq!(DIRECTED_PROTOCOL_V2, "/miasma/directed/2.0.0");
    }
}
