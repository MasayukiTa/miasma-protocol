//! Pure fixed-size audio packet sender.

use zeroize::Zeroizing;

use super::frame::SendChain;
use super::media::{Direction, MediaError, FRAME_PLAINTEXT_LEN};
use super::packet::{build_packet, MediaHeader};

pub struct MediaSender {
    chain: SendChain,
    call_id: [u8; 16],
    direction: Direction,
    next_seq: Option<u64>,
    oversize_replaced: u64,
}

impl MediaSender {
    pub fn new(
        mk_root: &[u8; 32],
        call_id: [u8; 16],
        direction: Direction,
        now_ms: u64,
    ) -> Result<Self, MediaError> {
        Ok(Self {
            chain: SendChain::start(mk_root, direction, now_ms)?,
            call_id,
            direction,
            next_seq: Some(0),
            oversize_replaced: 0,
        })
    }

    pub fn next_packet(
        &mut self,
        now_ms: u64,
        plain: Option<&[u8]>,
    ) -> Result<Vec<u8>, MediaError> {
        self.next_packet_type(now_ms, plain, 0)
    }

    pub fn next_packet_type(
        &mut self,
        now_ms: u64,
        plain: Option<&[u8]>,
        media_type: u8,
    ) -> Result<Vec<u8>, MediaError> {
        let seq = self.next_seq.ok_or(MediaError::EpochExhausted)?;
        // Consume the sequence even if sealing fails; it must never be reused.
        self.next_seq = seq.checked_add(1);
        let mut frame = Zeroizing::new([0u8; FRAME_PLAINTEXT_LEN]);
        if let Some(input) = plain {
            if input.len() > FRAME_PLAINTEXT_LEN {
                self.oversize_replaced = self.oversize_replaced.saturating_add(1);
            } else {
                frame[..input.len()].copy_from_slice(input);
            }
        }
        let (key_epoch, sealed) =
            self.chain
                .seal_packet(&self.call_id, seq, media_type, &frame[..], now_ms)?;
        let header = MediaHeader {
            direction: self.direction,
            key_epoch,
            packet_seq: seq,
            media_type,
        };
        build_packet(&header, &sealed).map_err(|_| MediaError::Malformed)
    }

    pub fn replaced_count(&self) -> u64 {
        self.oversize_replaced
    }
}

#[cfg(test)]
mod tests {
    use super::super::frame::{open_frame, ReplayWindow};
    use super::super::media::{chain_step, init_chain_key, MEDIA_REKEY_SECONDS};
    use super::super::packet::{split_packet, WIRE_LEN_AUDIO};
    use super::*;

    #[test]
    fn packets_round_trip_and_rekey() {
        let root = Zeroizing::new(std::array::from_fn(|_| rand::random::<u8>()));
        let call_id = std::array::from_fn(|_| rand::random::<u8>());
        let initial = init_chain_key(&root).unwrap();
        let (key0, next) = chain_step(&initial).unwrap();
        let (key1, _) = chain_step(&next).unwrap();
        let mut sender = MediaSender::new(&root, call_id, Direction::Caller, 0).unwrap();
        let exact = [7u8; FRAME_PLAINTEXT_LEN];
        let oversized = [8u8; FRAME_PLAINTEXT_LEN + 1];
        let inputs: [Option<&[u8]>; 5] = [
            Some(&[1, 2]),
            Some(&exact),
            Some(&[]),
            None,
            Some(&oversized),
        ];
        let mut window = ReplayWindow::new();
        for (i, input) in inputs.iter().enumerate() {
            let packet = sender.next_packet(0, *input).unwrap();
            assert_eq!(packet.len(), WIRE_LEN_AUDIO);
            let (h, body) = split_packet(&packet).unwrap();
            assert_eq!(h.packet_seq, i as u64);
            assert_eq!(h.key_epoch, 0);
            let opened = window
                .open_frame_and_accept(
                    &key0,
                    &call_id,
                    h.direction,
                    h.key_epoch,
                    h.packet_seq,
                    h.media_type,
                    body,
                )
                .unwrap();
            let mut expected = [0u8; FRAME_PLAINTEXT_LEN];
            if let Some(bytes) = input {
                if bytes.len() <= FRAME_PLAINTEXT_LEN {
                    expected[..bytes.len()].copy_from_slice(bytes);
                }
            }
            assert!(opened.as_slice() == expected);
            for j in 0..14 {
                let mut altered = packet.clone();
                altered[j] ^= 1;
                if let Ok((changed, sealed)) = split_packet(&altered) {
                    assert!(open_frame(
                        &key0,
                        &call_id,
                        changed.direction,
                        changed.key_epoch,
                        changed.packet_seq,
                        changed.media_type,
                        sealed
                    )
                    .is_err());
                }
            }
        }
        assert_eq!(sender.replaced_count(), 1);
        let packet = sender
            .next_packet(MEDIA_REKEY_SECONDS * 1000, None)
            .unwrap();
        let (h, body) = split_packet(&packet).unwrap();
        assert_eq!(h.key_epoch, 1);
        assert_eq!(h.packet_seq, 5);
        let opened = ReplayWindow::new()
            .open_frame_and_accept(
                &key1,
                &call_id,
                h.direction,
                h.key_epoch,
                h.packet_seq,
                h.media_type,
                body,
            )
            .unwrap();
        assert!(opened.as_slice() == [0u8; FRAME_PLAINTEXT_LEN]);
    }

    #[test]
    fn saturated_clock_does_not_panic() {
        let root = Zeroizing::new(std::array::from_fn(|_| rand::random::<u8>()));
        let call_id = std::array::from_fn(|_| rand::random::<u8>());
        let mut sender = MediaSender::new(&root, call_id, Direction::Caller, 0).unwrap();
        for _ in 0..200_000 {
            assert!(sender.next_packet(u64::MAX - 1, None).is_ok());
        }
    }
}
