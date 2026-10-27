//! Fixed media wire header and audio packet framing.

use super::media::{Direction, KEY_EPOCH_MAX, MEDIA_PROTOCOL_VERSION, WIRE_HEADER_LEN};

pub const WIRE_LEN_AUDIO: usize = super::media::FRAME_WIRE_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MediaHeader {
    pub direction: Direction,
    pub key_epoch: u32,
    pub packet_seq: u64,
    pub media_type: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PacketError;

impl core::fmt::Debug for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PacketError")
    }
}

pub fn encode_header(header: &MediaHeader) -> Result<[u8; WIRE_HEADER_LEN], PacketError> {
    if header.key_epoch > KEY_EPOCH_MAX || header.media_type > 2 {
        return Err(PacketError);
    }
    let mut out = [0u8; WIRE_HEADER_LEN];
    out[0] = MEDIA_PROTOCOL_VERSION;
    out[1] = header.direction.byte();
    out[2..5].copy_from_slice(&header.key_epoch.to_be_bytes()[1..]);
    out[5..13].copy_from_slice(&header.packet_seq.to_be_bytes());
    out[13] = header.media_type;
    Ok(out)
}

pub fn parse_header(bytes: &[u8]) -> Result<MediaHeader, PacketError> {
    if bytes.len() != WIRE_HEADER_LEN || bytes[0] != MEDIA_PROTOCOL_VERSION || bytes[13] > 2 {
        return Err(PacketError);
    }
    let direction = match bytes[1] {
        0 => Direction::Caller,
        1 => Direction::Callee,
        _ => return Err(PacketError),
    };
    let key_epoch = u32::from_be_bytes([0, bytes[2], bytes[3], bytes[4]]);
    let packet_seq = u64::from_be_bytes([
        bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
    ]);
    Ok(MediaHeader {
        direction,
        key_epoch,
        packet_seq,
        media_type: bytes[13],
    })
}

pub fn build_packet(header: &MediaHeader, sealed: &[u8]) -> Result<Vec<u8>, PacketError> {
    if sealed.len() != WIRE_LEN_AUDIO - WIRE_HEADER_LEN {
        return Err(PacketError);
    }
    let encoded = encode_header(header)?;
    let mut packet = Vec::with_capacity(WIRE_LEN_AUDIO);
    packet.extend_from_slice(&encoded);
    packet.extend_from_slice(sealed);
    Ok(packet)
}

pub fn split_packet(bytes: &[u8]) -> Result<(MediaHeader, &[u8]), PacketError> {
    if bytes.len() != WIRE_LEN_AUDIO {
        return Err(PacketError);
    }
    let (header, sealed) = bytes.split_at(WIRE_HEADER_LEN);
    Ok((parse_header(header)?, sealed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_header_validation() {
        let header = MediaHeader {
            direction: Direction::Caller,
            key_epoch: 7,
            packet_seq: 9,
            media_type: 0,
        };
        let encoded = encode_header(&header).unwrap();
        assert!(parse_header(&encoded).unwrap() == header);
        assert!(parse_header(&encoded[..13]).is_err());
        assert!(parse_header(&[0u8; 15]).is_err());
        for (index, value) in [(0, 0x81), (1, 0x80), (13, 3)] {
            let mut invalid = encoded;
            invalid[index] = value;
            assert!(parse_header(&invalid).is_err());
        }
        assert!(split_packet(&[0u8; 89]).is_err());
        assert!(split_packet(&[0u8; 91]).is_err());
    }
}
