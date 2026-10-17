//! A minimal DNS-over-UDP client for the reachability matrix.
//!
//! The matrix compares the system resolver's answer for a name with what two
//! public resolvers say when asked directly over UDP port 53. Only an `A` query
//! is built and only the `A` records of the answer are read; everything else in
//! the reply is skipped. The parser never trusts a length: every read is bounds
//! checked and a malformed reply is an error, not a panic.

use std::net::{IpAddr, Ipv4Addr};

/// Why a reply could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsWireError {
    /// Shorter than its own header or a record says it is.
    Truncated,
    /// The reply answers a different query (id or question mismatch).
    Mismatch,
    /// The name cannot be encoded (empty label, label over 63 bytes, ...).
    BadName,
}

/// What a well-formed reply says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsReply {
    /// RCODE 0 with these `A` records (possibly none).
    Answer(Vec<Ipv4Addr>),
    /// RCODE 3: the name does not exist.
    NxDomain,
    /// Any other non-zero RCODE (SERVFAIL, REFUSED, ...).
    ServerFailure(u8),
}

/// The query packet for `host` (type `A`, class `IN`, recursion desired).
pub fn build_query(id: u16, host: &str) -> Result<Vec<u8>, DnsWireError> {
    let mut p = Vec::with_capacity(32 + host.len());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // RD
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
    let name = host.trim_end_matches('.');
    if name.is_empty() {
        return Err(DnsWireError::BadName);
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsWireError::BadName);
        }
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    if p.len() > 512 {
        return Err(DnsWireError::BadName);
    }
    Ok(p)
}

/// Skip one (possibly compressed) name starting at `pos`; returns the position
/// after it.
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsWireError> {
    loop {
        let len = *buf.get(pos).ok_or(DnsWireError::Truncated)?;
        match len {
            0 => return Ok(pos + 1),
            l if l & 0xC0 == 0xC0 => {
                // A pointer ends the name; its target is not followed.
                buf.get(pos + 1).ok_or(DnsWireError::Truncated)?;
                return Ok(pos + 2);
            }
            l if l & 0xC0 != 0 => return Err(DnsWireError::Truncated),
            l => pos += 1 + l as usize,
        }
    }
}

fn u16_at(buf: &[u8], pos: usize) -> Result<u16, DnsWireError> {
    let b = buf.get(pos..pos + 2).ok_or(DnsWireError::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

/// Parse a reply to the query built with the same `id`.
pub fn parse_reply(id: u16, buf: &[u8]) -> Result<DnsReply, DnsWireError> {
    if buf.len() < 12 {
        return Err(DnsWireError::Truncated);
    }
    if u16_at(buf, 0)? != id {
        return Err(DnsWireError::Mismatch);
    }
    let flags = u16_at(buf, 2)?;
    if flags & 0x8000 == 0 {
        return Err(DnsWireError::Mismatch); // not a response
    }
    let rcode = (flags & 0x000F) as u8;
    match rcode {
        0 => {}
        3 => return Ok(DnsReply::NxDomain),
        other => return Ok(DnsReply::ServerFailure(other)),
    }
    let qd = u16_at(buf, 4)?;
    let an = u16_at(buf, 6)?;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(buf, pos)?;
        pos += 4;
        if pos > buf.len() {
            return Err(DnsWireError::Truncated);
        }
    }
    let mut out = Vec::new();
    for _ in 0..an {
        pos = skip_name(buf, pos)?;
        let ty = u16_at(buf, pos)?;
        let rdlen = u16_at(buf, pos + 8)? as usize;
        let rd = buf
            .get(pos + 10..pos + 10 + rdlen)
            .ok_or(DnsWireError::Truncated)?;
        if ty == 1 && rdlen == 4 {
            out.push(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]));
        }
        pos += 10 + rdlen;
    }
    Ok(DnsReply::Answer(out))
}

/// The IPv4 members of a list of addresses.
pub fn v4_only(ips: &[IpAddr]) -> Vec<Ipv4Addr> {
    ips.iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v) => Some(*v),
            IpAddr::V6(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply for `example.com` with the given RCODE and A records, the answer
    /// names compressed to point at the question.
    fn reply(id: u16, rcode: u8, ips: &[[u8; 4]]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&id.to_be_bytes());
        r.extend_from_slice(&(0x8180u16 | rcode as u16).to_be_bytes());
        r.extend_from_slice(&[0, 1]);
        r.extend_from_slice(&(ips.len() as u16).to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        r.extend_from_slice(&[7]);
        r.extend_from_slice(b"example");
        r.extend_from_slice(&[3]);
        r.extend_from_slice(b"com");
        r.extend_from_slice(&[0, 0, 1, 0, 1]);
        for ip in ips {
            r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            r.extend_from_slice(ip);
        }
        r
    }

    #[test]
    fn the_query_has_the_expected_wire_form() {
        let q = build_query(0xBEEF, "Example.com.").unwrap();
        assert_eq!(&q[..4], &[0xBE, 0xEF, 0x01, 0x00]);
        assert_eq!(&q[4..6], &[0, 1]);
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"Example");
        assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]);
    }

    #[test]
    fn bad_names_are_refused() {
        assert_eq!(build_query(1, ""), Err(DnsWireError::BadName));
        assert_eq!(build_query(1, "a..b"), Err(DnsWireError::BadName));
        assert_eq!(
            build_query(1, &format!("{}.com", "x".repeat(64))),
            Err(DnsWireError::BadName)
        );
    }

    #[test]
    fn a_normal_answer_is_read() {
        let r = reply(7, 0, &[[93, 184, 216, 34], [1, 2, 3, 4]]);
        assert_eq!(
            parse_reply(7, &r),
            Ok(DnsReply::Answer(vec![
                Ipv4Addr::new(93, 184, 216, 34),
                Ipv4Addr::new(1, 2, 3, 4)
            ]))
        );
    }

    #[test]
    fn nxdomain_and_server_failures_are_told_apart() {
        assert_eq!(parse_reply(7, &reply(7, 3, &[])), Ok(DnsReply::NxDomain));
        assert_eq!(
            parse_reply(7, &reply(7, 2, &[])),
            Ok(DnsReply::ServerFailure(2))
        );
        assert_eq!(
            parse_reply(7, &reply(7, 5, &[])),
            Ok(DnsReply::ServerFailure(5))
        );
    }

    #[test]
    fn a_reply_to_another_query_is_refused() {
        assert_eq!(
            parse_reply(8, &reply(7, 0, &[[1, 1, 1, 1]])),
            Err(DnsWireError::Mismatch)
        );
        // A query (QR bit clear) is not an answer.
        let mut q = reply(7, 0, &[[1, 1, 1, 1]]);
        q[2] &= 0x7F;
        assert_eq!(parse_reply(7, &q), Err(DnsWireError::Mismatch));
    }

    #[test]
    fn every_truncation_is_an_error_and_never_a_panic() {
        let r = reply(7, 0, &[[1, 1, 1, 1], [2, 2, 2, 2]]);
        for n in 0..r.len() {
            // A cut inside the answer section is an error; a cut that happens
            // to land on a record boundary may still parse, but nothing panics.
            let _ = parse_reply(7, &r[..n]);
        }
        assert_eq!(parse_reply(7, &r[..5]), Err(DnsWireError::Truncated));
        assert_eq!(
            parse_reply(7, &r[..r.len() - 1]),
            Err(DnsWireError::Truncated)
        );
    }

    #[test]
    fn a_record_that_claims_more_data_than_there_is_is_refused() {
        let mut r = reply(7, 0, &[[1, 1, 1, 1]]);
        let n = r.len();
        r[n - 6] = 0xFF; // rdlength high byte
        assert_eq!(parse_reply(7, &r), Err(DnsWireError::Truncated));
    }

    #[test]
    fn v4_only_drops_v6() {
        let ips = [
            "1.2.3.4".parse().unwrap(),
            "::1".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
        ];
        assert_eq!(v4_only(&ips).len(), 2);
    }
}
