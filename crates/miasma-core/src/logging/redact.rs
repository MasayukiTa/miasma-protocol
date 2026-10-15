//! Keeping identifying values out of log lines.
//!
//! Two layers:
//!
//! * **At the call site**: log arguments that name a file, folder, contact or
//!   content do not belong in an `info!`/`warn!` line. Use [`path`], [`name`],
//!   [`addr`] for the value, or [`short_id`] where a correlation between two
//!   lines is needed.
//! * **In the sink** ([`scrub`]): every line written to the diagnostic files
//!   (and every line at `info` or above in the memory buffer) is checked once
//!   more. Peer ids, content ids and other long identifiers are cut to a short
//!   prefix; IP addresses, multiaddresses and anything that looks like a file
//!   path are replaced. It is a safety net for sites that were missed, not a
//!   reason to log such values.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// Stands in for a file or folder path.
pub fn path(_p: &Path) -> &'static str {
    "<path>"
}

/// Stands in for a file name, contact label or other user-chosen text.
pub fn name(_s: &str) -> &'static str {
    "<name>"
}

/// Stands in for a network address.
pub fn addr<T: ?Sized>(_a: &T) -> &'static str {
    "<addr>"
}

/// The first 8 characters of an identifier followed by `..`; shorter values
/// are returned as they are.
pub fn short_id(id: &str) -> String {
    let mut it = id.char_indices();
    match it.nth(8) {
        Some((i, _)) => format!("{}..", &id[..i]),
        None => id.to_string(),
    }
}

fn is_delim(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '=' | ',' | '(' | ')' | '"' | '\'' | ';' | '<' | '>' | '{' | '}' | '|'
        )
}

fn is_windows_path(w: &str) -> bool {
    let b = w.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || w.starts_with("\\\\")
}

fn looks_like_path(w: &str) -> bool {
    if is_windows_path(w) || w.contains('\\') {
        return true;
    }
    if w.starts_with("~/") {
        return true;
    }
    // Absolute unix path: `/a/b`. Multiaddrs start with a known protocol.
    w.starts_with('/') && w[1..].contains('/') && !is_multiaddr(w)
}

fn is_multiaddr(w: &str) -> bool {
    [
        "/ip4/",
        "/ip6/",
        "/dns/",
        "/dns4/",
        "/dns6/",
        "/dnsaddr/",
        "/p2p/",
        "/memory/",
    ]
    .iter()
    .any(|p| w.starts_with(p))
}

fn public_ip(ip: IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified())
}

fn is_ip_word(w: &str) -> bool {
    if let Ok(sa) = w.parse::<SocketAddr>() {
        return public_ip(sa.ip());
    }
    if let Ok(ip) = w.parse::<IpAddr>() {
        return public_ip(ip);
    }
    // `[v6]` or `[v6]:port`, `v4:port`
    let t = w.trim_start_matches('[');
    if let Some((host, _port)) = t.rsplit_once(']') {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return public_ip(ip);
        }
    }
    if let Some((host, port)) = w.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                return public_ip(IpAddr::V4(ip));
            }
        }
    }
    false
}

fn is_long_id(w: &str) -> bool {
    w.len() >= 32
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && w.chars().any(|c| c.is_ascii_digit())
}

/// Rewrite one word. `None` leaves it unchanged.
fn scrub_word(w: &str) -> Option<String> {
    // Keep sentence punctuation that trails an identifier.
    let core = w.trim_end_matches(['.', ':', '!', '?']);
    let tail = &w[core.len()..];
    if core.is_empty() {
        return None;
    }
    let rewritten: Option<String> = if is_multiaddr(core) {
        Some("<addr>".into())
    } else if core.contains("://") {
        Some("<url>".into())
    } else if core.contains("://") {
        Some("<url>".into())
    } else if core.contains("://") {
        Some("<url>".into())
    } else if looks_like_path(core) {
        Some("<path>".into())
    } else if is_ip_word(core) {
        Some("<ip>".into())
    } else if let Some(rest) = core.strip_prefix("miasma:") {
        (rest.len() > 8).then(|| format!("miasma:{}..", &rest[..8]))
    } else if is_long_id(core) || (core.starts_with("12D3KooW") && core.len() >= 40) {
        Some(short_id(core))
    } else {
        None
    };
    rewritten.map(|r| format!("{r}{tail}"))
}

/// Check one line; returns it unchanged (no allocation) when nothing in it
/// needs hiding.
pub fn scrub(line: &str) -> Cow<'_, str> {
    let mut out: Option<String> = None;
    let mut copied = 0usize;
    let mut i = 0usize;
    let bytes = line.len();
    while i < bytes {
        // Start of a word.
        let rest = &line[i..];
        let c = rest.chars().next().unwrap();
        if is_delim(c) {
            i += c.len_utf8();
            continue;
        }
        let end = rest.find(is_delim).map(|e| i + e).unwrap_or(bytes);
        let word = &line[i..end];
        if let Some(r) = scrub_word(word) {
            let o = out.get_or_insert_with(|| String::with_capacity(line.len()));
            o.push_str(&line[copied..i]);
            o.push_str(&r);
            copied = end;
        }
        i = end;
    }
    match out {
        Some(mut o) => {
            o.push_str(&line[copied..]);
            Cow::Owned(o)
        }
        None => Cow::Borrowed(line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_cuts_after_eight_chars() {
        assert_eq!(short_id("0123456789abcdef"), "01234567..");
        assert_eq!(short_id("short"), "short");
        assert_eq!(short_id("12345678"), "12345678");
        // Multi-byte characters are not split.
        assert_eq!(short_id("ああああああああああ"), "ああああああああ..");
    }

    #[test]
    fn helpers_hide_the_value() {
        assert_eq!(path(Path::new("C:/x/y.txt")), "<path>");
        assert_eq!(name("Alice laptop"), "<name>");
        assert_eq!(addr("1.2.3.4:5"), "<addr>");
    }

    #[test]
    fn plain_text_is_not_touched_or_copied() {
        let l = "peer connected, 3 shares fetched in 120 ms (quic)";
        assert!(matches!(scrub(l), Cow::Borrowed(_)));
        let l = "WSS share server bound on 127.0.0.1:8080";
        assert!(matches!(scrub(l), Cow::Borrowed(_)));
    }

    #[test]
    fn peer_and_content_ids_are_shortened() {
        let peer = "12D3KooWAbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcdefgh";
        let input = format!("admission.verified peer={peer}");
        let out = scrub(&input);
        assert_eq!(out, "admission.verified peer=12D3KooW..");
        let mid = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert_eq!(scrub(&format!("stored {mid}.")), "stored 9f86d081...");
        assert_eq!(
            scrub("fetched miasma:3yZe7d9Qk8xJ2mNpLr5tVw"),
            "fetched miasma:3yZe7d9Q.."
        );
    }

    #[test]
    fn addresses_are_replaced_but_loopback_is_kept() {
        assert_eq!(scrub("dial 192.168.1.20:4001 failed"), "dial <ip> failed");
        assert_eq!(scrub("from [2001:db8::1]:443"), "from <ip>");
        assert_eq!(scrub("listen 127.0.0.1:9000"), "listen 127.0.0.1:9000");
        assert_eq!(
            scrub("Listening on /ip4/10.0.0.5/udp/4001/quic-v1"),
            "Listening on <addr>"
        );
        assert_eq!(
            scrub("bootstrap /ip4/203.0.113.9/udp/1/quic-v1/p2p/12D3KooWAbCd"),
            "bootstrap <addr>"
        );
    }

    #[test]
    fn paths_are_replaced() {
        assert_eq!(
            scrub(r"open C:\Users\someone\secret.pdf now"),
            "open <path> now"
        );
        assert_eq!(scrub("wrote /home/someone/inbox/a.bin"), "wrote <path>");
        assert_eq!(scrub(r#"path="D:\x\y" ok"#), r#"path="<path>" ok"#);
        assert_eq!(scrub(r"share \\server\share\f"), "share <path>");
        assert_eq!(scrub("ratio 3/4 done"), "ratio 3/4 done");
    }

    #[test]
    fn trailing_punctuation_survives() {
        assert_eq!(scrub(r"saved to C:\a\b."), "saved to <path>.");
    }
}
