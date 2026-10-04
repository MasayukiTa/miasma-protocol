//! Handing a share ID over, and getting it back out of whatever was pasted.
//!
//! [`invitation_text`] builds the message a sender pastes into an email or chat:
//! the share ID on its own line, how to receive, and a reminder that the
//! password goes by another channel. It never contains a password. The share ID
//! alone is safe to send (see `share_id.rs`).
//!
//! [`extract_share_id`] is the reverse: it finds a share ID anywhere in
//! arbitrary pasted text (a whole invitation, with brackets, quotes, trailing
//! punctuation, or a line wrap inside the ID) and returns it only when it passes
//! the real parser and checksum. [`share_id_from_link`] does the same for a
//! command-line argument that an OS or browser may have percent-encoded.

use super::share_id::{ShareId, SHARE_ID_PREFIX};

/// Where to download Miasma.
pub const RELEASES_URL: &str = "https://github.com/MasayukiTa/miasma-protocol/releases";

/// Language of an invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteLang {
    En,
    Ja,
}

/// The invitation message for `share_id` (a `miasma-share:...` string).
///
/// The share ID sits on a line of its own so it can be selected or recognised
/// without surrounding text. No password is ever part of the text.
pub fn invitation_text(share_id: &str, lang: InviteLang) -> String {
    let id = share_id.trim();
    match lang {
        InviteLang::En => format!(
            "I'm sharing a file with you through Miasma.\n\
             \n\
             {id}\n\
             \n\
             To receive it: open Miasma > Transfers > New transfer > Receive, paste the Share ID above, and enter the password.\n\
             From the command line: miasma network-get <ShareID> -o <file> --password-file <file>\n\
             The password is not in this message; I will send it to you separately.\n\
             \n\
             Get Miasma: {RELEASES_URL}\n"
        ),
        InviteLang::Ja => format!(
            "Miasma でファイルを共有します。\n\
             \n\
             {id}\n\
             \n\
             受け取り方: Miasma を開き、「転送」>「新しい転送」>「受信」で上の共有 ID を貼り付け、パスワードを入力してください。\n\
             コマンドラインの場合: miasma network-get <ShareID> -o <file> --password-file <file>\n\
             パスワードはこのメッセージには書かれていません。別の方法でお送りします。\n\
             \n\
             Miasma のダウンロード: {RELEASES_URL}\n"
        ),
    }
}

const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// Decoded share IDs are 70 bytes, which is 95 or 96 base58 characters; the
/// window is generous so a future length change fails in the parser, not here.
const MIN_ID_CHARS: usize = 60;
const MAX_ID_CHARS: usize = 130;

/// Find a valid share ID in `text` and return it in its normalised form
/// (`miasma-share:<base58>`).
///
/// Tolerates surrounding punctuation (`<...>`, quotes, a trailing `.` or `,`),
/// whitespace or line breaks inside the ID, and `> ` quote markers at the start
/// of a wrapped line. Returns `None` unless the candidate passes
/// [`ShareId::parse`] (including its checksum). A bare MID (`miasma:...`) is not
/// a share ID.
pub fn extract_share_id(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find(SHARE_ID_PREFIX) {
        let start = from + rel + SHARE_ID_PREFIX.len();
        if let Some(id) = candidate_after(&text[start..]) {
            return Some(id);
        }
        from = start;
    }
    None
}

/// Collect base58 characters after a prefix (skipping whitespace and quote
/// markers), then take the shortest prefix of them that is a valid share ID.
fn candidate_after(rest: &str) -> Option<String> {
    let mut chars = String::new();
    let mut after_newline = false;
    for c in rest.chars() {
        if c == '\n' || c == '\r' {
            after_newline = true;
            continue;
        }
        if c.is_whitespace() || matches!(c, '\u{200b}' | '\u{feff}' | '\u{00ad}') {
            continue;
        }
        if c == '>' && after_newline {
            continue;
        }
        after_newline = false;
        if !B58.contains(c) {
            break;
        }
        chars.push(c);
        if chars.len() >= MAX_ID_CHARS {
            break;
        }
    }
    for n in MIN_ID_CHARS..=chars.len() {
        let candidate = format!("{SHARE_ID_PREFIX}{}", &chars[..n]);
        if ShareId::parse(&candidate).is_ok() {
            return Some(candidate);
        }
    }
    None
}

/// Decode `%XX` escapes (UTF-8). Invalid escapes are kept literally.
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A share ID out of a command-line argument or URL as the OS handed it over:
/// `miasma-share:XXXX`, possibly with a trailing slash or percent-encoding.
pub fn share_id_from_link(arg: &str) -> Option<String> {
    extract_share_id(&percent_decode(arg)).or_else(|| extract_share_id(arg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::ContentId;

    fn sample_id() -> String {
        // A real, checksum-valid ID: publisher = a valid Ed25519 point.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mid = ContentId::from_digest([9u8; 32]);
        ShareId::new(&mid, sk.verifying_key().to_bytes(), true).to_string()
    }

    #[test]
    fn invitation_has_id_once_on_its_own_line_in_both_languages() {
        let id = sample_id();
        for lang in [InviteLang::En, InviteLang::Ja] {
            let t = invitation_text(&id, lang);
            assert_eq!(t.matches(&id).count(), 1, "{lang:?}");
            assert_eq!(t.lines().filter(|l| *l == id).count(), 1, "{lang:?}");
            assert!(t.contains(RELEASES_URL));
            assert!(t.contains("--password-file"));
            assert!(!t.to_lowercase().contains("password:"), "no password value");
        }
        assert!(invitation_text(&id, InviteLang::Ja).contains("別の方法"));
        assert!(invitation_text(&id, InviteLang::En).contains("separately"));
    }

    #[test]
    fn invitation_round_trips_through_extract() {
        let id = sample_id();
        for lang in [InviteLang::En, InviteLang::Ja] {
            assert_eq!(
                extract_share_id(&invitation_text(&id, lang)).as_deref(),
                Some(id.as_str())
            );
        }
    }

    #[test]
    fn bare_id() {
        let id = sample_id();
        assert_eq!(extract_share_id(&id).as_deref(), Some(id.as_str()));
        assert_eq!(
            extract_share_id(&format!("  {id}\n")).as_deref(),
            Some(id.as_str())
        );
    }

    #[test]
    fn id_inside_japanese_email() {
        let id = sample_id();
        let mail = format!(
            "田中さん\n\nお世話になっております。資料を共有します。\n\n{id}\n\nパスワードは別途お送りします。\nよろしくお願いします。\n"
        );
        assert_eq!(extract_share_id(&mail).as_deref(), Some(id.as_str()));
    }

    #[test]
    fn angle_brackets_quotes_and_trailing_punctuation() {
        let id = sample_id();
        for wrapped in [
            format!("<{id}>"),
            format!("\"{id}\""),
            format!("'{id}'"),
            format!("({id})"),
            format!("see {id}."),
            format!("{id},"),
            format!("{id}。"),
            format!("{id}/"),
            format!("{id}\nThanks and regards"),
        ] {
            assert_eq!(
                extract_share_id(&wrapped).as_deref(),
                Some(id.as_str()),
                "{wrapped}"
            );
        }
    }

    #[test]
    fn id_broken_by_newline_or_space() {
        let id = sample_id();
        let (a, b) = id.split_at(40);
        assert_eq!(
            extract_share_id(&format!("{a}\n{b}")).as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            extract_share_id(&format!("{a} {b}")).as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            extract_share_id(&format!("{a}\r\n> {b}")).as_deref(),
            Some(id.as_str())
        );
        assert_eq!(
            extract_share_id(&format!("{a}\n  {b}\n\nThe password follows")).as_deref(),
            Some(id.as_str())
        );
    }

    #[test]
    fn corrupted_checksum_is_none() {
        let id = sample_id();
        let mut chars: Vec<char> = id.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '2' { '3' } else { '2' };
        let bad: String = chars.into_iter().collect();
        assert_eq!(extract_share_id(&bad), None);
        assert_eq!(extract_share_id("miasma-share:"), None);
        assert_eq!(extract_share_id("no id here"), None);
    }

    #[test]
    fn mid_is_not_a_share_id() {
        let mid = ContentId::from_digest([9u8; 32]).to_string();
        assert!(mid.starts_with("miasma:"));
        assert_eq!(extract_share_id(&mid), None);
        assert_eq!(share_id_from_link(&mid), None);
    }

    #[test]
    fn link_arguments_from_the_os() {
        let id = sample_id();
        assert_eq!(
            share_id_from_link(&format!("{id}/")).as_deref(),
            Some(id.as_str())
        );
        let encoded = id.replace(':', "%3A");
        assert_eq!(share_id_from_link(&encoded).as_deref(), Some(id.as_str()));
        assert_eq!(percent_decode("a%2"), "a%2");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
    }
}
