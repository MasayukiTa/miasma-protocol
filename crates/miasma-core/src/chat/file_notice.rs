//! Carry file deposit notices in ordinary chat text messages.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use super::proto::FileDepositNotice;
pub use super::proto::NetworkFileNotice;

pub const FILE_NOTICE_PREFIX: &str = "miasma-file-notice:v1:";

/// Format a valid notice for both older and updated clients.
pub fn notice_to_text(n: &FileDepositNotice) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(n.encode().expect("valid file deposit notice"));
    format!(
        "Sent you a file: {} ({} bytes). Update Miasma to receive it.\n{}{}",
        n.file_name, n.size, FILE_NOTICE_PREFIX, encoded
    )
}

/// Extract a notice from a prefixed line, if present and valid.
pub fn text_to_notice(text: &str) -> Option<FileDepositNotice> {
    let encoded = text
        .lines()
        .find_map(|line| line.strip_prefix(FILE_NOTICE_PREFIX))?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    FileDepositNotice::decode(&bytes).ok()
}

pub const NETWORK_FILE_NOTICE_PREFIX: &str = "miasma-file-notice:v2:";

pub fn network_notice_to_text(n: &NetworkFileNotice) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(n.encode().expect("valid network file notice"));
    format!(
        "Sent you a file: {} ({} bytes). Update Miasma to receive it.\n{}{}",
        n.file_name, n.size, NETWORK_FILE_NOTICE_PREFIX, encoded
    )
}

pub fn text_to_network_notice(text: &str) -> Option<NetworkFileNotice> {
    let encoded = text
        .lines()
        .find_map(|line| line.strip_prefix(NETWORK_FILE_NOTICE_PREFIX))?;
    if encoded.len() > 1024 {
        return None;
    }
    NetworkFileNotice::decode(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()
}

pub const HOLDER_INTRO_PREFIX: &str = "miasma-holder-intro:v1:";
pub fn holder_intro_to_text(
    intro: &super::proto::HolderIntro,
) -> Result<String, super::proto::ProtoError> {
    let encoded = URL_SAFE_NO_PAD.encode(intro.encode()?);
    Ok(format!("A contact introduced storage holders. Update Miasma to use them.\n{HOLDER_INTRO_PREFIX}{encoded}"))
}
pub fn text_to_holder_intro(text: &str) -> Option<super::proto::HolderIntro> {
    let encoded = text
        .lines()
        .find_map(|line| line.strip_prefix(HOLDER_INTRO_PREFIX))?;
    if encoded.len() > 512 {
        return None;
    }
    super::proto::HolderIntro::decode(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::proto::MAX_TEXT_BYTES;

    fn notice() -> FileDepositNotice {
        FileDepositNotice {
            file_key: rand::random(),
            salt: rand::random(),
            manifest_id: [3; 16],
            holders: vec![[4; 32]; 8],
            file_name: "example.txt".into(),
            size: 123,
            sha256: [5; 32],
        }
    }

    #[test]
    fn round_trip() {
        let n = notice();
        assert!(text_to_notice(&notice_to_text(&n)) == Some(n));
    }

    #[test]
    fn plain_text_is_not_a_notice() {
        assert!(text_to_notice("Hello!").is_none());
    }

    #[test]
    fn damaged_base64_is_not_a_notice() {
        assert!(text_to_notice(&format!("{FILE_NOTICE_PREFIX}%%% ")).is_none());
    }

    #[test]
    fn long_file_name_fits_chat_limit() {
        let mut n = notice();
        n.file_name = "x".repeat(200);
        assert!(notice_to_text(&n).len() < MAX_TEXT_BYTES);
    }

    fn network_notice() -> NetworkFileNotice {
        NetworkFileNotice {
            share_id: "miasma-share:example".into(),
            password: "p".repeat(32),
            file_name: "example.txt".into(),
            size: 123,
            sha256: rand::random(),
        }
    }
    #[test]
    fn network_round_trip_and_versions() {
        let n = network_notice();
        let v2 = network_notice_to_text(&n);
        assert!(text_to_network_notice(&v2) == Some(n));
        assert!(text_to_notice(&v2).is_none());
        assert!(text_to_network_notice(&notice_to_text(&notice())).is_none());
        assert!(text_to_network_notice("miasma-file-notice:v3:AAAA").is_none());
        assert!(text_to_notice("miasma-file-notice:v3:AAAA").is_none());
    }
    #[test]
    fn network_rejects_bad_fields_and_payload() {
        let mut n = network_notice();
        for len in [0, 15, 129, 256] {
            n.password = "x".repeat(len);
            assert!(n.encode().is_err());
        }
        n.password = "x".repeat(16);
        let mut bytes = n.encode().unwrap();
        bytes.push(0);
        assert!(NetworkFileNotice::decode(&bytes).is_err());
        assert!(text_to_network_notice(&format!("{NETWORK_FILE_NOTICE_PREFIX}%%%")).is_none());
        assert!(text_to_network_notice(&format!(
            "{NETWORK_FILE_NOTICE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        ))
        .is_none());
    }
    #[test]
    fn network_long_name_fits_chat_limit() {
        let mut n = network_notice();
        n.file_name = "x".repeat(255);
        n.password = "x".repeat(128);
        n.share_id = "x".repeat(255);
        assert!(network_notice_to_text(&n).len() <= MAX_TEXT_BYTES);
    }
}
