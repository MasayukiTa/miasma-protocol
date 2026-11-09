//! Carry file deposit notices in ordinary chat text messages.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use super::proto::FileDepositNotice;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::proto::MAX_TEXT_BYTES;

    fn notice() -> FileDepositNotice {
        FileDepositNotice {
            file_key: [1; 32],
            salt: [2; 16],
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
}
