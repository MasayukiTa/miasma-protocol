//! A signature made by this tool must be accepted (and a wrong one refused)
//! by the verifier the update client really uses.

use miasma_core::update::verify::{verify_sums_signature, SignatureStatus, VerifyError};
use miasma_release_sign as rs;

fn sums() -> Vec<u8> {
    format!(
        "{}  Miasma-macOS.zip\n{} *miasma-macos.tar.gz\n",
        "0123456789abcdef".repeat(4),
        "fedcba9876543210".repeat(4)
    )
    .into_bytes()
}

#[test]
fn tool_signature_is_accepted_by_the_update_client_verifier() {
    let key = rs::generate_key();
    let pk = *key.verifying_key().as_bytes();
    let sig = rs::sign_sums(&key, &sums()).unwrap();
    for f in [rs::SigFormat::Hex, rs::SigFormat::Base64] {
        let text = rs::encode_signature(&sig, f);
        assert_eq!(
            verify_sums_signature(&sums(), Some(text.as_bytes()), &[pk]),
            Ok(SignatureStatus::Valid { key_index: 0 })
        );
    }
    assert_eq!(
        verify_sums_signature(&sums(), Some(&sig), &[pk]),
        Ok(SignatureStatus::Valid { key_index: 0 })
    );
}

#[test]
fn two_pinned_keys_either_one_signs() {
    let (primary, spare) = (rs::generate_key(), rs::generate_key());
    let pinned = [
        *primary.verifying_key().as_bytes(),
        *spare.verifying_key().as_bytes(),
    ];
    for (key, idx) in [(&primary, 0), (&spare, 1)] {
        let sig = rs::encode_signature(&rs::sign_sums(key, &sums()).unwrap(), rs::SigFormat::Hex);
        assert_eq!(
            verify_sums_signature(&sums(), Some(sig.as_bytes()), &pinned),
            Ok(SignatureStatus::Valid { key_index: idx })
        );
        assert_eq!(rs::verify_sums(&sums(), sig.as_bytes(), &pinned), Ok(idx));
    }
}

#[test]
fn wrong_key_tampered_sums_and_missing_signature_are_refused_by_the_client() {
    let (key, other) = (rs::generate_key(), rs::generate_key());
    let sig = rs::encode_signature(&rs::sign_sums(&key, &sums()).unwrap(), rs::SigFormat::Hex);
    let other_pk = *other.verifying_key().as_bytes();
    assert_eq!(
        verify_sums_signature(&sums(), Some(sig.as_bytes()), &[other_pk]),
        Err(VerifyError::SignatureInvalid)
    );
    let pk = *key.verifying_key().as_bytes();
    let mut tampered = sums();
    tampered[0] = b'9';
    assert_eq!(
        verify_sums_signature(&tampered, Some(sig.as_bytes()), &[pk]),
        Err(VerifyError::SignatureInvalid)
    );
    assert_eq!(
        verify_sums_signature(&sums(), None, &[pk]),
        Err(VerifyError::SignatureMissing)
    );
}

#[test]
fn sums_validation_agrees_with_the_client_parser() {
    let dup = format!("{0}  a.zip\n{1}  a.zip", "a".repeat(64), "b".repeat(64));
    let short = format!("{}  a.zip", "a".repeat(63));
    for text in ["", "# c\n", "x  a.zip", short.as_str(), dup.as_str()] {
        assert!(rs::validate_sums(text.as_bytes()).is_err(), "{text:?}");
        assert!(
            miasma_core::update::verify::parse_sums(text.as_bytes()).is_err(),
            "{text:?}"
        );
    }
    let ok = sums();
    assert_eq!(
        rs::validate_sums(&ok).unwrap(),
        miasma_core::update::verify::parse_sums(&ok).unwrap().len()
    );
    let bom = format!("\u{feff}{}  a.zip\r\n", "a".repeat(64));
    assert!(rs::validate_sums(bom.as_bytes()).is_ok());
    assert!(miasma_core::update::verify::parse_sums(bom.as_bytes()).is_ok());
}

#[test]
fn encrypted_key_signs_after_a_round_trip() {
    let key = rs::generate_key();
    let k = rs::KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };
    let file = rs::encrypt_key(&key, b"a long enough passphrase", k).unwrap();
    let back = rs::decrypt_key(&file, b"a long enough passphrase").unwrap();
    let sig = rs::encode_signature(&rs::sign_sums(&back, &sums()).unwrap(), rs::SigFormat::Hex);
    let pk = *key.verifying_key().as_bytes();
    assert_eq!(
        verify_sums_signature(&sums(), Some(sig.as_bytes()), &[pk]),
        Ok(SignatureStatus::Valid { key_index: 0 })
    );
}
