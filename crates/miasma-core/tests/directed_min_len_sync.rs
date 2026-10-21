//! The private-share password minimum lives in core. The web and Android
//! clients keep a copy because they have no other channel to it; this test
//! fails if a copy drifts from the core constant.

use miasma_core::transfer::password_policy::DIRECTED_MIN_LEN;

/// The integer after `name =` in `source`.
fn constant_value(source: &str, name: &str) -> usize {
    let at = source
        .find(name)
        .unwrap_or_else(|| panic!("{name} not found"));
    let rest = &source[at + name.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').expect("expected '='").trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().expect("number")
}

#[test]
fn web_copy_matches_core() {
    let js = include_str!("../../../web/js/password_policy.js");
    assert_eq!(
        constant_value(js, "const DIRECTED_MIN_LEN"),
        DIRECTED_MIN_LEN
    );
}

#[test]
fn android_copy_matches_core() {
    let kt = include_str!("../../../android/app/src/main/kotlin/dev/miasma/DirectedApi.kt");
    assert_eq!(
        constant_value(kt, "const val DIRECTED_MIN_PASSWORD_LEN"),
        DIRECTED_MIN_LEN
    );
}
