//! The password policy and generator as a person meets them on the command
//! line: the real binary, no daemon. `network-publish` checks the password
//! before it contacts a daemon, so a refusal needs none.

use std::process::{Command, Output};

use miasma_core::transfer::password_policy::{check, strength_hint, Strength};

fn run(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_miasma"))
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .env_remove("MIASMA_LANG")
        .env_remove("MIASMA_LOG")
        .output()
        .expect("run miasma")
}

/// Write `password` to a file (built at run time, never a literal secret) and
/// run `network-publish` on a small file with it.
fn publish_with(dir: &tempfile::TempDir, lang: &str, password: &str) -> Output {
    let data = dir.path().join("payload.bin");
    std::fs::write(&data, b"x").unwrap();
    let pw_file = dir.path().join("pw.txt");
    std::fs::write(&pw_file, format!("{password}\n")).unwrap();
    run(
        dir.path(),
        &[
            "--lang",
            lang,
            "network-publish",
            data.to_str().unwrap(),
            "--password-file",
            pw_file.to_str().unwrap(),
        ],
    )
}

#[test]
fn password_generate_prints_one_compliant_password_of_the_default_length() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["--lang", "en", "password-generate"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout must be the password alone"
    );
    let pw = stdout.trim_end();
    assert_eq!(pw.chars().count(), 16);
    assert!(check(pw).is_ok(), "{pw:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("Store this password somewhere safe"),
        "{stderr}"
    );
    assert!(!stderr.contains(pw), "the note must not repeat the secret");
}

#[test]
fn password_generate_honours_its_length_bounds() {
    let dir = tempfile::tempdir().unwrap();
    for (len, ok) in [("12", true), ("64", true), ("11", false), ("65", false)] {
        let out = run(dir.path(), &["password-generate", "--length", len]);
        assert_eq!(out.status.success(), ok, "--length {len}: {out:?}");
        if ok {
            let stdout = String::from_utf8(out.stdout).unwrap();
            let pw = stdout.trim_end();
            assert_eq!(pw.chars().count(), len.parse::<usize>().unwrap());
            assert!(check(pw).is_ok() && strength_hint(pw) == Strength::Ok);
        }
    }
    // Two runs differ.
    let a = run(dir.path(), &["password-generate"]).stdout;
    let b = run(dir.path(), &["password-generate"]).stdout;
    assert_ne!(a, b);
}

#[test]
fn a_weak_publish_password_is_refused_in_english() {
    let dir = tempfile::tempdir().unwrap();
    // Four characters, letters only: short, no digit, no symbol.
    let weak = "q".repeat(4);
    let out = publish_with(&dir, "en", &weak);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("not accepted for a new protected transfer"),
        "{stderr}"
    );
    assert!(stderr.contains("shorter than 6 characters"), "{stderr}");
    assert!(stderr.contains("no digit"), "{stderr}");
    assert!(stderr.contains("no symbol"), "{stderr}");
    assert!(stderr.contains("password-generate"), "{stderr}");
    assert!(!stderr.contains(&weak), "{stderr}");
}

#[test]
fn a_weak_publish_password_is_refused_in_japanese() {
    let dir = tempfile::tempdir().unwrap();
    let weak = format!("{}7", "q".repeat(5)); // no symbol
    let out = publish_with(&dir, "ja", &weak);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("新しい保護付き転送には使えません"),
        "{stderr}"
    );
    assert!(stderr.contains("記号"), "{stderr}");
    assert!(!stderr.contains("数字 (0-9) がありません"), "{stderr}");
}

#[test]
fn a_compliant_but_short_password_is_only_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    // 8 characters: digit, letters, symbol. Passes the policy; the publish then
    // fails only because there is no daemon to talk to.
    let short = format!("{}1!", "k".repeat(6));
    assert!(check(&short).is_ok());
    let out = publish_with(&dir, "en", &short);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("warning: short password"), "{stderr}");
    assert!(!stderr.contains("not accepted"), "{stderr}");
}

#[test]
fn a_generated_password_passes_without_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let generated = run(dir.path(), &["password-generate"]);
    let pw = String::from_utf8(generated.stdout).unwrap();
    let out = publish_with(&dir, "en", pw.trim_end());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(!stderr.contains("warning: short password"), "{stderr}");
    assert!(!stderr.contains("not accepted"), "{stderr}");
}
