//! `miasma web` as a person runs it: the real binary against a data directory
//! that looks like a running daemon's (a port file and a token file). No daemon
//! is needed, because the command only reads those two files.

use std::process::{Command, Output};

use miasma_core::daemon::{
    control_auth::{write_token_file, ControlToken},
    ipc::HTTP_PORT_FILE,
};

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

fn fake_daemon_dir(port: u16) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(HTTP_PORT_FILE), port.to_string()).unwrap();
    let token = ControlToken::generate();
    write_token_file(dir.path(), &token).unwrap();
    let t = token.as_str().to_owned();
    (dir, t)
}

#[test]
fn web_prints_only_the_link_on_stdout_and_the_token_stays_in_the_fragment() {
    let (dir, token) = fake_daemon_dir(17999);
    let out = run(dir.path(), &["--lang", "en", "web"]);
    assert!(out.status.success(), "{out:?}");

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim_end(),
        format!("http://127.0.0.1:17999/#token={token}")
    );
    assert_eq!(stdout.lines().count(), 1, "stdout must be the link alone");

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Open the link above"), "{stderr}");
    assert!(
        !stderr.contains(&token),
        "the explanation must not repeat the secret"
    );
}

#[test]
fn web_explains_itself_in_japanese_when_asked() {
    let (dir, _) = fake_daemon_dir(17999);
    let out = run(dir.path(), &["--lang", "ja", "web"]);
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("上のリンク"), "{stderr}");
}

#[test]
fn web_url_makes_a_link_to_your_own_static_server_naming_the_bridge() {
    let (dir, token) = fake_daemon_dir(17999);
    let out = run(dir.path(), &["web", "--web-url", "http://localhost:8080"]);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.trim_end(),
        format!("http://localhost:8080/#token={token}&bridge=http://127.0.0.1:17999")
    );
}

#[test]
fn web_refuses_to_put_the_token_in_a_link_to_another_computer() {
    let (dir, token) = fake_daemon_dir(17999);
    let out = run(dir.path(), &["web", "--web-url", "https://example.com"]);
    assert!(!out.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !all.contains(&token),
        "the token must not be printed: {all}"
    );
}

#[test]
fn web_without_a_running_daemon_says_how_to_start_one() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), &["--lang", "en", "web"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("miasma daemon"), "{stderr}");
}
