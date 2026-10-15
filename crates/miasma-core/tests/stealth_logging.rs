//! Stealth mode leaves nothing on disk and prints nothing: the init paths of
//! the daemon, the desktop app, the bridge and the command line are run in a
//! temporary data directory, 10 000 lines are logged, and the directory must
//! still be empty. A panic is checked in a child process so its stderr can be
//! inspected.

use std::path::Path;

use miasma_core::config::PrivacyConfig;
use miasma_core::logging::{build, Component, InitOptions};

fn opts(dir: &Path, component: Component) -> InitOptions<'_> {
    InitOptions {
        component,
        data_dir: dir,
        filter_env: "MIASMA_TEST_UNSET_FILTER",
        default_filter: "debug",
        process_hardening: false,
    }
}

fn walk(dir: &Path, out: &mut Vec<String>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        out.push(e.path().to_string_lossy().into_owned());
        if e.path().is_dir() {
            walk(&e.path(), out);
        }
    }
}

fn emit_lines(n: usize) {
    for i in 0..n {
        match i % 3 {
            0 => tracing::info!(i, "stealth test line"),
            1 => tracing::debug!(i, "stealth test debug line"),
            _ => tracing::warn!(i, "stealth test warning"),
        }
    }
}

#[test]
fn stealth_writes_zero_log_files_for_every_component() {
    for component in [
        Component::Daemon,
        Component::Desktop,
        Component::Bridge,
        Component::Cli,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let privacy = PrivacyConfig::default();
        assert!(privacy.stealth_mode && !privacy.diagnostic_logging);
        let (logger, sub) = build(&opts(dir.path(), component), &privacy);
        tracing::subscriber::with_default(sub, || emit_lines(10_000));

        let mut found = Vec::new();
        walk(dir.path(), &mut found);
        assert!(
            found.is_empty(),
            "{component:?} left files in stealth mode: {found:?}"
        );
        // The lines went to memory.
        let tail = logger.read(None, 50, 1 << 20);
        assert_eq!(tail.lines.len(), 50);
        assert_eq!(logger.read(None, 0, 0).next_seq, 10_000);
    }
}

#[test]
fn diagnostic_mode_creates_only_the_rotated_folder() {
    let dir = tempfile::tempdir().unwrap();
    let privacy = PrivacyConfig {
        diagnostic_logging: true,
        ..PrivacyConfig::default()
    };
    let (logger, sub) = build(&opts(dir.path(), Component::Daemon), &privacy);
    tracing::subscriber::with_default(sub, || emit_lines(10_000));
    let mut found = Vec::new();
    walk(dir.path(), &mut found);
    assert!(!found.is_empty());
    for f in &found {
        let rel = Path::new(f).strip_prefix(dir.path()).unwrap();
        let comps: Vec<_> = rel.components().collect();
        assert!(
            comps[0].as_os_str() == "lg",
            "unexpected file outside the diagnostic folder: {f}"
        );
        if comps.len() == 2 {
            assert!(
                miasma_core::paths::is_diag_log_name(&comps[1].as_os_str().to_string_lossy()),
                "{f}"
            );
        }
    }
    // No dates in names, nothing called *.log*.
    assert!(!found.iter().any(|f| f.contains(".log")));
    logger.set_diagnostic(false).unwrap();
    let mut after = Vec::new();
    walk(dir.path(), &mut after);
    assert!(after.is_empty(), "{after:?}");
}

const CHILD_ENV: &str = "MIASMA_STEALTH_PANIC_CHILD_DIR";

/// Runs only inside the child process started by the next test.
#[test]
fn panic_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let privacy = PrivacyConfig::default();
    let (logger, sub) = build(&opts(&dir, Component::Daemon), &privacy);
    miasma_core::logging::install_panic_hook(logger.clone());
    tracing::subscriber::set_global_default(sub).unwrap();
    emit_lines(10_000);
    let r = std::panic::catch_unwind(|| {
        panic!("secret-payload C:\\Users\\someone\\private.txt");
    });
    assert!(r.is_err());
    let tail = logger.read(None, 3, 1 << 20).lines;
    assert!(
        tail.iter().any(|l| l.contains("PANIC")),
        "no panic note in memory: {tail:?}"
    );
    assert!(
        !tail.iter().any(|l| l.contains("secret-payload")),
        "payload leaked into the buffer"
    );
    let mut found = Vec::new();
    walk(&dir, &mut found);
    assert!(found.is_empty(), "{found:?}");
    println!("CHILD-OK");
}

#[test]
fn panic_in_stealth_mode_prints_nothing_and_writes_nothing() {
    if std::env::var(CHILD_ENV).is_ok() {
        return; // we are the child
    }
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["panic_child", "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, dir.path())
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("CHILD-OK"), "{stdout}");
    assert!(
        !stderr.contains("panicked"),
        "panic text on stderr: {stderr}"
    );
    assert!(!stderr.contains("secret-payload"), "{stderr}");
    assert!(!stderr.contains("stack backtrace"), "{stderr}");
    assert!(!stdout.contains("secret-payload"), "{stdout}");
    let mut found = Vec::new();
    walk(dir.path(), &mut found);
    assert!(found.is_empty(), "{found:?}");
}
