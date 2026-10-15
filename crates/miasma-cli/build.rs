//! Build script for the `miasma` binary.
//!
//! 1. Reserve a bigger main-thread stack on Windows.
//!
//!    Windows gives a program's main thread 1 MiB unless the executable asks for
//!    more. In a debug build, parsing the command line with `clap` (one large
//!    generated function per command tree) and running the async `main` need just
//!    over that, so every command, even `--version`, died with a stack overflow
//!    once a few more options were added. Release builds are nowhere near it, and
//!    Unix main threads get 8 MiB; the fix is to make the Windows one match, not to
//!    keep trimming options.
//!
//! 2. Embed the short commit hash as `MIASMA_BUILD_ID` so `miasma --version` says
//!    which build it is. It falls back to "unknown" and never fails the build.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/STACK:8388608");
    }
    emit_build_id();
}

fn git_output(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// Re-run the build script when the checked-out commit changes. In a linked
/// worktree `.git` is a file and the refs live in the common directory, so both
/// directories are asked from git instead of being guessed.
fn rerun_when_head_moves() {
    println!("cargo:rerun-if-env-changed=MIASMA_BUILD_ID");
    let abs = |p: String| {
        let path = std::path::PathBuf::from(p);
        if path.is_absolute() {
            path
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        }
    };
    let Some(git_dir) = git_output(&["rev-parse", "--git-dir"]).map(abs) else {
        return;
    };
    let common = git_output(&["rev-parse", "--git-common-dir"])
        .map(abs)
        .unwrap_or_else(|| git_dir.clone());
    let head = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head.display());
    println!(
        "cargo:rerun-if-changed={}",
        common.join("packed-refs").display()
    );
    if let Ok(text) = std::fs::read_to_string(&head) {
        if let Some(r) = text.trim().strip_prefix("ref:") {
            println!("cargo:rerun-if-changed={}", common.join(r.trim()).display());
        }
    }
}

fn emit_build_id() {
    rerun_when_head_moves();
    let id = std::env::var("MIASMA_BUILD_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| git_output(&["rev-parse", "--short=9", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=MIASMA_BUILD_ID={id}");
}
