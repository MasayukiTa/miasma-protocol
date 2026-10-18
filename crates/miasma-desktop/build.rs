fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/miasma.ico");
    emit_build_id();
    emit_version();
    // Embed Windows resources: icon, version info, and file description.
    // This makes miasma-desktop.exe show the Miasma icon in Explorer, taskbar,
    // Start Menu shortcuts, and Alt-Tab.
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/miasma.ico");
        res.set("ProductName", "Miasma Protocol");
        res.set("FileDescription", "Miasma Desktop");
        res.set("LegalCopyright", "Miasma Contributors");
        if let Err(e) = res.compile() {
            // Don't fail the build if resource compilation fails (e.g., missing rc.exe).
            // The app will just not have an embedded icon.
            eprintln!("cargo:warning=Failed to compile Windows resources: {e}");
        }
    }
}

// ─── Build identifier ───────────────────────────────────────────────────────
//
// `MIASMA_BUILD_ID` is the short commit hash the binary was built from, or
// "unknown" when git (or a checkout) is not available. It never fails the build.

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

/// `MIASMA_VERSION`: the crate version, plus the pre-release label from the
/// optional `MIASMA_PRERELEASE` (for example `beta.3` gives `0.3.2-beta.3`). The
/// update check compares this string, so pre-release builds order correctly.
/// Unset, empty or malformed: the crate version alone, exactly as before.
fn emit_version() {
    println!("cargo:rerun-if-env-changed=MIASMA_PRERELEASE");
    let base = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let label = std::env::var("MIASMA_PRERELEASE").unwrap_or_default();
    let label = label.trim().trim_start_matches('-');
    let valid = !label.is_empty()
        && label.split('.').all(|p| {
            !p.is_empty()
                && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !(p.len() > 1 && p.starts_with('0') && p.chars().all(|c| c.is_ascii_digit()))
        });
    let version = if valid && !base.contains('-') {
        format!("{base}-{label}")
    } else {
        base
    };
    println!("cargo:rustc-env=MIASMA_VERSION={version}");
}
