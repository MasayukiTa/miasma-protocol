fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/miasma.ico");
    emit_build_id();
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
