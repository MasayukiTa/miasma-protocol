//! Finding a received file on disk and handing it to the OS ("Open file", "Show in folder").
//!
//! The daemon reports where it saved a file as `<contact folder>/<file name>` (relative to the
//! inbox), so a path has to be rebuilt from that and checked before anything is launched. The
//! name on disk can differ from the reported one in Unicode form (macOS stores file names
//! decomposed, e.g. a kana with a separate voiced-sound mark), so a name that is not found
//! exactly is looked up in its folder by a loose comparison. Launching waits for the helper
//! program in a background thread and reports a failure; nothing is swallowed.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

/// Where a received file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// The file exists at this path.
    Found(PathBuf),
    /// It does not exist anywhere plausible. `tried` is the path that was expected;
    /// `folder` is the nearest folder that does exist (opened instead).
    Missing {
        tried: PathBuf,
        folder: Option<PathBuf>,
    },
}

/// Fold a character to a form that is equal for its composed and decomposed spellings
/// (accented Latin letters and kana with a voiced-sound mark). Combining marks vanish.
fn fold_char(c: char) -> Option<char> {
    const PAIRS: &[(&str, char)] = &[
        ("ÀÁÂÃÄÅĀĂĄ", 'A'),
        ("àáâãäåāăą", 'a'),
        ("ÇĆĈĊČ", 'C'),
        ("çćĉċč", 'c'),
        ("ÈÉÊËĒĔĖĘĚ", 'E'),
        ("èéêëēĕėęě", 'e'),
        ("ÌÍÎÏĨĪĬĮİ", 'I'),
        ("ìíîïĩīĭįı", 'i'),
        ("ÑŃŅŇ", 'N'),
        ("ñńņň", 'n'),
        ("ÒÓÔÕÖØŌŎŐ", 'O'),
        ("òóôõöøōŏő", 'o'),
        ("ÙÚÛÜŨŪŬŮŰŲ", 'U'),
        ("ùúûüũūŭůűų", 'u'),
        ("ÝŶŸ", 'Y'),
        ("ýÿŷ", 'y'),
        ("ŚŜŞŠ", 'S'),
        ("śŝşš", 's'),
        ("ŹŻŽ", 'Z'),
        ("źżž", 'z'),
    ];
    const VOICED: &str = "がぎぐげござじずぜぞだぢづでどばびぶべぼぱぴぷぺぽ";
    const PLAIN: &str = "かきくけこさしすせそたちつてとはひふへほはひふへほ";
    const VOICED_K: &str = "ガギグゲゴザジズゼゾダヂヅデドバビブベボパピプペポヴ";
    const PLAIN_K: &str = "カキクケコサシスセソタチツテトハヒフヘホハヒフヘホウ";
    if matches!(c, '\u{0300}'..='\u{036F}' | '\u{3099}' | '\u{309A}') {
        return None;
    }
    for (set, to) in PAIRS {
        if set.contains(c) {
            return Some(*to);
        }
    }
    if let Some(i) = VOICED.chars().position(|v| v == c) {
        return PLAIN.chars().nth(i);
    }
    if let Some(i) = VOICED_K.chars().position(|v| v == c) {
        return PLAIN_K.chars().nth(i);
    }
    Some(c)
}

fn fold_name(name: &str) -> String {
    name.chars().filter_map(fold_char).collect()
}

/// In `dir`, the one entry whose name equals `name` apart from Unicode form.
fn loose_match(dir: &Path, name: &str) -> Option<PathBuf> {
    let want = fold_name(name);
    let mut found: Option<PathBuf> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if fold_name(&e.file_name().to_string_lossy()) == want {
            if found.is_some() {
                return None; // ambiguous: do not guess
            }
            found = Some(e.path());
        }
    }
    found
}

/// Where a received file is expected to be (the first place [`resolve_saved`] looks).
pub fn expected_path(
    saved_as: &str,
    contact_dir: Option<&Path>,
    inbox_root: Option<&Path>,
) -> PathBuf {
    candidates(saved_as, contact_dir, inbox_root).remove(0)
}

fn candidates(
    saved_as: &str,
    contact_dir: Option<&Path>,
    inbox_root: Option<&Path>,
) -> Vec<PathBuf> {
    let given = Path::new(saved_as);
    let leaf = saved_as.rsplit(['/', '\\']).next().unwrap_or(saved_as);
    let mut out: Vec<PathBuf> = Vec::new();
    if given.is_absolute() {
        out.push(given.to_path_buf());
    } else {
        // Separators of the daemon's OS may differ from this one's.
        let parts: PathBuf = saved_as
            .split(['/', '\\'])
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(root) = inbox_root {
            out.push(root.join(&parts));
        }
        if let Some(dir) = contact_dir {
            out.push(dir.join(&parts));
            out.push(dir.join(leaf));
        }
    }
    if out.is_empty() {
        out.push(given.to_path_buf());
    }
    out
}

/// Rebuild the path of a received file. `saved_as` is what the daemon reported: a path, or
/// `<contact folder>/<name>` relative to the inbox, or (older) a bare name in the contact's
/// folder. `contact_dir` is that contact's inbox folder, `inbox_root` the whole inbox.
pub fn resolve_saved(
    saved_as: &str,
    contact_dir: Option<&Path>,
    inbox_root: Option<&Path>,
) -> Resolved {
    let candidates = candidates(saved_as, contact_dir, inbox_root);
    if let Some(p) = candidates.iter().find(|p| p.exists()) {
        return Resolved::Found(p.clone());
    }
    for p in &candidates {
        if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
            if let Some(hit) = loose_match(parent, &name.to_string_lossy()) {
                return Resolved::Found(hit);
            }
        }
    }
    let folder = contact_dir
        .into_iter()
        .chain(inbox_root)
        .chain(candidates.iter().filter_map(|p| p.parent()))
        .find(|d| d.is_dir())
        .map(Path::to_path_buf);
    Resolved::Missing {
        tried: candidates[0].clone(),
        folder,
    }
}

/// A path as one command-line argument that cannot be read as an option.
pub fn safe_arg(path: &Path) -> OsString {
    let s = path.as_os_str();
    if !path.is_absolute() && s.to_string_lossy().starts_with('-') {
        let mut o = OsString::from("./");
        o.push(s);
        o
    } else {
        s.to_owned()
    }
}

/// What to do with a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Open a file or folder with the default program.
    Open,
    /// Show a file selected in its folder (the folder itself where selecting is not possible).
    Reveal,
}

/// The program and arguments for `action` on `path` on this OS.
pub fn command_for(action: Action, path: &Path) -> (&'static str, Vec<OsString>) {
    let arg = safe_arg(path);
    #[cfg(windows)]
    {
        match action {
            Action::Open => ("explorer", vec![arg]),
            Action::Reveal => {
                let mut o = OsString::from("/select,");
                o.push(arg);
                ("explorer", vec![o])
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        match action {
            Action::Open => ("open", vec![arg]),
            Action::Reveal => ("open", vec![OsString::from("-R"), arg]),
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        match action {
            Action::Open => ("xdg-open", vec![arg]),
            Action::Reveal => (
                "xdg-open",
                vec![path.parent().map_or(arg, |d| d.as_os_str().to_owned())],
            ),
        }
    }
}

/// Launch `action` in the background and send a short reason down `report` if it fails. The
/// helper is waited for up to a few seconds so a nonzero exit is seen; on Windows the shell
/// returns 1 even on success, so there only a failure to start counts.
pub fn launch(action: Action, path: PathBuf, report: Sender<String>) {
    std::thread::spawn(move || {
        let (cmd, args) = command_for(action, &path);
        run_and_wait(cmd, &args, &report);
    });
}

fn run_and_wait(cmd: &str, args: &[OsString], report: &Sender<String>) {
    {
        let mut child = match std::process::Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let _ = report.send(format!("{cmd}: {e}"));
                return;
            }
        };
        if cfg!(windows) {
            let _ = child.wait();
            return;
        }
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        let mut err = String::new();
                        if let Some(mut s) = child.stderr.take() {
                            use std::io::Read;
                            let mut buf = vec![0u8; 400];
                            let n = s.read(&mut buf).unwrap_or(0);
                            err = String::from_utf8_lossy(&buf[..n]).trim().to_owned();
                        }
                        let code = status
                            .code()
                            .map_or_else(|| "signal".to_owned(), |c| c.to_string());
                        let _ = report.send(if err.is_empty() {
                            format!("{cmd} exited with {code}")
                        } else {
                            format!("{cmd} exited with {code}: {err}")
                        });
                    }
                    return;
                }
                Ok(None) if start.elapsed() > Duration::from_secs(5) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(40)),
                Err(e) => {
                    let _ = report.send(format!("{cmd}: {e}"));
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GA_NFC: &str = "\u{304C}"; // が
    const GA_NFD: &str = "\u{304B}\u{3099}"; // か + dakuten
    const E_NFC: &str = "\u{00E9}";
    const E_NFD: &str = "e\u{0301}";

    fn make(dir: &Path, rel: &str) -> PathBuf {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"x").unwrap();
        p
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn the_daemons_leaf_slash_name_is_found_under_the_inbox_root_not_doubled() {
        let t = tmp();
        let name = "ChatGPT 画像 2026年10月9日 01_46_39.png";
        let want = make(t.path(), &format!("bob/{name}"));
        let contact_dir = t.path().join("bob");
        let r = resolve_saved(&format!("bob/{name}"), Some(&contact_dir), Some(t.path()));
        assert_eq!(r, Resolved::Found(want));
    }

    #[test]
    fn a_bare_name_and_a_backslash_path_resolve_too() {
        let t = tmp();
        let want = make(t.path(), "bob/a b.txt");
        let dir = t.path().join("bob");
        assert_eq!(
            resolve_saved("a b.txt", Some(&dir), Some(t.path())),
            Resolved::Found(want.clone())
        );
        assert_eq!(
            resolve_saved("bob\\a b.txt", Some(&dir), Some(t.path())),
            Resolved::Found(want)
        );
    }

    #[test]
    fn composed_and_decomposed_names_find_each_other_both_ways() {
        for (on_disk, asked) in [
            (format!("{GA_NFD}.png"), format!("{GA_NFC}.png")),
            (format!("{GA_NFC}.png"), format!("{GA_NFD}.png")),
            (format!("caf{E_NFD}.txt"), format!("caf{E_NFC}.txt")),
            (format!("caf{E_NFC}.txt"), format!("caf{E_NFD}.txt")),
        ] {
            let t = tmp();
            let dir = t.path().join("bob");
            let want = make(t.path(), &format!("bob/{on_disk}"));
            // On a filesystem that already treats the two as one name the exact lookup wins;
            // either way the file is found.
            let got = resolve_saved(&format!("bob/{asked}"), Some(&dir), Some(t.path()));
            match got {
                Resolved::Found(p) => assert_eq!(
                    fold_name(&p.file_name().unwrap().to_string_lossy()),
                    fold_name(&want.file_name().unwrap().to_string_lossy())
                ),
                other => panic!("{asked:?} vs {on_disk:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_different_name_is_not_taken_for_the_same_file() {
        let t = tmp();
        make(t.path(), "bob/report.txt");
        make(t.path(), "bob/report2.txt");
        let dir = t.path().join("bob");
        assert!(matches!(
            resolve_saved("bob/other.txt", Some(&dir), Some(t.path())),
            Resolved::Missing { .. }
        ));
        // Two entries that both fold to the asked name are ambiguous: no guess.
        make(t.path(), "amb/e.txt");
        make(t.path(), "amb/\u{00E9}.txt");
        assert_eq!(loose_match(&t.path().join("amb"), "\u{00E8}.txt"), None);
        // A case difference is a different name.
        assert_eq!(loose_match(&dir, "REPORT.TXT"), None);
    }

    #[test]
    fn a_missing_file_says_where_it_looked_and_offers_its_folder() {
        let t = tmp();
        let dir = t.path().join("bob");
        std::fs::create_dir_all(&dir).unwrap();
        let r = resolve_saved("bob/gone.png", Some(&dir), Some(t.path()));
        match r {
            Resolved::Missing { tried, folder } => {
                assert_eq!(tried, t.path().join("bob").join("gone.png"));
                assert_eq!(folder, Some(dir));
            }
            other => panic!("{other:?}"),
        }
        // Nothing exists at all: still a clear answer, no folder.
        let r = resolve_saved("x/y.png", None, None);
        assert!(matches!(r, Resolved::Missing { folder: None, .. }));
    }

    #[test]
    fn names_with_apostrophes_and_a_leading_dash_stay_one_argument() {
        let t = tmp();
        let p = make(t.path(), "bob/it's -a file (1).txt");
        let dir = t.path().join("bob");
        assert_eq!(
            resolve_saved("bob/it's -a file (1).txt", Some(&dir), Some(t.path())),
            Resolved::Found(p.clone())
        );
        assert_eq!(safe_arg(&p), p.as_os_str());
        assert_eq!(safe_arg(Path::new("-rf")), OsString::from("./-rf"));
        assert_eq!(
            safe_arg(Path::new("plain.txt")),
            OsString::from("plain.txt")
        );
        let (_, args) = command_for(Action::Open, &p);
        assert_eq!(args.last().unwrap(), p.as_os_str());
        assert_eq!(args.len(), 1);
        let (_, rv) = command_for(Action::Reveal, &p);
        assert!(!rv.is_empty());
    }

    #[test]
    fn a_failing_helper_is_reported_not_swallowed() {
        let (tx, rx) = std::sync::mpsc::channel();
        // A program that does not exist is a start failure on every OS.
        run_and_wait("miasma-no-such-program-xyz", &[], &tx);
        assert!(rx
            .try_recv()
            .unwrap()
            .contains("miasma-no-such-program-xyz"));
        // A helper that exits nonzero is reported with its code (Unix; Windows ignores it).
        if cfg!(unix) {
            let args = [
                OsString::from("-c"),
                OsString::from("echo boom >&2; exit 3"),
            ];
            run_and_wait("sh", &args, &tx);
            let m = rx.try_recv().unwrap();
            assert!(m.contains("exited with 3") && m.contains("boom"), "{m}");
            let ok = [OsString::from("-c"), OsString::from("exit 0")];
            run_and_wait("sh", &ok, &tx);
            assert!(rx.try_recv().is_err());
        }
    }
}
