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
use std::process::Command;
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

/// A path in the one form the Windows shell reads correctly: no `\\?\` prefix (`\\?\UNC\server`
/// becomes `\\server`) and backslashes only. Explorer silently opens the user's Documents
/// folder for a path it cannot read, so a path that reaches it in another form is not an error
/// anywhere - it just opens the wrong thing.
pub fn windows_form(path: &str) -> String {
    let p = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        path.to_owned()
    };
    p.replace('/', "\\")
}

/// The path made absolute (a relative one would be read against the helper's own folder).
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// What to do with a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Open a file or folder with the default program.
    Open,
    /// Show a file selected in its folder (the folder itself where selecting is not possible).
    Reveal,
}

/// The helper program for this OS.
#[cfg(windows)]
const PROGRAM: &str = "explorer";
#[cfg(target_os = "macos")]
const PROGRAM: &str = "open";
#[cfg(not(any(windows, target_os = "macos")))]
const PROGRAM: &str = "xdg-open";

/// The arguments for `action` on `path` on macOS and Linux (one argument per path, so no
/// quoting is involved).
#[cfg(not(windows))]
fn unix_args(action: Action, path: &Path) -> Vec<OsString> {
    let arg = safe_arg(&absolute(path));
    #[cfg(target_os = "macos")]
    {
        match action {
            Action::Open => vec![arg],
            Action::Reveal => vec![OsString::from("-R"), arg],
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        match action {
            Action::Open => vec![arg],
            Action::Reveal => vec![absolute(path)
                .parent()
                .map_or(arg, |d| d.as_os_str().to_owned())],
        }
    }
}

/// The process to run for `action` on `path`: `program` after `lead` arguments (a test hook).
///
/// On Windows the path is passed as ONE raw, quoted argument: `explorer "C:\a b\c"` and
/// `explorer /select,"C:\a b\c"`. Explorer parses its own command line, and the quoting Rust
/// applies to an ordinary argument (`"/select,C:\a b\c"`, the quote before the switch) makes it
/// give up and open Documents instead.
fn build(program: &std::ffi::OsStr, lead: &[OsString], action: Action, path: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(lead);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let shown = windows_form(&absolute(path).to_string_lossy());
        let mut raw = OsString::new();
        if action == Action::Reveal {
            raw.push("/select,");
        }
        raw.push("\"");
        raw.push(shown);
        raw.push("\"");
        cmd.raw_arg(raw);
    }
    #[cfg(not(windows))]
    {
        cmd.args(unix_args(action, path));
    }
    cmd
}

/// The process that does `action` on `path` on this OS.
pub fn command_for(action: Action, path: &Path) -> Command {
    build(std::ffi::OsStr::new(PROGRAM), &[], action, path)
}

/// Launch `action` in the background and send a short reason down `report` if it fails. The
/// path is checked first (the shell would otherwise open some other folder without a word), and
/// the helper is waited for up to a few seconds so a nonzero exit is seen; on Windows the shell
/// returns 1 even on success, so there only a failure to start counts.
pub fn launch(action: Action, path: PathBuf, report: Sender<String>) {
    std::thread::spawn(move || {
        if !path.exists() {
            let _ = report.send("the file or folder is not there".to_owned());
            return;
        }
        run_and_wait(command_for(action, &path), &report);
    });
}

fn run_and_wait(mut command: Command, report: &Sender<String>) {
    let cmd = command.get_program().to_string_lossy().into_owned();
    let mut child = match command
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
        let args: Vec<OsString> = command_for(Action::Open, &p)
            .get_args()
            .map(|a| a.to_owned())
            .collect();
        #[cfg(not(windows))]
        {
            assert_eq!(args, vec![absolute(&p).into_os_string()]);
            let rv: Vec<OsString> = command_for(Action::Reveal, &p)
                .get_args()
                .map(|a| a.to_owned())
                .collect();
            assert!(!rv.is_empty());
        }
        #[cfg(windows)]
        assert_eq!(args.len(), 1); // the one raw argument
    }

    #[test]
    fn windows_form_strips_verbatim_prefixes_and_uses_backslashes() {
        assert_eq!(windows_form(r"\\?\C:\a b\c.txt"), r"C:\a b\c.txt");
        assert_eq!(windows_form(r"C:/a b/c.txt"), r"C:\a b\c.txt");
        assert_eq!(
            windows_form(r"\\?\UNC\srv\share\f.txt"),
            r"\\srv\share\f.txt"
        );
        assert_eq!(windows_form(r"C:\already\fine.txt"), r"C:\already\fine.txt");
        // A mix as the daemon and the contact folder together can produce.
        assert_eq!(
            windows_form(r"C:\Users\Taro\inbox\bob/写真 1.png"),
            r"C:\Users\Taro\inbox\bob\写真 1.png"
        );
    }

    /// Run by the tests below in a child process: print the exact command line it was given.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn probe_print_cmdline() {
        extern "system" {
            fn GetCommandLineW() -> *const u16;
        }
        let s = unsafe {
            let p = GetCommandLineW();
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        };
        println!("CMDLINE<<{s}>>");
    }

    /// The exact command line a helper process would receive.
    #[cfg(windows)]
    fn windows_cmdline(action: Action, path: &Path) -> String {
        let lead: Vec<OsString> = [
            "--exact",
            "open_path::tests::probe_print_cmdline",
            "--ignored",
            "--nocapture",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let exe = std::env::current_exe().unwrap();
        let out = build(exe.as_os_str(), &lead, action, path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let start = text.find("CMDLINE<<").expect(&text) + "CMDLINE<<".len();
        let end = text[start..].find(">>").expect(&text) + start;
        text[start..end].to_owned()
    }

    #[cfg(windows)]
    #[test]
    fn windows_reveal_is_one_raw_select_argument_with_the_path_quoted_inside() {
        let t = tmp();
        let p = make(t.path(), "bob smith/写真 1 (a).txt");
        let plain = windows_form(&p.to_string_lossy());
        let line = windows_cmdline(Action::Reveal, &p);
        assert!(
            line.ends_with(&format!("/select,\"{plain}\"")),
            "command line was: {line}"
        );
        // The quote must come after the comma, never before the switch.
        assert!(!line.contains("\"/select"), "{line}");
        // The same path given with a verbatim prefix or forward slashes is rewritten.
        let verbatim = PathBuf::from(format!(r"\\?\{plain}"));
        assert!(
            windows_cmdline(Action::Reveal, &verbatim).ends_with(&format!("/select,\"{plain}\""))
        );
        let slashes = PathBuf::from(plain.replace('\\', "/"));
        assert!(
            windows_cmdline(Action::Reveal, &slashes).ends_with(&format!("/select,\"{plain}\""))
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_open_is_the_quoted_plain_path_alone() {
        let t = tmp();
        let p = make(t.path(), "bob smith/it's 日本語 file.txt");
        let plain = windows_form(&p.to_string_lossy());
        let line = windows_cmdline(Action::Open, &p);
        assert!(line.ends_with(&format!(" \"{plain}\"")), "{line}");
        assert!(!line.contains("/select"), "{line}");
        let verbatim = PathBuf::from(format!(r"\\?\{plain}"));
        assert!(windows_cmdline(Action::Open, &verbatim).ends_with(&format!(" \"{plain}\"")));
        // A folder too.
        let dir = p.parent().unwrap().to_path_buf();
        let d = windows_form(&dir.to_string_lossy());
        assert!(windows_cmdline(Action::Open, &dir).ends_with(&format!(" \"{d}\"")));
    }

    #[test]
    fn a_failing_helper_is_reported_not_swallowed() {
        let (tx, rx) = std::sync::mpsc::channel();
        // A program that does not exist is a start failure on every OS.
        run_and_wait(Command::new("miasma-no-such-program-xyz"), &tx);
        assert!(rx
            .try_recv()
            .unwrap()
            .contains("miasma-no-such-program-xyz"));
        // A helper that exits nonzero is reported with its code (Unix; Windows ignores it).
        if cfg!(unix) {
            let mut c = Command::new("sh");
            c.args(["-c", "echo boom >&2; exit 3"]);
            run_and_wait(c, &tx);
            let m = rx.try_recv().unwrap();
            assert!(m.contains("exited with 3") && m.contains("boom"), "{m}");
            let mut ok = Command::new("sh");
            ok.args(["-c", "exit 0"]);
            run_and_wait(ok, &tx);
            assert!(rx.try_recv().is_err());
        }
    }

    #[test]
    fn a_path_that_is_not_there_is_reported_and_nothing_is_launched() {
        let t = tmp();
        let (tx, rx) = std::sync::mpsc::channel();
        launch(Action::Open, t.path().join("gone.png"), tx.clone());
        let m = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(m.contains("not there"), "{m}");
        launch(Action::Reveal, t.path().join("gone.png"), tx);
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
    }

    /// Every place the app opens a file or folder goes through this module; a second,
    /// hand-written `explorer` / `xdg-open` / `open` call is what left the Settings button
    /// opening nothing on macOS.
    #[test]
    fn no_other_file_opens_a_file_manager_by_hand() {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(files.len() > 10);
        let mut bad = Vec::new();
        for f in files {
            if f.file_name().is_some_and(|n| n == "open_path.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            for needle in [
                "Command::new(\"explorer\")",
                "Command::new(\"xdg-open\")",
                "Command::new(\"open\")",
                "Command::new(opener)",
                "\"xdg-open\"",
                "\"explorer\"",
            ] {
                if text.contains(needle) {
                    bad.push(format!("{}: {needle}", f.display()));
                }
            }
        }
        assert!(bad.is_empty(), "{bad:?}");
    }
}
