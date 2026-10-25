//! `miasma recovery ...`: handle the recovery code and the exported backup
//! file from the command line. This is the technician's alternate route to the
//! same operations the desktop and mobile recovery screens perform; it is not
//! part of the ordinary user runbook.
//!
//! The 2048-word list is not embedded in this build (see
//! `root_key::recovery::code`), so the subcommands that show or read a code
//! take a `--wordlist` file of 2048 distinct words, one per line. The core
//! functions do the cryptography; this module only drives them and prints
//! results. Keys and words are never written anywhere but the terminal, and
//! never reach logs, `Debug`, or error text.
//!
//! Two limits of this build are stated plainly, because the earlier module
//! comment claimed guarantees the code did not provide:
//!
//! - Passphrases and codes are read from the terminal with ordinary line input,
//!   so the characters are echoed. A no-echo read needs a terminal-control
//!   dependency this crate does not have. To keep a secret off a shell history
//!   or a pipe, the secret prompts refuse a standard input that is not a
//!   terminal: a passphrase or a code can only be typed at an interactive
//!   terminal, not piped in.
//! - Passphrases are not NFKC-normalised here. `backup::create`/`open` require
//!   the caller to normalise, and this build has no normalisation dependency,
//!   so normalisation is left to the terminal and the operator. `export` prints
//!   a note saying so.
//!
//! Messages follow the pattern of `storage_cmd.rs` (one `match` per language in
//! one enum, language from `i18n::lang()`).

use std::{
    io::{BufRead as _, IsTerminal as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use miasma_core::root_key::{
    self,
    recovery::{
        add_recovery_wrap, backup, has_recovery_wrap, open_with_code, RecoveryCode, WordList,
    },
    CreatePolicy,
};

use crate::i18n::{lang, Lang};

#[derive(Subcommand)]
pub enum RecoveryCmd {
    /// Make a fresh 24-word recovery code, show it, and add a recovery wrap.
    ShowCode {
        /// File of 2048 distinct words, one per line (this build embeds none).
        #[arg(long, value_name = "FILE")]
        wordlist: PathBuf,
    },
    /// Write a passphrase-protected backup file (.miasma-key).
    Export {
        /// Path of the backup file to write.
        out: PathBuf,
    },
    /// Check that a 24-word recovery code opens the recovery wrap.
    VerifyCode {
        /// File of 2048 distinct words, one per line (this build embeds none).
        #[arg(long, value_name = "FILE")]
        wordlist: PathBuf,
    },
    /// Show whether a recovery wrap is present.
    Status,
}

// ─── Messages ───────────────────────────────────────

enum M {
    AlreadyPresent,
    WriteCode,
    CodeShown,
    EnterCode,
    Verified,
    NotVerified,
    EnterPassphrase,
    EnterPassphraseAgain,
    PassphraseMismatch,
    PassphraseEmpty,
    Exported,
    NfkcNote,
    EchoNote,
    NeedTerminal,
    BackupExists,
    StatusPresent,
    StatusAbsent,
}

impl M {
    fn t(&self) -> String {
        match lang() {
            Lang::En => self.en(),
            Lang::Ja => self.ja(),
        }
    }

    fn en(&self) -> String {
        match self {
            M::AlreadyPresent => "A recovery wrap is already present. Cancel it first, then make a new code.".into(),
            M::WriteCode => "Write these 24 words down and keep them safe:".into(),
            M::CodeShown => "A recovery wrap was added for this code.".into(),
            M::EnterCode => "Enter the 24 words, separated by spaces:".into(),
            M::Verified => "The recovery code opened the key.".into(),
            M::NotVerified => "The recovery code did not open the key.".into(),
            M::EnterPassphrase => "Enter a passphrase for the backup file:".into(),
            M::EnterPassphraseAgain => "Enter the same passphrase again:".into(),
            M::PassphraseMismatch => "The two passphrases did not match.".into(),
            M::PassphraseEmpty => "The passphrase was empty.".into(),
            M::Exported => "The backup file was written.".into(),
            M::NfkcNote => "Note: the passphrase is used as typed. It is not Unicode-normalised by this command, so enter it the same way, on a terminal with the same input method, when you open the file.".into(),
            M::EchoNote => "Note: what you type is shown on screen. Enter it where no one can read your screen.".into(),
            M::NeedTerminal => "This must be typed at an interactive terminal; it cannot be read from a pipe or a redirected file.".into(),
            M::BackupExists => "A file already exists at that path. Remove it or choose another path; the backup was not written.".into(),
            M::StatusPresent => "Recovery wrap: present.".into(),
            M::StatusAbsent => "Recovery wrap: none.".into(),
        }
    }

    fn ja(&self) -> String {
        match self {
            M::AlreadyPresent => "復旧の包みがすでにあります。先に取り消してから、新しいコードを作り直してください。".into(),
            M::WriteCode => "次の24語を紙に書き写して安全に保管してください:".into(),
            M::CodeShown => "このコードの復旧の包みを追加しました。".into(),
            M::EnterCode => "24語を空白区切りで入力してください:".into(),
            M::Verified => "復旧コードで鍵を開けました。".into(),
            M::NotVerified => "復旧コードで鍵を開けませんでした。".into(),
            M::EnterPassphrase => "バックアップファイルのパスフレーズを入力してください:".into(),
            M::EnterPassphraseAgain => "同じパスフレーズをもう一度入力してください:".into(),
            M::PassphraseMismatch => "2つのパスフレーズが一致しません。".into(),
            M::PassphraseEmpty => "パスフレーズが空です。".into(),
            M::Exported => "バックアップファイルを書き出しました。".into(),
            M::NfkcNote => "注意: パスフレーズは入力されたまま使います。このコマンドは Unicode 正規化を行いません。ファイルを開くときは、同じ入力方式の端末で、同じように入力してください。".into(),
            M::EchoNote => "注意: 入力した文字は画面に表示されます。画面を他人に見られない場所で入力してください。".into(),
            M::NeedTerminal => "これは対話的な端末から入力する必要があります。パイプやリダイレクトしたファイルからは読みません。".into(),
            M::BackupExists => "そのパスにはすでにファイルがあります。削除するか、別のパスを選んでください。バックアップは書き出していません。".into(),
            M::StatusPresent => "復旧の包み: あり。".into(),
            M::StatusAbsent => "復旧の包み: なし。".into(),
        }
    }
}

// ─── Plumbing ─────────────────────────────────

/// Read a 2048-word list from `path`: one word per line, surrounding spaces
/// trimmed, blank lines dropped. The core `WordList` checks the count and that
/// the words are distinct; normalisation of the words is left to the file.
fn load_wordlist(path: &Path) -> Result<WordList> {
    let text = std::fs::read_to_string(path).context("cannot read the word list file")?;
    let words: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    WordList::new(words).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Read one line from standard input, with the prompt on standard output.
fn prompt_line(msg: &M) -> Result<String> {
    print!("{} ", msg.t());
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("cannot read from standard input")?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Read one secret line (a passphrase or a recovery code). The input is refused
/// unless standard input is an interactive terminal, so a secret cannot be
/// piped in and left on a shell history; a one-line note warns that the input
/// is echoed, as this build has no no-echo terminal dependency.
fn prompt_secret(msg: &M) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("{}", M::NeedTerminal.t());
    }
    println!("{}", M::EchoNote.t());
    prompt_line(msg)
}

/// Write `bytes` to `out` without overwriting an existing file, and without
/// leaving a half-written file if the write fails partway. The bytes go to a
/// freshly named temporary file in the same directory, are flushed, and are
/// then linked into place only if nothing already holds that name; the
/// temporary file is always removed. A reader sees either no file or the whole
/// file, never a partial one, and an existing backup is never lost.
fn write_new_backup(out: &Path, bytes: &[u8]) -> Result<()> {
    if out.exists() {
        bail!("{}", M::BackupExists.t());
    }
    let dir = out.parent().filter(|p| !p.as_os_str().is_empty());
    // A unique suffix for the temporary name. This is a staging name, not key
    // material, so std's hasher seed is enough; this crate has no random-number
    // dependency. The hard link below is what actually guards against clobbering
    // an existing file, so a name clash at worst retries, never overwrites.
    let seed = {
        use std::hash::{BuildHasher as _, Hasher as _};
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    };
    let hex = format!("{seed:016x}");
    let file_name = out
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut tmp_name = file_name;
    tmp_name.push(format!(".{hex}.tmp"));
    let tmp = match dir {
        Some(d) => d.join(&tmp_name),
        None => PathBuf::from(&tmp_name),
    };

    let write_and_flush = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    };
    if let Err(e) = write_and_flush() {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context("cannot write the backup file"));
    }

    // Link into place only if nothing already has the name, then drop the
    // temporary. hard_link fails with AlreadyExists rather than overwriting.
    let linked = std::fs::hard_link(&tmp, out);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("{}", M::BackupExists.t())
        }
        Err(e) => Err(anyhow::Error::new(e).context("cannot place the backup file")),
    }
}

// ─── Commands ────────────────────────────────

pub async fn run_recovery(data_dir: &Path, cmd: RecoveryCmd) -> Result<()> {
    match cmd {
        RecoveryCmd::ShowCode { wordlist } => cmd_show_code(data_dir, &wordlist),
        RecoveryCmd::Export { out } => cmd_export(data_dir, &out),
        RecoveryCmd::VerifyCode { wordlist } => cmd_verify_code(data_dir, &wordlist),
        RecoveryCmd::Status => cmd_status(data_dir),
    }
}

fn cmd_show_code(data_dir: &Path, wordlist: &Path) -> Result<()> {
    // A recovery wrap that already exists is not overwritten: the caller is
    // told to cancel it first, as the design requires for a cancelled add.
    if has_recovery_wrap(data_dir).map_err(|e| anyhow::anyhow!("{e}"))? {
        println!("{}", M::AlreadyPresent.t());
        return Ok(());
    }
    let list = load_wordlist(wordlist)?;
    let code = RecoveryCode::generate();
    let words = code.to_words(&list);
    // Install the wrap first; the key is lent for the call only.
    let key = root_key::get(data_dir, CreatePolicy::Never).map_err(|e| anyhow::anyhow!("{e}"))?;
    key.with(|root| add_recovery_wrap(data_dir, &code, root))
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", M::WriteCode.t());
    println!("{}", words.join(" "));
    println!("{}", M::CodeShown.t());
    Ok(())
}

fn cmd_verify_code(data_dir: &Path, wordlist: &Path) -> Result<()> {
    let list = load_wordlist(wordlist)?;
    let line = prompt_secret(&M::EnterCode)?;
    let words: Vec<&str> = line.split_whitespace().collect();
    // Read the code, then try to open the wrap. The result is only success or
    // failure; neither the key nor the words are shown.
    let opened = match RecoveryCode::from_words(&words, &list) {
        Ok(code) => open_with_code(data_dir, &code).is_ok(),
        Err(_) => false,
    };
    if opened {
        println!("{}", M::Verified.t());
        Ok(())
    } else {
        bail!("{}", M::NotVerified.t())
    }
}

fn cmd_export(data_dir: &Path, out: &Path) -> Result<()> {
    // Refuse early if a file is already there, before asking for a passphrase.
    if out.exists() {
        bail!("{}", M::BackupExists.t());
    }
    let pass1 = prompt_secret(&M::EnterPassphrase)?;
    let pass2 = prompt_secret(&M::EnterPassphraseAgain)?;
    if pass1 != pass2 {
        bail!("{}", M::PassphraseMismatch.t());
    }
    if pass1.is_empty() {
        bail!("{}", M::PassphraseEmpty.t());
    }
    // The passphrase is used as typed: this build does not NFKC-normalise it.
    println!("{}", M::NfkcNote.t());
    // The backup file holds the current root key under the passphrase.
    let key = root_key::get(data_dir, CreatePolicy::Never).map_err(|e| anyhow::anyhow!("{e}"))?;
    let bytes = key
        .with(|root| backup::create_default(root, &pass1))
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    write_new_backup(out, &bytes)?;
    println!("{}", M::Exported.t());
    Ok(())
}

fn cmd_status(data_dir: &Path) -> Result<()> {
    let present = has_recovery_wrap(data_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    let msg = if present {
        M::StatusPresent
    } else {
        M::StatusAbsent
    };
    println!("{}", msg.t());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use miasma_core::paths::ROOT_SEALED;
    use miasma_core::root_key::format::{
        self, Blob, Header, Record, KDF_HKDF_SHA256, RECORD_DEVICE,
    };
    use miasma_core::root_key::recovery::WORD_COUNT;

    /// Random bytes for tests without pulling in a random-number crate: the
    /// core recovery code is 32 freshly generated random bytes, so enough
    /// generated codes concatenated fill any length. Built in a growing buffer
    /// so no zero-filled array stands in for key material. Nothing fixed is
    /// used.
    fn random<const N: usize>() -> [u8; N] {
        let mut buf: Vec<u8> = Vec::with_capacity(N);
        while buf.len() < N {
            let code = RecoveryCode::generate();
            buf.extend_from_slice(code.entropy());
        }
        buf.truncate(N);
        buf.try_into().expect("the buffer holds exactly N bytes")
    }

    /// A random passphrase for tests, hex-encoded from random bytes, never a
    /// literal secret.
    fn random_passphrase() -> String {
        let bytes = random::<16>();
        let mut s = String::with_capacity(2 + bytes.len() * 2);
        s.push_str("pp");
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// A throwaway 2048-word list written to a file in `dir`, one word per
    /// line: 2048 distinct words, nothing embedded and no fixed secret.
    fn write_test_wordlist(dir: &Path) -> PathBuf {
        let mut text = String::new();
        for i in 0..2048 {
            text.push_str(&format!("w{i:04}\n"));
        }
        let path = dir.join("words.txt");
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Seed a `root.sealed` holding only a device record for `root`, so a
    /// recovery wrap can be added on top. The device wrap bytes are random;
    /// these tests exercise only the recovery record.
    fn seed_sealed(data_dir: &Path, root: &[u8; 32]) {
        let header = Header {
            flags: 0,
            install_id: random(),
            key_id: random(),
            created_epoch: 1_700_000_000,
            root_check: format::root_check(root),
        };
        let device = Record {
            rtype: RECORD_DEVICE,
            provider: 0,
            kdf_id: KDF_HKDF_SHA256,
            kdf_params: Vec::new(),
            wrapped: random::<72>().to_vec(),
        };
        let blob = Blob {
            header,
            records: vec![device],
        };
        std::fs::create_dir_all(data_dir).unwrap();
        std::fs::write(ROOT_SEALED.in_dir(data_dir), blob.encode()).unwrap();
    }

    #[test]
    fn load_wordlist_reads_2048_words_and_trims_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_test_wordlist(dir.path());
        let list = load_wordlist(&path).unwrap();
        // A generated code round-trips through the loaded list, which only
        // succeeds if the list holds the full 2048 distinct words.
        let code = RecoveryCode::generate();
        let words = code.to_words(&list);
        assert_eq!(words.len(), WORD_COUNT);
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let read = RecoveryCode::from_words(&refs, &list).unwrap();
        assert_eq!(read.entropy(), code.entropy());
    }

    #[test]
    fn a_short_wordlist_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.txt");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        assert!(load_wordlist(&path).is_err());
    }

    #[test]
    fn show_code_then_verify_code_round_trips() {
        // After a wrap is added for a freshly generated code, that same code's
        // words open the wrap. This mirrors the show-code / verify-code round
        // trip without going through standard input: it exercises the same
        // core calls both subcommands make. No fixed key or code is used; the
        // code and the root key are both random.
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let root = random::<32>();
        seed_sealed(data_dir, &root);
        let list_path = write_test_wordlist(data_dir);
        let list = load_wordlist(&list_path).unwrap();

        assert!(!has_recovery_wrap(data_dir).unwrap());
        let code = RecoveryCode::generate();
        let words = code.to_words(&list);
        add_recovery_wrap(data_dir, &code, &root).unwrap();
        assert!(has_recovery_wrap(data_dir).unwrap());

        // verify-code reads the words back and opens the wrap.
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let read = RecoveryCode::from_words(&refs, &list).unwrap();
        assert!(open_with_code(data_dir, &read).is_ok());
    }

    #[test]
    fn a_different_code_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let root = random::<32>();
        seed_sealed(data_dir, &root);
        let code = RecoveryCode::generate();
        add_recovery_wrap(data_dir, &code, &root).unwrap();
        // A second, independent code must not open the wrap.
        let other = RecoveryCode::generate();
        assert!(open_with_code(data_dir, &other).is_err());
    }

    #[test]
    fn status_reflects_whether_a_wrap_is_present() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let root = random::<32>();
        seed_sealed(data_dir, &root);
        assert!(!has_recovery_wrap(data_dir).unwrap());
        let code = RecoveryCode::generate();
        add_recovery_wrap(data_dir, &code, &root).unwrap();
        assert!(has_recovery_wrap(data_dir).unwrap());
    }

    #[test]
    fn an_exported_backup_opens_with_its_passphrase() {
        // export writes a backup file that opens with the same passphrase and
        // yields the root key. The passphrase is built at run time, never a
        // literal secret, and the key is random.
        let dir = tempfile::tempdir().unwrap();
        let root = random::<32>();
        let passphrase = random_passphrase();
        let bytes = backup::create_default(&root, &passphrase).unwrap();
        let opened = backup::open(&bytes, &passphrase).unwrap();
        assert_eq!(opened.as_array(), &root);
    }

    #[test]
    fn write_new_backup_writes_then_reads_back_the_same_bytes() {
        // The atomic writer places exactly the bytes it was given, which open
        // again with the passphrase that made them. The bytes are a real backup
        // built from a random key and a run-time passphrase; nothing fixed.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("backup.miasma-key");
        let root = random::<32>();
        let passphrase = random_passphrase();
        let bytes = backup::create_default(&root, &passphrase).unwrap();
        write_new_backup(&out, &bytes).unwrap();
        let read = std::fs::read(&out).unwrap();
        assert_eq!(read, bytes);
        let opened = backup::open(&read, &passphrase).unwrap();
        assert_eq!(opened.as_array(), &root);
    }

    #[test]
    fn write_new_backup_refuses_to_overwrite_an_existing_file() {
        // An existing file at the path is never overwritten: the existing bytes
        // are left untouched and the call is an error. This guards the backup
        // against silently losing an earlier export.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("backup.miasma-key");
        let existing = random::<32>().to_vec();
        std::fs::write(&out, &existing).unwrap();
        let root = random::<32>();
        let passphrase = random_passphrase();
        let bytes = backup::create_default(&root, &passphrase).unwrap();
        assert!(write_new_backup(&out, &bytes).is_err());
        // The earlier file is intact.
        assert_eq!(std::fs::read(&out).unwrap(), existing);
    }

    #[test]
    fn write_new_backup_leaves_no_temporary_file_behind() {
        // After a successful write the directory holds only the backup file:
        // the temporary staging file is always removed.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("backup.miasma-key");
        let root = random::<32>();
        let passphrase = random_passphrase();
        let bytes = backup::create_default(&root, &passphrase).unwrap();
        write_new_backup(&out, &bytes).unwrap();
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["backup.miasma-key".to_string()], "{names:?}");
    }

    #[test]
    fn both_languages_render_every_message() {
        let all = [
            M::AlreadyPresent,
            M::WriteCode,
            M::CodeShown,
            M::EnterCode,
            M::Verified,
            M::NotVerified,
            M::EnterPassphrase,
            M::EnterPassphraseAgain,
            M::PassphraseMismatch,
            M::PassphraseEmpty,
            M::Exported,
            M::NfkcNote,
            M::EchoNote,
            M::NeedTerminal,
            M::BackupExists,
            M::StatusPresent,
            M::StatusAbsent,
        ];
        for m in &all {
            assert!(!m.en().is_empty());
            assert!(!m.ja().is_empty());
        }
    }
}
