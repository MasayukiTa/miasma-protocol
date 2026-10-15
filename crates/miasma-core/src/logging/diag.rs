//! Opt-in diagnostic log files: size-rotated, neutral names, no dates.
//!
//! Files live in one folder below the data directory. Each program writes its
//! own set (`<letter>0.dat` is the newest, `<letter>4.dat` the oldest) and a
//! file is replaced by the next one when it reaches [`MAX_FILE_BYTES`], so the
//! most a program ever keeps is [`MAX_FILES`] x [`MAX_FILE_BYTES`].

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::paths;

pub const MAX_FILES: usize = 5;
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// One program's rotating files.
#[derive(Debug)]
pub struct DiagFiles {
    dir: PathBuf,
    prefix: char,
    max_files: usize,
    max_bytes: u64,
    cur: Option<File>,
    written: u64,
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

impl DiagFiles {
    pub fn open(data_dir: &Path, prefix: char) -> io::Result<Self> {
        Self::open_with(data_dir, prefix, MAX_FILES, MAX_FILE_BYTES)
    }

    pub fn open_with(
        data_dir: &Path,
        prefix: char,
        max_files: usize,
        max_bytes: u64,
    ) -> io::Result<Self> {
        let dir = paths::diag_log_dir(data_dir);
        fs::create_dir_all(&dir)?;
        let mut me = Self {
            dir,
            prefix,
            max_files: max_files.max(1),
            max_bytes: max_bytes.max(1024),
            cur: None,
            written: 0,
        };
        let f = open_append(&me.path(0))?;
        me.written = f.metadata().map(|m| m.len()).unwrap_or(0);
        me.cur = Some(f);
        Ok(me)
    }

    fn path(&self, n: usize) -> PathBuf {
        self.dir.join(paths::diag_log_name(self.prefix, n))
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.cur = None; // close before renaming (Windows)
        let last = self.max_files - 1;
        let _ = secure_remove(&self.path(last));
        for i in (0..last).rev() {
            let from = self.path(i);
            if from.exists() {
                fs::rename(&from, self.path(i + 1))?;
            }
        }
        self.cur = Some(open_append(&self.path(0))?);
        self.written = 0;
        Ok(())
    }

    /// Append one line plus a newline.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        let need = line.len() as u64 + 1;
        if self.written > 0 && self.written + need > self.max_bytes {
            self.rotate()?;
        }
        if let Some(f) = self.cur.as_mut() {
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;
            self.written += need;
        }
        Ok(())
    }

    /// Close and delete this program's files; remove the folder when it is
    /// empty afterwards.
    pub fn close_and_delete(mut self) {
        self.cur = None;
        remove_set(&self.dir, Some(self.prefix));
    }
}

/// Overwrite a file with zeros in 64 KiB steps, then remove it.
pub fn secure_remove(path: &Path) -> io::Result<()> {
    let len = match fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    {
        let mut f = OpenOptions::new().write(true).open(path)?;
        let zeros = [0u8; 64 * 1024];
        let mut left = len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    fs::remove_file(path)
}

fn remove_set(dir: &Path, prefix: Option<char>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let mine = match prefix {
                Some(p) => paths::is_diag_log_name(&name) && name.starts_with(p),
                None => paths::is_diag_log_name(&name),
            };
            if mine {
                let _ = secure_remove(&e.path());
            }
        }
    }
    // Only succeeds when empty.
    let _ = fs::remove_dir(dir);
}

/// Delete every diagnostic log file of every program in `data_dir`.
pub fn delete_all(data_dir: &Path) {
    remove_set(&paths::diag_log_dir(data_dir), None);
}

/// Number of diagnostic log files in `data_dir`.
pub fn count_files(data_dir: &Path) -> usize {
    fs::read_dir(paths::diag_log_dir(data_dir))
        .map(|rd| {
            rd.flatten()
                .filter(|e| paths::is_diag_log_name(&e.file_name().to_string_lossy()))
                .count()
        })
        .unwrap_or(0)
}
