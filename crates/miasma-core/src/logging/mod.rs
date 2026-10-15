//! Central logging setup shared by the daemon, the desktop app, the bridge and
//! the command line.
//!
//! **Stealth mode** (`privacy.stealth_mode`, on by default): log lines live
//! only in a bounded in-memory ring buffer ([`ring`]). No log file is created
//! and library code prints nothing to stdout or stderr. A panic leaves one
//! fixed line in the buffer instead of a message and backtrace, and crash
//! dumps are switched off where the operating system allows it.
//!
//! **Diagnostic logging** (`privacy.diagnostic_logging`, off by default, or
//! stealth mode off): the same lines are also written to size-rotated files
//! ([`diag`]) with identifying values removed ([`redact`]). Switching it off
//! deletes the files.
//!
//! Everything is set up by [`init`]; no other code builds a `tracing`
//! subscriber or opens a log file.

pub mod diag;
mod hardening;
pub mod legacy;
pub mod redact;
pub mod ring;

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::{NodeConfig, PrivacyConfig};
use ring::{RingBuffer, Slice};

/// Which program is logging. Decides the diagnostic file set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Daemon,
    Desktop,
    Bridge,
    /// A one-shot command: memory buffer only, never files.
    Cli,
}

impl Component {
    fn file_prefix(self) -> Option<char> {
        match self {
            Component::Daemon => Some('d'),
            Component::Desktop => Some('u'),
            Component::Bridge => Some('b'),
            Component::Cli => None,
        }
    }
}

/// The destination of the log lines of one program.
#[derive(Debug)]
pub struct Logger {
    component: Component,
    data_dir: PathBuf,
    ring: Mutex<RingBuffer>,
    diag: Mutex<Option<diag::DiagFiles>>,
    diag_on: AtomicBool,
    stealth: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Logger {
    /// A logger with a ring of `ring_bytes` and no files.
    pub fn new(component: Component, data_dir: &Path, ring_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            component,
            data_dir: data_dir.to_path_buf(),
            ring: Mutex::new(RingBuffer::new(ring_bytes)),
            diag: Mutex::new(None),
            diag_on: AtomicBool::new(false),
            stealth: AtomicBool::new(true),
        })
    }

    /// Store one line. `scrub_memory`: also hide identifying values in the
    /// memory copy (always done for the files).
    pub fn record(&self, line: &str, scrub_memory: bool) {
        let mem: std::borrow::Cow<'_, str> = if scrub_memory {
            redact::scrub(line)
        } else {
            std::borrow::Cow::Borrowed(line)
        };
        lock(&self.ring).push(&mem);
        if self.diag_on.load(Ordering::Relaxed) {
            let disk = redact::scrub(line);
            if let Some(f) = lock(&self.diag).as_mut() {
                let _ = f.write_line(&disk);
            }
        }
    }

    /// A line that is already free of values (panic notice).
    pub fn record_raw(&self, line: &str) {
        // A panic may happen while another thread holds the lock; do not wait.
        if let Ok(mut r) = self.ring.try_lock() {
            r.push(line);
        }
        if self.diag_on.load(Ordering::Relaxed) {
            if let Ok(mut d) = self.diag.try_lock() {
                if let Some(f) = d.as_mut() {
                    let _ = f.write_line(line);
                }
            }
        }
    }

    /// Read the buffer; see [`RingBuffer::read`].
    pub fn read(&self, from: Option<u64>, max_lines: usize, max_bytes: usize) -> Slice {
        lock(&self.ring).read(from, max_lines, max_bytes)
    }

    /// Empty the buffer and zero its memory.
    pub fn clear(&self) {
        lock(&self.ring).clear();
    }

    pub fn ring_capacity(&self) -> usize {
        lock(&self.ring).capacity()
    }

    /// Whether stealth mode is on for this program.
    pub fn stealth(&self) -> bool {
        self.stealth.load(Ordering::Relaxed)
    }

    pub fn diagnostic_enabled(&self) -> bool {
        self.diag_on.load(Ordering::Relaxed)
    }

    /// Start or stop writing diagnostic files. Stopping deletes this
    /// program's files (and the folder when it is then empty).
    pub fn set_diagnostic(&self, on: bool) -> io::Result<()> {
        let Some(prefix) = self.component.file_prefix() else {
            return Ok(());
        };
        let mut g = lock(&self.diag);
        if on {
            if g.is_none() {
                *g = Some(diag::DiagFiles::open(&self.data_dir, prefix)?);
            }
            self.diag_on.store(true, Ordering::Relaxed);
        } else {
            self.diag_on.store(false, Ordering::Relaxed);
            if let Some(f) = g.take() {
                f.close_and_delete();
            }
        }
        Ok(())
    }
}

// ── tracing layer ───────────────────────────────────────────────────────────

struct MemoryLayer {
    logger: Arc<Logger>,
}

/// Reused per thread, so a steady stream of events allocates nothing.
struct Scratch {
    line: String,
    fields: String,
    msg: String,
}

thread_local! {
    static SCRATCH: std::cell::RefCell<Scratch> = const {
        std::cell::RefCell::new(Scratch {
            line: String::new(),
            fields: String::new(),
            msg: String::new(),
        })
    };
}

struct LineVisitor<'a> {
    fields: &'a mut String,
    msg: &'a mut String,
}

impl Visit for LineVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.msg, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={:?}", field.name(), value);
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.msg.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={}", field.name(), value);
        }
    }
}

fn clock(out: &mut String) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let s = d.as_secs() % 86_400;
    let _ = write!(
        out,
        "{:02}:{:02}:{:02}.{:03}",
        s / 3600,
        (s / 60) % 60,
        s % 60,
        d.subsec_millis()
    );
}

impl<S> Layer<S> for MemoryLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let scrub_memory = *meta.level() <= Level::INFO;
        let emit = |s: &mut Scratch| {
            s.line.clear();
            s.fields.clear();
            s.msg.clear();
            clock(&mut s.line);
            let _ = write!(s.line, " {:>5} {}:", meta.level(), meta.target());
            let mut v = LineVisitor {
                fields: &mut s.fields,
                msg: &mut s.msg,
            };
            event.record(&mut v);
            if !s.msg.is_empty() {
                s.line.push(' ');
                s.line.push_str(&s.msg);
            }
            s.line.push_str(&s.fields);
            self.logger.record(&s.line, scrub_memory);
            // A rare long line must not pin its memory for the thread's life.
            for b in [&mut s.line, &mut s.fields, &mut s.msg] {
                if b.capacity() > 4096 {
                    *b = String::new();
                }
            }
        };
        SCRATCH.with(|cell| match cell.try_borrow_mut() {
            Ok(mut s) => emit(&mut s),
            // A log call while formatting a log call: use a throw-away buffer.
            Err(_) => emit(&mut Scratch {
                line: String::new(),
                fields: String::new(),
                msg: String::new(),
            }),
        });
    }
}

// ── init ────────────────────────────────────────────────────────────────────

/// Everything [`init`] needs.
pub struct InitOptions<'a> {
    pub component: Component,
    pub data_dir: &'a Path,
    /// Environment variable that may hold an `EnvFilter` directive string.
    pub filter_env: &'a str,
    /// Used when that variable is not set.
    pub default_filter: &'a str,
    /// Install the panic hook and switch crash dumps off (real programs do,
    /// tests do not).
    pub process_hardening: bool,
}

/// What [`init`] decided.
#[derive(Debug, Clone)]
pub struct Settings {
    pub stealth: bool,
    pub diagnostic_files: bool,
    pub privacy: PrivacyConfig,
}

static GLOBAL: OnceLock<Arc<Logger>> = OnceLock::new();

/// The program-wide logger, once [`init`] has run.
pub fn global() -> Option<&'static Arc<Logger>> {
    GLOBAL.get()
}

/// Read `[privacy]` from the node configuration; defaults if there is no
/// configuration. `MIASMA_STEALTH=0` turns stealth mode off for this run.
pub fn load_privacy(data_dir: &Path) -> PrivacyConfig {
    let mut p = NodeConfig::load(data_dir)
        .map(|c| c.privacy)
        .unwrap_or_default();
    if std::env::var("MIASMA_STEALTH").is_ok_and(|v| v == "0") {
        p.stealth_mode = false;
    }
    p
}

fn env_filter(opts: &InitOptions<'_>) -> EnvFilter {
    EnvFilter::try_from_env(opts.filter_env)
        .unwrap_or_else(|_| opts.default_filter.parse().unwrap_or_default())
}

/// Build the logger and the subscriber for `opts` without installing either.
/// [`init`] uses it; tests install the subscriber for one thread.
pub fn build(
    opts: &InitOptions<'_>,
    privacy: &PrivacyConfig,
) -> (Arc<Logger>, impl Subscriber + Send + Sync + 'static) {
    let logger = Logger::new(opts.component, opts.data_dir, privacy.log_buffer_bytes());
    logger
        .stealth
        .store(privacy.stealth_mode, Ordering::Relaxed);
    if privacy.writes_log_files() {
        // A failure to open the folder must not stop the program.
        let _ = logger.set_diagnostic(true);
    }
    let console = (!privacy.stealth_mode).then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(io::stderr)
            .with_ansi(false)
    });
    let sub = tracing_subscriber::registry()
        .with(env_filter(opts))
        .with(MemoryLayer {
            logger: logger.clone(),
        })
        .with(console);
    (logger, sub)
}

/// Set up logging for this process. Safe to call twice; the second call
/// returns the first call's settings.
pub fn init(opts: InitOptions<'_>) -> Settings {
    let privacy = load_privacy(opts.data_dir);
    let settings = Settings {
        stealth: privacy.stealth_mode,
        diagnostic_files: privacy.writes_log_files(),
        privacy: privacy.clone(),
    };
    if GLOBAL.get().is_some() {
        return settings;
    }
    let (logger, sub) = build(&opts, &privacy);
    if sub.try_init().is_err() {
        // Another subscriber (a test harness) is already installed.
        let _ = GLOBAL.set(logger);
        return settings;
    }
    if opts.process_hardening && privacy.stealth_mode {
        hardening::install_panic_hook(logger.clone());
        hardening::disable_crash_dumps();
    }
    let _ = GLOBAL.set(logger);
    settings
}

/// Install the panic hook for a logger built by [`build`] (tests).
pub fn install_panic_hook(logger: Arc<Logger>) {
    hardening::install_panic_hook(logger);
}

/// Switch diagnostic logging on or off for this program and remember the
/// choice in the node configuration. Switching off also deletes the files of
/// every program that is not running (the others delete their own when they
/// are told).
pub fn set_diagnostic_persistent(data_dir: &Path, on: bool) -> io::Result<()> {
    if let Some(l) = global() {
        l.set_diagnostic(on)?;
    }
    if crate::paths::config_file(data_dir).exists() {
        let mut c = NodeConfig::load(data_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if c.privacy.diagnostic_logging != on {
            c.privacy.diagnostic_logging = on;
            c.save(data_dir)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        }
        c.transport.zeroize_secret_copies();
    }
    Ok(())
}

/// Delete every diagnostic file in `data_dir` (used when no daemon is there to
/// do it).
pub fn delete_diagnostic_files(data_dir: &Path) {
    diag::delete_all(data_dir);
}

#[cfg(test)]
mod tests;
