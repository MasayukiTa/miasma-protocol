//! Unit tests for the logging module: ring buffer, sink, diagnostic files,
//! old-log handling.

use super::ring::{RingBuffer, MAX_LINE};
use super::*;

fn small() -> RingBuffer {
    // Room for a few dozen short lines.
    RingBuffer::with_exact_capacity(2048)
}

#[test]
fn keeps_lines_in_order() {
    let mut r = small();
    for i in 0..10 {
        r.push(&format!("line {i}"));
    }
    let s = r.read(None, 100, 1 << 20);
    assert_eq!(s.lines.len(), 10);
    assert_eq!(s.lines[0], "line 0");
    assert_eq!(s.lines[9], "line 9");
    assert_eq!(s.next_seq, 10);
}

#[test]
fn oldest_lines_drop_when_full_and_capacity_holds() {
    let mut r = small();
    for i in 0..5000 {
        r.push(&format!("entry number {i:05}"));
        assert!(r.used_bytes() <= r.capacity());
    }
    let s = r.read(None, 10_000, 1 << 20);
    assert!(s.lines.len() < 5000 && s.lines.len() > 50);
    // The newest line is there, the oldest is gone, order is kept.
    assert_eq!(s.lines.last().unwrap(), "entry number 04999");
    assert!(!s.lines.iter().any(|l| l == "entry number 00000"));
    let nums: Vec<u32> = s
        .lines
        .iter()
        .map(|l| l.rsplit(' ').next().unwrap().parse().unwrap())
        .collect();
    assert!(nums.windows(2).all(|w| w[1] == w[0] + 1));
}

#[test]
fn long_lines_are_cut_at_512_bytes_on_a_char_boundary() {
    let mut r = small();
    r.push(&"x".repeat(2000));
    // 3-byte characters: 511 is not a boundary, so the cut is at 510.
    r.push(&"あ".repeat(400));
    let s = r.read(None, 10, 1 << 20);
    assert_eq!(s.lines[0].len(), MAX_LINE);
    assert_eq!(s.lines[1].len(), 510);
    assert!(s.lines[1].chars().all(|c| c == 'あ'));
}

#[test]
fn newline_is_not_stored_and_empty_lines_work() {
    let mut r = small();
    r.push("a\r\n");
    r.push("");
    r.push("b\n");
    let s = r.read(None, 10, 1 << 20);
    assert_eq!(s.lines, vec!["a", "", "b"]);
}

#[test]
fn wraparound_records_read_back_intact() {
    let mut r = RingBuffer::with_exact_capacity(1000);
    // Lines whose records straddle the end of the buffer many times over.
    for i in 0..400 {
        r.push(&format!("{i}:{}", "z".repeat(i % 97)));
    }
    let s = r.read(None, 1000, 1 << 20);
    for l in &s.lines {
        let (n, z) = l.split_once(':').unwrap();
        let n: usize = n.parse().unwrap();
        assert_eq!(z.len(), n % 97, "corrupt record {l}");
    }
    assert_eq!(s.lines.last().unwrap().split(':').next().unwrap(), "399");
}

#[test]
fn read_from_sequence_number_and_limits() {
    let mut r = small();
    for i in 0..20 {
        r.push(&format!("l{i}"));
    }
    let s = r.read(Some(15), 100, 1 << 20);
    assert_eq!(s.lines, vec!["l15", "l16", "l17", "l18", "l19"]);
    assert_eq!(s.next_seq, 20);
    // Following from the end yields nothing and keeps the position.
    let s2 = r.read(Some(s.next_seq), 100, 1 << 20);
    assert!(s2.lines.is_empty());
    assert_eq!(s2.next_seq, 20);
    // max_lines from a sequence number takes the oldest wanted ones.
    let s3 = r.read(Some(2), 3, 1 << 20);
    assert_eq!(s3.lines, vec!["l2", "l3", "l4"]);
    assert_eq!(s3.next_seq, 5);
    // Newest-N without a start number.
    assert_eq!(r.read(None, 2, 1 << 20).lines, vec!["l18", "l19"]);
    // A number older than anything held starts at the oldest line.
    let mut big = RingBuffer::with_exact_capacity(520);
    for i in 0..100 {
        big.push(&format!("m{i:03}"));
    }
    let first = big.read(Some(0), 1000, 1 << 20);
    assert!(first.lines.len() < 100);
    assert_eq!(first.lines.last().unwrap(), "m099");
}

#[test]
fn byte_limit_bounds_a_reply() {
    let mut r = small();
    for _ in 0..20 {
        r.push(&"y".repeat(100));
    }
    let s = r.read(None, 100, 450);
    assert_eq!(s.lines.len(), 4);
    let s = r.read(Some(0), 100, 450);
    assert_eq!(s.lines.len(), 4);
    assert_eq!(s.next_seq, 4);
}

#[test]
fn clear_zeroes_memory_and_keeps_numbering() {
    let mut r = small();
    r.push("secret-looking line");
    r.clear();
    assert!(r.is_empty());
    assert_eq!(r.used_bytes(), 0);
    assert!(r.read(None, 10, 1000).lines.is_empty());
    let seq = r.push("after");
    assert_eq!(seq, 1);
}

#[test]
fn capacity_is_clamped_to_one_to_eight_mib() {
    assert_eq!(RingBuffer::new(1).capacity(), 1024 * 1024);
    assert_eq!(RingBuffer::new(usize::MAX).capacity(), 8 * 1024 * 1024);
    assert_eq!(
        RingBuffer::new(ring::DEFAULT_CAPACITY).capacity(),
        2 * 1024 * 1024
    );
}

#[test]
fn bounded_after_two_million_appends() {
    let mut r = RingBuffer::new(1024 * 1024);
    for i in 0..2_000_000u32 {
        r.push(if i % 2 == 0 {
            "short"
        } else {
            "a somewhat longer log line for the test"
        });
    }
    assert!(r.used_bytes() <= r.capacity());
    assert_eq!(r.next_seq(), 2_000_000);
    assert!(r.len() > 10_000);
}

#[test]
fn concurrent_writers_do_not_corrupt_lines() {
    let dir = tempfile::tempdir().unwrap();
    let logger = Logger::new(Component::Cli, dir.path(), 1024 * 1024);
    let mut hs = Vec::new();
    for t in 0..8 {
        let l = logger.clone();
        hs.push(std::thread::spawn(move || {
            for i in 0..5000 {
                l.record(&format!("T{t} N{i} {}", "p".repeat(i % 40)), false);
            }
        }));
    }
    // A reader runs alongside.
    let l = logger.clone();
    let reader = std::thread::spawn(move || {
        for _ in 0..200 {
            let s = l.read(None, 500, 64 * 1024);
            for line in &s.lines {
                assert!(line.starts_with('T'), "torn line: {line}");
            }
        }
    });
    for h in hs {
        h.join().unwrap();
    }
    reader.join().unwrap();
    let all = logger.read(None, 100_000, 8 * 1024 * 1024);
    assert_eq!(logger.read(None, 0, 0).next_seq, 40_000);
    for line in &all.lines {
        let mut it = line.split(' ');
        let t = it.next().unwrap();
        let n: usize = it.next().unwrap()[1..].parse().unwrap();
        assert!(t.starts_with('T'));
        assert_eq!(it.next().map_or(0, str::len), n % 40);
    }
}

// ── tracing layer ───────────────────────────────────────────────────────────

fn opts(dir: &Path, component: Component) -> InitOptions<'_> {
    InitOptions {
        component,
        data_dir: dir,
        filter_env: "MIASMA_TEST_UNSET_FILTER",
        default_filter: "debug",
        process_hardening: false,
    }
}

#[test]
fn layer_formats_events_into_the_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let privacy = PrivacyConfig::default();
    let (logger, sub) = build(&opts(dir.path(), Component::Daemon), &privacy);
    tracing::subscriber::with_default(sub, || {
        tracing::info!(count = 3, "hello {}", "world");
        tracing::debug!("a debug line");
    });
    let lines = logger.read(None, 10, 1 << 20).lines;
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(lines[0].contains("hello world"));
    assert!(lines[0].contains("count=3"));
    assert!(lines[1].contains("DEBUG"));
    // Nothing on disk.
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn info_lines_are_scrubbed_in_memory_debug_lines_are_not() {
    let dir = tempfile::tempdir().unwrap();
    let (logger, sub) = build(&opts(dir.path(), Component::Cli), &PrivacyConfig::default());
    tracing::subscriber::with_default(sub, || {
        tracing::info!("peer at 192.168.4.5:4001");
        tracing::debug!("peer at 192.168.4.5:4001");
    });
    let lines = logger.read(None, 10, 1 << 20).lines;
    assert!(lines[0].contains("<ip>") && !lines[0].contains("192.168"));
    assert!(lines[1].contains("192.168.4.5:4001"));
}

#[test]
fn diagnostic_files_are_rotated_scrubbed_and_removed_on_switch_off() {
    let dir = tempfile::tempdir().unwrap();
    let logger = Logger::new(Component::Daemon, dir.path(), 1024 * 1024);
    logger.set_diagnostic(true).unwrap();
    assert!(logger.diagnostic_enabled());
    logger.record(
        "opened C:\\Users\\someone\\secret.pdf from 10.1.2.3:80",
        true,
    );
    // ~13 MiB of lines: more than 5 files x 2 MiB can hold.
    let line = format!("filler {}", "f".repeat(190));
    for _ in 0..70_000 {
        logger.record(&line, true);
    }
    let lg = crate::paths::diag_log_dir(dir.path());
    let mut names: Vec<String> = std::fs::read_dir(&lg)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["d0.dat", "d1.dat", "d2.dat", "d3.dat", "d4.dat"]
    );
    for n in &names {
        assert!(crate::paths::is_diag_log_name(n));
        let len = std::fs::metadata(lg.join(n)).unwrap().len();
        assert!(len <= diag::MAX_FILE_BYTES, "{n} is {len} bytes");
    }
    // Nothing else was created next to them.
    let top: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(top.len(), 1);
    // The first (identifying) line has rotated out; write another and check
    // the scrubbing on what is on disk.
    logger.record(
        "again C:\\Users\\someone\\secret.pdf from 10.1.2.3:80",
        true,
    );
    let newest = std::fs::read_to_string(lg.join("d0.dat")).unwrap();
    assert!(
        newest.contains("again <path> from <ip>"),
        "{}",
        &newest[newest.len() - 80..]
    );
    assert!(!newest.contains("someone"));

    logger.set_diagnostic(false).unwrap();
    assert!(!lg.exists(), "folder and files are gone");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    // The memory buffer is unaffected.
    assert!(!logger.read(None, 5, 1 << 20).lines.is_empty());
}

#[test]
fn one_shot_cli_never_writes_files_even_in_diagnostic_mode() {
    let dir = tempfile::tempdir().unwrap();
    let p = PrivacyConfig {
        diagnostic_logging: true,
        ..PrivacyConfig::default()
    };
    let (logger, sub) = build(&opts(dir.path(), Component::Cli), &p);
    tracing::subscriber::with_default(sub, || tracing::info!("x"));
    assert!(!logger.diagnostic_enabled());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn writes_log_files_follows_both_switches() {
    let mut p = PrivacyConfig::default();
    assert!(p.stealth_mode && !p.writes_log_files());
    p.diagnostic_logging = true;
    assert!(p.writes_log_files());
    p.diagnostic_logging = false;
    p.stealth_mode = false;
    assert!(p.writes_log_files());
}

#[test]
fn old_config_without_privacy_section_reads_as_stealth() {
    let c: NodeConfig = toml::from_str("[storage]\nquota_mb = 10\nbandwidth_mb_day = 5\n").unwrap();
    assert!(c.privacy.stealth_mode);
    assert!(!c.privacy.diagnostic_logging);
    assert_eq!(c.privacy.log_buffer_mib, 2);
    assert_eq!(c.privacy.log_buffer_bytes(), 2 * 1024 * 1024);
    let c: NodeConfig = toml::from_str("[privacy]\nlog_buffer_mib = 99\n").unwrap();
    assert_eq!(c.privacy.log_buffer_bytes(), 8 * 1024 * 1024);
}

#[test]
fn privacy_settings_survive_a_save_and_load() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = NodeConfig::default();
    c.privacy.diagnostic_logging = true;
    c.save(dir.path()).unwrap();
    assert!(load_privacy(dir.path()).diagnostic_logging);
    set_diagnostic_persistent(dir.path(), false).unwrap();
    assert!(!load_privacy(dir.path()).diagnostic_logging);
}

// ── old log files from earlier versions ─────────────────────────────────────

fn old_logs(dir: &Path) {
    for n in [
        "daemon.log.2026-01-02",
        "desktop.log.2026-03-04",
        "bridge.log.2026-05-06",
        "daemon.log",
    ] {
        std::fs::write(dir.join(n), vec![b'x'; 5000]).unwrap();
    }
    // Not ours to touch.
    std::fs::write(dir.join("notes.log"), b"keep").unwrap();
    std::fs::write(dir.join("daemon.logger.txt"), b"keep").unwrap();
}

fn with_config(dir: &Path) {
    NodeConfig::default().save(dir).unwrap();
}

#[test]
fn legacy_scan_finds_dated_names_only() {
    let dir = tempfile::tempdir().unwrap();
    old_logs(dir.path());
    let found = legacy::scan(&[dir.path()]);
    assert_eq!(found.files.len(), 4);
    assert_eq!(found.bytes, 20_000);
}

#[test]
fn headless_daemon_tells_first_and_removes_on_a_later_start() {
    let dir = tempfile::tempdir().unwrap();
    with_config(dir.path());
    old_logs(dir.path());
    // First start: notice only, nothing deleted.
    let r = legacy::headless_startup_with(dir.path(), false, false, false);
    assert!(
        matches!(r, legacy::Startup::Notice { files: 4, .. }),
        "{r:?}"
    );
    assert_eq!(legacy::scan(&[dir.path()]).files.len(), 4);
    assert!(
        NodeConfig::load(dir.path())
            .unwrap()
            .privacy
            .old_logs_notice_shown
    );
    // Later start: removed (and the bystanders stay).
    let r = legacy::headless_startup_with(dir.path(), false, false, false);
    assert_eq!(
        r,
        legacy::Startup::Removed(legacy::RemoveReport {
            removed: 4,
            failed: 0
        })
    );
    assert!(legacy::scan(&[dir.path()]).is_empty());
    assert!(dir.path().join("notes.log").exists());
    assert!(dir.path().join("daemon.logger.txt").exists());
}

#[test]
fn keep_env_gui_parent_and_keep_choice_all_prevent_deletion() {
    let dir = tempfile::tempdir().unwrap();
    with_config(dir.path());
    old_logs(dir.path());
    legacy::record_notice_shown(dir.path());
    assert_eq!(
        legacy::headless_startup_with(dir.path(), true, false, false),
        legacy::Startup::Nothing
    );
    assert_eq!(
        legacy::headless_startup_with(dir.path(), false, true, false),
        legacy::Startup::Nothing
    );
    legacy::record_keep(dir.path());
    assert_eq!(
        legacy::headless_startup_with(dir.path(), false, false, false),
        legacy::Startup::Nothing
    );
    assert!(legacy::pending_in(dir.path(), false).is_none());
    assert_eq!(legacy::scan(&[dir.path()]).files.len(), 4);
}

#[test]
fn never_deletes_before_the_notice_even_with_a_missing_config() {
    let dir = tempfile::tempdir().unwrap();
    old_logs(dir.path());
    // No config.toml: the notice cannot be recorded, so a daemon start keeps
    // reporting the notice and never removes.
    for _ in 0..3 {
        let r = legacy::headless_startup_with(dir.path(), false, false, false);
        assert!(matches!(r, legacy::Startup::Notice { .. }), "{r:?}");
    }
    assert_eq!(legacy::scan(&[dir.path()]).files.len(), 4);
    // And no config file was invented.
    assert!(!crate::paths::config_file(dir.path()).exists());
}

#[test]
fn gui_choice_delete_removes_files_and_pending_goes_away() {
    let dir = tempfile::tempdir().unwrap();
    with_config(dir.path());
    old_logs(dir.path());
    let found = legacy::pending_in(dir.path(), false).expect("pending");
    let rep = legacy::remove(&found);
    assert_eq!((rep.removed, rep.failed), (4, 0));
    assert!(legacy::pending_in(dir.path(), false).is_none());
}

#[test]
fn secure_remove_overwrites_before_unlinking() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("daemon.log.x");
    std::fs::write(&p, vec![0xAAu8; 200_000]).unwrap();
    // Keep a second handle to the same file to observe the overwrite.
    let mut f = std::fs::File::open(&p).unwrap();
    // Windows may refuse to delete a file that is open; the overwrite still ran.
    let _ = diag::secure_remove(&p);
    use std::io::Read;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).unwrap();
    assert!(buf.iter().all(|b| *b == 0), "content must be zeroed");
}
