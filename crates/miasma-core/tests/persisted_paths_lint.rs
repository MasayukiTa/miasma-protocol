//! Lint: nothing is written outside the persisted-paths registry.
//!
//! Two rules, both applied to non-test code in `crates/*/src`:
//!
//! 1. **Write sites are allow-listed.** A line that creates, writes, renames or
//!    copies a file, creates a directory, asks for the OS temp dir, or sets up
//!    file logging (`tracing_appender`) is only accepted in a file listed in
//!    `persisted_paths_allowlist.allow`, with a justification and a ceiling on the
//!    number of such lines. A new file, or more sites than the ceiling, fails the
//!    test. The fix is to route the new write through `miasma_core::paths`
//!    (add a registry entry) and then either use an already allow-listed module
//!    or add the file to the list with a reason.
//! 2. **Registered names are not spelled out again.** A quoted file name that
//!    the registry knows (`"master.key"`, `"daemon.log"`, ...) must not appear
//!    outside `paths.rs`; use the entry's `.name` or its typed accessor.
//!
//! Test code is exempt: `#[cfg(test)]` items, `tests/` directories and files
//! named `*_tests.rs`. Whole-line comments are ignored. The scan is textual on
//! purpose: it has no parser to break and costs milliseconds.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use miasma_core::paths::{Kind, REGISTRY};

/// Substrings that mark a place where the product puts bytes on disk, makes a
/// directory, or picks a scratch location.
const WRITE_MARKERS: &[&str] = &[
    "fs::write(",
    "File::create(",
    "File::create_new(",
    "OpenOptions::new(",
    "OpenOptions::new()",
    "create_dir_all(",
    "fs::create_dir(",
    "fs::rename(",
    "fs::copy(",
    "env::temp_dir()",
    "NamedTempFile",
    "tempfile::tempfile",
    "tracing_appender",
    "atomic_write(",
    "write_restricted(",
    "atomic_write_restricted(",
];

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Every non-test source file below `crates/*/src`, as (path relative to
/// `crates/` with `/` separators, contents).
fn product_sources() -> Vec<(String, String)> {
    let root = crates_dir();
    let mut files = Vec::new();
    let mut crate_dirs: Vec<_> = fs::read_dir(&root)
        .expect("read crates/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    crate_dirs.sort();
    for c in crate_dirs {
        rust_files(&c.join("src"), &mut files);
    }
    let mut out = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let name = rel.rsplit('/').next().unwrap_or("");
        if name.ends_with("_tests.rs") || name == "tests.rs" {
            continue;
        }
        let text = fs::read_to_string(&f).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        out.push((rel, text));
    }
    out
}

/// The lines of `src` that are neither comments nor inside a `#[cfg(test)]`
/// item. Relies on rustfmt: an item's closing brace sits at the indent of the
/// attribute that introduced it.
fn production_lines(src: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(test") {
            let indent = line.len() - trimmed.len();
            // Skip further attributes, then the item itself.
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
            if j >= lines.len() {
                break;
            }
            let head = lines[j].trim_end();
            if head.ends_with(';') || (head.contains('{') && head.ends_with('}')) {
                i = j + 1;
                continue;
            }
            // Multi-line item: skip to the closing brace at the same indent.
            let close = format!("{}}}", " ".repeat(indent));
            let mut k = j + 1;
            while k < lines.len() {
                let t = lines[k].trim_end();
                if t == close || t == format!("{close};") {
                    break;
                }
                k += 1;
            }
            i = k + 1;
            continue;
        }
        if !trimmed.starts_with("//") {
            out.push((i + 1, line));
        }
        i += 1;
    }
    out
}

fn is_write_site(line: &str) -> bool {
    WRITE_MARKERS.iter().any(|m| line.contains(m))
}

struct Allow {
    max: usize,
    reason: String,
}

fn allowlist() -> BTreeMap<String, Allow> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("persisted_paths_allowlist.allow");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let mut map = BTreeMap::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, '|').map(str::trim).collect();
        assert!(
            parts.len() == 3 && !parts[2].is_empty(),
            "allowlist line {} must be `path | max | reason` with a reason: {raw}",
            n + 1
        );
        let max: usize = parts[1]
            .parse()
            .unwrap_or_else(|_| panic!("allowlist line {}: max is not a number", n + 1));
        let prev = map.insert(
            parts[0].to_string(),
            Allow {
                max,
                reason: parts[2].to_string(),
            },
        );
        assert!(prev.is_none(), "allowlist repeats {}", parts[0]);
    }
    map
}

#[test]
fn write_sites_only_in_allowlisted_modules() {
    let allow = allowlist();
    let mut problems = Vec::new();
    let mut suggestions = Vec::new();
    let mut seen_allowed = Vec::new();

    for (rel, text) in product_sources() {
        if rel == "miasma-core/src/paths.rs" {
            continue;
        }
        let hits: Vec<(usize, &str)> = production_lines(&text)
            .into_iter()
            .filter(|(_, l)| is_write_site(l))
            .collect();
        if hits.is_empty() {
            continue;
        }
        match allow.get(&rel) {
            None => {
                problems.push(format!(
                    "{rel}: {} write site(s) outside the allow-list, first at line {}: {}",
                    hits.len(),
                    hits[0].0,
                    hits[0].1.trim()
                ));
                suggestions.push(format!(
                    "{rel} | {} | <why this module may write>",
                    hits.len()
                ));
            }
            Some(a) => {
                seen_allowed.push(rel.clone());
                if hits.len() > a.max {
                    problems.push(format!(
                        "{rel}: {} write sites, allow-list ceiling is {} ({}). New writes must go \
                         through miasma_core::paths; first extra candidate at line {}",
                        hits.len(),
                        a.max,
                        a.reason,
                        hits[a.max].0
                    ));
                    suggestions.push(format!("{rel} | {} | {}", hits.len(), a.reason));
                }
            }
        }
    }

    // A stale entry hides nothing today but would let a future write slip in.
    for (path, a) in &allow {
        if !seen_allowed.contains(path) {
            problems.push(format!(
                "allow-list entry `{path}` ({}) matches no write site: remove it",
                a.reason
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "persisted-paths lint failed:\n  {}\n\nTo accept a reviewed change, \
         update crates/miasma-core/tests/persisted_paths_allowlist.allow:\n  {}\n",
        problems.join("\n  "),
        suggestions.join("\n  ")
    );
}

#[test]
fn registered_names_are_not_respelled() {
    // Only names that cannot be mistaken for ordinary words: they contain a
    // dot, dash, underscore or backslash ("master.key", "daemon.log",
    // "url-scheme-registered.txt"), and are not patterns.
    let mut names: Vec<(&str, &str)> = Vec::new();
    for s in REGISTRY {
        if s.kind == Kind::Pattern {
            continue;
        }
        let distinctive = s
            .name
            .chars()
            .any(|c| matches!(c, '.' | '-' | '_' | '\\' | '/'));
        if distinctive {
            names.push((s.id, s.name));
        }
    }
    assert!(names.len() > 15, "registry shrank unexpectedly");

    let mut problems = Vec::new();
    for (rel, text) in product_sources() {
        if rel == "miasma-core/src/paths.rs" {
            continue;
        }
        for (n, line) in production_lines(&text) {
            for (id, name) in &names {
                let quoted = format!("\"{name}\"");
                if line.contains(&quoted) {
                    problems.push(format!(
                        "{rel}:{n}: {quoted} is registered as paths::{id}; use the registry"
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "registered names respelled outside paths.rs:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn production_line_filter_skips_test_modules_and_comments() {
    // Built from a list: a `\` line continuation would eat the indentation
    // this test is about.
    let src = [
        "fn a() { std::fs::write(p, b); }",
        "// std::fs::write(commented)",
        "#[cfg(test)]",
        "mod tests {",
        "    fn t() {",
        "        std::fs::write(x, y);",
        "    }",
        "}",
        "fn b() { File::create(q); }",
        "    #[cfg(test)]",
        "    fn helper() {",
        "        std::fs::write(x, y);",
        "    }",
        "fn c() {}",
        "#[cfg(test)]",
        "use something;",
        "fn d() { fs::rename(a, b); }",
    ]
    .join("\n");
    let hits: Vec<usize> = production_lines(&src)
        .into_iter()
        .filter(|(_, l)| is_write_site(l))
        .map(|(n, _)| n)
        .collect();
    assert_eq!(hits, vec![1, 9, 17]);
}
