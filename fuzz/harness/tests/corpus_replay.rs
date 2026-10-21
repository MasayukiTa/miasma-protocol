//! Runs every committed seed through its target on stable Rust, so a decoder
//! change that breaks a seed shows up in an ordinary `cargo test` without a
//! nightly toolchain. Also feeds each target a few degenerate inputs.

use std::path::PathBuf;

use miasma_fuzz_harness::TARGETS;

fn corpus_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("corpus")
        .join(name)
}

#[test]
fn every_seed_runs_without_panicking() {
    let mut seeds = 0usize;
    for (name, run) in TARGETS {
        let Ok(entries) = std::fs::read_dir(corpus_dir(name)) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().is_file() {
                let bytes = std::fs::read(entry.path()).expect("read seed");
                run(&bytes);
                seeds += 1;
            }
        }
    }
    assert!(seeds > 0, "no seed corpus found");
}

#[test]
fn degenerate_inputs_do_not_panic() {
    let zeros = vec![0u8; 4096];
    let ones = vec![0xffu8; 4096];
    for (_, run) in TARGETS {
        run(&[]);
        run(&[0]);
        run(&zeros);
        run(&ones);
    }
}
