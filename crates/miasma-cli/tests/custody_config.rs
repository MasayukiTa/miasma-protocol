use std::process::{Command, Output};

fn run(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_miasma"))
        .arg("--data-dir")
        .arg(dir)
        .args(args)
        .env_remove("MIASMA_LANG")
        .env_remove("MIASMA_LOG")
        .output()
        .expect("run miasma")
}

#[test]
fn custody_config_round_trip_and_offline_check() {
    let dir = tempfile::tempdir().unwrap();
    for key in [
        "chat.custody_enabled",
        "push.file_custody_enabled",
        "custody.accept_unknown_depositors",
    ] {
        for value in ["false", "true"] {
            let set = run(dir.path(), &["config", "--key", key, "--value", value]);
            assert!(set.status.success(), "{set:?}");
            let get = run(dir.path(), &["config", "--key", key]);
            assert!(get.status.success(), "{get:?}");
            assert_eq!(String::from_utf8(get.stdout).unwrap().trim(), value);
        }
    }
    let set = run(
        dir.path(),
        &[
            "config",
            "--key",
            "custody.accept_unknown_depositors",
            "--value",
            "false",
        ],
    );
    assert!(set.status.success(), "{set:?}");
    for command in ["offline-check", "status"] {
        let output = run(dir.path(), &[command]);
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("Accept unknown depositors: no"));
    }
    let set = run(
        dir.path(),
        &[
            "config",
            "--key",
            "custody.accept_unknown_depositors",
            "--value",
            "true",
        ],
    );
    assert!(set.status.success(), "{set:?}");
    let list = run(dir.path(), &["config"]);
    assert!(list.status.success(), "{list:?}");
    let listing = String::from_utf8(list.stdout).unwrap();
    assert!(listing.contains("custody_enabled = true"));
    assert!(listing.contains("file_custody_enabled = true"));
    for (value, expected) in [("true", "yes"), ("false", "no")] {
        let set = run(
            dir.path(),
            &[
                "config",
                "--key",
                "push.file_custody_enabled",
                "--value",
                value,
            ],
        );
        assert!(set.status.success(), "{set:?}");
        let check = run(dir.path(), &["offline-check"]);
        assert!(check.status.success(), "{check:?}");
        let stdout = String::from_utf8(check.stdout).unwrap();
        assert!(
            stdout.lines().any(|line| line
                .trim()
                .strip_prefix("File custody enabled:")
                .is_some_and(|v| v.trim() == expected)),
            "{stdout}"
        );
    }
}
