//! `WipeGate::write_output` only ever removes a file that this call created or
//! truncated. A target it could not open stays exactly as it was.

use miasma_core::wipe::WipeGate;

/// Hold `path` open so that opening it for writing fails, while deleting it
/// would still be allowed (the case where a careless cleanup does damage).
#[cfg(windows)]
fn block_writers(path: &std::path::Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_DELETE: u32 = 0x4;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_DELETE)
        .open(path)
        .unwrap()
}

#[cfg(unix)]
fn block_writers(path: &std::path::Path) -> std::fs::File {
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o444);
    std::fs::set_permissions(path, perms).unwrap();
    std::fs::File::open(path).unwrap()
}

#[tokio::test]
async fn a_target_that_cannot_be_opened_is_left_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("precious.bin");
    std::fs::write(&out, b"the user's own file").unwrap();
    let holder = block_writers(&out);

    let gate = WipeGate::new();
    let res = gate.write_output(&out, b"plaintext").await;
    drop(holder);
    // Running as a privileged user the open may succeed; nothing to check then.
    if res.is_ok() {
        return;
    }
    assert!(
        res.unwrap_err().to_string().contains("cannot write to"),
        "the failure is reported"
    );
    assert!(
        out.exists(),
        "a file that was never written must not be deleted"
    );
    assert_eq!(std::fs::read(&out).unwrap(), b"the user's own file");
}

#[tokio::test]
async fn an_existing_target_is_replaced_like_the_streaming_route_does() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.bin");
    std::fs::write(&out, b"old and longer content").unwrap();
    let gate = WipeGate::new();
    gate.write_output(&out, b"new").await.unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"new");
}

#[tokio::test]
async fn a_wipe_removes_the_file_this_call_created() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("created.bin");
    let gate = WipeGate::new();
    gate.begin_wipe();
    assert!(gate.write_output(&out, b"x").await.is_err());
    assert!(!out.exists());
}
