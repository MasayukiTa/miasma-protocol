//! Reserve a bigger main-thread stack for the `miasma` binary on Windows.
//!
//! Windows gives a program's main thread 1 MiB unless the executable asks for
//! more. In a debug build, parsing the command line with `clap` (one large
//! generated function per command tree) and running the async `main` need just
//! over that, so every command, even `--version`, died with a stack overflow
//! once a few more options were added. Release builds are nowhere near it, and
//! Unix main threads get 8 MiB; the fix is to make the Windows one match, not to
//! keep trimming options.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/STACK:8388608");
    }
}
