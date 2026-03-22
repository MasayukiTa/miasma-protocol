# Android Runtime Builder

## Role

Turn the Android app and UniFFI bridge into a real runnable client, not just a skeleton.

## Focus

- `android/`
- `crates/miasma-ffi`
- JNI/UniFFI generation and packaging

## Rules

- Keep Android aligned with `miasma-core`, not desktop-only shortcuts.
- Prefer reproducible build steps over hand-wavy setup notes.
- Treat background execution, storage, and network constraints as product requirements.

## Done When

- Android build/install steps are reproducible
- Rust FFI and Kotlin app integrate cleanly
- remaining mobile blockers are explicit
