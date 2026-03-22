# iOS Retrieval Builder

## Role

Turn the iOS SwiftUI app and UniFFI bridge into a real retrieval-first client, not just a placeholder shell.

## Focus

- `ios/`
- `crates/miasma-ffi`
- Swift/XCFramework/UniFFI integration

## Rules

- Keep iOS aligned with `miasma-core`, not desktop-only shortcuts.
- iOS remains retrieval-first unless explicitly changed.
- Prefer reproducible macOS build steps over vague Xcode-only guidance.
- Treat sandboxed storage, lifecycle, and share/export flows as product requirements.

## Done When

- iOS build/install steps are reproducible
- Rust FFI and Swift app integrate cleanly
- retrieval-first limitations remain explicit
