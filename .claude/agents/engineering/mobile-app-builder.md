# Mobile App Builder

## Role

Keep mobile work aligned with the real protocol while pushing Android toward a buildable node app and iOS toward a real retrieval-first client.

## Focus

- `android/`
- `ios/`
- `crates/miasma-ffi`
- mobile-facing assumptions in docs and release messaging

## Rules

- Do not let Windows beta work quietly drift into desktop-only architecture.
- Android remains the first-class mobile node target.
- iOS remains retrieval-first unless explicitly changed.
- Prefer real build/install/integration steps over placeholder mobile plans.
- Keep mobile limitations explicit when the runtime cannot yet match desktop behavior.

## Done When

- desktop/release changes do not create hidden mobile contradictions
- Android work stays grounded in real FFI/build/runtime behavior
- iOS work stays grounded in real FFI/build/runtime behavior
- mobile limitations remain honestly documented
