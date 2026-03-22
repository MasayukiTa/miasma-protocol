## iOS Staged Validation

### Purpose

Run iOS validation in a staged way so we do not blur together:

1. local build success
2. simulator success
3. real-device success
4. real retrieval-client success

### Important execution rule

This task is stage-gated.

After each stage:

1. stop work
2. summarize what passed and failed
3. recommend the next stage
4. explicitly ask whether to continue

### Stage 1: Build and launch

Validate:
- Rust Apple targets build
- UniFFI generation works
- XCFramework creation works
- app builds in Xcode or xcodebuild
- app launches on simulator or device without immediate crash

Do not continue until build/install/launch are real.

### Stage 2: Retrieval-first core flows

Validate:
- initialize local state if required
- status screen loads
- MID input flow works
- retrieve/get back works for a known sample
- share/save/export works for retrieved content
- FFI errors surface cleanly

Do not continue until the basic retrieval loop works or the blocker is explicit.

### Stage 3: Device reality

Validate:
- app survives foreground/background transitions reasonably
- storage and export paths behave as expected
- logs/diagnostics can be collected
- non-English text renders if localization exists

### Stage 4: Real retrieval reality

Validate:
- retrieval against an external peer if supported
- input flows from paste/share/open are understandable
- degraded-network failure behavior remains understandable

### Success criteria

The staged validation is useful even if later stages fail, as long as:

- the failure point is precise
- the failure is reproducible
- next work is obvious

### Final report format

1. highest stage reached
2. what passed
3. what failed
4. whether iOS should move to broader implementation or remain in foundation work
