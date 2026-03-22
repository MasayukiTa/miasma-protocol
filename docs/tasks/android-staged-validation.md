## Android Staged Validation

### Purpose

Run Android validation in a staged way so we do not blur together:

1. local build success
2. emulator success
3. real-device success
4. cross-device/network success

### Important execution rule

This task is stage-gated.

After each stage:

1. stop work
2. summarize what passed and failed
3. recommend the next stage
4. explicitly ask whether to continue

### Stage 1: Build and install

Validate:
- Gradle sync/build works
- Rust mobile build works
- app installs on emulator or device
- app launches without immediate crash

Do not continue until install/launch are real.

### Stage 2: Core flows

Validate:
- initialize node
- status screen loads
- save/store works for a small sample
- retrieve/get back works for a known sample
- FFI errors surface cleanly

Do not continue until the basic app loop works or the blocker is explicit.

### Stage 3: Device reality

Validate:
- app survives background/foreground transitions reasonably
- storage paths behave as expected
- logs/diagnostics can be collected
- non-English text renders if localization exists

### Stage 4: Network reality

Validate:
- same-network peer connectivity if Android node behavior exists
- retrieval against an external peer if supported
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
4. whether Android should move to broader implementation or remain in foundation work
