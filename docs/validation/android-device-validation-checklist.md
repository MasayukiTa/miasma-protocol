# Android Device Validation Checklist

**Version**: 0.3.1
**Purpose**: Step-by-step checklist for validating the Android directed sharing implementation on a real ARM64 device.

---

## Prerequisites

- [ ] Android SDK with API 34 installed (`$ANDROID_HOME`)
- [ ] Android NDK 27.0.12077973 installed
- [ ] Rust targets: `rustup target add aarch64-linux-android x86_64-linux-android`
- [ ] `cargo-ndk` installed: `cargo install cargo-ndk`
- [ ] JDK 17+ installed
- [ ] Real Android device (ARM64) with USB debugging enabled
- [ ] Windows machine running Miasma daemon (for cross-device tests)

## Build

```bash
./scripts/build-android.sh          # Debug APK
# OR
./scripts/build-android.sh --release  # Release APK
```

- [ ] Build completes without errors
- [ ] APK size is reasonable (expect ~15-30 MiB due to libp2p)
- [ ] `find android/app/src/main/jniLibs -name "*.so"` shows arm64-v8a and x86_64 libraries

## Track A: Install and Launch

- [ ] APK installs cleanly via `adb install`
- [ ] App launches without crash
- [ ] Notification appears: "Miasma Node — Starting…"
- [ ] Notification updates to: "Connected · port XXXXX"
- [ ] Home screen shows "Connected" status indicator
- [ ] Sharing contact appears (non-empty `msk:…@PeerId` string)

**Record**: Device model: ___, Android version: ___, Build type: ___

## Track B: Daemon and Network

- [ ] Status screen shows daemon running with HTTP port
- [ ] Node status shows share count and storage usage
- [ ] Sharing contact is a valid `msk:…@12D3KooW…` format
- [ ] No "Daemon error" message in notification or UI

**Network** (if another Miasma node is on the same network):
- [ ] mDNS peer discovery finds peer (check Status for peer count > 0)
- [ ] OR: manual bootstrap succeeds

## Track C: Windows ↔ Android Directed Sharing

### C.1: Windows → Android

On **Windows** (CLI):
```
miasma directed send --to <android-sharing-contact> --password "test123" --retention 1h
```
(Paste some text as input)

On **Android** (Inbox tab):
- [ ] New envelope appears with "Pending" or "Challenge" badge
- [ ] Challenge code is displayed
- [ ] Copy button works for challenge code

On **Windows** (CLI):
```
miasma directed confirm --envelope <id> --code <challenge-code>
```

On **Android** (Inbox tab after refresh):
- [ ] State transitions to "Confirmed"
- [ ] Password field appears
- [ ] Enter "test123" → tap Retrieve
- [ ] Content retrieved successfully
- [ ] Retrieved bytes match what was sent
- [ ] State transitions to "Retrieved" (terminal)
- [ ] Password field disappears
- [ ] Delete button disappears

### C.2: Android → Windows

On **Android** (Send tab):
- [ ] Enter Windows sharing contact in recipient field
- [ ] Enter message text
- [ ] Enter password
- [ ] Set retention hours
- [ ] Tap Send
- [ ] Success card shows envelope ID

On **Windows** (CLI):
```
miasma directed inbox
```
- [ ] Envelope appears with challenge code

On **Android** (Outbox tab):
- [ ] Envelope shows "Confirm" badge
- [ ] Enter challenge code from Windows
- [ ] Tap Confirm
- [ ] Success text appears

On **Windows** (CLI):
```
miasma directed retrieve --envelope <id> --password <password>
```
- [ ] Content matches what was sent from Android

## Track D: Lifecycle

- [ ] Background app (home button) → notification stays
- [ ] Return to app → state is coherent, daemon still running
- [ ] Force-stop app → relaunch → daemon restarts cleanly
- [ ] No stale port errors after restart

**Network interruption**:
- [ ] Toggle airplane mode on → app shows error or "local only"
- [ ] Toggle airplane mode off → daemon recovers or requires restart
- [ ] Inbox/outbox refresh works after network restore

## Track E: Security

### Keystore
- [ ] `master.key.enc` and `master.key.iv` exist in data dir after first run
- [ ] Keystore wrapping key exists: check via Android Keystore Explorer or `adb shell`
- [ ] Kill app → relaunch → daemon starts (Keystore unwrap works)

### Distress Wipe
- [ ] Long-press title on Home → wipe dialog appears
- [ ] Confirm wipe
- [ ] `master.key`, `master.key.enc`, `master.key.iv` are deleted
- [ ] App shows uninitialized state
- [ ] Inbox/outbox are cleared

### Fail-Closed (from daemon-side, but verify UI reflects)
- [ ] After 3 wrong challenge attempts: envelope shows "Failed" badge, no more challenge input
- [ ] After 3 wrong password attempts: envelope shows "Failed" badge, no more password input
- [ ] Revoked envelope shows "Revoked" badge, no action buttons
- [ ] Expired envelope shows "Expired" badge, no action buttons

## Track G: Record Results

**What succeeded**: ___

**What failed**: ___

**What was fragile**: ___

**Recommendation**:
- [ ] Ready for limited Android beta testers
- [ ] Ready for technical testers only
- [ ] Not ready yet — reason: ___
