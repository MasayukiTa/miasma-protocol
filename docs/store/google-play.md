# Google Play submission kit

[日本語](google-play.ja.md) | **English**

Draft for the owner. Everything here comes from the Android sources and scripts in this repository (`android/`, `scripts/build-android.sh`, `crates/miasma-ffi`). The README says the Android app "is not published as a download yet", and this kit agrees: section 8 lists what still blocks a submission. Items marked [Owner] need a decision or a real device.

The Android app is smaller than the desktop app. Its screens are Home, Files (received files, sent files, get a file back), Status and Settings. It has no Contacts screen, no Chat and no invitation code. Describe only what it has.

## 1. Listing text

### App name

Miasma

### Short description

Send, receive and save files privately, directly between devices.

### Full description

> Miasma lets you send a file to someone you trust, and keep your own files safe, without handing them to a company's server.
>
> What you can do
>
> - Send a file. Choose a file (up to 100 MiB) or type some text, enter the recipient's contact, and set a password and how long the recipient can fetch it. The recipient gives you a challenge code, which you confirm.
> - Receive a file. Files sent to you appear under Files. Send the challenge code to the sender, enter the password, and save the file to your device.
> - Save securely. Encrypt a file or some text and store it. Miasma gives you a Content ID that you keep. You can show it as a QR code.
> - Get a file back. Enter or scan a Content ID and save the recovered file to your device.
> - Emergency Wipe. Destroy the node key on this device. Everything stored here becomes unreadable.
>
> How it works
>
> - No account, no ads and no analytics.
> - Files travel encrypted, from your device to the person you chose. The publisher runs no server that stores your files.
> - The app has no built-in server to connect to. It starts from the peers you enter in Settings.
>
> Beta software
>
> Miasma is beta software and has not been externally audited. Do not use it for material whose exposure would be serious. Both people need Miasma. The app keeps a notification while its node runs, and Android may end that background session after a while. Open Miasma to start it again.

Check this text against the app before you submit. The wording above follows `android/app/src/main/res/values/strings.xml` and the screens in `android/app/src/main/kotlin/dev/miasma/ui`.

### Graphic assets

The repository has no Play listing graphics. Needed: app icon 512 x 512, feature graphic 1024 x 500, and phone screenshots taken on a real device. `web/icons/icon-512.png` is 512 x 512 and could serve as the icon if the owner likes it. [Owner] Screenshots need a real device or emulator running a release build. None exist yet.

### Privacy policy

Publish [privacy-policy.md](privacy-policy.md) after review and enter its public address in Play Console.

## 2. Data safety form (draft)

Match each answer to the question you see in Play Console and to Google's current help page on the meaning of "collect" and "share". As I read it, data that stays on the device, or that the user sends to a recipient the user chose, is not collected by the developer. [Owner] Confirm that reading against the current help page before you submit. The answers below are for the Android app only.

Facts behind the answers: the app has no account system, no advertising or analytics code (checked in `android/` and its Gradle dependencies: Compose, AndroidX, ZXing, JNA), and no developer-run server. The embedded node is the Rust core. On Android its iroh relay and discovery transport is switched off (`crates/miasma-ffi/src/lib.rs`), so the app contacts no relay or discovery service. It starts from the bootstrap peers the user types in Settings (there is no default), and then connects to the recipient and to other peers the shared data needs.

| Section | Draft answer | Reason |
|---|---|---|
| Does the app collect or share any of the required user data types | No | See the reading above. [Owner] confirm. |
| Location | Not collected | The app does not read location. |
| Personal info (name, email, user IDs, address, phone, other) | Not collected | No account, no sign-in. |
| Financial info | Not collected | No payments. |
| Health and fitness | Not collected | None. |
| Messages | Not collected by the developer | Text typed in Send goes to the recipient the user chose, encrypted. |
| Photos and videos, Files and docs | Not collected by the developer | Files the user picks go to the chosen recipient. |
| Audio | Not collected | None. |
| Calendar, Contacts (device contacts) | Not collected | The app does not read them. |
| App activity | Not collected | No analytics. |
| Web browsing | Not collected | None. |
| App info and performance (crash logs, diagnostics) | Not collected | Nothing is sent to the developer. |
| Device or other IDs | Not collected | The app does not read the advertising ID or device IDs. Its own node ID (peer ID) is visible to the peers it talks to. [Owner] decide if you want to mention it. |

Security practices:

| Question | Draft answer | Notes |
|---|---|---|
| Data encrypted in transit | Yes | Peer connections use QUIC, and content is encrypted before it leaves the device. |
| Way to request data deletion | The developer holds no user data. In the app, Emergency Wipe erases local data, and uninstalling removes it. | Play's account-deletion requirement is about accounts, and the app has none. [Owner] Confirm in the current Play policy. |
| Independent security review | No | The app has not been externally audited. |
| Follows the Families policy | Not applicable | The app is not designed for children. |

About encryption at rest, honestly: stored shares are encrypted. A recovery copy of the node key is wrapped by an Android Keystore key (`KeystoreHelper.kt`). The Rust core still reads a plaintext `master.key` file in the app-private directory while the node runs. The file comment says this is defense in depth, not a claim that the key never leaves secure hardware. Do not claim more in the listing.

## 3. Permissions and declarations

From `android/app/src/main/AndroidManifest.xml`:

| Permission | Why | Console action |
|---|---|---|
| `INTERNET`, `ACCESS_NETWORK_STATE` | Peer connections | None. |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC` | Keeps the node running with a notification | Complete the Foreground service declaration for the `dataSync` type and describe the user-facing feature. Android 15 and later limits how long a `dataSync` service may run. The service handles this in `onTimeout` and stops. |
| `CAMERA` (feature not required) | Reads a QR code when the user presses Scan | None beyond the permission declaration. The app does not ask at start. |
| `READ_EXTERNAL_STORAGE` up to API 28 | Reading files to save | None. |

Not declared: `POST_NOTIFICATIONS`. On Android 13 and later, the notification of the foreground service may not be visible until the user allows notifications. See section 8.

`android:allowBackup="false"`. Cleartext traffic is blocked except to `127.0.0.1` and `localhost`, which the embedded node uses. The file provider shares only an `exports/` subfolder.

## 4. Target API, 16 KiB pages and the AAB

- `compileSdk` 36, `targetSdk` 36, `minSdk` 26 (`android/app/build.gradle.kts`). [Owner] Check the current Play target API requirement for new apps. The repo targets 36.
- 16 KiB page size: the Android Gradle Plugin is 8.11.1, native libraries are stored with `useLegacyPackaging = false`, and `scripts/build-android.sh` fails the build when an ELF segment of `libmiasma_ffi.so` is not aligned to 16 KiB, when an APK is not 16 KiB zip-aligned, or when any `.so` inside the output (including the JNA library) is not aligned. For a release it also asks `bundletool` for `PAGE_ALIGNMENT_16K`, and only prints a warning if the tool is missing or does not report it. [Owner] These checks were not run here.
- ABIs: `arm64-v8a` and `x86_64`. No 32-bit ABI, which Play accepts for 64-bit-only apps.
- The release build turns on R8 shrinking (`isMinifyEnabled`), with rules in `android/app/proguard-rules.pro`.
- Version: `versionCode` comes from `MIASMA_ANDROID_VERSION_CODE` (default 1) and `versionName` from `MIASMA_ANDROID_VERSION_NAME` (default 0.3.2). Every upload to Play needs a higher `versionCode`.
- Application ID: `dev.miasma`. It cannot be changed after the first upload. [Owner] Confirm that you want this ID.

## 5. Signing: Play App Signing and the upload key

Use Play App Signing. Google keeps the app signing key. You hold an upload key and sign the AAB with it.

- Do not create or store a key in this repository. This kit does not include one.
- `scripts/build-android.sh --release` signs with the upload key and needs four environment variables: `MIASMA_ANDROID_KEYSTORE` (path to the keystore), `MIASMA_ANDROID_STORE_PASSWORD`, `MIASMA_ANDROID_KEY_ALIAS` and `MIASMA_ANDROID_KEY_PASSWORD`. Without them the script stops. `--unsigned-release` skips signing and is for checks only.
- The owner creates the upload keystore once on a trusted PC, for example with `keytool -genkeypair -v -keystore <path-outside-the-repo> -alias <alias> -keyalg RSA -keysize 2048 -validity 9125`. Keep the file and its passwords outside the repository, in a password manager, with an offline backup. If the upload key is lost, Play Console has a process to reset it, but that takes time.
- Output: `android/app/build/outputs/bundle/release/app-release.aab`.

## 6. Content rating (IARC questionnaire, draft)

| Topic | Draft answer | Why |
|---|---|---|
| Violence, fear, sexual content, bad language, gambling, drugs | No | The app has no such content of its own. |
| Users can communicate or share content with each other | Yes | A user can send a file or text to a recipient they choose. |
| Content visible to the public or to strangers | No | Only the chosen recipient can fetch it. There is no feed and no search. |
| Moderated by the developer | No | The developer runs no server. |
| Shares the user's location | No | Not read. |
| Purchases, ads | No | None. |

## 7. Testing track requirement

Google has had testing requirements for new personal developer accounts, such as a period of closed testing with a number of testers before production access. These rules change. Check the current Play Console rules for new personal accounts before you plan the schedule. This kit does not assert any number. [Owner] Plan for a closed test, and keep a list of testers who can install from the testing link.

## 8. What still blocks a Play submission

Read from the repository, not from a build:

1. The README states that the Android app is in the source tree but not published. The repository's contributor notes call it a skeleton to turn into a reproducible build. No real-device test record exists in the repository. [Owner / real device]
2. The CI workflows in `.github/workflows` do not build the Android app (a search for Android, Gradle and NDK found nothing). A release build has to be made and checked by hand.
3. The build needs tools that are not in the repository: Android SDK API 36, build-tools 36.0.0, NDK 30.0.16248370, Rust targets for Android, `cargo-ndk`, JDK 17 or newer. `./scripts/build-android.sh --setup` installs part of this.
4. The checked-in `android/app/src/main/kotlin/dev/miasma/uniffi/miasma_ffi.kt` is a small development stub. The script regenerates the real binding during a build and puts the stub back afterwards.
5. No upload keystore exists in the repository, by design. See section 5.
6. No Play listing graphics or phone screenshots exist.
7. `POST_NOTIFICATIONS` is not declared, so on Android 13 and later the foreground service notification may be hidden until the user allows it. Add the permission and a request, or accept that the notification stays hidden.
8. The Android 15 limit on `dataSync` services: the service stops itself on timeout and the app tells the user to open it again. This should be tested on a real device. [Real device]
9. Localization is incomplete. There is a `values-ja` file, but parts of the screens use fixed English text (the Settings title and buttons, and the notification text such as "Starting..." and "Connected"). The manifest label for the web view activity is the fixed text "Miasma Web". The Play listing in Japanese would show a mixed-language app.
10. Terms differ from the desktop Easy mode. Android says "Content ID", "sharing contact" (`msk:...@PeerId`) and "challenge code". The desktop says "invitation code" (for a Share ID), "contact code" and "check code". There is no Contacts screen on Android. Align them before a public release if you want one vocabulary across the product. [Owner]
11. The foreground service declaration and the Data safety form must be filled in Play Console, and the privacy policy must be published at a public address.
12. `applicationId` `dev.miasma` must be confirmed. [Owner]
