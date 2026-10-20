# Microsoft Store submission kit

[日本語](microsoft-store.ja.md) | **English**

Draft for the owner. Everything here is taken from the source in this repository. Anything marked [Owner] needs a decision or a check on a real Windows PC. The app is registered later, as an individual developer account.

The terms below match the Easy-mode screens: Home, Send a file, Receive a file, Save securely, Contacts, Chat, Files, Settings, and "invitation code".

## 1. Listing text

### Title

Miasma

(The manifest `DisplayName` is also `Miasma`. If Partner Center reserves a different name, change the title there and keep the manifest as it is.)

### Short description

Send files directly to people you trust and keep your own files safe, with no account.

### Full description

> Miasma lets you send a file to someone you trust, and keep your own files safe, without handing them to a company's server.
>
> Your Miasma app talks straight to your contact's Miasma app and encrypts everything on the way. When a direct connection is not possible, it uses a relay and tells you why.
>
> What you can do
>
> - Send a file. Pick a contact, pick the file, and send. No account, no upload to a website, and no link to paste around.
> - Receive a file. Files from your contacts show up in the app. You can also receive with an invitation code and an optional password.
> - Save securely. Keep a file in encrypted form on your own computer and get it back later.
> - Chat. Send short messages to one contact or to a group. A message sent while someone is offline waits on your computer until they return.
> - Large files. Stop a big transfer and continue it later from where it stopped.
> - Contacts. Exchange contact codes once, then compare the verification code to be sure you are talking to the right person.
>
> How it is different
>
> - No account, no ads and no analytics. No server run by the publisher holds your files.
> - Settings shows where your data is kept. You can clear finished transfers, delete a conversation's history, or erase everything with Emergency Wipe.
> - Interface languages: English, Japanese. [Owner: the app also has Simplified Chinese, but the package declares only en-us and ja-jp. See section 5.]
>
> Beta software
>
> Miasma is beta software and has not been externally audited. Do not use it for material whose exposure would be serious. Both people need Miasma installed. Requires Windows 10 version 2004 (build 19041) or later, 64-bit.

Avoid words the app cannot back up, such as "military-grade", "anonymous" or "untraceable". Store policies forbid misleading claims (check the current text), and SECURITY.md lists the real limits.

### What's new (template)

```
Version <x.y.z>
- <one plain sentence per visible change, using the screen names above>
- Fixes: <short list>
Miasma is beta software and has not been externally audited.
```

### Search terms

file sharing, send files, private file transfer, encrypted storage, peer to peer, secure chat, Japanese

Partner Center limits how many terms you can enter and how long each can be. Cut the list to fit.

### Category

Productivity. [Owner: pick the closest sub-category Partner Center offers for file sharing or utilities.]

### Privacy policy URL

Publish `privacy-policy.md` (after the owner has reviewed it) at a public address and enter that address in Partner Center. A file in the repository works if you use its public GitHub address. See [privacy-policy.md](privacy-policy.md).

## 2. Screenshots

Partner Center needs at least one desktop screenshot of 1366 x 768 or larger. Use real screens with sample data only. Never show a real contact code.

The images already in `docs/images` are all narrower than 1366 pixels (checked from the files), so none of them can be submitted as they are. Do not enlarge them.

| File | Size | Use for the Store |
|---|---|---|
| `docs/images/screenshot-home-en.png` | 1200 x 500 | No. Too small. Recapture Home. |
| `docs/images/screenshot-home-ja.png` | 1200 x 500 | No. Too small. Recapture Home in Japanese. |
| `docs/images/screenshot-contacts-en.png` | 1200 x 900 | No. Recapture Contacts. |
| `docs/images/screenshot-files-en.png` | 1200 x 1010 | No. Recapture Files. |
| `docs/images/screenshot-chat-en.png` | 1200 x 900 | No. Recapture Chat. |
| `docs/images/screenshot-chat-list-ja.png` | 1200 x 450 | No. Recapture the conversation list. |
| `docs/images/screenshot-settings-en.png` | 1200 x 430 | No. Recapture Settings. |

They are fine for the README. For the Store, capture at least these five, in English, and the same set in Japanese for the Japanese listing: Home, Contacts, Chat, Files, Settings.

### How to produce them with the UI tour

The desktop crate has a developer-only UI tour (`crates/miasma-desktop/src/app/tour.rs`, feature `ui-tour`). It is not part of any release build. It draws the real screens with fixture data, so no real contact code appears.

Headless tour (no window). Its step table has fixed sizes. Only the Chat and Contacts fixtures are at least 1366 pixels wide: Chat is 1400 x 900, Contacts is 1400 x 2100.

```powershell
$env:MIASMA_UI_TOUR_ALL = "1"
$env:MIASMA_UI_TOUR_FILTER = "chat_thread_light_en_wide,chat_list_light_en_wide,contacts_two_light_en_wide"
$env:MIASMA_UI_TOUR_OUT = "$env:TEMP\miasma-store-shots"
cargo test --package miasma-desktop --features ui-tour --bin miasma-desktop headless_tour_renders_every_step -- --nocapture
```

Step names are `chat_<fixture>_<light|dark>_<en|ja>_<wide|narrow>` and `contacts_<fixture>_...`. The fixtures are listed in `chat_ui::FIXTURES` and `contacts::FIXTURES`. The Contacts picture is tall, so crop it to a region of at least 1366 x 768. Crop only. Do not scale.

Home, Files and Settings in the headless Easy tour are 1200 pixels wide, which is too small. There are two ways to get them at a larger size:

1. Window tour on a PC with a display. It uses the window size you give it and writes `.ppm` files that you convert to PNG.

   ```powershell
   $env:MIASMA_UI_TOUR = "$env:TEMP\miasma-store-shots-gl"
   $env:MIASMA_UI_TOUR_EASY = "1"
   $env:MIASMA_UI_TOUR_SIZE = "1400x900"
   $env:MIASMA_UI_TOUR_FILTER = "light_en_home,light_en_files,light_en_settings"
   cargo run --release --package miasma-desktop --features ui-tour
   ```

2. A small follow-up change that lets the headless tour read `MIASMA_UI_TOUR_SIZE`. This is not done in this pull request.

[Owner] None of these commands was run while writing this kit (no builds were allowed on the machine used). Run them once and open every image before uploading. A screenshot taken from the installed app with a demo profile also works.

## 3. Age rating questionnaire (draft)

Partner Center uses the IARC questionnaire. The wording changes, so match each answer to the question you actually see. Answers below follow what the app does.

| Topic | Draft answer | Why |
|---|---|---|
| Violence, blood, fear | No | The app has no game or media content. |
| Sexual content or nudity | No | Same. The publisher supplies no content. |
| Bad language | No (from the app) | The app shows no text of its own that contains it. Contacts can write anything in a message, see the next row. |
| Gambling, simulated gambling | No | No such feature. |
| Alcohol, tobacco, drugs | No | No such content. |
| Users can communicate with each other | Yes | Chat between contacts, to one contact or a group. |
| Users can share files or user-generated content | Yes | Send a file to a contact. Only people who have added each other can exchange. There is no public feed and no way to find strangers. |
| Content is moderated by the publisher | No | There is no publisher server, so the publisher cannot see or filter content. Say so plainly if the form has a free-text field. |
| Shares the user's location | No | The app does not read location. Peers see the device's network address, which is not a location feature. Mention it only if the form asks about network addresses. |
| Personal information collected or shared | No by the publisher | See the privacy policy. Data goes only to the chosen contact and, in encrypted form, to storage peers. |
| In-app purchases, ads | No | None. |
| Unrestricted internet access or web browsing | No | The app does not browse the web. It connects to other Miasma apps, a relay and GitHub for update checks. |

[Owner] Expect a rating that reflects "users can interact". That is accurate, so accept it.

## 4. Restricted capability: runFullTrust

The manifest declares `runFullTrust` (restricted capability, `rescap:Capability`). Partner Center asks you to justify it. Draft text:

> Miasma is a Windows desktop program written in Rust, packaged with the Desktop Bridge as a full-trust packaged app. It cannot run in the UWP sandbox for these reasons:
>
> 1. It starts its own background service, a second executable in the same package (`miasma.exe`), as a child process. The service holds the encryption keys, stores files and handles all network connections. It starts when the user opens the app and stops when the user closes it.
> 2. It opens UDP sockets for direct peer-to-peer connections (QUIC) and a local loopback channel between the window and the service.
> 3. It reads files and writes files at locations the user chooses in the standard Windows file dialog, including large files of many gigabytes that are streamed from and to disk.
>
> It does not install drivers or services, does not change system settings or the PATH, does not register file associations, and does not ask for administrator rights. The Store package contains only `miasma-desktop.exe`, `miasma.exe` and logo images.

The statements about what the package does not do come from `scripts/build-store-msix.ps1`, which copies only those two executables and the logos. The first statement comes from the Settings text "This app runs a background service ... It starts automatically and stops when you close the app" and from the package contents. [Owner] Check on a real PC that closing the window stops `miasma.exe`.

The manifest also uses `uap10:RuntimeBehavior="packagedClassicApp"` and `uap10:TrustLevel="mediumIL"` (a normal user-level process, not elevated).

## 5. Package identity and building the MSIX

Reserve the app name in Partner Center first. Then copy three values into the build:

| Partner Center value | Where to find it | Script parameter | Environment variable |
|---|---|---|---|
| Identity Name (Package/Identity/Name) | Apps and games, your app, Product management, Product identity | `-PackageIdentityName` | `MIASMA_STORE_IDENTITY_NAME` |
| Publisher (Package/Identity/Publisher, a `CN=...` string) | Same page | `-Publisher` | `MIASMA_STORE_PUBLISHER` |
| Publisher display name (Package/Properties/PublisherDisplayName) | Same page | `-PublisherDisplayName` | `MIASMA_STORE_PUBLISHER_DISPLAY_NAME` |

Menu names in Partner Center change over time, so look for the page that shows the three values. Paste the Publisher string exactly. A single wrong character makes the Store reject the package.

Build:

```powershell
.\scripts\build-release.ps1                      # writes dist\miasma-desktop.exe, miasma.exe, miasma-bridge.exe
.\scripts\build-store-msix.ps1 `
  -PackageIdentityName "<Identity Name>" `
  -Publisher "<CN=... exactly as shown>" `
  -PublisherDisplayName "<Publisher display name>"
```

- Input folder: `dist` by default (`-InputDir`). It must contain `miasma-desktop.exe` and `miasma.exe`, both 64-bit. The script checks this. `miasma-bridge.exe` is not packaged.
- Output: `dist\store\miasma-<version>-windows-x64.msix` and a `.sha256` file.
- Version: if you do not pass `-PackageVersion`, workspace version X.Y.Z becomes `1.X.(Y*100+Z).0`. Today's workspace version is 0.3.2, so the package version is `1.0.302.0`. The fourth number must be 0 for the Store.
- Signing: not needed for the upload. The Store signs accepted packages. For a local install test, pass `-CertThumbprint` of a test certificate whose subject equals `-Publisher`.
- Needs a current Windows SDK (`makeappx.exe`). The manifest depends on `Microsoft.VCLibs.140.00.UWPDesktop`, which the Store installs for the user.

Manifest facts: minimum Windows 10.0.19041.0, x64 only, resource languages `en-us` and `ja-jp`, logos `StoreLogo.png` (50 x 50), `Square44x44Logo.png` and `Square150x150Logo.png`. [Owner] The app also has Simplified Chinese. Add `<Resource Language="zh-cn" />` to `installer/msix/AppxManifest.template.xml` if you want to list that language. Partner Center may also ask for store logos in larger sizes than those three files. Check its current list.

## 6. Certification checklist

Run on a clean Windows 10 or 11 x64 PC (a plain one, with no developer tools).

1. Build the MSIX as above.
2. Local install test: build once with `-CertThumbprint`, install the signed package, start Miasma, set up the node on first run, add a test contact, send a small file.
3. Close the window. Check in Task Manager that `miasma.exe` has exited too.
4. Windows may ask whether to allow network access when the app first listens. Accept it and confirm the app still works.
5. Windows App Certification Kit (from the Windows SDK): run the Windows desktop app test on the `.msix`. In a command prompt: `appcert.exe reset`, then `appcert.exe test -appxpackagepath <file.msix> -reportoutputpath <report.xml>`. The Kit also has a graphical front end. Fix every failure and keep the report.
6. Uninstall and check what remains on disk. Compare with the privacy policy text about the data folder.
7. Upload the unsigned package for submission. Fill in: age rating, privacy policy URL, the justification above, pricing (free), listing text, screenshots, and any notes for certification.
8. In the notes for certification, say: "Peer-to-peer file sharing between users who have added each other. No server operated by the publisher stores any content. Beta software."

## 7. Known review risks and how the app answers them

| Risk | What the app does | What is missing |
|---|---|---|
| Peer-to-peer file sharing can be taken as a tool for sharing unlawful content | Content goes only between people who added each other as contacts. There is no search, no public list and no way to find strangers. The Store package leaves out the BitTorrent bridge program. Everything is encrypted, and the publisher has no server and cannot host content. | No report button that reaches the publisher, because there is no publisher server. The privacy policy points to the GitHub issues page. [Owner] Check the Store policy text on user-generated content and write the reviewer note accordingly. |
| The app updates itself from GitHub, outside the Store | Updates have three settings in Settings, Updates: Off, Tell me (default), Automatic. | The default is Tell me with a check at start, and the source has no code that turns this off when the app runs from an MSIX package. Store policies generally expect a Store app to be updated by the Store (check the current text), and the install folder of an MSIX package is read-only. This is the most likely cause of a failed review. It needs a code change before submission: ship the Store build with updates Off and hide the control. |
| The app has an Import tab whose text mentions BitTorrent (magnet links and torrent files) | The bridge program is not in the package, so Import cannot work there. The manifest registers no file or link associations. | The tab is part of the Technical mode tab list, and the source also opens it for a magnet or torrent hand-off. [Owner] Check on a real PC whether a reviewer can reach it in the packaged app. If so, a reviewer sees a feature that does not run. |
| Network access and a listening socket | The app listens on a UDP port chosen by Windows on all interfaces, and connects out to relays. The description and the justification say so. | Windows shows a network access prompt on first start. |
| Restricted capability runFullTrust | Justification text in section 4. | A reviewer may ask for details. |
| Data wipe looks like an anti-forensic tool | Settings, Emergency Wipe is described as erasing the app's own data on the device. It says what is not erased. | Keep the description neutral. Do not call it "destroy evidence". |
| Security claims | The listing says beta and not audited. | Do not add claims the app cannot support. |
| Encryption | File and message contents are encrypted. | If a form asks about encryption or export rules, answer that the app uses encryption and check the current rules for individuals. |
| Language mismatch | App languages: English, Japanese, Simplified Chinese. | Manifest lists only en-us and ja-jp. |
| Data after uninstall | The desktop settings text says the data folder is kept after uninstall. | MSIX can redirect or remove app data on uninstall. Not tested. The privacy policy has a bracket for it. |
