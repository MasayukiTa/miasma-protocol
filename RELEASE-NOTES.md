# Miasma v0.3.2-beta.13

This beta adds calls between contacts, and lets a group member share recent messages with one other member.

## What's new

- In a group's information view, each other member now has a "Share recent messages" action. Choosing it offers that member the most recent messages this device still holds, so someone who was added after a conversation started can catch up. Sharing is opt-in: nothing is shared unless you choose this action for a member, and it does not need anyone's confirmation to send. Only the most recent messages are offered, and only their text; files are not shared this way. A shared message keeps its original author, and the view shows which member passed it on. If there is nothing recent to pass on, you are told so and nothing is sent. Sharing reaches a member who is online now; carrying an offer to a member who is offline is not part of this release, and hand-over is best-effort over what your device still holds (messages already removed by the retention limit are not offered).
- Contacts can make voice calls. The camera and screen sharing both work on Windows and macOS. Calls ring only for contacts. Calls are on by default; to turn them off, set `enabled = false` under `[call]` in `config.toml`.
- During a call you can turn your camera on or off and start or stop sharing your screen with buttons in the call view. The camera works on Windows and macOS; on macOS the system asks for camera access the first time, and the call continues without video if it is refused. Screen sharing works on Windows and macOS. On other platforms a call stays voice-only with test devices.
- You can choose which microphone and speaker the call uses from the audio-device menu in the call view.
- Calls are end-to-end protected, with keys exchanged inside the chat channel. During a call, both people can read the 20-digit safety code shown on their screens to each other. If the codes differ, an attacker may be interfering; end the call and check with your contact.
- An indicator stays visible while the microphone, camera or screen is in use.
- Chat can hold messages for an offline contact. When this is on, your node keeps a sealed copy of a message for a trusted contact who is offline, and when a direct send does not get through it leaves a copy with your other trusted contacts; the message is delivered once the recipient comes back online, and is applied only once even if the sender also resends in the meantime. The people who hold a copy only ever see the sealed message, never its contents, and nothing is written to disk. This is off by default; turn it on with `custody_enabled = true` under `[chat]` in `config.toml`, or with "Hold messages for offline contacts" on the Privacy and storage settings page. You can also set how many trusted contacts receive a copy with `custody_copies` (1 to 8).

## Notes

- **Calls are beta and have not been independently audited.** Do not use them for material whose exposure would be serious.
- Voice uses the Opus codec on Windows and macOS. Other platforms use test devices only. Calls are not yet available through the mobile apps.
- Video is simple in this release, at 160x120.

## How to get it

### Windows

See the release for the available Windows files.

### macOS

See the release for the available macOS files.

---

# Miasma v0.3.2-beta.12

This beta makes the post-quantum key exchange required by default and adds easier ways to add contacts. It also keeps file transfers smooth and ships a Windows installer.

## What's new

- Private conversations now require a post-quantum hybrid key exchange (X25519 + ML-KEM-768) by default. This also covers group chats: a group message body is held until the hybrid exchange with each member has completed. If the other side does not support it, messages are no longer sent the old way: Miasma shows that the two apps are not compatible and refuses to send or connect, rather than silently falling back to classical encryption. Ask the other person to update to the latest version. If you had left this unset, or on the earlier `prefer` default, beta.12 moves you to `require` once, on its first start. `off` and `prefer` are no longer offered in the normal settings; they take effect only when written into the settings file by hand or passed to an advanced option, and the status then warns that a classical fallback is allowed.
- Add a contact from a picture of its QR code.
- Add a contact by scanning its QR code with your camera.
- When a transfer starts, the receiving side opens the Transfers view so you can watch its progress.
- Your computer stays awake while a transfer or message delivery is in progress.
- File sending now paces itself so it does not slow down chat. By default there is no speed limit.
- Japanese on-screen wording was corrected and completed in several places.
- The macOS version shown in the app now includes the beta number.
- Android no longer includes app data in cloud backup or a device-to-device transfer, so your messages and files are not copied off the device by those paths.
- Fixed: the "Advanced encryption" setting is now saved even when no settings file exists yet. A settings file that cannot be read is left as is, not overwritten.
- In the browser version, trying to open a share made by a newer version now shows a clear message instead of a generic error.
- The chat list on desktop now groups conversations under separate "Groups" and "People" headings.
- A received private share now shows who sent it, marked as verified, unverified (claimed by the sender), or unknown for older records.
- Before setup, the Chat, Contacts and Files tabs now show the same single instruction, instead of pointing to a button that did not exist.
- The Receive screen now offers a way to receive by code, and Home suggests adding a contact while you have none.
- A send that fails after you switch conversations no longer lands in the composer of another chat.
- In group chats, a message that is still waiting now shows how many members have received it (for example "Waiting 0/2").
- The window title no longer shows the build hash or the word "Technical"; the build hash is in Settings, under About and Update.
- The message list in one-to-one and group chats now fills the window down to the message box.
- In group information, Leave and Delete history stay in view below the scrolling member list, and member status lines are no longer cut off.
- Group chats now match one-to-one chats more closely: a waiting message gets the same explanation, the message box and send button have matching names, and the header uses the same "..." menu.
- Chat messages are grouped under day headings (Today, Yesterday, or the date), so each message shows only its time.
- A search box appears in the conversation list and in the New conversation dialog once you have 8 or more entries.
- Disabled buttons and fields stay clearly visible in both light and dark themes, and scroll bars are always shown.
- Cancel, Done and the invite dialog actions now look like buttons, and buttons come in three consistent sizes.
- The Files screens are easier to follow: Transfers and Sent files are switched by a marked strip, and in Technical mode Send with Sent and Receive with Restore are grouped.
- In Easy mode the screens no longer show speed unit pickers, a relay service name or an unlabeled network count, and the restore page explains where a content ID comes from.
- Diagnostics copy and save now live on the Status screen, with a link from Settings, under About.
- Home shows "ready" only once, and the relay shows "connecting" for up to a minute before it is reported as a problem.
- The wording and notation of the Japanese, English and Simplified Chinese screens were unified, with one term for each concept (content ID, share ID, receive code, one-time code, verification code).

## Notes

- **The other person needs a post-quantum-capable app to receive your messages.** Because the hybrid exchange is now required, a contact on an app that does not support it cannot receive from you, and the conversation fails on your device with a stated reason. Ask the contact to update to the latest version. Group chats work the same way: a group message body is also held behind the hybrid exchange with each member.
- **Advanced encryption has not been reviewed by an outside security expert yet.** You can switch it in Settings, "Advanced encryption".
- **Windows may warn you.** The installer is not code-signed yet, so Windows SmartScreen can show "Windows protected your PC". Choose **More info**, then **Run anyway**.
- **Check your download.** `SHA256SUMS-windows.txt` in the same release lists the SHA-256 of the installer. In PowerShell, run `Get-FileHash .\Miasma-Setup-0.3.2-beta.12-x64.exe -Algorithm SHA256` and confirm the hash matches the line for this file.
- Installing a newer installer over an older one upgrades Miasma and keeps your data. Uninstalling (Settings, Apps) does not delete your data.
- Silent install: `Miasma-Setup-0.3.2-beta.12-x64.exe /quiet`. Silent uninstall: `Miasma-Setup-0.3.2-beta.12-x64.exe /uninstall /quiet`.

## How to get it

### Windows

Download **`Miasma-Setup-0.3.2-beta.12-x64.exe`** from the release and run it. You do not need Rust, Visual Studio or any other tool. The installer also installs the Microsoft Visual C++ runtime if your computer lacks it.

### macOS

The macOS file and its `SHA256SUMS.txt` are listed separately in the release.

---

Past release notes are available on the [GitHub Releases page](https://github.com/MasayukiTa/miasma-protocol/releases).
