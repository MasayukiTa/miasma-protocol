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
