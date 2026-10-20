# Miasma Privacy Policy

[日本語](privacy-policy.ja.md) | **English**

> **Draft for the owner to review.** This text describes what the Miasma source code does today. It is not legal advice and has not been reviewed by a lawyer. Items in [square brackets] must be filled in or confirmed by the owner before the policy is published. Do not publish it as it stands.

- Effective date: [YYYY-MM-DD]
- Applies to: the Miasma desktop app for Windows (including the Microsoft Store package) and the Miasma app for Android, once published
- Publisher: [publisher name as registered with the store]
- Contact: [GitHub issues](https://github.com/MasayukiTa/miasma-protocol/issues) of the project

## In short

- Miasma has no account, no advertising and no analytics. The publisher does not run a server that stores your files, messages or contacts.
- Your keys, contacts, message history and saved files stay on your own device.
- When you send a file or a message, it goes to the person you chose, encrypted. Connecting two apps can involve a relay and a discovery service run by a third party, which see connection details but not the content.
- Miasma is beta software and has not been checked by an outside security auditor. Do not use it for material whose exposure would be serious.

## 1. What stays on your device

| Data | Where and how |
|---|---|
| Node key (the key that identifies your app and encrypts what it stores) | Created on first start. On Windows it lives in the app's data folder. On Android it lives in the app's private storage, and a recovery copy is wrapped by a key held in the Android Keystore. |
| Contacts (names you gave, contact codes, verification codes) | Desktop app only. Stored in the data folder. |
| Message history | Desktop app only. Saved on disk in encrypted form by default. A setting keeps it in memory only. The default keeps messages until you delete them. |
| Files you save with Save securely | Stored on your device in encrypted form. |
| Files you receive | Written to the receive folder you can open from the app. These are ordinary files. |
| Transfer list, settings and the list of shares | Stored in the data folder. |
| Log files | None by default. Diagnostic logging is off unless you turn it on. When on, log files in the data folder show that Miasma was used and when. |

On Windows the data folder is `%LOCALAPPDATA%\miasma\data` for a normal install. [Owner: confirm where the Store package keeps it. Apps packaged as MSIX can have their file writes redirected into a package-private folder, which Windows removes when the app is uninstalled. This was not tested.]

The app does not read your address book, your location or your photos on its own. It reads only files you pick. On Android, the camera is used only when you press the scan button to read a QR code.

## 2. What leaves your device

### 2.1 To the people you choose

When you send a file or a message, the content is encrypted and sent to your contact's app. The publisher never receives it. The other person's app, and anyone who handles the connection on the way, can see that a connection took place and your device's network address.

### 2.2 Encrypted pieces for storage

Save securely and sharing by Share ID split a file into encrypted pieces. The app may place pieces on other Miasma nodes, which act as storage peers. These peers cannot read the content. They can see the size and timing of what they hold and the network address of the app that sent it.

Your own device can also hold encrypted pieces for others. On the desktop app this is on by default, with a limit of 1024 MiB. It is controlled in the node settings file, not on a Settings screen. Setting the limit to 0 refuses all pieces. [Owner: decide whether the Store build should start with this off, and update this paragraph to match.]

### 2.3 Connection setup: relay and discovery services

The desktop app connects two apps directly when it can. To find the other app and to carry the connection when a direct path is not possible, it uses the public relay and discovery services of the iroh project (run by Number 0, n0.computer). This is the default connection setting. While Miasma runs, these services learn:

- your app's endpoint ID (a public key; it is also the publisher key inside any Share ID you create),
- the relay your app uses,
- your device's IP addresses.

Anyone who holds one of your Share IDs can look your app up the same way. The relay sees connection details and encrypted data only. It cannot read file content.

The hosts the code contacts for this are `*.relay.n0.iroh.link` (the relays `use1-1`, `usw1-1`, `euc1-1` and `aps1-1`) and `dns.iroh.link`. They come from version 1.3.0 of the iroh library that Miasma uses and can change when the library is updated.

You can change this in Settings under Network (Connection):

- Public relay: the default described above.
- My own relay: only the relay servers you list carry traffic. The public discovery service is still used unless `iroh_discovery` is set to false in the node settings file (this is not on a Settings screen).
- Direct only: the relay path is switched off. Receiving by Share ID alone then does not work.

On the Android app this relay and discovery service is switched off in the code. The Android app starts from the peers you enter in its settings and has no default peer. It then connects to the other Miasma nodes it needs to reach.

### 2.4 Your local network

On the desktop app, local network discovery is on by default. The app announces its endpoint ID and its local network addresses so that two computers on the same network can find each other. Everyone on that network can see this announcement. In Settings under Network, Same-network discovery can be switched Off.

### 2.5 Update check (desktop app)

By default the desktop app asks GitHub once after it starts whether a newer release exists (`api.github.com`, the project's releases). If you agree, it downloads the update from the project's GitHub release files. GitHub sees your IP address and the time of the request, under GitHub's own privacy policy. In Settings under Updates you can choose Off (no connection to GitHub is made), Tell me (the default) or Automatic.

[Owner: if the Microsoft Store package is shipped with update checks switched off, because the Store handles updates, replace this section with: "The Microsoft Store version does not check for updates itself. Updates are delivered by the Microsoft Store." As of this draft the source contains no code that switches the update check off for a packaged install.]

### 2.6 What Miasma does not send

Miasma does not contain advertising or analytics code. It does not send crash reports, usage statistics or device identifiers to the publisher or to any third party for those purposes. [Owner: this statement is based on a search of the project's own source code. Confirm it against the full dependency list before publishing.]

## 3. Third parties

| Party | What it receives | Why |
|---|---|---|
| Other Miasma users you exchange with | Content you send them; your IP address and endpoint ID | Delivering files and messages |
| Storage peers (other Miasma nodes) | Encrypted pieces; your IP address | Keeping pieces of files you save or share |
| Number 0 (iroh relay and discovery services) | Endpoint ID, relay, IP addresses; encrypted traffic passes through relays | Connecting two apps |
| GitHub | IP address, time of the update check | Checking for and downloading updates |
| Microsoft or Google | Whatever the store collects when you install or update from it | Distribution; see their policies |

## 4. Keeping and deleting your data

The publisher holds none of your data, so there is nothing for the publisher to delete. You can delete the data yourself:

- Files, Clear finished: removes finished transfers from the list. It does not delete files you received or sent.
- Chat: delete a conversation's history on the device.
- Contacts: remove a contact.
- Sent files: revoke a share, so the recipient can no longer get it.
- Settings, Emergency Wipe (Erase All Data): erases everything Miasma stores on the device, including the keys that open it. This cannot be undone. It does not erase copies you already sent to others or files you saved elsewhere, such as the receive folder.
- Uninstalling: the desktop installer keeps the data folder when you uninstall. Delete the folder yourself, or use Emergency Wipe first. [Owner: confirm the behaviour of the Store package.] On Android, uninstalling removes the app's private storage, and the app does not allow system backups.

Encrypted pieces already placed on other devices are held by their owners. Nobody, including the publisher, can remove them for you. Without the keys they cannot be read.

## 5. Security

Content is encrypted before it leaves your device. Miasma is beta software and has not been externally audited. The known limits are listed in [SECURITY.md](../../SECURITY.md). Verify each contact with the verification code, because that check shows you are talking to the person you meant.

## 6. Children

Miasma is not directed at children. [Owner: state the minimum age that applies to you, for example 13, and match it to the answers in the store questionnaires.] The publisher holds no personal data about anyone, including children.

## 7. Changes to this policy

When the app's behaviour changes, this policy will be updated and the effective date changed. The history is public in the project's repository.

## 8. Contact

Questions and requests: open an issue at https://github.com/MasayukiTa/miasma-protocol/issues. Do not post private data or keys in an issue. To report a security problem, see [SECURITY.md](../../SECURITY.md).
