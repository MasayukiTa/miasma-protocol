# Store submission documents

[日本語](README.ja.md) | **English**

These documents prepare a person to submit Miasma to the Microsoft Store (MSIX, individual developer account, registered later by the owner) and to Google Play. They are drafts for the owner to review. Every fact comes from the code and docs in this repository. Nothing here was built or run: no builds were allowed on the machine used to write them.

| Document | Content |
|---|---|
| [privacy-policy.md](privacy-policy.md) | The privacy policy, with brackets for what the owner must fill in |
| [microsoft-store.md](microsoft-store.md) | Listing text, screenshots, age rating, runFullTrust text, package identity, certification checklist, review risks |
| [google-play.md](google-play.md) | Listing text, Data safety, permissions, target API and 16 KiB, signing, content rating, blockers |

Each document has a Japanese version with the same name and `.ja` before `.md`.

## Terms

The documents use the Easy-mode words of the desktop app: Home, Send a file, Receive a file, Save securely, Contacts, Chat, Files, Settings, "invitation code" (the field for a Share ID), "contact code" and "check code". The brief for this kit used "Keep safe" for the third action. The screen says "Save securely" (Japanese: 安全に保存する), so the documents use that.

## Status

| Item | Status | Open question |
|---|---|---|
| Privacy policy text, English and Japanese | Done as a draft | Owner fills the brackets (publisher name, effective date, minimum age) and reviews it. |
| Privacy policy: Store package data location and uninstall behaviour | Needs real device | Does an MSIX install keep or remove the data folder at uninstall? |
| Microsoft Store listing text | Done as a draft | Owner picks the sub-category and checks the search term limits. |
| Microsoft Store screenshots | Needs real device | No existing image is 1366 pixels wide. The tour commands are in the document and were not run. |
| Age rating answers | Done as a draft | Owner matches them to the questions shown. |
| runFullTrust text | Done as a draft | Owner checks that closing the window stops `miasma.exe`. |
| Package identity and build steps | Needs owner | Owner reserves the app and copies Identity Name, Publisher and display name. |
| WACK run and install test | Needs real device | A clean Windows PC and a test certificate. |
| Store build must not update itself | Needs owner | The source has no code that turns off the GitHub update check inside an MSIX package. A code change is needed. |
| Manifest languages | Needs owner | The app has Simplified Chinese, the manifest lists en-us and ja-jp. |
| Google Play listing text | Done as a draft | Owner checks it against the app on a device. |
| Google Play Data safety and content rating | Done as a draft | Owner confirms the reading of collect and share against Google's current help. |
| Google Play signing | Needs owner | Owner creates and keeps the upload key. This kit holds no key. |
| Google Play release build | Needs real device | Never checked here. CI does not build Android. Run the 16 KiB checks and test on a device. |
| Google Play graphics and screenshots | Needs real device | None exist. |
| Android blockers (section 8 of the Play document) | Needs owner | Notifications permission, mixed-language screens, vocabulary, application ID. |

## Open questions for the owner

1. Update check in the Store build. The desktop app checks GitHub for updates at start by default and can install them. Should the Store build ship with updates off and the control hidden? This needs a code change and is the most likely reason for a failed review. The privacy policy has a bracket that depends on the answer.
2. Hosted storage. A default desktop node stores encrypted pieces for other users, up to 1024 MiB, and there is no Settings screen for it. Should the Store build start with this off?
3. Which publisher name, effective date and minimum age go into the policy and the questionnaires?
4. Should the package declare Simplified Chinese (`zh-cn`) as well?
5. Does the Import tab (it mentions BitTorrent) appear in the packaged app, and is that acceptable?
6. For Android: is `dev.miasma` the application ID you want, do you want the notification permission added, and do you want the Android words (Content ID, challenge code) aligned with the desktop words?
7. The statement "no analytics, no crash reports" comes from a search of this repository's source. Please confirm it against the full dependency list.

## Not in these documents

No keys, passwords, accounts, certificates or personal contact details. The contact for users is the GitHub issues page of the project.
