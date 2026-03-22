# Miasma Windows Dual-Release Variant Guide

## Overview

Miasma ships two Windows release variants from one codebase and one binary:

| Variant | Name | Audience | Default mode |
|---------|------|----------|-------------|
| **Technical Beta** | Miasma Technical | Protocol testers, developers | Technical |
| **Easy Trial** | Miasma | Non-technical users, family trial | Easy |

Both variants share all backend code: storage, protocol, encryption, daemon IPC, anonymity stack, key management. The only differences are in presentation, defaults, and information density.

## What is shared (identical binary)

- Storage model (content-addressed, encrypted, erasure-coded)
- Protocol stack (libp2p, Kademlia DHT, relay, onion routing)
- Anonymity stack (BBS+ credentials, descriptors, onion+rendezvous)
- Daemon IPC (TCP loopback, ControlRequest/ControlResponse)
- Key management (master.key, Win32 DACL)
- Transport plane (WSS+TLS, ObfuscatedQuic+REALITY, SOCKS5 proxy)
- All 480 tests

## What differs (presentation only)

| Aspect | Technical | Easy |
|--------|-----------|------|
| Window title | Miasma v0.2.0 (Technical Beta) | Miasma v0.2.0 |
| Tab labels | Store / Retrieve | Save / Get Back |
| Welcome flow | Mentions encryption key, daemon | "We'll set everything up for you" |
| Status panel | Full: Connection, Storage, Transport grid, Diagnostics (card-grouped) | Simplified: Ready/Not Ready with status dot, items, storage, next-step hint |
| Stopped state | "Daemon not running" / "Start Daemon" | "Not running" / "Start" |
| Settings footer | "Miasma Technical Beta v0.2.0" | "Miasma v0.2.0" |
| Settings mode description | "Full diagnostics, transport details, protocol visibility" | "Simplified interface, less technical detail" |

## Visual design

Both variants share a dark-themed card-based design language:

- **Dark theme**: dark panel/card backgrounds with subtle borders
- **Card grouping**: all content sections (store input, retrieve input, status, settings) wrapped in rounded cards
- **Color system**: green (ready/success), yellow (warning), red (error/wipe), blue (accent/action), dim gray (secondary text)
- **Easy mode**: larger accent-colored action buttons, not-connected hints, next-step guidance text, status dot indicator
- **Technical mode**: same card system with ACCENT-colored section headings, full diagnostics grid, transport table

## Mode selection precedence

1. **CLI argument**: `--mode easy` or `--mode technical` (launcher scripts use this)
2. **`MIASMA_MODE` env var**: developer/testing override only
3. **Persisted preference**: saved in `desktop-prefs.toml` when user changes mode/locale in Settings
4. **Built-in default**: Easy

## How users launch each variant

### Installed (MSI)

Start Menu contains three shortcuts:
- **Miasma** — launches `miasma-desktop.exe --mode easy`
- **Miasma Technical** — launches `miasma-desktop.exe --mode technical`
- **Miasma CLI** — opens cmd.exe with Miasma on PATH

### Portable (ZIP)

ZIP contains two launcher scripts:
- **Miasma.cmd** — starts in Easy mode
- **Miasma Technical.cmd** — starts in Technical mode

Users can also run `miasma-desktop.exe` directly — it uses persisted preference or defaults to Easy.

## Persistence

Mode and locale are saved to `desktop-prefs.toml` in the data directory:

```toml
mode = "easy"
locale = "en"
```

This file:
- Survives restart
- Survives upgrade (data directory is preserved)
- Survives reinstall (data directory is not removed on uninstall)
- Falls back to defaults if missing or corrupt
- Accepts partial content (missing fields use defaults)

## Localization

Three languages ship:
- English (en)
- Japanese (ja) — 日本語
- Simplified Chinese (zh_cn) — 简体中文

Language is selectable in Settings and persists across restarts.

Diagnostics export stays English (support artifact, not user-facing).

## Build and packaging

```powershell
# Build all binaries (one binary serves both variants)
.\scripts\build-release.ps1

# Package for both variants
.\scripts\package-release.ps1 -Variant both

# Package for one variant only
.\scripts\package-release.ps1 -Variant technical
.\scripts\package-release.ps1 -Variant easy
```

Output:
- `miasma-0.2.0-windows-x64.zip` — Technical package (README leads with CLI/diagnostics)
- `miasma-0.2.0-windows-x64-easy.zip` — Easy package (README leads with "double-click and go")

Both ZIPs contain the same binaries plus variant-appropriate launcher scripts and README.

## Validation checklists

### Technical Beta RC

- [ ] Install via MSI
- [ ] "Miasma Technical" shortcut launches in Technical mode
- [ ] Window title shows "Miasma v0.2.0 (Technical Beta)"
- [ ] Set Up Node creates identity and starts daemon
- [ ] Status tab shows full Connection/Storage/Transport/Diagnostics
- [ ] Transport grid displays all transports with success/failure counts
- [ ] Copy Diagnostics produces complete support report
- [ ] Store content via text input and file picker
- [ ] Retrieve content by MID
- [ ] Daemon restart/recovery works (kill daemon, status poll triggers relaunch)
- [ ] Emergency Wipe works with translated confirmation dialog
- [ ] No console window visible during any operation
- [ ] Settings: can switch to Easy mode, change persists across restart
- [ ] Save Report exports diagnostics to file with native dialog
- [ ] magnet: link opens Import tab with confirmation flow
- [ ] .torrent file opens Import tab with confirmation flow
- [ ] Uninstall is clean (data directory preserved)

### Easy Trial Build

- [ ] Install via MSI or unzip portable
- [ ] "Miasma" shortcut or "Miasma.cmd" launches in Easy mode
- [ ] Window title shows "Miasma v0.2.0" (no "Technical Beta")
- [ ] Welcome screen says "Welcome" not "Welcome to Miasma"
- [ ] Setup button says "Set Up Node", progress says "Setting up..."
- [ ] No mention of "daemon" or "encryption key" in primary flow
- [ ] Save tab: "Save Content", "Save your content securely."
- [ ] Get Back tab: "Get Content Back", "Enter your Content ID to get your content back."
- [ ] Status shows Ready/Not Ready with green/red indicator
- [ ] Status does not show transport grid, peer ID, listening addresses
- [ ] A non-technical user can understand the current state
- [ ] Language selector works (EN/JA/ZH-CN), persists across restart
- [ ] Japanese text renders correctly (no mojibake)
- [ ] Chinese text renders correctly (no mojibake)
- [ ] Button widths accommodate translated text
- [ ] Settings: can switch to Technical mode, change persists
- [ ] Save Report button works in both Status and Settings panels
- [ ] magnet: link opens Import tab with simplified explanation
- [ ] .torrent file opens Import tab with simplified explanation
- [ ] No console window visible during any operation

## Font and rendering system

CJK rendering uses Windows system fonts loaded at startup:

- **Proportional**: Segoe UI → Yu Gothic → Microsoft YaHei → egui default
- **Monospace**: Consolas → Yu Gothic → Microsoft YaHei → egui default

All three fonts ship with Windows 10+ and are loaded from `C:\Windows\Fonts`. If a font file is missing, it is skipped and the fallback chain continues. On non-Windows platforms, egui's built-in fonts handle Latin text but CJK will show as tofu.

Validated rendering: English, Japanese, and Simplified Chinese all render correctly in the running Windows app — no tofu boxes, no mojibake, in both Easy and Technical modes.

## Shell integration

### magnet: protocol handler

The MSI installer registers Miasma as an available handler for `magnet:` URIs via Windows Registered Applications. Windows will offer Miasma in the "Default apps" chooser — it does not forcibly take over from existing torrent clients.

When launched with a magnet URI:
1. The app opens to an **Import** tab
2. A confirmation screen shows the magnet link and explains what will happen
3. The user clicks Import to start (or Cancel to dismiss)
4. The bridge subprocess downloads and dissolves the content into Miasma
5. On completion, the resulting MIDs are shown for safekeeping

### .torrent file association

The installer registers Miasma in the **Open with** list for `.torrent` files using `OpenWithProgids`. This is intentionally non-aggressive — existing torrent client associations are not overridden. Users see Miasma as one option when right-clicking a `.torrent` file.

The import flow is identical to magnet links: confirmation → bridge download → dissolve → MIDs.

### Portable mode

Shell integration requires the MSI installer (registry entries). Portable ZIP users can still open magnets and torrents by dragging files onto `miasma-desktop.exe` or passing arguments manually.

## Diagnostics and support

### Copy diagnostics (Technical mode)

The Status panel's "Copy Diagnostics" button copies a structured text report to the clipboard containing: version, OS, install type, uptime, daemon state, connection info, storage stats, transport readiness, and last error.

### Save report (both modes)

The "Save Report" button (available in both Status and Settings panels) opens a native file-save dialog to write the diagnostics report to a `.txt` file. This is the primary support path for Easy-mode users who may not use the clipboard.

### Recovery messaging

When the daemon cannot start or becomes unreachable, error messages include:
- What failed
- What the app already tried (auto-relaunch attempts)
- What to do next (clear actionable steps)

Messages avoid protocol jargon in Easy mode.

### Startup and retry policy

- Startup timeout: 30 seconds (accommodates slower machines and antivirus scanning)
- Auto-relaunch cap: 2 attempts before giving up
- Manual "Start" button resets the retry counter
- Stale port-file detection prevents confusion from zombie daemon state

## Honest limitations

- Mode is runtime, not compile-time: both variants are the same binary with different launch arguments
- The `MIASMA_MODE` env var still works as a developer override (this is intentional, not a gap)
- CJK font rendering loads Windows system fonts (Yu Gothic, Microsoft YaHei) — these ship with Windows 10+ but may not be present on older Windows or non-Windows platforms
- Installer does not yet prompt the user to choose a variant during install — both shortcuts are created
- No automatic locale detection from OS settings — defaults to English
- Shell integration (magnet/torrent) requires MSI install — portable ZIP users must pass arguments manually
- Import flow requires `miasma-bridge.exe` to be installed alongside the desktop binary
- Bridge subprocess import is blocking — the UI shows progress but cannot cancel a running download
- The binary is not code-signed; Windows SmartScreen will warn on first launch until a certificate is applied
