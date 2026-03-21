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
| Status panel | Full: Connection, Storage, Transport grid, Diagnostics | Simplified: Ready/Not Ready, items, storage |
| Stopped state | "Daemon not running" / "Start Daemon" | "Not running" / "Start" |
| Settings footer | "Miasma Technical Beta v0.2.0" | "Miasma v0.2.0" |
| Settings mode description | "Full diagnostics, transport details, protocol visibility" | "Simplified interface, less technical detail" |

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
- [ ] No console window visible during any operation

## Honest limitations

- Mode is runtime, not compile-time: both variants are the same binary with different launch arguments
- The `MIASMA_MODE` env var still works as a developer override (this is intentional, not a gap)
- CJK font rendering depends on egui's default_fonts feature — tested on Windows but glyph coverage depends on system fonts
- Installer does not yet prompt the user to choose a variant during install — both shortcuts are created
- No automatic locale detection from OS settings — defaults to English
