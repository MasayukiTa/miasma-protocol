# Validation Report — Miasma v0.3.1-beta.1

**Date**: 2026-03-22
**Platform**: Windows 11 Enterprise 10.0.22631 (x64)
**Machine**: Dev PC (primary validation)

---

## 1. Automated Validation

### Workspace tests
```
cargo test --workspace
```
**Result**: 480 passed, 0 failed, 1 ignored (quarantined Kademlia roundtrip)
- 268 core unit tests
- 112 adversarial tests
- 53 integration tests (1 ignored)
- 31 bridge tests
- 16 desktop tests (locale, serde, mode precedence, prefs persistence)

### Windows smoke tests
```
powershell -ExecutionPolicy Bypass -File scripts/smoke-windows.ps1
```
**Result**: 13 passed, 0 failed
1. Node initialization (config.toml + master.key created)
2. Daemon start (daemon.port written)
3. IPC status (peer ID returned)
4. Diagnostics (text + JSON output)
5. Dissolve + get round-trip (content integrity verified)
6. Wipe (master.key removed)
7. Restart recovery (re-init + daemon restart + dissolve/get after wipe)
8. Stale port-file recovery
9. Bridge safety defaults
10. Daemon log file creation

---

## 2. Installer / Package Validation

### Fresh install (v0.3.1 MSI)
- **Result**: PASS
- Binaries installed to `C:\Program Files\Miasma Protocol\`
- 3 Start Menu shortcuts created: Miasma, Miasma Technical, Miasma CLI
- Shell integration registry entries created:
  - `HKLM\Software\Classes\Miasma.Magnet` (magnet: protocol handler)
  - `HKLM\Software\Classes\.torrent\OpenWithProgids\Miasma.TorrentFile`
  - `HKLM\Software\RegisteredApplications\Miasma`

### Upgrade (v0.1.0 → v0.3.1 MSI)
- **Result**: PASS
- Installed v0.1.0 MSI silently
- Upgraded to v0.3.1 MSI silently
- Binaries replaced correctly during major upgrade
- Start Menu shortcuts preserved (3 shortcuts still present)
- Shell integration registry entries added by v0.3.1 (not in v0.1.0)
- No broken shortcuts or PATH state

### Uninstall (v0.3.1 MSI)
- **Result**: PASS
- `miasma-desktop.exe` removed
- `miasma.exe` removed
- `miasma-bridge.exe` removed
- Start Menu shortcuts removed (empty folder remains, cleared by Explorer)
- `Miasma.Magnet` registry key removed
- `RegisteredApplications\Miasma` removed
- Data directory (`%LOCALAPPDATA%\miasma`) NOT touched (preserved as designed)

### Portable ZIP
- **Result**: PASS (artifacts built)
- `miasma-0.3.1-windows-x64.zip` — Technical variant
- `miasma-0.3.1-windows-x64-easy.zip` — Easy variant
- Both include: 3 binaries, 2 launcher scripts, README.txt, RELEASE-NOTES.md

---

## 3. Desktop GUI Validation (Dev Machine)

### Easy mode
- CJK fonts load correctly (EN, JA, ZH-CN all render without tofu/mojibake)
- Health-state indicators: checkmarks for App/Backend/Network
- Not-connected hints shown when daemon is not running
- Save Report button works (native file dialog, writes diagnostics .txt)
- Mode and locale persist across restart

### Technical mode
- Full Connection/Storage/Transport/Diagnostics card-based panels
- Copy Diagnostics copies structured report to clipboard
- Transport grid shows all transports with success/failure counts
- ACCENT-colored section headings

### Import flow
- LaunchIntent parsing accepts magnet: URIs and .torrent file paths
- Import tab shows confirmation screen with content description
- Malformed magnet URI (missing xt=) shows validation warning
- Missing .torrent file shows validation warning
- Bridge subprocess spawned with CREATE_NO_WINDOW
- MIDs parsed from bridge stdout on success
- Empty output logged with warning

### Shell integration
- Registry entries verified after install (see Section 2)
- magnet: URI → LaunchIntent::Magnet → Import tab (code path verified)
- .torrent file → LaunchIntent::TorrentFile → Import tab (code path verified)
- **Not validated**: Real browser magnet: click or Explorer "Open with" (requires second device)

---

## 4. Recovery and Lifecycle

### Daemon lifecycle
- Auto-launch on startup: PASS
- Stale port-file detection: PASS (smoke test 8)
- Auto-reconnect with retry cap (MAX_AUTO_LAUNCHES=2): implemented
- Manual Start resets retry counter: implemented
- 30s startup timeout: configured

### Recovery messaging
- Missing bridge: "Cannot find miasma-bridge. Ensure it is installed alongside the desktop app."
- Daemon unreachable: "Not connected. Click the Start button above to restart."
- Spawn failure: actionable guidance about antivirus/SmartScreen
- Startup timeout: "The backend started but is taking too long to respond."

---

## 5. Documentation

### Updated
- `RELEASE-NOTES.md` — v0.3.1 with desktop GUI, shell integration, packaging sections; test count 480; release judgment
- `docs/variant-guide.md` — Shell integration, diagnostics/support, startup/retry policy, updated checklists
- `docs/TROUBLESHOOTING.md` — 9 sections (added SmartScreen), matches app wording
- `installer/README-installed.txt` — Added launch modes, SmartScreen, Save Report instructions

---

## 6. Remaining Limitations

### Not validated on this device
- Real browser magnet: click (needs browser + network)
- Real Explorer .torrent "Open with" (needs .torrent file + installed MSI)
- Bridge subprocess import with real torrent content (needs network + legal torrent)
- Import cancellation (bridge subprocess is blocking)

### Requires second device
- Fresh install on non-dev machine
- Non-English locale rendering on non-dev machine
- App icon appearance in Start Menu/taskbar/Explorer on clean Windows
- Cross-device save/retrieve
- Same-network peer discovery retry with the beta.2 mDNS/bootstrap fix

### Not available yet
- Code signing (SmartScreen will warn)
- External security audit
- Mobile runtime

---

## 7. Release Artifacts

| Artifact | Size | SHA-256 |
|---|---|---|
| `MiasmaSetup-0.3.1-x64.exe` | see release asset | see `.sha256` |
| `miasma-0.3.1-windows-x64.msi` | see release asset | see `.sha256` |
| `miasma-0.3.1-windows-x64.zip` | see release asset | see `.sha256` |
| `miasma-0.3.1-windows-x64-easy.zip` | see release asset | see `.sha256` |

---

## 8. Recommendation

**Acceptable for current beta continuation on dev machine. Ready for Stage 1 retry on a second Windows device.**

The 0.3.1 build passes all automated tests, all smoke scenarios, and installer lifecycle (install/upgrade/uninstall). Shell integration registry entries are confirmed working. Desktop GUI functions correctly in both modes with all 3 locales.

Stage 1 on a second Windows device already exposed a real same-network discovery gap. `v0.3.1-beta.1` addresses that gap with:

- mDNS-based same-network peer discovery
- CLI support for `network.bootstrap_peers`
- updated troubleshooting guidance for LAN discovery and manual bootstrap fallback

**Next step**: Retry `docs/tasks/windows-staged-cross-device-validation.md` Stage 1 using the `MiasmaSetup-0.3.1-x64.exe` artifact on the second Windows device, then stop and report before proceeding to Stage 2.
