# Miasma Protocol v0.2.0-beta.1 - Windows Technical Beta Prerelease

**Release date:** 2026-03-22  
**Platform:** Windows 10/11 x64  
**Status:** Public technical beta prerelease

---

## Release Positioning

This release is a serious protocol beta, not a stable production release.

It is suitable for:

- technical beta users
- protocol and routing testers
- Windows installer and operations validation

It is not yet claiming:

- production-ready anonymity
- resistance to a strong global passive adversary
- mobile runtime readiness
- external security audit clearance

If you are testing hostile-network or highly sensitive use cases, wait for further hardening and an external review.

## What This Beta Adds

This beta is the first release where the anonymity and reachability stack is materially integrated end to end.

### Core protocol and routing

- real Ed25519 DHT record verification
- PoW-gated and hybrid peer admission
- trust tiers and address-class separation
- prefix diversity and eclipse-resistance controls
- routing, admission, and retrieval diagnostics

### Anonymous reachability and retrieval

- descriptor exchange and descriptor-backed routing state
- relay trust tiers based on claims, passive outcomes, probes, and forwarding evidence
- rendezvous descriptors with introduction points for NATed peers
- onion retrieval
- rendezvous retrieval
- onion plus rendezvous retrieval in `Required` mode
- coherent privacy-path hierarchy across `Direct`, `Opportunistic`, and `Required`
- active relay probing and forwarding-verification slice

### Security fixes before this beta

- zero-key onion pubkey fallback removed
- `R1 != R2` enforced as a hard anonymity invariant
- `Required` hop semantics tightened
- Windows secret files are now created with restricted ACLs from the start

### Hardening

- fixed-size onion packet padding (8 KiB) to prevent size-based correlation
- onion replay protection via bounded BLAKE3 fingerprint cache
- anti-gaming relay demotion (failure-dominant relays forced to Claimed tier)
- periodic background relay probing (one stale relay per ~5000 ticks)
- DhtCommand backpressure (fire-and-forget commands non-blocking, request-reply commands timeout-bounded)

## Download

| File | For | Description |
|---|---|---|
| `MiasmaSetup-0.2.0-x64.exe` | Everyone | Recommended installer - handles prerequisites and installs everything |
| `miasma-0.2.0-windows-x64.msi` | IT admins | MSI package for managed or silent deployment |
| `miasma-0.2.0-windows-x64.zip` | Advanced users | Portable binary bundle without installer |

## Installation

### Installer (Recommended)

1. Download **`MiasmaSetup-0.2.0-x64.exe`**.
2. Double-click to run the installer and follow the prompts.
3. Miasma installs to `C:\Program Files\Miasma Protocol`.
4. Launch **Miasma Desktop** from the Start Menu.
5. Click **Set Up Node** on the welcome screen.

The installer handles prerequisites automatically, including the Visual C++ runtime.

**SmartScreen warning:** This beta is not code-signed. If Windows shows a warning, click **"More info"** and then **"Run anyway"**.

**Silent install:** `MiasmaSetup-0.2.0-x64.exe /install /quiet`

### MSI Package

For managed deployment:

1. Download `miasma-0.2.0-windows-x64.msi`.
2. Deploy via Group Policy, SCCM, or run manually.
3. Silent install: `msiexec /i miasma-0.2.0-windows-x64.msi /qn`

The MSI does not install the Visual C++ runtime automatically. If needed: https://aka.ms/vs/17/release/vc_redist.x64.exe

### Portable Zip

The zip contains:

- `miasma.exe`
- `miasma-desktop.exe`
- `miasma-bridge.exe`
- `README.txt`
- `RELEASE-NOTES.md`

## CLI Quick Start

```text
miasma init                    # Create node identity
miasma daemon                  # Start background service (keep running)
miasma dissolve <file>         # Store a file - prints Content ID
miasma get <MID>               # Retrieve by Content ID
miasma get <MID> -o out.bin    # Retrieve to a specific file
miasma diagnostics             # Show node diagnostics
miasma diagnostics --json      # Machine-readable diagnostics
```

## Privacy and Reachability Model in This Beta

This beta now exposes five meaningful retrieval paths:

1. direct retrieval
2. relay-circuit retrieval
3. onion retrieval
4. rendezvous retrieval
5. onion plus rendezvous retrieval

In practice, this means NATed peers are no longer second-class for retrieval testing, and `Required` mode can use a content-blind path in the currently implemented model.

## Validation Snapshot

At release time, the codebase includes:

- 464 automated tests across workspace (268 core unit + 112 adversarial + 53 integration + 31 bridge)
- protocol security hotfixes and hardening with regression coverage
- Windows-local secret handling validation for restricted file creation

## Known Limitations

These are still real limitations in `v0.2.0-beta.1`:

- **No code signing yet.** Windows SmartScreen will warn.
- **No external security audit yet.**
- **Timing-based traffic analysis is still possible.** Fixed-size packet padding and replay protection are shipped, but constant-rate traffic shaping is not.
- **Bootstrap trust remains beta-stage.** Early-network trust assumptions are still evolving.
- **Real Internet scale is not fully validated.**
- **Mobile runtime and operational behavior are not part of this release.**
- **Automatic peer discovery remains limited** and multi-node setups still need explicit bootstrap configuration.

## Diagnostics and Troubleshooting

**Desktop app:** Go to the Status tab and click **Copy Diagnostics**.

**Command line:** Run `miasma diagnostics --json`.

Log files live in your data directory:

- `daemon.log.<date>`
- `desktop.log.<date>`
- `bridge.log.<date>`

Common issues:

- **SmartScreen blocks launch:** Click **"More info"** and then **"Run anyway"**.
- **`miasma` not found after install:** Close and reopen the terminal.
- **Daemon fails after upgrade:** Remove `daemon.port` from the data directory and retry.
- **Using the MSI without VC++ runtime:** Install `vc_redist.x64.exe`.

## Verifying Your Download

Check the SHA-256 checksums in the `.sha256` file:

```powershell
$expected = Get-Content .\MiasmaSetup-0.2.0-x64.exe.sha256
$actual = (Get-FileHash .\MiasmaSetup-0.2.0-x64.exe -Algorithm SHA256).Hash
if ($actual -eq ($expected -split " ")[0]) { "OK" } else { "MISMATCH" }
```

## Feedback

Report issues at the project repository and include diagnostics output when possible.
