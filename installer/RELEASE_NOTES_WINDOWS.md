# Windows installer: release notes snippet and maintainer notes

This file is a template. Copy the "Release notes snippet" into the GitHub Release
text when you publish a release. The workflow `.github/workflows/release-windows.yml`
attaches the installer files to the Release; it never edits the release text.

## Release notes snippet

Replace `<version>` with the release version without the leading `v`
(for example `0.3.2-beta.12`).

```markdown
### Windows

Download **`Miasma-Setup-<version>-x64.exe`** below and run it. You do not need
Rust, Visual Studio or any other tool. The installer puts Miasma Desktop, the
background service and the command-line tool under `C:\Program Files\Miasma Protocol`
and installs the Microsoft Visual C++ runtime if your computer lacks it.

- **Windows may warn you.** This installer is not code-signed yet, so Windows
  SmartScreen can show "Windows protected your PC". Choose **More info**, then
  **Run anyway**.
- **Check your download.** `SHA256SUMS-windows.txt` (same release) lists the
  SHA-256 of the installer. In PowerShell:
  `Get-FileHash .\Miasma-Setup-<version>-x64.exe -Algorithm SHA256`
  The hash must match the line for this file name.
- Installing a newer installer over an older one upgrades Miasma and keeps your
  data. Uninstalling (Settings, Apps) does not delete your data.
- Silent install: `Miasma-Setup-<version>-x64.exe /quiet`. Silent uninstall:
  `Miasma-Setup-<version>-x64.exe /uninstall /quiet`.

The macOS file and its `SHA256SUMS.txt` are unchanged and listed separately.
```

## Files attached to a release

| File | What it is |
|---|---|
| `Miasma-Setup-<version>-x64.exe` | The installer to download (WiX bootstrapper: installs the Visual C++ runtime if needed, then the MSI). |
| `SHA256SUMS-windows.txt` | `sha256sum`-format line for the installer. Separate from the macOS `SHA256SUMS.txt`, which is never touched. |

The MSI (`miasma-<version>-windows-x64.msi`) is built too and kept as a workflow
artifact (`miasma-windows-msi-<version>`) for managed deployments. It is not
attached to the release.

## Version numbers

Windows Installer wants a numeric version and, when it decides whether one
package replaces another, **looks only at the first three fields**. A fourth
field is ignored, and so is any text such as `-beta.12`. So the release version
is mapped to numbers by `scripts/windows-version.ps1`:

| Release | MSI ProductVersion (compared) | Bundle version (shown in Settings, Apps) |
|---|---|---|
| `0.3.2-beta.11` | `0.3.2011` | `0.3.2.11` |
| `0.3.2-beta.12` | `0.3.2012` | `0.3.2.12` |
| `0.3.2-beta.13` | `0.3.2013` | `0.3.2.13` |
| `0.3.2-rc.1` | `0.3.2901` | `0.3.2.901` |
| `0.3.2` (final) | `0.3.2999` | `0.3.2.999` |
| `0.3.3-beta.1` | `0.3.3001` | `0.3.3.1` |

Rule: MSI version = `major.minor.(patch * 1000 + rank)`, where rank is `N` for
`beta.N`, `900 + N` for `rc.N` and `999` for a final release. Beta.N, beta.N+1,
rc, final, and the next series then sort correctly using only three fields, and
a final release replaces any beta of the same series. Limits: major and minor
at most 255, patch at most 65, beta at most 899, rc at most 98 (a WiX build with
a larger value warns that the MSI rules are broken). Other labels, such as
`alpha.N`, are rejected by the script until the table is extended.

`UpgradeCode` values in `miasma.wxs` and `bundle.wxs` must never change.

## Code signing (not enabled yet)

No code-signing certificate exists today, so the installer is unsigned and the
build does not fail without one. To turn signing on later, add two repository
secrets (Settings, Secrets and variables, Actions):

- `WINDOWS_SIGN_CERT_PFX_BASE64`: the Authenticode certificate as a base64-encoded `.pfx`.
- `WINDOWS_SIGN_CERT_PASSWORD`: the password of that `.pfx`.

The step "Import code-signing certificate (optional)" in the workflow then runs
by itself (it is guarded by `env.WINDOWS_SIGN_CERT_PRESENT == 'true'`), and
`scripts/build-installer.ps1 -CertThumbprint` signs the three program files, the
MSI and the bootstrapper (the bootstrapper engine is detached, signed and
reattached, as WiX requires). This path has not been run with a real
certificate. After the first signed release, check the file's Digital Signatures
tab. A new certificate still builds SmartScreen reputation over time; an EV
certificate avoids most of that delay.

## Testing a build

- `scripts/smoke-windows-installer.ps1` (elevated prompt, a computer with no
  Miasma installed) installs the Setup silently, starts the desktop app with a
  throwaway `--data-dir`, checks that the background service comes up, upgrades
  from an older installer, and uninstalls. The CI job runs it before anything is
  attached.
- Dry run of the workflow: Actions, "Release (Windows installer)", Run workflow,
  enter a tag such as `v0.3.2-beta.99`, leave "dry_run" checked. Nothing is
  uploaded to any release; the files are in the run's artifacts.
- After publishing a release, open the Actions tab: a run named
  "Release (Windows installer)" should start by itself and finish with the
  "Attach to the GitHub Release" job. If it does not, run the workflow by hand
  with the tag and `dry_run` unchecked; re-running is safe (`--clobber`).
