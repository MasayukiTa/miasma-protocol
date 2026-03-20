# package-release.ps1 — Package Miasma release binaries into a distributable zip.
#
# Usage:
#   .\scripts\package-release.ps1 [-InputDir .\dist] [-Version "0.1.0"]
#
# Produces:
#   miasma-<version>-windows-x64.zip

param(
    [string]$InputDir = ".\dist",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

# Auto-detect version from cargo if not supplied.
if (-not $Version) {
    $Version = (cargo metadata --format-version 1 --no-deps 2>$null |
        ConvertFrom-Json).packages |
        Where-Object { $_.name -eq "miasma-cli" } |
        Select-Object -ExpandProperty version
    if (-not $Version) { $Version = "0.0.0" }
}

$zipName = "miasma-$Version-windows-x64.zip"
$stagingDir = ".\dist\staging\miasma-$Version"

Write-Host "Packaging Miasma v$Version ..."

# Stage files.
New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

$files = @("miasma.exe", "miasma-desktop.exe", "miasma-bridge.exe")
foreach ($f in $files) {
    $src = Join-Path $InputDir $f
    if (Test-Path $src) {
        Copy-Item $src -Destination $stagingDir -Force
    } else {
        Write-Warning "Missing: $f"
    }
}

# Include tester-facing README.
@"
Miasma Protocol v$Version — Windows Beta
=========================================

WHAT'S INCLUDED

  miasma.exe         CLI and background daemon
  miasma-desktop.exe Desktop GUI (recommended for first-time users)
  miasma-bridge.exe  BitTorrent-to-Miasma bridge (advanced)

GETTING STARTED

  1. Place all .exe files in a single folder (e.g. C:\Miasma).
  2. Double-click miasma-desktop.exe.
  3. Click "Set Up Node" on the welcome screen.
  4. The daemon starts automatically. You're ready to store and retrieve content.

  Alternatively, use the CLI:
    miasma init
    miasma daemon          (leave running in a terminal)
    miasma dissolve <file> (store a file, prints a Content ID)
    miasma get <MID>       (retrieve by Content ID)

BRIDGE (ADVANCED)

  The bridge imports BitTorrent content into Miasma.
  Safe defaults: seeding disabled, 100 MiB size limit, no proxy.

    miasma-bridge dissolve "magnet:?xt=urn:btih:..."
    miasma-bridge --help

DIAGNOSTICS

  Desktop: Status tab > Copy Diagnostics
  CLI:     miasma diagnostics --json

KNOWN LIMITATIONS (BETA)

  - Single-machine testing only; multi-node requires manual bootstrap
  - No automatic peer discovery over the Internet yet
  - DHT convergence can take 10-30 seconds on first connect
  - Bridge requires real BitTorrent swarm availability
  - No code signing (Windows SmartScreen may warn on first run)

TROUBLESHOOTING

  - "Daemon not running": Ensure miasma.exe is in the same folder
    as miasma-desktop.exe, or on your PATH.
  - SmartScreen warning: Click "More info" > "Run anyway".
  - For verbose logs: set RUST_LOG=debug before running.
  - Copy diagnostics and include them when reporting issues.

For help: miasma --help | miasma-bridge --help
"@ | Set-Content (Join-Path $stagingDir "README.txt")

# Create zip.
$zipPath = Join-Path $InputDir $zipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipPath -Force

# Cleanup staging.
Remove-Item -Recurse -Force ".\dist\staging"

$zipSize = (Get-Item $zipPath).Length / 1MB
Write-Host "Created: $zipPath ({0:N1} MB)" -f $zipSize
Write-Host ""
Write-Host "Next: .\scripts\sign-release.ps1 $zipPath (optional)"
