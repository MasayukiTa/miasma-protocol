# package-release.ps1 — Package Miasma release binaries into a distributable zip.
#
# Usage:
#   .\scripts\package-release.ps1 [-InputDir .\dist] [-Version "0.2.0"]
#
# Produces:
#   miasma-<version>-windows-x64.zip

param(
    [string]$InputDir = ".\dist",
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

if (-not [System.IO.Path]::IsPathRooted($InputDir)) {
    $InputDir = Join-Path $REPO $InputDir
}

# Auto-detect version from cargo if not supplied.
if (-not $Version) {
    Push-Location $REPO
    try {
        $Version = (cargo metadata --format-version 1 --no-deps 2>$null |
            ConvertFrom-Json).packages |
            Where-Object { $_.name -eq "miasma-cli" } |
            Select-Object -ExpandProperty version
    } finally {
        Pop-Location
    }
    if (-not $Version) { $Version = "0.0.0" }
}

$zipName = "miasma-$Version-windows-x64.zip"
$stagingDir = Join-Path $REPO "dist\staging\miasma-$Version"

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

# Include public-beta-facing README.
@"
Miasma Protocol v$Version — Public Beta (Windows)
===================================================

WHAT'S INCLUDED

  miasma.exe         CLI tool and background daemon
  miasma-desktop.exe Desktop GUI (recommended for first-time users)
  miasma-bridge.exe  BitTorrent-to-Miasma bridge (advanced)

GETTING STARTED

  1. Place all .exe files in a single folder (e.g. C:\Miasma).
  2. Double-click miasma-desktop.exe.
  3. Click "Set Up Node" on the welcome screen.
  4. The daemon starts automatically. You're ready to store and retrieve content.

  NOTE: This beta is not code-signed. Windows SmartScreen will warn on first
  launch. Click "More info" > "Run anyway".

  Alternatively, use the CLI:
    miasma init                    Create node identity
    miasma daemon                  Start background daemon (keep running)
    miasma dissolve <file>         Store a file (prints a Content ID)
    miasma get <MID>               Retrieve by Content ID
    miasma get <MID> -o out.bin    Retrieve to a specific file
    miasma diagnostics             Show node diagnostics
    miasma diagnostics --json      Machine-readable diagnostics

BRIDGE (ADVANCED)

  The bridge imports BitTorrent content into Miasma.
  Safe defaults: seeding disabled, 100 MiB size limit, no proxy.

    miasma-bridge dissolve "magnet:?xt=urn:btih:..."
    miasma-bridge --help

DIAGNOSTICS AND LOGS

  Desktop: Status tab > Copy Diagnostics
  CLI:     miasma diagnostics --json

  Log files are stored in your data directory:
    daemon.log.<date>    Daemon activity
    desktop.log.<date>   Desktop GUI activity
    bridge.log.<date>    Bridge daemon activity

  Settings tab (Desktop) or "miasma diagnostics" (CLI) shows the log
  file location.

KNOWN LIMITATIONS

  - Not code-signed: SmartScreen will warn on first run
  - No automatic peer discovery; bootstrap peers must be configured manually
  - DHT convergence takes 10-30 seconds after first peer connection
  - Single-machine only; multi-node over real networks not validated
  - Bridge requires real BitTorrent swarm availability

TROUBLESHOOTING

  - "Daemon not running": Ensure miasma.exe is in the same folder
    as miasma-desktop.exe, or on your PATH.
  - SmartScreen warning: Click "More info" > "Run anyway".
  - For verbose logs: set RUST_LOG=debug before running.
  - Copy diagnostics and include them when reporting issues.

VERIFYING YOUR DOWNLOAD

  Check the SHA-256 hash in the .sha256 file against the zip:
    powershell -Command "(Get-FileHash .\miasma-$Version-windows-x64.zip).Hash"

  See RELEASE-NOTES.md for full release notes and changelog.

For help: miasma --help | miasma-bridge --help
"@ | Set-Content (Join-Path $stagingDir "README.txt")

# Include release notes if available.
$releaseNotesPath = Join-Path $REPO "RELEASE-NOTES.md"
if (Test-Path $releaseNotesPath) {
    Copy-Item $releaseNotesPath -Destination $stagingDir -Force
}

# Create zip.
$zipPath = Join-Path $InputDir $zipName
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipPath -Force

# Cleanup staging.
Remove-Item -Recurse -Force (Join-Path $REPO "dist\staging")

$zipSize = (Get-Item $zipPath).Length / 1MB
Write-Host ("Created: $zipPath ({0:N1} MB)" -f $zipSize)
Write-Host ""
Write-Host "Next: .\scripts\sign-release.ps1 $zipPath (optional)"
