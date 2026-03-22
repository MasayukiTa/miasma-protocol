# package-release.ps1 — Package Miasma release binaries into a distributable zip.
#
# Usage:
#   .\scripts\package-release.ps1 [-InputDir .\dist] [-Version "0.3.0"] [-Variant both]
#
# Produces:
#   miasma-<version>-windows-x64.zip                     (Variant=both or technical)
#   miasma-<version>-windows-x64-easy.zip                (Variant=both or easy)
#
# Variant:
#   technical — package for technical beta users (default README)
#   easy      — package for non-technical trial users (simplified README)
#   both      — produce two zip files, one for each variant

param(
    [string]$InputDir = ".\dist",
    [string]$Version = "",

    [ValidateSet("technical", "easy", "both")]
    [string]$Variant = "both"
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

Write-Host "Packaging Miasma v$Version (variant=$Variant) ..."

# ── Variant list ──────────────────────────────────────────────────────────────
$variants = @()
if ($Variant -eq "both") {
    $variants = @("technical", "easy")
} else {
    $variants = @($Variant)
}

foreach ($v in $variants) {
    $suffix = if ($v -eq "easy") { "-easy" } else { "" }
    $zipName = "miasma-$Version-windows-x64$suffix.zip"
    $stagingDir = Join-Path $REPO "dist\staging\miasma-$Version"

    New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null

    # Copy binaries.
    $files = @("miasma.exe", "miasma-desktop.exe", "miasma-bridge.exe")
    foreach ($f in $files) {
        $src = Join-Path $InputDir $f
        if (Test-Path $src) {
            Copy-Item $src -Destination $stagingDir -Force
        } else {
            Write-Warning "Missing: $f"
        }
    }

    # Copy variant-specific launchers.
    $launcherDir = Join-Path $REPO "scripts\launchers"
    Copy-Item (Join-Path $launcherDir "Miasma.cmd") -Destination $stagingDir -Force
    Copy-Item (Join-Path $launcherDir "Miasma Technical.cmd") -Destination $stagingDir -Force

    # Variant-appropriate README.
    if ($v -eq "easy") {
        $readmeContent = @"
Miasma v$Version — Trial Build (Windows)
=========================================

WHAT'S INCLUDED

  Miasma.cmd             Start here — launches the app
  Miasma Technical.cmd   Advanced mode (for developers/testers)
  miasma-desktop.exe     Desktop app (used by the launchers above)
  miasma.exe             Background service (used automatically)
  miasma-bridge.exe      Advanced tool (optional)

GETTING STARTED

  1. Place all files in a single folder (e.g. C:\Miasma).
  2. Double-click "Miasma.cmd".
  3. Click "Get Started" on the welcome screen.
  4. That's it. You can now save and retrieve content.

  NOTE: This app is not code-signed yet. Windows may show a warning
  on first launch. Click "More info" > "Run anyway".

LANGUAGE

  Go to Settings to switch between English, Japanese, and Chinese.

SAVING AND RETRIEVING

  Save:     Go to the "Save" tab, type or choose a file, click "Save".
            You will receive a Content ID — keep it safe.
  Get Back: Go to the "Get Back" tab, paste the Content ID, click "Get Back".
            Save the result to a file.

TWO MODES

  Easy mode (default):      Simplified interface for everyday use.
  Technical mode:           Full diagnostics for developers and testers.

  Switch between modes in Settings, or use the launcher scripts:
    Miasma.cmd              — starts in Easy mode
    Miasma Technical.cmd    — starts in Technical mode

  Your choice is saved and persists across restarts.

TROUBLESHOOTING

  - "Not running": Ensure miasma.exe is in the same folder.
  - SmartScreen warning: Click "More info" > "Run anyway".
  - Go to Status tab and click "Copy Diagnostics" to report issues.

For more: Settings tab shows data location and app details.
"@
    } else {
        $readmeContent = @"
Miasma Protocol v$Version — Technical Beta (Windows)
=====================================================

WHAT'S INCLUDED

  Miasma Technical.cmd   Start here — launches in Technical mode
  Miasma.cmd             Easy mode launcher (for non-technical users)
  miasma.exe             CLI tool and background daemon
  miasma-desktop.exe     Desktop GUI
  miasma-bridge.exe      BitTorrent-to-Miasma bridge (advanced)

GETTING STARTED

  1. Place all files in a single folder (e.g. C:\Miasma).
  2. Double-click "Miasma Technical.cmd".
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
  - Same-network peer discovery uses mDNS; restrictive networks may still need manual bootstrap peers
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
"@
    }

    $readmeContent | Set-Content (Join-Path $stagingDir "README.txt")

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
    Write-Host ("  Created: $zipPath ({0:N1} MB)" -f $zipSize)
}

Write-Host ""
Write-Host "Packaging complete."
Write-Host "Next: .\scripts\sign-release.ps1 <zip-path> (optional)"
