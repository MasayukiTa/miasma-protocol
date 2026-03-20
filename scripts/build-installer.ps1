<#
.SYNOPSIS
    Build the Miasma Windows MSI installer.

.DESCRIPTION
    Builds the WiX v4 MSI installer from the release binaries in .\dist\.
    Requires WiX Toolset v4 (install: dotnet tool install --global wix).

    Pipeline:
      1. Verify binaries exist in dist/
      2. Auto-detect version from Cargo metadata
      3. Build MSI with wix build
      4. Optionally sign the MSI with signtool

.PARAMETER InputDir
    Directory containing release binaries. Default: .\dist

.PARAMETER Version
    Override version string. Auto-detected from Cargo.toml if not provided.

.PARAMETER CertThumbprint
    Optional Authenticode certificate thumbprint to sign the MSI.

.EXAMPLE
    .\scripts\build-installer.ps1
    .\scripts\build-installer.ps1 -Version "0.1.0" -CertThumbprint "A1B2..."
#>

param(
    [string]$InputDir = ".\dist",
    [string]$Version = "",
    [string]$CertThumbprint = ""
)

$ErrorActionPreference = "Stop"
$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

if (-not [System.IO.Path]::IsPathRooted($InputDir)) {
    $InputDir = Join-Path $REPO $InputDir
}

# ── Check prerequisites ──────────────────────────────────────────────────────

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    Write-Host "ERROR: WiX Toolset v4 not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install WiX v4:" -ForegroundColor Yellow
    Write-Host "  dotnet tool install --global wix"
    Write-Host ""
    Write-Host "Then install the WiX UI extension:"
    Write-Host "  wix extension add WixToolset.UI.wixext"
    Write-Host ""
    Write-Host "See: https://wixtoolset.org/docs/intro/"
    exit 1
}

# Verify binaries exist.
$requiredBins = @("miasma.exe", "miasma-desktop.exe", "miasma-bridge.exe")
$missing = $requiredBins | Where-Object { -not (Test-Path (Join-Path $InputDir $_)) }
if ($missing) {
    Write-Host "ERROR: Missing binaries in ${InputDir}:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""
    Write-Host "Run first:  .\scripts\build-release.ps1"
    exit 1
}

# Auto-detect version.
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
    if (-not $Version) { $Version = "0.1.0" }
}

Write-Host "=== Building Miasma Installer ===" -ForegroundColor Cyan
Write-Host "Version:  $Version"
Write-Host "Binaries: $InputDir"
Write-Host ""

# ── Verify installer source files ────────────────────────────────────────────

$wxsPath = Join-Path $REPO "installer\miasma.wxs"
$readmePath = Join-Path $REPO "installer\README-installed.txt"
$licensePath = Join-Path $REPO "installer\license.rtf"
$releaseNotesPath = Join-Path $REPO "RELEASE-NOTES.md"

foreach ($f in @($wxsPath, $readmePath, $licensePath)) {
    if (-not (Test-Path $f)) {
        Write-Error "Missing installer source: $f"
        exit 1
    }
}

# ── Build MSI ────────────────────────────────────────────────────────────────

$msiName = "miasma-$Version-windows-x64.msi"
$msiPath = Join-Path $InputDir $msiName

Write-Host "Building MSI..."

# WiX v4 build command.
& wix build $wxsPath `
    -o $msiPath `
    -d "Version=$Version" `
    -d "BinDir=$InputDir" `
    -ext WixToolset.UI.wixext

if ($LASTEXITCODE -ne 0) {
    Write-Error "WiX build failed."
    exit 1
}

$msiSize = (Get-Item $msiPath).Length / 1MB
Write-Host ("Created: $msiPath ({0:N1} MB)" -f $msiSize) -ForegroundColor Green

# ── Optional: sign MSI ───────────────────────────────────────────────────────

if ($CertThumbprint) {
    $signtool = $null
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
    )
    foreach ($pattern in $sdkPaths) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { $signtool = $found.FullName; break }
    }

    if ($signtool) {
        Write-Host "Signing MSI..."
        & $signtool sign /fd SHA256 /sha1 $CertThumbprint /tr http://timestamp.digicert.com /td SHA256 $msiPath
        if ($LASTEXITCODE -eq 0) {
            Write-Host "MSI signed successfully." -ForegroundColor Green
        } else {
            Write-Warning "MSI signing failed. Unsigned MSI still available."
        }
    } else {
        Write-Warning "signtool.exe not found. MSI is unsigned."
    }
}

# ── Checksum ─────────────────────────────────────────────────────────────────

$hash = (Get-FileHash $msiPath -Algorithm SHA256).Hash
$checksumFile = "$msiPath.sha256"
"$hash  $msiName" | Set-Content $checksumFile
Write-Host "SHA-256: $hash"
Write-Host "Written: $checksumFile"

Write-Host ""
Write-Host "=== Installer Build Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Install (interactive):  msiexec /i $msiPath"
Write-Host "Install (silent):       msiexec /i $msiPath /qn"
Write-Host "Uninstall:              msiexec /x $msiPath /qn"
