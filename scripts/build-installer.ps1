<#
.SYNOPSIS
    Build the Miasma Windows installer (MSI and bootstrapper EXE).

.DESCRIPTION
    Builds the WiX v6 MSI installer and optional bootstrapper bundle from
    release binaries in .\dist\.

    Requires:
      - WiX Toolset v6 (install: dotnet tool install --global wix)
      - WiX extensions: WixToolset.UI.wixext, WixToolset.Bal.wixext, WixToolset.Util.wixext

    Pipeline:
      1. Verify binaries exist in dist/
      2. Auto-detect version from Cargo metadata
      3. Build MSI with wix build
      4. Build bootstrapper EXE (bundles MSI + VC++ Redistributable)
      5. Generate SHA-256 checksums
      6. Optionally sign with signtool

.PARAMETER InputDir
    Directory containing release binaries. Default: .\dist

.PARAMETER Version
    Override version string. Auto-detected from Cargo.toml if not provided.

.PARAMETER CertThumbprint
    Optional Authenticode certificate thumbprint to sign the installer.

.PARAMETER SkipBundle
    Skip building the bootstrapper EXE (build MSI only).

.PARAMETER VCRedistPath
    Path to vc_redist.x64.exe. If not provided and not in InputDir, it will
    be downloaded automatically.

.EXAMPLE
    .\scripts\build-installer.ps1
    .\scripts\build-installer.ps1 -Version "0.2.0" -SkipBundle
    .\scripts\build-installer.ps1 -CertThumbprint "A1B2..."
#>

param(
    [string]$InputDir = ".\dist",
    [string]$Version = "",
    [string]$CertThumbprint = "",
    [switch]$SkipBundle,
    [string]$VCRedistPath = ""
)

$ErrorActionPreference = "Stop"
$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

if (-not [System.IO.Path]::IsPathRooted($InputDir)) {
    $InputDir = Join-Path $REPO $InputDir
}

# ── Check prerequisites ──────────────────────────────────────────────────────

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    Write-Host "ERROR: WiX Toolset v6 not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install WiX v6:" -ForegroundColor Yellow
    Write-Host "  dotnet tool install --global wix"
    Write-Host ""
    Write-Host "Then install the required extensions:"
    Write-Host "  wix extension add WixToolset.UI.wixext"
    Write-Host "  wix extension add WixToolset.Bal.wixext"
    Write-Host "  wix extension add WixToolset.Util.wixext"
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
    if (-not $Version) { $Version = "0.2.0" }
}

Write-Host "=== Building Miasma Installer ===" -ForegroundColor Cyan
Write-Host "Version:  $Version"
Write-Host "Binaries: $InputDir"
Write-Host ""

# ── Verify installer source files ────────────────────────────────────────────

$wxsPath = Join-Path $REPO "installer\miasma.wxs"
$bundleWxsPath = Join-Path $REPO "installer\bundle.wxs"
$readmePath = Join-Path $REPO "installer\README-installed.txt"
$licensePath = Join-Path $REPO "installer\license.rtf"

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

& wix build $wxsPath `
    -o $msiPath `
    -d "Version=$Version" `
    -d "BinDir=$InputDir" `
    -ext WixToolset.UI.wixext `
    -arch x64

if ($LASTEXITCODE -ne 0) {
    Write-Error "WiX MSI build failed."
    exit 1
}

$msiSize = (Get-Item $msiPath).Length / 1MB
Write-Host ("Created: $msiName ({0:N1} MB)" -f $msiSize) -ForegroundColor Green
Write-Host ""

# ── Build Bootstrapper EXE ───────────────────────────────────────────────────

if (-not $SkipBundle) {
    if (-not (Test-Path $bundleWxsPath)) {
        Write-Warning "Bundle manifest not found at $bundleWxsPath — skipping bootstrapper."
    } else {
        # Locate or download VC++ Redistributable.
        if (-not $VCRedistPath) {
            $VCRedistPath = Join-Path $InputDir "vc_redist.x64.exe"
        }
        if (-not (Test-Path $VCRedistPath)) {
            Write-Host "Downloading VC++ 2015-2022 Redistributable (x64)..."
            $downloadUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
            Invoke-WebRequest -Uri $downloadUrl -OutFile $VCRedistPath -UseBasicParsing
            if (-not (Test-Path $VCRedistPath)) {
                Write-Warning "Failed to download VC++ Redistributable. Skipping bootstrapper."
                $SkipBundle = $true
            } else {
                $vcSize = (Get-Item $VCRedistPath).Length / 1MB
                Write-Host ("Downloaded: vc_redist.x64.exe ({0:N1} MB)" -f $vcSize)
            }
        }

        if (-not $SkipBundle) {
            $bundleName = "MiasmaSetup-$Version-x64.exe"
            $bundlePath = Join-Path $InputDir $bundleName

            Write-Host "Building bootstrapper EXE..."

            & wix build $bundleWxsPath `
                -o $bundlePath `
                -d "Version=$Version" `
                -d "MsiPath=$msiPath" `
                -d "VCRedistPath=$VCRedistPath" `
                -ext WixToolset.Bal.wixext `
                -ext WixToolset.Util.wixext `
                -arch x64

            if ($LASTEXITCODE -ne 0) {
                Write-Error "WiX Bundle build failed."
                exit 1
            }

            $bundleSize = (Get-Item $bundlePath).Length / 1MB
            Write-Host ("Created: $bundleName ({0:N1} MB)" -f $bundleSize) -ForegroundColor Green
            Write-Host ""
        }
    }
}

# ── Optional: sign installer artifacts ────────────────────────────────────────

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
        $toSign = @($msiPath)
        if (-not $SkipBundle -and (Test-Path $bundlePath)) { $toSign += $bundlePath }

        foreach ($artifact in $toSign) {
            $leaf = Split-Path -Leaf $artifact
            Write-Host "Signing $leaf..."
            & $signtool sign /fd SHA256 /sha1 $CertThumbprint /tr http://timestamp.digicert.com /td SHA256 $artifact
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  Signed." -ForegroundColor Green
            } else {
                Write-Warning "  Signing failed for $leaf. Unsigned artifact still available."
            }
        }
    } else {
        Write-Warning "signtool.exe not found. Artifacts are unsigned."
    }
}

# ── Checksums ─────────────────────────────────────────────────────────────────

Write-Host "Generating checksums..."

$artifacts = @($msiPath)
if (-not $SkipBundle -and (Test-Path $bundlePath)) { $artifacts += $bundlePath }

foreach ($artifact in $artifacts) {
    $leaf = Split-Path -Leaf $artifact
    $hash = (Get-FileHash $artifact -Algorithm SHA256).Hash
    $checksumFile = "$artifact.sha256"
    "$hash  $leaf" | Set-Content $checksumFile
    Write-Host "  $leaf  SHA-256: $hash"
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Installer Build Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Artifacts in $InputDir :"

Write-Host "  MSI (advanced):       $msiName"
if (-not $SkipBundle -and (Test-Path $bundlePath)) {
    Write-Host "  Setup EXE (primary):  $bundleName  [recommended for distribution]"
}
Write-Host ""
Write-Host "Install (Setup EXE):    .\$bundleName"
Write-Host "Install (MSI only):     msiexec /i $msiName"
Write-Host "Silent install (MSI):   msiexec /i $msiName /qn"
Write-Host "Uninstall (MSI):        msiexec /x $msiName /qn"
