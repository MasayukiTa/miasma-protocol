<#
.SYNOPSIS
    Build the Miasma Windows installer (MSI and bootstrapper EXE).

.DESCRIPTION
    Builds the WiX v6 MSI installer and the bootstrapper bundle from release
    binaries in .\dist\ (produced by scripts\build-release.ps1).

    Requires:
      - WiX Toolset v6 (install: dotnet tool install --global wix --version 6.0.2)
      - WiX extensions: WixToolset.UI.wixext, WixToolset.Bal.wixext, WixToolset.Util.wixext
        (install: wix extension add -g WixToolset.UI.wixext/6.0.2 ...)

    Pipeline:
      1. Verify binaries exist in the input directory
      2. Work out the version and map it to MSI / bundle versions
         (scripts\windows-version.ps1 explains the scheme)
      3. Optionally sign the three program files
      4. Build the MSI with wix build
      5. Build the bootstrapper EXE (bundles the MSI and the VC++ Redistributable)
      6. Optionally sign the MSI and the bootstrapper
      7. Write SHA-256 checksums

    Output names:
      miasma-<version>-windows-x64.msi          (advanced / managed installs)
      Miasma-Setup-<version>-x64.exe            (the file users download)
      SHA256SUMS-windows.txt                    (lines for the two files above)
    where <version> is the release version without the leading v, for example
    0.3.2-beta.12.

.PARAMETER InputDir
    Directory containing release binaries. Default: .\dist

.PARAMETER OutputDir
    Directory for the installers. Default: the same as InputDir.

.PARAMETER Version
    Release version, for example 0.3.2-beta.12 or 0.3.2 (a leading v is ignored).
    Default: the miasma-cli crate version, plus the pre-release label in the
    MIASMA_PRERELEASE environment variable when it is set.

.PARAMETER CertThumbprint
    Optional Authenticode certificate thumbprint (certificate in the current
    user or local machine store). When given, miasma.exe, miasma-desktop.exe,
    miasma-bridge.exe, the MSI and the bootstrapper are signed. Without it the
    installer is unsigned and nothing fails.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server used when signing.

.PARAMETER SkipBundle
    Skip building the bootstrapper EXE (build MSI only).

.PARAMETER VCRedistPath
    Path to vc_redist.x64.exe. If not provided and not in InputDir, it is
    downloaded from Microsoft and its signature is checked.

.EXAMPLE
    .\scripts\build-installer.ps1 -Version 0.3.2-beta.12
    .\scripts\build-installer.ps1 -Version 0.3.2 -SkipBundle
    .\scripts\build-installer.ps1 -Version 0.3.2-beta.12 -CertThumbprint "A1B2..."
#>

param(
    [string]$InputDir = ".\dist",
    [string]$OutputDir = "",
    [string]$Version = "",
    [string]$CertThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$SkipBundle,
    [string]$VCRedistPath = ""
)

$ErrorActionPreference = "Stop"
$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
. (Join-Path $PSScriptRoot "windows-version.ps1")

if (-not [System.IO.Path]::IsPathRooted($InputDir)) {
    $InputDir = Join-Path (Get-Location).Path $InputDir
}
if (-not $OutputDir) { $OutputDir = $InputDir }
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path (Get-Location).Path $OutputDir
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# The .wxs files use paths relative to the repository root.
Push-Location $REPO
try {

# -- Check prerequisites -------------------------------------------------------

$wix = Get-Command wix -ErrorAction SilentlyContinue
if (-not $wix) {
    Write-Host "ERROR: WiX Toolset v6 not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install WiX v6:" -ForegroundColor Yellow
    Write-Host "  dotnet tool install --global wix --version 6.0.2"
    Write-Host ""
    Write-Host "Then install the required extensions:"
    Write-Host "  wix extension add -g WixToolset.UI.wixext/6.0.2"
    Write-Host "  wix extension add -g WixToolset.Bal.wixext/6.0.2"
    Write-Host "  wix extension add -g WixToolset.Util.wixext/6.0.2"
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

# -- Version -------------------------------------------------------------------

if (-not $Version) {
    $base = (cargo metadata --format-version 1 --no-deps 2>$null |
        ConvertFrom-Json).packages |
        Where-Object { $_.name -eq "miasma-cli" } |
        Select-Object -ExpandProperty version
    if (-not $base) { throw "Could not read the miasma-cli version from cargo metadata; pass -Version." }
    $Version = $base
    if ($env:MIASMA_PRERELEASE) { $Version = "$base-$($env:MIASMA_PRERELEASE.Trim().TrimStart('-'))" }
}
$ver = ConvertTo-MiasmaWindowsVersion $Version
$Version = $ver.Semver

Write-Host "=== Building Miasma Installer ===" -ForegroundColor Cyan
Write-Host "Version:         $Version"
Write-Host "MSI version:     $($ver.MsiVersion)"
Write-Host "Bundle version:  $($ver.BundleVersion)"
Write-Host "Binaries:        $InputDir"
Write-Host ""

# -- Verify installer source files ---------------------------------------------

$wxsPath = Join-Path $REPO "installer\miasma.wxs"
$bundleWxsPath = Join-Path $REPO "installer\bundle.wxs"
$readmePath = Join-Path $REPO "installer\README-installed.txt"
$licensePath = Join-Path $REPO "installer\license.rtf"
$notesPath = Join-Path $REPO "RELEASE-NOTES.md"

foreach ($f in @($wxsPath, $readmePath, $licensePath, $notesPath)) {
    if (-not (Test-Path $f)) {
        throw "Missing installer source: $f"
    }
}

# -- Optional signing helpers --------------------------------------------------

$signtool = $null
if ($CertThumbprint) {
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
    )
    foreach ($pattern in $sdkPaths) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { $signtool = $found.FullName; break }
    }
    if (-not $signtool) { throw "-CertThumbprint was given but signtool.exe was not found (install the Windows SDK)." }
}

function Sign-File([string]$Path) {
    if (-not $signtool) { return }
    $leaf = Split-Path -Leaf $Path
    Write-Host "Signing $leaf..."
    & $signtool sign /fd SHA256 /sha1 $CertThumbprint /tr $TimestampUrl /td SHA256 $Path
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $leaf." }
}

# Program files are signed before they are packed, so the installed files carry
# the signature as well as the installer.
foreach ($exe in $requiredBins) { Sign-File (Join-Path $InputDir $exe) }

# -- Build MSI -----------------------------------------------------------------

$msiName = "miasma-$Version-windows-x64.msi"
$msiPath = Join-Path $OutputDir $msiName

Write-Host "Building MSI..."

& wix build $wxsPath `
    -o $msiPath `
    -d "Version=$($ver.MsiVersion)" `
    -d "BinDir=$InputDir" `
    -ext WixToolset.UI.wixext `
    -arch x64

if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed." }

Write-Host ("Created: $msiName ({0:N1} MB)" -f ((Get-Item $msiPath).Length / 1MB)) -ForegroundColor Green
Write-Host ""

# -- Build Bootstrapper EXE ----------------------------------------------------

$bundlePath = $null
$bundleName = "Miasma-Setup-$Version-x64.exe"

if (-not $SkipBundle) {
    if (-not (Test-Path $bundleWxsPath)) { throw "Bundle manifest not found at $bundleWxsPath." }

    # Locate or download the VC++ Redistributable. The program files link the
    # C runtime dynamically (checked by scripts\check-exe-deps.ps1), so the
    # bootstrapper installs the redistributable when it is missing.
    if (-not $VCRedistPath) { $VCRedistPath = Join-Path $InputDir "vc_redist.x64.exe" }
    if (-not (Test-Path $VCRedistPath)) {
        Write-Host "Downloading VC++ 2015-2022 Redistributable (x64)..."
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $VCRedistPath -UseBasicParsing
        if (-not (Test-Path $VCRedistPath)) { throw "Failed to download the VC++ Redistributable." }
    }
    # Only embed a file that Microsoft signed.
    $sig = Get-AuthenticodeSignature $VCRedistPath
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
        throw "vc_redist.x64.exe is not validly signed by Microsoft Corporation (status: $($sig.Status))."
    }
    Write-Host ("VC++ Redistributable: {0:N1} MB, signature {1}" -f ((Get-Item $VCRedistPath).Length / 1MB), $sig.Status)

    $bundlePath = Join-Path $OutputDir $bundleName

    Write-Host "Building bootstrapper EXE..."

    & wix build $bundleWxsPath `
        -o $bundlePath `
        -d "Version=$($ver.BundleVersion)" `
        -d "MsiPath=$msiPath" `
        -d "VCRedistPath=$VCRedistPath" `
        -ext WixToolset.Bal.wixext `
        -ext WixToolset.Util.wixext `
        -arch x64

    if ($LASTEXITCODE -ne 0) { throw "WiX Bundle build failed." }

    Write-Host ("Created: $bundleName ({0:N1} MB)" -f ((Get-Item $bundlePath).Length / 1MB)) -ForegroundColor Green
    Write-Host ""
}

# -- Optional: sign installer artifacts ----------------------------------------

if ($signtool) {
    Sign-File $msiPath
    if ($bundlePath) {
        # A bootstrapper must be signed in two steps: the engine is signed on its
        # own and reattached, then the whole file is signed. Signing the
        # finished bundle directly would invalidate its attached container.
        $engine = Join-Path $OutputDir "burn-engine.exe"
        & wix burn detach $bundlePath -engine $engine
        if ($LASTEXITCODE -ne 0) { throw "wix burn detach failed." }
        Sign-File $engine
        & wix burn reattach $bundlePath -engine $engine -o $bundlePath
        if ($LASTEXITCODE -ne 0) { throw "wix burn reattach failed." }
        Remove-Item $engine -Force
        Sign-File $bundlePath
    }
}

# -- Checksums -----------------------------------------------------------------

Write-Host "Generating checksums..."

$artifacts = @($msiPath)
if ($bundlePath) { $artifacts += $bundlePath }

$sums = @()
foreach ($artifact in $artifacts) {
    $leaf = Split-Path -Leaf $artifact
    $hash = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    $sums += "$hash  $leaf"
    Write-Host "  $leaf  SHA-256: $hash"
}
# sha256sum format (two spaces), LF line ends, no BOM.
[System.IO.File]::WriteAllText((Join-Path $OutputDir "SHA256SUMS-windows.txt"), (($sums -join "`n") + "`n"),
    (New-Object System.Text.UTF8Encoding($false)))

# -- Summary -------------------------------------------------------------------

Write-Host ""
Write-Host "=== Installer Build Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Artifacts in $OutputDir :"
Write-Host "  MSI (advanced):       $msiName"
if ($bundlePath) {
    Write-Host "  Setup EXE (primary):  $bundleName  [recommended for distribution]"
}
Write-Host "  Checksums:            SHA256SUMS-windows.txt"
Write-Host ""
if ($bundlePath) { Write-Host "Install (Setup EXE):    .\$bundleName" }
Write-Host "Silent install (EXE):   .\$bundleName /quiet /norestart"
Write-Host "Silent install (MSI):   msiexec /i $msiName /qn"
Write-Host "Uninstall (MSI):        msiexec /x $msiName /qn"

} finally {
    Pop-Location
}
