<#
.SYNOPSIS
    Build a Microsoft Store-ready x64 MSIX for the native Miasma desktop app.

.DESCRIPTION
    Packages only the consumer desktop executable and its sibling daemon backend.
    It intentionally excludes the BitTorrent bridge, technical shortcuts, PATH
    mutation, and registry associations from the Store package. The manifest
    declares Microsoft.VCLibs.140.00.UWPDesktop because the Rust/MSVC binaries
    import VCRUNTIME140.dll; Microsoft Store installs framework dependencies.

    Partner Center assigns the package Identity Name and Publisher. Pass those
    exact values with parameters or the MIASMA_STORE_* environment variables.
    Store submission does not require a CA-trusted signing certificate: the Store
    re-signs accepted MSIX packages. For local install testing, -CertThumbprint can
    sign the package with a certificate whose subject matches -Publisher.

.PARAMETER InputDir
    Directory containing miasma-desktop.exe and miasma.exe.

.PARAMETER PackageIdentityName
    Partner Center package identity Name. Falls back to MIASMA_STORE_IDENTITY_NAME.

.PARAMETER Publisher
    Partner Center Publisher DN (for example CN=...). Falls back to MIASMA_STORE_PUBLISHER.

.PARAMETER PublisherDisplayName
    Friendly publisher name. Falls back to MIASMA_STORE_PUBLISHER_DISPLAY_NAME.

.PARAMETER PackageVersion
    Four-part MSIX version. The fourth component must be 0 for Store submission.
    When omitted, workspace semver X.Y.Z maps monotonically to 1.X.(Y*100+Z).0.

.PARAMETER CertThumbprint
    Optional certificate thumbprint for local signing. Do not use a self-signed
    package as the artifact uploaded to Partner Center unless Store guidance says so.
#>

param(
    [string]$InputDir = ".\dist",
    [string]$OutputDir = ".\dist\store",
    [string]$PackageIdentityName = $env:MIASMA_STORE_IDENTITY_NAME,
    [string]$Publisher = $env:MIASMA_STORE_PUBLISHER,
    [string]$PublisherDisplayName = $env:MIASMA_STORE_PUBLISHER_DISPLAY_NAME,
    [string]$PackageVersion = "",
    [string]$CertThumbprint = ""
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

function Resolve-RepoPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) { return [System.IO.Path]::GetFullPath($Path) }
    return [System.IO.Path]::GetFullPath((Join-Path $repo $Path))
}

function Find-SdkTool([string]$Name) {
    $onPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    $patterns = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\$Name",
        "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\$Name"
    )
    foreach ($pattern in $patterns) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw "$Name not found. Install a current Windows SDK."
}

function Assert-X64Pe([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    $reader = New-Object System.IO.BinaryReader($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "Not a PE executable: $Path" }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) { throw "Invalid PE header offset: $Path" }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $Path" }
        $machine = $reader.ReadUInt16()
        if ($machine -ne 0x8664) {
            throw ("Store package is x64 but {0} has PE machine 0x{1:X4}." -f $Path, $machine)
        }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Get-WorkspaceVersion {
    Push-Location $repo
    try {
        $metadata = cargo metadata --format-version 1 --no-deps 2>$null | ConvertFrom-Json
        $pkg = $metadata.packages | Where-Object { $_.name -eq "miasma-desktop" } | Select-Object -First 1
        if (-not $pkg) { throw "miasma-desktop package not found in cargo metadata" }
        return $pkg.version
    } finally {
        Pop-Location
    }
}

function Convert-SemverToStoreVersion([string]$Semver) {
    if ($Semver -notmatch '^(\d+)\.(\d+)\.(\d+)') {
        throw "Cannot map workspace version '$Semver' to an MSIX version."
    }
    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    $patch = [int]$Matches[3]
    if ($patch -gt 99) {
        throw "Automatic MSIX mapping requires semver patch <= 99; pass -PackageVersion explicitly."
    }
    $build = ($minor * 100) + $patch
    if ($major -gt 65535 -or $build -gt 65535) {
        throw "Workspace version '$Semver' cannot be represented safely; pass -PackageVersion explicitly."
    }
    return "1.$major.$build.0"
}

function Assert-StoreVersion([string]$Version) {
    if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)\.(\d+)$') {
        throw "MSIX version must be four numeric components: Major.Minor.Build.Revision."
    }
    $parts = @($Matches[1], $Matches[2], $Matches[3], $Matches[4]) | ForEach-Object { [int]$_ }
    if ($parts[0] -eq 0) { throw "MSIX package Major version cannot be 0 for Store submission." }
    if ($parts | Where-Object { $_ -gt 65535 }) { throw "Every MSIX version component must be <= 65535." }
    if ($parts[3] -ne 0) { throw "The fourth MSIX version component is reserved for Store use and must be 0." }
}

if ([string]::IsNullOrWhiteSpace($PackageIdentityName)) {
    throw "Package identity is required. Reserve the app in Partner Center, then pass -PackageIdentityName or MIASMA_STORE_IDENTITY_NAME."
}
if ([string]::IsNullOrWhiteSpace($Publisher)) {
    throw "Publisher DN is required. Copy it exactly from Partner Center and pass -Publisher or MIASMA_STORE_PUBLISHER."
}
if ([string]::IsNullOrWhiteSpace($PublisherDisplayName)) {
    throw "Publisher display name is required. Pass -PublisherDisplayName or MIASMA_STORE_PUBLISHER_DISPLAY_NAME."
}

$InputDir = Resolve-RepoPath $InputDir
$OutputDir = Resolve-RepoPath $OutputDir
$template = Join-Path $repo "installer\msix\AppxManifest.template.xml"
$assets = Join-Path $repo "installer\msix\Assets"

$required = @("miasma-desktop.exe", "miasma.exe")
$missing = $required | Where-Object { -not (Test-Path (Join-Path $InputDir $_)) }
if ($missing) { throw "Missing Store payload in ${InputDir}: $($missing -join ', ')" }
foreach ($file in $required) {
    Assert-X64Pe (Join-Path $InputDir $file)
}

if (-not $PackageVersion) {
    $PackageVersion = Convert-SemverToStoreVersion (Get-WorkspaceVersion)
}
Assert-StoreVersion $PackageVersion

$makeappx = Find-SdkTool "makeappx.exe"
$signtool = if ($CertThumbprint) { Find-SdkTool "signtool.exe" } else { $null }

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$stage = Join-Path $OutputDir "staging"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stage "Assets") | Out-Null

foreach ($file in $required) {
    Copy-Item (Join-Path $InputDir $file) (Join-Path $stage $file) -Force
}
Copy-Item (Join-Path $assets "*.png") (Join-Path $stage "Assets") -Force

function XmlEscape([string]$Value) {
    return [System.Security.SecurityElement]::Escape($Value)
}
$manifest = Get-Content $template -Raw -Encoding UTF8
$manifest = $manifest.Replace('@@IDENTITY_NAME@@', (XmlEscape $PackageIdentityName))
$manifest = $manifest.Replace('@@PUBLISHER@@', (XmlEscape $Publisher))
$manifest = $manifest.Replace('@@PUBLISHER_DISPLAY_NAME@@', (XmlEscape $PublisherDisplayName))
$manifest = $manifest.Replace('@@VERSION@@', $PackageVersion)
$manifestPath = Join-Path $stage "AppxManifest.xml"
[System.IO.File]::WriteAllText($manifestPath, $manifest, (New-Object System.Text.UTF8Encoding($false)))

$safeVersion = $PackageVersion.Replace('.', '_')
$output = Join-Path $OutputDir "miasma-$safeVersion-windows-x64.msix"
Remove-Item $output -Force -ErrorAction SilentlyContinue

Write-Host "Building Microsoft Store MSIX..."
Write-Host "  Identity:  $PackageIdentityName"
Write-Host "  Publisher: $Publisher"
Write-Host "  Version:   $PackageVersion"
Write-Host "  Payload:   miasma-desktop.exe + miasma.exe"

& $makeappx pack /d $stage /p $output /o
if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed with exit code $LASTEXITCODE" }

if ($CertThumbprint) {
    & $signtool sign /fd SHA256 /sha1 $CertThumbprint /tr "http://timestamp.digicert.com" /td SHA256 $output
    if ($LASTEXITCODE -ne 0) { throw "SignTool failed with exit code $LASTEXITCODE" }
}

$hash = (Get-FileHash $output -Algorithm SHA256).Hash.ToLowerInvariant()
$hashPath = "$output.sha256"
[System.IO.File]::WriteAllText($hashPath, "$hash  $([IO.Path]::GetFileName($output))`r`n", (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "MSIX:   $output"
Write-Host "SHA256: $hash"
if (-not $CertThumbprint) {
    Write-Host "Signing: skipped (expected for Partner Center Store submission; use -CertThumbprint for local install testing)."
}
Write-Host "Run Windows App Certification Kit before submission."
