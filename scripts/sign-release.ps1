<#
.SYNOPSIS
    Sign and checksum Miasma release artifacts for public distribution.

.DESCRIPTION
    Three-stage signing pipeline:
      1. Authenticode-sign each .exe (if signtool.exe and certificate are available)
      2. Compute per-file SHA-256 checksums
      3. Optionally GPG-sign the .zip archive

    Without a code-signing certificate, stages 1 and 3 are skipped gracefully
    and the script still produces valid checksums.

.PARAMETER ZipPath
    Path to the release .zip file (e.g. .\dist\miasma-0.2.0-windows-x64.zip).

.PARAMETER CertThumbprint
    SHA-1 thumbprint of the Authenticode code-signing certificate in the
    Windows certificate store. Optional — if omitted, Authenticode signing
    is skipped with a warning.

.PARAMETER TimestampUrl
    RFC 3161 timestamp server URL. Default: http://timestamp.digicert.com

.PARAMETER GpgSign
    If set, GPG-sign the .zip producing a .zip.asc detached signature.

.PARAMETER GpgKeyId
    GPG key ID to sign with. If omitted, GPG uses its default key.

.EXAMPLE
    # Checksum only (no cert):
    .\scripts\sign-release.ps1 .\dist\miasma-0.2.0-windows-x64.zip

    # Full signing with Authenticode + GPG:
    .\scripts\sign-release.ps1 .\dist\miasma-0.2.0-windows-x64.zip `
        -CertThumbprint "A1B2C3..." -GpgSign
#>

param(
    [Parameter(Mandatory)]
    [string]$ZipPath,

    [string]$CertThumbprint = "",

    [string]$TimestampUrl = "http://timestamp.digicert.com",

    [switch]$GpgSign,

    [string]$GpgKeyId = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ZipPath)) {
    Write-Error "File not found: $ZipPath"
    exit 1
}

$zipDir = Split-Path -Parent $ZipPath
$warnings = @()

Write-Host "=== Miasma Release Signing ===" -ForegroundColor Cyan
Write-Host "Artifact: $ZipPath"
Write-Host ""

# ── Stage 1: Authenticode signing ────────────────────────────────────────────

Write-Host "[1/3] Authenticode signing" -ForegroundColor Yellow

# Find signtool.exe.
$signtool = $null
$sdkPaths = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
    "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
)
foreach ($pattern in $sdkPaths) {
    $found = Get-Item $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if ($found) { $signtool = $found.FullName; break }
}

if ($CertThumbprint -and $signtool) {
    # Unzip, sign each .exe, re-zip.
    $tempExtract = Join-Path $zipDir "sign-staging-$(Get-Random)"
    Expand-Archive -Path $ZipPath -DestinationPath $tempExtract -Force

    $exes = Get-ChildItem -Path $tempExtract -Filter "*.exe" -Recurse
    foreach ($exe in $exes) {
        Write-Host "  Signing: $($exe.Name)"
        & $signtool sign /fd SHA256 /sha1 $CertThumbprint /tr $TimestampUrl /td SHA256 $exe.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Error "signtool failed for $($exe.Name)"
            exit 1
        }

        # Verify signature.
        & $signtool verify /pa $exe.FullName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Signature verification failed for $($exe.Name)"
            exit 1
        }
        Write-Host "  Verified: $($exe.Name)" -ForegroundColor Green
    }

    # Re-create zip with signed binaries.
    Remove-Item $ZipPath -Force
    Compress-Archive -Path "$tempExtract\*" -DestinationPath $ZipPath -Force
    Remove-Item -Recurse -Force $tempExtract
    Write-Host "  Re-packaged with signed binaries." -ForegroundColor Green
} else {
    if (-not $CertThumbprint) {
        $warnings += "No -CertThumbprint provided — Authenticode signing skipped."
        Write-Host "  SKIPPED: No certificate thumbprint provided." -ForegroundColor DarkYellow
    }
    if (-not $signtool) {
        $warnings += "signtool.exe not found — install Windows SDK to enable Authenticode signing."
        Write-Host "  SKIPPED: signtool.exe not found (install Windows SDK)." -ForegroundColor DarkYellow
    }
}
Write-Host ""

# ── Stage 2: SHA-256 checksums ───────────────────────────────────────────────

Write-Host "[2/3] SHA-256 checksums" -ForegroundColor Yellow

# Checksum the zip itself.
$zipHash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash
$checksumFile = "$ZipPath.sha256"
$checksumLines = @("$zipHash  $(Split-Path -Leaf $ZipPath)")

# Also checksum individual binaries inside the zip for verification.
$tempVerify = Join-Path $zipDir "checksum-staging-$(Get-Random)"
Expand-Archive -Path $ZipPath -DestinationPath $tempVerify -Force
$innerFiles = Get-ChildItem -Path $tempVerify -File -Recurse | Where-Object { $_.Extension -in ".exe", ".txt" }
foreach ($f in $innerFiles) {
    $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    $checksumLines += "$h  $($f.Name)"
    Write-Host "  $($f.Name): $h"
}
Remove-Item -Recurse -Force $tempVerify

$checksumLines | Set-Content $checksumFile
Write-Host "  Written: $checksumFile" -ForegroundColor Green
Write-Host ""

# ── Stage 3: GPG signature ──────────────────────────────────────────────────

Write-Host "[3/3] GPG signature" -ForegroundColor Yellow

if ($GpgSign) {
    $gpgCmd = Get-Command gpg -ErrorAction SilentlyContinue
    if ($gpgCmd) {
        $gpgArgs = @("--detach-sign", "--armor", "--output", "$ZipPath.asc")
        if ($GpgKeyId) { $gpgArgs += @("--local-user", $GpgKeyId) }
        $gpgArgs += $ZipPath

        & gpg @gpgArgs
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  GPG signature: $ZipPath.asc" -ForegroundColor Green

            # Verify.
            & gpg --verify "$ZipPath.asc" $ZipPath
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  GPG signature verified." -ForegroundColor Green
            } else {
                Write-Warning "GPG verification failed."
            }
        } else {
            Write-Error "GPG signing failed."
            exit 1
        }
    } else {
        $warnings += "gpg not found on PATH — GPG signing skipped."
        Write-Host "  SKIPPED: gpg not found on PATH." -ForegroundColor DarkYellow
    }
} else {
    Write-Host "  SKIPPED: Use -GpgSign to enable." -ForegroundColor DarkYellow
}
Write-Host ""

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host "=== Signing Complete ===" -ForegroundColor Cyan
Write-Host "  Archive:  $ZipPath"
Write-Host "  Checksum: $checksumFile"
if (Test-Path "$ZipPath.asc") {
    Write-Host "  GPG sig:  $ZipPath.asc"
}

if ($warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor DarkYellow
    foreach ($w in $warnings) {
        Write-Host "  - $w" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "Verification command:"
Write-Host "  Get-Content $checksumFile | ForEach-Object { `$h, `$f = `$_ -split '  '; if ((Get-FileHash `$f -Algorithm SHA256).Hash -eq `$h) { Write-Host `"OK: `$f`" -ForegroundColor Green } else { Write-Host `"MISMATCH: `$f`" -ForegroundColor Red } }"
