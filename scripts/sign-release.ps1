# sign-release.ps1 — Stub for signing Miasma release artifacts.
#
# Usage:
#   .\scripts\sign-release.ps1 <path-to-zip>
#
# This is a placeholder. When a code-signing certificate is available,
# this script should:
#   1. Authenticode-sign each .exe with signtool.exe
#   2. Compute SHA-256 checksums
#   3. Optionally GPG-sign the .zip

param(
    [Parameter(Mandatory)]
    [string]$ZipPath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ZipPath)) {
    Write-Error "File not found: $ZipPath"
    exit 1
}

Write-Host "Sign stub for: $ZipPath"
Write-Host ""

# SHA-256 checksum.
$hash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash
$checksumFile = "$ZipPath.sha256"
"$hash  $(Split-Path -Leaf $ZipPath)" | Set-Content $checksumFile
Write-Host "SHA-256: $hash"
Write-Host "Written: $checksumFile"
Write-Host ""
Write-Host "NOTE: Authenticode signing not yet configured."
Write-Host "      To sign, install a code-signing cert and update this script"
Write-Host "      to call: signtool sign /fd SHA256 /tr <timestamp-url> <exe>"
