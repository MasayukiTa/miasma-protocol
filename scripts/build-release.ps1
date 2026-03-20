# build-release.ps1 — Build Miasma release binaries for Windows.
#
# Usage:
#   .\scripts\build-release.ps1 [-Target release|debug] [-OutputDir .\dist]
#
# Produces:
#   $OutputDir\miasma.exe         — CLI + daemon
#   $OutputDir\miasma-desktop.exe — Desktop GUI
#   $OutputDir\miasma-bridge.exe  — BitTorrent bridge

param(
    [ValidateSet("release", "debug")]
    [string]$Target = "release",

    [string]$OutputDir = ".\dist"
)

$ErrorActionPreference = "Stop"

Write-Host "Building Miasma ($Target) ..."

# Ensure output directory.
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Build flags.
$cargoArgs = @("build")
if ($Target -eq "release") {
    $cargoArgs += "--release"
}

# Build all workspace binaries.
& cargo @cargoArgs --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed."
    exit 1
}

$profile = if ($Target -eq "release") { "release" } else { "debug" }
$targetDir = "target\$profile"

# Copy binaries.
$binaries = @(
    @{ Name = "miasma.exe";         Source = "$targetDir\miasma.exe" },
    @{ Name = "miasma-desktop.exe"; Source = "$targetDir\miasma-desktop.exe" },
    @{ Name = "miasma-bridge.exe";  Source = "$targetDir\miasma-bridge.exe" }
)

foreach ($bin in $binaries) {
    if (Test-Path $bin.Source) {
        Copy-Item $bin.Source -Destination "$OutputDir\$($bin.Name)" -Force
        $size = (Get-Item "$OutputDir\$($bin.Name)").Length / 1MB
        Write-Host ("  {0,-25} {1:N1} MB" -f $bin.Name, $size)
    } else {
        Write-Warning "$($bin.Name) not found at $($bin.Source)"
    }
}

Write-Host ""
Write-Host "Build complete. Binaries in: $OutputDir"
Write-Host "Next: .\scripts\package-release.ps1 -InputDir $OutputDir"
