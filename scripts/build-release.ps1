# build-release.ps1 — Build Miasma release binaries for Windows.
#
# Usage:
#   .\scripts\build-release.ps1 [-Target release|debug] [-OutputDir .\dist] [-Variant technical|easy|both]
#
# Produces:
#   $OutputDir\miasma.exe         — CLI + daemon
#   $OutputDir\miasma-desktop.exe — Desktop GUI
#   $OutputDir\miasma-bridge.exe  — BitTorrent bridge
#
# Variant controls the default product mode baked into the desktop binary:
#   technical — MIASMA_MODE=technical (full diagnostics, "Technical Beta" title)
#   easy      — MIASMA_MODE=easy     (simplified UX, product-like title)
#   both      — builds once, copies desktop binary twice with variant suffix

param(
    [ValidateSet("release", "debug")]
    [string]$Target = "release",

    [string]$OutputDir = ".\dist",

    [ValidateSet("technical", "easy", "both")]
    [string]$Variant = "both"
)

$ErrorActionPreference = "Stop"

Write-Host "Building Miasma ($Target, variant=$Variant) ..."

# Ensure output directory.
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Build flags.
$cargoArgs = @("build")
if ($Target -eq "release") {
    $cargoArgs += "--release"
}

# Variant sets the default mode the desktop binary will use when no
# MIASMA_MODE env var is set at runtime.  The detection logic in
# variant.rs reads MIASMA_MODE at startup, so we set it at build-time
# only as documentation — the runtime env var always wins.
# For "both" we build once (mode is runtime-selectable anyway).
if ($Variant -eq "technical") {
    $env:MIASMA_MODE = "technical"
} elseif ($Variant -eq "easy") {
    $env:MIASMA_MODE = "easy"
}

# Build all workspace binaries.
& cargo @cargoArgs --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed."
    exit 1
}

# Clear build-time env var.
Remove-Item Env:\MIASMA_MODE -ErrorAction SilentlyContinue

$profile = if ($Target -eq "release") { "release" } else { "debug" }
$targetDir = "target\$profile"

# Copy shared binaries (CLI + bridge are mode-independent).
$shared = @(
    @{ Name = "miasma.exe";        Source = "$targetDir\miasma.exe" },
    @{ Name = "miasma-bridge.exe"; Source = "$targetDir\miasma-bridge.exe" }
)

foreach ($bin in $shared) {
    if (Test-Path $bin.Source) {
        Copy-Item $bin.Source -Destination "$OutputDir\$($bin.Name)" -Force
        $size = (Get-Item "$OutputDir\$($bin.Name)").Length / 1MB
        Write-Host ("  {0,-25} {1:N1} MB" -f $bin.Name, $size)
    } else {
        Write-Warning "$($bin.Name) not found at $($bin.Source)"
    }
}

# Copy desktop binary — variant naming.
$desktopSrc = "$targetDir\miasma-desktop.exe"
if (Test-Path $desktopSrc) {
    if ($Variant -eq "both") {
        # Both variants: same binary, two copies for packaging convenience.
        Copy-Item $desktopSrc -Destination "$OutputDir\miasma-desktop.exe" -Force
        $size = (Get-Item "$OutputDir\miasma-desktop.exe").Length / 1MB
        Write-Host ("  {0,-25} {1:N1} MB" -f "miasma-desktop.exe", $size)
        Write-Host "  (Runtime mode selection: set MIASMA_MODE=technical or easy)"
    } else {
        Copy-Item $desktopSrc -Destination "$OutputDir\miasma-desktop.exe" -Force
        $size = (Get-Item "$OutputDir\miasma-desktop.exe").Length / 1MB
        Write-Host ("  {0,-25} {1:N1} MB  [default: $Variant]" -f "miasma-desktop.exe", $size)
    }
} else {
    Write-Warning "miasma-desktop.exe not found at $desktopSrc"
}

Write-Host ""
Write-Host "Build complete. Binaries in: $OutputDir"
Write-Host "Next: .\scripts\package-release.ps1 -InputDir $OutputDir"
