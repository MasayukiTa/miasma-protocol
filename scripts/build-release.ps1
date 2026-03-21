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
# The -Variant parameter is passed through to package-release.ps1 and controls
# which launchers and README are included in the release package.
# The compiled binary is identical for all variants — mode is selected at
# runtime via launcher scripts, persisted settings, or --mode argument.

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

# Mode selection is entirely runtime — the same binary serves both variants.
# The -Variant parameter controls packaging (which launchers and READMEs
# are included), not the compiled binary itself.
# Build once; variant distinction comes from launcher scripts and persisted prefs.

# Build all workspace binaries.
& cargo @cargoArgs --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed."
    exit 1
}

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

# Copy desktop binary (same binary for all variants — mode is runtime).
$desktopSrc = "$targetDir\miasma-desktop.exe"
if (Test-Path $desktopSrc) {
    Copy-Item $desktopSrc -Destination "$OutputDir\miasma-desktop.exe" -Force
    $size = (Get-Item "$OutputDir\miasma-desktop.exe").Length / 1MB
    Write-Host ("  {0,-25} {1:N1} MB" -f "miasma-desktop.exe", $size)
} else {
    Write-Warning "miasma-desktop.exe not found at $desktopSrc"
}

# Copy variant launcher scripts.
$launcherDir = Join-Path $PSScriptRoot "launchers"
if (Test-Path $launcherDir) {
    Copy-Item (Join-Path $launcherDir "Miasma.cmd") -Destination $OutputDir -Force
    Copy-Item (Join-Path $launcherDir "Miasma Technical.cmd") -Destination $OutputDir -Force
    Write-Host "  Launchers:              Miasma.cmd, Miasma Technical.cmd"
}

Write-Host ""
Write-Host "Build complete. Binaries in: $OutputDir"
Write-Host "Next: .\scripts\package-release.ps1 -InputDir $OutputDir"
