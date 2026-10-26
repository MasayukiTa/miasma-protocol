<#
.SYNOPSIS
    Shows, on this computer, that Windows Installer ignores the fourth field of
    ProductVersion when it decides about an upgrade (why scripts\windows-version.ps1
    puts the pre-release rank into the THIRD field).

.DESCRIPTION
    Builds four MSI files from the programs in -InputDir, with ProductVersion
    0.3.2.1, 0.3.2.2, 0.3.2012 and 0.3.2013, and installs them in pairs:
      pair A (differ only in the 4th field): the second install does NOT replace the first
      pair B (differ in the 3rd field)     : the second install replaces the first
    Needs an elevated prompt, WiX v6 on PATH and no Miasma installed. Everything
    it installs is removed again. Exit code 0 when both pairs behave as described.

.PARAMETER InputDir
    Directory with miasma.exe, miasma-desktop.exe and miasma-bridge.exe.
#>

param(
    [string]$InputDir = ".\dist",
    [string]$WorkDir = ".\out-proof"
)

$ErrorActionPreference = "Stop"
$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$InputDir = (Resolve-Path $InputDir).Path
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$WorkDir = (Resolve-Path $WorkDir).Path
$UpgradeCode = "{E8A3F0C1-7B2D-4E56-9A1F-3C8D5E7F0B12}"

function Get-Products {
    $inst = New-Object -ComObject WindowsInstaller.Installer
    $codes = @()
    try { $codes = @($inst.RelatedProducts($UpgradeCode)) } catch { $codes = @() }
    foreach ($c in $codes) { [PSCustomObject]@{ Code = $c; Version = $inst.ProductInfo($c, "VersionString") } }
}

function Build-Msi([string]$ver) {
    $out = Join-Path $WorkDir "proof-$ver.msi"
    Push-Location $REPO
    try {
        & wix build installer\miasma.wxs -o $out -d "Version=$ver" -d "BinDir=$InputDir" -ext WixToolset.UI.wixext -arch x64
        if ($LASTEXITCODE -ne 0) { throw "wix build failed for $ver" }
    } finally { Pop-Location }
    return $out
}

function Install-Msi([string]$msi) {
    $log = $msi + ".log"
    $p = Start-Process msiexec.exe -ArgumentList @("/i", "`"$msi`"", "/qn", "/norestart", "/l*v", "`"$log`"") -Wait -PassThru
    return $p.ExitCode
}

function Remove-All {
    foreach ($p in @(Get-Products)) {
        Start-Process msiexec.exe -ArgumentList @("/x", $p.Code, "/qn", "/norestart") -Wait | Out-Null
    }
}

if (@(Get-Products).Count -gt 0) { Write-Host "A Miasma MSI product is already installed; stopping." -ForegroundColor Red; exit 2 }

$ok = $true
try {
    foreach ($pair in @(
            @{ Name = "A (4th field differs)"; V1 = "0.3.2.1"; V2 = "0.3.2.2"; ExpectReplaced = $false },
            @{ Name = "B (3rd field differs)"; V1 = "0.3.2012"; V2 = "0.3.2013"; ExpectReplaced = $true })) {
        Write-Host ""
        Write-Host "== Pair $($pair.Name): $($pair.V1) then $($pair.V2)"
        $m1 = Build-Msi $pair.V1
        $m2 = Build-Msi $pair.V2
        $rc1 = Install-Msi $m1
        Write-Host "  install $($pair.V1): exit code $rc1"
        $rc2 = Install-Msi $m2
        Write-Host "  install $($pair.V2): exit code $rc2"
        $now = @(Get-Products)
        Write-Host ("  installed products with Miasma's upgrade code: " + $now.Count + " -> " + (($now | ForEach-Object { $_.Version }) -join ", "))
        $versions = @($now | ForEach-Object { $_.Version })
        if ($pair.ExpectReplaced) {
            $pass = ($now.Count -eq 1) -and ($versions[0] -eq $pair.V2)
        } else {
            # The second package was not treated as a newer version of the first.
            $pass = -not (($now.Count -eq 1) -and ($versions[0] -eq $pair.V2))
        }
        if ($pass) { Write-Host "  PASS: behaves as documented (replaced = $($pair.ExpectReplaced))" -ForegroundColor Green }
        else { Write-Host "  FAIL: unexpected result" -ForegroundColor Red; $ok = $false }
        Remove-All
        Write-Host "  after cleanup: $(@(Get-Products).Count) product(s)"
    }
} finally {
    Remove-All
}
if ($ok) { exit 0 } else { exit 1 }
