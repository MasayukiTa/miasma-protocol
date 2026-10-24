# test-windows-version.ps1 -- checks the version mapping in windows-version.ps1.
# Exit code 0 when every check passes.

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\windows-version.ps1"

$fail = 0
function Check($name, $ok) {
    if ($ok) { Write-Host "  PASS: $name" } else { Write-Host "  FAIL: $name"; $script:fail++ }
}

# Strictly increasing release order. Each pair must compare "less" using ONLY the
# first three fields of the MSI version (what Windows Installer looks at).
$order = @("0.3.2-beta.1", "0.3.2-beta.11", "0.3.2-beta.12", "0.3.2-beta.13",
           "0.3.2-rc.1", "0.3.2-rc.2", "0.3.2", "0.3.3-beta.1", "0.3.3", "0.4.0-beta.1")
$maps = $order | ForEach-Object { ConvertTo-MiasmaWindowsVersion $_ }

Write-Host "Mapping table:"
$maps | ForEach-Object { Write-Host ("  {0,-16} MSI {1,-10} bundle {2}" -f $_.Semver, $_.MsiVersion, $_.BundleVersion) }

for ($i = 0; $i -lt $maps.Count - 1; $i++) {
    $a = $maps[$i]; $b = $maps[$i + 1]
    Check "$($a.Semver) < $($b.Semver) by MSI (3 fields)" ((Compare-MsiVersion $a.MsiVersion $b.MsiVersion) -lt 0)
    Check "$($a.Semver) < $($b.Semver) by bundle (4 fields)" ([version]$a.BundleVersion -lt [version]$b.BundleVersion)
}

Check "leading v accepted" ((ConvertTo-MiasmaWindowsVersion "v0.3.2-beta.12").MsiVersion -eq "0.3.2012")
Check "beta.12 -> 0.3.2012 / 0.3.2.12" ((ConvertTo-MiasmaWindowsVersion "0.3.2-beta.12").BundleVersion -eq "0.3.2.12")
Check "final -> 0.3.2999" ((ConvertTo-MiasmaWindowsVersion "0.3.2").MsiVersion -eq "0.3.2999")
Check "fourth MSI field is not used" (-not ((ConvertTo-MiasmaWindowsVersion "0.3.2-beta.12").MsiVersion -match '^\d+\.\d+\.\d+\.\d+$'))

foreach ($bad in @("0.3.2-alpha.1", "0.3.2-beta", "0.3.2-beta.0", "0.3.2-beta.900", "0.3.66", "256.0.0", "0.3", "abc", "0.3.2-beta.01")) {
    $threw = $false
    try { ConvertTo-MiasmaWindowsVersion $bad | Out-Null } catch { $threw = $true }
    Check "rejects '$bad'" $threw
}

if ($fail -gt 0) { Write-Host "$fail check(s) failed"; exit 1 }
Write-Host "All version checks passed"
exit 0
