<#
.SYNOPSIS
    List the DLLs that the Miasma programs load and say which ones the
    installer has to provide.

.DESCRIPTION
    Runs `dumpbin /dependents` (from the Visual Studio build tools) on each
    program in a directory and sorts every dependency into one of:
      - system     : found in System32 (always present on Windows 10 and later)
      - vc-runtime : the Visual C++ 2015-2022 runtime (vcruntime140.dll, ...);
                     the Setup EXE installs the Microsoft redistributable for it
      - missing    : not in System32 and not next to the program -> FAIL
    Exit code 1 when anything is missing, or when dumpbin cannot be found and
    -Require is set.

.PARAMETER Dir
    Directory that holds miasma.exe, miasma-desktop.exe and miasma-bridge.exe.

.PARAMETER Require
    Fail (instead of warn) when dumpbin.exe is not available.
#>

param(
    [string]$Dir = ".\dist",
    [switch]$Require
)

$ErrorActionPreference = "Stop"

function Find-Dumpbin {
    $cmd = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * -find "VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe" | Select-Object -First 1
        if ($found) { return $found }
    }
    return $null
}

$dumpbin = Find-Dumpbin
if (-not $dumpbin) {
    $msg = "dumpbin.exe not found (install the Visual Studio C++ build tools)."
    if ($Require) { Write-Host "FAIL: $msg" -ForegroundColor Red; exit 1 }
    Write-Warning $msg
    exit 0
}
Write-Host "dumpbin: $dumpbin"

$sys32 = Join-Path $env:WINDIR "System32"
$vcPattern = '^(vcruntime140|vcruntime140_1|msvcp140|msvcp140_1|msvcp140_2|concrt140|vcomp140)(_\w+)?\.dll$'
$failed = $false
$needsVc = $false

foreach ($name in @("miasma.exe", "miasma-desktop.exe", "miasma-bridge.exe")) {
    $path = Join-Path $Dir $name
    if (-not (Test-Path $path)) { Write-Host "FAIL: $name not found in $Dir" -ForegroundColor Red; $failed = $true; continue }

    $out = & $dumpbin /nologo /dependents $path
    if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: dumpbin failed on $name" -ForegroundColor Red; $failed = $true; continue }

    # The dependent DLL names are the indented lines between the header and "Summary".
    $dlls = @()
    $inList = $false
    foreach ($line in $out) {
        if ($line -match 'Image has the following dependencies') { $inList = $true; continue }
        if ($line -match '^\s*Summary') { break }
        if ($inList -and $line -match '^\s+(\S+\.dll)\s*$') { $dlls += $Matches[1] }
    }

    Write-Host ""
    Write-Host "$name ($($dlls.Count) dependencies)"
    foreach ($dll in ($dlls | Sort-Object)) {
        $lower = $dll.ToLowerInvariant()
        if ($lower -match $vcPattern) {
            $needsVc = $true
            Write-Host ("  {0,-34} vc-runtime (installed by Setup)" -f $dll)
        } elseif ($lower -like "api-ms-win-*" -or $lower -like "ext-ms-win-*") {
            Write-Host ("  {0,-34} system (API set)" -f $dll)
        } elseif (Test-Path (Join-Path $sys32 $dll)) {
            Write-Host ("  {0,-34} system" -f $dll)
        } elseif (Test-Path (Join-Path $Dir $dll)) {
            Write-Host ("  {0,-34} next to the program" -f $dll)
        } else {
            Write-Host ("  {0,-34} MISSING" -f $dll) -ForegroundColor Red
            $failed = $true
        }
    }
}

Write-Host ""
if ($needsVc) {
    Write-Host "The programs link the Visual C++ runtime dynamically; Miasma-Setup-<version>-x64.exe installs the Microsoft redistributable when it is missing."
} else {
    Write-Host "The programs do not depend on the Visual C++ runtime."
}
if ($failed) { Write-Host "RESULT: FAIL" -ForegroundColor Red; exit 1 }
Write-Host "RESULT: OK"
exit 0
