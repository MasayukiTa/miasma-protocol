<#
.SYNOPSIS
    End-to-end smoke test of the Miasma Windows installer (Setup EXE).

.DESCRIPTION
    Phase 1, clean install:
      silent install -> program files and docs are in place -> the desktop app
      starts with a throwaway data directory -> the background service (daemon)
      comes up (daemon.port written, `miasma.exe status` answers) -> the desktop
      window process stays alive -> stop everything -> silent uninstall removes
      the files and the Programs and Features entry but leaves the data
      directory alone.
    Phase 2, upgrade (when -OldSetupExe is given):
      install the older Setup -> install the current Setup -> the older version
      is replaced and exactly one entry remains. With -NextSetupExe, a later
      release (for example the final release after a beta) is installed over the
      current one the same way. Finally the older Setup is run again to see
      that it does not downgrade.

    The data directory is always a new temporary directory passed with
    --data-dir; the real profile is never touched. Needs an elevated prompt
    (the installer installs for all users). The script refuses to run when a
    Miasma install already exists, so it cannot replace a real install.

.PARAMETER SetupExe
    The Setup EXE under test (Miasma-Setup-<version>-x64.exe).

.PARAMETER OldSetupExe
    A Setup EXE with a LOWER version (same programs are fine). Enables phase 2.

.PARAMETER NextSetupExe
    A Setup EXE with a HIGHER version than SetupExe (for example the final
    release built from the same programs).

.PARAMETER AliveSeconds
    How long the desktop window process must stay alive after the daemon is up.

.PARAMETER LogDir
    Where installer logs are written. Default: .\smoke-logs

.PARAMETER ChainSetupExes
    Setup EXEs in increasing version order (for example beta.11, beta.12, beta.13,
    final). Each is installed over the one before; every step must leave exactly
    one entry at the new version.

.PARAMETER SoftwareGlDir
    TEST ONLY. The desktop window needs OpenGL 2.0 or later. A CI runner has no
    graphics driver, so it only has OpenGL 1.1 and the window cannot open. Give a
    folder with a software OpenGL (Mesa llvmpipe: opengl32.dll, libgallium_wgl.dll,
    libglapi.dll). Those files are copied next to miasma-desktop.exe for the launch
    test and removed again before the uninstall. Not needed on a computer with a
    normal graphics driver.

.PARAMETER ExpectedVersion
    Release version the programs were built with (for example 0.3.2-beta.12).
    When given, `miasma.exe --version` must contain it.

.EXAMPLE
    .\scripts\smoke-windows-installer.ps1 -SetupExe .\dist\Miasma-Setup-0.3.2-beta.12-x64.exe
#>

param(
    [Parameter(Mandatory = $true)][string]$SetupExe,
    [string]$OldSetupExe = "",
    [string]$NextSetupExe = "",
    [int]$AliveSeconds = 15,
    [string]$LogDir = ".\smoke-logs",
    [string]$ExpectedVersion = "",
    [string]$SoftwareGlDir = "",
    [string[]]$ChainSetupExes = @()
)

$ErrorActionPreference = "Continue"
$script:passed = 0
$script:failed = 0
$script:dataDir = $null
$script:desktopProc = $null
$script:glFiles = @()

$InstallDir = Join-Path $env:ProgramFiles "Miasma Protocol"
$MsiUpgradeCode = "{E8A3F0C1-7B2D-4E56-9A1F-3C8D5E7F0B12}"

function Step($t) { Write-Host ""; Write-Host "== $t" -ForegroundColor Cyan }
function Pass($n) { Write-Host "  PASS: $n" -ForegroundColor Green; $script:passed++ }
function Fail($n, $d) { Write-Host "  FAIL: $n -- $d" -ForegroundColor Red; $script:failed++ }
function Check($n, $ok, $detail) { if ($ok) { Pass $n } else { Fail $n $detail } }

# -- helpers -------------------------------------------------------------------

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Programs and Features entries for Miasma: name, version, and whether it is a
# hidden "system component" entry.
function Get-ArpEntries {
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        foreach ($k in Get-ChildItem $r -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -like "Miasma Protocol*") {
                [PSCustomObject]@{
                    Key = $k.PSChildName; Name = $p.DisplayName; Version = $p.DisplayVersion
                    Hidden = ($p.SystemComponent -eq 1); Msi = ($p.WindowsInstaller -eq 1)
                }
            }
        }
    }
}

# Installed MSI products that share Miasma's upgrade code: product code and version.
function Get-MsiProducts {
    $inst = New-Object -ComObject WindowsInstaller.Installer
    $codes = @()
    try { $codes = @($inst.RelatedProducts($MsiUpgradeCode)) } catch { $codes = @() }
    foreach ($c in $codes) {
        [PSCustomObject]@{ ProductCode = $c; Version = $inst.ProductInfo($c, "VersionString") }
    }
}

# The installer appends the folder with a trailing backslash; ignore that.
function Test-InMachinePath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $want = $InstallDir.TrimEnd('\')
    foreach ($p in ($machinePath -split ';')) { if ($p.TrimEnd('\') -eq $want) { return $true } }
    return $false
}

function Show-State($label) {
    Write-Host "  [$label] Programs and Features entries:"
    $e = @(Get-ArpEntries)
    if ($e.Count -eq 0) { Write-Host "    (none)" }
    $e | ForEach-Object { Write-Host ("    {0}  {1}  version {2}  hidden={3}  msi={4}" -f $_.Key, $_.Name, $_.Version, $_.Hidden, $_.Msi) }
    $m = @(Get-MsiProducts)
    Write-Host "  [$label] MSI products with Miasma's upgrade code: $($m.Count)"
    $m | ForEach-Object { Write-Host ("    {0}  version {1}" -f $_.ProductCode, $_.Version) }
}

function Invoke-Setup([string]$Exe, [string[]]$SetupArgs, [string]$Tag) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $log = Join-Path (Resolve-Path $LogDir) "$Tag.log"
    $all = @($SetupArgs) + @("/quiet", "/norestart", "/log", "`"$log`"")
    Write-Host "  running: $(Split-Path -Leaf $Exe) $($all -join ' ')"
    $p = Start-Process -FilePath $Exe -ArgumentList $all -PassThru
    if (-not $p.WaitForExit(900000)) { Stop-Process -Id $p.Id -Force; return -999 }
    return $p.ExitCode
}

function Stop-MiasmaForDataDir {
    # Stop only the processes that belong to this test's data directory.
    if ($script:desktopProc -and -not $script:desktopProc.HasExited) {
        try { $null = $script:desktopProc.CloseMainWindow() } catch {}
        Start-Sleep -Seconds 2
        if (-not $script:desktopProc.HasExited) { Stop-Process -Id $script:desktopProc.Id -Force -ErrorAction SilentlyContinue }
    }
    $script:desktopProc = $null
    if (-not $script:dataDir) { return }
    foreach ($proc in @(Get-CimInstance Win32_Process -Filter "Name='miasma.exe' OR Name='miasma-desktop.exe' OR Name='miasma-bridge.exe'")) {
        if ($proc.CommandLine -and $proc.CommandLine.Contains($script:dataDir)) {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 2
}

function Wait-Until([scriptblock]$Cond, [int]$Seconds) {
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) { if (& $Cond) { return $true }; Start-Sleep -Milliseconds 500 }
    return [bool](& $Cond)
}

function Uninstall-Current([string]$Exe, [string]$Tag) {
    $rc = Invoke-Setup $Exe @("/uninstall") $Tag
    Check "uninstall exit code ($Tag)" (($rc -eq 0) -or ($rc -eq 3010)) "exit code $rc"
}

function Assert-InstallLayout([string]$Tag) {
    foreach ($f in @("miasma-desktop.exe", "miasma.exe", "miasma-bridge.exe", "docs\README.txt", "docs\RELEASE-NOTES.md")) {
        Check "$Tag installed file: $f" (Test-Path (Join-Path $InstallDir $f)) "missing under $InstallDir"
    }
    # The desktop app looks for its background service next to itself.
    $dd = (Get-Item (Join-Path $InstallDir "miasma-desktop.exe") -ErrorAction SilentlyContinue).DirectoryName
    $dm = (Get-Item (Join-Path $InstallDir "miasma.exe") -ErrorAction SilentlyContinue).DirectoryName
    Check "$Tag miasma.exe sits next to miasma-desktop.exe" ($dd -and ($dd -eq $dm)) "desktop='$dd' daemon='$dm'"
    Check "$Tag install dir is on the machine PATH" (Test-InMachinePath) "not found in machine PATH"
    $lnk = Join-Path ([Environment]::GetFolderPath("CommonPrograms")) "Miasma Protocol\Miasma.lnk"
    Check "$Tag Start menu shortcut" (Test-Path $lnk) "missing $lnk"
}

function Assert-SingleEntry([string]$Tag, [string]$ExpectedBundleVersion) {
    $visible = @(Get-ArpEntries | Where-Object { -not $_.Hidden })
    Check "$Tag exactly one visible Programs and Features entry" ($visible.Count -eq 1) "found $($visible.Count)"
    if ($ExpectedBundleVersion -and $visible.Count -eq 1) {
        Check "$Tag entry version is $ExpectedBundleVersion" ($visible[0].Version -eq $ExpectedBundleVersion) "found $($visible[0].Version)"
    }
    $msi = @(Get-MsiProducts)
    Check "$Tag exactly one MSI product with Miasma's upgrade code" ($msi.Count -eq 1) "found $($msi.Count)"
}

# Version string a Setup EXE will install (read from the file's product version).
function Get-SetupVersion([string]$Exe) {
    (Get-Item $Exe).VersionInfo.ProductVersion
}

# -- start ---------------------------------------------------------------------

if (-not (Test-Admin)) { Write-Host "Run this script from an elevated PowerShell." -ForegroundColor Red; exit 2 }
foreach ($f in @($SetupExe, $OldSetupExe, $NextSetupExe)) {
    if ($f -and -not (Test-Path $f)) { Write-Host "File not found: $f" -ForegroundColor Red; exit 2 }
}
$SetupExe = (Resolve-Path $SetupExe).Path
if ($OldSetupExe) { $OldSetupExe = (Resolve-Path $OldSetupExe).Path }
if ($NextSetupExe) { $NextSetupExe = (Resolve-Path $NextSetupExe).Path }

if ((Test-Path $InstallDir) -or @(Get-ArpEntries).Count -gt 0 -or @(Get-MsiProducts).Count -gt 0) {
    Write-Host "A Miasma install already exists on this computer. This test would replace it, so it stops here." -ForegroundColor Red
    Show-State "found"
    exit 2
}

$script:dataDir = Join-Path ([System.IO.Path]::GetTempPath()) ("miasma-smoke-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $script:dataDir | Out-Null
Write-Host "Setup under test: $SetupExe"
Write-Host "Throwaway data directory: $($script:dataDir)"

try {
    # ===== Phase 1: clean install -> launch -> uninstall ======================
    Step "Phase 1: clean silent install"
    $rc = Invoke-Setup $SetupExe @("/install") "install-current"
    Check "install exit code" (($rc -eq 0) -or ($rc -eq 3010)) "exit code $rc"
    Show-State "after install"
    Assert-InstallLayout "clean"
    Assert-SingleEntry "clean" $null

    Step "Phase 1: programs run"
    $cli = Join-Path $InstallDir "miasma.exe"
    $desktop = Join-Path $InstallDir "miasma-desktop.exe"
    $ver = (& $cli --version 2>&1 | Out-String).Trim()
    Write-Host "  miasma.exe --version: $ver"
    Check "miasma.exe --version runs" ($LASTEXITCODE -eq 0) "exit code $LASTEXITCODE"
    if ($ExpectedVersion) { Check "version output contains $ExpectedVersion" ($ver -like "*$ExpectedVersion*") "got: $ver" }
    $bridgeHelp = (& (Join-Path $InstallDir "miasma-bridge.exe") --help 2>&1 | Out-String)
    Check "miasma-bridge.exe --help runs" ($bridgeHelp.Length -gt 0) "no output"

    # Create the node in the throwaway directory (the desktop only starts the
    # service for an initialised node).
    & $cli --data-dir $script:dataDir init 2>&1 | Out-Null
    Check "miasma.exe init (throwaway data dir)" ((Test-Path (Join-Path $script:dataDir "master.key")) -and ($LASTEXITCODE -eq 0)) "exit code $LASTEXITCODE"

    Step "Phase 1: desktop app starts the background service"
    if ($SoftwareGlDir) {
        foreach ($n in @("opengl32.dll", "libgallium_wgl.dll", "libglapi.dll")) {
            $src = Join-Path $SoftwareGlDir $n
            if (Test-Path $src) { Copy-Item $src (Join-Path $InstallDir $n) -Force; $script:glFiles += $n }
        }
        Write-Host "  software OpenGL copied next to the desktop app (test only): $($script:glFiles -join ', ')"
    }
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $deskOut = Join-Path (Resolve-Path $LogDir) "desktop-stdout.txt"
    $deskErr = Join-Path (Resolve-Path $LogDir) "desktop-stderr.txt"
    $script:desktopProc = Start-Process -FilePath $desktop -ArgumentList @("--mode", "easy", "--data-dir", "`"$($script:dataDir)`"") -PassThru -RedirectStandardOutput $deskOut -RedirectStandardError $deskErr
    $portFile = Join-Path $script:dataDir "daemon.port"
    $up = Wait-Until { (Test-Path $portFile) -or $script:desktopProc.HasExited } 60
    if ($script:desktopProc.HasExited) {
        Fail "desktop stays running" "miasma-desktop.exe exited early with code $($script:desktopProc.ExitCode)"
        Write-Host "  desktop stderr:"; Get-Content $deskErr -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" }
        Write-Host "  desktop stdout:"; Get-Content $deskOut -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" }
        Write-Host "  session: $([Diagnostics.Process]::GetCurrentProcess().SessionId); display adapters:"
        Get-CimInstance Win32_VideoController | ForEach-Object { Write-Host "    $($_.Name) driver $($_.DriverVersion)" }
        Write-Host "  recent application errors mentioning miasma:"
        Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match "miasma" } | Select-Object -First 3 |
            ForEach-Object { Write-Host ("    " + (($_.Message -split "`n" | Select-Object -First 8) -join " | ")) }
    }
    Check "daemon.port written by the service the desktop started" (Test-Path $portFile) "no daemon.port within 60s"
    $svc = @(Get-CimInstance Win32_Process -Filter "Name='miasma.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($script:dataDir) -and $_.CommandLine -match "daemon" })
    Check "miasma.exe daemon process exists for the test data dir" ($svc.Count -ge 1) "none found"
    if ($svc.Count -ge 1) {
        Check "daemon runs from the install directory" ($svc[0].ExecutablePath -eq $cli) "ran from $($svc[0].ExecutablePath)"
    }
    $status = (& $cli --data-dir $script:dataDir status 2>&1 | Out-String)
    Check "miasma.exe status reaches the daemon" ($LASTEXITCODE -eq 0) "exit code $LASTEXITCODE; $status"
    Write-Host ($status.Trim() -split "`n" | Select-Object -First 6 | ForEach-Object { "    $_" } | Out-String)

    Start-Sleep -Seconds $AliveSeconds
    $alive = $script:desktopProc -and -not $script:desktopProc.HasExited
    Check "desktop process alive $AliveSeconds s after the daemon came up" $alive "exited with code $($script:desktopProc.ExitCode)"
    if ($alive) {
        $script:desktopProc.Refresh()
        Write-Host "  window title: '$($script:desktopProc.MainWindowTitle)' (handle $($script:desktopProc.MainWindowHandle))"
    }

    Step "Phase 1: stop the app and the service"
    Stop-MiasmaForDataDir
    foreach ($n in $script:glFiles) { Remove-Item (Join-Path $InstallDir $n) -Force -ErrorAction SilentlyContinue }
    $script:glFiles = @()
    $left = @(Get-CimInstance Win32_Process -Filter "Name='miasma.exe' OR Name='miasma-desktop.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($script:dataDir) })
    Check "no Miasma process left for the test data dir" ($left.Count -eq 0) "$($left.Count) left"
    Set-Content -Path (Join-Path $script:dataDir "keep-me.txt") -Value "user file" -Encoding ASCII
    $keyBefore = (Get-FileHash (Join-Path $script:dataDir "master.key") -Algorithm SHA256).Hash

    Step "Phase 1: silent uninstall"
    Uninstall-Current $SetupExe "uninstall-current"
    Show-State "after uninstall"
    Check "program files removed" (-not (Test-Path (Join-Path $InstallDir "miasma-desktop.exe"))) "miasma-desktop.exe still there"
    Check "install folder removed" (-not (Test-Path $InstallDir)) "folder still exists"
    Check "Programs and Features entry removed" (@(Get-ArpEntries).Count -eq 0) "entries remain"
    Check "no MSI product left" (@(Get-MsiProducts).Count -eq 0) "product remains"
    Check "install dir removed from the machine PATH" (-not (Test-InMachinePath)) "still in PATH"
    Check "data directory untouched (user file)" (Test-Path (Join-Path $script:dataDir "keep-me.txt")) "user file gone"
    Check "data directory untouched (master.key identical)" ((Test-Path (Join-Path $script:dataDir "master.key")) -and ((Get-FileHash (Join-Path $script:dataDir "master.key") -Algorithm SHA256).Hash -eq $keyBefore)) "key changed or gone"

    # ===== Phase 2: upgrade ===================================================
    if ($OldSetupExe) {
        Step "Phase 2: upgrade - install the older Setup"
        $oldVer = Get-SetupVersion $OldSetupExe
        $curVer = Get-SetupVersion $SetupExe
        Write-Host "  older Setup version: $oldVer; current Setup version: $curVer"
        $rc = Invoke-Setup $OldSetupExe @("/install") "upgrade-1-old"
        Check "older install exit code" (($rc -eq 0) -or ($rc -eq 3010)) "exit code $rc"
        Show-State "older installed"
        Assert-SingleEntry "older" $oldVer
        $oldMsi = @(Get-MsiProducts)[0].Version

        Step "Phase 2: upgrade - install the current Setup over it"
        $rc = Invoke-Setup $SetupExe @("/install") "upgrade-2-current"
        Check "upgrade exit code" (($rc -eq 0) -or ($rc -eq 3010)) "exit code $rc"
        Show-State "after upgrade"
        Assert-SingleEntry "upgraded" $curVer
        $curMsi = @(Get-MsiProducts)[0].Version
        Check "MSI version moved up ($oldMsi -> $curMsi)" ($oldMsi -ne $curMsi) "unchanged"
        Assert-InstallLayout "upgraded"

        if ($NextSetupExe) {
            Step "Phase 2: upgrade - install the next release over the current one"
            $nextVer = Get-SetupVersion $NextSetupExe
            Write-Host "  next Setup version: $nextVer"
            $rc = Invoke-Setup $NextSetupExe @("/install") "upgrade-3-next"
            Check "second upgrade exit code" (($rc -eq 0) -or ($rc -eq 3010)) "exit code $rc"
            Show-State "after second upgrade"
            Assert-SingleEntry "next" $nextVer
            $nextMsi = @(Get-MsiProducts)[0].Version
            Write-Host "  MSI versions seen: older $oldMsi, current $curMsi, next $nextMsi"
            Check "next MSI version is above the current one" ($nextMsi -ne $curMsi) "unchanged"
            $last = $NextSetupExe; $lastVer = $nextVer
        } else { $last = $SetupExe; $lastVer = $curVer }

        Step "Phase 2: running the older Setup again does not downgrade"
        $rc = Invoke-Setup $OldSetupExe @("/install") "upgrade-4-downgrade-attempt"
        Write-Host "  older Setup exit code: $rc"
        Show-State "after downgrade attempt"
        $visible = @(Get-ArpEntries | Where-Object { -not $_.Hidden })
        Check "still exactly one entry, at the newer version" (($visible.Count -eq 1) -and ($visible[0].Version -eq $lastVer)) "entries: $($visible | ForEach-Object { $_.Version })"

        Step "Phase 2: uninstall"
        Uninstall-Current $last "upgrade-5-uninstall"
        Show-State "after uninstall"
        Check "nothing left after uninstall" ((@(Get-ArpEntries).Count -eq 0) -and (-not (Test-Path $InstallDir))) "leftovers"
    }

    # ===== Phase 3: release-order chain =======================================
    if ($ChainSetupExes.Count -gt 0) {
        Step "Phase 3: each release replaces the one before it"
        $prevMsi = $null
        $lastExe = $null
        foreach ($exe in $ChainSetupExes) {
            $exe = (Resolve-Path $exe).Path
            $v = Get-SetupVersion $exe
            $rc = Invoke-Setup $exe @("/install") ("chain-" + (Split-Path -Leaf $exe))
            Check "install $(Split-Path -Leaf $exe) (exit code $rc)" (($rc -eq 0) -or ($rc -eq 3010)) "exit code $rc"
            Assert-SingleEntry "chain $v" $v
            $m = @(Get-MsiProducts)
            if ($m.Count -eq 1) {
                Write-Host "  now installed: bundle $v, MSI $($m[0].Version)"
                if ($prevMsi) { Check "MSI version rose ($prevMsi -> $($m[0].Version))" ([version]$m[0].Version -gt [version]$prevMsi) "did not rise" }
                $prevMsi = $m[0].Version
            }
            $lastExe = $exe
        }
        Uninstall-Current $lastExe "chain-uninstall"
        Check "nothing left after the chain" ((@(Get-ArpEntries).Count -eq 0) -and (-not (Test-Path $InstallDir))) "leftovers"
    }
}
finally {
    Stop-MiasmaForDataDir
    foreach ($n in $script:glFiles) { Remove-Item (Join-Path $InstallDir $n) -Force -ErrorAction SilentlyContinue }
    # Leave the machine clean even if a step failed half way.
    if ((Test-Path (Join-Path $InstallDir "miasma.exe")) -and ($script:failed -gt 0)) {
        Write-Host "Cleaning up after a failure..."
        $e = @(Get-ArpEntries | Where-Object { -not $_.Hidden })
        foreach ($exe in (@($NextSetupExe, $SetupExe, $OldSetupExe) + @($ChainSetupExes))) {
            if ($exe -and (Test-Path $InstallDir)) { Invoke-Setup $exe @("/uninstall") "cleanup" | Out-Null }
        }
    }
    if ($script:dataDir -and (Test-Path $script:dataDir)) { Remove-Item -Recurse -Force $script:dataDir -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host ("Result: {0} passed, {1} failed" -f $script:passed, $script:failed)
if ($script:failed -gt 0) { exit 1 }
exit 0
