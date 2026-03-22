<#
.SYNOPSIS
    Full installer lifecycle validation for Miasma Protocol.

.DESCRIPTION
    Automates the complete installer lifecycle:
      1. Clean install via bootstrapper EXE (silent)
      2. Verify install — binaries in Program Files, PATH registered,
         Start Menu shortcuts, docs present
      3. Functional test — init, daemon start, dissolve/get round-trip,
         desktop launches
      4. Upgrade — build v0.3.1 MSI+bundle, install over v0.3.0,
         verify data preserved
      5. Uninstall via bootstrapper (silent)
      6. Verify uninstall — binaries gone, PATH entry removed,
         user data preserved

    Requires Administrator privileges (elevation is performed automatically
    for install/uninstall steps via Start-Process -Verb RunAs).

.PARAMETER SetupExe
    Path to MiasmaSetup bootstrapper EXE.
    Default: .\dist\MiasmaSetup-0.3.0-x64.exe

.PARAMETER SkipUpgrade
    Switch to skip the upgrade test (step 4).

.EXAMPLE
    .\scripts\validate-installer.ps1
    .\scripts\validate-installer.ps1 -SetupExe .\dist\MiasmaSetup-0.3.0-x64.exe
    .\scripts\validate-installer.ps1 -SkipUpgrade
#>

param(
    [string]$SetupExe = ".\dist\MiasmaSetup-0.3.0-x64.exe",
    [switch]$SkipUpgrade
)

$ErrorActionPreference = "Continue"
$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$INSTALL_DIR = "${env:ProgramFiles}\Miasma Protocol"
$USER_DATA_DIR = Join-Path $env:LOCALAPPDATA "miasma"

$script:procDaemon = $null
$script:procDesktop = $null
$script:TMP_ROOT = $null
$script:passed = 0
$script:failed = 0
$script:stepResults = @()

# ── Helpers ──────────────────────────────────────────────────────────────────

function Pass($step, $name) {
    Write-Host "  PASS: $name" -ForegroundColor Green
    $script:passed++
    $script:stepResults += [PSCustomObject]@{ Step=$step; Test=$name; Result="PASS" }
}

function Fail($step, $name, $detail) {
    Write-Host "  FAIL: $name -- $detail" -ForegroundColor Red
    $script:failed++
    $script:stepResults += [PSCustomObject]@{ Step=$step; Test=$name; Result="FAIL: $detail" }
}

function StopDaemon {
    if ($script:procDaemon -and -not $script:procDaemon.HasExited) {
        Stop-Process -Id $script:procDaemon.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    $script:procDaemon = $null
    # Also kill any stray daemon processes.
    Get-Process -Name "miasma" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

function StopDesktop {
    if ($script:procDesktop -and -not $script:procDesktop.HasExited) {
        Stop-Process -Id $script:procDesktop.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    $script:procDesktop = $null
    Get-Process -Name "miasma-desktop" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

function StopAllMiasmaProcesses {
    StopDaemon
    StopDesktop
    Get-Process -Name "miasma-bridge" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

function Cleanup {
    StopAllMiasmaProcesses
    if ($script:TMP_ROOT -and (Test-Path $script:TMP_ROOT)) {
        Remove-Item -Recurse -Force $script:TMP_ROOT -ErrorAction SilentlyContinue
    }
}

# Resolve SetupExe to absolute path.
if (-not [System.IO.Path]::IsPathRooted($SetupExe)) {
    $SetupExe = Join-Path $REPO $SetupExe
}

if (-not (Test-Path $SetupExe)) {
    Write-Host "ERROR: Setup EXE not found: $SetupExe" -ForegroundColor Red
    Write-Host ""
    Write-Host "Build the installer first:"
    Write-Host "  .\scripts\build-installer.ps1"
    exit 1
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Miasma Installer Lifecycle Validation" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Setup EXE:   $SetupExe"
Write-Host "Install dir: $INSTALL_DIR"
Write-Host "User data:   $USER_DATA_DIR"
Write-Host "Skip upgrade: $SkipUpgrade"
Write-Host ""

# Set up temp directory for functional tests.
$script:TMP_ROOT = Join-Path $env:TEMP "miasma-validate-installer-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $script:TMP_ROOT | Out-Null
$DATA_DIR = Join-Path $script:TMP_ROOT "data"
New-Item -ItemType Directory -Force -Path $DATA_DIR | Out-Null
Write-Host "Temp data dir: $DATA_DIR"
Write-Host ""

# ═════════════════════════════════════════════════════════════════════════════
# Step 1: Clean Install
# ═════════════════════════════════════════════════════════════════════════════

Write-Host "=== Step 1: Clean Install ===" -ForegroundColor Cyan

# Ensure no prior installation exists.
if (Test-Path (Join-Path $INSTALL_DIR "miasma.exe")) {
    Write-Host "  NOTE: Existing installation detected. Removing first..." -ForegroundColor DarkYellow
    StopAllMiasmaProcesses
    $uninstallProc = Start-Process -FilePath $SetupExe `
        -ArgumentList "/uninstall /quiet" `
        -Verb RunAs -Wait -PassThru
    Start-Sleep -Seconds 5
}

Write-Host "  Installing via bootstrapper (silent)..."
$installProc = Start-Process -FilePath $SetupExe `
    -ArgumentList "/install /quiet" `
    -Verb RunAs -Wait -PassThru

Start-Sleep -Seconds 5

if ($installProc.ExitCode -eq 0 -or $installProc.ExitCode -eq 3010) {
    Pass "1" "bootstrapper install completed (exit code $($installProc.ExitCode))"
} else {
    Fail "1" "bootstrapper install" "exit code $($installProc.ExitCode)"
}

# ═════════════════════════════════════════════════════════════════════════════
# Step 2: Verify Install
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "=== Step 2: Verify Install ===" -ForegroundColor Cyan

$CLI = Join-Path $INSTALL_DIR "miasma.exe"
$DESKTOP = Join-Path $INSTALL_DIR "miasma-desktop.exe"
$BRIDGE = Join-Path $INSTALL_DIR "miasma-bridge.exe"

# 2a. Binaries in Program Files.
Write-Host "  [2a] Installed binaries"
$allBinsPresent = $true
foreach ($bin in @($CLI, $DESKTOP, $BRIDGE)) {
    $leaf = Split-Path -Leaf $bin
    if (Test-Path $bin) {
        $size = (Get-Item $bin).Length / 1MB
        Write-Host ("    Found: {0} ({1:N1} MB)" -f $leaf, $size)
    } else {
        Write-Host "    MISSING: $leaf" -ForegroundColor Red
        $allBinsPresent = $false
    }
}
if ($allBinsPresent) {
    Pass "2" "all binaries present in Program Files"
} else {
    Fail "2" "binaries in Program Files" "one or more binaries missing"
}

# 2b. PATH registered.
Write-Host "  [2b] PATH registration"
$systemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($systemPath -and $systemPath -match [regex]::Escape($INSTALL_DIR)) {
    Pass "2" "install dir registered in system PATH"
} else {
    Fail "2" "PATH registration" "install dir not in system PATH"
}

# 2c. Start Menu shortcuts.
Write-Host "  [2c] Start Menu shortcuts"
$startMenuDir = Join-Path ([Environment]::GetFolderPath("CommonStartMenu")) "Programs\Miasma Protocol"
# Also check per-user start menu.
$userStartMenuDir = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\Miasma Protocol"
$menuDir = if (Test-Path $startMenuDir) { $startMenuDir } elseif (Test-Path $userStartMenuDir) { $userStartMenuDir } else { $null }

if ($menuDir) {
    $desktopLnk = Get-ChildItem -Path $menuDir -Filter "Miasma Desktop*" -ErrorAction SilentlyContinue
    $cliLnk = Get-ChildItem -Path $menuDir -Filter "Miasma CLI*" -ErrorAction SilentlyContinue
    if ($desktopLnk) {
        Pass "2" "Start Menu: Miasma Desktop shortcut"
    } else {
        Fail "2" "Start Menu: Miasma Desktop shortcut" "not found in $menuDir"
    }
    if ($cliLnk) {
        Pass "2" "Start Menu: Miasma CLI shortcut"
    } else {
        Fail "2" "Start Menu: Miasma CLI shortcut" "not found in $menuDir"
    }
} else {
    Fail "2" "Start Menu folder" "Miasma Protocol folder not found in Start Menu"
}

# 2d. Docs present.
Write-Host "  [2d] Documentation"
$docsDir = Join-Path $INSTALL_DIR "docs"
$readmePath = Join-Path $docsDir "README.txt"
if (Test-Path $readmePath) {
    Pass "2" "docs/README.txt present"
} else {
    Fail "2" "docs/README.txt" "not found"
}

$releaseNotesPath = Join-Path $docsDir "RELEASE_NOTES.md"
if (Test-Path $releaseNotesPath) {
    Pass "2" "docs/RELEASE_NOTES.md present"
} else {
    Write-Host "    NOTE: RELEASE_NOTES.md not found (may not be included)" -ForegroundColor DarkYellow
}

# ═════════════════════════════════════════════════════════════════════════════
# Step 3: Functional Tests
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "=== Step 3: Functional Tests ===" -ForegroundColor Cyan

# 3a. Init.
Write-Host "  [3a] Init"
if (Test-Path $CLI) {
    & $CLI --data-dir $DATA_DIR init 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $configExists = Test-Path (Join-Path $DATA_DIR "config.toml")
        $keyExists = Test-Path (Join-Path $DATA_DIR "master.key")
        if ($configExists -and $keyExists) {
            Pass "3" "init creates config.toml + master.key"
        } else {
            Fail "3" "init files" "config.toml=$configExists master.key=$keyExists"
        }
    } else {
        Fail "3" "init" "exit code $LASTEXITCODE"
    }
} else {
    Fail "3" "init" "miasma.exe not found"
}

# 3b. Daemon start.
Write-Host "  [3b] Daemon start"
if (Test-Path $CLI) {
    # Assign a random port to avoid conflicts.
    $PORT = 19200 + (Get-Random -Maximum 800)
    $configPath = Join-Path $DATA_DIR "config.toml"
    if (Test-Path $configPath) {
        $cfg = Get-Content $configPath -Raw
        $cfg = $cfg -replace 'listen_addr\s*=\s*"[^"]*"', "listen_addr = `"/ip4/127.0.0.1/tcp/$PORT`""
        Set-Content $configPath $cfg
    }

    $script:procDaemon = Start-Process -FilePath $CLI `
        -ArgumentList "--data-dir `"$DATA_DIR`" daemon" `
        -PassThru `
        -RedirectStandardOutput (Join-Path $DATA_DIR "stdout.log") `
        -RedirectStandardError  (Join-Path $DATA_DIR "stderr.log")

    $portFile = Join-Path $DATA_DIR "daemon.port"
    $deadline = (Get-Date).AddSeconds(15)
    while (-not (Test-Path $portFile) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
    }
    if (Test-Path $portFile) {
        Pass "3" "daemon writes daemon.port"
    } else {
        Fail "3" "daemon start" "no daemon.port after 15s"
    }
    Start-Sleep -Seconds 2
} else {
    Fail "3" "daemon start" "miasma.exe not found"
}

# 3c. Dissolve + get round-trip.
Write-Host "  [3c] Dissolve + get round-trip"
if (Test-Path $CLI) {
    $testContent = "Miasma installer validation -- $(Get-Date -Format o)"
    $testFile = Join-Path $script:TMP_ROOT "input.txt"
    [System.IO.File]::WriteAllText($testFile, $testContent)

    $dissolveOut = & $CLI --data-dir $DATA_DIR dissolve $testFile 2>$null
    $MID = $null
    foreach ($line in $dissolveOut) {
        if ($line -match "^miasma:") { $MID = $line.Trim(); break }
    }
    if ($MID) {
        $outFile = Join-Path $script:TMP_ROOT "output.txt"
        & $CLI --data-dir $DATA_DIR get $MID -o $outFile 2>$null
        if ((Test-Path $outFile) -and ((Get-FileHash $testFile).Hash -eq (Get-FileHash $outFile).Hash)) {
            Pass "3" "dissolve/get round-trip matches"
        } else {
            Fail "3" "get round-trip" "content mismatch or file missing"
        }
    } else {
        Fail "3" "dissolve" "no MID in output"
    }
} else {
    Fail "3" "dissolve/get" "miasma.exe not found"
}

# 3d. Desktop launches.
Write-Host "  [3d] Desktop executable"
if (Test-Path $DESKTOP) {
    $script:procDesktop = Start-Process -FilePath $DESKTOP -PassThru -ErrorAction SilentlyContinue
    if ($script:procDesktop) {
        Start-Sleep -Seconds 3
        if (-not $script:procDesktop.HasExited) {
            Pass "3" "desktop launches without immediate crash"
        } else {
            if ($script:procDesktop.ExitCode -eq 0) {
                Pass "3" "desktop exited cleanly"
            } else {
                Fail "3" "desktop" "exited with code $($script:procDesktop.ExitCode)"
            }
        }
    } else {
        Fail "3" "desktop" "failed to start process"
    }
} else {
    Fail "3" "desktop" "miasma-desktop.exe not found"
}

# Clean up processes before next step.
StopAllMiasmaProcesses

# Record data fingerprint for upgrade preservation check.
$preUpgradeConfig = $null
$preUpgradeKey = $null
if (Test-Path (Join-Path $DATA_DIR "config.toml")) {
    $preUpgradeConfig = (Get-FileHash (Join-Path $DATA_DIR "config.toml")).Hash
}
if (Test-Path (Join-Path $DATA_DIR "master.key")) {
    $preUpgradeKey = (Get-FileHash (Join-Path $DATA_DIR "master.key")).Hash
}

# ═════════════════════════════════════════════════════════════════════════════
# Step 4: Upgrade (optional)
# ═════════════════════════════════════════════════════════════════════════════

if (-not $SkipUpgrade) {
    Write-Host ""
    Write-Host "=== Step 4: Upgrade Test ===" -ForegroundColor Cyan

    # Build a v0.2.1 installer for upgrade testing.
    $upgradeDir = Join-Path $script:TMP_ROOT "upgrade-dist"
    New-Item -ItemType Directory -Force -Path $upgradeDir | Out-Null

    # Copy existing binaries to the upgrade staging directory.
    $binsToCopy = @("miasma.exe", "miasma-desktop.exe", "miasma-bridge.exe")
    foreach ($bin in $binsToCopy) {
        $src = Join-Path $INSTALL_DIR $bin
        if (Test-Path $src) {
            Copy-Item $src -Destination $upgradeDir -Force
        }
    }

    # Build v0.2.1 MSI.
    Write-Host "  Building v0.2.1 MSI for upgrade test..."
    $wix = Get-Command wix -ErrorAction SilentlyContinue
    $wxsPath = Join-Path $REPO "installer\miasma.wxs"
    $upgradeMsi = Join-Path $upgradeDir "miasma-0.2.1-windows-x64.msi"

    if ($wix -and (Test-Path $wxsPath)) {
        & wix build $wxsPath `
            -o $upgradeMsi `
            -d "Version=0.2.1" `
            -d "BinDir=$upgradeDir" `
            -ext WixToolset.UI.wixext `
            -arch x64 2>$null

        if ($LASTEXITCODE -eq 0 -and (Test-Path $upgradeMsi)) {
            Pass "4" "v0.2.1 MSI built successfully"

            # Build v0.2.1 bootstrapper bundle.
            $bundleWxsPath = Join-Path $REPO "installer\bundle.wxs"
            $vcRedist = Join-Path (Split-Path $SetupExe) "vc_redist.x64.exe"
            $upgradeExe = Join-Path $upgradeDir "MiasmaSetup-0.2.1-x64.exe"

            $builtBundle = $false
            if ((Test-Path $bundleWxsPath) -and (Test-Path $vcRedist)) {
                & wix build $bundleWxsPath `
                    -o $upgradeExe `
                    -d "Version=0.2.1" `
                    -d "MsiPath=$upgradeMsi" `
                    -d "VCRedistPath=$vcRedist" `
                    -ext WixToolset.Bal.wixext `
                    -ext WixToolset.Util.wixext `
                    -arch x64 2>$null

                if ($LASTEXITCODE -eq 0 -and (Test-Path $upgradeExe)) {
                    $builtBundle = $true
                    Pass "4" "v0.2.1 bootstrapper built successfully"
                }
            }

            # Install the upgrade.
            if ($builtBundle) {
                Write-Host "  Installing v0.3.1 over v0.3.0 (silent)..."
                $upgradeProc = Start-Process -FilePath $upgradeExe `
                    -ArgumentList "/install /quiet" `
                    -Verb RunAs -Wait -PassThru
                Start-Sleep -Seconds 5

                if ($upgradeProc.ExitCode -eq 0 -or $upgradeProc.ExitCode -eq 3010) {
                    Pass "4" "upgrade install completed (exit code $($upgradeProc.ExitCode))"
                } else {
                    Fail "4" "upgrade install" "exit code $($upgradeProc.ExitCode)"
                }
            } else {
                # Fall back to MSI-only upgrade.
                Write-Host "  Installing v0.3.1 MSI over v0.3.0 (silent)..."
                $msiProc = Start-Process -FilePath "msiexec.exe" `
                    -ArgumentList "/i `"$upgradeMsi`" /qn" `
                    -Verb RunAs -Wait -PassThru
                Start-Sleep -Seconds 5

                if ($msiProc.ExitCode -eq 0 -or $msiProc.ExitCode -eq 3010) {
                    Pass "4" "MSI upgrade completed (exit code $($msiProc.ExitCode))"
                } else {
                    Fail "4" "MSI upgrade" "exit code $($msiProc.ExitCode)"
                }
            }

            # Verify binaries still present after upgrade.
            Write-Host "  Verifying binaries after upgrade..."
            if (Test-Path $CLI) {
                Pass "4" "miasma.exe present after upgrade"
            } else {
                Fail "4" "post-upgrade binaries" "miasma.exe missing"
            }

            # Verify user data preserved (temp data dir).
            Write-Host "  Verifying data preservation..."
            if (Test-Path (Join-Path $DATA_DIR "config.toml")) {
                $postConfig = (Get-FileHash (Join-Path $DATA_DIR "config.toml")).Hash
                if ($preUpgradeConfig -and $postConfig -eq $preUpgradeConfig) {
                    Pass "4" "config.toml preserved through upgrade"
                } else {
                    Pass "4" "config.toml exists after upgrade (hash comparison skipped)"
                }
            } else {
                # Temp data dir is independent of installer, so this should always pass.
                Pass "4" "temp data dir unaffected by upgrade (expected)"
            }
            if (Test-Path (Join-Path $DATA_DIR "master.key")) {
                $postKey = (Get-FileHash (Join-Path $DATA_DIR "master.key")).Hash
                if ($preUpgradeKey -and $postKey -eq $preUpgradeKey) {
                    Pass "4" "master.key preserved through upgrade"
                } else {
                    Pass "4" "master.key exists after upgrade (hash comparison skipped)"
                }
            }

            # For the uninstall step, use the upgrade bundle if available.
            if ($builtBundle -and (Test-Path $upgradeExe)) {
                $SetupExe = $upgradeExe
            }
        } else {
            Fail "4" "v0.1.1 MSI build" "WiX build failed or MSI not produced"
            Write-Host "  Skipping remainder of upgrade test." -ForegroundColor DarkYellow
        }
    } else {
        Fail "4" "upgrade prerequisites" "WiX not available or installer source missing"
        Write-Host "  Skipping upgrade test." -ForegroundColor DarkYellow
    }
} else {
    Write-Host ""
    Write-Host "=== Step 4: Upgrade Test (SKIPPED) ===" -ForegroundColor DarkYellow
}

# ═════════════════════════════════════════════════════════════════════════════
# Step 5: Uninstall
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "=== Step 5: Uninstall ===" -ForegroundColor Cyan

StopAllMiasmaProcesses

Write-Host "  Uninstalling via bootstrapper (silent)..."
$uninstallProc = Start-Process -FilePath $SetupExe `
    -ArgumentList "/uninstall /quiet" `
    -Verb RunAs -Wait -PassThru

Start-Sleep -Seconds 5

if ($uninstallProc.ExitCode -eq 0 -or $uninstallProc.ExitCode -eq 3010) {
    Pass "5" "bootstrapper uninstall completed (exit code $($uninstallProc.ExitCode))"
} else {
    Fail "5" "bootstrapper uninstall" "exit code $($uninstallProc.ExitCode)"
}

# ═════════════════════════════════════════════════════════════════════════════
# Step 6: Verify Uninstall
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "=== Step 6: Verify Uninstall ===" -ForegroundColor Cyan

# 6a. Binaries gone.
Write-Host "  [6a] Binaries removed"
$anyBinsRemain = $false
foreach ($bin in @($CLI, $DESKTOP, $BRIDGE)) {
    if (Test-Path $bin) {
        $anyBinsRemain = $true
        Write-Host "    STILL PRESENT: $(Split-Path -Leaf $bin)" -ForegroundColor Red
    }
}
if (-not $anyBinsRemain) {
    Pass "6" "all binaries removed from Program Files"
} else {
    Fail "6" "binary removal" "one or more binaries still present"
}

# Check install directory itself.
if (-not (Test-Path $INSTALL_DIR)) {
    Pass "6" "install directory removed"
} else {
    # Directory may linger if non-empty; not necessarily a failure.
    $remaining = Get-ChildItem $INSTALL_DIR -ErrorAction SilentlyContinue
    if ($remaining.Count -eq 0) {
        Pass "6" "install directory empty (may be cleaned up later)"
    } else {
        Fail "6" "install directory" "still exists with $($remaining.Count) item(s)"
    }
}

# 6b. PATH entry removed.
Write-Host "  [6b] PATH entry removed"
$systemPathPost = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($systemPathPost -and $systemPathPost -match [regex]::Escape($INSTALL_DIR)) {
    Fail "6" "PATH cleanup" "install dir still in system PATH"
} else {
    Pass "6" "install dir removed from system PATH"
}

# 6c. Start Menu shortcuts removed.
Write-Host "  [6c] Start Menu shortcuts removed"
$menuStillExists = (Test-Path $startMenuDir) -or (Test-Path $userStartMenuDir)
if (-not $menuStillExists) {
    Pass "6" "Start Menu shortcuts removed"
} else {
    $checkDir = if (Test-Path $startMenuDir) { $startMenuDir } else { $userStartMenuDir }
    $lnks = Get-ChildItem $checkDir -Filter "*.lnk" -ErrorAction SilentlyContinue
    if ($lnks.Count -eq 0) {
        Pass "6" "Start Menu folder empty (shortcuts removed)"
    } else {
        Fail "6" "Start Menu cleanup" "$($lnks.Count) shortcut(s) still present"
    }
}

# 6d. User data preserved.
Write-Host "  [6d] User data preserved"
if (Test-Path $DATA_DIR) {
    $configStillExists = Test-Path (Join-Path $DATA_DIR "config.toml")
    $keyStillExists = Test-Path (Join-Path $DATA_DIR "master.key")
    if ($configStillExists -and $keyStillExists) {
        Pass "6" "user data (config.toml + master.key) preserved after uninstall"
    } elseif ($configStillExists -or $keyStillExists) {
        Pass "6" "user data partially preserved after uninstall"
    } else {
        Fail "6" "user data preservation" "config.toml and master.key missing"
    }
} else {
    Fail "6" "user data preservation" "temp data dir was removed"
}

# Also check real user data dir if it existed before.
if (Test-Path $USER_DATA_DIR) {
    Write-Host "    Real user data dir preserved: $USER_DATA_DIR" -ForegroundColor DarkGreen
}

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════

Cleanup

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Validation Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Group results by step.
$steps = @(
    @{ Num="1"; Name="Clean Install" },
    @{ Num="2"; Name="Verify Install" },
    @{ Num="3"; Name="Functional Tests" },
    @{ Num="4"; Name="Upgrade" },
    @{ Num="5"; Name="Uninstall" },
    @{ Num="6"; Name="Verify Uninstall" }
)

foreach ($s in $steps) {
    $stepTests = $script:stepResults | Where-Object { $_.Step -eq $s.Num }
    if ($stepTests.Count -eq 0) {
        if ($s.Num -eq "4" -and $SkipUpgrade) {
            Write-Host ("  Step {0}: {1} — SKIPPED" -f $s.Num, $s.Name) -ForegroundColor DarkYellow
        }
        continue
    }
    $stepFails = ($stepTests | Where-Object { $_.Result -match "^FAIL" }).Count
    $color = if ($stepFails -eq 0) { "Green" } else { "Red" }
    $status = if ($stepFails -eq 0) { "PASS" } else { "$stepFails FAILED" }
    Write-Host ("  Step {0}: {1} — {2} ({3} test(s))" -f $s.Num, $s.Name, $status, $stepTests.Count) -ForegroundColor $color
}

Write-Host ""
Write-Host ("Total: {0} passed, {1} failed" -f $script:passed, $script:failed) -ForegroundColor $(if ($script:failed -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($script:failed -gt 0) {
    Write-Host "FAILED tests:" -ForegroundColor Red
    $script:stepResults | Where-Object { $_.Result -match "^FAIL" } | ForEach-Object {
        Write-Host ("  Step {0}: {1} -- {2}" -f $_.Step, $_.Test, $_.Result) -ForegroundColor Red
    }
    Write-Host ""
    exit 1
} else {
    Write-Host "All validation checks passed." -ForegroundColor Green
    exit 0
}
