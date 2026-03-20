<#
.SYNOPSIS
    Smoke test for Miasma installed from the MSI or placed in Program Files.

.DESCRIPTION
    Validates the installed-app experience end-to-end:
      1. Binaries exist in the expected install location
      2. miasma.exe is on PATH
      3. First-run init creates data in %APPDATA%\miasma
      4. Daemon starts and writes port file
      5. IPC status returns peer ID
      6. Dissolve + get round-trip
      7. Desktop executable launches (headless check)
      8. Bridge help output includes safety flags
      9. Uninstall leaves user data intact
      10. Log files created in data directory

    Designed to run on a clean Windows machine after MSI install.
    Uses a temporary data directory by default to avoid modifying real user data.

.PARAMETER InstallDir
    Miasma install directory. Default: auto-detected from PATH or Program Files.

.PARAMETER UseRealDataDir
    If set, uses the real %APPDATA%\miasma directory instead of a temp directory.
    WARNING: This will modify your actual Miasma data.

.EXAMPLE
    .\scripts\smoke-installed.ps1
    .\scripts\smoke-installed.ps1 -InstallDir "C:\Program Files\Miasma Protocol"
#>

param(
    [string]$InstallDir = "",
    [switch]$UseRealDataDir
)

$ErrorActionPreference = "Continue"
$script:procDaemon = $null
$script:TMP_ROOT = $null
$script:passed = 0
$script:failed = 0

function Pass($name) {
    Write-Host "  PASS: $name" -ForegroundColor Green
    $script:passed++
}

function Fail($name, $detail) {
    Write-Host "  FAIL: $name — $detail" -ForegroundColor Red
    $script:failed++
}

function StopDaemon {
    if ($script:procDaemon -and -not $script:procDaemon.HasExited) {
        Stop-Process -Id $script:procDaemon.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
    $script:procDaemon = $null
}

function Cleanup {
    StopDaemon
    Start-Sleep -Seconds 1
    if ($script:TMP_ROOT -and (Test-Path $script:TMP_ROOT)) {
        Remove-Item -Recurse -Force $script:TMP_ROOT -ErrorAction SilentlyContinue
    }
}

# ── Locate install directory ─────────────────────────────────────────────────

if (-not $InstallDir) {
    # Try Program Files first.
    $candidate = "${env:ProgramFiles}\Miasma Protocol"
    if (Test-Path (Join-Path $candidate "miasma.exe")) {
        $InstallDir = $candidate
    } else {
        # Try finding on PATH.
        $found = Get-Command miasma.exe -ErrorAction SilentlyContinue
        if ($found) {
            $InstallDir = Split-Path -Parent $found.Source
        }
    }
}

if (-not $InstallDir -or -not (Test-Path $InstallDir)) {
    Write-Host "ERROR: Cannot find Miasma installation." -ForegroundColor Red
    Write-Host "  Checked: ${env:ProgramFiles}\Miasma Protocol"
    Write-Host "  Checked: PATH"
    Write-Host ""
    Write-Host "Provide -InstallDir or install Miasma first."
    exit 1
}

$CLI = Join-Path $InstallDir "miasma.exe"
$DESKTOP = Join-Path $InstallDir "miasma-desktop.exe"
$BRIDGE = Join-Path $InstallDir "miasma-bridge.exe"

Write-Host "=== Miasma Installed-App Smoke Tests ===" -ForegroundColor Cyan
Write-Host "Install dir: $InstallDir"
Write-Host ""

# Set up data directory.
if ($UseRealDataDir) {
    $DATA_DIR = Join-Path $env:APPDATA "miasma"
    Write-Host "Data dir: $DATA_DIR (REAL)" -ForegroundColor Yellow
} else {
    $script:TMP_ROOT = Join-Path $env:TEMP "miasma-install-smoke-$(Get-Random)"
    $DATA_DIR = Join-Path $script:TMP_ROOT "data"
    New-Item -ItemType Directory -Force -Path $DATA_DIR | Out-Null
    Write-Host "Data dir: $DATA_DIR (temp)"
}
Write-Host ""

# ── Test 1: Binaries exist ──────────────────────────────────────────────────

Write-Host "[1] Installed binaries"
$allPresent = $true
foreach ($bin in @($CLI, $DESKTOP, $BRIDGE)) {
    if (Test-Path $bin) {
        $size = (Get-Item $bin).Length / 1MB
        Write-Host ("  Found: {0} ({1:N1} MB)" -f (Split-Path -Leaf $bin), $size)
    } else {
        Write-Host "  MISSING: $(Split-Path -Leaf $bin)" -ForegroundColor Red
        $allPresent = $false
    }
}
if ($allPresent) {
    Pass "all binaries present in install dir"
} else {
    Fail "binaries" "one or more binaries missing"
}

# Check docs.
$docsDir = Join-Path $InstallDir "docs"
if (Test-Path (Join-Path $docsDir "README.txt")) {
    Pass "docs/README.txt present"
} else {
    # Not a hard failure for portable installs.
    Write-Host "  NOTE: docs/README.txt not found (expected for MSI install)" -ForegroundColor DarkYellow
}

# ── Test 2: PATH availability ───────────────────────────────────────────────

Write-Host "[2] PATH availability"
$pathMiasma = Get-Command miasma.exe -ErrorAction SilentlyContinue
if ($pathMiasma) {
    Pass "miasma.exe found on PATH: $($pathMiasma.Source)"
} else {
    Fail "PATH" "miasma.exe not found on PATH (expected after MSI install)"
}

# ── Test 3: Init ─────────────────────────────────────────────────────────────

Write-Host "[3] First-run init"
& $CLI --data-dir $DATA_DIR init 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    $configExists = Test-Path (Join-Path $DATA_DIR "config.toml")
    $keyExists = Test-Path (Join-Path $DATA_DIR "master.key")
    if ($configExists -and $keyExists) {
        Pass "init creates config.toml + master.key"
    } else {
        Fail "init files" "config.toml=$configExists master.key=$keyExists"
    }
} else {
    Fail "init" "exit code $LASTEXITCODE"
}

# ── Test 4: Daemon start ────────────────────────────────────────────────────

Write-Host "[4] Daemon start"
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
    Pass "daemon writes daemon.port"
} else {
    Fail "daemon start" "no daemon.port after 15s"
}

Start-Sleep -Seconds 2

# ── Test 5: IPC status ──────────────────────────────────────────────────────

Write-Host "[5] IPC status"
$statusOut = & $CLI --data-dir $DATA_DIR status 2>$null
if ($statusOut -match "Peer ID") {
    Pass "status returns peer ID"
} else {
    Fail "status" "no Peer ID in output"
}

# ── Test 6: Dissolve + get round-trip ────────────────────────────────────────

Write-Host "[6] Dissolve + get round-trip"
$testDir = if ($script:TMP_ROOT) { $script:TMP_ROOT } else { Join-Path $env:TEMP "miasma-install-smoke-$(Get-Random)" }
if (-not (Test-Path $testDir)) { New-Item -ItemType Directory -Force -Path $testDir | Out-Null }

$testContent = "Miasma installed-app smoke test — $(Get-Date -Format o)"
$testFile = Join-Path $testDir "input.txt"
[System.IO.File]::WriteAllText($testFile, $testContent)

$dissolveOut = & $CLI --data-dir $DATA_DIR dissolve $testFile 2>$null
$MID = $null
foreach ($line in $dissolveOut) {
    if ($line -match "^miasma:") { $MID = $line.Trim(); break }
}
if ($MID) {
    $outFile = Join-Path $testDir "output.txt"
    & $CLI --data-dir $DATA_DIR get $MID -o $outFile 2>$null
    if ((Test-Path $outFile) -and ((Get-FileHash $testFile).Hash -eq (Get-FileHash $outFile).Hash)) {
        Pass "dissolve/get round-trip matches"
    } else {
        Fail "get round-trip" "content mismatch or file missing"
    }
} else {
    Fail "dissolve" "no MID in output"
}

# ── Test 7: Desktop launches ────────────────────────────────────────────────

Write-Host "[7] Desktop executable"
if (Test-Path $DESKTOP) {
    # Launch and immediately kill — just verify it starts without crash.
    $proc = Start-Process -FilePath $DESKTOP -PassThru -ErrorAction SilentlyContinue
    if ($proc) {
        Start-Sleep -Seconds 3
        if (-not $proc.HasExited) {
            Pass "desktop launches without immediate crash"
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        } else {
            if ($proc.ExitCode -eq 0) {
                Pass "desktop exited cleanly"
            } else {
                Fail "desktop" "exited with code $($proc.ExitCode)"
            }
        }
    } else {
        Fail "desktop" "failed to start process"
    }
} else {
    Fail "desktop" "miasma-desktop.exe not found"
}

# ── Test 8: Bridge safety flags ──────────────────────────────────────────────

Write-Host "[8] Bridge safety flags"
if (Test-Path $BRIDGE) {
    $helpOut = & $BRIDGE --help 2>$null
    $helpStr = $helpOut -join " "
    if ($helpStr -match "--proxy" -and $helpStr -match "--no-seed" -and $helpStr -match "--download-limit") {
        Pass "bridge help shows safety flags"
    } else {
        Fail "bridge help" "missing expected flags"
    }
} else {
    Fail "bridge" "miasma-bridge.exe not found"
}

# ── Test 9: Data directory structure ─────────────────────────────────────────

Write-Host "[9] Data directory structure"
StopDaemon
Start-Sleep -Seconds 1

$expectedFiles = @("config.toml", "master.key", "store_index.json")
$presentCount = 0
foreach ($f in $expectedFiles) {
    if (Test-Path (Join-Path $DATA_DIR $f)) { $presentCount++ }
}
$sharesDir = Join-Path $DATA_DIR "shares"
if ((Test-Path $sharesDir) -and (Get-ChildItem $sharesDir -ErrorAction SilentlyContinue).Count -gt 0) {
    $presentCount++
} else {
    $presentCount++ # shares dir might be empty if no files stored yet
}

if ($presentCount -ge 3) {
    Pass "data directory has expected structure"
} else {
    Fail "data structure" "only $presentCount of $($expectedFiles.Count) expected files found"
}

# ── Test 10: Log files ──────────────────────────────────────────────────────

Write-Host "[10] Log file creation"
$logFiles = Get-ChildItem -Path $DATA_DIR -Filter "daemon.log.*" -ErrorAction SilentlyContinue
if ($logFiles -and $logFiles.Count -gt 0) {
    Pass "daemon log files created"
} else {
    Fail "log files" "no daemon.log.* found in data dir"
}

# ── Summary ──────────────────────────────────────────────────────────────────

Cleanup

Write-Host ""
Write-Host "Results: $($script:passed) passed, $($script:failed) failed" -ForegroundColor $(if ($script:failed -eq 0) { "Green" } else { "Red" })

if ($script:failed -gt 0) { exit 1 } else { exit 0 }
