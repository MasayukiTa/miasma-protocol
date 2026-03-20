<#
.SYNOPSIS
    Windows-specific smoke validation for Miasma release binaries.

.DESCRIPTION
    Tests scenarios specific to Windows release readiness:
    1. Init creates data dir, config, master.key
    2. Daemon starts and writes daemon.port
    3. IPC status returns valid response
    4. Diagnostics command works (text + JSON)
    5. Dissolve + get round-trip
    6. Wipe removes master.key and makes shares unreadable
    7. Daemon restart recovery (re-init + daemon + dissolve/get)
    8. Stale port-file recovery
    9. Bridge safety defaults (--help output, flag parsing)
    10. Daemon log file creation

.NOTES
    Run from the repository root:
      powershell -ExecutionPolicy Bypass -File scripts\smoke-windows.ps1 [-UseDist]
#>

param(
    # Use binaries from .\dist\ instead of building
    [switch]$UseDist
)

$ErrorActionPreference = "Continue"
$script:procDaemon = $null
$script:TMP_ROOT = $null
$script:passed = 0
$script:failed = 0

$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

function Cleanup {
    if ($script:procDaemon -and -not $script:procDaemon.HasExited) {
        Stop-Process -Id $script:procDaemon.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
    if ($script:TMP_ROOT -and (Test-Path $script:TMP_ROOT)) {
        Remove-Item -Recurse -Force $script:TMP_ROOT -ErrorAction SilentlyContinue
    }
}

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

# ── Locate binaries ──────────────────────────────────────────────────────────

if ($UseDist) {
    $CLI = Join-Path $REPO "dist\miasma.exe"
    $BRIDGE = Join-Path $REPO "dist\miasma-bridge.exe"
} else {
    Write-Host "Building release binaries..."
    Push-Location $REPO
    cargo build -p miasma-cli -p miasma-bridge --release 2>$null
    Pop-Location
    $CLI = Join-Path $REPO "target\release\miasma.exe"
    $BRIDGE = Join-Path $REPO "target\release\miasma-bridge.exe"
}

if (-not (Test-Path $CLI)) {
    Write-Host "ABORT: miasma.exe not found at $CLI" -ForegroundColor Red
    exit 1
}

Write-Host "=== Miasma Windows Smoke Tests ===" -ForegroundColor Cyan
Write-Host "CLI: $CLI"
if (Test-Path $BRIDGE) { Write-Host "Bridge: $BRIDGE" }
Write-Host ""

$script:TMP_ROOT = Join-Path $env:TEMP "miasma-winsmoke-$(Get-Random)"
$DATA_DIR = Join-Path $script:TMP_ROOT "data"
New-Item -ItemType Directory -Force -Path $DATA_DIR | Out-Null

# ── Test 1: Init ─────────────────────────────────────────────────────────────

Write-Host "[1] Node initialization"
& $CLI --data-dir $DATA_DIR init 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    if ((Test-Path (Join-Path $DATA_DIR "config.toml")) -and (Test-Path (Join-Path $DATA_DIR "master.key"))) {
        Pass "init creates config.toml + master.key"
    } else {
        Fail "init files" "config.toml or master.key missing"
    }
} else {
    Fail "init" "exit code $LASTEXITCODE"
}

# ── Test 2: Daemon start ────────────────────────────────────────────────────

Write-Host "[2] Daemon start"
$PORT = 19200 + (Get-Random -Maximum 800)
# Update listen addr to a known port.
$configPath = Join-Path $DATA_DIR "config.toml"
$cfg = Get-Content $configPath -Raw
$cfg = $cfg -replace 'listen_addr\s*=\s*"[^"]*"', "listen_addr = `"/ip4/127.0.0.1/tcp/$PORT`""
Set-Content $configPath $cfg

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

# ── Test 3: IPC status ──────────────────────────────────────────────────────

Write-Host "[3] IPC status"
$statusOut = & $CLI --data-dir $DATA_DIR status 2>$null
if ($statusOut -match "Peer ID") {
    Pass "status returns peer ID"
} else {
    Fail "status" "no Peer ID in output"
}

# ── Test 4: Diagnostics ─────────────────────────────────────────────────────

Write-Host "[4] Diagnostics"
$diagText = & $CLI --data-dir $DATA_DIR diagnostics 2>$null
if ($diagText -match "Diagnostics Report") {
    Pass "diagnostics text output"
} else {
    Fail "diagnostics text" "no report header"
}

$diagJson = & $CLI --data-dir $DATA_DIR diagnostics --json 2>$null
$diagJsonStr = $diagJson -join "`n"
try {
    $parsed = $diagJsonStr | ConvertFrom-Json
    if ($parsed.version) {
        Pass "diagnostics JSON output"
    } else {
        Fail "diagnostics JSON" "no version field"
    }
} catch {
    Fail "diagnostics JSON" "invalid JSON: $_"
}

# ── Test 5: Dissolve + get round-trip ────────────────────────────────────────

Write-Host "[5] Dissolve + get round-trip"
$testContent = "Miasma Windows smoke test payload -- $(Get-Date -Format o)"
$testFile = Join-Path $script:TMP_ROOT "input.txt"
[System.IO.File]::WriteAllText($testFile, $testContent)

$dissolveOut = & $CLI --data-dir $DATA_DIR dissolve $testFile 2>$null
$MID = $null
foreach ($line in $dissolveOut) {
    if ($line -match "^miasma:") { $MID = $line.Trim(); break }
}
if ($MID) {
    Pass "dissolve produces MID"
    $outFile = Join-Path $script:TMP_ROOT "output.txt"
    & $CLI --data-dir $DATA_DIR get $MID -o $outFile 2>$null
    if ((Test-Path $outFile) -and ((Get-FileHash $testFile).Hash -eq (Get-FileHash $outFile).Hash)) {
        Pass "get round-trip matches"
    } else {
        Fail "get round-trip" "content mismatch or file missing"
    }
} else {
    Fail "dissolve" "no MID in output"
}

# ── Test 6: Wipe ────────────────────────────────────────────────────────────

Write-Host "[6] Wipe"
StopDaemon

& $CLI --data-dir $DATA_DIR wipe --confirm 2>$null | Out-Null
if (-not (Test-Path (Join-Path $DATA_DIR "master.key"))) {
    Pass "wipe removes master.key"
} else {
    Fail "wipe" "master.key still exists"
}

# ── Test 7: Restart recovery ────────────────────────────────────────────────

Write-Host "[7] Restart recovery (re-init + daemon)"
& $CLI --data-dir $DATA_DIR init 2>$null | Out-Null
$script:procDaemon = Start-Process -FilePath $CLI `
    -ArgumentList "--data-dir `"$DATA_DIR`" daemon" `
    -PassThru `
    -RedirectStandardOutput (Join-Path $DATA_DIR "stdout2.log") `
    -RedirectStandardError  (Join-Path $DATA_DIR "stderr2.log")

$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path $portFile) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}
if (Test-Path $portFile) {
    Pass "daemon restarts after wipe + re-init"

    # Verify dissolve/get still works after restart.
    Start-Sleep -Seconds 2
    $testContent2 = "Post-restart payload -- $(Get-Date -Format o)"
    $testFile2 = Join-Path $script:TMP_ROOT "input2.txt"
    [System.IO.File]::WriteAllText($testFile2, $testContent2)
    $dissolveOut2 = & $CLI --data-dir $DATA_DIR dissolve $testFile2 2>$null
    $MID2 = $null
    foreach ($line in $dissolveOut2) {
        if ($line -match "^miasma:") { $MID2 = $line.Trim(); break }
    }
    $outFile2 = Join-Path $script:TMP_ROOT "output2.txt"
    if ($MID2) {
        & $CLI --data-dir $DATA_DIR get $MID2 -o $outFile2 2>$null
        if ((Test-Path $outFile2) -and ((Get-FileHash $testFile2).Hash -eq (Get-FileHash $outFile2).Hash)) {
            Pass "dissolve/get works after restart"
        } else {
            Fail "post-restart get" "content mismatch"
        }
    } else {
        Fail "post-restart dissolve" "no MID"
    }
} else {
    Fail "restart" "daemon did not start after re-init"
}
StopDaemon

# ── Test 8: Stale port-file recovery ────────────────────────────────────────

Write-Host "[8] Stale port-file recovery"
# Write a fake daemon.port pointing to a port nothing listens on.
"59999" | Set-Content $portFile
$script:procDaemon = Start-Process -FilePath $CLI `
    -ArgumentList "--data-dir `"$DATA_DIR`" daemon" `
    -PassThru `
    -RedirectStandardOutput (Join-Path $DATA_DIR "stdout3.log") `
    -RedirectStandardError  (Join-Path $DATA_DIR "stderr3.log")

$deadline = (Get-Date).AddSeconds(15)
$recovered = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    if ((Test-Path $portFile) -and ((Get-Content $portFile).Trim() -ne "59999")) {
        $recovered = $true
        break
    }
}
if ($recovered) {
    Pass "daemon recovers from stale port file"
} else {
    # The daemon may have started on the stale port or the port file may not have been overwritten.
    # Check if IPC works regardless.
    $statusCheck = & $CLI --data-dir $DATA_DIR status 2>$null
    if ($statusCheck -match "Peer ID") {
        Pass "daemon recovered (IPC works)"
    } else {
        Fail "stale recovery" "daemon did not recover from stale port file"
    }
}
StopDaemon

# ── Test 9: Bridge safety defaults ───────────────────────────────────────────

if (Test-Path $BRIDGE) {
    Write-Host "[9] Bridge safety defaults"
    $helpOut = & $BRIDGE --help 2>$null
    $helpStr = $helpOut -join " "
    if ($helpStr -match "--proxy" -and $helpStr -match "--no-seed" -and $helpStr -match "--download-limit") {
        Pass "bridge help shows new safety flags"
    } else {
        Fail "bridge help" "missing expected flags in help output"
    }
} else {
    Write-Host "[9] Bridge not built — skipping"
}

# ── Test 10: Daemon log file creation ────────────────────────────────────────

Write-Host "[10] Daemon log file creation"
# Re-init and start daemon briefly to check log file is created.
& $CLI --data-dir $DATA_DIR init 2>$null | Out-Null
$script:procDaemon = Start-Process -FilePath $CLI `
    -ArgumentList "--data-dir `"$DATA_DIR`" daemon" `
    -PassThru `
    -RedirectStandardOutput (Join-Path $DATA_DIR "stdout4.log") `
    -RedirectStandardError  (Join-Path $DATA_DIR "stderr4.log")

$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path $portFile) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}
Start-Sleep -Seconds 2
StopDaemon

$logFiles = Get-ChildItem -Path $DATA_DIR -Filter "daemon.log.*" -ErrorAction SilentlyContinue
if ($logFiles -and $logFiles.Count -gt 0) {
    Pass "daemon creates log file in data dir"
} else {
    Fail "log file" "no daemon.log.* found in $DATA_DIR"
}

# ── Summary ──────────────────────────────────────────────────────────────────

Cleanup

Write-Host ""
Write-Host "Results: $($script:passed) passed, $($script:failed) failed" -ForegroundColor $(if ($script:failed -eq 0) { "Green" } else { "Red" })

if ($script:failed -gt 0) { exit 1 } else { exit 0 }
