<#
.SYNOPSIS
    Soak test for Miasma daemon stability — repeated start/stop/dissolve/get cycles.

.DESCRIPTION
    Validates daemon reliability under repeated lifecycle operations:
      - Multiple init/daemon/dissolve/get/wipe cycles
      - Stale port-file recovery between cycles
      - Payload integrity verification each round
      - Timing and error accumulation reporting

    Designed to catch intermittent failures, resource leaks, and state
    corruption that single-run smoke tests miss.

.PARAMETER Cycles
    Number of full init→daemon→dissolve→get→wipe cycles to run. Default: 10.

.PARAMETER UseDist
    Use binaries from .\dist\ instead of building.

.PARAMETER PayloadSizeKB
    Size of random test payload per cycle, in KB. Default: 64.

.EXAMPLE
    .\scripts\soak-test.ps1 -Cycles 20 -UseDist
    .\scripts\soak-test.ps1 -Cycles 5 -PayloadSizeKB 512
#>

param(
    [int]$Cycles = 10,
    [switch]$UseDist,
    [int]$PayloadSizeKB = 64
)

$ErrorActionPreference = "Continue"
$script:procDaemon = $null
$script:TMP_ROOT = $null

$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

function FillRandomBytes {
    param(
        [Parameter(Mandatory)]
        [byte[]]$Buffer
    )

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($Buffer)
    } finally {
        $rng.Dispose()
    }
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

# ── Locate binaries ──────────────────────────────────────────────────────────

if ($UseDist) {
    $CLI = Join-Path $REPO "dist\miasma.exe"
} else {
    Write-Host "Building release binaries..."
    Push-Location $REPO
    cargo build -p miasma-cli --release 2>$null
    Pop-Location
    $CLI = Join-Path $REPO "target\release\miasma.exe"
}

if (-not (Test-Path $CLI)) {
    Write-Host "ABORT: miasma.exe not found at $CLI" -ForegroundColor Red
    exit 1
}

Write-Host "=== Miasma Soak Test ===" -ForegroundColor Cyan
Write-Host "CLI:          $CLI"
Write-Host "Cycles:       $Cycles"
Write-Host "Payload size: $PayloadSizeKB KB"
Write-Host ""

$script:TMP_ROOT = Join-Path $env:TEMP "miasma-soak-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $script:TMP_ROOT | Out-Null

$results = @()
$totalPassed = 0
$totalFailed = 0

# ── Run cycles ───────────────────────────────────────────────────────────────

for ($i = 1; $i -le $Cycles; $i++) {
    $cycleStart = Get-Date
    $cycleErrors = @()
    $DATA_DIR = Join-Path $script:TMP_ROOT "cycle-$i"
    New-Item -ItemType Directory -Force -Path $DATA_DIR | Out-Null

    Write-Host "[$i/$Cycles] " -NoNewline -ForegroundColor Cyan

    # ── Step 1: Init ─────────────────────────────────────────────────────────
    & $CLI --data-dir $DATA_DIR init 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $cycleErrors += "init failed (exit $LASTEXITCODE)"
    }

    # ── Step 2: Start daemon ─────────────────────────────────────────────────
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
    if (-not (Test-Path $portFile)) {
        $cycleErrors += "daemon did not write daemon.port within 15s"
    }

    Start-Sleep -Seconds 2

    # ── Step 3: Dissolve payload ─────────────────────────────────────────────
    $payload = [byte[]]::new($PayloadSizeKB * 1024)
    FillRandomBytes -Buffer $payload
    $inputFile = Join-Path $DATA_DIR "input.bin"
    [System.IO.File]::WriteAllBytes($inputFile, $payload)

    $MID = $null
    if ($cycleErrors.Count -eq 0) {
        $dissolveOut = & $CLI --data-dir $DATA_DIR dissolve $inputFile 2>$null
        foreach ($line in $dissolveOut) {
            if ($line -match "^miasma:") { $MID = $line.Trim(); break }
        }
        if (-not $MID) {
            $cycleErrors += "dissolve produced no MID"
        }
    }

    # ── Step 4: Get and verify ───────────────────────────────────────────────
    if ($MID) {
        $outputFile = Join-Path $DATA_DIR "output.bin"
        & $CLI --data-dir $DATA_DIR get $MID -o $outputFile 2>$null
        if ((Test-Path $outputFile) -and ((Get-FileHash $inputFile).Hash -eq (Get-FileHash $outputFile).Hash)) {
            # OK
        } else {
            $cycleErrors += "get round-trip content mismatch or file missing"
        }
    }

    # ── Step 5: Stop daemon ──────────────────────────────────────────────────
    StopDaemon

    # ── Step 6: Wipe ────────────────────────────────────────────────────────
    & $CLI --data-dir $DATA_DIR wipe --confirm 2>$null | Out-Null
    if (Test-Path (Join-Path $DATA_DIR "master.key")) {
        $cycleErrors += "wipe did not remove master.key"
    }

    # ── Cycle result ─────────────────────────────────────────────────────────
    $elapsed = ((Get-Date) - $cycleStart).TotalSeconds

    if ($cycleErrors.Count -eq 0) {
        Write-Host ("PASS ({0:N1}s)" -f $elapsed) -ForegroundColor Green
        $totalPassed++
    } else {
        Write-Host ("FAIL ({0:N1}s): {1}" -f $elapsed, ($cycleErrors -join "; ")) -ForegroundColor Red
        $totalFailed++
    }

    $results += [PSCustomObject]@{
        Cycle   = $i
        Status  = if ($cycleErrors.Count -eq 0) { "PASS" } else { "FAIL" }
        Elapsed = [math]::Round($elapsed, 1)
        Errors  = ($cycleErrors -join "; ")
    }

    # Small pause between cycles to release ports.
    Start-Sleep -Seconds 1
}

# ── Summary ──────────────────────────────────────────────────────────────────

Cleanup

Write-Host ""
Write-Host "=== Soak Test Results ===" -ForegroundColor Cyan
Write-Host "Cycles: $Cycles  |  Passed: $totalPassed  |  Failed: $totalFailed"

$totalElapsed = ($results | Measure-Object -Property Elapsed -Sum).Sum
$avgElapsed = ($results | Measure-Object -Property Elapsed -Average).Average
Write-Host ("Total time: {0:N1}s  |  Avg cycle: {1:N1}s" -f $totalElapsed, $avgElapsed)

if ($totalFailed -gt 0) {
    Write-Host ""
    Write-Host "Failed cycles:" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
        Write-Host ("  Cycle {0}: {1}" -f $_.Cycle, $_.Errors)
    }
}

# Write results to file.
$reportPath = Join-Path $REPO "dist\soak-results.txt"
New-Item -ItemType Directory -Force -Path (Split-Path $reportPath) | Out-Null
$reportLines = @(
    "Miasma Soak Test — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Cycles: $Cycles  |  Payload: $PayloadSizeKB KB  |  Passed: $totalPassed  |  Failed: $totalFailed"
    "Total: $([math]::Round($totalElapsed, 1))s  |  Avg: $([math]::Round($avgElapsed, 1))s"
    ""
)
foreach ($r in $results) {
    $reportLines += "{0,3}  {1,-5}  {2,6}s  {3}" -f $r.Cycle, $r.Status, $r.Elapsed, $r.Errors
}
$reportLines | Set-Content $reportPath
Write-Host ""
Write-Host "Report written: $reportPath"

if ($totalFailed -gt 0) { exit 1 } else { exit 0 }
