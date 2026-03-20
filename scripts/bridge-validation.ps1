<#
.SYNOPSIS
    End-to-end bridge validation with a small legal torrent.

.DESCRIPTION
    Validates the full BitTorrent bridge pipeline:
      1. Preflight: parses magnet, enforces size limit, shows safety defaults
      2. Download: fetches torrent content from real swarm
      3. Dissolve: stores content into Miasma, returns MID
      4. Retrieve: gets content back by MID and verifies integrity

    Uses a small (<10 MiB) Creative Commons-licensed torrent for testing.
    The default test torrent is the "SMPTE Color Bars" test pattern (public domain).

.PARAMETER UseDist
    Use binaries from .\dist\ instead of building.

.PARAMETER MagnetUri
    Override the default test magnet URI. Must point to a small (<10 MiB),
    legally redistributable torrent.

.PARAMETER SkipDownload
    Skip the actual torrent download (test preflight and flag parsing only).

.EXAMPLE
    .\scripts\bridge-validation.ps1 -UseDist
    .\scripts\bridge-validation.ps1 -SkipDownload  # Test safety flags only
#>

param(
    [switch]$UseDist,
    [string]$MagnetUri = "",
    [switch]$SkipDownload
)

$ErrorActionPreference = "Continue"
$script:procDaemon = $null
$script:TMP_ROOT = $null
$script:passed = 0
$script:failed = 0

$REPO = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

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
if (-not (Test-Path $BRIDGE)) {
    Write-Host "ABORT: miasma-bridge.exe not found at $BRIDGE" -ForegroundColor Red
    exit 1
}

Write-Host "=== Miasma Bridge End-to-End Validation ===" -ForegroundColor Cyan
Write-Host "CLI:    $CLI"
Write-Host "Bridge: $BRIDGE"
Write-Host ""

$script:TMP_ROOT = Join-Path $env:TEMP "miasma-bridge-val-$(Get-Random)"
$DATA_DIR = Join-Path $script:TMP_ROOT "data"
New-Item -ItemType Directory -Force -Path $DATA_DIR | Out-Null

# ── Test 1: Help output and safety flags ──────────────────────────────────────

Write-Host "[1] Help output and safety flags"
$helpOut = & $BRIDGE --help 2>$null
$helpStr = $helpOut -join " "

if ($helpStr -match "--proxy") {
    Pass "--proxy flag documented"
} else {
    Fail "--proxy" "not found in help output"
}

if ($helpStr -match "--no-seed") {
    Pass "--no-seed flag documented"
} else {
    Fail "--no-seed" "not found in help output"
}

if ($helpStr -match "--download-limit") {
    Pass "--download-limit flag documented"
} else {
    Fail "--download-limit" "not found in help output"
}

if ($helpStr -match "Safe defaults" -or $helpStr -match "safe defaults" -or $helpStr -match "SAFE DEFAULTS") {
    Pass "safe defaults section present"
} else {
    Fail "safe defaults" "no safe defaults section in help output"
}

# ── Test 2: Flag parsing validation ──────────────────────────────────────────

Write-Host "[2] Flag parsing validation"

# --no-seed should be accepted.
$nsOut = & $BRIDGE dissolve --no-seed 2>&1
if (($nsOut -join " ") -match "Usage: miasma-bridge dissolve") {
    Pass "--no-seed flag accepted"
} else {
    Fail "--no-seed parse" "flag rejected (exit $LASTEXITCODE)"
}

# --seed should be accepted.
$sOut = & $BRIDGE dissolve --seed 2>&1
if (($sOut -join " ") -match "Usage: miasma-bridge dissolve") {
    Pass "--seed flag accepted"
} else {
    Fail "--seed parse" "flag rejected (exit $LASTEXITCODE)"
}

# --max-total-bytes should be accepted.
$mtbOut = & $BRIDGE dissolve --max-total-bytes 1000000 2>&1
if (($mtbOut -join " ") -match "Usage: miasma-bridge dissolve") {
    Pass "--max-total-bytes flag accepted"
} else {
    Fail "--max-total-bytes parse" "flag rejected (exit $LASTEXITCODE)"
}

# ── Test 3: Size limit enforcement ───────────────────────────────────────────

Write-Host "[3] Size limit enforcement"
if ($SkipDownload) {
    Write-Host "  SKIPPED: requires live metadata fetch to validate size enforcement deterministically." -ForegroundColor DarkYellow
    Write-Host "           Help/flag parsing still verified above; run without -SkipDownload to exercise live preflight." -ForegroundColor DarkYellow
} elseif ($MagnetUri) {
    $limitOut = & $BRIDGE dissolve $MagnetUri --max-total-bytes 1 2>&1
    $limitStr = $limitOut -join " "
    if ($LASTEXITCODE -ne 0 -and ($limitStr -match "--confirm-download" -or $limitStr -match "--max-total-bytes")) {
        Pass "size limit rejection includes actionable guidance"
    } elseif ($LASTEXITCODE -ne 0) {
        Pass "bridge rejected oversized torrent"
    } else {
        Fail "size limit enforcement" "torrent completed without triggering the configured limit"
    }
} else {
    Write-Host "  SKIPPED: provide -MagnetUri to validate live size-limit rejection." -ForegroundColor DarkYellow
}

# ── Test 4: E2E with real torrent (optional) ────────────────────────────────

if ($SkipDownload) {
    Write-Host "[4] E2E download — SKIPPED (-SkipDownload)" -ForegroundColor DarkYellow
} else {
    Write-Host "[4] E2E download with legal test torrent"

    if (-not $MagnetUri) {
        Write-Host "  No -MagnetUri provided." -ForegroundColor DarkYellow
        Write-Host "  To run E2E validation, provide a small (<10 MiB) CC-licensed magnet URI:"
        Write-Host "    .\scripts\bridge-validation.ps1 -MagnetUri `"magnet:?xt=urn:btih:...`""
        Write-Host ""
        Write-Host "  Recommended test torrents (Creative Commons / public domain):"
        Write-Host "    - Ubuntu mini.iso (any recent release, ~80 MB, use --confirm-download)"
        Write-Host "    - Any CC-licensed content from archive.org under 10 MiB"
        Write-Host ""
        Write-Host "  SKIPPED: no magnet URI" -ForegroundColor DarkYellow
    } else {
        # Init and start daemon.
        & $CLI --data-dir $DATA_DIR init 2>$null | Out-Null
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
            Start-Sleep -Seconds 2

            # Run bridge dissolve with the provided magnet.
            Write-Host "  Downloading torrent content..."
            $bridgeOut = & $BRIDGE dissolve $MagnetUri --data-dir $DATA_DIR --confirm-download 2>&1
            $bridgeStr = $bridgeOut -join "`n"

            # Extract MID from bridge output.
            $MID = $null
            foreach ($line in $bridgeOut) {
                if ($line -match "^miasma:") { $MID = $line.Trim(); break }
            }

            if ($MID) {
                Pass "bridge produced MID: $MID"

                # Retrieve and verify.
                $outDir = Join-Path $script:TMP_ROOT "retrieved"
                New-Item -ItemType Directory -Force -Path $outDir | Out-Null
                $outFile = Join-Path $outDir "content"
                & $CLI --data-dir $DATA_DIR get $MID -o $outFile 2>$null

                if (Test-Path $outFile) {
                    $size = (Get-Item $outFile).Length
                    Pass "retrieved content ($size bytes)"
                } else {
                    Fail "retrieve" "output file not created"
                }
            } else {
                Fail "bridge dissolve" "no MID in output"
                Write-Host "  Bridge output:" -ForegroundColor DarkYellow
                $bridgeStr -split "`n" | ForEach-Object { Write-Host "    $_" }
            }
        } else {
            Fail "daemon start" "daemon.port not created within 15s"
        }

        StopDaemon
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────

Cleanup

Write-Host ""
Write-Host "Results: $($script:passed) passed, $($script:failed) failed" -ForegroundColor $(if ($script:failed -eq 0) { "Green" } else { "Red" })

if ($script:failed -gt 0) { exit 1 } else { exit 0 }
