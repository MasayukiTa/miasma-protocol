<#
.SYNOPSIS
    Two-node loopback smoke test for Miasma on a single Windows PC.

.DESCRIPTION
    1. Builds miasma (CLI) in release mode.
    2. Initializes two separate nodes (A and B) in temp directories.
    3. Starts daemon A, queries its listen address via IPC status.
    4. Starts daemon B with --bootstrap pointing to A.
    5. Publishes a test file on node A via IPC.
    6. Retrieves the file on node B via IPC using the MID.
    7. Compares SHA256 of original vs retrieved bytes.
    8. Cleans up both daemons and temp directories.

.NOTES
    Run from the repository root:
      powershell -ExecutionPolicy Bypass -File scripts\smoke-loopback.ps1
#>

$ErrorActionPreference = "Continue"

$CARGO = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
$REPO  = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

# Track processes for cleanup
$script:procA = $null
$script:procB = $null
$script:TMP_ROOT = $null

function Cleanup {
    if ($script:procA -and -not $script:procA.HasExited) {
        Stop-Process -Id $script:procA.Id -Force -ErrorAction SilentlyContinue
    }
    if ($script:procB -and -not $script:procB.HasExited) {
        Stop-Process -Id $script:procB.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
    if ($script:TMP_ROOT -and (Test-Path $script:TMP_ROOT)) {
        Remove-Item -Recurse -Force $script:TMP_ROOT -ErrorAction SilentlyContinue
    }
}

function Fail($msg) {
    Write-Host "FAIL: $msg" -ForegroundColor Red
    Cleanup
    exit 1
}

Write-Host "=== Miasma two-node loopback smoke test ===" -ForegroundColor Cyan

# ── Build ────────────────────────────────────────────────────────────────────

Write-Host "`n[1/7] Building miasma (release)..."
Push-Location $REPO
# Use Start-Process to isolate cargo stderr progress output from PowerShell.
$buildProc = Start-Process -FilePath $CARGO `
    -ArgumentList "build -p miasma-cli --release" `
    -PassThru -NoNewWindow -Wait
Pop-Location

if ($buildProc.ExitCode -ne 0) {
    Fail "cargo build failed (exit code $($buildProc.ExitCode))"
}

# The binary is named "miasma.exe" per Cargo.toml [[bin]] name = "miasma".
$CLI = Join-Path $REPO "target\release\miasma.exe"
if (-not (Test-Path $CLI)) {
    Fail "miasma.exe not found at $CLI"
}
Write-Host "  Binary: $CLI"

# ── Create temp directories ──────────────────────────────────────────────────

$script:TMP_ROOT = Join-Path $env:TEMP "miasma-smoke-$(Get-Random)"
$DIR_A = Join-Path $script:TMP_ROOT "node-a"
$DIR_B = Join-Path $script:TMP_ROOT "node-b"
New-Item -ItemType Directory -Force -Path $DIR_A | Out-Null
New-Item -ItemType Directory -Force -Path $DIR_B | Out-Null

Write-Host "`n[2/7] Initializing nodes..."
Write-Host "  Node A: $DIR_A"
Write-Host "  Node B: $DIR_B"

# Use different listen ports in the high ephemeral range.
$PORT_A = 19100 + (Get-Random -Maximum 900)
$PORT_B = $PORT_A + 1

# Run init via direct invocation; discard stderr (tracing logs).
& $CLI --data-dir $DIR_A init --listen-addr "/ip4/127.0.0.1/tcp/$PORT_A" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "miasma init (node A) failed" }
& $CLI --data-dir $DIR_B init --listen-addr "/ip4/127.0.0.1/tcp/$PORT_B" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "miasma init (node B) failed" }
Write-Host "  Initialized A (port $PORT_A) and B (port $PORT_B)"

# ── Start daemon A ───────────────────────────────────────────────────────────

Write-Host "`n[3/7] Starting daemon A..."
# Redirect both stdout and stderr to files so daemon output doesn't pollute
# the script console and doesn't interfere with later command captures.
$script:procA = Start-Process -FilePath $CLI `
    -ArgumentList "--data-dir `"$DIR_A`" daemon" `
    -PassThru `
    -RedirectStandardOutput (Join-Path $DIR_A "stdout.log") `
    -RedirectStandardError  (Join-Path $DIR_A "stderr.log")

# Wait for daemon.port file (max 15s).
$portFileA = Join-Path $DIR_A "daemon.port"
$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path $portFileA) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}
if (-not (Test-Path $portFileA)) {
    Fail "Daemon A did not start (no daemon.port after 15s)"
}
$ipcPortA = (Get-Content $portFileA).Trim()
Write-Host "  Daemon A running (IPC port: $ipcPortA)"

# Brief settle, then query status via IPC for the bootstrap address.
Start-Sleep -Seconds 2

# Use direct invocation to capture stdout reliably.
$statusLines = & $CLI --data-dir $DIR_A status 2>$null
Write-Host "  Daemon A status:"
$statusLines | ForEach-Object { Write-Host "    $_" }

# Parse:  "  Listen addr:         /ip4/127.0.0.1/tcp/19152/p2p/12D3Koo..."
$bootstrapAddr = $null
foreach ($line in $statusLines) {
    if ($line -match "Listen addr:\s*(.+)") {
        $bootstrapAddr = $Matches[1].Trim()
        break
    }
}
if (-not $bootstrapAddr) {
    Fail "Could not parse bootstrap address from daemon A status"
}
Write-Host "  Bootstrap: $bootstrapAddr"

# ── Start daemon B ───────────────────────────────────────────────────────────

Write-Host "`n[4/7] Starting daemon B (bootstrap -> A)..."
$script:procB = Start-Process -FilePath $CLI `
    -ArgumentList "--data-dir `"$DIR_B`" daemon --bootstrap $bootstrapAddr" `
    -PassThru `
    -RedirectStandardOutput (Join-Path $DIR_B "stdout.log") `
    -RedirectStandardError  (Join-Path $DIR_B "stderr.log")

$portFileB = Join-Path $DIR_B "daemon.port"
$deadline = (Get-Date).AddSeconds(15)
while (-not (Test-Path $portFileB) -and (Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
}
if (-not (Test-Path $portFileB)) {
    Fail "Daemon B did not start (no daemon.port after 15s)"
}
Write-Host "  Daemon B running (IPC port: $(Get-Content $portFileB))"

# Allow DHT convergence.
Write-Host "  Waiting for DHT convergence (5s)..."
Start-Sleep -Seconds 5

# ── Publish on A ─────────────────────────────────────────────────────────────

Write-Host "`n[5/7] Publishing test content on node A..."
$testContent = "Miasma smoke test payload -- $(Get-Date -Format o)"
$testFile = Join-Path $script:TMP_ROOT "test-input.bin"
[System.IO.File]::WriteAllText($testFile, $testContent)

# network-publish prints the bare MID to stdout.
$publishLines = & $CLI --data-dir $DIR_A network-publish $testFile 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail "network-publish failed (exit $LASTEXITCODE)"
}

$MID = $null
foreach ($line in $publishLines) {
    if ($line -match "^miasma:") {
        $MID = $line.Trim()
        break
    }
}
if (-not $MID) {
    Write-Host "  Publish output: $($publishLines -join '; ')" -ForegroundColor Yellow
    Fail "Could not extract MID from publish output"
}
Write-Host "  MID: $MID"

# ── Retrieve on B ────────────────────────────────────────────────────────────

Write-Host "`n[6/7] Retrieving on node B..."
$outputFile = Join-Path $script:TMP_ROOT "test-output.bin"

& $CLI --data-dir $DIR_B network-get $MID -o $outputFile 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail "network-get failed (exit $LASTEXITCODE)"
}
if (-not (Test-Path $outputFile)) {
    Fail "Output file was not created at $outputFile"
}
Write-Host "  Retrieved $((Get-Item $outputFile).Length) bytes"

# ── Compare ──────────────────────────────────────────────────────────────────

Write-Host "`n[7/7] Verifying content integrity..."
$hashInput  = (Get-FileHash -Path $testFile  -Algorithm SHA256).Hash
$hashOutput = (Get-FileHash -Path $outputFile -Algorithm SHA256).Hash

Write-Host "  Input  SHA256: $hashInput"
Write-Host "  Output SHA256: $hashOutput"

# ── Cleanup & result ─────────────────────────────────────────────────────────

Cleanup

if ($hashInput -eq $hashOutput) {
    Write-Host "`n=== PASS: content matches ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n=== FAIL: content mismatch ===" -ForegroundColor Red
    exit 1
}
