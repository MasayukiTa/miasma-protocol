# wss-probe-windows.ps1
# Run this on Windows (GlobalProtect active) to test WSS connectivity
# to a GitHub Actions runner via Cloudflare tunnel.
#
# Usage:
#   .\scripts\wss-probe-windows.ps1
#   .\scripts\wss-probe-windows.ps1 -RunId 12345678  # specify run ID manually
#
# What it does:
#   1. Reads the WSS_PROBE_INFO comment from GitHub issue #5 (latest run)
#   2. Extracts the Cloudflare tunnel URL
#   3. Runs: miasma wss-probe <url>
#   4. Posts the result back to issue #5 as WSS_PROBE_RESULT comment
#
# Requires:
#   - gh (GitHub CLI) authenticated
#   - miasma.exe in PATH or current directory

param(
    [string]$RunId = "",
    [string]$Repo = "MasayukiTa/miasma-protocol",
    [int]$TimeoutSecs = 20
)

$ErrorActionPreference = "Stop"

# ── 1. Find miasma.exe ────────────────────────────────────────────────────────
$miasma = Get-Command miasma -ErrorAction SilentlyContinue
if (-not $miasma) {
    $local = Join-Path $PSScriptRoot "..\target\release\miasma.exe"
    if (Test-Path $local) { $miasma = $local }
    else {
        Write-Error "miasma.exe not found in PATH or target\release. Build first."
        exit 1
    }
} else {
    $miasma = $miasma.Source
}
Write-Host "Using miasma: $miasma"

# ── 2. Get WSS_PROBE_INFO from issue #5 ──────────────────────────────────────
Write-Host "`nFetching probe info from issue #5..."
$commentsJson = gh issue view 5 -R $Repo --comments --json comments 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "gh issue view failed: $commentsJson"
    exit 1
}

$comments = ($commentsJson | ConvertFrom-Json).comments

# Filter for WSS_PROBE_INFO comments
$probeComments = $comments | Where-Object { $_.body -match "WSS_PROBE_INFO" }
if (-not $probeComments) {
    Write-Error "No WSS_PROBE_INFO comment found in issue #5. Run the workflow first."
    exit 1
}

# Use latest comment, or filter by RunId if provided
if ($RunId) {
    $probeComment = $probeComments | Where-Object { $_.body -match "run=$RunId" } | Select-Object -Last 1
    if (-not $probeComment) {
        Write-Error "No WSS_PROBE_INFO comment for run=$RunId"
        exit 1
    }
} else {
    $probeComment = $probeComments | Select-Object -Last 1
}

$body = $probeComment.body
Write-Host "Found probe info: $body"

# Parse fields
$fields = @{}
foreach ($token in $body -split ' ') {
    if ($token -match '^(\w+)=(.+)$') {
        $fields[$Matches[1]] = $Matches[2]
    }
}

$tunnelUrl  = $fields["TUNNEL_URL"]
$mid        = $fields["MID"]
$actualRunId = $fields["run"]
$runnerIp   = $fields["RUNNER_IP"]

if (-not $tunnelUrl) {
    Write-Error "Could not parse TUNNEL_URL from: $body"
    exit 1
}

Write-Host ""
Write-Host "Run ID:      $actualRunId"
Write-Host "Runner IP:   $runnerIp"
Write-Host "Tunnel URL:  $tunnelUrl"
Write-Host "Test MID:    $mid"
Write-Host ""

# Convert http/https to ws/wss for the probe
$probeUrl = $tunnelUrl -replace '^https://', 'wss://' -replace '^http://', 'ws://'
Write-Host "WSS probe URL: $probeUrl"

# ── 3. Run miasma wss-probe ──────────────────────────────────────────────────
Write-Host "`nRunning: miasma wss-probe $probeUrl --timeout-secs $TimeoutSecs"
Write-Host "─────────────────────────────────────────────────────────"

$probeOutput = & $miasma wss-probe $probeUrl --timeout-secs $TimeoutSecs 2>&1
$probeExit   = $LASTEXITCODE
$probeResult = ($probeExit -eq 0) ? "PASS" : "FAIL"

Write-Host $probeOutput
Write-Host "─────────────────────────────────────────────────────────"
Write-Host "Result: $probeResult (exit $probeExit)"

# ── 4. Post result to issue #5 ───────────────────────────────────────────────
Write-Host "`nPosting result to issue #5..."
$resultBody = "WSS_PROBE_RESULT run=$actualRunId RESULT=$probeResult EXIT=$probeExit OUTPUT=$($probeOutput -join ' | ' | Select-String '.' | ForEach-Object { $_.Line } | Select-Object -First 3 | Join-String -Separator ' | ')"

gh issue comment 5 -R $Repo --body $resultBody
if ($LASTEXITCODE -eq 0) {
    Write-Host "Result posted."
} else {
    Write-Warning "Could not post result to issue (gh error). Result was: $probeResult"
}

Write-Host ""
if ($probeResult -eq "PASS") {
    Write-Host "✓ WSS connectivity PROVEN through GlobalProtect"
    Write-Host "  TCP + WebSocket over port 443 reaches internet (Cloudflare)."
    Write-Host "  This is the transport foundation for DPI-resistant connections."
} else {
    Write-Host "✗ WSS connectivity BLOCKED"
    Write-Host "  TCP 443 to Cloudflare is blocked on this network."
    Write-Host "  Try from an unrestricted network to confirm baseline."
}

exit $probeExit
