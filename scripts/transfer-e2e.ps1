<#
.SYNOPSIS
    End-to-end check of protected, resumable transfer with the real miasma binary,
    including a hard kill of each daemon part-way through.

.DESCRIPTION
    Two nodes on loopback. It checks, in this order:
      1. A password-protected, multi-segment file is published from node A.
      2. Node B is refused with a wrong password, and with no password, before any data moves.
      3. Node B starts receiving; its daemon is KILLED after the first segment lands;
         the daemon is restarted, `miasma transfers` shows the paused transfer, and running the
         same `network-get` again resumes it. The result must match by SHA256.
      4. Node A publishes a second file; ITS daemon is killed after the first segment;
         restarted; running the same `network-publish` resumes it, and B receives the result.

    ASCII only on purpose (the file may be run on a machine that reads it in a legacy code page).

.PARAMETER Cli
    Path to miasma.exe. Default: target\release, then target\debug.

.PARAMETER SizeMB
    Size of each test file. Must span several segments: with k=2 a segment is ~16 MB, so the
    default 40 MB is three segments.

.PARAMETER KeepTemp
    Keep the temp directory (logs, journals) for inspection.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\transfer-e2e.ps1
#>
param(
    [string]$Cli = "",
    [int]$SizeMB = 40,
    [int]$K = 2,
    [int]$N = 3,
    [switch]$KeepTemp
)

$ErrorActionPreference = "Stop"
# This script matches the CLI's English wording ("wrong password", "Paused", "seg N/M", ...).
# The CLI follows the OS language by default, so pin it; child processes inherit it.
$env:MIASMA_LANG = "en"
$REPO =Split-Path -Parent (Split-Path -Parent $PSCommandPath)

if (-not $Cli) {
    foreach ($c in @("target\release\miasma.exe", "target\debug\miasma.exe")) {
        $p = Join-Path $REPO $c
        if (Test-Path $p) { $Cli = $p; break }
    }
}
if (-not $Cli -or -not (Test-Path $Cli)) { throw "miasma.exe not found; build with: cargo build -p miasma-cli" }
Write-Host "Using $Cli"

$script:Failures = 0
$script:Procs = @()
$TMP = Join-Path $env:TEMP ("miasma-e2e-" + (Get-Random))
$DIR_A = Join-Path $TMP "node-a"
$DIR_B = Join-Path $TMP "node-b"
New-Item -ItemType Directory -Force -Path $DIR_A, $DIR_B | Out-Null

function Check($ok, $what) {
    if ($ok) { Write-Host ("  PASS: " + $what) -ForegroundColor Green }
    else { Write-Host ("  FAIL: " + $what) -ForegroundColor Red; $script:Failures++ }
}

function Cleanup {
    foreach ($p in $script:Procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Start-Sleep -Seconds 1
    if (-not $KeepTemp -and (Test-Path $TMP)) { Remove-Item -Recurse -Force $TMP -ErrorAction SilentlyContinue }
    elseif ($KeepTemp) { Write-Host "Kept: $TMP" }
}

# Run the CLI, capture stdout+stderr and the exit code without letting stderr abort the script.
function Run-Cli([string[]]$CliArgs) {
    $out = Join-Path $TMP ("out-" + (Get-Random) + ".txt")
    $err = Join-Path $TMP ("err-" + (Get-Random) + ".txt")
    $proc = Start-Process -FilePath $Cli -ArgumentList $CliArgs -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $o = ""; $e = ""
    if (Test-Path $out) { $o = [IO.File]::ReadAllText($out) }
    if (Test-Path $err) { $e = [IO.File]::ReadAllText($err) }
    return [pscustomobject]@{ Code = $proc.ExitCode; Out = $o; Err = $e }
}

function Start-Daemon([string]$dir, [string]$bootstrap) {
    $portFile = Join-Path $dir "daemon.port"
    Remove-Item $portFile -ErrorAction SilentlyContinue
    $a = "--data-dir `"$dir`" daemon"
    if ($bootstrap) { $a += " --bootstrap $bootstrap" }
    $p = Start-Process -FilePath $Cli -ArgumentList $a -PassThru `
        -RedirectStandardOutput (Join-Path $dir ("stdout-" + (Get-Random) + ".log")) `
        -RedirectStandardError (Join-Path $dir ("stderr-" + (Get-Random) + ".log"))
    $script:Procs += $p
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path $portFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    if (-not (Test-Path $portFile)) { throw "daemon in $dir did not start" }
    return $p
}

function Kill-Daemon($p, [string]$dir) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    $p.WaitForExit(10000) | Out-Null
    Remove-Item (Join-Path $dir "daemon.port") -ErrorAction SilentlyContinue
}

# The highest "seg N/M" among the transfers listed by `miasma transfers`, or -1.
function Segments-Done([string]$dir, [string]$match) {
    $r = Run-Cli @("--data-dir", $dir, "transfers")
    $best = -1
    $blocks = ($r.Out -split "\r?\n(?=\S)")
    foreach ($b in $blocks) {
        if ($match -and $b -notmatch [regex]::Escape($match)) { continue }
        if ($b -match "seg (\d+)/(\d+)") { $best = [Math]::Max($best, [int]$Matches[1]) }
    }
    return $best
}

function Wait-Segments([string]$dir, [string]$match, [int]$atLeast, [int]$timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ((Segments-Done $dir $match) -ge $atLeast) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# "Connected peers: N" from `miasma status`, or -1 when the daemon does not answer.
function Peers-Of([string]$dir) {
    $r = Run-Cli @("--data-dir", $dir, "status")
    foreach ($line in ($r.Out -split "\r?\n")) {
        if ($line -match "Connected peers:\s*(\d+)") { return [int]$Matches[1] }
    }
    return -1
}

# Wait until the node at $dir is connected to at least one peer. This is what the runbook
# tells the user to do before starting a transfer, so the script does the same.
function Wait-Peers([string]$dir, [int]$timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ((Peers-Of $dir) -ge 1) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function New-TestFile([string]$path, [int]$mb) {
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $fs = [IO.File]::Create($path)
    $buf = New-Object byte[] (1MB)
    for ($i = 0; $i -lt $mb; $i++) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }
    $fs.Close()
}

function Sha([string]$p) { return (Get-FileHash -Path $p -Algorithm SHA256).Hash }

try {
    Write-Host "=== Miasma protected + resumable transfer, end to end ===" -ForegroundColor Cyan

    $PORT_A = 21000 + (Get-Random -Maximum 800)
    $PORT_B = $PORT_A + 1
    Run-Cli @("--data-dir", $DIR_A, "init", "--listen-addr", "/ip4/127.0.0.1/tcp/$PORT_A") | Out-Null
    Run-Cli @("--data-dir", $DIR_B, "init", "--listen-addr", "/ip4/127.0.0.1/tcp/$PORT_B") | Out-Null

    $daemonA = Start-Daemon $DIR_A ""
    Start-Sleep -Seconds 2
    $status = (Run-Cli @("--data-dir", $DIR_A, "status")).Out
    $bootstrap = $null
    foreach ($line in ($status -split "\r?\n")) {
        if ($line -match "Listen addr:\s*(\S+)") { $bootstrap = $Matches[1]; break }
    }
    if (-not $bootstrap) { throw "could not read node A's listen address" }
    Write-Host "  Node A: $bootstrap"
    $daemonB = Start-Daemon $DIR_B $bootstrap
    Check (Wait-Peers $DIR_B 60) "node B is connected to node A before the first transfer"

    $pwFile = Join-Path $TMP "password.txt"
    [IO.File]::WriteAllText($pwFile, "e2e-correct-horse`n")
    $badPw = Join-Path $TMP "wrong.txt"
    [IO.File]::WriteAllText($badPw, "not-the-password`n")

    # ---- 1. publish -------------------------------------------------------------------
    Write-Host "`n[1] Publish $SizeMB MB, password-protected, k=$K n=$N" -ForegroundColor Cyan
    $src1 = Join-Path $TMP "payload1.bin"
    New-TestFile $src1 $SizeMB
    $hash1 = Sha $src1
    $pub = Run-Cli @("--data-dir", $DIR_A, "network-publish", $src1, "--data-shards", "$K", "--total-shards", "$N", "--password-file", $pwFile)
    $mid1 = ($pub.Out -split "\r?\n" | Where-Object { $_ -match "^miasma:" } | Select-Object -First 1)
    Check ($pub.Code -eq 0 -and $mid1) "network-publish succeeded and printed a MID"
    Write-Host "  MID: $mid1"

    # ---- 2. refused without the password ------------------------------------------------
    Write-Host "`n[2] Wrong and missing passwords are refused before any data moves" -ForegroundColor Cyan
    $out2 = Join-Path $TMP "should-not-exist.bin"
    $wrong = Run-Cli @("--data-dir", $DIR_B, "network-get", $mid1, "-o", $out2, "--password-file", $badPw)
    Check ($wrong.Code -ne 0 -and ($wrong.Err + $wrong.Out) -match "wrong password") "wrong password: non-zero exit and 'wrong password'"
    $none = Run-Cli @("--data-dir", $DIR_B, "network-get", $mid1, "-o", $out2)
    Check ($none.Code -ne 0 -and ($none.Err + $none.Out) -match "password") "no password: non-zero exit and a password message"
    Check (-not (Test-Path $out2) -and -not (Test-Path "$out2.part")) "neither attempt left an output or a .part file"

    # ---- 3. receiver killed mid-transfer ------------------------------------------------
    Write-Host "`n[3] Receiver: kill B's daemon after the first segment, restart, resume" -ForegroundColor Cyan
    $recv = Join-Path $TMP "received1.bin"
    $start = Run-Cli @("--data-dir", $DIR_B, "network-get", $mid1, "-o", $recv, "--password-file", $pwFile, "--no-wait")
    Check ($start.Code -eq 0) "network-get --no-wait started the transfer"
    $reached = Wait-Segments $DIR_B $mid1 1 900
    Check $reached "the first segment was received"
    Kill-Daemon $daemonB $DIR_B
    Write-Host "  B's daemon killed."
    Check (-not (Test-Path $recv)) "no output file while incomplete"
    Check (Test-Path "$recv.part") "the partial file is kept"

    $daemonB = Start-Daemon $DIR_B $bootstrap
    Check (Wait-Peers $DIR_B 60) "after the restart, node B is connected to node A again"
    $listed =(Run-Cli @("--data-dir", $DIR_B, "transfers")).Out
    Check ($listed -match "Paused" -and $listed -match "resumable") "after the restart, 'transfers' shows it paused and resumable"
    $doneBefore = Segments-Done $DIR_B $mid1
    Write-Host "  Segments already safe on disk: $doneBefore"
    Check ($doneBefore -ge 1) "the journal remembers the finished segment(s)"

    $resume = Run-Cli @("--data-dir", $DIR_B, "network-get", $mid1, "-o", $recv, "--password-file", $pwFile)
    Check ($resume.Code -eq 0) "running the same network-get again completed"
    Check ((Test-Path $recv) -and ((Sha $recv) -eq $hash1)) "the received file matches the original byte for byte (SHA256)"
    Check (-not (Test-Path "$recv.part")) "the .part file is gone"

    # ---- 4. sender killed mid-publish -----------------------------------------------------
    Write-Host "`n[4] Sender: kill A's daemon after the first segment, restart, resume" -ForegroundColor Cyan
    # The kill has to land while the send is still running. On a fast machine a small file can
    # finish between the poll that sees segment 1 and the kill; the job is then complete, its
    # journal is gone, and there is nothing to resume (seen on a fast CI runner). That is a
    # property of the machine, not a defect, so retry with a file twice as large (each attempt
    # uses its own file name) until the kill provably came mid-send.
    $sizeMB2 = $SizeMB
    $paused = $false
    $hash2 = $null; $args2 = $null; $listedA = ""
    for ($try = 1; $try -le 4 -and -not $paused; $try++) {
        $name2 = "payload2-$try.bin"
        $src2 = Join-Path $TMP $name2
        New-TestFile $src2 $sizeMB2
        $hash2 = Sha $src2
        $args2 = @("--data-dir", $DIR_A, "network-publish", $src2, "--data-shards", "$K", "--total-shards", "$N", "--password-file", $pwFile)
        $s2 = Run-Cli ($args2 + @("--no-wait"))
        Check ($s2.Code -eq 0) "network-publish --no-wait started the publish ($sizeMB2 MB)"
        $reached = Wait-Segments $DIR_A $name2 1 900
        Check $reached "the first segment was published"
        Kill-Daemon $daemonA $DIR_A
        Write-Host "  A's daemon killed."

        $daemonA = Start-Daemon $DIR_A ""
        Start-Sleep -Seconds 3
        $listedA = (Run-Cli @("--data-dir", $DIR_A, "transfers")).Out
        $paused = (($listedA -match "(?m)^send") -and $listedA -match "Paused")
        if (-not $paused -and $try -lt 4) {
            Write-Host "  the send finished before the kill landed at $sizeMB2 MB; retrying with $($sizeMB2 * 2) MB"
            $sizeMB2 = $sizeMB2 * 2
        }
    }
    Check $paused "after the restart, 'transfers' shows the send paused"
    $pub2 = Run-Cli $args2
    $mid2 = ($pub2.Out -split "\r?\n" | Where-Object { $_ -match "^miasma:" } | Select-Object -First 1)
    Check ($pub2.Code -eq 0 -and $mid2) "running the same network-publish again completed and printed a MID"

    Check (Wait-Peers $DIR_B 60) "node B is connected to the restarted node A before it starts receiving"
    $recv2 = Join-Path $TMP "received2.bin"
    $g2 = Run-Cli @("--data-dir", $DIR_B, "network-get", $mid2, "-o", $recv2, "--password-file", $pwFile)
    Check ($g2.Code -eq 0) "node B received the resumed publish"
    Check ((Test-Path $recv2) -and ((Sha $recv2) -eq $hash2)) "the resumed publish's file matches the original (SHA256)"
}
catch {
    Write-Host ("ERROR: " + $_.Exception.Message) -ForegroundColor Red
    $script:Failures++
}
finally {
    Cleanup
}

if ($script:Failures -eq 0) {
    Write-Host "`n=== PASS ===" -ForegroundColor Green
    exit 0
}
Write-Host ("`n=== FAIL: " + $script:Failures + " check(s) failed ===") -ForegroundColor Red
exit 1
