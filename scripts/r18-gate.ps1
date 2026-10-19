# Runs the whole r18 gate with cargo, in order, and prints one line per step.
#
#   .\scripts\r18-gate.ps1                 run every step, stop at the first failure
#   .\scripts\r18-gate.ps1 -KeepGoing      run every step, report all failures at the end
#   .\scripts\r18-gate.ps1 -Seeds 7        run the seeded scenarios with seed 7 only
#   .\scripts\r18-gate.ps1 -Seeds 0..300   run them with seeds 0 to 299
#   .\scripts\r18-gate.ps1 -Repeat 5       run the whole gate five times (flakiness check)
#   .\scripts\r18-gate.ps1 -List           only print the commands
#
# Needs a Rust toolchain on PATH. Run it from any directory inside the
# repository. The seeded scenarios read R18_GATE_SEEDS; when it is not set they
# run their default schedule. A failing seeded test names its seed in the
# message; rerun that seed alone with -Seeds <n>.

[CmdletBinding()]
param(
    [string]$Seeds = '',
    [int]$Repeat = 1,
    [switch]$KeepGoing,
    [switch]$List
)

$ErrorActionPreference = 'Stop'
$root = (& git rev-parse --show-toplevel).Trim()
Set-Location $root

# Each entry: a label and the cargo arguments after "cargo".
$steps = @(
    # --- Unit tests of the r18 modules ---------------------------------------
    @('lib: capability negotiation and fragmentation', 'test --package miasma-core --lib protocol::'),
    @('lib: hybrid key exchange (pqc feature)', 'test --package miasma-core --features pqc --lib protocol::hybrid'),
    @('lib: wipe gate', 'test --package miasma-core --lib wipe::'),
    @('lib: key vault', 'test --package miasma-core --lib secure_memory::'),
    @('lib: cover traffic and its wire shape', 'test --package miasma-core --lib cover_traffic'),
    @('lib: onion cells', 'test --package miasma-core --lib onion::'),
    @('lib: piece maintenance', 'test --package miasma-core --lib repair::'),
    @('lib: maintenance daemon wiring', 'test --package miasma-core --lib daemon::maintenance_exec'),
    @('lib: transfer receive', 'test --package miasma-core --lib transfer::'),
    @('lib: payload transport selection', 'test --package miasma-core --lib transport::payload'),

    # --- New r18 test targets ------------------------------------------------
    @('r18 gate (chaos, crash, wipe, compatibility)', 'test --package miasma-core --test r18_gate_test'),
    @('piece maintenance on a real network', 'test --package miasma-core --test piece_maintenance_test'),
    @('RAM-only receive', 'test --package miasma-core --test receive_stream_test'),
    @('RAM-only receive, memory', 'test --package miasma-core --test receive_stream_ram'),
    @('transport chaos', 'test --package miasma-core --test transport_chaos_test'),
    @('wipe through a running daemon', 'test --package miasma-core --test wipe_daemon_test'),

    # --- Guards and compatibility --------------------------------------------
    @('persisted paths lint', 'test --package miasma-core --test persisted_paths_lint'),
    @('wire compatibility: push and chat frames', 'test --package miasma-core --test wire_compat_test'),
    @('wire compatibility: group chat frames', 'test --package miasma-core --test wire_compat_group_test'),
    @('wire compatibility: older peers over iroh', 'test --package miasma-core --test wire_compat_net_test'),

    # --- Adversarial suites --------------------------------------------------
    @('adversarial: control interface', 'test --package miasma-core --test adversarial_ipc_test'),
    @('adversarial: storage', 'test --package miasma-core --test adversarial_storage_test'),
    @('adversarial: transfer', 'test --package miasma-core --test adversarial_transfer_test'),
    @('adversarial: protocol', 'test --package miasma-core --test adversarial_test')
)

if ($List) {
    foreach ($s in $steps) { Write-Output ("cargo " + $s[1] + "    # " + $s[0]) }
    exit 0
}

if ($Seeds -ne '') { $env:R18_GATE_SEEDS = $Seeds }

$failed = @()
for ($run = 1; $run -le $Repeat; $run++) {
    if ($Repeat -gt 1) { Write-Output ("=== run $run of $Repeat ===") }
    foreach ($s in $steps) {
        $label = $s[0]
        $watch = [Diagnostics.Stopwatch]::StartNew()
        & cargo ($s[1] -split ' ')
        $code = $LASTEXITCODE
        $watch.Stop()
        $status = if ($code -eq 0) { 'ok  ' } else { 'FAIL' }
        Write-Output ("{0} {1,6:N1}s  {2}" -f $status, $watch.Elapsed.TotalSeconds, $label)
        if ($code -ne 0) {
            $failed += ("run $run : " + $label)
            if (-not $KeepGoing) {
                Write-Output "stopped at the first failure (use -KeepGoing to run on)"
                exit 1
            }
        }
    }
}

if ($failed.Count -gt 0) {
    Write-Output ""
    Write-Output "failed steps:"
    $failed | ForEach-Object { Write-Output ("  " + $_) }
    exit 1
}
Write-Output "r18 gate: all steps passed"
exit 0
