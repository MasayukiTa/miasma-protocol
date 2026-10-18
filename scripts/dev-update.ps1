<#
.SYNOPSIS
  Developer rebuild flow: copy freshly built Miasma programs into an install
  folder with the same rename-swap and .prev rotation the app's updater uses.

.DESCRIPTION
  A running program cannot be overwritten on Windows but it can be renamed, so
  the swap is a sequence of renames in the install folder:

      miasma.exe       -> miasma.exe.old.<id>
      miasma.exe.new   -> miasma.exe
      (miasma.exe --version must answer within 10 s and report the build that
       was copied; the desktop program is never started with arguments)
      miasma.exe.old.<id> -> miasma.exe.prev   (the one backup that is kept)

  If the check fails, or a rename fails, the old files are renamed back.
  Nothing is started or stopped by name: with -StopOwn only processes whose
  executable path is inside InstallDir are stopped (by process id).

.PARAMETER BuildDir
  Folder with the freshly built programs. Default: target\release

.PARAMETER InstallDir
  The install folder to update. Required.

.PARAMETER StopOwn
  Stop the Miasma processes that run from InstallDir before swapping. Without
  it the script refuses to continue while any is running.

.EXAMPLE
  .\scripts\dev-update.ps1 -InstallDir C:\Tools\miasma
  .\scripts\dev-update.ps1 -BuildDir C:\build\release -InstallDir C:\Tools\miasma -StopOwn
#>
[CmdletBinding()]
param(
    [string]$BuildDir = "target\release",
    [Parameter(Mandatory = $true)][string]$InstallDir,
    [switch]$StopOwn
)

$ErrorActionPreference = "Stop"

$Names = @("miasma.exe", "miasma-desktop.exe", "miasma-bridge.exe")
$Cli = "miasma.exe"

function Resolve-Dir([string]$p, [string]$what) {
    if (-not (Test-Path -LiteralPath $p -PathType Container)) {
        Write-Error "$what not found: $p"
    }
    return (Resolve-Path -LiteralPath $p).ProviderPath.TrimEnd('\')
}

# Run <exe> --version with a time limit; returns the first output line.
function Get-VersionLine([string]$exe, [int]$timeoutMs = 10000) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = "--version"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    if (-not $p.WaitForExit($timeoutMs)) {
        try { $p.Kill() } catch {}
        throw "no answer from $exe within $($timeoutMs / 1000) s"
    }
    if ($p.ExitCode -ne 0) { throw "$exe --version exited with $($p.ExitCode)" }
    $line = ($p.StandardOutput.ReadToEnd() -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $line -or $line -notmatch '^miasma \S+ \([A-Za-z0-9]+\)\s*$') {
        throw "unexpected --version output from $exe"
    }
    return $line.Trim()
}

function Get-OwnProcesses([string]$dir) {
    $prefix = $dir.TrimEnd('\') + '\'
    $found = @()
    foreach ($proc in Get-Process -ErrorAction SilentlyContinue) {
        $path = $null
        try { $path = $proc.Path } catch {}
        if ($path -and $path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $found += $proc
        }
    }
    return $found
}

$build = Resolve-Dir $BuildDir "BuildDir"
$install = Resolve-Dir $InstallDir "InstallDir"
if ($build -ieq $install) { Write-Error "BuildDir and InstallDir are the same folder" }

if (-not (Test-Path -LiteralPath (Join-Path $build $Cli))) { Write-Error "$Cli is not in $build" }
if (-not (Test-Path -LiteralPath (Join-Path $install $Cli))) { Write-Error "$Cli is not in $install (not an install folder)" }

# Every program installed must come from the build, or the result mixes two builds.
# The bridge is optional on both sides.
$todo = @()
foreach ($n in $Names) {
    $inBuild = Test-Path -LiteralPath (Join-Path $build $n)
    $inInstall = Test-Path -LiteralPath (Join-Path $install $n)
    if ($inInstall -and -not $inBuild -and $n -ne "miasma-bridge.exe") {
        Write-Error "$n is installed but the build folder has no $n"
    }
    if ($inBuild -and ($inInstall -or $n -eq $Cli)) { $todo += $n }
}

# The build must report a version before anything is touched.
$buildLine = Get-VersionLine (Join-Path $build $Cli)
Write-Host "build:   $buildLine"
Write-Host "current: $(Get-VersionLine (Join-Path $install $Cli))"

# Refuse while Miasma runs from the install folder, unless asked to stop it.
$own = @(Get-OwnProcesses $install)
if ($own.Count -gt 0) {
    if (-not $StopOwn) {
        Write-Host "These processes run from ${install}:"
        $own | ForEach-Object { Write-Host ("  {0} (pid {1})" -f $_.ProcessName, $_.Id) }
        Write-Host "Close them, or run again with -StopOwn to stop exactly these processes."
        exit 2
    }
    foreach ($proc in $own) {
        Write-Host ("stopping {0} (pid {1})" -f $proc.ProcessName, $proc.Id)
        Stop-Process -Id $proc.Id -Force
    }
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline -and @(Get-OwnProcesses $install).Count -gt 0) {
        Start-Sleep -Milliseconds 200
    }
    if (@(Get-OwnProcesses $install).Count -gt 0) {
        Write-Error "some processes from $install are still running"
    }
}

$id = -join ((1..8) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })

# Leftovers of an attempt that never finished.
foreach ($n in $Names) {
    Remove-Item -LiteralPath (Join-Path $install "$n.new") -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $install -Filter "$n.failed.*" -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
}

# Stage: copy next to the old files and check the copy.
foreach ($n in $todo) {
    $dest = Join-Path $install "$n.new"
    Copy-Item -LiteralPath (Join-Path $build $n) -Destination $dest -Force
    $a = (Get-FileHash -LiteralPath (Join-Path $build $n) -Algorithm SHA256).Hash
    $b = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    if ($a -ne $b) {
        foreach ($m in $todo) { Remove-Item -LiteralPath (Join-Path $install "$m.new") -Force -ErrorAction SilentlyContinue }
        Write-Error "the copy of $n does not match the build"
    }
}

function Restore-All {
    foreach ($n in $todo) {
        $cur = Join-Path $install $n
        $old = Join-Path $install "$n.old.$id"
        $failed = Join-Path $install "$n.failed.$id"
        if (Test-Path -LiteralPath $old) {
            if (Test-Path -LiteralPath $cur) { Rename-Item -LiteralPath $cur -NewName "$n.failed.$id" -Force -ErrorAction SilentlyContinue }
            Rename-Item -LiteralPath $old -NewName $n -Force
        }
        Remove-Item -LiteralPath $failed -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $install "$n.new") -Force -ErrorAction SilentlyContinue
    }
}

# Swap.
try {
    foreach ($n in $todo) {
        $cur = Join-Path $install $n
        if (Test-Path -LiteralPath $cur) { Rename-Item -LiteralPath $cur -NewName "$n.old.$id" -Force }
        Rename-Item -LiteralPath (Join-Path $install "$n.new") -NewName $n -Force
    }
    $after = Get-VersionLine (Join-Path $install $Cli)
    if ($after -ne $buildLine) { throw "the installed program reports '$after', not '$buildLine'" }
}
catch {
    Write-Host "update failed ($($_.Exception.Message)); restoring the previous version"
    Restore-All
    exit 1
}

# Keep exactly one backup: the version just replaced.
foreach ($n in $todo) {
    $old = Join-Path $install "$n.old.$id"
    $prev = Join-Path $install "$n.prev"
    if (Test-Path -LiteralPath $old) {
        Remove-Item -LiteralPath $prev -Force -ErrorAction SilentlyContinue
        try { Rename-Item -LiteralPath $old -NewName "$n.prev" -Force }
        catch { Write-Host "could not keep $n.prev ($($_.Exception.Message)); the old file stays as $n.old.$id" }
    }
    Get-ChildItem -LiteralPath $install -Filter "$n.old.*" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "$n.old.$id" } |
        ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
}

Write-Host "updated: $($todo -join ', ')"
Write-Host "now:     $after"
Write-Host "the previous version is kept as <program>.prev"
exit 0
