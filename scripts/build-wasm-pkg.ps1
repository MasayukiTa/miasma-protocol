# Build the browser package (the contents of web/pkg) from crates/miasma-wasm.
#
#   scripts\build-wasm-pkg.ps1 -OutDir <dir>   build into <dir>
#   scripts\build-wasm-pkg.ps1 -Update         rebuild web/pkg in place, then rewrite
#                                              crates/miasma-wasm/pkg-build.json and web/asset-manifest.json
#
# Same steps as scripts/build-wasm-pkg.sh (see the notes there). wasm-bindgen-cli
# must equal the wasm-bindgen version in Cargo.lock:
#   cargo install wasm-bindgen-cli --version <version in Cargo.lock> --locked
[CmdletBinding()]
param(
  [string]$OutDir = '',
  [switch]$Update
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$lock = Get-Content (Join-Path $root 'Cargo.lock') -Raw
$m = [regex]::Match($lock, 'name = "wasm-bindgen"\r?\nversion = "([^"]+)"')
if (-not $m.Success) { throw 'cannot read the wasm-bindgen version from Cargo.lock' }
$want = $m.Groups[1].Value
$have = ''
try { $have = ((& wasm-bindgen --version) -split ' ')[1] } catch { }
if ($have -ne $want) {
  throw "wasm-bindgen-cli is '$have', Cargo.lock needs ${want}: cargo install wasm-bindgen-cli --version $want --locked"
}

if ($Update) { $out = Join-Path $root 'web\pkg' }
elseif ($OutDir) { $out = $OutDir }
else { throw 'pass -OutDir <dir> or -Update' }

cargo build --package miasma-wasm --lib --release --target wasm32-unknown-unknown --locked
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
New-Item -ItemType Directory -Force $out | Out-Null
wasm-bindgen (Join-Path $targetDir 'wasm32-unknown-unknown\release\miasma_wasm.wasm') `
  --target web --typescript --out-dir $out --out-name miasma_wasm
if ($LASTEXITCODE -ne 0) { throw 'wasm-bindgen failed' }

if ($Update) {
  node scripts/check-wasm-pkg.mjs --write
  node scripts/web-asset-manifest.mjs
}
