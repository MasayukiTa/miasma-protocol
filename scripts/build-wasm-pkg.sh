#!/usr/bin/env bash
# Build the browser package (the contents of web/pkg) from crates/miasma-wasm.
#
#   scripts/build-wasm-pkg.sh OUT_DIR   build into OUT_DIR (CI does this and compares with web/pkg)
#   scripts/build-wasm-pkg.sh --update  rebuild web/pkg in place, then rewrite
#                                       crates/miasma-wasm/pkg-build.json and web/asset-manifest.json
#
# This is the same two steps wasm-pack runs for
#   wasm-pack build crates/miasma-wasm --target web --out-dir ../../web/pkg
# (cargo release build for wasm32-unknown-unknown, then wasm-bindgen --target web;
# wasm-opt is off, see the wasm-pack profile in crates/miasma-wasm/Cargo.toml),
# without wasm-pack itself, so the only tool version that matters is
# wasm-bindgen-cli, which must equal the wasm-bindgen version in Cargo.lock:
#
#   cargo install wasm-bindgen-cli --version <version in Cargo.lock> --locked
#   rustup target add wasm32-unknown-unknown
#
# The .wasm bytes embed absolute build paths and so differ between machines;
# scripts/check-wasm-pkg.mjs compares what is stable (see its header).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

want="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, "", $0); print; exit }' Cargo.lock)"
have="$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }' || true)"
if [ -z "$want" ]; then echo "cannot read the wasm-bindgen version from Cargo.lock" >&2; exit 1; fi
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen-cli is '${have:-missing}', Cargo.lock needs $want: cargo install wasm-bindgen-cli --version $want --locked" >&2
  exit 1
fi

update=0
if [ "${1:-}" = "--update" ]; then
  update=1
  out="$root/web/pkg"
elif [ -n "${1:-}" ]; then
  out="$1"
else
  echo "usage: scripts/build-wasm-pkg.sh OUT_DIR | --update" >&2
  exit 2
fi

# Keep the machine's own paths (home directory, user name) out of the .wasm:
# panic locations in a release build would otherwise embed them.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$root=/miasma --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"

cargo build --package miasma-wasm --lib --release --target wasm32-unknown-unknown --locked
target_dir="${CARGO_TARGET_DIR:-$root/target}"
mkdir -p "$out"
wasm-bindgen "$target_dir/wasm32-unknown-unknown/release/miasma_wasm.wasm" \
  --target web --typescript --out-dir "$out" --out-name miasma_wasm

if [ "$update" = 1 ]; then
  node scripts/check-wasm-pkg.mjs --write
  node scripts/web-asset-manifest.mjs
fi
