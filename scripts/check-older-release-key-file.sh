#!/bin/bash
# check-older-release-key-file.sh -- run a RELEASED command-line program against
# a data directory whose master.key is 64 bytes instead of a plain 32-byte key.
#
# A 64-byte master.key means "the key is kept elsewhere". A released program
# reads master.key and accepts exactly 32 bytes; it must stop with a length
# error, must not create a key, and must leave the data directory as it was.
#
# Steps:
#   1. Download the macOS archive of the release and check it against SHA256SUMS.txt.
#   2. `miasma init` with that release to get a data directory it wrote itself.
#   3. Replace master.key with 64 random bytes and record every file's hash.
#   4. Run `daemon`, `dissolve` and `status` of that release against it.
#      `daemon` and `dissolve` must fail with the length error.
#   5. The recorded hashes must be unchanged and master.key must still be the
#      same 64 bytes.
#
# Usage:  scripts/check-older-release-key-file.sh [TAG]     (default v0.3.2-beta.11)
# Needs the GitHub CLI (`gh`, with GH_TOKEN set) and an Apple-silicon macOS host
# (the release archive holds an arm64 binary).

set -u

TAG="${1:-v0.3.2-beta.11}"
REPO="MasayukiTa/miasma-protocol"
export MIASMA_LANG=en

WORK="$(mktemp -d "${TMPDIR:-/tmp}/miasma-older-release-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
FAILURES=0

fail() {
    echo "FAIL: $1"
    FAILURES=$((FAILURES + 1))
}

# Hash of every file below $1, one line per file, sorted by path.
snapshot() {
    (
        cd "$1" || exit 1
        find . -type f | LC_ALL=C sort | while IFS= read -r f; do
            shasum -a 256 "$f"
        done
    )
}

# Run a command with a time limit; prints its output, returns its exit code
# (142 when the limit was hit).
run_limited() {
    perl -e 'alarm shift; exec @ARGV' 60 "$@" 2>&1
}

echo "== Download $TAG"
mkdir -p "$WORK/dl" "$WORK/bin"
gh release download "$TAG" --repo "$REPO" \
    --pattern 'miasma-macos.tar.gz' --pattern 'SHA256SUMS.txt' --dir "$WORK/dl" \
    || { echo "FAIL: cannot download the release"; exit 1; }
EXPECTED="$(grep ' miasma-macos.tar.gz$' "$WORK/dl/SHA256SUMS.txt" | awk '{print $1}')"
ACTUAL="$(shasum -a 256 "$WORK/dl/miasma-macos.tar.gz" | awk '{print $1}')"
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "FAIL: archive hash does not match SHA256SUMS.txt ($EXPECTED / $ACTUAL)"
    exit 1
fi
tar -xzf "$WORK/dl/miasma-macos.tar.gz" -C "$WORK/bin" miasma-macos/miasma || exit 1
CLI="$WORK/bin/miasma-macos/miasma"
chmod +x "$CLI"
xattr -dr com.apple.quarantine "$CLI" 2>/dev/null || true

echo "== Create a data directory with the released program"
DATA="$WORK/data"
export MIASMA_DATA_DIR="$DATA"
INIT_OUT="$(run_limited "$CLI" init)"
INIT_CODE=$?
echo "$INIT_OUT" | tail -n 3
if [ "$INIT_CODE" -ne 0 ] || [ ! -f "$DATA/master.key" ]; then
    echo "FAIL: init did not create a data directory (exit $INIT_CODE)"
    exit 1
fi
if [ "$(wc -c < "$DATA/master.key" | tr -d ' ')" != "32" ]; then
    echo "FAIL: the released program wrote a master.key that is not 32 bytes"
    exit 1
fi

echo "== Put a 64-byte file in place of master.key"
head -c 64 /dev/urandom > "$DATA/master.key"
if [ "$(wc -c < "$DATA/master.key" | tr -d ' ')" != "64" ]; then
    echo "FAIL: could not write the 64-byte file"
    exit 1
fi
head -c 1000 /dev/urandom > "$WORK/input.bin"
snapshot "$DATA" > "$WORK/before.txt"
echo "files in the data directory: $(wc -l < "$WORK/before.txt" | tr -d ' ')"

for cmd in "daemon" "dissolve $WORK/input.bin"; do
    echo "== miasma $cmd"
    # shellcheck disable=SC2086
    OUT="$(run_limited "$CLI" $cmd)"
    CODE=$?
    echo "$OUT" | tail -n 5
    echo "exit code: $CODE"
    if [ "$CODE" -eq 0 ]; then
        fail "'$cmd' succeeded against a 64-byte master.key"
    elif [ "$CODE" -eq 142 ]; then
        fail "'$cmd' did not stop (time limit)"
    elif ! echo "$OUT" | grep -qi 'wrong length'; then
        fail "'$cmd' failed, but not with the length error"
    fi
done

echo "== miasma status"
OUT="$(run_limited "$CLI" status)"
CODE=$?
echo "$OUT" | tail -n 5
echo "exit code: $CODE"
if [ "$CODE" -eq 142 ]; then
    fail "'status' did not stop (time limit)"
fi

echo "== Compare the data directory"
snapshot "$DATA" > "$WORK/after.txt"
# The released program stamps its own version into a file called "version" on
# start-up, before it looks at the key. That is not key or share data, so it is
# left out of the comparison (it is the one file this release adds by itself).
grep -v '  \./version$' "$WORK/before.txt" > "$WORK/before.cmp"
grep -v '  \./version$' "$WORK/after.txt" > "$WORK/after.cmp"
if ! diff "$WORK/before.cmp" "$WORK/after.cmp"; then
    fail "the data directory changed"
fi
if [ "$(wc -c < "$DATA/master.key" | tr -d ' ')" != "64" ]; then
    fail "master.key is no longer the 64-byte file"
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "$FAILURES check(s) failed"
    exit 1
fi
echo "OK: $TAG stops on a 64-byte master.key and leaves the data directory unchanged"
