#!/bin/bash
# transfer-e2e.sh -- end-to-end check of protected, resumable transfer with the
# real miasma binary, including a hard kill of each daemon part-way through.
#
# Two nodes on loopback. In order:
#   1. A password-protected, multi-segment file is published from node A.
#   2. Node B is refused with a wrong password, and with no password, before
#      any data moves.
#   3. B starts receiving; its daemon is KILLED after the first segment lands;
#      restarted; `miasma transfers` shows the paused transfer; running the same
#      `network-get` again resumes it. The result must match by SHA256.
#   4. A publishes a second file; ITS daemon is killed after the first segment;
#      restarted; running the same `network-publish` resumes it; B receives it.
#
# Run this on each machine BEFORE a cross-machine test: it is the check that the
# binary built there works at all.
#
# Usage:  scripts/transfer-e2e.sh [--cli PATH] [--size-mb N] [--keep]
# Works with the macOS default bash (3.2) and Linux.

set -u

# This script greps the CLI's English wording ("wrong password", "Paused", "seg N/M", ...).
# The CLI follows the OS language by default, so pin it.
export MIASMA_LANG=en

CLI=""
SIZE_MB=40
K=2
N=3
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --cli) CLI="$2"; shift 2 ;;
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1"; exit 2 ;;
    esac
done

HERE="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "$CLI" ]; then
    for c in target/release/miasma target/debug/miasma; do
        if [ -x "$HERE/$c" ]; then CLI="$HERE/$c"; break; fi
    done
fi
if [ -z "$CLI" ] || [ ! -x "$CLI" ]; then
    echo "miasma binary not found. Build with: cargo build --release -p miasma-cli"
    exit 1
fi
echo "Using $CLI"

TMP="$(mktemp -d /tmp/miasma-e2e-XXXXXX)"
DIR_A="$TMP/node-a"
DIR_B="$TMP/node-b"
mkdir -p "$DIR_A" "$DIR_B"
FAILURES=0
PID_A=""
PID_B=""

check() {  # check <0|1 ok> <description>
    if [ "$1" = "1" ]; then echo "  PASS: $2"; else echo "  FAIL: $2"; FAILURES=$((FAILURES + 1)); fi
}

cleanup() {
    [ -n "$PID_A" ] && kill -9 "$PID_A" 2>/dev/null
    [ -n "$PID_B" ] && kill -9 "$PID_B" 2>/dev/null
    sleep 1
    if [ "$KEEP" = "0" ]; then rm -rf "$TMP"; else echo "Kept: $TMP"; fi
}
trap cleanup EXIT

sha() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

new_file() {  # new_file <path> <MB>
    head -c $(( $2 * 1024 * 1024 )) /dev/urandom > "$1"
}

start_daemon() {  # start_daemon <dir> <bootstrap or ""> -> prints pid
    local dir="$1" boot="$2"
    rm -f "$dir/daemon.port"
    if [ -n "$boot" ]; then
        "$CLI" --data-dir "$dir" daemon --bootstrap "$boot" >"$dir/daemon-$RANDOM.log" 2>&1 &
    else
        "$CLI" --data-dir "$dir" daemon >"$dir/daemon-$RANDOM.log" 2>&1 &
    fi
    local pid=$!
    local i=0
    while [ ! -f "$dir/daemon.port" ] && [ $i -lt 100 ]; do sleep 0.3; i=$((i + 1)); done
    if [ ! -f "$dir/daemon.port" ]; then echo "daemon in $dir did not start" >&2; return 1; fi
    echo "$pid"
}

kill_daemon() {  # kill_daemon <pid> <dir>
    kill -9 "$1" 2>/dev/null
    wait "$1" 2>/dev/null
    rm -f "$2/daemon.port"
}

segments_done() {  # segments_done <dir> <match or ""> -> highest "seg N/M" N, or -1
    local dir="$1" match="$2" best=-1 n
    local listing
    listing="$("$CLI" --data-dir "$dir" transfers 2>/dev/null)"
    if [ -n "$match" ]; then
        listing="$(echo "$listing" | grep -A2 -F "$match")"
    fi
    for n in $(echo "$listing" | grep -o 'seg [0-9]*/' | sed 's/seg //; s/\///'); do
        [ "$n" -gt "$best" ] && best="$n"
    done
    echo "$best"
}

wait_segments() {  # wait_segments <dir> <match> <at least> <timeout s>
    local i=0
    while [ $i -lt $(( $4 * 2 )) ]; do
        if [ "$(segments_done "$1" "$2")" -ge "$3" ]; then return 0; fi
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}

peers_of() {  # peers_of <dir> -> "Connected peers: N" from `miasma status` (empty if the daemon is silent)
    "$CLI" --data-dir "$1" status 2>/dev/null | sed -n 's/.*Connected peers: *\([0-9][0-9]*\).*/\1/p' | head -1
}

# Wait until the node at <dir> is connected to at least one peer: what the runbook tells
# the user to do before starting a transfer, so the script does the same.
wait_peers() {  # wait_peers <dir> <timeout s>
    local i=0 p
    while [ $i -lt $(( $2 * 2 )) ]; do
        p="$(peers_of "$1")"
        if [ -n "$p" ] && [ "$p" -ge 1 ]; then return 0; fi
        sleep 0.5
        i=$((i + 1))
    done
    return 1
}

echo "=== Miasma protected + resumable transfer, end to end ==="

PORT_A=$(( 21000 + RANDOM % 800 ))
PORT_B=$(( PORT_A + 1 ))
"$CLI" --data-dir "$DIR_A" init --listen-addr "/ip4/127.0.0.1/tcp/$PORT_A" >/dev/null 2>&1
"$CLI" --data-dir "$DIR_B" init --listen-addr "/ip4/127.0.0.1/tcp/$PORT_B" >/dev/null 2>&1

PID_A="$(start_daemon "$DIR_A" "")" || exit 1
sleep 2
BOOT="$("$CLI" --data-dir "$DIR_A" status 2>/dev/null | sed -n 's/.*Listen addr: *\([^ ]*\).*/\1/p' | head -1)"
[ -n "$BOOT" ] || { echo "could not read node A's listen address"; exit 1; }
echo "  Node A: $BOOT"
PID_B="$(start_daemon "$DIR_B" "$BOOT")" || exit 1
wait_peers "$DIR_B" 60 && check 1 "node B is connected to node A before the first transfer" || check 0 "node B is connected to node A before the first transfer"

PW="$TMP/password.txt";  printf 'e2e-correct-horse\n' > "$PW"
BADPW="$TMP/wrong.txt";  printf 'not-the-password\n' > "$BADPW"

# ---- 1. publish -------------------------------------------------------------
echo
echo "[1] Publish ${SIZE_MB} MB, password-protected, k=$K n=$N"
SRC1="$TMP/payload1.bin"; new_file "$SRC1" "$SIZE_MB"; HASH1="$(sha "$SRC1")"
MID1="$("$CLI" --data-dir "$DIR_A" network-publish "$SRC1" --data-shards $K --total-shards $N --password-file "$PW" 2>/dev/null | grep '^miasma:' | head -1)"
if [ -n "$MID1" ]; then check 1 "network-publish succeeded and printed a MID"; else check 0 "network-publish succeeded and printed a MID"; fi
echo "  MID: $MID1"

# ---- 2. refused without the password ----------------------------------------
echo
echo "[2] Wrong and missing passwords are refused before any data moves"
OUT2="$TMP/should-not-exist.bin"
R="$("$CLI" --data-dir "$DIR_B" network-get "$MID1" -o "$OUT2" --password-file "$BADPW" 2>&1)"; RC=$?
if [ $RC -ne 0 ] && echo "$R" | grep -qi "wrong password"; then check 1 "wrong password: non-zero exit and 'wrong password'"; else check 0 "wrong password: non-zero exit and 'wrong password'"; fi
R="$("$CLI" --data-dir "$DIR_B" network-get "$MID1" -o "$OUT2" 2>&1)"; RC=$?
if [ $RC -ne 0 ] && echo "$R" | grep -qi "password"; then check 1 "no password: non-zero exit and a password message"; else check 0 "no password: non-zero exit and a password message"; fi
if [ ! -e "$OUT2" ] && [ ! -e "$OUT2.part" ]; then check 1 "neither attempt left an output or a .part file"; else check 0 "neither attempt left an output or a .part file"; fi

# ---- 3. receiver killed mid-transfer ----------------------------------------
echo
echo "[3] Receiver: kill B's daemon after the first segment, restart, resume"
RECV="$TMP/received1.bin"
"$CLI" --data-dir "$DIR_B" network-get "$MID1" -o "$RECV" --password-file "$PW" --no-wait >/dev/null 2>&1; RC=$?
[ $RC -eq 0 ] && check 1 "network-get --no-wait started the transfer" || check 0 "network-get --no-wait started the transfer"
wait_segments "$DIR_B" "$MID1" 1 900 && check 1 "the first segment was received" || check 0 "the first segment was received"
kill_daemon "$PID_B" "$DIR_B"; PID_B=""
echo "  B's daemon killed."
[ ! -e "$RECV" ] && check 1 "no output file while incomplete" || check 0 "no output file while incomplete"
[ -e "$RECV.part" ] && check 1 "the partial file is kept" || check 0 "the partial file is kept"

PID_B="$(start_daemon "$DIR_B" "$BOOT")" || exit 1
wait_peers "$DIR_B" 60 && check 1 "after the restart, node B is connected to node A again" || check 0 "after the restart, node B is connected to node A again"
LISTED="$("$CLI" --data-dir "$DIR_B" transfers 2>/dev/null)"
if echo "$LISTED" | grep -q "Paused" && echo "$LISTED" | grep -q "resumable"; then check 1 "after the restart, 'transfers' shows it paused and resumable"; else check 0 "after the restart, 'transfers' shows it paused and resumable"; fi
DONE_BEFORE="$(segments_done "$DIR_B" "$MID1")"
echo "  Segments already safe on disk: $DONE_BEFORE"
[ "$DONE_BEFORE" -ge 1 ] && check 1 "the journal remembers the finished segment(s)" || check 0 "the journal remembers the finished segment(s)"

"$CLI" --data-dir "$DIR_B" network-get "$MID1" -o "$RECV" --password-file "$PW" >/dev/null 2>&1; RC=$?
[ $RC -eq 0 ] && check 1 "running the same network-get again completed" || check 0 "running the same network-get again completed"
if [ -f "$RECV" ] && [ "$(sha "$RECV")" = "$HASH1" ]; then check 1 "the received file matches the original byte for byte (SHA256)"; else check 0 "the received file matches the original byte for byte (SHA256)"; fi
[ ! -e "$RECV.part" ] && check 1 "the .part file is gone" || check 0 "the .part file is gone"

# ---- 4. sender killed mid-publish -------------------------------------------
echo
echo "[4] Sender: kill A's daemon after the first segment, restart, resume"
# The kill has to land while the send is still running. On a fast machine a small file can
# finish between the poll that sees segment 1 and the kill; the job is then complete, its
# journal is gone, and there is nothing to resume (seen on a fast CI runner). That is a
# property of the machine, not a defect, so retry with a file twice as large (each attempt
# uses its own file name) until the kill provably came mid-send.
SIZE2="$SIZE_MB"
PAUSED=0
TRY=1
while [ "$TRY" -le 4 ] && [ "$PAUSED" = "0" ]; do
    NAME2="payload2-$TRY.bin"
    SRC2="$TMP/$NAME2"; new_file "$SRC2" "$SIZE2"; HASH2="$(sha "$SRC2")"
    "$CLI" --data-dir "$DIR_A" network-publish "$SRC2" --data-shards $K --total-shards $N --password-file "$PW" --no-wait >/dev/null 2>&1; RC=$?
    [ $RC -eq 0 ] && check 1 "network-publish --no-wait started the publish (${SIZE2} MB)" || check 0 "network-publish --no-wait started the publish (${SIZE2} MB)"
    wait_segments "$DIR_A" "$NAME2" 1 900 && check 1 "the first segment was published" || check 0 "the first segment was published"
    kill_daemon "$PID_A" "$DIR_A"; PID_A=""
    echo "  A's daemon killed."

    PID_A="$(start_daemon "$DIR_A" "")" || exit 1
    sleep 3
    LISTED_A="$("$CLI" --data-dir "$DIR_A" transfers 2>/dev/null)"
    if echo "$LISTED_A" | grep -q "^send" && echo "$LISTED_A" | grep -q "Paused"; then
        PAUSED=1
    elif [ "$TRY" -lt 4 ]; then
        echo "  the send finished before the kill landed at ${SIZE2} MB; retrying with $(( SIZE2 * 2 )) MB"
        SIZE2=$(( SIZE2 * 2 ))
    fi
    TRY=$(( TRY + 1 ))
done
[ "$PAUSED" = "1" ] && check 1 "after the restart, 'transfers' shows the send paused" || check 0 "after the restart, 'transfers' shows the send paused"
MID2="$("$CLI" --data-dir "$DIR_A" network-publish "$SRC2" --data-shards $K --total-shards $N --password-file "$PW" 2>/dev/null | grep '^miasma:' | head -1)"
[ -n "$MID2" ] && check 1 "running the same network-publish again completed and printed a MID" || check 0 "running the same network-publish again completed and printed a MID"

wait_peers "$DIR_B" 60 && check 1 "node B is connected to the restarted node A before it starts receiving" || check 0 "node B is connected to the restarted node A before it starts receiving"
RECV2="$TMP/received2.bin"
"$CLI" --data-dir "$DIR_B" network-get "$MID2" -o "$RECV2" --password-file "$PW" >/dev/null 2>&1; RC=$?
[ $RC -eq 0 ] && check 1 "node B received the resumed publish" || check 0 "node B received the resumed publish"
if [ -f "$RECV2" ] && [ "$(sha "$RECV2")" = "$HASH2" ]; then check 1 "the resumed publish's file matches the original (SHA256)"; else check 0 "the resumed publish's file matches the original (SHA256)"; fi

echo
if [ "$FAILURES" -eq 0 ]; then echo "=== PASS ==="; exit 0; fi
echo "=== FAIL: $FAILURES check(s) failed ==="
exit 1
