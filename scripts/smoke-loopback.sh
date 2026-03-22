#!/bin/bash
# smoke-loopback.sh — Two-node P2P loopback test (Linux/macOS)
#
# Validates the complete Miasma P2P flow:
#   1. Init two independent nodes (A and B)
#   2. Start daemon A
#   3. Start daemon B with bootstrap pointing to A
#   4. Verify peer connectivity
#   5. Publish content on A via network-publish
#   6. Retrieve content on B via network-get
#   7. Verify SHA256 integrity match
#
# Usage:
#   ./scripts/smoke-loopback.sh [--use-dist]
#
# Requirements:
#   - miasma binary (built from workspace or in dist/)
#   - No external network required (loopback 127.0.0.1)

set -euo pipefail

USE_DIST=false
for arg in "$@"; do
    case "$arg" in
        --use-dist) USE_DIST=true ;;
    esac
done

if [ "$USE_DIST" = true ] && [ -f "dist/miasma" ]; then
    CLI="dist/miasma"
elif [ -f "target/release/miasma" ]; then
    CLI="target/release/miasma"
elif [ -f "target/debug/miasma" ]; then
    CLI="target/debug/miasma"
else
    echo "ERROR: miasma binary not found. Build with: cargo build --release -p miasma-cli"
    exit 1
fi

echo "Using binary: $CLI"

DIR_A=$(mktemp -d /tmp/miasma-loopback-A-XXXXXX)
DIR_B=$(mktemp -d /tmp/miasma-loopback-B-XXXXXX)
PASS=0
FAIL=0

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    kill "$DAEMON_A_PID" "$DAEMON_B_PID" 2>/dev/null || true
    wait "$DAEMON_A_PID" "$DAEMON_B_PID" 2>/dev/null || true
    rm -rf "$DIR_A" "$DIR_B" /tmp/miasma-loopback-payload-*.txt /tmp/miasma-loopback-retrieved-*.txt
    echo "Temp dirs and daemons cleaned up."
    echo ""
    echo "=== Results: $PASS passed, $FAIL failed ==="
    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
}
trap cleanup EXIT

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

DAEMON_A_PID=0
DAEMON_B_PID=0

# ── Step 1: Initialize two nodes ─────────────────────────────────────────────
echo ""
echo "=== Step 1: Initialize nodes ==="
"$CLI" --data-dir "$DIR_A" init >/dev/null 2>&1 && pass "Node A initialized" || fail "Node A init"
"$CLI" --data-dir "$DIR_B" init >/dev/null 2>&1 && pass "Node B initialized" || fail "Node B init"

# ── Step 2: Start daemon A ───────────────────────────────────────────────────
echo ""
echo "=== Step 2: Start daemon A ==="
"$CLI" --data-dir "$DIR_A" daemon >/dev/null 2>&1 &
DAEMON_A_PID=$!
sleep 3

if kill -0 "$DAEMON_A_PID" 2>/dev/null; then
    pass "Daemon A running (PID=$DAEMON_A_PID)"
else
    fail "Daemon A did not start"
    exit 1
fi

# ── Step 3: Extract bootstrap address ────────────────────────────────────────
echo ""
echo "=== Step 3: Get bootstrap address ==="
STATUS_A=$("$CLI" --data-dir "$DIR_A" status 2>&1)

PEER_ID_A=$(echo "$STATUS_A" | grep -oP '12D3Koo\w+' | head -1)
# Get the loopback listen address
LISTEN_ADDR=$(echo "$STATUS_A" | grep -oP '/ip4/127\.0\.0\.1/udp/\d+/quic-v1' | head -1)

if [ -z "$LISTEN_ADDR" ]; then
    # Fallback: extract port from 0.0.0.0 address and construct loopback
    PORT=$(echo "$STATUS_A" | grep -oP '/ip4/0\.0\.0\.0/udp/\K\d+' | head -1)
    if [ -n "$PORT" ]; then
        LISTEN_ADDR="/ip4/127.0.0.1/udp/$PORT/quic-v1"
    fi
fi

BOOTSTRAP="${LISTEN_ADDR}/p2p/${PEER_ID_A}"
echo "  Bootstrap: $BOOTSTRAP"
if [ -n "$PEER_ID_A" ] && [ -n "$LISTEN_ADDR" ]; then
    pass "Bootstrap address extracted"
else
    fail "Could not extract bootstrap address"
    exit 1
fi

# ── Step 4: Start daemon B with bootstrap ────────────────────────────────────
echo ""
echo "=== Step 4: Start daemon B (bootstrap → A) ==="
"$CLI" --data-dir "$DIR_B" daemon --bootstrap "$BOOTSTRAP" >/dev/null 2>&1 &
DAEMON_B_PID=$!
sleep 5

if kill -0 "$DAEMON_B_PID" 2>/dev/null; then
    pass "Daemon B running (PID=$DAEMON_B_PID)"
else
    fail "Daemon B did not start"
    exit 1
fi

# ── Step 5: Verify peer connectivity ─────────────────────────────────────────
echo ""
echo "=== Step 5: Verify connectivity ==="
PEERS_A=$("$CLI" --data-dir "$DIR_A" status 2>&1 | grep -oP 'Connected peers:\s+\K\d+')
PEERS_B=$("$CLI" --data-dir "$DIR_B" status 2>&1 | grep -oP 'Connected peers:\s+\K\d+')

echo "  Node A peers: ${PEERS_A:-0}"
echo "  Node B peers: ${PEERS_B:-0}"

if [ "${PEERS_A:-0}" -ge 1 ]; then
    pass "Node A has peers"
else
    fail "Node A has no peers"
fi
if [ "${PEERS_B:-0}" -ge 1 ]; then
    pass "Node B has peers"
else
    fail "Node B has no peers"
fi

# ── Step 6: Publish content on Node A ────────────────────────────────────────
echo ""
echo "=== Step 6: Publish on Node A ==="
PAYLOAD_FILE="/tmp/miasma-loopback-payload-$$.txt"
TEST_CONTENT="Miasma P2P loopback test $(date -u +%Y-%m-%dT%H:%M:%SZ) pid=$$"
echo "$TEST_CONTENT" > "$PAYLOAD_FILE"

PUBLISH_OUT=$("$CLI" --data-dir "$DIR_A" network-publish "$PAYLOAD_FILE" 2>&1)
MID=$(echo "$PUBLISH_OUT" | grep -oP 'miasma:\S+' | head -1)

if [ -n "$MID" ]; then
    pass "Content published: $MID"
else
    fail "Publish returned no MID"
    echo "  Output: $PUBLISH_OUT"
    exit 1
fi

# Wait for DHT propagation and replication
sleep 3

# ── Step 7: Retrieve on Node B ───────────────────────────────────────────────
echo ""
echo "=== Step 7: Retrieve on Node B ==="
RETRIEVED_FILE="/tmp/miasma-loopback-retrieved-$$.txt"
RETRIEVE_OUT=$("$CLI" --data-dir "$DIR_B" network-get "$MID" --output "$RETRIEVED_FILE" 2>&1)

if [ -f "$RETRIEVED_FILE" ]; then
    pass "Content retrieved to file"
else
    fail "Retrieved file not found"
    echo "  Output: $RETRIEVE_OUT"
    exit 1
fi

# ── Step 8: Verify integrity ─────────────────────────────────────────────────
echo ""
echo "=== Step 8: Verify integrity ==="
ORIGINAL_HASH=$(sha256sum "$PAYLOAD_FILE" | awk '{print $1}')
RETRIEVED_HASH=$(sha256sum "$RETRIEVED_FILE" | awk '{print $1}')

echo "  Original:  $ORIGINAL_HASH"
echo "  Retrieved: $RETRIEVED_HASH"

if [ "$ORIGINAL_HASH" = "$RETRIEVED_HASH" ]; then
    pass "SHA256 matches — P2P round-trip verified"
    echo ""
    echo "  Content: $(cat "$RETRIEVED_FILE")"
else
    fail "SHA256 mismatch — data corruption"
    echo "  Original:  $(cat "$PAYLOAD_FILE")"
    echo "  Retrieved: $(cat "$RETRIEVED_FILE")"
fi
