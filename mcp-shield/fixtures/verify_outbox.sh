#!/usr/bin/env bash
# Drives MCP-Shield's durable outbox end-to-end. No Docker required: a local
# Node stub stands in for the dashboard's /api/ingest so its availability and
# its status code can both be controlled.
#
#   Phase A: dashboard DOWN  -> events must persist to the spool, proxy still works
#   Phase B: dashboard UP    -> the next invocation must deliver phase A's backlog
#   Phase C: dashboard 401   -> events must dead-letter, not retry forever
#
# Phase B is the claim that matters for a short-lived process: MCP-Shield exits
# when the agent closes stdin, so it cannot retry on a background loop the way
# the Python services do. It must pick the backlog up on its *next* run.
#
# Usage: bash fixtures/verify_outbox.sh    (from mcp-shield/)
set -u

SHIELD_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOKEN="test-token-0123456789abcdef"
PORT="${PORT:-4599}"

# Windows builds carry a .exe suffix; Linux/macOS do not.
BIN="$SHIELD_DIR/target/debug/mcp-shield"
[ -x "$BIN" ] || BIN="$SHIELD_DIR/target/debug/mcp-shield.exe"
if [ ! -x "$BIN" ]; then
  echo "error: no debug binary at $SHIELD_DIR/target/debug/mcp-shield[.exe] — run 'cargo build' first." >&2
  exit 1
fi

# `cargo test` builds the unittest binary, NOT the bin target: a stale
# target/debug/mcp-shield silently tests the previous source. Always rebuild.
( cd "$SHIELD_DIR" && cargo build --quiet ) || exit 1

WORK="$SHIELD_DIR/target/outbox-verify"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

REQUESTS='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

run_shield() {
  # Outbox/baseline paths stay RELATIVE to $WORK on purpose: MSYS (Git Bash on
  # Windows) rewrites a leading-slash env value into a Windows path.
  ( cd "$WORK" && echo "$REQUESTS" | \
    MONOLITH_DASHBOARD_URL="http://127.0.0.1:$PORT/api/ingest" \
    MONOLITH_EVENT_TOKEN="$TOKEN" \
    MONOLITH_EVENT_OUTBOX_PATH="outbox.jsonl" \
    MCP_SHIELD_BASELINE="baseline.json" \
    "$BIN" python "$SHIELD_DIR/fixtures/fake_mcp_server.py" \
    >shield_stdout.txt 2>shield_stderr.txt )
}

spool_count() { [ -f outbox.jsonl ] && grep -c . outbox.jsonl || echo 0; }

echo "=============================================="
echo "PHASE A — dashboard DOWN"
echo "=============================================="
run_shield
A_SPOOL=$(spool_count)
echo "spooled events:            $A_SPOOL"
echo "proxy stdout (MCP stream): $(grep -c . shield_stdout.txt) lines"
[ "$A_SPOOL" -gt 0 ] && echo "PASS: events persisted while the dashboard was unreachable" \
                     || { echo "FAIL: nothing spooled"; exit 1; }
grep -q '"jsonrpc"' shield_stdout.txt && echo "PASS: proxy still served the MCP stream" \
                                      || { echo "FAIL: proxy path broken"; exit 1; }

echo
echo "=============================================="
echo "PHASE B — dashboard UP, backlog must drain"
echo "=============================================="
OUT="received.json" PORT="$PORT" RESPOND=201 node "$SHIELD_DIR/fixtures/fake_ingest.js" &
SRV=$!
sleep 1
run_shield
sleep 1
kill $SRV 2>/dev/null
B_SPOOL=$(spool_count)
DELIVERED=$(node -e 'console.log(require("./received.json").length)' 2>/dev/null || echo 0)
echo "events delivered:          $DELIVERED"
echo "events left on spool:      $B_SPOOL"
[ "$DELIVERED" -ge "$A_SPOOL" ] && echo "PASS: phase A backlog was redelivered by the next run" \
                                || { echo "FAIL: backlog not delivered"; exit 1; }
[ "$B_SPOOL" -eq 0 ] && echo "PASS: spool compacted to empty after delivery" \
                     || { echo "FAIL: spool still holds $B_SPOOL"; exit 1; }

echo
echo "--- delivered envelope checks ---"
TOKEN="$TOKEN" node -e '
const r = require("./received.json");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
let ok = true;
const ids = new Set();
for (const { auth, body } of r) {
  const e = JSON.parse(body);
  if (auth !== "Bearer " + process.env.TOKEN) { console.log("FAIL: bad auth header:", auth); ok = false; }
  if (!UUID.test(e.event_id)) { console.log("FAIL: event_id not a v4 UUID:", e.event_id); ok = false; }
  if (e.module !== "mcp-shield") { console.log("FAIL: module:", e.module); ok = false; }
  if (e.schema_version !== 2) { console.log("FAIL: schema_version:", e.schema_version); ok = false; }
  ids.add(e.event_id);
}
console.log("distinct event_ids:       " + ids.size + " / " + r.length);
console.log("event types:              " + r.map(x => JSON.parse(x.body).event_type).join(", "));
if (ok) console.log("PASS: every envelope carried a valid bearer token + v4 UUID + schema_version 2");
process.exit(ok ? 0 : 1);
' || exit 1

echo
echo "=============================================="
echo "PHASE C — dashboard rejects with 401"
echo "=============================================="
# Drop the baseline so this run registers one again and therefore actually
# emits an event to be rejected — a clean re-sighting emits nothing, which
# would make this phase pass vacuously.
rm -f received.json baseline.json
OUT="received.json" PORT="$PORT" RESPOND=401 node "$SHIELD_DIR/fixtures/fake_ingest.js" &
SRV=$!
sleep 1
run_shield
sleep 1
kill $SRV 2>/dev/null
C_SPOOL=$(spool_count)
C_DEAD=$([ -f outbox.dead ] && grep -c . outbox.dead || echo 0)
echo "events left on spool:      $C_SPOOL"
echo "events dead-lettered:      $C_DEAD"
[ "$C_DEAD" -gt 0 ] && echo "PASS: a permanent rejection dead-letters instead of retrying forever" \
                    || { echo "FAIL: nothing dead-lettered"; exit 1; }
[ "$C_SPOOL" -eq 0 ] && echo "PASS: rejected events did not stay pending" \
                     || { echo "FAIL: $C_SPOOL still pending"; exit 1; }

echo
echo "ALL PHASES PASSED"
