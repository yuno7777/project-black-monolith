#!/usr/bin/env bash
# Proves the cross-layer session circuit breaker against the running Compose
# stack: two independent layers reporting critical detections revoke the
# session, every layer enforces the refusal, and an analyst restore releases
# all of them again.
#
# The enforcement half matters as much as the trip: a breaker that only writes
# a row to the ledger is an alert, not a control.
#
# Prerequisites: `docker compose up -d` (the stack must already be healthy).
#
# Usage: bash scripts/verify_circuit_breaker.sh    (from anywhere)
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

BASE="${MONOLITH_DASHBOARD_BASE:-http://localhost:3000}"
DC="docker compose"
PASS=0; FAIL=0
set -a; . ./.env; set +a
OP="${MONOLITH_OPERATOR_TOKEN:?set MONOLITH_OPERATOR_TOKEN in .env}"
TENANT="${MONOLITH_TENANT_ID:-default}"
AUTH_HEADER="Authorization: Bearer $OP"
api() { curl -sf -H "$AUTH_HEADER" "$1"; }

check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $3)"; PASS=$((PASS+1));
  else echo "  FAIL  $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}

is_true() { python -c 'import sys,json; sys.exit(0 if json.load(sys.stdin).get("session_quarantined") is True else 1)'; }
# "Not quarantined" and "returned documents" are different claims. These two
# checks are about enforcement — a session that is not revoked must be served
# — so they test the quarantine flag alone. Folding in "has results" made
# them fail for an unrelated reason on a stack with an empty corpus, where a
# perfectly healthy retrieval returns no documents.
not_quarantined() { python -c 'import sys,json; sys.exit(0 if json.load(sys.stdin).get("session_quarantined") is not True else 1)'; }

# The recovery script deliberately restarts the dashboard container, and a
# restarting container is briefly unreachable. Every dashboard call in this
# script is a single-shot request, so without this guard the script would
# measure the restart window instead of the circuit breaker. Wait for the
# endpoint to answer before making any claim about it.
echo "waiting for the dashboard to answer..."
DASHBOARD_READY=0
for _ in $(seq 1 40); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$BASE/api/ingest" 2>/dev/null)" != "000" ]; then
    DASHBOARD_READY=1
    break
  fi
  sleep 1
done
if [ "$DASHBOARD_READY" -ne 1 ]; then
  echo "  FAIL: the dashboard never became reachable"
  exit 1
fi

SESSION="verify-cb-$(date +%s)-$$"
BYSTANDER="verify-cb-ok-$(date +%s)-$$"
EVENT_A=$(python -c 'import uuid;print(uuid.uuid4())')
EVENT_B=$(python -c 'import uuid;print(uuid.uuid4())')

echo "revoked session: $SESSION"
echo "bystander:       $BYSTANDER"

echo
echo "=============================================="
echo "1. TWO DISTINCT LAYERS TRIP THE BREAKER"
echo "=============================================="
# mcp-shield reports one critical detection for the session.
FIRST=$(curl -sf -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_MCP_SHIELD" \
  -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$EVENT_A\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"mcp-shield\",\"event_type\":\"tool_call_blocked\",\"severity\":\"critical\",\"details\":{\"probe\":\"circuit-breaker-verify\"},\"tenant_id\":\"$TENANT\",\"agent_id\":\"$SESSION-agent\",\"session_id\":\"$SESSION\",\"source\":\"module\"}")
check "one layer does not trip" "False" \
  "$(echo "$FIRST" | python -c "import sys,json;print('$SESSION' in json.load(sys.stdin).get('revoked_sessions',[]))")"

# A second, independent layer reports critical for the same identity.
SECOND=$(curl -sf -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_TRACE_AUDIT" \
  -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$EVENT_B\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"trace-audit\",\"event_type\":\"reasoning_divergence_terminate\",\"severity\":\"critical\",\"details\":{\"probe\":\"circuit-breaker-verify\"},\"tenant_id\":\"$TENANT\",\"agent_id\":\"$SESSION-agent\",\"session_id\":\"$SESSION\",\"source\":\"module\"}")
check "the second distinct layer trips" "True" \
  "$(echo "$SECOND" | python -c "import sys,json;print('$SESSION' in json.load(sys.stdin).get('revoked_sessions',[]))")"

# The snapshot endpoint is what a module with no event traffic polls.
SNAPSHOT=$(curl -sf -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR" \
  -H "x-monolith-tenant-id: $TENANT" -H "x-monolith-module: vector-anchor" \
  "$BASE/api/sessions/revoked")
check "the snapshot carries the session" "True" \
  "$(echo "$SNAPSHOT" | python -c "import sys,json;print('$SESSION' in (json.load(sys.stdin).get('revoked_sessions') or []))")"
check "the snapshot requires a module credential" "401" \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "x-monolith-tenant-id: $TENANT" \
     -H "x-monolith-module: vector-anchor" "$BASE/api/sessions/revoked")"

echo
echo "=============================================="
echo "2. EVERY LAYER ENFORCES THE REVOCATION"
echo "=============================================="
echo "waiting up to 40s for the 15s revocation poll..."
VA_BODY=""
VA_REFUSED=1
for _ in $(seq 1 40); do
  VA_BODY=$($DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
    -H 'Content-Type: application/json' -H "X-Monolith-Session-Id: $SESSION" \
    -d '{"query":"how do I prune tomato plants"}' 2>/dev/null)
  if echo "$VA_BODY" | is_true 2>/dev/null; then VA_REFUSED=0; break; fi
  sleep 1
done
check "vector-anchor refuses the revoked session" "0" "$VA_REFUSED"
check "the refused retrieval returns no documents" "0" \
  "$(echo "$VA_BODY" | python -c 'import sys,json;print(len(json.load(sys.stdin).get("results",[])))')"

# Trace-Audit polls the revocation snapshot on the same 15-second cadence as
# the other layers, so a single request can arrive before the poll that
# carries the revocation has landed. This retries until the refusal appears,
# exactly as the VectorAnchor check above does — otherwise the check is
# measuring the poll schedule rather than the enforcement.
TA_BODY=""
TA_REFUSED=0
for _ in $(seq 1 40); do
  TA_BODY=$($DC exec -T -e VERIFY_SESSION="$SESSION" trace-audit python -c '
import json, os, urllib.request
req = urllib.request.Request(
    "http://localhost:8002/generate",
    data=json.dumps({"prompt": "hello"}).encode(),
    headers={
        "Content-Type": "application/json",
        "X-Monolith-Session-Id": os.environ["VERIFY_SESSION"],
    },
)
print(urllib.request.urlopen(req, timeout=15).read().decode())
' 2>/dev/null)
  if echo "$TA_BODY" | grep -q 'session_revoked'; then TA_REFUSED=1; break; fi
  sleep 1
done
check "trace-audit terminates with session_revoked" "1" "$TA_REFUSED"

# A fresh MCP-Shield process polls on startup before the delayed tool call.
#
# MCP-Shield is a per-session proxy: it is spawned for one agent session and
# exits when stdin closes, so it learns which session it serves from the
# environment rather than from a request header. The long-lived services
# above take the session per request via X-Monolith-Session-Id, which is why
# they read VERIFY_SESSION instead. Both names are passed here so the proxy
# resolves the same session the other layers were revoked for.
MCP_BODY=$($DC exec -T -e VERIFY_SESSION="$SESSION" -e MONOLITH_SESSION_ID="$SESSION" \
  mcp-shield sh -c '
  { sleep 2; printf "%s\n" "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{}}}"; } \
    | mcp-shield python fixtures/fake_mcp_server.py' 2>/dev/null)
check "mcp-shield blocks the tool call" "1" \
  "$(echo "$MCP_BODY" | grep -c 'circuit breaker' || true)"

# A bystander session with the same shape must keep working.
BYSTANDER_BODY=$($DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
  -H 'Content-Type: application/json' -H "X-Monolith-Session-Id: $BYSTANDER" \
  -d '{"query":"how long should I boil pasta"}' 2>/dev/null)
check "an unrelated session is unaffected" "0" \
  "$(echo "$BYSTANDER_BODY" | not_quarantined; echo $?)"

echo
echo "=============================================="
echo "3. AN ANALYST RESTORE RELEASES THE SESSION"
echo "=============================================="
RESTORE=$(curl -sf -X DELETE -H "$AUTH_HEADER" \
  "$BASE/api/incidents/$EVENT_A/session")
check "restore succeeds" "False" \
  "$(echo "$RESTORE" | python -c 'import sys,json;print(json.load(sys.stdin)["session"]["revoked"])')"

RESTORED=1
for _ in $(seq 1 40); do
  VA_BODY=$($DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
    -H 'Content-Type: application/json' -H "X-Monolith-Session-Id: $SESSION" \
    -d '{"query":"how do I prune tomato plants"}' 2>/dev/null)
  if echo "$VA_BODY" | not_quarantined 2>/dev/null; then RESTORED=0; break; fi
  sleep 1
done
check "vector-anchor serves again after restore" "0" "$RESTORED"

check "the snapshot no longer lists the session" "False" \
  "$(curl -sf -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR" \
     -H "x-monolith-tenant-id: $TENANT" -H "x-monolith-module: vector-anchor" \
     "$BASE/api/sessions/revoked" \
     | python -c "import sys,json;print('$SESSION' in (json.load(sys.stdin).get('revoked_sessions') or []))")"

echo
echo "=============================================="
echo "RESULT: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ]
