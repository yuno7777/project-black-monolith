#!/usr/bin/env bash
# Proves the cross-layer correlation claim against the running Compose stack:
# detections raised by different modules in the same agent session are tied
# together, and detections from different sessions are not.
#
# The second half matters as much as the first. A correlation that groups
# everything is not a correlation — it is a bug that happens to look like the
# feature working.
#
# Prerequisites: `docker compose up -d` (the stack must already be healthy).
#
# Usage: bash scripts/verify_correlation.sh    (from anywhere)
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

BASE="${MONOLITH_DASHBOARD_BASE:-http://localhost:3000}"
DC="docker compose"
PASS=0; FAIL=0
set -a; . ./.env; set +a
OP="${MONOLITH_OPERATOR_TOKEN:?set MONOLITH_OPERATOR_TOKEN in .env}"
AUTH_HEADER="Authorization: Bearer $OP"
api() { curl -sf -H "$AUTH_HEADER" "$1"; }

check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $3)"; PASS=$((PASS+1));
  else echo "  FAIL  $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}

SESSION_A="verify-a-$(date +%s)-$$"
SESSION_B="verify-b-$(date +%s)-$$"

echo "session A: $SESSION_A"
echo "session B: $SESSION_B"

echo
echo "=============================================="
echo "1. RAISE DETECTIONS ACROSS LAYERS"
echo "=============================================="
# Session A touches the memory and reasoning layers. Only the caller knows the
# session, so it is supplied per request — exactly as an agent framework would.
$DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
  -H 'Content-Type: application/json' -H "X-Monolith-Session-Id: $SESSION_A" \
  -d '{"query":"how do I prune tomato plants"}' >/dev/null && echo "  A: vector-anchor retrieval"
$DC exec -T -e MONOLITH_SESSION_ID="$SESSION_A" trace-audit \
  python fixtures/divergence_prompt.py pii >/dev/null 2>&1 && echo "  A: trace-audit generation"

# Session B is a different agent doing something innocuous. It must not be
# swept into A.
$DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
  -H 'Content-Type: application/json' -H "X-Monolith-Session-Id: $SESSION_B" \
  -d '{"query":"how long should I boil pasta"}' >/dev/null && echo "  B: vector-anchor retrieval"

# Delivery is asynchronous through each module's outbox.
for _ in $(seq 1 20); do
  n=$(api "$BASE/api/incidents?status=all&session=$SESSION_A&limit=500" 2>/dev/null \
      | grep -o '"module":"[a-z-]*"' | sort -u | wc -l | tr -d ' ')
  [ "${n:-0}" -ge 2 ] && break
  sleep 1
done

echo
echo "=============================================="
echo "2. THE SESSION TIES THE LAYERS TOGETHER"
echo "=============================================="
A_MODULES=$(api "$BASE/api/incidents?status=all&session=$SESSION_A&limit=500" \
  | grep -o '"module":"[a-z-]*"' | sort -u | wc -l | tr -d ' ')
check "session A spans two layers" "2" "$A_MODULES"

check "session B stayed separate" "1" \
  "$(api "$BASE/api/incidents?status=all&session=$SESSION_B&limit=500" \
     | grep -o '"module":"[a-z-]*"' | sort -u | wc -l | tr -d ' ')"

# A grouping that also grabs the neighbours is worse than none.
check "session A's filter excludes session B" "0" \
  "$(api "$BASE/api/incidents?status=all&session=$SESSION_A&limit=500" \
     | grep -c "$SESSION_B" || true)"

check "an unknown session returns nothing" "0" \
  "$(api "$BASE/api/incidents?status=all&session=no-such-session-xyz&limit=500" \
     | python -c 'import sys,json;print(len(json.load(sys.stdin)["incidents"]))')"

echo
echo "=============================================="
echo "3. THE CROSS-LAYER VIEW"
echo "=============================================="
EID=$(api "$BASE/api/incidents?status=all&session=$SESSION_A&limit=1" \
  | python -c 'import sys,json;print(json.load(sys.stdin)["incidents"][0]["event_id"])')
VIEW=$(api "$BASE/api/incidents/$EID/session")
echo "  $VIEW" | head -c 220; echo

check "the view reports the right session" "$SESSION_A" \
  "$(echo "$VIEW" | python -c 'import sys,json;print(json.load(sys.stdin)["session"]["session_id"])')"
check "it is flagged cross-layer" "True" \
  "$(echo "$VIEW" | python -c 'import sys,json;print(json.load(sys.stdin)["session"]["cross_layer"])')"
check "it breaks down by layer" "2" \
  "$(echo "$VIEW" | python -c 'import sys,json;print(len(json.load(sys.stdin)["session"]["layers"]))')"
check "it reports each layer's worst severity" "warning" \
  "$(echo "$VIEW" | python -c '
import sys, json
layers = json.load(sys.stdin)["session"]["layers"]
print(next(l["worst"] for l in layers if l["module"] == "trace-audit"))')"

# The severity ranking has to be by rank, not by text. Real fixtures cannot
# prove that: every natural combination happens to agree with alphabetical
# order. {info, warning} is the case that separates them — sorted as text it
# yields "info", so a session with a warning in it would be reported as merely
# informational. Seed that case deliberately.
SESSION_C="verify-c-$(date +%s)-$$"
for sev in info warning; do
  curl -s -o /dev/null -X POST "$BASE/api/ingest" \
    -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_MCP_SHIELD" \
    -H 'Content-Type: application/json' \
    -d "{\"event_id\":\"$(python -c 'import uuid;print(uuid.uuid4())')\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"mcp-shield\",\"event_type\":\"rank_probe\",\"severity\":\"$sev\",\"details\":{},\"tenant_id\":\"${MONOLITH_TENANT_ID:-default}\",\"agent_id\":\"demo-agent\",\"session_id\":\"$SESSION_C\",\"source\":\"module\"}"
done
C_EID=$(api "$BASE/api/incidents?status=all&session=$SESSION_C&limit=1" \
  | python -c 'import sys,json;d=json.load(sys.stdin)["incidents"];print(d[0]["event_id"] if d else "")')
if [ -n "$C_EID" ]; then
  check "worst severity is ranked, not alphabetical" "warning" \
    "$(api "$BASE/api/incidents/$C_EID/session" \
       | python -c 'import sys,json;print(json.load(sys.stdin)["session"]["layers"][0]["worst"])')"
else
  echo "  FAIL  could not seed the ranking probe"; FAIL=$((FAIL+1))
fi

echo
echo "=============================================="
echo "4. SEARCH AND HONESTY"
echo "=============================================="
# Pasting a session id into the search box is the obvious analyst move.
check "free-text search finds the session" "2" \
  "$(api "$BASE/api/incidents?status=all&q=$SESSION_A&limit=500" \
     | grep -o '"module":"[a-z-]*"' | sort -u | wc -l | tr -d ' ')"
check "the agent id is stamped too" "demo-agent" \
  "$(api "$BASE/api/incidents?status=all&session=$SESSION_A&limit=1" \
     | python -c 'import sys,json;print(json.load(sys.stdin)["incidents"][0].get("agent_id"))')"
check "every operation carries a trace id" "True" \
  "$(api "$BASE/api/incidents?status=all&session=$SESSION_A&limit=500" \
     | python -c 'import sys,json;print(all(i.get("trace_id") for i in json.load(sys.stdin)["incidents"]))')"

# An uncorrelated event must say so rather than be handed a fake grouping.
NOSESS=$($DC exec -T database psql -U postgres -d postgres -tAc \
  "select event_id from monolith.security_events where session_id is null limit 1" 2>/dev/null | tr -d '\r')
if [ -n "$NOSESS" ]; then
  check "an event with no session is not given one" "404" \
    "$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTH_HEADER" "$BASE/api/incidents/$NOSESS/session")"
else
  echo "  SKIP  no uncorrelated event in the ledger to test against"
fi

echo
echo "=============================================="
echo "5. AGENT/SESSION COLLISION ISOLATION"
echo "=============================================="
# Session labels are not globally unique. Two different agents may both call
# their first session "session-1"; that must never manufacture a cross-layer
# compromise by joining their unrelated detections.
COLLISION="shared-session-$(date +%s)-$$"
ALPHA_EID=$(python -c 'import uuid;print(uuid.uuid4())')
BETA_EID=$(python -c 'import uuid;print(uuid.uuid4())')
curl -s -o /dev/null -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_MCP_SHIELD" \
  -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$ALPHA_EID\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"mcp-shield\",\"event_type\":\"collision_probe_alpha\",\"severity\":\"warning\",\"details\":{},\"tenant_id\":\"${MONOLITH_TENANT_ID:-default}\",\"agent_id\":\"agent-alpha\",\"session_id\":\"$COLLISION\",\"source\":\"module\"}"
curl -s -o /dev/null -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_TRACE_AUDIT" \
  -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$BETA_EID\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"trace-audit\",\"event_type\":\"collision_probe_beta\",\"severity\":\"critical\",\"details\":{},\"tenant_id\":\"${MONOLITH_TENANT_ID:-default}\",\"agent_id\":\"agent-beta\",\"session_id\":\"$COLLISION\",\"source\":\"module\"}"

check "agent-qualified filtering keeps alpha isolated" "1" \
  "$(api "$BASE/api/incidents?status=all&session=$COLLISION&agent=agent-alpha&limit=50" \
     | python -c 'import sys,json;print(len(json.load(sys.stdin)["incidents"]))')"
check "agent-qualified filtering keeps beta isolated" "1" \
  "$(api "$BASE/api/incidents?status=all&session=$COLLISION&agent=agent-beta&limit=50" \
     | python -c 'import sys,json;print(len(json.load(sys.stdin)["incidents"]))')"
check "same session label across agents is not cross-layer" "False" \
  "$(api "$BASE/api/incidents/$ALPHA_EID/session" \
     | python -c 'import sys,json;print(json.load(sys.stdin)["session"]["cross_layer"])')"

echo
echo "=============================================="
echo "RESULT: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ]
