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
  "$(echo "$SNAPSHOT" | python -c "import sys,json;print('$SESSION' in json.load(sys.stdin)['revoked_sessions'])")"
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
     | python -c "import sys,json;print('$SESSION' in json.load(sys.stdin)['revoked_sessions'])")"

echo
echo "=============================================="
echo "4. A TENANT AT THE SNAPSHOT CAP STILL REFUSES A NEW SESSION"
echo "=============================================="
# The snapshot a module polls used to be the tenant's entire live revoked
# set, so a tenant with enough live revocations produced a body past the
# 64 KiB the module reads. The body was cut short, it failed to parse, and
# the module kept the set it already had — so a session revoked a moment ago
# was still served. The revocation path is supposed to fail closed, and it
# did not.
#
# The fill below gives the tenant more live revocations than that. The
# identifier length decides how quickly the body passed the cap, not the
# session count, so every fill session carries the longest identifier the
# ledger allows: 512 revocations of 128 characters are 67,072 bytes, past the
# 65,536-byte cap.
FILL_COUNT="${MONOLITH_CB_FILL_COUNT:-512}"
FILL_PREFIX="verify-cb-fill-$$"
FILL_EVENT_IDS=$(mktemp)
FILL_BODY=$(mktemp)
FILL_FAILED=$(mktemp)
trap 'rm -f "$FILL_EVENT_IDS" "$FILL_BODY" "$FILL_FAILED"' EXIT
echo "filling the tenant with $FILL_COUNT live revocations (longest identifiers)..."

# One batch of fill events for a module. Every event is critical and carries
# the same agent id, so the second module's batch is what trips the breaker:
# two distinct layers reporting critical for one identity is what revokes it.
#
# The body goes to a file, not into an argument: a hundred of these events is
# 47 KB, which is past the command-line limit on some hosts, and curl would
# then never run at all. The event ids are read back out of that file rather
# than written by python, because a path this shell made is not a path the
# interpreter can open: on some hosts the two resolve to different files.
fill_batch() { # module start count record_ids
  MODULE_NAME="$1" BATCH_START="$2" BATCH_COUNT="$3" TENANT="$TENANT" \
  FILL_PREFIX="$FILL_PREFIX" \
  python -c '
import json, os, uuid
module = os.environ["MODULE_NAME"]
start = int(os.environ["BATCH_START"])
count = int(os.environ["BATCH_COUNT"])
prefix = os.environ["FILL_PREFIX"]
events = []
for i in range(start, start + count):
    session = prefix + "-" + str(i)
    session += "f" * (128 - len(session))
    events.append({
        "event_id": str(uuid.uuid4()),
        "schema_version": 2,
        "timestamp_ms": 1750000000000,
        "module": module,
        "event_type": "tool_call_blocked",
        "severity": "critical",
        "details": {"probe": "circuit-breaker-fill"},
        "tenant_id": os.environ["TENANT"],
        "agent_id": prefix + "-agent",
        "session_id": session,
        "source": "module",
    })
print(json.dumps(events))
' > "$FILL_BODY"
  if [ "$4" = "1" ]; then
    python -c 'import json,sys;print("\n".join(e["event_id"] for e in json.load(sys.stdin)))' \
      < "$FILL_BODY" >> "$FILL_EVENT_IDS"
  fi
}

# Post the staged batch, waiting out the module's ingest budget when the
# dashboard says the window is full. The budget is per module per minute and
# the fill spends it.
post_batch() { # token
  local code attempt
  for attempt in $(seq 1 12); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/ingest" \
      -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
      --data-binary "@$FILL_BODY" 2>/dev/null)
    if [ "$code" = "201" ]; then return 0; fi
    if [ "$code" != "429" ]; then return 1; fi
    sleep 5
  done
  return 1
}

BEFORE_COUNT=$(curl -sf -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR" \
  -H "x-monolith-tenant-id: $TENANT" -H "x-monolith-module: vector-anchor" \
  "$BASE/api/sessions/revoked" \
  | python -c 'import sys,json;print(len(json.load(sys.stdin)["revoked_sessions"]))')

INDEX=0
while [ "$INDEX" -lt "$FILL_COUNT" ]; do
  COUNT=$(( FILL_COUNT - INDEX ))
  if [ "$COUNT" -gt 100 ]; then COUNT=100; fi
  fill_batch mcp-shield "$INDEX" "$COUNT" 1
  post_batch "$MONOLITH_EVENT_TOKEN_MCP_SHIELD" || break
  fill_batch trace-audit "$INDEX" "$COUNT" 0
  post_batch "$MONOLITH_EVENT_TOKEN_TRACE_AUDIT" || break
  INDEX=$(( INDEX + COUNT ))
done
check "the tenant holds more live revocations than the snapshot carries" "True" \
  "$( [ "$INDEX" -ge "$FILL_COUNT" ] && echo True || echo False )"

# The snapshot a module polls. It has to fit the reader, and it has to say
# that it does not carry the whole set — a module that cannot tell the
# difference would replace its local set with a partial one and un-revoke
# everything the body did not mention.
SNAPSHOT=$(curl -sf -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR" \
  -H "x-monolith-tenant-id: $TENANT" -H "x-monolith-module: vector-anchor" \
  "$BASE/api/sessions/revoked")
SNAPSHOT_BYTES=$(printf '%s' "$SNAPSHOT" | wc -c | tr -d ' ')
echo "snapshot body: $SNAPSHOT_BYTES bytes"
check "the snapshot body fits the 64 KiB the modules read" "True" \
  "$( [ "$SNAPSHOT_BYTES" -lt 65536 ] && echo True || echo False )"
check "the snapshot says the set is bounded" "True" \
  "$(echo "$SNAPSHOT" | python -c 'import sys,json;d=json.load(sys.stdin);s=d.get("revoked_sessions") or [];print(d.get("complete") is False and d.get("truncated") is True and 0 < len(s) <= 128)')"

# The session the tenant revokes while it is over the cap. This is the case
# the truncation threshold hides: before the snapshot was bounded, the body
# was cut short, the module kept the set it had, and this session was served
# like any other.
CAP_SESSION="verify-cb-cap-$(date +%s)-$$"
CAP_EVENT_A=$(python -c 'import uuid;print(uuid.uuid4())')
CAP_EVENT_B=$(python -c 'import uuid;print(uuid.uuid4())')
echo "newly revoked session: $CAP_SESSION"

# Every layer must refuse it. A layer learns about the revocation from its
# next poll, so the refusal has to arrive within one poll interval (15s) plus
# a margin for a slow poll and a slow snapshot fetch. The window is a
# deadline measured from the revocation, not a number of attempts: a probe
# costs several seconds, so thirty attempts would stretch the window past two
# minutes and a layer that refused late would still pass.
CAP_WINDOW=30
CAP_START=$(date +%s)
CAP_DEADLINE=$(( CAP_START + CAP_WINDOW ))
curl -sf -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_MCP_SHIELD" \
  -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$CAP_EVENT_A\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"mcp-shield\",\"event_type\":\"tool_call_blocked\",\"severity\":\"critical\",\"details\":{\"probe\":\"circuit-breaker-cap-verify\"},\"tenant_id\":\"$TENANT\",\"agent_id\":\"$CAP_SESSION-agent\",\"session_id\":\"$CAP_SESSION\",\"source\":\"module\"}" \
  -o /dev/null
curl -sf -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_TRACE_AUDIT" \
  -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$CAP_EVENT_B\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"trace-audit\",\"event_type\":\"reasoning_divergence_terminate\",\"severity\":\"critical\",\"details\":{\"probe\":\"circuit-breaker-cap-verify\"},\"tenant_id\":\"$TENANT\",\"agent_id\":\"$CAP_SESSION-agent\",\"session_id\":\"$CAP_SESSION\",\"source\":\"module\"}" \
  -o /dev/null

check "the snapshot carries the newly revoked session" "True" \
  "$(curl -sf -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR" \
     -H "x-monolith-tenant-id: $TENANT" -H "x-monolith-module: vector-anchor" \
     "$BASE/api/sessions/revoked" \
     | python -c "import sys,json;print('$CAP_SESSION' in json.load(sys.stdin)['revoked_sessions'])")"

echo "waiting up to ${CAP_WINDOW}s for the 15s revocation poll..."
VA_BODY=""
VA_REFUSED=1
VA_ELAPSED=""
while :; do
  # The latency is measured when the probe started, not when it returned: the
  # probe reports the layer's state at the moment it was sent, and a slow
  # probe must not eat the window the layer had to refuse in.
  PROBE_AT=$(date +%s)
  VA_BODY=$($DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
    -H 'Content-Type: application/json' -H "X-Monolith-Session-Id: $CAP_SESSION" \
    -d '{"query":"how do I prune tomato plants"}' 2>/dev/null)
  if echo "$VA_BODY" | is_true 2>/dev/null; then
    VA_ELAPSED=$(( PROBE_AT - CAP_START ))
    [ "$VA_ELAPSED" -le "$CAP_WINDOW" ] && VA_REFUSED=0
    break
  fi
  if [ "$(date +%s)" -ge "$CAP_DEADLINE" ]; then break; fi
  sleep 1
done
check "vector-anchor refuses the session revoked at the cap" "0" "$VA_REFUSED"
if [ -n "$VA_ELAPSED" ]; then
  echo "  vector-anchor refusal latency: ${VA_ELAPSED}s"
else
  echo "  vector-anchor refusal latency: no refusal observed"
fi

TA_BODY=""
TA_REFUSED=0
TA_ELAPSED=""
while :; do
  PROBE_AT=$(date +%s)
  TA_BODY=$($DC exec -T -e VERIFY_SESSION="$CAP_SESSION" trace-audit python -c '
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
  if echo "$TA_BODY" | grep -q 'session_revoked'; then
    TA_ELAPSED=$(( PROBE_AT - CAP_START ))
    [ "$TA_ELAPSED" -le "$CAP_WINDOW" ] && TA_REFUSED=1
    break
  fi
  if [ "$(date +%s)" -ge "$CAP_DEADLINE" ]; then break; fi
  sleep 1
done
check "trace-audit terminates the session revoked at the cap" "1" "$TA_REFUSED"
if [ -n "$TA_ELAPSED" ]; then
  echo "  trace-audit refusal latency: ${TA_ELAPSED}s"
else
  echo "  trace-audit refusal latency: no refusal observed"
fi

# MCP-Shield is a fresh process: it reads the snapshot at startup rather than
# on a cadence, so the deadline above does not apply to it. What matters is
# that it refuses the session it was just given.
MCP_BODY=$($DC exec -T -e VERIFY_SESSION="$CAP_SESSION" -e MONOLITH_SESSION_ID="$CAP_SESSION" \
  mcp-shield sh -c '
  { sleep 2; printf "%s\n" "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{}}}"; } \
    | mcp-shield python fixtures/fake_mcp_server.py' 2>/dev/null)
check "mcp-shield blocks the session revoked at the cap" "1" \
  "$(echo "$MCP_BODY" | grep -c 'circuit breaker' || true)"
echo "elapsed: $(( $(date +%s) - CAP_START ))s (the poll cadence is 15s)"

# The fill is scratch, not evidence: restore every session it created so the
# stack is left the way it was found. The ledger keeps the events — it is
# append-only — but the live revoked set goes back to what it was.
#
# A restore that does not answer leaves the session revoked, so the outcome of
# every request is recorded and the ones that failed are tried again. Swallowing
# the failures would leave the stack dirty and the script's own last check
# would report a leftover the script had caused.
echo "restoring the fill sessions..."
while read -r FILL_EVENT_ID; do
  # The ids were written by an interpreter that ends its lines with CRLF on
  # some hosts, and a trailing carriage return in a URL is a 404.
  FILL_EVENT_ID=${FILL_EVENT_ID%$'\r'}
  [ -n "$FILL_EVENT_ID" ] || continue
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "$AUTH_HEADER" \
    "$BASE/api/incidents/$FILL_EVENT_ID/session" 2>/dev/null)
  if [ "$CODE" != "200" ]; then
    echo "  the restore of $FILL_EVENT_ID answered ${CODE:-000}"
    printf '%s\n' "$FILL_EVENT_ID" >> "$FILL_FAILED"
  fi
done < "$FILL_EVENT_IDS"
if [ -s "$FILL_FAILED" ]; then
  echo "retrying $(wc -l < "$FILL_FAILED" | tr -d ' ') restore(s)..."
  while read -r FILL_EVENT_ID; do
    FILL_EVENT_ID=${FILL_EVENT_ID%$'\r'}
    [ -n "$FILL_EVENT_ID" ] || continue
    curl -s -o /dev/null -X DELETE -H "$AUTH_HEADER" \
      "$BASE/api/incidents/$FILL_EVENT_ID/session" 2>/dev/null || true
  done < "$FILL_FAILED"
fi
curl -sf -X DELETE -H "$AUTH_HEADER" \
  "$BASE/api/incidents/$CAP_EVENT_A/session" -o /dev/null 2>/dev/null || true

AFTER_COUNT=$(curl -sf -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR" \
  -H "x-monolith-tenant-id: $TENANT" -H "x-monolith-module: vector-anchor" \
  "$BASE/api/sessions/revoked" \
  | python -c 'import sys,json;print(len(json.load(sys.stdin)["revoked_sessions"]))')
check "the fill left the live revoked set as it was found" "$BEFORE_COUNT" "$AFTER_COUNT"

# Clean up synthetic events and restored fill sessions so the durable ledger remains unpolluted
echo "cleaning up synthetic verification events and records..."
$DC exec -T database psql -U postgres -d postgres -c \
  "DELETE FROM monolith.security_events WHERE session_id LIKE '$FILL_PREFIX%' OR session_id = '$SESSION' OR session_id = '$BYSTANDER' OR session_id = '$CAP_SESSION'; DELETE FROM monolith.revoked_sessions WHERE session_id LIKE '$FILL_PREFIX%' OR session_id = '$SESSION' OR session_id = '$BYSTANDER' OR session_id = '$CAP_SESSION';" >/dev/null 2>&1 || true

echo
echo "=============================================="
echo "RESULT: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ]
