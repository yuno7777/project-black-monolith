#!/usr/bin/env bash
# Exercises the incident lifecycle against the running Compose stack: triage
# transitions, the constraints that keep the queue honest, and the append-only
# audit trail.
#
# Prerequisites: `docker compose up -d` and at least one event in the ledger
# (run ./run_full_demo.sh first if the ledger is empty).
#
# Usage: bash scripts/verify_incidents.sh    (from anywhere)
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

BASE="${MONOLITH_DASHBOARD_BASE:-http://localhost:3000}"
PASS=0; FAIL=0

check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $3)"; PASS=$((PASS+1));
  else echo "  FAIL  $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}

# Triage is authenticated: every write carries the operator credential, and the
# actor in the audit trail is derived from it rather than from the body.
set -a; . ./.env; set +a
OP="${MONOLITH_OPERATOR_TOKEN:?set MONOLITH_OPERATOR_TOKEN in .env — run scripts/generate_secrets.sh}"
OPNAME="${MONOLITH_OPERATOR_NAME:-operator}"

post() {
  curl -s -X POST "$BASE/api/incidents" -H "Authorization: Bearer $OP" \
    -H 'Content-Type: application/json' -d "$1"
}
post_status() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/incidents" \
    -H "Authorization: Bearer $OP" -H 'Content-Type: application/json' -d "$1"
}

# Seed an event of our own so the script is self-contained and does not depend
# on which fixtures happen to have run.
EID=$(python -c "import uuid;print(uuid.uuid4())")
curl -s -o /dev/null -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_MCP_SHIELD" -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$EID\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"mcp-shield\",\"event_type\":\"lifecycle_probe\",\"severity\":\"critical\",\"details\":{\"probe\":true},\"source\":\"module\"}"
echo "seeded incident: $EID"

echo
echo "=============================================="
echo "QUEUE"
echo "=============================================="
# A brand-new event has no triage row at all; it must still show up as open,
# or detections would land in the ledger and never reach an analyst.
check "an untriaged event appears in the open queue" "1" \
  "$(curl -s "$BASE/api/incidents?status=open&limit=1000" | python -c "import sys,json;print(sum(1 for i in json.load(sys.stdin)['incidents'] if i['event_id']=='$EID'))")"
check "its synthesized status is new" "new" \
  "$(curl -s "$BASE/api/incidents?status=new&limit=1000" | python -c "import sys,json;print(next((i.get('triage') or {}).get('status','new') for i in json.load(sys.stdin)['incidents'] if i['event_id']=='$EID'))")"
check "free-text search finds it by event_type" "1" \
  "$(curl -s "$BASE/api/incidents?status=all&q=lifecycle_probe&limit=1000" | python -c "import sys,json;print(sum(1 for i in json.load(sys.stdin)['incidents'] if i['event_id']=='$EID'))")"
check "an unknown status filter is rejected" "422" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/incidents?status=bogus")"

echo
echo "=============================================="
echo "TRANSITIONS"
echo "=============================================="
ACK=$(post "{\"event_id\":\"$EID\",\"status\":\"acknowledged\",\"assignee\":\"ci-analyst\",\"note\":\"taking a look\"}")
echo "  ack -> $ACK"
check "acknowledge sets the status" "acknowledged" \
  "$(echo "$ACK" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"]["status"])')"
check "acknowledge records the assignee" "ci-analyst" \
  "$(echo "$ACK" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"]["assignee"])')"

# Resolving without restating the assignee must NOT unassign the incident:
# omitting a field means "leave it alone", not "clear it".
RES=$(post "{\"event_id\":\"$EID\",\"status\":\"resolved\",\"resolution\":\"true_positive\"}")
echo "  resolve -> $RES"
check "resolve sets the status" "resolved" \
  "$(echo "$RES" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"]["status"])')"
check "resolve preserves the assignee" "ci-analyst" \
  "$(echo "$RES" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"].get("assignee"))')"
check "resolve preserves the earlier note" "taking a look" \
  "$(echo "$RES" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"].get("note"))')"
check "resolve records the verdict" "true_positive" \
  "$(echo "$RES" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"]["resolution"])')"
check "a resolved incident leaves the open queue" "0" \
  "$(curl -s "$BASE/api/incidents?status=open&limit=1000" | python -c "import sys,json;print(sum(1 for i in json.load(sys.stdin)['incidents'] if i['event_id']=='$EID'))")"

REOPEN=$(post "{\"event_id\":\"$EID\",\"status\":\"new\",\"note\":\"reopening\"}")
check "reopening clears the stale verdict" "None" \
  "$(echo "$REOPEN" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"].get("resolution"))')"

echo
echo "=============================================="
echo "CONSTRAINTS"
echo "=============================================="
# A "resolved" queue with no verdict is just a hidden queue — the
# false-positive rate could never be recovered from it.
check "resolving with no resolution -> 422" "422" \
  "$(post_status "{\"event_id\":\"$EID\",\"status\":\"resolved\"}")"
check "a resolution on a non-resolved status -> 422" "422" \
  "$(post_status "{\"event_id\":\"$EID\",\"status\":\"acknowledged\",\"resolution\":\"benign\"}")"
check "an unknown resolution -> 422" "422" \
  "$(post_status "{\"event_id\":\"$EID\",\"status\":\"resolved\",\"resolution\":\"vibes\"}")"
check "an unknown status -> 422" "422" \
  "$(post_status "{\"event_id\":\"$EID\",\"status\":\"wontfix\"}")"
check "a non-UUID event_id -> 422" "422" \
  "$(post_status '{"event_id":"not-a-uuid","status":"acknowledged"}')"
check "an event not in the ledger -> 404" "404" \
  "$(post_status '{"event_id":"00000000-0000-4000-8000-000000000000","status":"acknowledged"}')"
check "invalid JSON -> 400" "400" "$(post_status 'not json at all')"

echo
echo "=============================================="
echo "OPERATOR AUTHENTICATION"
echo "=============================================="
# A second event, so the successful transitions below do not pollute the audit
# trail asserted on $EID.
AUTH_EID=$(python -c "import uuid;print(uuid.uuid4())")
curl -s -o /dev/null -X POST "$BASE/api/ingest" \
  -H "Authorization: Bearer $MONOLITH_EVENT_TOKEN_MCP_SHIELD" -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$AUTH_EID\",\"schema_version\":2,\"timestamp_ms\":$(date +%s)000,\"module\":\"mcp-shield\",\"event_type\":\"auth_probe\",\"severity\":\"warning\",\"details\":{},\"source\":\"module\"}"

naked() { # POST with an arbitrary (or absent) credential
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/incidents" \
    ${1:+-H "Authorization: Bearer $1"} -H 'Content-Type: application/json' \
    -d "{\"event_id\":\"$AUTH_EID\",\"status\":\"acknowledged\"}"
}
check "no credential cannot triage" "401" "$(naked '')"
check "a wrong credential cannot triage" "401" "$(naked 'definitely-not-the-operator-token')"
# A module token identifies a module. If it worked here, any module could close
# its own findings.
check "a module token cannot triage" "401" "$(naked "$MONOLITH_EVENT_TOKEN_MCP_SHIELD")"

# The actor is derived from the credential, so a caller cannot record someone
# else's name against its decision. The body's actor is ignored outright.
FORGE=$(post "{\"event_id\":\"$AUTH_EID\",\"status\":\"acknowledged\",\"actor\":\"someone-else\",\"note\":\"forgery attempt\"}")
check "the body's actor is ignored, not honoured" "$OPNAME" \
  "$(echo "$FORGE" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"]["updated_by"])')"
check "the forged name never reaches the trail" "0" \
  "$(curl -s "$BASE/api/incidents/$AUTH_EID/audit" | grep -c 'someone-else' || true)"

# The client cannot name itself, so "take this" is a request the server resolves.
TAKE=$(post "{\"event_id\":\"$AUTH_EID\",\"status\":\"acknowledged\",\"assign_to_me\":true}")
check "assign_to_me resolves to the authenticated operator" "$OPNAME" \
  "$(echo "$TAKE" | python -c 'import sys,json;print(json.load(sys.stdin)["triage"]["assignee"])')"
check "assign_to_me and assignee together -> 422" "422" \
  "$(post_status "{\"event_id\":\"$AUTH_EID\",\"status\":\"acknowledged\",\"assign_to_me\":true,\"assignee\":\"someone-else\"}")"

echo
echo "=============================================="
echo "AUDIT TRAIL"
echo "=============================================="
TRAIL=$(curl -s "$BASE/api/incidents/$EID/audit")
echo "  transitions recorded: $(echo "$TRAIL" | python -c 'import sys,json;print(len(json.load(sys.stdin)["audit"]))')"
check "every transition was recorded" "3" \
  "$(echo "$TRAIL" | python -c 'import sys,json;print(len(json.load(sys.stdin)["audit"]))')"
check "the trail is newest-first" "new" \
  "$(echo "$TRAIL" | python -c 'import sys,json;print(json.load(sys.stdin)["audit"][0]["to_status"])')"
check "it records where each transition came from" "acknowledged" \
  "$(echo "$TRAIL" | python -c 'import sys,json;print(json.load(sys.stdin)["audit"][1]["from_status"])')"
check "the first transition has no prior status" "None" \
  "$(echo "$TRAIL" | python -c 'import sys,json;print(json.load(sys.stdin)["audit"][2].get("from_status"))')"

# The trail is the whole point of having a trail: it must not be rewritable,
# and a REVOKE would not bind the table owner, so a trigger enforces it.
UPD=$(docker compose exec -T database psql -U postgres -d postgres -tAc \
  "update monolith.incident_audit set actor = 'tampered' where event_id = '$EID'" 2>&1 | tr -d '\r')
echo "$UPD" | grep -q "append-only" \
  && { echo "  PASS  the audit trail rejects UPDATE"; PASS=$((PASS+1)); } \
  || { echo "  FAIL  an UPDATE was allowed: $UPD"; FAIL=$((FAIL+1)); }
DEL=$(docker compose exec -T database psql -U postgres -d postgres -tAc \
  "delete from monolith.incident_audit where event_id = '$EID'" 2>&1 | tr -d '\r')
echo "$DEL" | grep -q "append-only" \
  && { echo "  PASS  the audit trail rejects DELETE"; PASS=$((PASS+1)); } \
  || { echo "  FAIL  a DELETE was allowed: $DEL"; FAIL=$((FAIL+1)); }

# The evidence itself must stay immutable regardless of triage state.
EVT=$(docker compose exec -T database psql -U postgres -d postgres -tAc \
  "select severity from monolith.security_events where event_id = '$EID'" 2>/dev/null | tr -d '\r')
check "triage never mutated the underlying event" "critical" "$EVT"

echo
echo "=============================================="
echo "RESULT: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ]
