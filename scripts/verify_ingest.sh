#!/usr/bin/env bash
# Exercises the ingestion contract against the running Compose stack:
# authentication, idempotency, validation, batching, persistence and replay.
#
# Prerequisites: `docker compose up -d` (the stack must already be healthy) and
# a .env with the ingest tokens (see scripts/generate_secrets.sh).
#
# Usage: bash scripts/verify_ingest.sh    (from anywhere)
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

if [ ! -f .env ]; then
  echo "error: no .env — run 'bash scripts/generate_secrets.sh' first." >&2
  exit 1
fi
set -a; . ./.env; set +a

BASE="${MONOLITH_DASHBOARD_BASE:-http://localhost:3000}"
TOK="$MONOLITH_EVENT_TOKEN_MCP_SHIELD"
VA_TOK="$MONOLITH_EVENT_TOKEN_VECTOR_ANCHOR"
PASS=0; FAIL=0

check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $3)"; PASS=$((PASS+1));
  else echo "  FAIL  $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi
}

uuid() { python -c "import uuid;print(uuid.uuid4())"; }

status() { # token body -> http status
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/ingest" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -d "$2"
}
body() { # token body -> response body
  curl -s -X POST "$BASE/api/ingest" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -d "$2"
}

event() { # event_id [module]
  local mod="${2:-mcp-shield}"
  printf '{"event_id":"%s","schema_version":2,"timestamp_ms":%s,"module":"%s","event_type":"contract_probe","severity":"warning","details":{"probe":true},"source":"module"}' \
    "$1" "$(date +%s)000" "$mod"
}

echo "=============================================="
echo "AUTHENTICATION"
echo "=============================================="
check "valid module token is accepted"        "201" "$(status "$TOK" "$(event "$(uuid)")")"
check "no token is rejected"                  "401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/ingest" -H 'Content-Type: application/json' -d "$(event "$(uuid)")")"
check "wrong token is rejected"               "401" "$(status "definitely-not-the-right-token" "$(event "$(uuid)")")"
# A token is scoped to ONE module: vector-anchor's credential must not be
# usable to forge mcp-shield events.
check "cross-module token is rejected"        "401" "$(status "$VA_TOK" "$(event "$(uuid)" "mcp-shield")")"
check "vector-anchor token works on its own"  "201" "$(status "$VA_TOK" "$(event "$(uuid)" "vector-anchor")")"

echo
echo "=============================================="
echo "IDEMPOTENCY"
echo "=============================================="
# This is what makes an outbox's at-least-once redelivery safe: the same
# event_id twice must insert once.
DUP=$(uuid)
FIRST=$(body "$TOK" "$(event "$DUP")")
SECOND=$(body "$TOK" "$(event "$DUP")")
echo "  first  -> $FIRST"
echo "  second -> $SECOND"
check "first delivery is accepted"   "1" "$(echo "$FIRST"  | python -c 'import sys,json;print(json.load(sys.stdin)["accepted"])')"
check "redelivery is a duplicate"    "1" "$(echo "$SECOND" | python -c 'import sys,json;print(json.load(sys.stdin)["duplicates"])')"
check "redelivery inserts nothing"   "0" "$(echo "$SECOND" | python -c 'import sys,json;print(json.load(sys.stdin)["accepted"])')"

echo
echo "=============================================="
echo "VALIDATION"
echo "=============================================="
# The poison-pill case: event_id is a Postgres uuid column. A non-UUID must be
# a permanent 422, not a 503 that module outboxes would retry forever.
check "non-UUID event_id -> permanent 422" "422" \
  "$(status "$TOK" '{"event_id":"not-a-uuid","module":"mcp-shield","event_type":"probe","severity":"info","details":{}}')"
check "unknown module -> 422"        "422" "$(status "$TOK" '{"module":"who-dis","event_type":"probe","severity":"info","details":{}}')"
check "missing event_type -> 422"    "422" "$(status "$TOK" '{"module":"mcp-shield","severity":"info","details":{}}')"
check "invalid JSON -> 400"          "400" "$(status "$TOK" 'not json at all')"
check "mixed-module batch -> 422"    "422" "$(status "$TOK" "[$(event "$(uuid)"),$(event "$(uuid)" "vector-anchor")]")"

echo
echo "=============================================="
echo "BATCH"
echo "=============================================="
BATCH=$(body "$TOK" "[$(event "$(uuid)"),$(event "$(uuid)"),$(event "$(uuid)")]")
echo "  batch -> $BATCH"
check "a 3-event batch is accepted" "3" "$(echo "$BATCH" | python -c 'import sys,json;print(json.load(sys.stdin)["accepted"])')"

echo
echo "=============================================="
echo "PERSISTENCE + REPLAY"
echo "=============================================="
ROWS=$(docker compose exec -T database psql -U postgres -d postgres -tAc \
  "select count(*) from monolith.security_events where event_type = 'contract_probe'" 2>/dev/null | tr -d '\r')
echo "  rows persisted in Postgres: $ROWS"
[ "${ROWS:-0}" -gt 0 ] && { echo "  PASS  events reached the ledger"; PASS=$((PASS+1)); } \
                       || { echo "  FAIL  nothing in the ledger"; FAIL=$((FAIL+1)); }

# A fresh SSE client must be replayed the events it was never connected for —
# proving the ledger, not the in-process broker, is the source of truth.
REPLAY=$(curl -s -N --max-time 5 "$BASE/api/events" | grep -c "contract_probe" || true)
echo "  contract_probe events replayed to a new SSE client: $REPLAY"
[ "${REPLAY:-0}" -gt 0 ] && { echo "  PASS  a new client is replayed persisted history"; PASS=$((PASS+1)); } \
                         || { echo "  FAIL  no replay"; FAIL=$((FAIL+1)); }

echo
echo "=============================================="
echo "RESULT: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ]
