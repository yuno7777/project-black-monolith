#!/usr/bin/env bash
# Exercises the benchmark ledger contract against the running Compose stack:
# authenticated ingest, server-side metric recomputation, validation, isolation
# from the event ledger, and read-back.
#
# Prerequisites: `docker compose up -d` (the stack must already be healthy).
#
# Usage: bash scripts/verify_benchmarks.sh
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

BASE="${MONOLITH_DASHBOARD_BASE:-http://localhost:3000}"
PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1 (got $3)"; PASS=$((PASS+1));
  else echo "  FAIL  $1 (expected $2, got $3)"; FAIL=$((FAIL+1)); fi; }

set -a; . ./.env; set +a
OP="${MONOLITH_OPERATOR_TOKEN:?set MONOLITH_OPERATOR_TOKEN in .env}"
MARK="verify_bench_$(date +%s)_$$"   # a unique detector name to find our rows

post() { # token body -> http status
  curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/benchmarks" \
    ${1:+-H "Authorization: Bearer $1"} -H 'Content-Type: application/json' -d "$2"; }

# A valid run with ONE detector whose claimed metrics are deliberately wrong
# (says 100% detection while the confusion matrix says 1 of 2).
RUN="$(printf '{"run_at_ms":%s000,"git_commit":"verify","detectors":[{"module":"vector-anchor","detector":"%s","paradigm":"threshold","confusion":{"tp":1,"fp":0,"tn":3,"fn":1},"metrics":{"detection_rate":1.0,"false_positive_rate":0.0,"precision":1.0,"recall":1.0,"f1":1.0},"latency_us":null,"thresholds":{}}]}' "$(date +%s)" "$MARK")"

echo "=============================================="
echo "AUTHENTICATION"
echo "=============================================="
check "no credential is rejected"     "401" "$(post '' "$RUN")"
check "a wrong credential is rejected" "401" "$(post 'not-the-operator-token' "$RUN")"
# A module token identifies a module, not an operator — it must not work here.
check "a module token is rejected"     "401" "$(post "$MONOLITH_EVENT_TOKEN_MCP_SHIELD" "$RUN")"
check "the operator token is accepted" "201" "$(post "$OP" "$RUN")"

echo
echo "=============================================="
echo "INTEGRITY — metrics recomputed, not trusted"
echo "=============================================="
STORED=$(docker compose exec -T database psql -U postgres -d postgres -tAc \
  "select detection_rate from monolith.benchmark_runs where detector='$MARK'" 2>/dev/null | tr -d '\r ')
# Claimed 1.0, confusion is 1/(1+1) = 0.5. The server must store 0.5.
check "a lied detection_rate is recomputed from the confusion matrix" "0.5000" "$STORED"

echo
echo "=============================================="
echo "VALIDATION"
echo "=============================================="
check "unknown paradigm -> 422" "422" \
  "$(post "$OP" '{"detectors":[{"module":"vector-anchor","detector":"x","paradigm":"vibes","confusion":{"tp":1,"fp":0,"tn":0,"fn":0}}]}')"
check "unknown module -> 422" "422" \
  "$(post "$OP" '{"detectors":[{"module":"who","detector":"x","paradigm":"exact","confusion":{"tp":1,"fp":0,"tn":0,"fn":0}}]}')"
check "negative confusion cell -> 422" "422" \
  "$(post "$OP" '{"detectors":[{"module":"vector-anchor","detector":"x","paradigm":"exact","confusion":{"tp":-1,"fp":0,"tn":0,"fn":0}}]}')"
check "empty detector list -> 422" "422" "$(post "$OP" '{"detectors":[]}')"
check "invalid JSON -> 400" "400" "$(post "$OP" 'not json')"

echo
echo "=============================================="
echo "READ-BACK + ISOLATION"
echo "=============================================="
check "the run reads back over the API" "1" \
  "$(curl -s "$BASE/api/benchmarks" | grep -c "$MARK" | tr -d ' ')"
# The load-bearing guarantee: benchmark results are evaluation metadata and must
# never enter the event ledger or be counted as detections.
LEAK=$(docker compose exec -T database psql -U postgres -d postgres -tAc \
  "select count(*) from monolith.security_events where event_type ilike '%benchmark%' or details::text ilike '%$MARK%'" 2>/dev/null | tr -d '\r ')
check "no benchmark data leaked into the event ledger" "0" "$LEAK"

# --- clean up our probe rows so we do not skew the real latest run -----------
docker compose exec -T database psql -U postgres -d postgres -tAc \
  "delete from monolith.benchmark_runs where detector='$MARK'" >/dev/null 2>&1

echo
echo "=============================================="
echo "RESULT: $PASS passed, $FAIL failed"
echo "=============================================="
[ "$FAIL" -eq 0 ]
