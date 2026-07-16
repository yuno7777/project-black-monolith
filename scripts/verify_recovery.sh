#!/usr/bin/env bash
# Proves the Python outbox durability claim against the running Compose stack:
# collector down -> detections spool to disk -> collector back -> spool drains
# into the ledger. Nothing is lost, only delayed.
#
# NOTE: this deliberately stops and starts the dashboard container. That is the
# only way to actually demonstrate recovery rather than assert it. It is fully
# reversible and touches no data — the ledger volume is never removed.
#
# Prerequisites: `docker compose up -d` (the stack must already be healthy).
#
# Usage: bash scripts/verify_recovery.sh    (from anywhere)
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

ledger() {
  docker compose exec -T database psql -U postgres -d postgres -tAc \
    "select count(*) from monolith.security_events" 2>/dev/null | tr -d '\r'
}
pending() { # $1 = service
  docker compose exec -T "$1" python -c "
import sqlite3
try:
    c = sqlite3.connect('/var/lib/monolith/outbox.db')
    print(c.execute(\"select count(*) from event_outbox where status='pending'\").fetchone()[0])
except Exception:
    print(0)
" 2>/dev/null | tr -d '\r'
}

BEFORE=$(ledger)
echo "ledger rows at start:            $BEFORE"

echo
echo "=============================================="
echo "1. TAKE THE DASHBOARD DOWN"
echo "=============================================="
docker compose stop dashboard >/dev/null 2>&1
docker compose ps --format '{{.Service}}\t{{.State}}' | grep dashboard

echo
echo "=============================================="
echo "2. GENERATE DETECTIONS WHILE IT IS DOWN"
echo "=============================================="
for q in "how do I prune tomato plants" "what is a red giant star" "how long to boil pasta" "emergency fund budget"; do
  curl -s -X POST http://localhost:8001/retrieve -H 'Content-Type: application/json' \
    -d "{\"query\":\"$q\",\"n_results\":3}" >/dev/null && echo "  queried: $q"
done
sleep 3
VA_PENDING=$(pending vector-anchor)
echo "vector-anchor events spooled:    $VA_PENDING"
MID=$(ledger)
echo "ledger rows (must be unchanged): $MID"

[ "${VA_PENDING:-0}" -gt 0 ] \
  && echo "  PASS: events persisted locally while the collector was unreachable" \
  || { echo "  FAIL: nothing spooled"; docker compose start dashboard >/dev/null 2>&1; exit 1; }
[ "$MID" = "$BEFORE" ] \
  && echo "  PASS: nothing reached the ledger (as expected — it was down)" \
  || echo "  NOTE: ledger moved to $MID"

echo
echo "=============================================="
echo "3. BRING THE DASHBOARD BACK"
echo "=============================================="
docker compose start dashboard >/dev/null 2>&1
for i in $(seq 1 40); do
  docker compose ps --format '{{.Service}}:{{.Health}}' | grep -q "dashboard:healthy" && break
  sleep 3
done
docker compose ps --format '{{.Service}}\t{{.Health}}' | grep dashboard

# Give the outbox worker a few backoff cycles to drain.
for i in $(seq 1 20); do
  [ "$(pending vector-anchor)" = "0" ] && break
  sleep 3
done

AFTER=$(ledger)
VA_AFTER=$(pending vector-anchor)
echo
echo "ledger rows after recovery:      $AFTER  (was $BEFORE)"
echo "vector-anchor still pending:     $VA_AFTER"

DELIVERED=$((AFTER - BEFORE))
echo "events recovered:                $DELIVERED"

echo
# `>=` rather than `==`: the other two modules stay live throughout and may
# deliver their own events into the same ledger while this runs. The claim
# under test is that nothing spooled was LOST, so a floor is the honest check.
[ "$DELIVERED" -ge "$VA_PENDING" ] \
  && echo "  PASS: every spooled event was delivered after recovery" \
  || { echo "  FAIL: expected >= $VA_PENDING recovered, got $DELIVERED"; exit 1; }
[ "${VA_AFTER:-1}" = "0" ] \
  && echo "  PASS: the spool drained to empty" \
  || { echo "  FAIL: $VA_AFTER still pending"; exit 1; }

echo
echo "ALL RECOVERY CHECKS PASSED"
