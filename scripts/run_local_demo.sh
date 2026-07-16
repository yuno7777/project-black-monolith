#!/usr/bin/env bash
# Project Black Monolith — full end-to-end demo WITHOUT Docker.
#
# Starts the dashboard, VectorAnchor, and TraceAudit as local background
# processes (each with MONOLITH_DASHBOARD_URL set so their events reach the
# dashboard), then drives all three attack fixtures. Use this when Docker is
# unavailable; it is the local equivalent of `docker compose up` +
# `run_full_demo.sh`.
#
#   ./scripts/run_local_demo.sh
#   open http://localhost:3000
#
# Requires: python (fastapi/uvicorn/chromadb installed), node/npm, cargo.

set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

DASH_PORT="${DASH_PORT:-3000}"
VA_PORT="${VA_PORT:-8001}"
TA_PORT="${TA_PORT:-8002}"
DASH_URL="http://localhost:${DASH_PORT}/api/ingest"
PY="${PYTHON:-python}"; command -v "$PY" >/dev/null 2>&1 || PY=python3

TMP="$(mktemp -d)"
PIDS=()
# next/uvicorn fork child processes, so kill whatever is actually LISTENING on
# each demo port (Windows netstat + taskkill) — reliable regardless of the
# process tree.
kill_port() {
  for pid in $(netstat -ano 2>/dev/null | grep LISTENING | grep -E ":$1 " | awk '{print $NF}' | sort -u); do
    [ -n "$pid" ] && [ "$pid" != "0" ] && taskkill //PID "$pid" //F >/dev/null 2>&1 || true
  done
}
cleanup() {
  echo; echo "== stopping local services =="
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  kill_port "$DASH_PORT"; kill_port "$VA_PORT"; kill_port "$TA_PORT"
  rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_health() { # <url> <name>
  for _ in $(seq 1 60); do curl -sf "$1" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "ERROR: $2 did not become healthy at $1" >&2; return 1
}

echo "================================================================"
echo " Project Black Monolith — LOCAL demo (no Docker)"
echo "================================================================"

# --- 1. Dashboard ------------------------------------------------------
echo "== starting dashboard on :${DASH_PORT} =="
( cd dashboard
  [ -f .next/BUILD_ID ] || npm run build >/dev/null 2>&1
  npm start >"$TMP/dashboard.log" 2>&1 ) &
PIDS+=($!)
wait_health "http://localhost:${DASH_PORT}/api/ingest" "dashboard" || exit 1
echo "  dashboard up: $(curl -s http://localhost:${DASH_PORT}/api/ingest)"

# --- 2. VectorAnchor ---------------------------------------------------
echo "== starting VectorAnchor on :${VA_PORT} =="
( cd vector-anchor
  MONOLITH_DASHBOARD_URL="$DASH_URL" MONOLITH_EMBEDDING=hash \
    MONOLITH_CHROMA_PATH="$TMP/chroma" \
    "$PY" -m uvicorn src.main:app --host 127.0.0.1 --port "$VA_PORT" --log-level warning \
    >"$TMP/vector-anchor.log" 2>&1 ) &
PIDS+=($!)
wait_health "http://localhost:${VA_PORT}/health" "vector-anchor" || exit 1
echo "  vector-anchor up"

# --- 3. TraceAudit (capture baseline first) ----------------------------
echo "== starting TraceAudit on :${TA_PORT} =="
( cd trace-audit
  export MONOLITH_BASELINE_PATH="$TMP/baseline.json"
  "$PY" fixtures/baseline_capture.py >"$TMP/ta_baseline.log" 2>&1
  MONOLITH_DASHBOARD_URL="$DASH_URL" MONOLITH_MODEL_BACKEND=mock \
    "$PY" -m uvicorn src.main:app --host 127.0.0.1 --port "$TA_PORT" --log-level warning \
    >"$TMP/trace-audit.log" 2>&1 ) &
PIDS+=($!)
wait_health "http://localhost:${TA_PORT}/health" "trace-audit" || exit 1
echo "  trace-audit up: $(curl -s http://localhost:${TA_PORT}/health)"

sleep 2
echo; echo ">> Open http://localhost:${DASH_PORT} to watch the live feed <<"; sleep 2

# ======================================================================
echo; echo "== ATTACK 1/3 — MCP-Shield rug pull =="
MONOLITH_DASHBOARD_URL="$DASH_URL" bash mcp-shield/fixtures/run_demo.sh 2>&1 \
  | grep -E "SCHEMA MISMATCH DETECTED|SUSPICIOUS DESCRIPTION FLAGGED|\[OK\]|DEMO" | head -12

echo; echo "== ATTACK 2/3 — VectorAnchor corpus poisoning =="
export MONOLITH_SERVICE_URL="http://localhost:${VA_PORT}"
curl -s -X POST "$MONOLITH_SERVICE_URL/admin/reset-detection" >/dev/null || true
"$PY" vector-anchor/fixtures/seed_corpus.py
for q in "how to compost kitchen scraps for my garden" "how do astronomers measure distance to a nebula" \
         "how to sear a steak so the meat stays juicy" "how to pay off high interest credit card debt"; do
  curl -s -X POST "$MONOLITH_SERVICE_URL/retrieve" -H 'Content-Type: application/json' -d "{\"query\":\"$q\"}" >/dev/null
done
"$PY" vector-anchor/fixtures/inject_poison.py
for q in "how do I prune tomato plants in my garden" "what is a red giant star in a galaxy" \
         "how long should I boil pasta noodles" "how much emergency fund and savings should I budget"; do
  curl -s -X POST "$MONOLITH_SERVICE_URL/retrieve" -H 'Content-Type: application/json' -d "{\"query\":\"$q\"}" >/dev/null
done
echo "  quarantine: $(curl -s "$MONOLITH_SERVICE_URL/quarantine" | "$PY" -c 'import sys,json;d=json.load(sys.stdin);print(d["count"],"doc(s):",[x["doc_id"] for x in d["documents"]])')"

echo; echo "== ATTACK 3/3 — TraceAudit divergence + PII =="
export MONOLITH_SERVICE_URL="http://localhost:${TA_PORT}"
"$PY" trace-audit/fixtures/divergence_prompt.py divergence 2>&1 | grep -E "TERMINATED|result:"
"$PY" trace-audit/fixtures/divergence_prompt.py pii 2>&1 | grep -E "REDACTED|result:"

# ======================================================================
sleep 2
echo; echo "== dashboard received =="
curl -sN --max-time 3 "http://localhost:${DASH_PORT}/api/events" | grep '^data:' | sed 's/^data: //' \
  | "$PY" -c '
import sys, json, collections
mods=collections.Counter(); types=collections.Counter()
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    e=json.loads(line); mods[e["module"]]+=1; types[(e["module"],e["event_type"],e["severity"])]+=1
print("  total events:", sum(mods.values()), "| by module:", dict(mods))
for (m,t,s),n in sorted(types.items()): print(f"    {m:14s} {t:32s} {s:8s} x{n}")
'
echo
if [ "${DEMO_HOLD:-1}" = "1" ]; then
  echo "== LOCAL DEMO COMPLETE — services still running =="
  echo "   Open http://localhost:${DASH_PORT} to explore the live feed."
  echo "   Press Ctrl-C to stop all services."
  wait
else
  echo "== LOCAL DEMO COMPLETE (DEMO_HOLD=0) — stopping services =="
fi
