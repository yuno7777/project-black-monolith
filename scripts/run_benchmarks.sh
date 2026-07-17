#!/usr/bin/env bash
# Run every detector benchmark, bundle the per-detector scorecards into one run,
# and POST it to the dashboard's authenticated benchmark endpoint.
#
# The harnesses are offline and deterministic (no running services needed to
# compute them); only the upload needs the dashboard. Run from anywhere:
#
#   bash scripts/run_benchmarks.sh            # compute + upload to localhost:3000
#   MONOLITH_DASHBOARD_BASE=... bash scripts/run_benchmarks.sh
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

BASE="${MONOLITH_DASHBOARD_BASE:-http://localhost:3000}"
if [ ! -f .env ]; then
  echo "error: no .env — run 'bash scripts/generate_secrets.sh' first." >&2
  exit 1
fi
set -a; . ./.env; set +a
OP="${MONOLITH_OPERATOR_TOKEN:?set MONOLITH_OPERATOR_TOKEN in .env}"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

say() { printf '\033[1m%s\033[0m\n' "$*"; }

say "Computing detector benchmarks (offline, deterministic)…"

# --- VectorAnchor + TraceAudit: harnesses write benchmark_results.json -------
( cd vector-anchor && python fixtures/benchmark_detection.py >/dev/null ) \
  && echo "  vector-anchor: scored" || { echo "  vector-anchor benchmark FAILED (gate)"; exit 1; }
( cd trace-audit && python fixtures/benchmark_detection.py >/dev/null ) \
  && echo "  trace-audit: scored" || { echo "  trace-audit benchmark FAILED (gate)"; exit 1; }

# --- MCP-Shield: the ignored test prints a BENCHMARK_JSON: marker line -------
SHIELD_JSON="$(cd mcp-shield && cargo test --release benchmark_report -- --ignored --nocapture 2>/dev/null \
  | grep '^BENCHMARK_JSON:' | sed 's/^BENCHMARK_JSON://')"
[ -n "$SHIELD_JSON" ] && echo "  mcp-shield: scored" || { echo "  mcp-shield benchmark produced no report"; exit 1; }

# --- bundle every detector report into one run and POST ----------------------
say "Uploading run (commit $COMMIT) to $BASE …"
export BASE OP COMMIT
RESP="$(python - "$SHIELD_JSON" <<'PY'
import json, os, sys, time, urllib.request, urllib.error

reports = []
for path in ("vector-anchor/fixtures/benchmark_results.json",
             "trace-audit/fixtures/benchmark_results.json"):
    with open(path, encoding="utf-8") as fh:
        reports += json.load(fh)
reports += json.loads(sys.argv[1])  # mcp-shield, from the marker line

run = {"run_at_ms": int(time.time() * 1000),
       "git_commit": os.environ.get("COMMIT", "unknown"),
       "detectors": reports}

req = urllib.request.Request(
    os.environ["BASE"].rstrip("/") + "/api/benchmarks",
    data=json.dumps(run).encode("utf-8"),
    headers={"Content-Type": "application/json",
             "Authorization": "Bearer " + os.environ["OP"]},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print(f"{r.status} {r.read().decode()}")
except urllib.error.HTTPError as e:
    print(f"{e.code} {e.read().decode()}")
    sys.exit(1)
except Exception as e:
    print(f"upload failed: {type(e).__name__}: {e}")
    sys.exit(1)
PY
)"
STATUS="$?"
echo "  $RESP"
[ "$STATUS" -eq 0 ] || exit 1
say "Done — benchmark run uploaded."
