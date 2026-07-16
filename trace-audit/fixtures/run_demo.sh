#!/usr/bin/env bash
# TraceAudit end-to-end reasoning-divergence + PII-redaction demo.
#
# 1. Capture a baseline token distribution from normal prompts (if missing).
# 2. Start the streaming service.
# 3. Stream 2 normal prompts — KL stays low, streams complete.
# 4. Stream the divergence test prompt — KL climbs past threshold, the stream
#    is terminated early and a safe refusal is returned.
# 5. Stream a prompt whose context holds a fake credential — the scanner
#    redacts it in the trace and a pii_redacted event fires.
#
# Fully local: uses the deterministic offline "mock" model backend by default
# (set MONOLITH_MODEL_BACKEND=ollama + MONOLITH_OLLAMA_URL to use a real one).

set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${MONOLITH_TA_PORT:-8002}"
BASE="http://localhost:${PORT}"
export MONOLITH_SERVICE_URL="$BASE"
export MONOLITH_BASELINE_PATH="${MONOLITH_BASELINE_PATH:-$(mktemp -d)/baseline_distribution.json}"

PY="${PYTHON:-python}"
command -v "$PY" >/dev/null 2>&1 || PY=python3

echo "== 1. Capturing baseline distribution =="
"$PY" fixtures/baseline_capture.py

echo
echo "== 2. Starting TraceAudit service on :${PORT} =="
"$PY" -m uvicorn src.main:app --host 0.0.0.0 --port "$PORT" --log-level warning &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 40); do
    curl -sf "$BASE/health" >/dev/null 2>&1 && break
    sleep 0.5
done
curl -sf "$BASE/health" >/dev/null || { echo "service did not start" >&2; exit 1; }
echo "service is up: $(curl -s "$BASE/health")"

stream_prompt() {
    curl -sN -X POST "$BASE/generate" -H 'Content-Type: application/json' -d "{\"prompt\": $1}"
}

echo
echo "== 3. Normal prompts (expect completion, no termination) =="
for p in "Explain how to make a simple cup of tea." "Summarize why sleep matters for health."; do
    echo "  prompt: $p"
    out=$(stream_prompt "\"$p\"")
    if echo "$out" | grep -q '"type": "done"'; then
        peak=$(echo "$out" | grep -o '"peak_kl": [0-9.]*' | tail -1)
        echo "    -> completed normally ($peak)"
    else
        echo "    -> UNEXPECTED: normal prompt did not complete"; exit 1
    fi
done

echo
echo "== 4. Divergence test prompt (expect early termination + safe refusal) =="
"$PY" fixtures/divergence_prompt.py divergence | sed 's/^/  /'

echo
echo "== 5. PII prompt (expect credential redacted in the trace) =="
"$PY" fixtures/divergence_prompt.py pii | sed 's/^/  /'

echo
echo "== Verifying detections =="
pass=true

DIV=$("$PY" fixtures/divergence_prompt.py divergence)
if echo "$DIV" | grep -q "STREAM TERMINATED"; then
    echo "  [OK]   reasoning divergence terminated the stream early"
else
    echo "  [FAIL] divergence prompt did not terminate"; pass=false
fi

PII=$("$PY" fixtures/divergence_prompt.py pii)
if echo "$PII" | grep -q "REDACTED:aws_access_key_id" && echo "$PII" | grep -q "REDACTED:email_address"; then
    echo "  [OK]   credential + email redacted in the reasoning trace"
else
    echo "  [FAIL] PII was not redacted as expected"; pass=false
fi
if echo "$PII" | grep -q "AKIAIOSFODNN7EXAMPLE"; then
    echo "  [FAIL] raw credential leaked into the client stream"; pass=false
else
    echo "  [OK]   raw credential never appears in the client stream"
fi

echo
if $pass; then
    echo "DEMO PASSED: TraceAudit terminated divergent reasoning and redacted credentials in the trace."
else
    echo "DEMO FAILED: see output above."; exit 1
fi
