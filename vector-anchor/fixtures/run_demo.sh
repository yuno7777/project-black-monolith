#!/usr/bin/env bash
# VectorAnchor end-to-end corpus-poisoning detection demo.
#
# 1. Start the service on a fresh corpus.
# 2. Seed ~24 clean documents across six unrelated topics.
# 3. Run several clean, on-topic queries — no document is flagged.
# 4. Inject one adversarial "universal bait" document.
# 5. Run four unrelated queries that all retrieve the bait.
# 6. Show the quarantine event firing (with the anomaly score) the moment the
#    document has ranked across four dissimilar queries, and confirm it is
#    then withheld from results.
#
# Fully local: ChromaDB runs embedded (no external service). Exit 0 on success.

set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${MONOLITH_VA_PORT:-8001}"
BASE="http://localhost:${PORT}"
export MONOLITH_SERVICE_URL="$BASE"
# Fresh embedded corpus each run for reproducibility.
export MONOLITH_CHROMA_PATH="$(mktemp -d)/chroma_store"

PY="${PYTHON:-python}"
command -v "$PY" >/dev/null 2>&1 || PY=python3

echo "== Starting VectorAnchor service on :${PORT} =="
"$PY" -m uvicorn src.main:app --host 0.0.0.0 --port "$PORT" --log-level warning &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$(dirname "$MONOLITH_CHROMA_PATH")" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for health.
for _ in $(seq 1 40); do
    if curl -sf "$BASE/health" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
curl -sf "$BASE/health" >/dev/null || { echo "service did not start" >&2; exit 1; }
echo "service is up: $(curl -s "$BASE/health")"

retrieve() { curl -s -X POST "$BASE/retrieve" -H 'Content-Type: application/json' -d "{\"query\": $1}"; }
jqget() { "$PY" -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

echo
echo "== 1. Seeding clean corpus =="
"$PY" fixtures/seed_corpus.py

echo
echo "== 2. Clean queries (expect NO quarantine) =="
while IFS= read -r q; do
    [ -z "$q" ] && continue
    n=$(retrieve "\"$q\"" | jqget "len(d['results'])")
    echo "  query: $q -> $n results"
done <<'CLEANQ'
how to compost kitchen scraps for my garden
how do astronomers measure distance to a nebula
how to sear a steak so the meat stays juicy
how to pay off high interest credit card debt
CLEANQ
qcount=$(curl -s "$BASE/quarantine" | jqget "d['count']")
echo "  quarantine size after clean queries: $qcount"

echo
echo "== 3. Injecting adversarial universal-bait document =="
"$PY" fixtures/inject_poison.py

echo
echo "== 4. Four unrelated queries that all retrieve the bait =="
i=0
while IFS= read -r q; do
    [ -z "$q" ] && continue
    i=$((i+1))
    resp=$(retrieve "\"$q\"")
    withheld=$(echo "$resp" | jqget "len(d['withheld'])")
    echo "  trigger $i: $q  (withheld this call: $withheld)"
done <<'TRIGQ'
how do I prune tomato plants in my garden
what is a red giant star in a galaxy
how long should I boil pasta noodles
how much emergency fund and savings should I budget
TRIGQ

echo
echo "== 5. Quarantine state =="
curl -s "$BASE/quarantine" | "$PY" -m json.tool

echo
echo "== Verifying detection =="
FINAL=$(curl -s "$BASE/quarantine")
if echo "$FINAL" | grep -q "poison-universal-bait"; then
    score=$(echo "$FINAL" | jqget "d['documents'][0]['score']")
    echo "  [OK]   universal-bait document quarantined (anomaly score = $score across distinct topics)"
    echo
    echo "DEMO PASSED: VectorAnchor detected and quarantined the corpus-poisoning document."
else
    echo "  [FAIL] poison document was not quarantined"
    exit 1
fi
