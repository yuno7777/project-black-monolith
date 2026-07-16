#!/usr/bin/env bash
# Project Black Monolith — full end-to-end integration demo.
#
# Prereq: the stack is up  ->  docker compose up -d --build
# Then:   ./run_full_demo.sh
# Watch:  http://localhost:3000  (detections stream in live as each fires)
#
# This drives all three attack fixtures in sequence — MCP-Shield rug pull,
# VectorAnchor corpus poisoning, TraceAudit reasoning divergence + PII — every
# one entirely through `docker compose exec`, so the only host requirement is
# Docker. Each module forwards its detection events to the dashboard over the
# internal network, so the whole story appears on one live feed.

set -uo pipefail
cd "$(dirname "$0")"

DC="docker compose"
PAUSE="${DEMO_PAUSE:-3}"   # seconds between phases, so events are easy to follow

# Every attack below is deliberately tolerant (`|| true`) so a hiccup in one
# phase still lets the rest of the story play out on screen. That tolerance is
# why the run is verified against the ledger at the end rather than by exit
# codes along the way — otherwise "the demo ran" and "the demo worked" would be
# indistinguishable, which is exactly the kind of green-but-meaningless check
# this project is supposed to be arguing against.
#
# Only detections newer than this are counted, so a ledger left over from an
# earlier run cannot make this pass.
START_MS="$(date +%s)000"

hr() { printf '\n\033[1m%s\033[0m\n' "══════════════════════════════════════════════════════════════"; }
say() { printf '\033[1m%s\033[0m\n' "$*"; }

# --- wait for services --------------------------------------------------
say "Checking the stack is up (dashboard :3000, vector-anchor :8001, trace-audit :8002)…"
ready=false
for _ in $(seq 1 60); do
    if curl -sf http://localhost:3000/api/ingest >/dev/null 2>&1 \
       && curl -sf http://localhost:8001/health >/dev/null 2>&1 \
       && curl -sf http://localhost:8002/health >/dev/null 2>&1; then
        ready=true; break
    fi
    sleep 2
done
if [ "$ready" != true ]; then
    echo "error: services are not all healthy. Run 'docker compose up -d --build' first." >&2
    exit 1
fi
say "All services healthy. Open http://localhost:3000 to watch the live feed."
sleep "$PAUSE"

# ═══════════════════════════════════════════════════════════════════════
hr; say "ATTACK 1/3 — MCP-Shield: tool-schema rug pull (tool layer)"; hr
# Reset the service-configured baseline (MCP_SHIELD_BASELINE=/tmp/baseline_hashes.json)
# so phase 1 registers cleanly on every run. The reset + demo run inside one
# quoted `sh -c` so the /tmp path is never passed as a bare shell argument
# (which some Windows shells would path-mangle).
$DC exec -T mcp-shield sh -c 'rm -f /tmp/baseline_hashes.json && bash fixtures/run_demo.sh' 2>&1 \
    | grep -E "PHASE|SCHEMA MISMATCH|SUSPICIOUS|\[OK\]|\[FAIL\]|DEMO" || true
sleep "$PAUSE"

# ═══════════════════════════════════════════════════════════════════════
hr; say "ATTACK 2/3 — VectorAnchor: corpus poisoning / universal bait (memory layer)"; hr
say "  Resetting detection state and seeding a clean corpus…"
$DC exec -T vector-anchor curl -s -X POST http://localhost:8001/admin/reset-detection >/dev/null || true
$DC exec -T vector-anchor python fixtures/seed_corpus.py || true

say "  Running clean, on-topic queries (expect no quarantine)…"
for q in \
    "how to compost kitchen scraps for my garden" \
    "how do astronomers measure distance to a nebula" \
    "how to sear a steak so the meat stays juicy" \
    "how to pay off high interest credit card debt"; do
    $DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
        -H 'Content-Type: application/json' -d "{\"query\":\"$q\"}" >/dev/null || true
done

say "  Injecting the adversarial universal-bait document…"
$DC exec -T vector-anchor python fixtures/inject_poison.py || true

say "  Running four unrelated queries that all retrieve the bait…"
for q in \
    "how do I prune tomato plants in my garden" \
    "what is a red giant star in a galaxy" \
    "how long should I boil pasta noodles" \
    "how much emergency fund and savings should I budget"; do
    $DC exec -T vector-anchor curl -s -X POST http://localhost:8001/retrieve \
        -H 'Content-Type: application/json' -d "{\"query\":\"$q\"}" >/dev/null || true
done
say "  Quarantine state:"
$DC exec -T vector-anchor curl -s http://localhost:8001/quarantine || true
echo
sleep "$PAUSE"

# ═══════════════════════════════════════════════════════════════════════
hr; say "ATTACK 3/3 — TraceAudit: reasoning divergence + PII leak (reasoning layer)"; hr
say "  Streaming the divergence test prompt (expect early termination)…"
$DC exec -T trace-audit python fixtures/divergence_prompt.py divergence 2>&1 \
    | grep -E "TERMINATED|safe refusal|result:" || true
say "  Streaming a prompt whose context holds a fake credential (expect redaction)…"
$DC exec -T trace-audit python fixtures/divergence_prompt.py pii 2>&1 \
    | grep -E "REDACTED|result:" || true
sleep "$PAUSE"

# ═══════════════════════════════════════════════════════════════════════
hr; say "VERIFYING — did every attack actually reach the ledger?"; hr
# This asserts the whole delivery path, not just the detectors: detection ->
# on-disk outbox -> authenticated ingest -> Postgres. Delivery is asynchronous,
# so each check is given a few seconds to arrive.
expect() { # event_type  human-label
    for _ in $(seq 1 20); do
        if curl -sf "http://localhost:3000/api/incidents?status=all&since_ms=$START_MS&limit=500" 2>/dev/null \
             | grep -q "\"$1\""; then
            printf '  \033[32m[OK]\033[0m   %s\n' "$2"; return 0
        fi
        sleep 1
    done
    printf '  \033[31m[FAIL]\033[0m %s — no %s event reached the ledger\n' "$2" "$1"; return 1
}

fails=0
expect schema_mismatch                "MCP-Shield flagged the rug pull"          || fails=$((fails + 1))
expect corpus_poison_quarantine       "VectorAnchor quarantined the bait doc"    || fails=$((fails + 1))
expect reasoning_divergence_terminate "TraceAudit terminated on divergence"      || fails=$((fails + 1))
expect pii_redacted                   "TraceAudit redacted the fake credential"  || fails=$((fails + 1))

hr
if [ "$fails" -ne 0 ]; then
    say "DEMO FAILED — $fails of 4 expected detections never reached the dashboard."
    hr
    exit 1
fi
say "DEMO PASSED — all three layers detected, and every detection reached the ledger."
say "See the unified live feed at  http://localhost:3000"
hr
