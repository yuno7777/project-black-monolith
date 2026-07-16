#!/usr/bin/env bash
# Reset Project Black Monolith to a clean state before a live demo run —
# WITHOUT a rebuild. Wipes:
#   * MCP-Shield's trusted-schema baseline  (baseline_hashes.json)
#   * VectorAnchor's quarantine + frequency-tracker state
#   * TraceAudit's captured baseline distribution (re-captured on next start)
#   * the dashboard's in-memory event history (bounded ring buffer)
#
# Works whether the stack is running under Docker Compose or locally, and is
# safe to run when nothing is up (it just clears on-disk artifacts).
#
#   ./scripts/reset_demo_state.sh

set -uo pipefail
cd "$(dirname "$0")/.."

say() { printf '  %s\n' "$*"; }

echo "== Resetting Project Black Monolith demo state =="

# --- 1. On-disk artifacts (always safe) --------------------------------
say "removing on-disk artifacts…"
rm -f  mcp-shield/baseline_hashes.json
rm -rf vector-anchor/chroma_store
rm -f  trace-audit/baseline_distribution.json
say "  cleared baseline_hashes.json, chroma_store/, baseline_distribution.json"

# --- 2. Running services under Docker Compose --------------------------
if command -v docker >/dev/null 2>&1 && [ -n "$(docker compose ps -q 2>/dev/null)" ]; then
    say "docker compose stack is up — resetting live state…"
    # MCP-Shield writes its baseline to /tmp inside the container.
    docker compose exec -T mcp-shield sh -c 'rm -f /tmp/baseline_hashes.json' 2>/dev/null \
        && say "  mcp-shield: baseline reset"
    # VectorAnchor: clear the in-memory tracker + quarantine (corpus is kept).
    docker compose exec -T vector-anchor curl -fs -X POST \
        http://localhost:8001/admin/reset-detection >/dev/null 2>&1 \
        && say "  vector-anchor: quarantine + tracker reset"
    # Dashboard event history is an in-memory ring buffer — a restart clears it.
    docker compose restart dashboard >/dev/null 2>&1 \
        && say "  dashboard: event history cleared (restarted)"
else
    # --- 3. Local (non-Docker) services, if reachable ------------------
    if curl -fs -X POST http://localhost:8001/admin/reset-detection >/dev/null 2>&1; then
        say "vector-anchor (localhost:8001): quarantine + tracker reset"
    fi
    say "note: the dashboard event history is in-memory; restart the dashboard"
    say "      process to clear it if it is running locally."
fi

echo "== Done. State is clean for a fresh demo run. =="
