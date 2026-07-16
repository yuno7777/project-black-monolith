#!/usr/bin/env bash
# MCP-Shield end-to-end detection + blocking demo.
#
# Phase 1 (clean / enforce default): proxy the fixture server in "clean"
#     mode and send initialize + tools/list — the read_file tool's schema
#     fingerprint (and full schema) is registered as the trusted baseline.
# Phase 2 (rug pull / enforce default): relaunch with the fixture in
#     "modified" mode. The mutated description must trigger the SCHEMA
#     MISMATCH and SUSPICIOUS DESCRIPTION detections, AND the agent-facing
#     stdout must contain the clean baseline schema, not the poisoned one —
#     proving enforce mode actively blocks the rug pull.
# Phase 3 (rug pull / monitor mode): same replay with MCP_SHIELD_MODE=monitor.
#     Detections still fire (including the repeat mismatch re-flag), but the
#     mutated schema passes through unmodified — today's log-only behavior.
#
# Everything runs locally: mcp-shield spawns the fixture as a child process
# over stdio. Exit code 0 = all checks passed.

set -euo pipefail
cd "$(dirname "$0")/.."

# --- locate a working python interpreter --------------------------------
if command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
    PY=python
elif command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
    PY=python3
else
    echo "error: no working python interpreter found on PATH" >&2
    exit 1
fi

# In a container (or CI) a prebuilt binary can be supplied via MCP_SHIELD_BIN
# to skip the build step entirely.
if [ -n "${MCP_SHIELD_BIN:-}" ] && [ -x "${MCP_SHIELD_BIN}" ]; then
    BIN="${MCP_SHIELD_BIN}"
    echo "== Using prebuilt mcp-shield: $BIN =="
else
    echo "== Building mcp-shield =="
    cargo build --quiet
    BIN="target/debug/mcp-shield"
    [ -x "$BIN" ] || BIN="target/debug/mcp-shield.exe"
    if [ ! -x "$BIN" ]; then
        echo "error: built binary not found under target/debug" >&2
        exit 1
    fi
fi

# Fresh baseline so the demo is reproducible run-to-run.
BASELINE="baseline_hashes.json"
rm -f "$BASELINE"

OUTDIR="$(mktemp -d)"
trap 'rm -rf "$OUTDIR"' EXIT

# The scripted "agent": initialize, initialized notification, tools/list.
REQUESTS='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-client","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# run_phase <id> <fixture_mode> <shield_mode|""=default> <label>
run_phase() {
    local id="$1" fixture_mode="$2" shield_mode="$3" label="$4"
    echo
    echo "======================================================================"
    echo "  PHASE $id: $label"
    echo "  (fixture: $fixture_mode | MCP_SHIELD_MODE: ${shield_mode:-<unset, defaults to enforce>})"
    echo "======================================================================"
    (
        export MCP_FIXTURE_MODE="$fixture_mode"
        if [ -n "$shield_mode" ]; then
            export MCP_SHIELD_MODE="$shield_mode"
        fi
        printf '%s\n' "$REQUESTS" | "$BIN" "$PY" fixtures/fake_mcp_server.py
    ) > "$OUTDIR/$id.out" 2> "$OUTDIR/$id.err" || true
    echo "---- mcp-shield security log (stderr) ----"
    cat "$OUTDIR/$id.err"
    echo "---- responses forwarded to the agent (stdout) ----"
    cat "$OUTDIR/$id.out"
}

run_phase 1 clean    ""        "establish trusted baseline (enforce default)"
run_phase 2 modified ""        "rug-pull replay — enforce mode BLOCKS the mutation"
run_phase 3 modified "monitor" "rug-pull replay — monitor mode logs but forwards"

echo
echo "== Verifying detections and blocking behavior =="
pass=true
check() { # check <expr-result> <ok-msg> <fail-msg>
    if [ "$1" -eq 0 ]; then echo "  [OK]   $2"; else echo "  [FAIL] $3"; pass=false; fi
}

grep -q "registered trusted baseline" "$OUTDIR/1.err"; check $? \
    "phase 1: baseline registered during the clean run" \
    "phase 1: baseline registration not observed"

grep -q "SCHEMA MISMATCH DETECTED" "$OUTDIR/2.err"; check $? \
    "phase 2: SCHEMA MISMATCH DETECTED fired" \
    "phase 2: schema mismatch warning did not fire"

grep -q "SUSPICIOUS DESCRIPTION FLAGGED" "$OUTDIR/2.err"; check $? \
    "phase 2: SUSPICIOUS DESCRIPTION FLAGGED fired" \
    "phase 2: suspicious description warning did not fire"

! grep -q "<IMPORTANT>" "$OUTDIR/2.out"; check $? \
    "phase 2: poisoned description NOT forwarded to the agent (blocked)" \
    "phase 2: poisoned description leaked to the agent in enforce mode"

grep -q '"read_file"' "$OUTDIR/2.out"; check $? \
    "phase 2: agent still received the read_file tool (clean baseline schema)" \
    "phase 2: rewritten response is missing the tool entirely"

grep -q "SCHEMA MISMATCH DETECTED" "$OUTDIR/3.err"; check $? \
    "phase 3: repeat mismatch RE-FLAGGED on a later sighting" \
    "phase 3: repeat mismatch was silently suppressed"

grep -q "<IMPORTANT>" "$OUTDIR/3.out"; check $? \
    "phase 3: monitor mode forwarded the mutated schema unmodified" \
    "phase 3: monitor mode unexpectedly altered the response"

grep -q "DEVELOPMENT HMAC KEY IN USE" "$OUTDIR/1.err"; check $? \
    "dev-key warning banner is present in the logs" \
    "dev-key warning banner missing"

echo
if $pass; then
    echo "DEMO PASSED: rug pull detected, blocked in enforce mode, forwarded (with warnings) in monitor mode."
else
    echo "DEMO FAILED: one or more checks did not pass (see logs above)."
    exit 1
fi
