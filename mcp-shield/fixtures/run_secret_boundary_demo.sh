#!/usr/bin/env bash
# MCP-Shield Secret Boundary end-to-end demo.
#
# What this proves (all of it locally, with no network and no real secret):
#
#   1. SHADOWING — the backend advertises a tool named `get_secure_weather`
#      that shadows a Secret Boundary tool. The agent must see the BOUNDARY's
#      trusted definition, never the backend's impostor.
#   2. INTERCEPTION — a `tools/call` for the secret-bound tool is answered by
#      the boundary inside the proxy. It must never reach the backend child
#      process, which records every method it receives.
#   3. FAIL-CLOSED OUTBOUND — the approved destination is a cloud metadata
#      address. The policy allows the operation, but the SSRF guard refuses
#      the destination, so the agent gets a clean JSON-RPC error and the
#      credential is never transmitted anywhere.
#   4. NO LEAKAGE — neither the agent-facing output nor the proxy's event
#      stream contains the synthetic credential.
#
# The outbound HTTPS *success* path is not exercised here: the SSRF guard
# blocks loopback and private destinations by design, so a local server
# cannot legitimately be the approved destination. That path is covered by
# the Rust integration suite (mcp-shield/src/secret_boundary/tests.rs), which
# runs a real local TLS server with a trusted certificate.
#
# Exit code 0 = all checks passed.

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

OUTDIR="$(mktemp -d)"
trap 'rm -rf "$OUTDIR"' EXIT

# Fresh baseline so the demo is reproducible run-to-run.
BASELINE="${MCP_SHIELD_BASELINE:-baseline_hashes.json}"
rm -f "$BASELINE"

# The backend's own log: the record of every method it actually received.
BACKEND_LOG="$OUTDIR/backend.log"
: > "$BACKEND_LOG"

export MCP_SHIELD_SECRET_BOUNDARY_CONFIG="$PWD/fixtures/secret_boundary_config.json"
export MCP_FIXTURE_LOG="$BACKEND_LOG"
export MCP_SHIELD_BASELINE="$BASELINE"
export MCP_SHIELD_KEY="demo-secret-boundary-key"

# The scripted "agent": initialize, initialized notification, tools/list, then
# a call to the secret-bound tool.
REQUESTS='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo-client","version":"0.1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_secure_weather","arguments":{"city":"Austin"}}}'

echo
echo "======================================================================"
echo "  SECRET BOUNDARY DEMO"
echo "  (mock credential provider | cloud-metadata destination | no network)"
echo "======================================================================"

printf '%s\n' "$REQUESTS" | "$BIN" "$PY" fixtures/fake_boundary_mcp_server.py \
    > "$OUTDIR/agent.out" 2> "$OUTDIR/shield.err" || true

echo "---- mcp-shield security log (stderr) ----"
cat "$OUTDIR/shield.err"
echo "---- responses forwarded to the agent (stdout) ----"
cat "$OUTDIR/agent.out"
echo "---- methods the backend actually received ----"
cat "$BACKEND_LOG"

echo
echo "== Verifying the secret boundary =="
pass=true
check() { # check <expr-result> <ok-msg> <fail-msg>
    if [ "$1" -eq 0 ]; then echo "  [OK]   $2"; else echo "  [FAIL] $3"; pass=false; fi
}

# 1. Shadowing: the agent must see the boundary's trusted description, and
#    never the backend's impostor description.
grep -q "Fetch current weather observations securely." "$OUTDIR/agent.out"; check $? \
    "the boundary's trusted tool definition was advertised to the agent" \
    "the boundary's tool definition is missing from the agent-facing tools/list"

! grep -q "BACKEND IMPOSTOR" "$OUTDIR/agent.out"; check $? \
    "the backend's impostor tool definition was shadowed" \
    "the backend's impostor definition reached the agent"

# 2. Interception: the backend must never have seen the secret-bound call.
! grep -q "CALLED get_secure_weather" "$BACKEND_LOG"; check $? \
    "the secret-bound tools/call was NOT forwarded to the backend" \
    "the secret-bound tools/call was forwarded to the backend"

! grep -q "BACKEND HANDLED" "$OUTDIR/agent.out"; check $? \
    "the call was answered by the boundary, not the backend" \
    "the agent received the backend's answer instead of the boundary's"

# 3. Fail-closed outbound: the SSRF guard refuses the metadata destination,
#    so the agent gets a clean JSON-RPC error rather than a fetched body.
grep -q '"id":3' "$OUTDIR/agent.out"; check $? \
    "the blocked call produced a response to the agent" \
    "no response was produced for the blocked call"

grep '"id":3' "$OUTDIR/agent.out" | grep -qi "ssrf\|blocked\|metadata"; check $? \
    "the error names the SSRF refusal" \
    "the error does not explain why the destination was refused"

! grep '"id":3' "$OUTDIR/agent.out" | grep -q '"result"'; check $? \
    "no successful result was returned for the blocked call" \
    "a successful result was returned for a destination that must be refused"

# The ordinary tool must still be advertised: the boundary shadows one tool,
# it does not take over the whole catalogue.
grep -q '"name":"read_file"' "$OUTDIR/agent.out"; check $? \
    "the ordinary backend tool is still advertised" \
    "the ordinary backend tool disappeared from the tools/list"

# 4. No leakage: the synthetic credential must appear nowhere.
! grep -q "synthetic-dev-token" "$OUTDIR/agent.out"; check $? \
    "the synthetic credential is absent from the agent-facing output" \
    "the synthetic credential LEAKED into the agent-facing output"

! grep -q "synthetic-dev-token" "$OUTDIR/shield.err"; check $? \
    "the synthetic credential is absent from the security log" \
    "the synthetic credential LEAKED into the security log"

# The audit event must have been emitted for the failed operation.
grep -q "secret_operation_failed" "$OUTDIR/shield.err"; check $? \
    "a secret_operation_failed audit event was emitted" \
    "no secret_operation_failed audit event was emitted"

# The interception must be visible in the log.
grep -q "intercepting secret-bound tool call" "$OUTDIR/shield.err"; check $? \
    "the interception is recorded in the security log" \
    "the interception was not recorded in the security log"

echo
if $pass; then
    echo "DEMO PASSED: the boundary shadowed the impostor, intercepted the call locally,"
    echo "refused the metadata destination, and leaked no credential."
else
    echo "DEMO FAILED: one or more checks did not pass (see logs above)."
    exit 1
fi
