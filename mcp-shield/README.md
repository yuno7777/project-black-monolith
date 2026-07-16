# MCP-Shield

**Project Black Monolith — tool-layer defense (Module 1 of 3)**

MCP-Shield is a security proxy for the
[Model Context Protocol](https://modelcontextprotocol.io) (stdio transport).
It sits between an AI agent and a real MCP server, forwards JSON-RPC
traffic, and watches the `tools/list` channel for two documented attack
classes:

1. **Schema mutation ("MCP rug pull")** — a server presents a clean tool
   schema when the user first approves it, then silently swaps in a mutated
   schema on a later `tools/list`. MCP-Shield fingerprints every tool object
   with **HMAC-SHA256 over a canonical (sorted-key) serialization**, stores
   the first-seen hash *and the full tool schema* as a trusted baseline in
   `baseline_hashes.json`, and raises a `SCHEMA MISMATCH DETECTED` warning
   (with a description diff and old/new hashes) whenever a later sighting
   doesn't match. In **enforce mode (the default)** it goes further and
   actively blocks the mutation — see below.

2. **Hidden-instruction injection ("tool poisoning")** — instructions aimed
   at the model buried inside a tool description. Every description is
   scanned for instruction-override phrases ("ignore previous instructions",
   …), embedded shell-command-looking substrings (`rm -rf`, `curl `, …), and
   invisible/non-printable Unicode (zero-width spaces, bidi overrides, …).
   Hits raise a `SUSPICIOUS DESCRIPTION FLAGGED` warning.

## Monitor vs. enforce mode

`MCP_SHIELD_MODE` selects what happens when a schema mismatch is detected:

| Mode                  | Detection logged | Agent receives                                    |
| --------------------- | ---------------- | ------------------------------------------------- |
| `enforce` **(default)** | yes            | the response **rewritten** so every mismatched tool carries its **trusted baseline schema** — the agent never sees the poisoned description |
| `monitor`             | yes              | the server's bytes unmodified (log-only, the pre-enforce behavior) |

Notes on enforce mode:

- Only mismatched tools are swapped; tools that match their baseline pass
  through as served. The rewritten response is re-serialized by the proxy,
  so whitespace/key order may differ from the server's original bytes —
  semantically identical JSON-RPC.
- The sanitizer still scans (and flags) the *mutated* description that the
  server actually sent, even though the agent receives the clean one.
- If an internal analysis error ever occurs, the proxy **fails open**: the
  response is forwarded unmodified and an `INTERNAL ANALYSIS ERROR` is
  logged at error level plus an `analysis_error` event — a detector bug is
  never silently mistaken for "nothing to flag." The same applies to a
  structurally malformed `tools/list` response (no `result.tools` array),
  which is logged as `MALFORMED tools/list RESPONSE`, distinct from a clean
  pass.
- Baseline files written by pre-enforce versions lack the stored schema
  (`tool` field); such entries are still flagged on mismatch but cannot be
  rewritten (the log says so explicitly). Delete `baseline_hashes.json` to
  re-register with full schemas.

**Re-flag semantics (intentional):** a mismatch is flagged — and in enforce
mode re-blocked — on *every* `tools/list` that serves the mutated schema,
not just the first. Each serving is a live attempt against the agent, so
repeat warnings are never suppressed. The trusted baseline is never
overwritten by a mismatch; to re-trust a legitimately updated tool, delete
its entry (or the whole `baseline_hashes.json`).

## Structured events

Detections are also emitted as single-line JSON events in the shared Project
Black Monolith shape (tracing target `monolith_event`) so they can be pushed
to the unified dashboard unchanged. When `MONOLITH_DASHBOARD_URL` and
`MONOLITH_EVENT_TOKEN` are set, each event is spooled to a **durable outbox**
(`MONOLITH_EVENT_OUTBOX_PATH`) and delivered asynchronously — a down dashboard
delays delivery but never loses the detection, and never affects the proxy
path:

```json
{
  "timestamp_ms": 1770000000000,
  "module": "mcp-shield",
  "event_type": "schema_mismatch",
  "severity": "critical",
  "details": { "tool": "read_file", "mode": "enforce", "action": "rewritten", "...": "..." }
}
```

Event types: `baseline_registered` (info), `schema_mismatch` (critical, with
`mode` and `action: rewritten|forwarded`), `suspicious_description`
(warning), `analysis_error` (warning), `tools_list_changed` (info, see
limitations).

## Architecture

```text
             stdin                child stdin
  agent ────────────▶ mcp-shield ────────────▶ real MCP server
        ◀────────────            ◀────────────
             stdout               child stdout
        (enforce mode may rewrite tools/list responses on this leg)

  stderr ◀── logs + structured security events (never stdout!)
```

- `src/main.rs` — entrypoint; sets up stderr logging and spawns the proxy.
- `src/proxy.rs` — pass-through routing, request/response id correlation,
  `tools/list` interception, enforce-mode response rewriting.
- `src/fingerprint.rs` — canonical serialization, HMAC-SHA256, baseline
  store (`baseline_hashes.json`), description diffing.
- `src/sanitizer.rs` — description pattern scanning (3 detector families).
- `src/jsonrpc.rs` — minimal JSON-RPC 2.0 message model.
- `src/events.rs` — structured event emission in the shared Monolith shape.
- `src/outbox.rs` — durable at-least-once dashboard delivery: a
  newline-delimited JSON spool (fsync on append, atomic compaction), retry
  with exponential backoff, and dead-lettering for permanent rejections.

  Because this proxy is **short-lived** — it exits when the agent closes
  stdin — it cannot rely on a background retry loop the way the long-running
  Python services do. Instead it drains the previous run's backlog on
  startup, flushes live while running, and makes one final forced pass before
  exit. Anything still undelivered stays on the spool and is retried by the
  next invocation. The honest limit: if the dashboard is down and the proxy
  never runs again, those events remain on disk undelivered — preserved, not
  lost.

Framing: line-delimited JSON-RPC (one message per `\n`-terminated line),
matching the MCP stdio transport. Logs go exclusively to **stderr**; stdout
carries only the (possibly rewritten) protocol stream.

## Setup

Requirements: Rust (stable) and Python 3 (only for the demo fixture).

```sh
cd mcp-shield
cargo build
```

Run against any stdio MCP server:

```sh
./target/debug/mcp-shield <server-command> [args...]
# e.g.
./target/debug/mcp-shield python fixtures/fake_mcp_server.py
```

Configuration (environment variables):

| Variable              | Default                         | Purpose                                  |
| --------------------- | ------------------------------- | ---------------------------------------- |
| `MCP_SHIELD_MODE`     | `enforce`                       | `enforce` (rewrite/block on mismatch) or `monitor` (log only) |
| `MCP_SHIELD_KEY`      | built-in dev key (banner-warns) | HMAC-SHA256 secret key                   |
| `MCP_SHIELD_BASELINE` | `baseline_hashes.json`          | baseline store path                      |
| `MONOLITH_DASHBOARD_URL` | *(unset)*                    | if set (e.g. `http://localhost:3000/api/ingest`), events are also POSTed here |
| `RUST_LOG`            | `info`                          | log filter (`monolith_event=info` isolates the JSON event feed) |

If `MCP_SHIELD_KEY` is unset, a **boxed `DEVELOPMENT HMAC KEY IN USE`
banner** is printed at warn level, exactly once at startup — it cannot be
missed in a demo log. Set a real key for anything beyond local testing.

## Running the detection + blocking demo

```sh
./fixtures/run_demo.sh        # from mcp-shield/ (bash / Git Bash on Windows)
```

The demo is fully local and self-contained: `fixtures/fake_mcp_server.py`
is a mock MCP server exposing one `read_file` tool, spawned as a child
process of mcp-shield. Nothing in it executes any command — the "poisoned"
description is inert text used only to validate the detector.

Three phases:

1. **Clean (enforce default):** `initialize` + `tools/list` establish the
   trusted baseline (`registered trusted baseline fingerprint`).
2. **Rug pull, enforce (default):** the fixture serves the mutated schema.
   Both warning banners fire, **and** the script asserts the agent-facing
   stdout contains the *clean* baseline description with no trace of the
   injected `<IMPORTANT>` payload — proving the block actually happened,
   not just the log line.
3. **Rug pull, monitor:** same replay with `MCP_SHIELD_MODE=monitor`. The
   mismatch is re-flagged (repeat sightings are never suppressed) but the
   mutated schema passes through unmodified.

The script exits 0 only if all eight checks pass, ending with:

```text
DEMO PASSED: rug pull detected, blocked in enforce mode, forwarded (with warnings) in monitor mode.
```

## Verifying the durable outbox

```sh
bash fixtures/verify_outbox.sh    # from mcp-shield/; needs cargo, node and python
```

No Docker required — `fixtures/fake_ingest.js` stands in for the dashboard's
`/api/ingest` so both its availability and its status code can be controlled.
Three phases, run in CI:

1. **Dashboard down** — events must persist to the spool and the proxy must
   keep serving the MCP stream regardless.
2. **Dashboard up** — the *next* invocation must deliver the backlog phase A
   left behind. This is the claim that matters here: the proxy exits when the
   agent closes stdin, so it cannot retry on a background loop. The script also
   asserts every delivered envelope carried a bearer token, a v4 UUID
   `event_id`, and `schema_version: 2`.
3. **Dashboard returns 401** — a permanent rejection must dead-letter rather
   than retry forever.

Unit tests (`cargo test`, 11 tests) cover the sanitizer families, an exact
hit-count check against the fixture's poisoned description (guarding
against double-counting from overlapping patterns), canonicalization
determinism, re-flag-on-every-sighting semantics, malformed-response
handling, and the enforce/monitor rewrite paths.

## Known limitations

- **Only request-matched `tools/list` responses are analyzed.** The proxy
  correlates responses to `tools/list` requests by JSON-RPC id; any MCP
  transport pattern where a server pushes schema data outside that exact
  request/response pairing is not inspected. In the current MCP spec the
  server-initiated path is `notifications/tools/list_changed`, which
  carries **no schema data** itself — it only tells the client to re-query,
  and that re-query *is* analyzed. MCP-Shield logs the notification and
  emits a `tools_list_changed` event when it sees one (it is the classic
  prelude to a rug pull). A future pass would need to also fingerprint
  schema data embedded in other surfaces (e.g. `prompts/list`,
  `resources/list`, tool *results* that define further tools) if those are
  ever used to smuggle schemas.
- The dev HMAC key is for local use only; set `MCP_SHIELD_KEY` in any real
  deployment.
- Only line-delimited framing is implemented (the MCP stdio standard);
  `Content-Length` framing is future work.
- A tool that is poisoned from its very first sighting has no clean
  baseline to rewrite to — it is registered as-is (and the sanitizer still
  flags its description). First-contact trust is inherent to the
  fingerprint-on-first-sight model.
