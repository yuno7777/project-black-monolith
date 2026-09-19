# Codebase review and cross-platform work

Reviewed baseline: `6472eacc119e65722772b8494f6bd1f1ffaffc60`.

## What exists

This is already a multi-service security system, with Linux Docker support:

| Component | Implementation | Existing controls |
| --- | --- | --- |
| MCP-Shield | Rust/Tokio, stdio and HTTP bridge | Authenticated schema baselines, approval mode, description scanning, enforced schema replacement, durable event spool |
| VectorAnchor | Python/FastAPI/Chroma | Cross-topic frequency tracking, quarantine, persisted detector state, admin authorization |
| TraceAudit | Python/FastAPI | Mock/Ollama streams, distribution drift detection, bounded streaming PII redaction |
| Dashboard | Next.js/PostgreSQL | Tenant-scoped event history, authenticated operators, incident workflows, SSE replay, alert delivery, benchmark ledger |

The portability gap was primarily the native workflow. The previous local
runner required Bash and used Windows `netstat`/`taskkill` port scanning for
cleanup. Its documented installation commands also assumed Windows `py`.

## Changes in this branch

- Native Python entry points for local startup and secret generation, with
  existing Bash commands retained as wrappers.
- Paths resolved from the script location, the current Python interpreter
  reused for services, and Next.js invoked through Node without `npm.cmd`.
- Literal `.env` parsing, environment overrides, proper JSON serialization
  and URL-encoded generated database connection passwords.
- Isolated per-run detector state, retained diagnostic logs, checked subprocess
  exit codes, readiness deadlines, and occupied-port refusal.
- Owned process-group cleanup on POSIX and Windows process-group signaling
  with a tree-termination fallback. No port-wide process killing.
- Native CI matrices for Linux, Windows, and macOS across service suites and
  launcher tests. Docker integration remains on Linux.
- Consistent LF checkouts to keep migration hashes stable across platforms.

## Recommended next implementation work

### 1. Bound and supervise the MCP stdio boundary

`mcp-shield/src/proxy.rs` uses `BufReader::lines()` for the agent and server
streams. Pending-request counts are bounded, but a single unterminated line
can still grow without a message-size limit. The HTTP bridge already has a
bounded reader. Reuse that pattern for both stdio directions and add tests
for oversized input, missing newlines, and invalid encodings. Also put a
deadline on child exit and terminate the child when forwarding fails; the
current unconditional `child.wait()` can hang on a server that closes stdout
but keeps running. This is the highest-priority boundary-hardening task.

### 2. Evaluate real traffic before broadening detection claims

`evaluation/profiles.json` provides a real-model profile, but the main gates
and calibration corpora are small and synthetic. VectorAnchor defaults to
hash embeddings and TraceAudit's mock intentionally generates an anomalous
vocabulary for marked prompts. Excellent regression coverage does not yet
establish detection quality on real agent traffic.

Run held-out corpora with semantic embeddings and several actual models,
separate tuning from evaluation, and report false positives by benign task
type as well as attack recall. Include code, multilingual text, valid shell
tool documentation, topic shifts, and low-frequency targeted poisoning.
Record model identity, parameters, policy version, and p95 added latency.

### 3. Close the remaining streaming-secret boundary

`trace-audit/src/stream_proxy.py` delays 16 output fragments. Its own scanner
documentation acknowledges that longer adversarial fragmentation can escape
that window. Implement a bounded character-level incremental scanner with
explicit handling for incomplete candidate matches, then measure its latency
and false positives. Keep the existing evasion tests and add splits at every
character, whitespace/Unicode variants, and adjacent normal text.

### 4. Make retrieval and corpus updates a consistent transaction

`vector-anchor/src/retriever_proxy.py` queries Chroma before acquiring the
detector state lock, while administrative upserts run under that lock and
invalidate old tracking. An in-flight retrieval can therefore apply an old
document version after an upsert has reset its history. Add a corpus revision
check/retry or serialize the query with updates. A regression test should
pause a retrieval between query and scoring, replace the document, and verify
that stale content never repopulates the new version's tracking state.

### 5. Finish operational tooling and native integration coverage

`scripts/reset_demo_state.sh` still says a dashboard restart clears event
history. PostgreSQL now persists that history, so its current completion
message is misleading. Define an explicit, tenant-scoped demo reset and
separate corpus reset from ledger retention. Do not silently delete real
incident evidence. The remaining Docker/verification helpers can stay Bash,
but any additional advertised native workflows need portable entry points.

Add a native full-stack smoke job with PostgreSQL on each OS, including
startup failure, Ctrl-C, spawned descendants, occupied ports, and an actual
three-layer event reaching the ledger. Matrix unit tests alone do not prove
the complete native stack starts successfully on every host.

## Validation limits

The implementation was exercised in a Linux VM. Native Windows/macOS execution
and complete PostgreSQL-backed startup require their respective environments.
The CI matrix is configured to supply native service coverage; adding it is
not itself evidence that those runs passed. Rust was not installed in the VM.

Local checks passed:

- 8 native tooling tests using Python unittest.
- 64 TraceAudit, 71 VectorAnchor, and 17 shared event-delivery tests.
- 32 dashboard tests using `node --import tsx --test test/contracts.test.ts`.
- Migration structure validation, Ruff on the new Python code, and diff checks.

The ordinary `npm test` wrapper could not create its tsx IPC socket in this VM;
the same dashboard suite passed through Node's tsx import hook instead.
The full native stack, Rust build, and Docker integration were not run locally.

## Follow-up implementation

The follow-up branch implements the next-work items above:

- MCP stdio is bounded to 1 MiB in both directions; invalid JSON/UTF-8 aborts
  forwarding. EOF and failed forwarding trigger bounded child cleanup.
- Corpus query and scoring are serialized with document replacement.
- TraceAudit uses a character-bounded look-behind, handles format-control and
  compatibility-glyph obfuscation, and retains incomplete variable-length keys.
  Overlong unbroken candidates fail closed. This can redact benign long IDs.
- Ollama fragments preserve whitespace and subword boundaries. Successful
  generations emit content-free correlation events.
- A held-out real-model evaluator runs semantic retrieval and multiple installed
  Ollama models, records provenance, category false positives, and added latency.
  It never substitutes mock output for unavailable external models.
- The native demo verifies all three attack findings in PostgreSQL and runs the
  read-only protected note agent. Native PostgreSQL CI covers the three OSes.
- Reset tooling now resets authenticated detector history and explicitly retains
  corpus documents and the incident ledger. New runs use fresh local state.

The first PR's native service tests passed Windows and macOS, including Rust
and dashboard builds. Its Linux audit failures identified dependencies requiring
updates: Next.js, Sharp, js-yaml, and rustls. Those have been updated in the
follow-up. Full-stack CI results must still be reviewed for the follow-up commit.

Local follow-up evidence includes Rust unit and stdio-process integration tests,
Python service regressions, dashboard tests/build, and a three-service attack
smoke test against a test ingestion endpoint. This smoke is not a substitute for
PostgreSQL integration. External semantic-model download timed out, and the
Ollama binary download was blocked by the VM proxy. No real-model accuracy
results are claimed from those attempts.
