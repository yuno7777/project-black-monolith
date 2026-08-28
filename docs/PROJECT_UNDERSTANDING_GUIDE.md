# Project Black Monolith — Easy Understanding Guide

> Written to prepare you for a technical interview. Everything below is traced
> from the actual code, not the README. Where the docs and the code disagree, the
> code wins and the discrepancy is called out.

---

## 1. Executive Project Summary

Project Black Monolith is **defensive security middleware for autonomous AI
agents**. Modern AI agents have three places where attacks can happen that operate independently:
the **tools** they can call (which can be poisoned or changed after approval), the
**stored knowledge or memory** they read from (which can be poisoned with documents engineered
to rank everywhere), and their **live model output** (which can drift very different from normal behavior
or leak secrets before the final answer). Black Monolith places an independent,
security check at each of those three layers, and joins
every detection into one authenticated, tenant-aware, permanent record of security events on a
PostgreSQL event database, surfaced through a Next.js dashboard that a person using the dashboard uses
to investigate and review and handle.

The three detection modules are deliberately **independent services with no shared
library**. What unifies them is a single **JSON event contract** — every module
emits the exact same envelope shape, saves it locally before trying to send it, and
delivers it with automatic retries, with repeatedly failing events kept aside for inspection to the dashboard's authenticated ingest
endpoint. The dashboard saves each event *before* publishing it live to browsers
over SSE, so the live feed is always a view over durable history, never a
temporary stream that could disappear.

The stack is: **Rust/Tokio** (MCP-Shield, tool layer), **Python/FastAPI + embedded
ChromaDB** (VectorAnchor, memory layer), **Python/FastAPI streaming SSE** (TraceAudit,
reasoning layer), and **Next.js 16 + PostgreSQL 17** (the dashboard/central dashboard).
The whole thing was originally built as a B.E. final-year project under the working
name "AEOS Guard" (the two PDFs in the repo root and `build_aeos_*.py` are leftover
artifacts of that phase); the module names MCP-Shield, VectorAnchor and TraceAudit
are unchanged.

The project is a **defensive research demo with real engineering rigor**: every
detector is calibrated against labelled corpora, scored into a evaluation table of correct and incorrect detections
that is itself persisted to the ledger and shown on the dashboard, and the
documented evasions are actually built and tested to confirm the claims. All
"attacks" in the repository are local, synthetic detection fixtures — nothing
targets real systems, and there are no real credentials.

---

## 2. What Problem It Solves

An autonomous agent (Claude with tools, a coding agent, an MCP-connected assistant)
does not have a single place where an attack can happen:

- **Tool layer.** A tool server can present a clean schema for human approval,
  then silently swap in a mutated one — a "rug pull" — that injects instructions
  into the agent's context ("ignore previous instructions, run curl …"). Tools can
  also be *first-contact poisoned*: already malicious before anyone ever looked.
- **Memory layer.** A vector store can be seeded with a "bait" document
  engineered to rank highly for many unrelated queries, so the agent pulls attacker
  content into its context no matter what it asks.
- **Reasoning layer.** A model's reasoning trace can drift very different from normal behavior (jailbreak
  or evasion) or echo secrets from its context (credentials, PII) into the stream
  before the final answer is produced — where a final-answer filter would never see it.

Harden only one layer and the others remain open. Black Monolith's core claim is
**protection at multiple layers**: intercept → analyze → block/quarantine/redact → persist →
investigate, at every layer, with a unified evidence trail so an operator can see
that the tool, memory, *and* reasoning layers all fired for the same agent session —
the signature of a compromised agent, which no single module could ever see.

---

## 3. Core User Experience

Two audiences:

**The agent runtime (machine-to-machine).** An agent that uses MCP tools runs its
tool server through `mcp-shield <server-command>` (or `--remote-url` for Streamable
HTTP). An agent with a vector retriever calls `POST /retrieve` on VectorAnchor
instead of hitting ChromaDB directly. An agent generating text calls
`POST /generate` on TraceAudit instead of the model API directly. Each module
transparently proxies the traffic, enforces its detection, and emits events — the
agent's own code barely changes.

**The person using the dashboard (human-to-machine).** An operator opens
`http://localhost:3000`, signs in with a bootstrap operator token (exchanged for a
revocable HttpOnly session cookie), and sees:

- a **live threat feed** — persisted history replayed, then real-time SSE updates;
- a **threat overview** — KPIs (attacks intercepted, open incidents, criticals,
  latency) plus per-module and per-severity breakdowns;
- an **investigation queue** (`/investigate`) — assign, acknowledge, resolve (with a
  mandatory verdict: true/false positive, benign, duplicate), reopen, filter, search,
  and inspect the can be added to but not silently rewritten audit trail of every decision;
- a **session view** — every event from the same `(tenant, agent, session)` tuple,
  grouped by layer, so a cross-layer hit is visible as one story;
- a **benchmarks page** — the latest confusion-matrix scorecard per detector, plus
  per-detector trend, next to *observed* precision computed from analysts' real
  verdicts;
- an **operations center** — ledger latency, per-module reachability and delivery
  backlog/failed-event storage counts, alert webhook status;
- **evidence export** — one versioned JSON bundle of an event + its incident state +
  audit trail + linked agent session.

The demo (`./run_full_demo.sh`) drives all three attacks in one agent session and
verifies against the ledger that all three modules reported under the same identity.

---

## 4. Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Tool layer | **Rust 1.86, Tokio, Serde, HMAC-SHA256**, reqwest (rustls) | Byte-exact stdio proxying, no GC pauses, small deps, `fsync`-grade durability |
| Memory layer | **Python 3.12, FastAPI, embedded ChromaDB** (PersistentClient) | Vector retrieval + the detector logic; embedder is a custom repeatable hash function by default |
| Reasoning layer | **Python 3.12, FastAPI, StreamingResponse (SSE), httpx** (lazy, for Ollama) | Per-token streaming interception |
| Control plane | **Next.js 16 (App Router), React 19.2, `pg`, `jose`, recharts** | Server routes are the API; client components consume SSE |
| Database | **PostgreSQL 17** (`supabase/postgres` image) | Immutable ledger, RLS, LISTEN/NOTIFY, transactional review and handle |
| Delivery | SQLite (WAL) outbox in Python modules; JSONL spool in Rust; Postgres `alert_outbox` | Durable at-least-once delivery with retry/failed-event storage |
| Live feed | Postgres `LISTEN`/`NOTIFY` + in-process broker + SSE | Multi-instance distribution to multiple listeners, save-before-show |
| Deployment | **Docker Compose** (5 services + migrator + bootstrap + alert dispatcher), CI on GitHub Actions | Reproducible local/CI stack |
| Auth | Bearer tokens (module, admin, operator), SHA-256 session digests, OIDC/Supabase JWT via `jose` | Four non-interchangeable types of identities |
| Monitoring of quality | ruff, mypy, pytest, cargo fmt/clippy/test, ESLint, CodeQL, cargo-audit, npm audit | Gates in CI |

**Not used (deliberately):** no message queue (no Kafka/RabbitMQ/Redis — Postgres
and local outboxes do the job at this scale), no ORM (raw parameterized SQL), no
auth framework (hand-rolled, deliberately small), no separate vector DB service
(ChromaDB is embedded), no real LLM by default (TraceAudit defaults to an offline
mock; Ollama optional).

---

## 5. High-Level Architecture

**In simple terms:** the AI agent's tool use, memory retrieval, and model output each pass through their own security checker. If one finds something suspicious, it records the event and sends it to the same dashboard.

```
                          ┌─────────────────────────────────────────────┐
                          │          AGENT RUNTIME (the defended)       │
                          └───────┬──────────────┬──────────────┬───────┘
                                  │              │              │
                   MCP stdio/HTTP │              │ retrieve     │ generate (SSE)
                                  ▼              ▼              ▼
                    ┌──────────────────┐ ┌──────────────┐ ┌──────────────┐
                    │  MCP-SHIELD      │ │ VECTOR-ANCHOR│ │ TRACE-AUDIT  │
                    │  Rust proxy      │ │ FastAPI +    │ │ FastAPI SSE  │
                    │  tool schemas    │ │ ChromaDB     │ │ token stream │
                    │  fingerprint +   │ │ frequency    │ │ KL divergence│
                    │  sanitizer       │ │ anomaly      │ │ + PII redact │
                    └────────┬─────────┘ └──────┬───────┘ └──────┬───────┘
                             │                  │                │
                JSONL spool  │        SQLite outbox (WAL)        │
                             │                  │                │
                             └─────────┬────────┴────────┬───────┘
                                       ▼                 ▼
                              POST /api/ingest   (per-module access token)
                                       │
                                       ▼
                          ┌─────────────────────────────┐
                          │ DASHBOARD (Next.js)         │
                          │  authenticate → validate →  │
                          │  persist → publish          │
                          └───────┬─────────────┬───────┘
                                  │             │
                    LISTEN/NOTIFY │             │ SSE /api/events
                                  ▼             ▼
                       ┌────────────────┐   ┌─────────────────┐
                       │  PostgreSQL    │   │  Browser UI     │
                       │  monolith schema│   │  (operator)     │
                       └────────────────┘   └─────────────────┘
                                  │
                                  ▼
                       alert-dispatcher → signed webhook
```

**Layers explained:**

1. **Detection modules** — each sits *inline* on the path it protects, makes its
   enforcement decision independently, and emits events through its own durable
   outbox. They never talk to each other.
2. **Delivery contract** — event written to a local reliable local event storage *before* the
   detection path continues; a background worker (or, for the short-lived Rust
   process, drain-on-startup + force-drain-on-exit + a resident `--drain-outbox`
   worker) POSTs to `/api/ingest` with increasing wait times between retries; 4xx/413/422 are
   moved aside as a permanent failure (permanent), 5xx retried (transient); `event_id` makes redelivery
   safe to retry without creating duplicates.
3. **Dashboard** — authenticates the access token scoped to `(tenant, module)`,
   strictly validates the envelope, inserts into Postgres with
   `on conflict (event_id) do nothing`, and only then publishes to SSE subscribers
   (via a Postgres LISTEN/NOTIFY-fed in-process broker). Save-before-show is
   the core reliability rule.
4. **PostgreSQL** — the main trusted copy of the data: immutable `security_events`, human
   judgement in `incident_review and handle`, can be added to but not silently rewritten `incident_audit`, benchmark
   scorecards in `benchmark_runs`, session digests in `operator_sessions`, webhook
   jobs in `alert_outbox`. All tenant-scoped by application predicates *and* RLS.
5. **Human operator** — investigates, review and handles, exports evidence. Every decision is
   an audit-trail row; the security event itself is never mutated.

---

## 6. Architecture Diagram — Deployment

```
                ┌───────────────────────── Docker Compose ─────────────────────────┐
                │                                                                  │
                │  database (supabase/postgres:17)          monolith-postgres-data │
                │      ▲                                    (volume)               │
                │      │ healthy                                                   │
                │  database-bootstrap (runs once: creates monolith_runtime)        │
                │      │ completed                                                 │
                │  dashboard-migrator (runs once: applies migrations)              │
                │      │ completed                                                 │
                │  dashboard :3000 ────► alert-dispatcher (webhook worker)         │
                │      │ healthy                                                   │
                │   ┌──┴───────────────┬───────────────────┐                       │
                │   ▼                  ▼                   ▼                       │
                │  vector-anchor :8001  trace-audit :8002   mcp-shield (resident    │
                │  (Chroma embedded,   (mock/ollama backend, outbox drainer;        │
                │   outbox+state vols)  baseline captured    proxies spawn on       │
                │                       at entrypoint)      demand via exec)        │
                └──────────────────────────────────────────────────────────────────┘
```

Ports 3000/8001/8002 bind to `127.0.0.1` only. All services are `read_only`,
`no-new-privileges`, with tmpfs `/tmp` and memory/pids limits. Compose refuses to
start without every secret in `.env`.

---

## 7. Why the Architecture Looks Like This

The consistent theme: **the evidence trail is the product, so delivery and
immutability come first; the detectors are inline, so they must be cheap and
fail-safe.**

**Decision: three independent services, no shared library.**
- *Likely reason*: each layer has genuinely different tech needs (byte-exact
  proxying → Rust; vector math + embedding → Python; streaming → FastAPI). A shared
  library would couple releases and force one language on all three.
- *Benefit*: modules can be deployed, tested, and scaled independently; a bug in one
  detector cannot crash another layer.
- *Tradeoff*: the event contract is duplicated (in Rust, in Python, in TypeScript,
  in JSON Schema) and must be kept in sync by convention + CI contract checks.
- *Alternatives*: a monorepo with a shared protobuf/avro schema; a message bus. At
  this scale, the JSON contract + `contracts/check_contracts.py` gate is cheaper.
- *When I'd change it*: when modules need to evolve the contract independently, or
  when there are many more modules — then a real schema registry and a bus make sense.

**Decision: reliable local event storage (SQLite WAL / JSONL spool) instead of fire-and-forget.**
- *Reason*: the dashboard can be down. If a detection is lost, the defense is
  unaccountable. The outbox makes "collector outage" cost *latency*, not evidence.
- *Tradeoff*: disk usage, a delivery worker per process, complexity at the edge
  (drain-on-exit for short-lived MCP-Shield).
- *Why SQLite for Python and JSONL for Rust*: the Python modules already depend on
  SQLite; MCP-Shield keeps its Cargo.toml minimal (no rusqlite) and uses an
  can be added to but not silently rewritten JSONL file with atomic compaction.

**Decision: Postgres as the ledger, not a document store or log service.**
- *Reason*: the system already needs transactional review and handle (state change + audit row
  in one transaction), RLS for separation between different users or organizations, LISTEN/NOTIFY for multi-instance
  distribution to multiple listeners, and SQL for the investigation queries. Postgres gives all four.
- *Tradeoff*: event volume is bounded by Postgres write throughput (~thousands/sec
  on one node); the GIN index on `details` and the `to_tsvector` search are already
  the most expensive queries.
- *Alternatives*: ClickHouse (analytics), TimescaleDB (time-series), Kafka + S3.
  Overkill for a demo-scale security ledger.

**Decision: strict validation: reject bad data instead of silently changing it.**
- *Reason*: coercing an unknown severity to `info` would silently *downgrade* a
  finding. A permanent 422 failed-event storages the event where a human can see it. The
  malformed-event test suite pins this deliberately.
- *Tradeoff*: a sender bug produces dead letters instead of a best-effort record —
  but that is the point: silent mutation is worse than visible failure.

**Decision: database RLS + application-level checks enforce the same tenant boundary twice.**
- *Reason*: protection at multiple layers for the most sensitive property (separation between different users or organizations).
  The app filters by `tenant_id` in every query *and* Postgres RLS checks a
  transaction-local `monolith.tenant_id` set via `set_config(..., true)`. If one
  layer has a bug, the other still holds.
- *Tradeoff*: every query carries a `set_config` call and a WHERE clause; some
  operational queries (session GC) become policy-constrained.

**Decision: mock backends by default (hash embedder, mock model).**
- *Reason*: the demo must run fully offline and be repeatable. The repeatable
  profile is the CI claim; the `real` profile (sentence-transformers, Ollama) is
  explicitly reported as NOT MEASURED until it runs.
- *Tradeoff*: real-backend behavior (semantic embedding distributions, real model
  token distributions) is *not* validated — the calibration documents this honestly
  as a limitation.

**What looks like it was vibe-coded (honestly):** the repo-root `AEOS_Guard_*.pdf`,
`build_aeos_pdf.py`, `build_aeos_report.py` and `video/` are college-phase leftovers
unrelated to the current system. `dashboard/node_modules` and `mcp-shield/target`
are committed into the working tree (see `git status`) — build artifacts that should
be gitignored. `trace-audit/src/events.py` and `vector-anchor/src/events.py` are
vendored copies of `python-common/monolith_events/events.py` — the modules import
their own copy rather than the shared package (the docs say "no shared library",
but `python-common` exists; the copy is to keep the modules runnable standalone).

---

## 8. Repository / Folder Map

```
project-black-monolith/
├── mcp-shield/                TOOL LAYER — Rust stdio/HTTP MCP proxy
│   ├── src/
│   │   ├── main.rs            entry point; CLI dispatch; stderr logging; final drain
│   │   ├── proxy.rs           the proxy: bidirectional forwarding, tools/list
│   │   │                      interception, enforce/monitor, first-contact gate
│   │   ├── fingerprint.rs     canonical serialization → HMAC-SHA256; JSON baseline
│   │   │                      store (authenticated on load, atomic save)
│   │   ├── sanitizer.rs       3 detector families: instruction phrases, shell
│   │   │                      patterns, invisible Unicode
│   │   ├── jsonrpc.rs         minimal JSON-RPC 2.0 message model (loose, bounded)
│   │   ├── http_transport.rs  Streamable HTTP bridge (--remote-url)
│   │   ├── events.rs          event envelope emission (stderr + outbox)
│   │   └── outbox.rs          JSONL spool, drain/flusher, failed-event storage file, fsync
│   ├── fixtures/              fake_mcp_server.py, run_demo.sh (3-phase), verify_outbox.sh
│   └── Cargo.toml             tokio, serde, hmac/sha2, reqwest(rustls), fs2, tracing
├── vector-anchor/             MEMORY LAYER — FastAPI + embedded ChromaDB
│   ├── src/
│   │   ├── main.py            FastAPI app, /retrieve, /admin/* routes, admin auth
│   │   ├── retriever_proxy.py the choke point: retrieve → record → quarantine → serve
│   │   ├── frequency_tracker.py  THE detector: per-doc query clustering, retention
│   │   ├── embedding.py       hash bag-of-words embedder; normalize/unit_dot
│   │   ├── store.py           ChromaDB client/collection helpers
│   │   ├── quarantine.py      quarantine store
│   │   ├── detector_state.py  atomic JSON persistence of tracker + quarantine
│   │   ├── config.py          env → validated Config
│   │   └── events.py          vendored copy of the shared outbox
│   ├── fixtures/              seed_corpus.py, inject_poison.py, calibrate.py, benchmark.py
│   └── tests/                 unit + evasion tests
├── trace-audit/               REASONING LAYER — FastAPI streaming SSE
│   ├── src/
│   │   ├── main.py            FastAPI app, POST /generate, baseline loading
│   │   ├── stream_proxy.py    StreamAuditor: per-token KL + PII, PiiStreamBuffer
│   │   ├── divergence_monitor.py  rolling KL vs baseline; <other> bucket
│   │   ├── pii_scanner.py     regex + Luhn; 6 pattern families
│   │   ├── redaction.py       typed [REDACTED:label] replacement
│   │   ├── config.py          env → validated Config
│   │   └── events.py          vendored copy of the shared outbox
│   ├── fixtures/              baseline_capture.py, calibrate.py, divergence_prompt.py
│   └── tests/                 unit + evasion + validation tests
├── dashboard/                 CONTROL PLANE — Next.js 16 App Router
│   ├── app/
│   │   ├── api/ingest/route.ts        POST events (single or batch), GET liveness
│   │   ├── api/events/route.ts        SSE: replay ledger then stream live
│   │   ├── api/auth/session/route.ts  GET identity, POST login (token→session), DELETE logout
│   │   ├── api/incidents/route.ts     GET queue, POST review and handle transition
│   │   ├── api/incidents/[eventId]/audit|session|export/route.ts
│   │   ├── api/benchmarks/route.ts    GET latest+history+observed, POST a run
│   │   ├── api/operations/route.ts    ledger + runtime health
│   │   ├── page.tsx                   threat overview (client)
│   │   ├── investigate/page.tsx       investigation queue (client)
│   │   ├── operations/page.tsx        ops command center
│   │   ├── benchmarks/page.tsx        benchmark scorecards
│   │   ├── login/page.tsx             operator sign-in
│   │   └── components/                ThreatFeed, IncidentPanel, Sidebar, charts, theme
│   ├── lib/
│   │   ├── db.ts               pg Pool with `-c role=monolith_app`; withTenantDb/withSessionDb
│   │   ├── event-store.ts      normalizeEvent (strict) + persistEvents (safe to retry without creating duplicates)
│   │   ├── event-ingest.ts     in-process broker singleton (globalThis)
│   │   ├── live-event-listener.ts  Postgres LISTEN → load event → broker
│   │   ├── sse-event-stream.ts replay + live, Last-Event-ID, dedupe
│   │   ├── ingest-auth.ts      per-(tenant,module) access tokens, timingSafeEqual
│   │   ├── operator-auth.ts    operator tokens, sessions, cookies, roles
│   │   ├── external-auth.ts    OIDC/Supabase JWT validation (jose)
│   │   ├── login-rate-limit.ts Postgres-backed login throttling
│   │   ├── incident-store.ts   queue queries, review and handle transitions, session correlation
│   │   ├── benchmark-store.ts  validate + recompute metrics + persist runs
│   │   ├── operations-store.ts ledger health reads
│   │   ├── alert-config.ts     webhook config validation
│   │   ├── route-auth.ts       requireOperator + CSRF-style same-origin check
│   │   └── credentials.ts      access token shape validation
│   ├── scripts/
│   │   ├── migrate.mjs         checksum-verified migrations (advisory lock)
│   │   └── dispatch-alerts.mjs webhook worker (claim → sign → deliver → retry delay)
│   └── test/                   contract + malformed-event integration tests
├── supabase/
│   ├── bootstrap/001-runtime-role.sh  creates monolith_runtime login → monolith_app role
│   └── migrations/             7 versioned SQL migrations (see §12)
├── contracts/
│   ├── schemas/                event-envelope.v2, vector-anchor-api.v1,
│   │                           trace-audit-api.v1, benchmark-run.v1 JSON Schemas
│   ├── openapi.yaml            shared API surface + correlation headers
│   ├── check_contracts.py      CI gate: schemas valid, fixtures valid, headers pinned
│   └── fixtures/               canonical valid/invalid payloads
├── python-common/
│   └── monolith_events/events.py   the SHARED Python outbox (source of the vendored copies)
├── evaluation/
│   ├── run_profile.py          provenance wrapper (git rev, hashes, env, duration)
│   ├── profiles.json           repeatable vs real profiles
│   └── results/                (gitignored) per-run manifests + detector reports
├── scripts/
│   ├── generate_secrets.sh     .env with 8 random secrets
│   ├── run_local_demo.sh       Docker-free local stack runner
│   ├── run_benchmarks.sh       offline compute + upload scorecards
│   ├── verify_ingest.sh / verify_recovery.sh / verify_incidents.sh /
│   │   verify_correlation.sh / verify_benchmarks.sh   live-stack contract gates
│   └── reset_demo_state.sh
├── run_full_demo.sh            the correlated 3-attack demo + ledger verification
├── docker-compose.yml          the whole stack
├── .env.example                documented env contract (no values by design)
├── .github/workflows/          ci.yml, codeql.yml, sbom.yml
├── EVALUATION.md               the rigor story: calibration, evasions, overhead
├── docs/                       IDENTITY_AND_ACCESS.md, OPERATIONS.md
└── README.md / CLAUDE.md / SECURITY.md / CONTRIBUTING.md / LICENSE
```

**Leftovers to ignore in an interview:** `AEOS_Guard_*.pdf`, `build_aeos_pdf.py`,
`build_aeos_report.py`, `video/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`,
`mcp-shield/target/`, `dashboard/node_modules/`.

---

## 9. Important Entry Points

**1. `mcp-shield/src/main.rs`** — parses CLI args: `<server-command>...`,
`--remote-url <url>`, `--drain-outbox`, `--list-pending`, `--approve <tool>`.
Initializes stderr tracing, loads `ShieldConfig` from env (HMAC key, baseline path,
mode, first-contact policy), loads+authenticates the baseline store, spawns the
outbox flusher (drains prior backlog first), runs the proxy, then aborts the
flusher and does a forced 3-second final drain before exit.

**2. `vector-anchor/src/main.py`** — FastAPI lifespan builds the proxy: load config
→ create emitter → build embedding fn → open the single ChromaDB PersistentClient
collection → load (or quarantine-unreadable) detector state → construct
FrequencyTracker + Quarantine → emit `service_start`. Routes: `/health`, `/retrieve`,
`/admin/add-documents`, `/quarantine`, `/stats`, `/admin/reset-detection`.

**3. `trace-audit/src/main.py`** — lifespan loads config, builds emitter, loads +
validates the baseline distribution JSON, constructs `StreamAuditor`, emits
`service_start` (+ `baseline_missing` warning if no baseline). Routes: `/health`,
`/stats` (admin), `POST /generate` (SSE).

**4. `dashboard/scripts/migrate.mjs`** — runs at container start (as the `postgres`
role): takes a Postgres advisory lock, creates `monolith.schema_migrations`, applies
each `supabase/migrations/*.sql` in order, rejecting any applied migration whose
SHA-256 checksum changed.

**5. `dashboard/scripts/dispatch-alerts.mjs`** — separate container; loops: for each
configured tenant, claims one pending `alert_outbox` row (`for update skip locked`),
HMAC-SHA256-signs `"<timestamp>.<body>"`, POSTs to the webhook, marks delivered or
schedules retry delay; permanent failures failed-event storage.

**6. Next.js route handlers** — `/api/ingest` (module→dashboard), `/api/events`
(SSE), `/api/auth/session`, `/api/incidents*`, `/api/benchmarks`, `/api/operations`.
Every route is `runtime = "nodejs"`, `dynamic = "force-dynamic"`.

**7. `run_full_demo.sh`** — the human-visible entry point: waits for health, resets
MCP baseline, runs the 3-phase rug-pull demo via `docker compose exec`, seeds +
poisons + queries VectorAnchor, streams the divergence and PII fixtures through
TraceAudit, then queries the ledger with the operator token and asserts all four
detection event types arrived under one session id.

**8. `evaluation/run_profile.py`** — runs the `repeatable` or `real` profile,
writing a provenance manifest (git commit, source SHA-256s, python version, env,
duration, exit codes) into `evaluation/results/<profile>-<timestamp>/`.

---

## 10. End-to-End Application Flows

This section follows what actually happens from the moment an agent does something until a detection appears on the dashboard.

### Flow A — MCP-Shield: tool rug pull (the demo's attack 1)

1. Operator runs `mcp-shield python fixtures/fake_mcp_server.py` (or the demo runs
   it inside the container). The child MCP server is spawned with piped stdio.
2. The agent writes JSON-RPC lines (initialize, notifications/initialized,
   `tools/list`) to the proxy's stdin. `forward_agent_to_server` parses a *copy* of
   each line, records the `tools/list` request id in a bounded `VecDeque`, and
   forwards the original bytes to the child — byte-for-byte.
3. The server responds. `forward_server_to_agent` parses a copy, sees a response
   whose id matches a pending `tools/list`, and runs `analyze_tools_list`:
   - validates the tool entries (names unique, non-empty, ≤128 bytes, `inputSchema`
     present);
   - per tool: `sanitizer::scan_description`; then
     `fingerprint_tool` (canonicalize → HMAC-SHA256);
   - first sighting → baseline registered (`baseline_registered` info event);
     hash match → pass; hash mismatch → `schema_mismatch` critical event; in
     **enforce** mode (default) the tool in the response is *rewritten back to the
     trusted baseline schema*; in **monitor** mode the mutated schema is forwarded
     and only logged. The baseline is never overwritten on mismatch, so repeat
     servings re-flag every time.
   - a suspicious first-contact description (no baseline yet) is removed entirely,
     never blessed; under `MCP_SHIELD_FIRST_CONTACT=approve` every unseen tool is
     withheld (`tool_pending_approval`) until `mcp-shield --approve <tool>`.
4. The (possibly rewritten) line is written to the proxy's stdout — which is the
   *only* thing on stdout. Logs and events go to stderr.
5. Each event is emitted as a JSON line under the `monolith_event` tracing target
   and enqueued to the JSONL outbox (fsynced append). The background flusher
   POSTs to the dashboard; on proxy exit a forced drain gives events a last chance;
   the resident `--drain-outbox` container handles anything left.
6. Fail-open invariant: any internal analysis error logs at error level, emits
   `analysis_error`, and forwards the message unmodified — a detector bug must never
   look like "nothing to flag".

### Flow B — VectorAnchor: poisoned-document attack (attack 2)

1. `seed_corpus.py` (via `POST /admin/add-documents`) seeds 60 clean documents
   across twelve topics. The service owns the single ChromaDB client; fixtures
   never open a second one.
2. `inject_poison.py` upserts the universal-bait document (vocabulary from four
   unrelated topics).
3. An agent calls `POST /retrieve` with a query + correlation headers
   (`X-Monolith-*`). The proxy:
   - embeds the query once (same vector for Chroma and the detector);
   - pulls `k + candidate_buffer` candidates (buffer so quarantined docs can be
     replaced by the next-best clean result);
   - records the top-`top_rank_threshold` doc ids in the FrequencyTracker
     (per-doc `{query_id → embedding}` capped at `max_queries_per_doc`);
   - for each candidate: skips if already quarantined; if
     `distinct_topic_count(doc) >= min_distinct_topics` (4), quarantines it and
     emits `corpus_poison_quarantine` (critical) — with a SHA-256 of the document
     text, never the text itself, in telemetry;
   - serves the top-k clean docs; withheld docs are listed with reasons.
4. Detector state (tracker + quarantine) is atomically saved to
   `detector_state.json` after every retrieval, so the detector's memory survives
   restarts.
5. The bait document ranks for ~4 unrelated queries, its greedy clustering yields
   4+ distinct topics, and it is quarantined; later retrievals serve clean docs.

### Flow C — TraceAudit: reasoning divergence + PII (attack 3)

1. `baseline_capture.py` (run at container entrypoint) streams benign prompts
   through the mock backend and writes `baseline_distribution.json` (token counts).
2. An agent calls `POST /generate` with a prompt. `StreamAuditor.audit`:
   - builds a `DivergenceMonitor` (fixed vocab = baseline tokens + `<other>`;
     smoothed baseline probabilities `q`);
   - streams tokens from the backend (mock by default; Ollama if configured);
   - `observe(token)` updates a rolling window (20 tokens) and returns the current
     KL divergence after `min_tokens_before_check` (12);
   - each token also goes through `PiiStreamBuffer` — a bounded 16-token
     look-behind that scans every contiguous suffix of the buffer so a credential
     split across tokens is caught before any fragment is released;
   - PII match → span replaced with `[REDACTED:label]` in the output, and one
     `pii_redacted` event per unique secret (SHA-256 dedupe);
   - KL ≥ threshold (1.0) → the stream is terminated early, buffered fragments are
     discarded, a `reasoning_divergence_terminate` critical event is emitted, and a
     safe-refusal message is substituted.
3. Output frames are SSE `data:` lines: `{"type":"token","token":…,"kl":…}`,
   `{"type":"pii",…}`, `{"type":"terminated",…}`, `{"type":"done",…}`.

### Flow D — Event ingest and live feed (the spine)

1. A module's outbox POSTs a JSON envelope (or batch) to `/api/ingest` with
   `Authorization: Bearer <module token>`.
2. The route: reads body (≤256 KB, hard byte cap) → validates it is 1–100 events →
   `normalizeEvent` per event (strict: module must be known, event_type required,
   severity/timestamp/details *rejected* if invalid — only absent optional fields
   are defaulted; `event_id` must be a UUID or is generated; a supplied non-UUID is
   a 422 — this is the poison-pill fix) → batch must be single-module and
   single-tenant → `authenticateIngest` (SHA-256 + `timingSafeEqual` against the
   per-(tenant,module) token) → `persistEvents` inside `withTenantDb(tenant)`:
   `insert … on conflict (event_id) do nothing`, and if the event is critical and a
   webhook is configured, also inserts into `alert_outbox` **in the same
   transaction**.
3. The Postgres `notify_security_event` trigger fires `pg_notify` on
   `monolith_security_events`. Every dashboard instance's `LiveEventListener`
   receives it, loads the event by id, and pushes it into the in-process broker,
   which fans out to SSE subscribers in the same tenant.
4. A browser connecting to `/api/events`: authenticates (operator session or
   access-token) → subscribes to the broker → replays the last 500 ledger rows (from
   `Last-Event-ID` cursor if reconnecting) → then streams live events. Client dedupes
   by `event_id`; the server holds live events until replay completes so ordering is
   preserved.

### Flow E — Operator review and handle (the human loop)

1. Operator signs in at `/login` → POST `/api/auth/session` with the bootstrap
   token (rate-limited via the Postgres `record_operator_login_attempt` function:
   8 attempts / 15 min per IP) → server creates a 256-bit random session token,
   stores its SHA-256 digest in `operator_sessions`, returns an `HttpOnly,
   SameSite=Strict, Max-Age=8h` cookie.
2. Operator opens `/investigate` → GET `/api/incidents?status=open` → worst-first,
   newest-first paginated list of events left-joined with review and handle state (unreview and handled
   events are synthesized as "new" on read — no write on the ingest path).
3. Operator clicks "Resolve" with verdict `true_positive` → POST `/api/incidents`:
   `requireOperator(req, "analyst")` → `normalizeTransition` (actor derived from the
   credential, `assign_to_me` resolved server-side, resolution required for
   resolve) → `applyTransition` in one transaction: advisory lock per event →
   existence check scoped to tenant → `upsert incident_review and handle` (coalesce so omitted
   fields are never cleared; resolution cleared on reopen) → **append audit row in
   the same transaction**.
4. The audit trail is physically can be added to but not silently rewritten: the runtime role has no UPDATE/DELETE
   grant, and a `before update or delete` trigger raises even for the table owner.

### Flow F — Critical alert webhook

1. Critical event persisted (Flow D) → `alert_outbox` row.
2. `alert-dispatcher` claims due rows (`for update skip locked`), builds
   `{format, sent_at_ms, tenant_id, event}`, signs `"<timestamp>.<body>"` with
   HMAC-SHA256, POSTs with `x-monolith-timestamp` + `x-monolith-signature` headers.
3. 2xx → delivered; 408/429/5xx → increasing wait times between retries (2^n s, cap 5 min, max 10
   attempts); everything else → dead. Dead and delivered rows are pruned by a
   maintenance function after 30 days.

### Flow G — Benchmark upload

1. `scripts/run_benchmarks.sh` (or `cargo test benchmark_report`) computes the
   evaluation table of correct and incorrect detections per detector offline.
2. POST `/api/benchmarks` with the operator token → `normalizeRun` *recomputes every
   metric from the evaluation table of correct and incorrect detections* (a run claiming 100% with a 1-of-2 matrix is
   stored as 0.50) → persisted to `benchmark_runs` (one row per run+module+detector).
3. The Benchmarks page shows the latest run, per-detector history, and *observed*
   precision from analysts' verdicts — lab accuracy and operational accuracy side by
   side.

---

## 11. Data Flow

| Data | Origin | Stored | Transformed | Consumed by | Destination |
|---|---|---|---|---|---|
| Event envelope | detection modules | local outbox (SQLite/JSONL) → Postgres `security_events` | normalized strictly at ingest; enriched with `received_at` | SSE feed, incident queue, ops, export | audit-bundle exports; pruned after 90 days |
| Correlation identity | `X-Monolith-*` headers (per-request, Python) or env (MCP-Shield, per-process) | columns on the event | cleaned/clamped to ≤128 chars; omitted when unknown (never null) | session view, cross-layer count | ledger rows |
| Query text | agent → `/retrieve` | **never persisted in clear** — only SHA-256 + length in `details` | embedded → vector | frequency tracker | detector state |
| Document text | corpus seeds/poison | ChromaDB (embedded, on volume) | embedded once; preview kept only in quarantine (admin-only route) | retrieval, quarantine | quarantine list |
| Detector state | runtime observations | `detector_state.json` (atomic) | snapshots versioned; mismatched policy files quarantined aside, never deleted | restarts | next run |
| Baseline distribution | `baseline_capture.py` | `baseline_distribution.json` | counts → smoothed probabilities | DivergenceMonitor | startup |
| Operator identity | `OPERATOR_TOKENS_JSON` / OIDC JWT | session SHA-256 in `operator_sessions` | token → identity → session | every API route | audit trail `actor` |
| Triage decisions | analyst | `incident_review and handle` + `incident_audit` | normalized transitions | queue, observed precision | export bundles |
| Benchmark runs | offline detectors | `benchmark_runs` | metrics recomputed server-side | Benchmarks page | none (metadata only — never events) |
| Alert jobs | critical event insert (same txn) | `alert_outbox` | signed payload | dispatcher → webhook | delivered/dead rows |

**Where state lives:** browser (only theme + transient feed buffer; never
credentials), React state (client-side filtering), in-process broker (live distribution to multiple listeners
only, not main trusted copy of the data), Postgres (main trusted copy of the data), ChromaDB + detector_state.json
(module-local detector memory), local outboxes (delivery buffer), Docker volumes
(persistence across restarts).

---

## 12. Database Architecture

**Database:** PostgreSQL 17 (`supabase/postgres` image). The ledger lives in the
`monolith` **schema** of the `postgres` database — not a database of its own. This
is a real, documented constraint discovery: the Supabase image bootstraps as
superuser `supabase_admin`, so a database created via `POSTGRES_DB` is owned by it
and the app's `postgres` role gets CONNECT but not CREATE — `create schema` failed
with 42501 until the schema was moved into `postgres` (which also matches the real
Supabase-hosted target, where you cannot create databases at all).

**Roles (bootstrap script + migration):**

- `monolith_app` — NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOINHERIT group role; owns
  only the SQL verbs the app needs.
- `monolith_runtime` — LOGIN role the dashboard pool connects as; password set by
  bootstrap; `SET ROLE monolith_app` at connection (`options: "-c role=..."`); the
  pool then executes as `monolith_app`. It can only `SET ROLE` to `monolith_app`
  (no superuser anywhere on the path).
- Migrator runs as `postgres` (has CREATEROLE, can run migrations); role
  management is confined to the bootstrap script.

**Tables (simplified):**

```
monolith.security_events          -- immutable evidence (SELECT, INSERT only)
  event_id uuid PK                -- the safe retry behavior without duplicates key (on conflict do nothing)
  schema_version smallint, occurred_at_ms bigint, received_at timestamptz
  module text CHECK IN 3 modules, event_type text, severity text CHECK
  details jsonb, tenant_id text NOT NULL
  agent_id/session_id/trace_id/correlation_id/resource_type/resource_id/outcome/policy_version
  source text
  indexes: received_at, (module,received_at), (severity,received_at),
           (correlation_id,received_at) partial, (tenant_id,agent_id,session_id,received_at) partial,
           (tenant_id,received_at,event_id) cursor idx, GIN(details), GIN(to_tsvector(details::text))
  RLS: SELECT/INSERT with check tenant_id = current_setting('monolith.tenant_id')

monolith.incident_review and handle          -- human judgement ABOUT an event (SELECT, INSERT, UPDATE)
  event_id PK → security_events ON DELETE CASCADE
  status CHECK new|acknowledged|resolved
  assignee/note/resolution (CHECK: resolved ⇒ resolution NOT NULL)
  updated_at, updated_by
  RLS: existence join against security_events tenant

monolith.incident_audit           -- can be added to but not silently rewritten (SELECT, INSERT; trigger blocks UPDATE/DELETE)
  audit_id bigint identity PK, event_id, at, actor, from_status, to_status, assignee, resolution, note

monolith.benchmark_runs           -- evaluation metadata (SELECT, INSERT)
  PK (run_id, module, detector); evaluation table of correct and incorrect detections + derived metrics + latency percentiles
  metrics recomputed server-side; RLS tenant

monolith.operator_sessions        -- session digest (SELECT, INSERT, UPDATE; DELETE only expired/revoked)
  session_hash text PK (sha256 hex), actor, role CHECK viewer|analyst|admin,
  tenant_id, issued_at, expires_at, revoked_at, last_seen_at
  RLS: select/update scoped to session_hash = current_setting('monolith.session_hash')

monolith.operator_login_limits    -- rate limit table (no direct access)
  key_hash PK, window_started, attempts
  exposed only via security-definer fns record_operator_login_attempt / clear_operator_login_attempts

monolith.alert_outbox             -- webhook jobs (SELECT, INSERT, UPDATE)
  event_id PK → security_events, tenant_id, payload jsonb, status pending|delivered|dead,
  attempts, next_attempt_at, last_error, created_at, delivered_at
  RLS tenant; dispatcher claims with FOR UPDATE SKIP LOCKED
```

**Key queries:** worst-first incident queue (severity rank → received_at → event_id
with a base64url cursor); session grouping `group by agent_id, session_id having
count(distinct module) > 1`; observed precision from resolved verdicts; the SSE
cursor replay `(received_at, event_id) > (cursor)`.

**Read/write pattern:** writes are rare (events, review and handle, sessions, benchmarks) and
transactional; reads are frequent (queue, SSE replay, ops polling). The event table
grows monotonically — retention is a bounded maintenance function
(`prune_security_events`, 90 days default) callable only by a database owner, not
the app role.

**Consistency concerns:** `on conflict (event_id) do nothing` means a genuinely
duplicate id (two different events with the same UUID) silently drops the second —
acceptable because sources are trusted to generate UUIDs. Cross-tenant events in
one batch are rejected (one transaction cannot span tenants). The RLS tenant
context is transaction-local (`set_config(..., true)`), so pooled connections
cannot leak tenant context.

---

## 13. API Architecture

### Internal APIs (the dashboard)

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/api/ingest` | POST | per-(tenant,module) access-token | accept 1–100 events; validate, persist, queue alerts; 201/401/422/503 |
| `/api/ingest` | GET | none | liveness (checks DB) |
| `/api/events` | GET | operator (viewer) | SSE: replay 500 + live stream |
| `/api/auth/session` | GET | operator | current identity |
| `/api/auth/session` | POST | operator token in body | login: rate-limited, exchanges token for session cookie |
| `/api/auth/session` | DELETE | session cookie | logout: revoke + expire cookie |
| `/api/incidents` | GET | viewer | filtered, worst-first, cursor-paginated queue + counts |
| `/api/incidents` | POST | analyst | review and handle transition (assign/ack/resolve/reopen) + audit row |
| `/api/incidents/:id/audit` | GET | viewer | can be added to but not silently rewritten trail |
| `/api/incidents/:id/session` | GET | viewer | cross-layer session view (404 if uncorrelatable) |
| `/api/incidents/:id/export` | GET | viewer | versioned evidence bundle JSON download |
| `/api/benchmarks` | GET | viewer | latest run + history + observed accuracy |
| `/api/benchmarks` | POST | analyst | record a run (metrics recomputed) |
| `/api/operations` | GET | viewer | ledger health + module runtime health + alerting status |

### Module service APIs

| Route | Service | Purpose |
|---|---|---|
| `POST /retrieve` | VectorAnchor | proxied retrieval with quarantine (request `{query, k?}`; response `{results, withheld, quarantine_size}`) |
| `POST /admin/add-documents` | VectorAnchor | corpus upsert (admin token) |
| `GET /quarantine`, `GET /stats`, `POST /admin/reset-detection` | VectorAnchor | admin routes |
| `POST /generate` | TraceAudit | SSE token stream with divergence + PII enforcement |
| `GET /stats` | TraceAudit | admin |
| `POST /api/generate` | Ollama | the proxied model backend (TraceAudit is its client) |
| MCP stdio / Streamable HTTP | mcp-shield child | the proxied tool server |

### External APIs

| Service | Why | Data sent | Data back | Auth | Failure behavior |
|---|---|---|---|---|---|
| Ollama (optional) | real model backend for TraceAudit | prompt + `num_predict` | streaming tokens | none (local) | httpx errors → stream terminates with error (fail via exception) |
| Chroma sentence-transformers (optional) | semantic embeddings | documents/queries | vectors | none (local) | model download on first use |
| Alert webhook (optional) | critical notifications | signed JSON bundle | HTTP status | HMAC-SHA256 over `"<ts>.<body>"` | retry with retry delay; failed-event storage after 10 |
| Supabase Auth JWKS (optional) | operator identity | JWT | public keys | OIDC validation (RS256/ES256/EdDSA) | invalid/absent → 401; config error → 503 |

**Cost/rate-limit concerns:** only Ollama tokens are usage-based and that is local
and optional. The project's own APIs are rate-limited only for operator login
(8/15 min); ingest is intentionally unthrottled (modules are trusted) — a
misconfigured or compromised module could flood the ledger (see §21).

---

## 14. AI / ML Architecture

The important thing to remember is that Black Monolith protects AI systems, but its detectors are mostly normal security and statistical techniques rather than trained AI models.

This project is **not** an ML pipeline — it is a set of *detectors around* ML
systems. Distinguish carefully in an interview:

- **Implemented:** MCP-Shield's fingerprint (exact HMAC — not ML), sanitizer
  (regex lists), VectorAnchor's frequency-anomaly detector (greedy clustering over
  query embeddings — repeatable), TraceAudit's divergence monitor (rolling KL
  divergence vs a captured baseline distribution — statistical, not learned) and
  PII scanner (regex + Luhn).
- **Implied but not implemented:** no model training, no learned thresholds (all
  thresholds calibrated empirically from fixtures), no neural network anywhere in
  the detection path.
- **Model usage:** *optional* — TraceAudit can proxy a real Ollama model
  (`MONOLITH_MODEL_BACKEND=ollama`) and VectorAnchor can use Chroma's
  sentence-transformers (`MONOLITH_EMBEDDING=default`); the default
  repeatable backends (mock model, hash embedder) are the repeatable demo
  path.
- **RAG:** VectorAnchor is a RAG *retrieval* layer (ChromaDB + embeddings) with a
  poisoning detector bolted in front.
- **Guardrails:** the divergence termination and PII redaction are the guardrail
  mechanisms; they run on every token.
- **Evaluation:** labelled corpora per module → evaluation table of correct and incorrect detections per detector →
  persisted to the ledger → dashboard. The imperfect numbers are intentional
  (sanitizer recall 71.4%, VectorAnchor detection 75%) — see §25.

**The three detectors, precisely:**

1. **MCP-Shield fingerprint** — `canonicalize()` (recursive key-sorted
   serialization) → HMAC-SHA256. Exact by construction: 100% mutation detection, 0%
   false flags — it cannot be "tuned", and the dashboard labels it `exact` rather
   than pretending it is learned.
2. **VectorAnchor frequency anomaly** — per document, keep the query embeddings
   for which the doc ranked in the top-2 (`top_rank_threshold`), capped at 8
   (`max_queries_per_doc`) with **redundancy-based eviction** (drop the retained hit
   the newest one most duplicates — a same-topic flood evicts itself), within a
   500-query horizon (`retention_horizon`). Score = number of greedy clusters of
   mutually dissimilar queries (cosine < `topic_similarity` 0.20). Threshold:
   `min_distinct_topics` 4. This detector is deliberately *not* raw frequency — a
   doc ranking for many queries on one topic is legitimate; ranking across many
   *dissimilar* topics is the poison signature.
3. **TraceAudit divergence monitor** — rolling window of 20 normalized tokens;
   Laplace-smoothed live distribution `p` vs smoothed baseline `q` over the fixed
   vocabulary (baseline tokens + `<other>`); KL threshold 1.0 calibrated in the gap
   between the worst benign peak (0.481) and the divergent fixture (3.29). Tokens
   outside the baseline vocab collapse into `<other>` with near-zero baseline mass,
   which is what makes very different from normal behavior reasoning spike the KL.

---

## 15. External Services

See §13 for the table. The only *required* external service is PostgreSQL (can be
local). Everything else is optional and local: Ollama, Chroma's embedder, the
webhook receiver, Supabase Auth for OIDC. The stack runs fully offline with zero
model downloads on the default profile.

---

## 16. Important Dependencies

**Core framework:** Next.js 16 / React 19.2 (dashboard); FastAPI (both Python
modules); Tokio + Rust 1.86 (MCP-Shield).

**Database:** `pg` (Node driver with parameterized queries), raw SQL; ChromaDB
(Python, embedded PersistentClient); SQLite (stdlib, WAL outboxes).

**Auth:** `jose` (JWT verification, JWKS fetching), Node `crypto` (timingSafeEqual,
HMAC, SHA-256).

**Networking:** `reqwest` with rustls (MCP-Shield outbox + HTTP transport); `httpx`
(lazy, Ollama backend); `urllib` (stdlib, Python outboxes).

**Serialization/validation:** `serde`/`serde_json` (Rust); Pydantic v2 (FastAPI
request models, `extra="forbid"`); JSON Schema 2020-12 + `jsonschema` (contract
gate); TypeScript types shared across dashboard lib/routes.

**AI/ML:** none in the detection path; `chromadb` for the store; optional
sentence-transformers via Chroma's DefaultEmbeddingFunction.

**UI:** `recharts` (charts on the overview/benchmarks pages), hand-rolled CSS
(no component library — dark-theme-first glassmorphism with CSS variables).

**Testing/dev:** pytest, mypy, ruff, cargo fmt/clippy/test, ESLint, `tsx` test
runner, `cargo-audit`, npm audit, CodeQL.

**Deployment:** Docker Compose with healthchecks; the `supabase/postgres` image.

---

## 17. Environment & Configuration

Full contract in `.env.example` (deliberately **no placeholder values** — a fake
value shaped like a password is indistinguishable from a real one to a secret
scanner). `scripts/generate_secrets.sh` writes 8 random values (24 CSPRNG bytes
each).

| Variable | Purpose | Required |
|---|---|---|
| `MONOLITH_POSTGRES_PASSWORD` | DB superuser password (baked at volume init) | yes |
| `MONOLITH_DATABASE_RUNTIME_PASSWORD` | dashboard runtime login password | yes |
| `MONOLITH_EVENT_TOKEN_MCP_SHIELD` / `_VECTOR_ANCHOR` / `_TRACE_AUDIT` | per-module ingest tokens | yes |
| `MCP_SHIELD_KEY` | HMAC key for baseline fingerprints; rotation invalidates the baseline | yes |
| `MONOLITH_TENANT_ID` | tenant boundary stamped on events/sessions | yes (default "default") |
| `MONOLITH_ADMIN_TOKEN` | VectorAnchor/TraceAudit admin routes | yes |
| `MONOLITH_OPERATOR_NAME` / `MONOLITH_OPERATOR_TOKEN` | operator bootstrap credential + audit actor name | yes |
| `MONOLITH_DISABLE_AUTH` | exactly `"true"` disables sign-in (demo only) | no (default false) |
| `OPERATOR_TRUST_PROXY_HEADERS` | use X-Forwarded-For for login rate limiting | no (false) |
| `OPERATOR_SESSION_TTL_SECONDS` | session lifetime, clamped 5m–24h | no (8h) |
| `OPERATOR_COOKIE_SECURE` | force/disable Secure cookie | no (auto) |
| `OPERATOR_OIDC_ISSUER` / `_AUDIENCE` / `_JWKS_URL` | OIDC/Supabase Auth (all three or none) | no |
| `OPERATOR_OIDC_REQUIRE_MFA` | require `aal=aal2` | no (true) |
| `OPERATOR_OIDC_DEFAULT_TENANT` | fallback tenant for JWTs without the claim | no |
| `MONOLITH_ALERT_WEBHOOK_URL` / `_SECRET` | critical webhook (both or none; HTTPS or loopback HTTP) | no |
| `MONOLITH_MODULE_ADMIN_TOKEN` | dashboard→module `/stats` health checks | yes (in compose) |
| Module-side: `MONOLITH_DASHBOARD_URL`, `MONOLITH_EVENT_TOKEN`, `MONOLITH_EVENT_OUTBOX_PATH`, `MONOLITH_AGENT_ID`, `MONOLITH_SESSION_ID` | delivery config | depends |
| VectorAnchor: `MONOLITH_EMBEDDING`, `MONOLITH_CHROMA_PATH`, `MONOLITH_DETECTOR_STATE_PATH`, `MONOLITH_TOP_K`, `MONOLITH_CANDIDATE_BUFFER`, `MONOLITH_TOP_RANK_THRESHOLD`, `MONOLITH_MIN_DISTINCT_TOPICS`, `MONOLITH_TOPIC_SIMILARITY`, `MONOLITH_RETENTION_HORIZON`, `MONOLITH_MAX_QUERIES_PER_DOC`, `MONOLITH_EMBEDDING_DIM`, `MONOLITH_COLLECTION` | detector + store tuning | no (calibrated defaults) |
| TraceAudit: `MONOLITH_MODEL_BACKEND`, `MONOLITH_OLLAMA_URL`, `MONOLITH_OLLAMA_MODEL`, `MONOLITH_BASELINE_PATH`, `MONOLITH_KL_THRESHOLD`, `MONOLITH_TA_WINDOW`, `MONOLITH_MIN_TOKENS`, `MONOLITH_SMOOTHING`, `MONOLITH_MAX_TOKENS` | backend + divergence tuning | no (calibrated defaults) |
| MCP-Shield: `MCP_SHIELD_MODE`, `MCP_SHIELD_BASELINE`, `MCP_SHIELD_FIRST_CONTACT`, `MCP_SHIELD_REMOTE_TOKEN`, `MCP_SHIELD_PROTOCOL_VERSION`, `MCP_SHIELD_REMOTE_TIMEOUT_SECS` | proxy behavior | no |
| Dashboard: `DATABASE_URL`, `DATABASE_APP_ROLE`, `EVENT_INGEST_TOKENS_JSON`, `OPERATOR_TOKENS_JSON`, `VECTOR_ANCHOR_INTERNAL_URL`, `TRACE_AUDIT_INTERNAL_URL`, `DATABASE_MIGRATIONS_DIR` | wiring | yes (in compose) |

**To run the project someone needs:** Docker with Compose (or local PostgreSQL 17 +
Python 3.12 + Node 22 + Rust), Bash, curl, and a generated `.env`. No external
accounts required for the demo.

---

## 18. Deployment Architecture

**Local/CI (the only supported deployment):** `docker compose up -d --build
--wait` builds five images (dashboard, vector-anchor, trace-audit, mcp-shield, plus
the shared dashboard image reused for migrator and alert-dispatcher) with strict
startup ordering: database healthy → bootstrap completes → migrator completes →
dashboard healthy → the three modules start (so no `service_start` event is
dropped). Read-only root filesystems, no-new-privileges, tmpfs /tmp, mem/pids
limits, named volumes for Postgres data, Chroma state, outboxes, and detector
state.

**Production-readiness gaps (honest):** no Helm/k8s manifests, no Terraform, no
managed Postgres wiring beyond the Supabase-compatible image, no TLS termination in
Compose (the dashboard binds 127.0.0.1), no log aggregation, no metrics/alerting
beyond the optional webhook, no horizontal autoscaling story. The auth model,
though, is designed with real production ideas in mind (OIDC adapter, minimum required permissions DB role, RLS) — the
*identity* layer was built for a real target even though the *deployment* layer is
demo-grade.

---

## 19. Resource Consumption

- **Compute:** trivial. Detectors are microseconds: MCP-Shield ~6.4 µs/tool,
  TraceAudit ~13 µs/token, VectorAnchor ~439 µs/retrieval (measured, single
  machine). No GPU anywhere.
- **Memory:** ChromaDB (embedded, loaded corpus) is the biggest resident consumer
  (vector-anchor gets 1 GB limit); Postgres shared buffers; Next.js Node processes
  (512 MB limit); the outbox SQLite handles are small. `max_queries_per_doc=8`
  bounds detector memory per document.
- **Network:** module→dashboard HTTP (event delivery), dashboard→module `/stats`
  health checks, Postgres LISTEN/NOTIFY, SSE to browsers, optional webhook + JWKS
  fetches. All loopback/local in the demo.
- **Storage:** Postgres volume (events grow; pruned at 90 days), Chroma volume,
  outbox volumes (bounded: 10k records JSONL, 10k pending / 2k dead SQLite),
  detector state (32 MiB cap).
- **AI tokens:** only with the optional Ollama backend — each `/generate` prompt is
  forwarded to the model; the mock costs nothing.
- **External API costs:** zero in the default demo.

**What gets expensive first:** the Postgres event ledger (write amplification on
the GIN indexes + `to_tsvector` search; unbounded growth without the maintenance
prune) and — at higher agent volumes — the per-request detector work on
VectorAnchor (clustering is quadratic per document, capped by
`max_queries_per_doc`). SSE connections and the in-process broker are cheap until
thousands of concurrent dashboards, at which point Postgres LISTEN/NOTIFY distribution to multiple listeners
and broker memory become the constraint.

---

## 20. Feasibility

Ratings (1–10, honest):

| Dimension | Score | Why |
|---|---|---|
| Technical feasibility | **9** | Everything is implemented, tested, and demoed end-to-end; CI runs the full stack. The mock-backend default is what makes it feasible offline. |
| Maintainability | **7** | Small, focused modules with excellent comments and tests; but the event contract is duplicated in four languages and the Python `events.py` is vendored twice instead of imported. |
| Scalability | **5** | Single-node by design; Postgres ledger + in-process broker bound horizontal scale; no queue, no partitioning story. |
| Reliability | **8** | Durable outboxes, failed-event storageing, safe retry behavior without duplicates, save-before-show, RLS, can be added to but not silently rewritten triggers — genuinely strong for a demo. Single points of failure (one Postgres, one dashboard) keep it from higher. |
| Security | **8** | Remarkably deliberate: minimum required permissions DB role, RLS + app predicates, timing-safe comparisons, no default creds, strict validation, can be added to but not silently rewritten audit. Gaps: ingest is unthrottled, `/retrieve` + `/generate` have no auth (documented as trusted-network), no TLS in compose. |
| Performance | **8** | Microsecond detectors, measured and documented; the VectorAnchor clustering is the hot path and was optimized (unit_dot). |
| Cost efficiency | **9** | Runs on one machine, no paid services, no model downloads by default. |
| Production readiness | **4** | The *security model* is designed with real production ideas in mind but the *deployment* is a demo: no HA, no TLS termination, no observability stack, single maintainer, synthetic corpora only. |

---

## 21. Scalability

- **10 users / 1 agent:** nothing to worry about. Everything fits in one Postgres
  and one dashboard.
- **100 users / 100 agents:** the ledger grows; the incident queue queries (GIN
  search, `to_tsvector`) start to show; SSE per-browser connections are fine. The
  outboxes batch at 16 rows/pass — fine. Keep the maintenance prune running.
- **1,000 agents:** VectorAnchor becomes the hot path (per-retrieval clustering
  × QPS); one Postgres is still OK for a security-event rate of a few thousand
  events/hour. The dashboard's in-process broker + one LISTEN connection per
  instance is fine; the incident search may need a dedicated FTS index strategy.
- **10,000 agents:** Postgres write throughput and the `details` GIN index become
  the bottleneck; the single Next.js dashboard instance (its 8-connection pool)
  saturates; LISTEN/NOTIFY payload churn grows; the in-process broker's memory
  (ring buffer) needs sharding. The modules' local outboxes would need real
  partitioning or a queue.
- **100,000 agents:** the architecture as designed breaks. The ledger must become
  partitioned/time-series (ClickHouse/TimescaleDB), delivery must move to a real
  queue (Kafka/NATS) with the outboxes as edge buffers, the dashboard must be
  horizontally scaled behind a load balancer with Redis/Postgres pub-sub for
  distribution to multiple listeners, and the frequency tracker's per-document state would need sharding by
  tenant/doc-id. MCP-Shield's JSONL spool with a single resident drainer would
  also become a bottleneck (multiple drainers already supported via file locks,
  but not exercised).

**What breaks first:** Postgres (write + search), then the single dashboard pool,
then the in-process broker. The detectors themselves are cheap enough to survive
long past the delivery layer.

---

## 22. Failure Modes

| Failure | Current behavior | Sufficient? |
|---|---|---|
| Dashboard down | Modules spool to outbox; drain on restart; recovery test proves it | Yes — the flagship property |
| Module outbox disk full | `enqueue` fails; error logged; event still on stderr; no crash | Acceptable (documented) |
| Permanent rejection (401/403/413/422) | Dead-lettered immediately, never retried | Yes |
| Non-UUID `event_id` | 422 (poison-pill fix) — prevents infinite 503 retry loops | Yes |
| Postgres down | Ingest returns 503 → modules retry with retry delay; SSE history unavailable (error frame) | Yes for ingest; SSE degrades gracefully |
| LLM/Ollama down | TraceAudit stream errors out via httpx exception; no events emitted for the failed generation | Acceptable — it is optional |
| ChromaDB corruption | Detector state file unreadable → quarantined aside (never deleted), service starts empty | Yes |
| Baseline file tampered | HMAC verification fails at load → startup fails closed | Yes |
| Operator auth misconfigured | 503 on every route (fail closed) — never a silent pass | Yes |
| Login brute force | 8 attempts/15 min per IP (Postgres-backed), constant-time token compare | Good for demo; per-IP only |
| Cross-tenant access attempt | App predicates + RLS double-check; missing context matches no tenant | Yes |
| Concurrent review and handle on one event | `pg_advisory_xact_lock` serializes writers | Yes |
| MCP-Shield child crash | Proxy sees stdout close, reaps child, exits; events already spooled | Acceptable |
| MCP unparseable line | Forwarded unmodified with a warning (transparency invariant) | Yes |
| Detector internal error | Fail-open: forward unmodified, emit `analysis_error` at error level | Yes |
| Webhook receiver down | alert_outbox retry delay, failed-event storage after 10 attempts | Yes |
| Race: SSE replay vs live event | Subscribe-before-replay + client-side event_id dedupe | Yes |
| Memory leak risk | Broker bounded by 2,048-event dedupe set; outbox bounded; detector state capped | Yes |
| Corrupted JSONL tail (power loss) | Torn line skipped, rest readable | Yes |
| Two migrators | Advisory lock | Yes |

---

## 23. Security Model

Four non-interchangeable types of identities (the project's central security idea):

1. **Detection modules** — per-tenant, per-module access token; scope: ingest only.
   A module token cannot close its own findings (review and handle requires an operator token).
2. **Human operators** — bootstrap token → revocable, expiring, HttpOnly,
   SameSite=Strict session cookie; role viewer/analyst/admin; tenant from
   credential config, never from the request body.
3. **Federated operators** — OIDC/Supabase JWT (RS256/ES256/EdDSA, issuer +
   audience + expiry + `aal2` if required), with explicit `monolith_role` and
   `monolith_tenant_id` claims.
4. **Dashboard runtime** — `monolith_runtime` login → `SET ROLE monolith_app`
   (NOLOGIN, NOBYPASSRLS); only the SQL verbs needed; event/audit ledgers have no
   UPDATE/DELETE grants; can be added to but not silently rewritten enforced by trigger too.

**Other controls:** token comparison via SHA-256 + `timingSafeEqual` (all entries
compared, no early exit); strict request-body byte caps; Pydantic `extra="forbid"`
and `additionalProperties: false` in the schema; same-origin check (`Sec-Fetch-Site`
+ Origin) for session-authenticated mutations (CSRF defense); login rate limiting;
event text fields constrained to printable characters (no control chars → no
injection into logs/SSE); UUID-pattern validation on all event ids; details GIN
index is safe (parameterized queries throughout, no string-built SQL except
internally-computed predicates with bound params); secrets never in the browser
(the bootstrap token is only ever in the login form body); module telemetry hashes
query text and document text rather than copying it into the ledger (PII hygiene);
TraceAudit redacts *before* any log or event is written.

**Known boundaries (documented, intentional):** `/retrieve` and `/generate` are
unauthenticated service-to-service interfaces intended for a trusted network —
their `X-Monolith-*` headers are attribution, not auth; ingest is not
rate-limited; the demo escape hatch `MONOLITH_DISABLE_AUTH=true` exists and is
build-time-baked; MCP-Shield's HMAC key defaults to a public dev key with a loud
warning; the mock model and hash embedder are dev-only.

**Prompt injection:** the entire point of the tool layer — MCP-Shield's sanitizer
and first-contact gate are the defense; the project itself documents that
first-contact poisoning beyond the sanitizer corpus is a trust-on-first-use
limitation unless `approve` mode is used.

---

## 24. Technical Debt / Vibe-Coded Areas

**Duplication that is deliberate but still smells:**
- The event contract lives in Rust (`events.rs`), Python (`events.py`), TypeScript
  (`types.ts`), and JSON Schema. The JSON Schema + `check_contracts.py` gate keeps
  them honest, but a single source (e.g. a generated schema) would be cleaner.
- `vector-anchor/src/events.py` and `trace-audit/src/events.py` are vendored copies
  of `python-common/monolith_events/events.py`. The README claims "no shared
  library", but `python-common` exists — the copies keep each module runnable
  standalone. If they drift, the CI python-common job won't catch it (it only tests
  the shared package itself).

**Leftover college artifacts:** `AEOS_Guard_*.pdf`, `build_aeos_pdf.py`,
`build_aeos_report.py`, `video/`, and committed build outputs
(`dashboard/node_modules`, `mcp-shield/target/`, `.mypy_cache/` etc. — visible in
`git status`). These should be gitignored/removed; in an interview, don't claim
them.

**Mild overengineering in places:** the per-module `verify_*.sh` suites and the
EVALUATION.md culture are genuinely good, but some code is *very* defensive for a
demo (e.g. the Rust UUID generation built from SHA-256 of pid+nanos+counter+stack
address to avoid a `uuid` dependency — clever, but a `uuid` crate would be simpler
and more obviously correct). The `--drain-outbox` resident worker + drain-on-startup
+ force-drain-on-exit is three mechanisms for one job — justified by the
short-lived-process reality, but complex.

**What SHOULD be restructured (if this were a product):**
1. Single main trusted copy of the data for the event schema (JSON Schema → generated bindings
   for Rust/Python/TS).
2. Import `python-common` properly in both Python modules (it already exists!).
3. A real message queue when the outbox fan-in exceeds one Postgres.
4. Separate the "detector" packages from the "service" packages so the pure
   detectors are pip-installable libraries with their own versions.
5. Move `prune_security_events`/session GC into a scheduled job rather than
   maintenance functions + opportunistic deletes.
6. Gitignore/build-clean the artifacts above.

**Naming:** `normalizeEvent` defaults *absent* optional fields but rejects *invalid*
ones — the name undersells the strictness. `event-ingest.ts` (the broker) vs
`event-store.ts` (the persistence) is easy to confuse. `KNOWN_MODULES` is
duplicated across `types.ts`, `ingest-auth`, `event-store`, `incident-store`, and
`benchmark-store` — a shared constant module would be better.

---

## 25. What Is Actually Technically Impressive

**Real engineering complexity (yours to claim):**
- **The delivery spine.** Durable local outboxes with fsync-before-continue,
  permanent-vs-transient classification, increasing wait times between retries with jitter, bounded
  dead letters, safe to retry without creating duplicates redelivery keyed on `event_id`, drain-on-startup +
  force-drain-on-exit for a short-lived process, and a resident drainer on a shared
  volume with inter-process file locking. This is a mini at-least-once messaging
  system built from scratch, and it is tested (verify_outbox, verify_recovery).
- **Save-before-show + LISTEN/NOTIFY.** The live feed is a view over durable
  history; multiple dashboard instances stay in sync through Postgres pub-sub; SSE
  clients resume from `Last-Event-ID` with dedupe. The subscribe-before-replay
  ordering trick is subtle and correct.
- **The VectorAnchor retention design.** Separating the detection horizon
  (`retention_horizon`) from the memory/cost bound (`max_queries_per_doc`) — with
  redundancy-based eviction that makes a same-topic flood evict *itself* — is a
  genuinely thought-through adversarial-memory design, backed by measured cost
  data (10× horizon for 1.5× cost; the `unit_dot` optimization).
- **Calibrated thresholds with honest numbers.** The KL threshold derivation
  (mean+2σ sits *at* the benign max, so 1.0 is chosen in the gap), the
  corpus-breadth finding (a bigger corpus broke a bait and that is correct
  behavior), the false-positive sweeps — this is evaluation culture most
  production teams lack. And the below-100% scores are kept on purpose.
- **The trust model.** Four types of identities, no interchangeable credentials,
  derived-not-declared actors, can be added to but not silently rewritten enforced twice (grants + trigger),
  database RLS + application-level checks as independent bounds, `SET ROLE` privilege
  shedding, the poison-pill 422 fix. This reads like someone who actually thought
  about security, not a checklist.
- **Cross-layer correlation as a first-class query.** The session view and
  `count(distinct module) > 1` "compromised agent" signal is the payoff of the
  whole architecture, and the demo asserts it.

**Things that sound complicated but are mostly library/framework functionality
(don't oversell):**
- SSE streaming — that's `ReadableStream` + `text/event-stream`; the interesting
  part is the ordering/dedupe, not the streaming itself.
- ChromaDB retrieval — the interesting part is the *detector in front of it*, not
  the vector search.
- JWT validation — that's `jose`; the interesting part is the claim mapping and
  the fail-closed posture.
- Next.js App Router routes — standard; the interesting part is the ingest
  pipeline ordering.
- The "AI" parts — there is **no trained model anywhere**; the detectors are
  exact hashing, regex, clustering, and a statistical divergence measure. Say that
  plainly; it is more credible than implying ML.

---

## 26. What I Would Improve

1. **Single event-schema source** — generate Rust/Python/TS types from the JSON
   Schema so the contract cannot drift.
2. **Properly share python-common** — import it instead of vendoring copies.
3. **Authenticate the agent-facing endpoints** (`/retrieve`, `/generate`) with
   service tokens when moving past a trusted network; add ingest rate limiting.
4. **Horizontal scale:** move outbox fan-in behind a queue; partition the event
   table by time; shard the dashboard behind a load balancer with a shared
   pub/sub.
5. **Observability:** structured log shipping, OpenTelemetry spans for the ingest
   pipeline, alerting on failed-event storage growth (the ops page already shows it).
6. **Production deployment:** TLS termination, managed Postgres, backup/restore
   drill, HA for the dashboard + DB.
7. **Real-backend validation:** actually run the `real` profile (Ollama +
   sentence-transformers) and report numbers instead of NOT MEASURED.
8. **Clean the repo:** remove the college PDFs/builders and gitignore the build
   outputs.
9. **Extend the tool layer** to inspect `resources/read`, prompt payloads, and
   `sampling/createMessage` — currently only catalog text and tool results are
   inspected.
10. **Benchmark the ingest path** (events/sec through the dashboard) and the SSE
    distribution to multiple listeners at N subscribers.

---

## 27. Technical Concepts I Need to Study

You do not need to memorize textbook definitions first. Focus on what each concept does inside Black Monolith and why the project needs it.

**Must know** (you will be asked about these):
- **At-least-once delivery + safe retry behavior without duplicates** — why the outboxes, why `event_id` as
  PK with `on conflict do nothing`, why 5xx-retry vs 4xx-failed-event storage.
- **RLS and minimum required permissions DB roles** — `SET ROLE`, NOLOGIN group roles, grants,
  why the app role cannot UPDATE the ledger.
- **SSE vs WebSockets** — why SSE was chosen (one-way server push, HTTP reuse,
  Last-Event-ID), how replay-before-stream works.
- **Postgres LISTEN/NOTIFY** — how multi-instance distribution to multiple listeners works, its limits
  (payload size, no persistence — which is why the broker reloads events from the
  DB).
- **KL divergence** — what it measures, Laplace smoothing, the `<other>` bucket,
  why very different from normal behavior tokens spike it.
- **Cosine similarity / embeddings** — bag-of-words hashing, normalization, why
  `unit_dot` equals cosine on normalized vectors.
- **The MCP protocol** — JSON-RPC 2.0 over stdio, `tools/list`, why stdout purity
  matters for a transparent proxy.

**Should know:**
- **Transaction-local settings** (`set_config(..., true)`) and why pooled
  connections can't leak tenant context.
- **Exponential retry delay with jitter** and retry storms.
- **Timing-safe comparison** and why naive `==` leaks.
- **Advisory locks** (`pg_advisory_xact_lock`) for serializing one row's writers
  without expanding table privileges.
- **Confusion matrix metrics** — precision/recall/F1/FPR, and why detection rate
  (recall) is the headline here.
- **OIDC/JWT flows** — JWKS, audience/issuer, `aal`/AAL2, asymmetric signatures.

**Nice to know:**
- Rust async (Tokio) basics — why the proxy uses two spawned tasks for the two
  directions, `JoinSet` in the HTTP bridge.
- ChromaDB internals (PersistentClient, HNSW) and why a second client on the same
  path contends on SQLite.
- HMAC vs plain hash and why keyed hashing resists baseline-file forgery.
- Docker Compose healthchecks and startup ordering (`service_completed_successfully`
  vs `service_healthy`).
- Unicode bidi/zero-width characters and why they're an injection vector.

---

## 28. Interview Questions

### Basic
1. What does Project Black Monolith do, in one paragraph?
2. What are the four components and what does each protect?
3. What is the shared event envelope and why does it exist?
4. How do the three modules get their events to the dashboard?
5. What is a "rug pull" in the MCP context and how does MCP-Shield stop it?
6. What is a "bait" document and how does VectorAnchor detect it?
7. What does TraceAudit do when it detects divergence or PII?
8. How do I run the project? What services come up?
9. What database does the dashboard use and where do events live?
10. What do the benchmark numbers mean (75%, 71.4%, 100%)?

### Intermediate
1. Why does each module have its own outbox instead of sending events directly?
2. What makes event redelivery safe to retry without creating duplicates?
3. Why is the baseline never overwritten on a schema mismatch?
4. How does enforce mode differ from monitor mode? When would you use each?
5. How does VectorAnchor's eviction policy prevent an attacker from flushing a
   bait's earned topics?
6. Why is `retention_horizon` separate from `max_queries_per_doc`?
7. How does the SSE endpoint guarantee no events are missed between replay and live?
8. What does "persist before publish" mean and why does it matter?
9. How is separation between different users or organizations enforced? Name two independent mechanisms.
10. How does the dashboard know the actor of a review and handle change? Why not read it from
    the request?
11. What happens to a critical event when the webhook receiver is down?
12. Why are benchmark results not stored as security events?
13. How is the operator's bootstrap token different from the session cookie?
14. What is the `<other>` bucket in the KL monitor and why does it exist?

### Difficult
1. Trace the full path of one detection event from the detector firing to a
   browser showing it. Name every hop and every durability guarantee.
2. A module's outbox POSTs an event with a non-UUID `event_id`. What happens, and
   what *would* have happened before the fix?
3. What breaks if two dashboard instances run? What doesn't? (Think broker vs
   LISTEN/NOTIFY.)
4. The incident queue must not let an unreview and handled event disappear. How is "open"
   implemented and why is that a deliberate design choice?
5. VectorAnchor: why does the newest-hit-most-duplicates eviction beat
   oldest-first? Construct the attack each one defends against.
6. How would you scale the event ledger to 100k events/sec? What parts of the
   current design survive and what must change?
7. If a module's clock is wrong, what data is corrupted and what is not?
   (`timestamp_ms` vs `received_at`.)
8. Why is the MCP proxy's fail-open policy correct? What would fail-closed cost?
9. How does the login rate limiter work across multiple dashboard instances?
10. The app role cannot DELETE security events, yet retention exists. Who prunes,
    and what's the privilege boundary?
11. What is the trust-on-first-use problem for the fingerprint, and what are the
    two mitigations? What remains?
12. How would you add a fourth module (e.g. a network-layer detector) to this
    system? List every place that must change.

---

## 29. Model Interview Answers

**Q: What does Project Black Monolith do?**
"It's defense-in-depth security middleware for AI agents. Agents have three
independent places where attacks can happen — the tools they call, the stored knowledge or memory they read,
and their live model output — and I built a small independent detector for each
one: MCP-Shield fingerprints tool schemas to catch rug-pull mutations and scans
descriptions for hidden instructions; VectorAnchor watches a vector store for
documents that rank across many unrelated topics, which is the signature of a
poisoned corpus; TraceAudit sits in front of a model's token stream and terminates
it if the reasoning distribution drifts, and redacts credentials or PII before
they're released. All three emit events in one shared JSON format through durable
local outboxes into a Postgres-backed dashboard where an operator investigates and
review and handle decisions are can be added to but not silently rewritten. Everything is defensible — the detectors are
calibrated against labelled corpora and the scores are published, including the
imperfect ones."

**Q: Why no shared library between the modules?**
"I wanted each layer to be independently deployable and testable — they have very
different needs, so MCP-Shield is Rust for byte-exact proxying, and the other two
are FastAPI. A shared library would have coupled them. The cost is that the event
contract exists in several places, which I keep honest with a JSON Schema contract
gate in CI. In hindsight, importing the shared Python outbox package instead of
vendoring copies would have been cleaner."

**Q: Why the local outbox instead of just POSTing?**
"Because a detection that gets lost is a defense that lied. The dashboard can be
down during an attack, so each module writes the event to a durable local store
first — fsynced before the detection path continues — and a worker delivers it
with retry delay. Permanent rejections failed-event storage so nothing is silently dropped, and
the event's UUID makes redelivery safe to retry without creating duplicates. The recovery test proves it: with
the dashboard stopped, events spool; on restart they drain into the ledger."

**Q: How does the SSE live feed not lose events between replay and live?**
"Subscribe to the in-process broker first, then replay the committed ledger rows,
then switch to live. Any event committed during the replay query is both in the
query result and buffered from the broker — the client dedupes by event_id, so
nothing is missed and nothing duplicates. I also sort by receive time after
dedupe, because a just-committed live event can arrive before older replay
frames."

**Q: How does VectorAnchor actually decide a document is poison?**
"It's not raw frequency — a document that ranks for many queries on one topic is
legitimate. I track, per document, the query embeddings it ranked top-2 for, and
greedily cluster them by similarity. A doc that ranks across four mutually
dissimilar clusters is the universal-bait signature. The interesting knob is
retention: I keep a 500-query horizon but cap retained hits per document at 8, so
the detection reach and the memory cost are separate knobs — that's what makes a
slow-drip attacker pay ~500 covering retrievals per hidden topic instead of ~50.
And the eviction drops whichever retained hit the newest one most duplicates, so a
flood of similar queries evicts itself rather than flushing a bait's earned
topics."

**Q: Why is the KL threshold 1.0 and not mean+2σ?**
"The textbook 2σ cut landed at 0.47, which is basically the worst benign peak —
0.481 — so it would false-positive. The calibration fixture's divergent trace hits
3.29. So I set the threshold in the gap, at 1.0: about 2× the worst benign and a
third of the divergent. I should be honest that the baseline was calibrated
against the offline mock backend, so a real model would need recalibration — the
repo says exactly that."

**Q: What would you change if you had to scale it?**
"The detector layer would survive — it's microseconds per event. The delivery
spine would not: one Postgres ledger and one in-process broker are the limits. I'd
move the outbox fan-in behind a real queue, partition the event table by time, and
shard the dashboard horizontally with a shared pub/sub. Honestly, the current
design is a rigorous single-node system — the security model is designed with real production ideas in mind,
the deployment is a demo, and I'd expect to rework the plumbing before claiming
production scale."

**Q: What are the benchmark numbers, and why aren't they all 100%?**
"Each detector is scored on a labelled corpus into a evaluation table of correct and incorrect detections, persisted
to the ledger and shown on the dashboard. The fingerprint is 100% *by
construction* — it's an exact HMAC comparison, so it's labeled as exact, not as a
tuned detector. The sanitizer is 71.4% recall because it's pattern-based — it's
precise on look-alikes but misses novel injection phrasings with no known marker;
the corpus deliberately retains those misses. VectorAnchor is 75% because one of
the four bait fixtures is engineered to be too subtle to rank broadly enough. The
imperfect numbers are the honest ones — the point of the benchmark is to measure,
not to flatter."

---

## 30. The 20 Things I Cannot Go Into an Interview Without Knowing

1. **The elevator pitch:** three independent inline detectors (tool/memory/
   reasoning) + a dashboard, unified by one event contract.
2. **The event envelope:** `{event_id (UUID v4), schema_version: 2, timestamp_ms,
   module, event_type, severity (info|warning|critical), details, source,
   tenant_id}` + optional correlation fields. AdditionalProperties false.
3. **Delivery spine:** reliable local event storage (SQLite WAL for Python, JSONL for
   Rust) → authenticated POST /api/ingest → retry with retry delay → failed-event storage on
   permanent rejection → safe to retry without creating duplicates via `on conflict (event_id) do nothing`.
4. **The ingest pipeline order:** authenticate (per-tenant, per-module access-token,
   timingSafeEqual) → strictly validate (reject, don't coerce) → persist to
   Postgres → publish to SSE. Save-before-show is the invariant.
5. **Poison-pill fix:** a non-UUID `event_id` is a permanent 422 because a
   Postgres `uuid` column would have rejected it with 22P02 → 503 → infinite
   retry.
6. **Live feed mechanics:** Postgres LISTEN/NOTIFY → per-instance listener loads
   the event → in-process broker → SSE replay-then-stream with Last-Event-ID and
   event_id dedupe.
7. **MCP-Shield mechanics:** transparent byte-for-byte stdio proxy; only
   `tools/list` responses are analyzed (correlated by request id); stdout is
   protocol-only, everything else on stderr; fail-open on detector errors.
8. **Fingerprint:** canonical key-sorted serialization → HMAC-SHA256; baseline
   never overwritten on mismatch (repeat servings re-flag); baseline file
   authenticated on load (tamper = fail closed); atomic save.
9. **Enforce vs monitor vs first-contact:** enforce rewrites mutated schemas back
   to the baseline; monitor logs and forwards; `first_contact=approve` withholds
   unseen tools until `--approve`.
10. **VectorAnchor detector:** per-doc query-embedding history, greedy
    dissimilar-topic clustering, threshold 4, `retention_horizon=500` +
    `max_queries_per_doc=8` as separate knobs, redundancy-based eviction.
11. **VectorAnchor defaults:** hash bag-of-words embedder (256-dim, repeatable,
    offline); `MONOLITH_EMBEDDING=default` switches to sentence-transformers;
    quarantine serves next-best clean result; detector state persisted atomically.
12. **TraceAudit detector:** rolling 20-token window, Laplace-smoothed KL vs a
    captured baseline, `<other>` bucket for OOV tokens, threshold 1.0
    (calibrated), terminate + safe refusal on breach.
13. **PII redaction:** 6 regex families + Luhn check; 16-token bounded look-behind
    so token-split secrets are caught before release; redact before forward/log/
    event; SHA-256 dedupe of reported secrets.
14. **Backends:** mock model (repeatable, prompt-seeded via hashlib — the
    PYTHONHASHSEED bug and fix) and hash embedder by default; Ollama and
    sentence-transformers optional; `real` profile is NOT MEASURED until run.
15. **DB layout:** `monolith` schema in the `postgres` database; tables
    security_events / incident_review and handle / incident_audit / benchmark_runs /
    operator_sessions / operator_login_limits / alert_outbox; the 42501 schema
    ownership story.
16. **Trust model:** four types of identities (module token / operator token + session
    / OIDC JWT / monolith_app DB role); actors derived from credentials, never the
    body; audit trail can be added to but not silently rewritten by grants *and* trigger.
17. **Tenant isolation:** app predicates + transaction-local RLS context
    (`set_config(..., true)`), independently; pooled connections can't leak
    context.
18. **Triage:** lazy review and handle rows (unreview and handled = "new" synthesized on read), resolve
    requires a verdict, omitted fields never clear, reopen clears resolution,
    advisory lock serializes writers, audit row written in the same transaction.
19. **Benchmarks:** evaluation table of correct and incorrect detections persisted per (run, module, detector);
    metrics recomputed server-side (a lying client can't store a lying rate);
    benchmark rows never enter the event ledger; observed precision from analyst
    verdicts shown alongside lab accuracy.
20. **The honest numbers:** detection overhead ~6.4 µs/tool, ~13 µs/token,
    ~439 µs/retrieval; sanitizer recall 71.4%, VectorAnchor 75%, fingerprint 100%
    by construction; known evasions built and tested (slow drip repriced 10×,
    token-boundary split closed within the 16-token window).

---

## 31. 30-Second Explanation

"Project Black Monolith is security middleware for AI agents. Agents have three
places where attacks can happen — their tools, their stored knowledge or memory, and their reasoning — so I
built three small detectors, one per layer. MCP-Shield is a Rust proxy that
fingerprints tool schemas and catches them being swapped for poisoned versions.
VectorAnchor watches a vector database for documents engineered to rank for every
query. TraceAudit sits in front of a model's output and stops the stream if the
reasoning drifts, redacting any credentials it sees. All three report into one
Postgres-backed dashboard through reliable local event storagees, so the evidence survives
outages, and an operator can investigate, review and handle, and export it — with everything
audit-trailed. It's built as a defensible demo: detectors are calibrated on
labelled corpora and the scores are published, imperfect ones included."

---

## 32. 1-Minute Explanation

"Project Black Monolith protects autonomous AI agents from attacks that live at
three different layers. The tool layer: an MCP server can present a clean tool
schema, get approved, then silently swap in a poisoned description that injects
instructions into the agent's context. MCP-Shield proxies the MCP connection,
fingerprints every tool schema with an HMAC over a canonical serialization, and in
enforce mode rewrites a mutated schema back to its trusted baseline — plus it
scans descriptions for hidden-instruction markers and invisible Unicode. The
memory layer: a vector store can be poisoned with a document engineered to rank
for every query. VectorAnchor wraps ChromaDB and quarantines any document that
ranks across too many dissimilar topics, serving the next clean result instead.
The reasoning layer: a model's trace can drift very different from normal behavior or echo secrets.
TraceAudit monitors each token against a baseline distribution with rolling KL
divergence, terminates the stream on divergence, and redacts PII before it's
forwarded.

Every detection becomes one JSON event, spooled to a reliable local event storage and
delivered with automatic retries, with repeatedly failing events kept aside for inspection to a Next.js dashboard that persists to
Postgres before publishing live over SSE. The dashboard gives an operator a live
feed, an investigation queue with an can be added to but not silently rewritten audit trail, cross-layer session
correlation — so you can see the same agent tripped all three layers — a benchmark
ledger with real confusion-matrix scores, and evidence export. It runs fully
offline with repeatable mock backends, so the demo is repeatable end to end."

---

## 33. 3-Minute Technical Explanation

"Project Black Monolith is a defense-in-depth system for autonomous agents, built
as three independent services plus a central dashboard, unified by a single event
contract.

MCP-Shield is a Rust/Tokio proxy that sits between an agent and an MCP tool server
over stdio — or Streamable HTTP via a bridge. It forwards every JSON-RPC line
byte-for-byte, but correlates `tools/list` requests to responses and runs each
tool through two detectors: an exact fingerprint — canonical, key-sorted
serialization hashed with HMAC-SHA256 — compared against a persisted baseline, and
a not dependent on saved history description sanitizer covering instruction-override phrases, shell
patterns, and invisible Unicode. On a mismatch in enforce mode, the mutated tool
is replaced with the trusted baseline schema in the response the agent receives.
First-contact poisoning is handled by refusing suspicious first sightings and, in
approve mode, withholding every unseen tool until an operator approves it.

VectorAnchor is a FastAPI service wrapping an embedded ChromaDB. Every /retrieve
embeds the query once, pulls k-plus-buffer candidates, and records the top-ranked
documents per document in a frequency tracker. The detector's signal is not raw
frequency but the number of mutually dissimilar topic clusters a document ranks
for — a bait spans unrelated topics. Retention is per-document with a
500-query horizon and an 8-query-per-document cap, so the detection reach and the
quadratic clustering cost are separate knobs; eviction drops the hit the newest
one most duplicates, which makes a same-topic flood evict itself. Quarantined
documents are withheld and the next clean result is served, with the detector's
state persisted atomically to disk.

TraceAudit is a FastAPI SSE proxy in front of a model backend — an offline
repeatable mock by default, Ollama optionally. Every token updates a rolling
20-token window; the monitor computes Laplace-smoothed KL divergence against a
captured baseline distribution, with out-of-vocabulary tokens collapsed into an
<other> bucket with near-zero baseline mass, so very different from normal behavior reasoning spikes
the KL past the calibrated threshold of 1.0 and terminates the stream with a safe
refusal. A bounded 16-token look-behind buffer scans token concatenations for PII
patterns — AWS keys, API keys, emails, SSNs, Luhn-validated cards — and redacts
matches before any fragment is released, logged, or emitted.

Delivery is the load-bearing part. Each module writes every event to a durable
local outbox before continuing — SQLite WAL in Python, a JSONL spool with fsync in
Rust, which also drains on startup, force-drains before exit, and has a resident
worker for the shared volume. Events POST to /api/ingest with a per-tenant,
per-module access token; the dashboard validates strictly — rejects, never
coerces — inserts with `on conflict (event_id) do nothing` for safe retry behavior without duplicates, and
only then publishes. A Postgres trigger notifies a LISTEN/NOTIFY channel, each
dashboard instance loads the committed row into an in-process broker, and SSE
clients get a replay-then-stream with Last-Event-ID resume and dedupe.

The database is a Postgres `monolith` schema: immutable security events, review and handle
state and an can be added to but not silently rewritten audit trail written in the same transaction, benchmark
scorecards whose metrics are recomputed server-side, session digests, and an alert
outbox for HMAC-signed webhooks. The runtime connects as a restricted login that
SET ROLEs to a NOLOGIN monolith_app role, and separation between different users or organizations is enforced twice —
application predicates and transaction-local RLS context. Operator identities are
bootstrap tokens, revocable HttpOnly sessions, or validated OIDC JWTs, and the
actor on every audit row comes from the credential, never the request body.

Everything is measured: detectors cost microseconds per event, thresholds are
calibrated against labelled corpora, confusion matrices are published — including
the honest sub-100% numbers — and the documented evasions are built and tested,
not just claimed. The whole stack runs offline with repeatable backends and is
gated by a CI pipeline that builds all five services and runs live-stack contract
verification."

---

## 34. Project Engineering Story

**1. The problem.** An autonomous agent is only as trustworthy as its inputs: its
tool server can be a liar, its vector store can be seeded with attacker content,
and its reasoning trace can leak or drift. These are three separate failure
domains, so a single "AI firewall" cannot cover them.

**2. The simplest implementation.** A README describing three threats. Or a single
Python script that greps tool descriptions for "ignore previous instructions". But
none of that would survive the obvious follow-ups: *how do you know a schema
changed after approval?* (you need a persisted, keyed baseline), *how do you know a
document is bait and not just popular?* (you need cross-topic evidence over time),
*how do you catch a secret split across two tokens?* (you need a look-behind
buffer), and *how do you prove any of it works?* (you need labelled corpora and
measured scores).

**3. Why the architecture evolved.** Each question forced a real mechanism, and
the mechanisms forced the architecture. Detections that must survive a collector
outage forced reliable local event storagees. A dashboard that must not lose or duplicate
evidence forced save-before-show, safe to retry without creating duplicates inserts, and an can be added to but not silently rewritten
review and handle model. Detections that must be attributable to one agent session forced the
shared session identity and the cross-layer session query. Calibration that must be
defensible forced the evaluation harness, the provenance wrapper, and the honesty
to keep sub-100% scores. The adversarial-evaluation section — actually building
each documented evasion to see if it works — is the same instinct applied to the
project's own claims.

**4. Technical challenges encountered (real ones, in the code's comments):**
- the Supabase image's superuser is `supabase_admin`, which broke schema creation
  (42501) until the ledger moved into the `postgres` database;
- `pg_isready` reported healthy on an unusable database — healthchecks now run a
  real query;
- a non-UUID `event_id` would have been retried forever as a 503 poison pill;
- the mock backend's `hash()` seeding made the "repeatable" demo non-
  repeatable across processes (PYTHONHASHSEED) — fixed with hashlib seeding;
- the naive oldest-first eviction created a *cheaper* evasion than the one it
  fixed — fixed with redundancy-based eviction;
- `cosine()` on the hot path cost ~4× — fixed by normalizing once and using
  `unit_dot`;
- a larger corpus broke one of the project's own attack fixtures — correctly
  reinterpreted as corpus breadth being a defense, not a detector regression;
- the documented contract said "coerce to safe values" while the implementation
  strictly rejects — the test that finally ran found the drift.

**5. Tradeoffs made.** Independent services over shared code (contract sync cost);
Postgres over a message bus (scale ceiling, benefit of keeping related database changes together); mock backends
over real models (repeatability over realism, honestly labeled); regex and exact
matching over ML (transparent and repeatable, at the cost of recall); reject-
don't-coerce validation (visible dead letters over silent mutation); trust-on-
first-use by default (convenience) with an explicit approve-mode opt-out.

**6. The next version.** Import the shared Python outbox instead of vendoring;
generate contract types from the JSON Schema; authenticate the agent-facing
endpoints; run the `real` profile and publish its numbers; move delivery to a
queue and the ledger to a partitioned store when the single Postgres becomes the
limit; and production-hardening the deployment (TLS, HA, observability) — the
identity and evidence model is already built for it.

---

*Sources: traced from the actual codebase — module sources, migrations, contracts,
CI, scripts, and evaluation docs — on 2026-08-17. Where README/CLAUDE.md statements
were verified against code, they are marked accordingly; discrepancies are called
out inline.*