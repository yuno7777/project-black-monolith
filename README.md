<div align="center">

# PROJECT BLACK MONOLITH

**Unified security middleware for autonomous AI agents — defending the tool, memory, and reasoning layers.**

<sub>Three independent detection modules · one shared event schema · one real-time threat dashboard</sub>

<br/>

[![CI](https://github.com/yuno7777/project-black-monolith/actions/workflows/ci.yml/badge.svg)](https://github.com/yuno7777/project-black-monolith/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-111111.svg?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-tokio-111111?style=flat-square&logo=rust&logoColor=white)](mcp-shield/)
[![Python](https://img.shields.io/badge/Python-FastAPI-111111?style=flat-square&logo=python&logoColor=white)](vector-anchor/)
[![Next.js](https://img.shields.io/badge/Next.js-15-111111?style=flat-square&logo=nextdotjs&logoColor=white)](dashboard/)
[![Status](https://img.shields.io/badge/status-research-555555?style=flat-square)](#)

<br/>

[Overview](#overview) &nbsp;·&nbsp; [Threat model](#threat-model) &nbsp;·&nbsp; [Architecture](#architecture) &nbsp;·&nbsp; [Quick start](#quick-start) &nbsp;·&nbsp; [Demo](#end-to-end-demo) &nbsp;·&nbsp; [Modules](#modules) &nbsp;·&nbsp; [Development](#development) &nbsp;·&nbsp; [Contributing](#contributing)

</div>

---

## Overview

Autonomous AI agents are attacked at more than one layer of their execution. The **tools** they rely on can be silently swapped after approval. The **memory** they retrieve from can be seeded with adversarial documents. The **reasoning** they generate can be steered off-distribution or coaxed into leaking secrets mid-thought. Hardening a single layer leaves the others exposed.

**Project Black Monolith** addresses all three with a set of independent-but-consistent defense modules. Each is deployable on its own, each sits inline on the path it protects, and each follows the same lifecycle:

<div align="center">

**intercept → analyze → flag / quarantine / block → emit a structured event**

</div>

Because every module emits the same event shape, a single dashboard renders all three feeds as one unified, real-time picture of what is being attempted against the agent and what was stopped.

> [!NOTE]
> **This is defensive tooling.** Every "attack" artifact in this repository — a mutated tool schema, an engineered bait document, an off-distribution prompt, a fake credential — is a **local, self-contained detection-test fixture** used only to verify that the detectors fire. No live systems, third parties, or real vulnerabilities are targeted anywhere, and there are no real secrets in the repository. See [SECURITY.md](SECURITY.md).

---

## Threat model

<table>
  <thead>
    <tr>
      <th align="left">Layer</th>
      <th align="left">Module</th>
      <th align="left">Attack class</th>
      <th align="left">Defense</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Tool</b></td>
      <td><a href="mcp-shield/"><b>MCP-Shield</b></a></td>
      <td>Tool-schema <b>rug pull</b>; hidden-instruction (tool-poisoning) descriptions</td>
      <td>HMAC-SHA256 schema fingerprinting against a trusted baseline; in enforce mode <b>rewrites the response</b> so the agent only ever sees the clean schema</td>
    </tr>
    <tr>
      <td><b>Memory</b></td>
      <td><a href="vector-anchor/"><b>VectorAnchor</b></a></td>
      <td><b>Corpus poisoning</b> — "universal bait" documents that rank across unrelated queries</td>
      <td>Cross-query frequency-anomaly detection; <b>quarantines</b> the document and serves the next-best clean result</td>
    </tr>
    <tr>
      <td><b>Reasoning</b></td>
      <td><a href="trace-audit/"><b>TraceAudit</b></a></td>
      <td><b>Reasoning divergence</b>; <b>PII / credential leakage</b> in the trace</td>
      <td>Rolling <b>KL divergence</b> against a baseline (terminates the stream on breach); regex scanner <b>redacts</b> secrets before they are forwarded or logged</td>
    </tr>
  </tbody>
</table>

---

## Architecture

```text
                           ┌──────────────────────────────────────────┐
                           │         Unified Dashboard (Next.js)        │
                           │    live SSE threat feed · session summary  │
                           └──────────────────▲───────────────────────┘
                                              │  POST /api/ingest   (shared event JSON)
             ┌────────────────────────────────┼────────────────────────────────┐
             │                                │                                 │
  ┌──────────┴──────────┐      ┌─────────────┴──────────┐      ┌───────────────┴────────┐
  │   MCP-Shield (Rust)  │      │ VectorAnchor (FastAPI) │      │  TraceAudit (FastAPI)  │
  │      TOOL LAYER      │      │      MEMORY LAYER      │      │     REASONING LAYER    │
  ├─────────────────────┤      ├────────────────────────┤      ├────────────────────────┤
  │ MCP stdio proxy.     │      │ Retriever proxy over    │      │ Streaming proxy over a │
  │ Fingerprints tool    │      │ embedded ChromaDB.      │      │ model endpoint. Rolling│
  │ schemas (HMAC-256);  │      │ Flags "universal bait"  │      │ KL divergence vs a     │
  │ detects & blocks     │      │ documents ranking       │      │ baseline; terminates   │
  │ rug-pull mutations + │      │ across unrelated        │      │ divergent traces and   │
  │ hidden-instruction   │      │ queries; quarantines    │      │ redacts PII / creds in │
  │ poisoning.           │      │ them.                   │      │ the trace.             │
  └─────────▲───────────┘      └───────────▲────────────┘      └───────────▲────────────┘
            │ stdio (MCP)                  │ HTTP /retrieve                 │ HTTP /generate (SSE)
         ┌──┴──┐                        ┌──┴──┐                          ┌──┴──┐
         │agent│                        │agent│                          │agent│
         └─────┘                        └─────┘                          └─────┘
```

### Shared event schema

All three modules emit a single JSON shape, so the dashboard consumes every feed uniformly and new modules integrate for free:

```json
{
  "timestamp_ms": 1770000000000,
  "module": "mcp-shield",
  "event_type": "schema_mismatch",
  "severity": "critical",
  "details": { "tool": "read_file", "action": "rewritten" }
}
```

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp_ms` | number | Unix epoch milliseconds at detection time |
| `module` | string | `mcp-shield` · `vector-anchor` · `trace-audit` |
| `event_type` | string | e.g. `schema_mismatch`, `corpus_poison_quarantine`, `reasoning_divergence_terminate` |
| `severity` | string | `info` · `warning` · `critical` |
| `details` | object | Module-specific payload (hashes, scores, previews, latency) |

Modules deliver events by POSTing them to the dashboard's ingest endpoint (`MONOLITH_DASHBOARD_URL`) with a per-module bearer token. Each module first spools the event to a **durable on-disk outbox**, then delivers it asynchronously with exponential backoff, so a dashboard outage costs delivery latency rather than evidence — a security tool must not lose a detection because the collector was restarting. Emission never blocks the detection path. The dashboard persists every event to a Postgres ledger before fanning it out to the browser over Server-Sent Events; `event_id` is the idempotency key, so a redelivered event is deduplicated rather than double-counted.

---

## Quick start

> [!IMPORTANT]
> **Requirements: Docker (with Compose) and `curl` — nothing else.** ChromaDB runs embedded inside VectorAnchor and TraceAudit ships an offline mock model backend, so no external vector database or Ollama is required to run the full demo. Both are configurable if you want the real thing (see the module READMEs).

```bash
git clone https://github.com/yuno7777/project-black-monolith.git
cd project-black-monolith

bash scripts/generate_secrets.sh # write a local .env (gitignored) — required
docker compose up -d --build     # build and start all five services
./run_full_demo.sh               # drive all three attacks, then verify the ledger
```

The stack has **no default credentials**: the database password and the three
per-module ingest tokens have to exist before anything starts, and Compose
refuses to start without them rather than falling back to a weak default. That
is what the first command is for — it writes 24 bytes of CSPRNG output per value
into `.env`, which is gitignored and must never be committed. See
[`.env.example`](.env.example) for what it sets and why.

Open **[http://localhost:3000](http://localhost:3000)** and watch detections stream in live as each fixture runs.

| Service | Port | Interface |
| :--- | :--- | :--- |
| Dashboard | `3000` | Live threat feed (web UI) + `POST /api/ingest` |
| VectorAnchor | `8001` | `POST /retrieve` |
| TraceAudit | `8002` | `POST /generate` (SSE) |

---

## End-to-end demo

`run_full_demo.sh` drives all three fixtures in sequence, entirely through `docker compose exec` — so Docker is the only host requirement — pausing between each so the events are easy to follow on the dashboard.

**1 — MCP-Shield · rug pull.**
Establishes a trusted baseline for a `read_file` tool, then serves a mutated schema whose description carries injected instructions and a zero-width space. In enforce mode the mutation is **blocked** — the agent receives the clean baseline schema — while `schema_mismatch` (critical) and `suspicious_description` (warning) events fire.

**2 — VectorAnchor · corpus poisoning.**
Seeds a clean corpus, runs on-topic queries that flag nothing, injects one "universal bait" document, then runs four unrelated queries that all retrieve it. On the fourth distinct topic the frequency anomaly trips, a `corpus_poison_quarantine` (critical) event fires, and the document is withheld from results thereafter.

**3 — TraceAudit · divergence and PII.**
Streams a prompt that pushes the model into off-distribution reasoning; KL divergence climbs past the threshold and the stream is **terminated** early with a safe refusal (`reasoning_divergence_terminate`, critical). A second prompt whose context holds a fake credential and email has both **redacted** in the trace before they reach the client or the logs (`pii_redacted`, warning).

Each detection reaches the dashboard within a second, tagged by module and severity, with an expandable full payload.

---

## Verifying the delivery guarantees

The demo shows detections *working*; these three scripts show the delivery path
holding up when the collector does not. All three run against the live stack and
are gated in CI.

```bash
bash mcp-shield/fixtures/verify_outbox.sh   # (from mcp-shield/) no Docker needed
bash scripts/verify_ingest.sh               # 16 checks against the ingest contract
bash scripts/verify_recovery.sh             # kills the dashboard, proves nothing is lost
bash scripts/verify_incidents.sh            # 27 checks on the incident lifecycle
```

- **`verify_outbox.sh`** drives MCP-Shield's spool through three phases against
  a local stub dashboard: unreachable (events persist, the proxy keeps serving),
  reachable (the previous run's backlog drains — the claim that matters for a
  short-lived process), and rejecting with 401 (events dead-letter instead of
  retrying forever). It also asserts every delivered envelope carried a bearer
  token, a v4 UUID `event_id`, and `schema_version: 2`.
- **`verify_ingest.sh`** covers the ingestion contract: token scoping (one
  module's credential cannot forge another's events), idempotent redelivery,
  the validation rejections that must be permanent rather than retryable, batch
  acceptance, and that a newly connected SSE client is replayed persisted
  history rather than an in-memory buffer.
- **`verify_recovery.sh`** stops the dashboard container, drives real
  retrievals, and asserts the events sit in VectorAnchor's SQLite spool with the
  ledger frozen — then restarts it and asserts the spool drains into the ledger.
  It restarts a container but removes no data.
- **`verify_incidents.sh`** walks an incident through its lifecycle and asserts
  the constraints that keep the queue honest: an untriaged event still reaches
  the queue, resolving demands a verdict, omitting a field never silently clears
  it, the underlying event is never mutated by triage, and the audit trail
  rejects `UPDATE` and `DELETE` outright.

---

## Modules

Each module is standalone, with its own README, tests, demo script, and Dockerfile.

### MCP-Shield &nbsp;<sub>tool layer · Rust / tokio</sub>

A transparent JSON-RPC pass-through proxy for the Model Context Protocol (stdio transport). It fingerprints every tool schema with HMAC-SHA256 over a canonical, key-sorted serialization; compares each `tools/list` response against a persisted baseline to catch rug-pull mutations; scans descriptions for hidden-instruction injection (override phrases, shell-command substrings, invisible/bidirectional Unicode); and, in enforce mode, rewrites a mutated response back to the trusted schema so the poisoned version never reaches the agent.

<details>
<summary><b>Detection events &amp; run</b></summary>

<br/>

**Events:** `baseline_registered` (info) · `schema_mismatch` (critical) · `suspicious_description` (warning) · `analysis_error` (warning)

```bash
cd mcp-shield
cargo test
bash fixtures/run_demo.sh
```
See [mcp-shield/README.md](mcp-shield/README.md) for `MCP_SHIELD_MODE` (monitor/enforce), the HMAC key, and configuration.

</details>

### VectorAnchor &nbsp;<sub>memory layer · Python / FastAPI + ChromaDB</sub>

A retriever proxy that sits in front of a vector store. A legitimate document is relevant to one topic; a poisoned "universal bait" document ranks across many *mutually dissimilar* queries. VectorAnchor tracks, per document, how many distinct topics it has ranked highly for within a rolling window, and quarantines any document that crosses the threshold — serving the next-best clean result in its place before poison reaches the context window.

<details>
<summary><b>Detection events &amp; run</b></summary>

<br/>

**Events:** `corpus_poison_quarantine` (critical) · `retrieval` (info) · `service_start` (info)

```bash
cd vector-anchor
pip install -r requirements.txt
python -m pytest tests/
bash fixtures/run_demo.sh
```
See [vector-anchor/README.md](vector-anchor/README.md) for the embedding backends and detection thresholds.

</details>

### TraceAudit &nbsp;<sub>reasoning layer · Python / FastAPI (streaming)</sub>

A streaming proxy over a model's generation endpoint. It builds a baseline token distribution from normal prompts, then computes a rolling KL divergence of each live stream against it; a trace that wanders off-distribution is terminated early and replaced with a standardized safe refusal. In parallel, a regex scanner inspects the streaming trace and redacts credential/PII spans before they are forwarded, logged, or persisted.

<details>
<summary><b>Detection events &amp; run</b></summary>

<br/>

**Events:** `reasoning_divergence_terminate` (critical) · `pii_redacted` (warning) · `service_start` (info)

```bash
cd trace-audit
pip install -r requirements.txt
python -m pytest tests/
bash fixtures/run_demo.sh
```
See [trace-audit/README.md](trace-audit/README.md) for the mock/Ollama backends and the KL threshold.

</details>

### Dashboard &nbsp;<sub>Next.js 15 · React 19</sub>

An authenticated ingest endpoint over a Postgres event ledger, plus a Server-Sent Events stream. Modules POST events to `/api/ingest` with a per-module bearer token; events are persisted before publication and keyed by `event_id` for idempotent redelivery. The browser subscribes to `/api/events` and is replayed the persisted history on connect, so a client that joins late — or after a restart — still sees what it missed. The UI presents a unified feed color-coded by module and severity, severity and module breakdowns, and average detection latency, on a pitch-black console with an optional light theme. See [dashboard/README.md](dashboard/README.md).

---

## Development

```bash
# MCP-Shield — Rust
cd mcp-shield    && cargo test && bash fixtures/run_demo.sh

# VectorAnchor — Python
cd vector-anchor && pip install -r requirements.txt && python -m pytest tests/ && bash fixtures/run_demo.sh

# TraceAudit — Python
cd trace-audit   && pip install -r requirements.txt && python -m pytest tests/ && bash fixtures/run_demo.sh

# Dashboard — Next.js
cd dashboard     && npm install && npm run build
```

Continuous integration runs `cargo build` + `cargo test` for MCP-Shield, `pytest` for VectorAnchor and TraceAudit, and a Next.js build for the dashboard on every push and pull request to `main`. Once those are green, an **integration job** builds the full Compose stack and runs the ingest-contract, outage-recovery and end-to-end demo scripts against it, so the delivery guarantees are gated rather than asserted.

### Project structure

```text
project-black-monolith/
├── mcp-shield/          Rust MCP proxy — schema fingerprinting + enforce-mode blocking
├── vector-anchor/       FastAPI retriever proxy — corpus-poisoning quarantine
├── trace-audit/         FastAPI streaming proxy — KL divergence + PII redaction
├── dashboard/           Next.js 15 real-time SSE threat feed
├── docker-compose.yml   One-command full stack
├── run_full_demo.sh     End-to-end integration demo
├── scripts/             Secret generation · ingest-contract and recovery verification
└── .github/             CI workflow · issue & pull-request templates
```

### Technology

<table>
  <tr><td><b>MCP-Shield</b></td><td>Rust · tokio · serde · hmac / sha2</td></tr>
  <tr><td><b>VectorAnchor / TraceAudit</b></td><td>Python · FastAPI · ChromaDB (embedded) · Ollama (optional)</td></tr>
  <tr><td><b>Dashboard</b></td><td>Next.js 15 · React 19 · Server-Sent Events</td></tr>
  <tr><td><b>Orchestration</b></td><td>Docker Compose</td></tr>
</table>

---

## Roadmap

- [x] MCP-Shield — fingerprinting, description sanitizer, enforce-mode blocking
- [x] VectorAnchor — cross-query frequency-anomaly quarantine
- [x] TraceAudit — KL-divergence termination and PII redaction
- [x] Unified real-time dashboard and one-command Docker stack
- [ ] Content-Length framing for MCP-Shield, alongside line-delimited
- [ ] Semantic embeddings by default for VectorAnchor (sentence-transformers)
- [ ] Persisted event history and filtering in the dashboard

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, commit conventions, and the one hard rule — **preserve the shared event shape**, which every module and the dashboard depend on. Security reports are handled per [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE). &nbsp;Copyright © 2026 Sleepers Research.

---

<div align="center">

<sub>Built by Sleepers Research. Originally developed under the working name "AEOS Guard" for a B.E. final-year submission and since renamed to Project Black Monolith; the module names (MCP-Shield, VectorAnchor, TraceAudit) are unchanged.</sub>

</div>
