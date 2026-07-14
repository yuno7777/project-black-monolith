# Project Black Monolith

**A unified security middleware system that protects autonomous AI agents
across three layers of their execution — tool, memory, and reasoning.**
_Sleepers Research · B.E. final-year submission._

Autonomous agents are attacked at more than one layer: their tools can be
swapped out from under them, their memory can be poisoned, and their own
reasoning can be steered off the rails or made to leak secrets. Project Black
Monolith is three independent-but-consistent defense modules — each deployable
standalone — that all follow the same pattern (**intercept → analyze →
flag / quarantine / block → emit a structured event**) and stream their
detections to one shared real-time dashboard.

## Architecture

```text
                            ┌──────────────────────────────────────────┐
                            │        Unified Dashboard (Next.js)        │
                            │   live SSE threat feed · session summary  │
                            └──────────────▲───────────────────────────┘
                                           │  POST /api/ingest  (shared event JSON)
              ┌────────────────────────────┼────────────────────────────┐
              │                            │                             │
   ┌──────────┴──────────┐   ┌────────────┴───────────┐   ┌─────────────┴──────────┐
   │  MCP-Shield (Rust)  │   │ VectorAnchor (FastAPI) │   │  TraceAudit (FastAPI)  │
   │     TOOL LAYER      │   │     MEMORY LAYER       │   │    REASONING LAYER     │
   ├─────────────────────┤   ├────────────────────────┤   ├────────────────────────┤
   │ MCP stdio proxy.    │   │ Retriever proxy over   │   │ Streaming proxy over a │
   │ Fingerprints tool   │   │ embedded ChromaDB.     │   │ model endpoint. Rolling│
   │ schemas (HMAC-      │   │ Flags "universal bait" │   │ KL divergence vs a     │
   │ SHA256); detects &  │   │ docs that rank across  │   │ baseline; terminates   │
   │ blocks rug-pull     │   │ many unrelated queries;│   │ divergent traces +     │
   │ mutations + hidden  │   │ quarantines them.      │   │ redacts PII/creds in   │
   │ instruction poison. │   │                        │   │ the trace.             │
   └─────────▲───────────┘   └───────────▲────────────┘   └───────────▲────────────┘
             │ stdio                      │ HTTP                       │ HTTP (SSE)
        agent │ MCP                  agent │ /retrieve             agent │ /generate
```

All three emit the **same event shape** so the dashboard consumes them
uniformly:

```json
{ "timestamp_ms": 0, "module": "mcp-shield", "event_type": "schema_mismatch",
  "severity": "critical", "details": { "…": "…" } }
```

| Module | Layer | Language | Catches |
| ------ | ----- | -------- | ------- |
| [MCP-Shield](mcp-shield/) | Tool | Rust / tokio | MCP tool-schema rug pulls; hidden-instruction (tool-poisoning) descriptions |
| [VectorAnchor](vector-anchor/) | Memory | Python / FastAPI + ChromaDB | Corpus-poisoning "universal bait" documents |
| [TraceAudit](trace-audit/) | Reasoning | Python / FastAPI (streaming) | Reasoning-trace divergence; PII/credential leakage |
| [Dashboard](dashboard/) | — | Next.js 15 | Unified real-time threat feed |

## One-command setup

Requires Docker (with Compose) and `curl`.

```sh
docker compose up -d --build      # build & start all four services
./run_full_demo.sh                # drive all three attack fixtures
```

Then open **http://localhost:3000** and watch detections stream in live.

Service ports: dashboard `3000`, VectorAnchor `8001`, TraceAudit `8002`.
ChromaDB runs embedded inside VectorAnchor; TraceAudit uses an offline mock
model backend by default — so **no external vector DB or Ollama is required**
for the demo (both are configurable if you want the real thing; see the module
READMEs).

## What `run_full_demo.sh` does

It drives all three fixtures in sequence, entirely through `docker compose
exec` (so Docker is the only host requirement), pausing between each so the
events are easy to follow on the dashboard:

1. **MCP-Shield — rug pull.** Establishes a trusted baseline for a `read_file`
   tool, then serves a mutated schema whose description carries injected
   instructions + a zero-width space. In enforce mode the mutation is
   **blocked** (the agent receives the clean baseline schema) and
   `schema_mismatch` + `suspicious_description` events fire.
2. **VectorAnchor — corpus poisoning.** Seeds a clean corpus, runs on-topic
   queries (no flags), injects one "universal bait" document, then runs four
   unrelated queries that all retrieve it — tripping the frequency anomaly and
   firing a `corpus_poison_quarantine` event; the document is then withheld.
3. **TraceAudit — divergence + PII.** Streams a prompt that pushes the model
   into off-distribution reasoning (KL divergence crosses threshold → stream
   **terminated** early with a safe refusal), then a prompt whose context holds
   a fake credential + email (redacted in the trace → `pii_redacted` events).

Each detection appears on the dashboard's live feed within a second, tagged by
module and severity, with an expandable full payload.

## Running / testing modules individually

Each module is standalone and has its own README, demo, and tests:

```sh
# MCP-Shield (Rust)
cd mcp-shield && cargo test && bash fixtures/run_demo.sh

# VectorAnchor (Python)
cd vector-anchor && pip install -r requirements.txt && python -m pytest tests/ && bash fixtures/run_demo.sh

# TraceAudit (Python)
cd trace-audit && pip install -r requirements.txt && python -m pytest tests/ && bash fixtures/run_demo.sh
```

## Safety / scope note

This is **defensive** tooling. Every "attack" in the repo is a local,
self-contained detection-test fixture (a mutated schema, an engineered bait
document, an off-distribution prompt, a fake credential) used only to validate
that the detectors fire. No live systems, third parties, or real
vulnerabilities are targeted anywhere. It is a single-operator local research
system: no authentication, accounts, or cloud deployment.

## History

This project began under the working name "AEOS Guard" for a college B.E.
final-year submission and was renamed to Project Black Monolith. The module
names (MCP-Shield, VectorAnchor, TraceAudit) and Sleepers Research branding are
unchanged.
