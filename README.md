<div align="center">

# ⬛ Project Black Monolith

### Unified security middleware that defends autonomous AI agents across the **tool**, **memory**, and **reasoning** layers.

*Three independent detection modules. One shared event schema. One live threat dashboard.*

[![CI](https://github.com/yuno7777/project-black-monolith/actions/workflows/ci.yml/badge.svg)](https://github.com/yuno7777/project-black-monolith/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-black.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-tokio-000000?logo=rust&logoColor=white)](mcp-shield/)
[![Python](https://img.shields.io/badge/Python-FastAPI-3776AB?logo=python&logoColor=white)](vector-anchor/)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?logo=nextdotjs&logoColor=white)](dashboard/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quick start](#-quick-start) · [Architecture](#-architecture) · [The threats](#-the-threats-it-catches) · [Demo](#-the-full-demo) · [Modules](#-modules) · [Contributing](#-contributing)

</div>

---

## 🛡️ Why

Autonomous AI agents are attacked at more than one layer. Their **tools** can be swapped out from under them after approval (an MCP "rug pull"). Their **memory** can be poisoned so a malicious document is retrieved no matter what the agent asks. Their **reasoning** can be steered off the rails or made to leak secrets mid-thought.

Defending only one layer leaves the others open. **Project Black Monolith** is three independent-but-consistent defense modules — each deployable standalone — that all follow the same pattern:

> **intercept → analyze → flag / quarantine / block → emit a structured event**

…and stream every detection to a single real-time dashboard.

> [!NOTE]
> **This is defensive tooling.** Every "attack" in the repo is a local, self-contained *detection-test fixture* used only to validate that the detectors fire. No live systems, third parties, or real vulnerabilities are targeted anywhere. See [SECURITY.md](SECURITY.md).

---

## 🏗️ Architecture

```text
                          ┌──────────────────────────────────────────┐
                          │        Unified Dashboard (Next.js)         │
                          │   live SSE threat feed · session summary   │
                          └──────────────────▲───────────────────────┘
                                             │  POST /api/ingest  (shared event JSON)
            ┌────────────────────────────────┼────────────────────────────────┐
            │                                │                                 │
 ┌──────────┴──────────┐      ┌─────────────┴──────────┐      ┌───────────────┴────────┐
 │   MCP-Shield (Rust)  │      │ VectorAnchor (FastAPI) │      │  TraceAudit (FastAPI)  │
 │      TOOL LAYER      │      │      MEMORY LAYER      │      │     REASONING LAYER    │
 ├─────────────────────┤      ├────────────────────────┤      ├────────────────────────┤
 │ MCP stdio proxy.     │      │ Retriever proxy over    │      │ Streaming proxy over a │
 │ Fingerprints tool    │      │ embedded ChromaDB.      │      │ model endpoint. Rolling│
 │ schemas (HMAC-256);  │      │ Flags "universal bait"  │      │ KL divergence vs a     │
 │ detects & blocks     │      │ docs ranking across     │      │ baseline; terminates   │
 │ rug-pull mutations + │      │ many unrelated queries; │      │ divergent traces +     │
 │ hidden-instruction   │      │ quarantines them.       │      │ redacts PII/creds in   │
 │ poisoning.           │      │                         │      │ the trace.             │
 └─────────▲───────────┘      └───────────▲────────────┘      └───────────▲────────────┘
           │ stdio (MCP)                  │ HTTP /retrieve                 │ HTTP /generate (SSE)
        ┌──┴──┐                        ┌──┴──┐                          ┌──┴──┐
        │agent│                        │agent│                          │agent│
        └─────┘                        └─────┘                          └─────┘
```

Every module emits the **same event shape**, so the dashboard consumes all three feeds uniformly:

```json
{
  "timestamp_ms": 1770000000000,
  "module": "mcp-shield",
  "event_type": "schema_mismatch",
  "severity": "critical",
  "details": { "tool": "read_file", "action": "rewritten" }
}
```

---

## 🎯 The threats it catches

| Layer | Module | Attack class | Defense |
| :---- | :----- | :----------- | :------ |
| 🔧 **Tool** | **MCP-Shield** | Tool-schema **rug pull** + hidden-instruction (tool-poisoning) descriptions | HMAC-SHA256 schema fingerprinting vs a trusted baseline; **rewrites the response** so the agent gets the clean schema |
| 🧠 **Memory** | **VectorAnchor** | **Corpus poisoning** — "universal bait" docs that rank across unrelated queries | Cross-query frequency-anomaly detection; **quarantines** the doc and serves the next-best clean result |
| 💭 **Reasoning** | **TraceAudit** | **Reasoning divergence** + **PII / credential leakage** in the trace | Rolling **KL divergence** vs a baseline (terminates the stream); regex scanner **redacts** secrets before they're forwarded or logged |

---

## 🚀 Quick start

> **Requirements:** Docker (with Compose) and `curl`. Nothing else — ChromaDB runs embedded and TraceAudit ships an offline mock model backend, so **no external vector DB or Ollama is needed** for the demo.

```bash
git clone https://github.com/yuno7777/project-black-monolith.git
cd project-black-monolith

docker compose up -d --build     # build & start all four services
./run_full_demo.sh               # fire all three attack fixtures
```

Then open **[http://localhost:3000](http://localhost:3000)** and watch detections stream in live.

| Service | Port | |
| :------ | :--- | :-- |
| Dashboard | `3000` | live threat feed |
| VectorAnchor | `8001` | `POST /retrieve` |
| TraceAudit | `8002` | `POST /generate` (SSE) |

---

## 🎬 The full demo

`run_full_demo.sh` drives all three fixtures in sequence — entirely through `docker compose exec`, so Docker is the only host requirement — pausing between each so the events are easy to follow on the dashboard:

1. **🔧 MCP-Shield — rug pull.** Establishes a trusted baseline for a `read_file` tool, then serves a mutated schema whose description carries injected instructions + a zero-width space. In enforce mode the mutation is **blocked** (the agent receives the clean baseline schema); `schema_mismatch` + `suspicious_description` events fire.
2. **🧠 VectorAnchor — corpus poisoning.** Seeds a clean corpus, runs on-topic queries (no flags), injects one "universal bait" document, then runs four unrelated queries that all retrieve it — tripping the frequency anomaly and firing a `corpus_poison_quarantine` event; the document is then withheld.
3. **💭 TraceAudit — divergence + PII.** Streams a prompt that pushes the model into off-distribution reasoning (KL divergence crosses threshold → stream **terminated** early with a safe refusal), then a prompt whose context holds a fake credential + email (**redacted** in the trace → `pii_redacted` events).

Each detection appears on the dashboard within a second, tagged by module and severity, with an expandable full payload.

---

## 📦 Modules

Each module is standalone, with its own README, tests, demo, and Dockerfile.

### 🔧 [MCP-Shield](mcp-shield/) — tool layer · Rust / tokio
Transparent JSON-RPC pass-through proxy for the Model Context Protocol (stdio). Fingerprints every tool schema with HMAC-SHA256 over a canonical serialization, detects rug-pull mutations against a persisted baseline, scans descriptions for hidden-instruction injection, and in **enforce mode** rewrites mutated responses back to the trusted schema.

### 🧠 [VectorAnchor](vector-anchor/) — memory layer · Python / FastAPI + ChromaDB
Retriever proxy over an embedded vector store. Detects documents that rank highly across many *mutually dissimilar* queries — the signature of corpus poisoning — and quarantines them before they reach the agent's context window.

### 💭 [TraceAudit](trace-audit/) — reasoning layer · Python / FastAPI (streaming)
Streaming proxy over a model endpoint. Computes a rolling KL divergence of the token stream against a captured baseline and terminates divergent traces with a safe refusal; a regex scanner redacts PII / credentials before anything is forwarded or logged.

### 📊 [Dashboard](dashboard/) — Next.js 15
In-memory ingest broker + Server-Sent Events. A unified, color-coded live feed with per-module status and a session summary (totals, severity distribution, average detection latency).

---

## 🧪 Develop & test a single module

```bash
# 🔧 MCP-Shield (Rust)
cd mcp-shield && cargo test && bash fixtures/run_demo.sh

# 🧠 VectorAnchor (Python)
cd vector-anchor && pip install -r requirements.txt && python -m pytest tests/ && bash fixtures/run_demo.sh

# 💭 TraceAudit (Python)
cd trace-audit && pip install -r requirements.txt && python -m pytest tests/ && bash fixtures/run_demo.sh

# 📊 Dashboard (Next.js)
cd dashboard && npm install && npm run build
```

---

## 🗂️ Project structure

```text
project-black-monolith/
├── mcp-shield/        🔧 Rust MCP proxy — schema fingerprinting + enforce-mode blocking
├── vector-anchor/     🧠 FastAPI retriever proxy — corpus-poisoning quarantine
├── trace-audit/       💭 FastAPI streaming proxy — KL divergence + PII redaction
├── dashboard/         📊 Next.js 15 real-time SSE threat feed
├── docker-compose.yml 🐳 one-command full stack
├── run_full_demo.sh   🎬 end-to-end integration demo
└── .github/           ⚙️ CI (build + test) · issue / PR templates
```

---

## 🧰 Tech stack

**MCP-Shield:** Rust · tokio · serde · hmac/sha2 &nbsp;•&nbsp; **VectorAnchor / TraceAudit:** Python · FastAPI · ChromaDB (embedded) · Ollama (optional) &nbsp;•&nbsp; **Dashboard:** Next.js 15 · React 19 · Server-Sent Events &nbsp;•&nbsp; **Orchestration:** Docker Compose

---

## 🗺️ Roadmap

- [x] MCP-Shield: fingerprinting, sanitizer, enforce-mode blocking
- [x] VectorAnchor: cross-query frequency-anomaly quarantine
- [x] TraceAudit: KL-divergence termination + PII redaction
- [x] Unified real-time dashboard + one-command Docker stack
- [ ] Content-Length framing for MCP-Shield (alongside line-delimited)
- [ ] Semantic embeddings by default for VectorAnchor (sentence-transformers)
- [ ] Persisted event history + filtering in the dashboard

---

## 🤝 Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for setup, conventions, and the golden rule (**keep the shared event shape**). Security reports: [SECURITY.md](SECURITY.md).

## 📜 License

[MIT](LICENSE) © 2026 Sleepers Research.

---

<div align="center">

**Built by Sleepers Research.**
<sub>Originally developed under the working name "AEOS Guard" for a B.E. final-year submission, since renamed to Project Black Monolith. Module names (MCP-Shield, VectorAnchor, TraceAudit) unchanged.</sub>

</div>
