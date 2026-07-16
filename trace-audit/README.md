# TraceAudit

**Project Black Monolith — reasoning-layer defense (Module 3 of 3)**

TraceAudit sits in front of a model's generation endpoint and watches the
token stream in real time. It defends the reasoning layer two ways:

1. **Reasoning divergence.** It builds a baseline token distribution from
   normal prompts, then computes a rolling **KL divergence** of the live
   stream against that baseline. If the trace wanders far off-distribution
   (a stand-in for alignment-evasion-style / roundabout reasoning), it
   **terminates the stream early** and returns a standardized safe refusal
   instead of continuing to forward tokens.
2. **PII / credential leakage.** A regex scanner runs on the streaming trace;
   on a match the span is **redacted before anything is forwarded, logged, or
   persisted**, and an event fires. A secret that surfaces in the reasoning
   trace never reaches the client or the logs in the clear.

## How it works

```text
  agent ──POST /generate──▶ TraceAudit ──prompt──▶ model backend (mock | ollama)
                              │  StreamAuditor (per token):
                              │   ├─ pii_scanner + redaction  (redact secrets)
                              │   ├─ divergence_monitor        (rolling KL vs baseline)
                              │   └─ terminate + safe refusal if KL >= threshold
  agent ◀──SSE token stream──┘   (redacted; truncated on divergence)
```

- `src/stream_proxy.py` — backend wrapper + per-token security orchestration.
- `src/divergence_monitor.py` — rolling KL-divergence monitor (pure Python).
- `src/pii_scanner.py` — regex scanner for credential/PII patterns.
- `src/redaction.py` — span redaction (runs before any logging).
- `src/events.py` — shared Monolith event shape, delivered through a durable
  WAL-backed SQLite outbox: events are spooled locally and delivered on a
  background thread with exponential backoff, so a dashboard outage delays
  delivery rather than losing the detection. Permanent rejections
  (401/422/…) are dead-lettered instead of retried forever.
- `src/main.py` — FastAPI streaming (SSE) app.

## Design decisions (noted for the reviewer)

- **Model backend.** Default is `mock`: a deterministic, offline stand-in
  model, so the demo runs with **no model download**. Its output distribution
  depends on the prompt exactly as a real model's would — an ordinary prompt
  yields normal reasoning tokens; a prompt pushing for roundabout/evasive
  reasoning yields off-distribution tokens; a prompt whose context contains a
  credential-looking string causes the mock to "leak" it into the trace (so
  the PII path has something to catch). Set `MONOLITH_MODEL_BACKEND=ollama`
  and `MONOLITH_OLLAMA_URL` to stream from a real local Ollama server (or any
  compatible `/api/generate` endpoint) instead — the detection logic is
  identical.
- **KL over a token-identity distribution** with an `<other>` catch-all for
  tokens unseen in the baseline. Off-baseline reasoning concentrates mass on
  `<other>` (near-zero baseline mass), which drives KL up sharply.

### Threshold calibration

The termination threshold is **derived, not guessed** — see
[`fixtures/calibration_results.md`](fixtures/calibration_results.md), reproducible
with `python fixtures/calibrate.py`. The baseline is captured from 10 benign
prompts spanning four styles (factual Q&A, creative writing, step-by-step
reasoning, casual conversation); the peak rolling KL of **16 held-out benign
prompts** from those same styles is then measured:

| | mean | std | min | max | divergent fixture |
| :-- | ---: | ---: | ---: | ---: | ---: |
| peak KL | 0.343 | 0.064 | 0.247 | 0.481 | **3.29** |

`mean + 2·std = 0.47` sits right at the benign maximum (0.481), so a strict
2σ cut leaves no margin. The **operating threshold is `1.0`** — ~2.1× above the
worst benign peak and ~0.30× of the divergent fixture. **False-positive test
result: 0 / 16 benign prompts triggered termination**, while the divergent
fixture (3.29) crosses decisively.

> **Limitation — the baseline is domain-specific.** It was calibrated against
> the deterministic mock backend and conversational/reasoning prompt styles.
> A very different distribution — e.g. code generation, or a real model backend
> (Ollama) with wider benign spread — would shift the benign KL range and needs
> recalibration (re-run `fixtures/calibrate.py` and update
> `DEFAULT_KL_THRESHOLD`). The threshold is not a universal constant.

## Endpoints

| Method + path    | Purpose                                                    |
| ---------------- | ---------------------------------------------------------- |
| `GET  /health`   | liveness + backend + baseline status                       |
| `POST /generate` | `{prompt, max_tokens?}` → SSE token stream (audited)        |
| `GET  /stats`    | detector configuration                                     |

Each SSE `data:` line is a JSON event: `{type: "token", token, kl, threshold}`,
`{type: "pii", label, redacted}`, `{type: "terminated", reason, kl, safe_refusal}`,
or `{type: "done", peak_kl, tokens}`.

## Configuration (environment variables)

| Variable                    | Default    | Purpose                                        |
| --------------------------- | ---------- | ---------------------------------------------- |
| `MONOLITH_MODEL_BACKEND`    | `mock`     | `mock` (offline) or `ollama`                   |
| `MONOLITH_OLLAMA_URL`       | `http://localhost:11434` | Ollama base URL (ollama backend) |
| `MONOLITH_OLLAMA_MODEL`     | `llama3.2` | model name (ollama backend)                    |
| `MONOLITH_BASELINE_PATH`    | `./baseline_distribution.json` | baseline distribution file |
| `MONOLITH_KL_THRESHOLD`     | `1.0`      | divergence threshold for termination (derived; see above) |
| `MONOLITH_TA_WINDOW`        | `20`       | rolling token window size                      |
| `MONOLITH_MIN_TOKENS`       | `12`       | minimum tokens before evaluating divergence    |
| `MONOLITH_MAX_TOKENS`       | `60`       | max tokens generated per request               |
| `MONOLITH_DASHBOARD_URL`    | *(unset)*  | if set, events are also POSTed here             |

## Setup & demo

```sh
cd trace-audit
pip install -r requirements.txt          # mock backend needs only stdlib + fastapi/uvicorn

bash fixtures/run_demo.sh                 # baseline -> normal -> divergence -> PII
python -m pytest tests/                   # unit tests, no backend needed
```

Expected demo outcome: normal prompts complete; the divergence prompt
terminates early once KL crosses 1.0 and returns the safe refusal; the PII
prompt's fake credential and email are redacted in the trace (and never
appear raw in the client stream). The script prints `DEMO PASSED`.

## Known limitations

- The PII scanner is per-token plus a running scan; a secret split across
  token boundaries by a real tokenizer could evade the per-token check
  (a production version would scan a sliding character window with overlap).
- The KL baseline is intentionally small for a fast demo; a production
  baseline would be captured from a large, representative prompt set.
- Divergence detection flags *distributional* anomaly, not semantics — it is
  a stand-in for a real alignment-evasion classifier, not a substitute.
