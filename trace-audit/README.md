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
  identical. Connections use finite connect, write, pool, and idle-read
  timeouts; non-success HTTP responses fail before model output is streamed.
- **KL over a token-identity distribution** with an `<other>` catch-all for
  tokens unseen in the baseline. Off-baseline reasoning concentrates mass on
  `<other>` (near-zero baseline mass), which drives KL up sharply.

### Threshold calibration

The termination threshold is **derived, not guessed** — see
[`fixtures/calibration_results.md`](fixtures/calibration_results.md), reproducible
with `python fixtures/calibrate.py`. The baseline is captured from 10 benign
prompts spanning four styles (factual Q&A, creative writing, step-by-step
reasoning, casual conversation); the peak rolling KL of **36 held-out benign
prompts** from eight styles is then measured:

| | mean | std | min | max | divergent fixture |
| :-- | ---: | ---: | ---: | ---: | ---: |
| peak KL | 0.351 | 0.065 | 0.247 | 0.481 | **3.29** |

`mean + 2·std = 0.48` sits right at the benign maximum (0.481), so a strict
2σ cut leaves no margin. The **operating threshold is `1.0`** — ~2.1× above the
worst benign peak and ~0.30× of the divergent fixture. **False-positive test
result: 0 / 36 benign prompts triggered termination**, while the divergent
fixture (3.29) crosses decisively.

> **Known defect — the threshold does not hold against a real model.** The
> derivation above is the mock backend's, and the mock's baseline has 36
> distinct tokens. The number that decides whether the gate can fire at all is
> the *ceiling*: the KL of a window in which every token is off-vocabulary,
> which is the most divergent window this statistic can express. The mock's
> ceiling is 3.29 — exactly what the divergent fixture scores. Measured
> against `qwen2.5:0.5b` on Ollama, a real model's baseline has ~330 tokens
> and the ceiling is **0.59**, so the threshold of 1.0 is *above* it: the gate
> cannot fire, for any answer, from any model. The committed measurement is
> [`fixtures/real_model_calibration.json`](fixtures/real_model_calibration.json),
> the finding is `docs/FINDINGS.md` §12, and `calibration.yml` re-measures it
> on every change to the monitor. **The threshold is not a universal
> constant, and against a real model it is not reachable at all.**

## Endpoints

| Method + path    | Purpose                                                    |
| ---------------- | ---------------------------------------------------------- |
| `GET  /health`   | minimal liveness response                                  |
| `POST /generate` | `{prompt, max_tokens?}` → SSE token stream (audited)        |
| `POST /v1/messages` | Anthropic Messages API, audited (see below)              |
| `GET  /stats`    | admin-authenticated detector + delivery health              |

Each SSE `data:` line is a JSON event: `{type: "token", token, kl, threshold}`,
`{type: "pii", label, redacted}`, `{type: "terminated", reason, kl, safe_refusal}`,
or `{type: "done", peak_kl, tokens}`.

## The Anthropic gateway (`POST /v1/messages`)

`POST /v1/messages` is the Messages API every Anthropic client already
speaks, put behind the auditor. Point a client's base URL at it and the
answer is inspected as it arrives:

- **The client's own credential is forwarded upstream untouched.** The gateway
  holds no key of its own unless the operator configured one as a fallback
  (`MONOLITH_ANTHROPIC_API_KEY`). A request that carries neither header is
  rejected rather than sent unauthenticated.
- **The body is forwarded byte for byte.** The only change is that the
  upstream is always asked to stream, because the audit needs the stream; a
  client that wanted one JSON document gets one, assembled here.
- **The credential in the middle of an answer is redacted** before the client
  sees it, and the redaction is reported to the ledger as `pii_redacted`.
- **Divergence detection is only enabled when the baseline belongs to the
  model being asked.** A baseline captured from a different model would make
  the KL score meaningless — it would terminate ordinary traffic — so the
  gateway disables it and records a one-shot `divergence_disabled` event
  saying why. Credential redaction is model-independent and always runs.
- **The operator's token ceiling is a ceiling.** A request asking for more
  tokens than `MONOLITH_ANTHROPIC_MAX_TOKENS` is rejected with `400` rather
  than silently truncated.
- **The credential is not sent over plain HTTP to a host that is not
  loopback.** The same rule the modules apply to their own delivery applies
  here: HTTPS everywhere, plain HTTP only to a loopback address. A request
  to any other plain-HTTP upstream is refused with `503` before it leaves,
  and the refusal is recorded once as `upstream_transport_refused`. An
  operator whose model service is genuinely on a trusted network can say so
  with `MONOLITH_ALLOW_INSECURE_ANTHROPIC=true`; nobody else can enable it
  by accident.
- **A revoked session is refused** before the upstream is contacted.

To try it with no API key and no credits:

```sh
python fixtures/fake_anthropic_server.py --port 8100 --mode secret
MONOLITH_MODEL_BACKEND=anthropic \
MONOLITH_ANTHROPIC_BASE_URL=http://127.0.0.1:8100 \
  python -m uvicorn src.main:app --port 8002
```

The stub leaks AWS's own published example key — a value that exists in the
AWS documentation so scanners can recognise it, and which is not a credential
to anything.

## Configuration (environment variables)

| Variable                    | Default    | Purpose                                        |
| --------------------------- | ---------- | ---------------------------------------------- |
| `MONOLITH_MODEL_BACKEND`    | `mock`     | `mock` (offline), `ollama`, or `anthropic`      |
| `MONOLITH_OLLAMA_URL`       | `http://localhost:11434` | Ollama base URL (ollama backend) |
| `MONOLITH_OLLAMA_MODEL`     | `llama3.2` | model name (ollama backend)                    |
| `MONOLITH_ANTHROPIC_BASE_URL`| `https://api.anthropic.com` | upstream for the Messages gateway |
| `MONOLITH_ANTHROPIC_API_KEY`| *(unset)*  | fallback credential when the client sends none |
| `MONOLITH_ANTHROPIC_MODEL`  | *(unset)*  | pin the upstream model regardless of the request |
| `MONOLITH_ANTHROPIC_MAX_TOKENS` | `8192` | hard ceiling on `max_tokens` per request     |
| `MONOLITH_ALLOW_INSECURE_ANTHROPIC` | *(unset)* | allow plain HTTP to a non-loopback model upstream on a trusted network |
| `MONOLITH_BASELINE_PATH`    | `./baseline_distribution.json` | baseline distribution file |
| `MONOLITH_KL_THRESHOLD`     | `1.0`      | divergence threshold for termination (derived; see above) |
| `MONOLITH_TA_WINDOW`        | `20`       | rolling token window size                      |
| `MONOLITH_MIN_TOKENS`       | `12`       | minimum tokens before evaluating divergence    |
| `MONOLITH_MAX_TOKENS`       | `60`       | max tokens generated per request               |
| `MONOLITH_DASHBOARD_URL`    | *(unset)*  | if set, events are also POSTed here             |
| `MONOLITH_ALLOW_INSECURE_DASHBOARD` | *(unset)* | allow HTTP delivery on a trusted private network |
| `MONOLITH_EVENT_TOKEN`      | *(unset)*  | module-scoped ingest token; required with dashboard URL |
| `MONOLITH_EVENT_OUTBOX_PATH`| `./event_outbox.db` | bounded SQLite retry/dead-letter queue       |
| `MONOLITH_TENANT_ID`        | `default`  | tenant stamped onto emitted events              |
| `MONOLITH_ADMIN_TOKEN`      | *(unset)*  | bearer token required by `GET /stats`           |

`GET /stats` fails closed: an unconfigured admin credential returns `503`,
and an absent or incorrect bearer token returns `401`.

## Setup & demo

```sh
cd trace-audit
python -m pip install --require-hashes -r requirements.lock

bash fixtures/run_demo.sh                 # baseline -> normal -> divergence -> PII
python -m pytest tests/                   # unit tests, no backend needed
```

Expected demo outcome: normal prompts complete; the divergence prompt
terminates early once KL crosses 1.0 and returns the safe refusal; the PII
prompt's fake credential and email are redacted in the trace (and never
appear raw in the client stream). The script prints `DEMO PASSED`.

## Known limitations

- PII output holds text back in a bounded 256-character look-behind, so a
  credential split across fragments is redacted before any fragment is
  released. A credential longer than that window can outlive it; increasing
  the window trades more first-token latency for more coverage.
- The KL baseline is intentionally small for a fast demo; a production
  baseline would be captured from a large, representative prompt set.
- Divergence detection flags *distributional* anomaly, not semantics — it is
  a stand-in for a real alignment-evasion classifier, not a substitute.
- Against a real model, divergence detection stays **off** until a baseline
  captured from that same model is loaded. The shipped baseline came from the
  mock backend, so scoring a real model's output against it would terminate
  ordinary traffic. Credential redaction is unaffected and always runs.
