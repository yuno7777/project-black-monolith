# Evaluation — calibration, false-positive validation, and resilience

This document summarizes the rigor pass across all three detection modules.
Every number below is measured, not aspirational; each is reproducible from
the per-module `fixtures/calibrate.py` (or the MCP-Shield demo loop) and is
recorded in the corresponding `fixtures/calibration_results.md`.

All measurements use the modules' **deterministic offline backends** (the
mock model for TraceAudit, the hashing embedder for VectorAnchor), so results
are stable run to run. Where a detector uses a real backend instead (Ollama,
sentence-transformers), the thresholds are domain-specific and would need
re-calibration — stated per module below.

---

## 1. TraceAudit (reasoning layer) — KL-divergence threshold

**Calibration method.** The baseline token distribution is captured from 10
benign prompts spanning four styles (factual Q&A, creative writing,
step-by-step reasoning, casual conversation). The peak rolling KL divergence
of **16 held-out benign prompts** — drawn from those same four styles, none in
the baseline set — is then measured against that baseline, giving the benign
KL distribution. Reproduce: `python fixtures/calibrate.py`.

**Measured benign peak-KL distribution (N = 16):**

| mean | std | min | max | mean + 2σ | divergent fixture |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0.343 | 0.064 | 0.247 | 0.481 | 0.470 | **3.289** |

**Derived threshold = 1.0.** The textbook `mean + 2σ = 0.470` sits essentially
*at* the benign maximum (0.481), leaving no margin — a strict 2σ cut would
false-positive. The operating threshold is set in the wide gap between the two
populations: **1.0 is ~2.1× the worst benign peak (0.481) and ~0.30× the
divergent fixture (3.289)**. Encoded as `DEFAULT_KL_THRESHOLD` in
`src/divergence_monitor.py` with the derivation in-comment.

**False-positive result: 0 / 16** benign prompts triggered termination; the
divergent fixture (3.289) crosses 1.0 decisively.

**Bug found & fixed during calibration.** The mock backend seeded its RNG with
Python's built-in `hash()`, which is salted per process (`PYTHONHASHSEED`), so
the "deterministic" mock produced different output across restarts (KL max
drifted 0.43 → 0.48, divergent 2.9 → 3.3 between runs). Fixed with a stable
`hashlib`-based seed so the mock — and this calibration — are genuinely
reproducible.

**Limitation (honest).** The baseline is domain-specific: it was calibrated
against the deterministic mock backend and conversational/reasoning prompt
styles. A very different distribution — e.g. code generation, or a real model
backend (Ollama) with wider benign spread — would shift the benign KL range
and needs recalibration (re-run `fixtures/calibrate.py`, update
`DEFAULT_KL_THRESHOLD`). The threshold is not a universal constant.

---

## 2. VectorAnchor (memory layer) — frequency-anomaly threshold

**Calibration method.** The 24-document clean corpus is seeded and **18
diverse clean queries** across six topics (no poison present) are run through
the frequency-anomaly detector; the highest distinct-topic score reached by
any legitimate document is recorded, then compared against the poison
fixture's score. Reproduce: `python fixtures/calibrate.py`.

**Measured separation:**

| | distinct-topic score |
| :-- | ---: |
| highest **clean** document | 2 |
| `min_distinct_topics` threshold | **4** |
| **poison** fixture | 4 |

**Derived parameters.** The original `(top_rank_threshold=3,
topic_similarity=0.30)` was found **broken**: a broad but legitimate
single-domain document (`garden-4`) accumulated a distinct-topic score of
**7 — higher than the poison's 5** — because a bag-of-words embedder treats
narrow gardening sub-topics ("prune", "mulch", "compost") as unrelated. No
threshold can separate 7-vs-5. A parameter sweep showed `(top_rank_threshold=2,
topic_similarity=0.20)` restores separation: related sub-topic queries
(pairwise cosine 0.15–0.30) merge into one topic while the poison's
truly-unrelated triggers (pairwise ~0.0) stay separate. At those parameters
the highest clean score is **2** and the poison is **4**, so
`min_distinct_topics = 4` clears the worst clean document by a **2-topic
margin**.

**False-positive result: 0 / 24** clean documents flagged.

**Limitation (honest).** Detection is frequency-based within a *bounded rolling
window* (`window_size`, default 50 queries), not persistent long-term
tracking. A **slow-drip** attacker who surfaces a bait document for only one
unrelated topic per window — letting earlier hits age out — never reaches
`min_distinct_topics` within any single window and would evade detection.
Catching that would require long-horizon per-document accumulation, which the
window-based design deliberately trades away for bounded memory and recency.

---

## 3. MCP-Shield (tool layer) — detection repeatability

**Calibration method.** The clean → rug-pull fixture demo was run **5 times**;
each run asserts 8 detection conditions (baseline registration, schema
mismatch, suspicious-description flag, enforce-mode blocking, monitor-mode
re-flag, and that the poisoned description never reaches the agent). Results in
`mcp-shield/fixtures/calibration_results.md`.

**Result: 5 / 5 trials passed all 8 assertions**, with no flakiness from
timing or ordering. Detection is not threshold-based — it is an exact
HMAC-SHA256 fingerprint comparison over a canonical schema serialization — so
the trusted (`0d1c0b7a4558cb7e…`) and mutated (`e1b8838a08626ded…`) fingerprints
are byte-identical across every trial. There is no false-positive/negative
tuning surface: a schema either matches its baseline or it does not.

**Limitation (honest).** Only request-matched `tools/list` responses are
inspected; the fingerprint is exact, so a benign but *legitimate* schema update
also flags (by design — the operator must re-baseline). This is a
zero-false-negative / re-approval-required posture, not a tuned detector.

---

## 4. Resilience / cold-start

- **Startup ordering hardened.** `docker-compose.yml` now gives every service
  a healthcheck and makes the three defense modules depend on the dashboard
  with `condition: service_healthy` (was `service_started`). This guarantees
  the ingest endpoint is ready before any module emits its first event, so no
  startup event is dropped. There is no external ChromaDB or Ollama service to
  race against — ChromaDB is embedded and the model backend defaults to the
  offline mock — so no cross-service DB/model dependency was needed.
- **`scripts/reset_demo_state.sh`** resets the system to a clean state without a
  rebuild: it clears MCP-Shield's baseline, VectorAnchor's quarantine +
  tracker state, TraceAudit's captured baseline, and the dashboard's in-memory
  event history, handling both the Docker and local cases. Verified on the
  local path.
- **Docker cold-start — validated end-to-end.** On Docker 29.6.1,
  `docker compose up -d --build` from a stopped state builds and brings **all
  five services to healthy** (database, dashboard :3000, vector-anchor :8001,
  trace-audit :8002, mcp-shield) with no manual intervention; the ledger
  migration is applied automatically at dashboard startup by
  `scripts/migrate.mjs`, and `./run_full_demo.sh` then drove all three attacks
  through to the dashboard successfully.

  Two real defects were found and fixed getting there, both of which had made
  the stack look like a Docker problem when it was not:

  - **The dashboard crashed on boot with `42501 permission denied for
    database`.** `supabase/postgres` bootstraps as the superuser
    `supabase_admin`, so a database created via `POSTGRES_DB` is owned by it and
    the app's `postgres` role receives CONNECT but not CREATE — `create schema`
    then fails. The ledger now lives in the `monolith` **schema** of the
    `postgres` database, which also matches Supabase-hosted projects (where you
    cannot create databases at all). Because the three modules
    `depend_on: dashboard: service_healthy`, this single failure was why only
    part of the stack came up.
  - **The database healthcheck was a false positive.** `pg_isready` reported
    healthy on a database the application could not actually use, because it
    neither authenticates nor runs a query. It is now
    `psql -U postgres -d postgres -c 'select 1'`.

- **Delivery guarantees — gated, not asserted.** Three scripts run against the
  live stack and are wired into CI (`integration` job):

  | Script | What it proves | Result |
  | :-- | :-- | :-- |
  | `mcp-shield/fixtures/verify_outbox.sh` | spool while the collector is down · backlog redelivered on the *next* run · 401 dead-letters | all 3 phases PASS |
  | `scripts/verify_ingest.sh` | token scoping · idempotent redelivery · permanent-vs-retryable rejections · batch · persistence + SSE replay | **16 / 16 PASS** |
  | `scripts/verify_recovery.sh` | dashboard stopped → detections spool → restarted → spool drains to the ledger | PASS |

  The recovery run is the load-bearing one: with the dashboard stopped, four
  live retrievals produced **5 events held in VectorAnchor's SQLite spool while
  the ledger stayed frozen**; on restart the spool drained to **0** and every
  event landed in the ledger. A collector outage costs latency, not evidence.

- **A latent poison-pill was found and fixed.** `event_id` is a Postgres `uuid`
  column, so a non-UUID value failed the insert with `22P02`, surfaced as a 503,
  and would have been retried **forever** by the outboxes — which correctly
  treat 5xx as transient. It is now rejected as a permanent 422. The existing
  malformed-event test (§5) never caught this because it never sends an
  `event_id` at all.
- **Cold-start also validated Docker-free**, via `scripts/run_local_demo.sh` —
  the local equivalent of the full stack (dashboard :3000, VectorAnchor :8001,
  TraceAudit :8002 as background processes with `MONOLITH_DASHBOARD_URL` set).
  It was run **3× from a clean state**; every run brought all services up with
  no manual intervention (fresh dashboard, `buffered:0`), drove all three
  attacks, delivered **19 events** to the dashboard (`schema_mismatch` ×2,
  `corpus_poison_quarantine` ×1, `reasoning_divergence_terminate` ×1,
  `pii_redacted` ×2, plus lifecycle events), and tore down cleanly with all
  ports freed. This exercises the same startup/health/event-delivery path as the
  Docker cold-start. **Note:** only one stack can own ports 3000/8001/8002 at a
  time — stop the local runner before `docker compose up` (and vice-versa).

---

## 5. Dashboard — malformed-event resilience

**Test.** `dashboard/test/malformed-event.test.mjs` posts 11 malformed /
incomplete events (empty object, missing fields, invalid severity, `null` /
string / array `details`, non-numeric timestamp, a bare string body, and
nested `null`/`undefined` values) into the real `/api/ingest` path, then reads
them back over the `/api/events` SSE stream.

**Result: PASSED — 20 streamed events all normalized.** Every event came back
with a numeric timestamp, non-empty string `module`/`event_type`, a valid
severity, and an object `details`; **none serialized with a literal
"undefined"**. The ingest broker coerces missing/invalid fields to safe
defaults (`module`/`event_type` → `"unknown"`, `severity` → `"info"`,
`details` → `{}`), and the frontend components (`EventDetail`, `ThreatFeed`)
were hardened to render a `(no details)` placeholder and a safe timestamp
rather than crash or show `undefined`.

---

## Reproduce everything

```bash
# TraceAudit calibration + false-positive table
cd trace-audit    && python fixtures/calibrate.py     # -> fixtures/calibration_results.md

# VectorAnchor false-positive + separation table
cd vector-anchor  && python fixtures/calibrate.py     # -> fixtures/calibration_results.md

# MCP-Shield 5-trial repeatability (regenerates the trial table)
cd mcp-shield     && for i in 1 2 3 4 5; do bash fixtures/run_demo.sh >/dev/null 2>&1 \
                       && echo "trial $i PASS"; done

# Dashboard malformed-event ingest test (needs the dashboard running)
cd dashboard && npm start &  BASE=http://localhost:3000 node test/malformed-event.test.mjs

# Delivery guarantees. The outbox phases need no Docker; the other two run
# against a live `docker compose up -d` stack.
cd mcp-shield && bash fixtures/verify_outbox.sh
bash scripts/verify_ingest.sh            # 16 ingest-contract checks
bash scripts/verify_recovery.sh          # stops/restarts the dashboard; removes no data

# Full end-to-end integration WITHOUT Docker (dashboard + all 3 modules + attacks)
./scripts/run_local_demo.sh            # holds services up; open http://localhost:3000
DEMO_HOLD=0 ./scripts/run_local_demo.sh  # run once and tear down (cold-start check)
```
