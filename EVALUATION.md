# Evaluation — calibration, false-positive validation, and resilience

This document summarizes the rigor pass across all three detection modules and
the console in front of them. Every number below is measured, not aspirational,
and every claim has a command that reproduces it — see
[Reproduce everything](#reproduce-everything). Detector thresholds come from the
per-module `fixtures/calibrate.py` and are recorded in the corresponding
`fixtures/calibration_results.md`; the delivery, lifecycle and resilience results
come from the `verify_*.sh` harnesses, which are gated in CI so these numbers
cannot quietly stop being true.

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

**Limitation — measured, not asserted.** Detection is frequency-based within a
*bounded rolling window* (`window_size`, default 50 queries), not persistent
long-term tracking. A **slow-drip** attacker who surfaces a bait document for
one unrelated topic per window — letting earlier hits age out — never reaches
`min_distinct_topics` within any single window. This evasion was **built and
confirmed to work** (§7): the bait peaks at a score of 1 against a threshold of
4 while covering 12 distinct topics. The cost to the attacker is ~50 covering
retrievals per hidden topic, which makes `window_size` — not
`min_distinct_topics` — the parameter that actually prices the attack. Catching
it would require long-horizon per-document accumulation, which the window-based
design deliberately trades away for bounded memory and recency.

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

**First-contact trust — measured (§7).** A tool poisoned the *first* time it is
ever seen has no clean baseline to compare against, so it is registered as-is
and enforce mode has nothing to rewrite to. Confirmed by test. The blast radius
is bounded in both directions: the sanitizer is stateless, so the poisoning is
still *reported* on first sighting, and any later mutation still flags — the
attacker buys one serving and must stay poisoned to stay hidden.

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

## 6. Incident lifecycle — integrity of the triage record

A detector that fires and is never acted on is not a defense, so the ledger
carries an incident lifecycle (assign → acknowledge → resolve) on top of the
event record. What is evaluated here is not that the buttons work but that the
**record cannot lie**.

**Test.** `scripts/verify_incidents.sh` seeds an event, walks it through the
lifecycle against the live stack, and asserts the invariants.

**Result: PASSED — 33 / 33 checks.**

| Property under test | Why it matters | Result |
| :-- | :-- | :-- |
| An untriaged event still appears in the open queue | Triage rows are created lazily, so an event with no row must not be invisible — that would mean detections silently never reach an analyst | PASS |
| Resolving requires a verdict | A "resolved" queue with no verdict is a hidden queue; without it the false-positive rate (§1, §2) can never be recovered from production data | PASS (`422` without one) |
| Omitting a field never clears it | Found a real defect: resolving without restating the assignee **silently unassigned the incident**, erasing who made the call | PASS (after fix) |
| Reopening clears the stale verdict | A reopened incident that still reads "false positive" is worse than no label | PASS |
| Triage never mutates the event | `security_events` is evidence; judgement about it lives in a separate table | PASS (severity unchanged) |
| The audit trail rejects `UPDATE` | "Who cleared this critical, and why" must survive later edits | PASS (trigger raises) |
| The audit trail rejects `DELETE` | As above — a deletable trail is not a trail | PASS (trigger raises) |
| Every transition is recorded | The trail is written in the **same transaction** as the state change, so an unaccounted-for change is impossible | PASS (3 / 3) |

Two design points the tests pin down:

- **Append-only is enforced by a trigger, not a `REVOKE`.** A `REVOKE` does not
  bind the table's owner, which is the role the application connects as, so it
  would have been a comment rather than a control.
- **The actor is derived from the credential, never from the request.** Triage
  requires an operator token, separate from the per-module ingest tokens — if a
  module token worked here, any module could close its own findings. The body's
  `actor` is ignored outright, and the tests confirm a forged name reaches
  neither the triage row nor the trail. Missing configuration returns **503 and
  refuses every write**: an authenticator that was never set up must not be
  mistaken for one that passed.

  **Remaining gap, stated plainly:** `GET /api/incidents` is still
  unauthenticated, and the token is a bearer credential in `localStorage` with
  no sessions, expiry or rotation. The trail is now tamper-evident *and*
  attributable on a single-operator stack; it is not an identity layer, and a
  multi-user deployment needs real sessions in front of these routes.

---

## 7. Adversarial evaluation — do the known evasions actually work?

Sections 1–3 measure the detectors against the attacks they are built for. This
section does the opposite: it takes the three evasions the module READMEs admit
in prose and **builds each one, to find out whether the admission is true**.

**All three evasions succeed.** That is the result, and it is reported rather
than buried: a limitation stated with a number is a boundary, the same
limitation stated in prose is a hope. Each is now a test that asserts the
detector *misses* the attack, so if anyone later closes a gap, a failing test
forces the claim to be updated rather than left stale.

| Evasion | Module | Outcome | Measured cost / bound |
| :-- | :-- | :-- | :-- |
| **Slow drip** — surface the bait for one topic per window, let earlier hits age out | VectorAnchor | **Evades.** Peak score 1 vs. a threshold of 4, across 12 distinct topics — 3× the threshold | ~50 covering retrievals per hidden topic (= `window_size`). Drip any faster and it is caught |
| **Token-boundary split** — a secret the tokenizer splits across two tokens | TraceAudit | **Evades.** All 19 possible split points of a 20-char key match neither half | Bounded: only the split secret is missed; an unsplit secret in the same trace is still caught |
| **First-contact poisoning** — the tool is poisoned the first time it is ever seen | MCP-Shield | **Not blocked.** No clean baseline exists to compare or rewrite to | Bounded: still *reported* by the sanitizer, and any later mutation is still caught |

Reproduce: `python -m pytest tests/test_evasion.py` in `vector-anchor/` and
`trace-audit/`; `cargo test known_evasion` in `mcp-shield/`.

What the numbers say beyond "it evades":

- **VectorAnchor's real security parameter is `window_size`, not
  `min_distinct_topics`.** The threshold is what the attacker must stay under;
  the window is what sets the price of doing so. At the shipped window of 50 the
  attacker needs ~50 covering retrievals per topic they want to hide — and the
  test pins the boundary by showing that hits spaced to co-exist inside one
  window are still caught. Raising the window raises the cost linearly, at the
  price of memory and recency.
- **TraceAudit's gap is a windowing choice, not a detection ceiling.**
  Concatenating the fragments — what a sliding character window with overlap
  would do — recovers the secret the per-token scan missed. The regexes are
  fine; the input they are handed is not. This also corrected a docstring in
  `pii_scanner.py` that claimed it "runs against the rolling text buffer": it
  does not, `stream_proxy` hands it one token at a time.
- **MCP-Shield's gap is inherent to trust-on-first-use**, not a detector bug,
  and it is the shallowest of the three: the attack is reported (the sanitizer
  is stateless and needs no baseline) and buys exactly one serving, since any
  later mutation still flags. It is a gap, not a hole.

---

## 8. Detection overhead — what does the defense cost?

Every module here sits **inline** on the path it protects, so its cost is paid
on every request an agent makes. A detector nobody can afford to run is not a
defense, so the price is measured rather than assumed.

**Method.** Each benchmark times *only what the defense adds*. The model's
generation, the vector search, and the child MCP server's own work are excluded:
they happen with or without this project, and charging them to the defense would
flatter it. Each detector is warmed to its steady state first — a full rolling
window, a monitor past `min_tokens_before_check`, regexes already built —
because the cold path is not the one that runs in production.

**Measured on the development machine (Windows 11, Docker 29.6.1). Timings are
machine-specific; the reproduction commands are below.**

| Module | Unit of work | mean | median | p95 | p99 |
| :-- | :-- | ---: | ---: | ---: | ---: |
| **MCP-Shield** | per tool in a `tools/list` (canonical serialize + HMAC-SHA256 + description scan) | **6.4 µs** | 5.1 µs | 7.4 µs | 12.5 µs |
| **TraceAudit** | per streamed token (PII scan + rolling KL update) | **13.0 µs** | 11.8 µs | 16.9 µs | 30.0 µs |
| **VectorAnchor** | per `/retrieve` (record the query + cluster each returned doc's history) | **295.7 µs** | 273.5 µs | 513.2 µs | 711.7 µs |

In terms an operator would care about:

- A **20-tool `tools/list`** costs **~0.13 ms** of analysis — against a proxied
  process spawn and JSON-RPC round trip, this is free.
- A **60-token response** costs **~0.78 ms** of auditing spread across the whole
  stream — roughly 13 µs added to each token's latency, against a model that
  takes tens of milliseconds per token. Invisible.
- A **retrieval** costs **~0.3 ms**, the most expensive of the three and the one
  worth watching. It is dominated by the topic clustering, which is quadratic in
  the number of queries a document has ranked for within the window — so the
  cost scales with `window_size`, the same parameter §7 identifies as what
  prices the slow-drip evasion. **Widening the window to resist slow-drip makes
  retrieval more expensive; that trade-off is the real design knob**, and it is
  the thing to measure again before changing it.

**Honest notes.** These are single-machine numbers with no cross-run variance
analysis, and the `max` column is dominated by scheduler noise and GC rather
than the detector (VectorAnchor's 5.9 ms max against a 274 µs median is an
outlier, not a tail). They establish an order of magnitude — "microseconds, not
milliseconds" for the two inline hot paths — which is the claim being made, not
a throughput benchmark.

**Not gated in CI.** Timings vary by runner, and a benchmark that fails on a
noisy machine teaches people to ignore failures. The MCP-Shield benchmark is
`#[ignore]`d for the same reason and must be asked for explicitly.

```bash
cd mcp-shield    && cargo test --release benchmark -- --ignored --nocapture
cd vector-anchor && python fixtures/benchmark.py
cd trace-audit   && python fixtures/benchmark.py
```

---

## 9. Dashboard — theme contrast

**Test.** Both themes were audited by computing WCAG 2.1 contrast ratios for 19
text/background pairs, compositing every translucent surface down to an opaque
colour rather than trusting the token values (the cards are glass over a black
canvas, so the declared colour is not the rendered one).

**Result: PASSED — 19 / 19 pairs meet AA (4.5:1) in both themes**; worst case
4.53:1 (light) and 5.10:1 (dark).

This found a real defect. The light palette had been written as a tonal mirror
of the dark one, which does not survive inversion: muted text (timestamps, card
subtitles, KPI labels — 10–11.5px, so "small text" under WCAG) measured
**2.2–2.5:1 against the near-white cards** and was effectively unreadable. Dark
mode was also borderline at 3.7:1 on the same labels. Both ink steps were moved
so the hierarchy stays ordered.

> **Method note.** The measurements are taken with transitions disabled. Reading
> a transitioned property immediately after switching themes returns the *old*
> value, which silently produces a page of fake failures — an artifact worth
> knowing about before trusting any automated audit of a themed UI.

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

# Adversarial evaluation — do the documented evasions actually work?
cd vector-anchor && python -m pytest tests/test_evasion.py -q
cd trace-audit   && python -m pytest tests/test_evasion.py -q
cd mcp-shield    && cargo test known_evasion

# Detection overhead (machine-specific; not gated in CI)
cd mcp-shield    && cargo test --release benchmark -- --ignored --nocapture
cd vector-anchor && python fixtures/benchmark.py
cd trace-audit   && python fixtures/benchmark.py

# Dashboard malformed-event ingest test (needs the dashboard running)
cd dashboard && npm start &  BASE=http://localhost:3000 node test/malformed-event.test.mjs

# Delivery guarantees. The outbox phases need no Docker; the other two run
# against a live `docker compose up -d` stack.
cd mcp-shield && bash fixtures/verify_outbox.sh
bash scripts/verify_ingest.sh            # 16 ingest-contract checks
bash scripts/verify_recovery.sh          # stops/restarts the dashboard; removes no data
bash scripts/verify_incidents.sh         # 33 incident-lifecycle checks
bash scripts/verify_correlation.sh       # 13 cross-layer correlation checks

# Full end-to-end integration WITHOUT Docker (dashboard + all 3 modules + attacks)
./scripts/run_local_demo.sh            # holds services up; open http://localhost:3000
DEMO_HOLD=0 ./scripts/run_local_demo.sh  # run once and tear down (cold-start check)
```
