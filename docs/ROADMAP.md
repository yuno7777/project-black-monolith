# Roadmap — the next phase of Project Black Monolith

**Written 2026-10-21.** This is the plan for what happens after the current
release line. It is a work list with acceptance criteria, not a set of
decisions: the open trade-offs live in [`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md)
and the defects it draws on live in [`FINDINGS.md`](FINDINGS.md).

## Where this came from

Eleven subsystems were surveyed separately — the tool layer, the memory layer,
the reasoning layer, the Secret Boundary, the dashboard, the launcher, the
event contract, the operations paths, the evaluation fixtures, the deployment
and the documentation. Sixty-six raw gaps were found; the sixteen that
survived deduplication were each deep-dived and then attacked by three
independent reviewers with different lenses (does it reproduce, is it real, is
it already done, is it worth doing now). None of the sixteen was refuted. The
result was then cross-checked against `docs/FINDINGS.md`, which carries eleven
verified defects, ten test gaps and five documentation drifts recorded by
earlier sessions, and against the repository as it actually stands.

Where the two disagree, this roadmap takes the stricter reading. Where the
repository has moved since the survey — work that has since been merged, or a
branch that turns out to be a duplicate — the plan says so rather than
scheduling it again.

## Where the project actually is

The repository is a working, defended system rather than a prototype. The
three layers detect, the outboxes deliver durably, the dashboard persists
before it publishes, and the cross-layer breaker revokes a session that two
layers independently agree on. The remaining work is not "build the product"
work. It is the work of a security product that has to be able to say — with
evidence — that each layer is defended.

Two things follow from that, and they set the shape of everything below.

**First, the most valuable work is making a claim testable.** Several of the
strongest claims the project makes are currently unfalsifiable: the reasoning
layer's divergence detector has never been observed in its armed state, the
sanitizer's accuracy gate is scored against fourteen strings the author wrote
himself, the MCP-Shield gaps have no adversarial fixtures at all, and the
Secret Boundary's advertised zeroization invariant is not upheld for the copy
that leaves the process. A control that cannot fail is not evidence.

**Second, the remaining defects are concentrated in the paths that decide
whether a defence is on.** Not in the detectors — those are the part that
works — but in the code that turns a detector's output into enforcement: the
baseline write, the trust store, the snapshot the modules poll, the
credential the status listener falls back to. A detector that is right and an
enforcement path that is wrong is a product that reports defences it does not
have.

**A third thing, which is new.** The event contract is the one thing the four
modules share, and it is the one thing still mostly *assumed*. The dashboard
mints an event id when a module did not supply one, which is the one thing
that must never happen to an idempotency key. A contract that is documented,
versioned, and then quietly re-interpreted at the edge is not a contract.

## The milestones

Ordered by dependency, then by what unblocks the most. Effort is in working
days for one engineer and is a rough order of magnitude, not an estimate.

---

### M1 — Land what is written, and delete what is not

**Effort: 2 days. Blocks everything else.**

Several bodies of work are in flight against a `main` that has moved past
their fork points. Nothing new can be demonstrated against `main` until these
are on it, and a milestone written against a tree that does not exist is a
milestone that gets re-planned.

- **Land the working tree as one reviewable security PR.** It carries the
  ingest rate limit, the bounded revocation snapshot, the admin-token
  separation, the live-listener reconnect, the console's truth-telling and the
  delivery read-failure handling. Its acceptance is the full suite green and
  the branch's diff touching each file additively.
- **Rebase and land PR #65** (`fix/gateway-review-fixes`, 15 commits). It
  already carries the model-aware baseline capture (`6041854`), the
  session-scoped session report (`ac1b5f8`), the launcher credential-hygiene
  work (`577908c`, `d40cf05`) and the shield credential-hygiene work
  (`84c2314`) — none of that is new work, and none of it should be scheduled
  again. After the rebase its diff must show `main`'s alert-outbox
  transaction fix and the session-report fix as *additive*, never as a
  reversion.
- **Reconcile PR #67** (`fix/vector-anchor/truncated-error-body`). `main`
  already carries `be31121`, which is the same fix; the branch's `29743c9` is a
  different implementation of the same change plus two documentation files.
  Close it if it adds nothing, rebase it if it does — but do not merge a
  second implementation of a fix that is already live.
- **Land `chore/build-context-and-ci-timeout`**, which supplies
  `scripts/check_dockerignore.py` and the CI job that runs it. The root
  `.dockerignore` is now the only one: the per-module copies are already gone,
  and every image builds from the repository root.
- **Delete, do not merge: `feature/active`.** All 310 of its commits are
  already in `main`, patch for patch, and it has no merge base with `main` at
  all. `fix/tenant-scoped-dead-letter-replay` is the same change as the
  already-merged `#59` and differs only in the commit.
- **Reconcile `docs/FINDINGS.md` with the tree.** It is the shared backlog.
  Move the sections whose defects this roadmap has closed into "Already
  fixed", naming the PR that closed each one, and correct every row that
  describes a state that no longer exists.

**Acceptance:** `gh pr list --state open` is empty, `main` is the only branch
carrying unmerged work, a fresh clone builds green under CI, and
`docs/FINDINGS.md` describes the tree that exists.

---

### M2 — The event contract is enforced, not assumed

**Effort: ~5 days.**

The contract is what the four modules share. It is also the thing that is
least checked. `dashboard/lib/event-store.ts` still calls `randomUUID()` when
a module supplies no `event_id`, while
`contracts/schemas/event-envelope.v2.schema.json` lists `event_id` as
required — the dashboard is the only component that disagrees with the
contract, and it disagrees by inventing identity. The Postgres `uuid` column
is the idempotency key, so a minted id turns a redelivered event into two
events, and a non-UUID id from a module is a permanent 422 that dead-letters
forever.

- **Make `event_id` mandatory at ingest.** `normalizeEvent` must reject a
  missing or malformed `event_id` with a permanent 422 rather than minting
  one. The dashboard's own live test
  (`dashboard/test/malformed-event.test.mjs`) currently asserts the opposite
  — that a body with no `event_id` is accepted and defaulted — so that file
  changes in the same commit, and it runs against a live stack rather than in
  `npm test`.
- **Wire every dashboard test file into CI.** The test script names its
  files explicitly, because `cmd.exe` does not expand a glob. That makes the
  list a thing somebody has to remember to update, and the failure is silent:
  a test that is not named never runs. `dashboard/scripts/check-test-wiring.mjs`
  now fails when a test file on disk is not named by the script, when the
  script names a file that is gone, or when a live-stack test is named by no
  workflow.
- **Put every schema under `contracts/` in the contract check.**
  `contracts/check_contracts.py` loads its schemas by name, and the
  revocation snapshot's was not among them — a schema that nothing validates
  is a schema that drifts.
- **Pin the transient-versus-permanent split in both outboxes, 429 included.**
  `PERMANENT_HTTP_STATUSES` in the shared Python package and `is_permanent` in
  the Rust spool must agree: 429, 500, 502, 503 and 504 are transient; 400,
  401, 403, 413 and 422 are permanent. 429 matters more now than it did — it
  is the ingest rate limiter's answer, and a module over its budget must be
  told to wait, not dead-lettered.
- **Bound the payload instead of losing the event.** An event above the size
  limit is delivered with the oversized field trimmed and the size recorded,
  not raised out of the emitter.
- **Assert that the console counts events, not frames.** The same
  `event_id` delivered twice is one detection.

**Acceptance:** a module that emits a bad event id gets a permanent 422
rather than a silently double-counted event; `npm test` and
`python contracts/check_contracts.py` run every test file and every schema in
the repository; a feed carrying one event twice shows one detection.

---

### M3 — The tool layer cannot be switched off by the server

**Effort: ~25 days. The largest milestone, and the one that decides whether
the tool layer's guarantees are real.**

The tool layer is the layer with the most findings, and they share a shape:
in each case the *server* can influence whether the defence applies. This is
the hardest class of bug to find by testing, because the test has to behave
like an attacker who also speaks the protocol.

- **Correlation-first routing.** A response must be analysed because it
  answers a `tools/list` request the shield sent — matched on the JSON-RPC
  id in the pending queue — not because the payload claims to be a response.
  `is_response()` and `is_jsonrpc_2()` must not be able to veto the analysis.
- **No silent skip.** When the layer declines to analyse — no `result.content`,
  a block that is not text, an unparseable result — it must say so in an
  event rather than returning `Ok(None)` and forwarding.
- **Scan the whole tool object, not just the description,** and record which
  axis a finding came from, so an operator can tell a poisoned tool from a
  poisoned answer.
- **Scope the trust store by MCP server identity.** Two servers that expose a
  tool of the same name collide today: the first one seen establishes the
  baseline and the second one's tools are judged against it. The store is
  keyed by tool name alone, where it must be keyed by (server, tool), with a
  `format_version` and a migration that fails closed on a file it cannot
  read.
- **Put the server id in the shield's events,** and have the launcher supply
  a stable one per MCP server entry, so the dashboard can group detections by
  server.
- **Rewrite faithfully.** An enforced rewrite must change only the poisoned
  field and leave the rest of the response identical, and a rewrite that
  could not be built must be reported as *not enforced* rather than claimed.
- **Build the sanitizer's accuracy gate from a labelled corpus that was not
  written in the same sitting as the detector.** The gate is scored against
  fourteen strings the author wrote himself, so it cannot fail, and it
  therefore reports a score that means nothing.
- **Add a hostile-matrix CI gate.** A fixture that serves a `tools/list`
  response in every shape the layer claims to handle, and a test that fails
  when a shape is added to the matrix and the code silently skips it.
- **Make the benchmarks honest.** Every published number states its corpus,
  its machine and its measured baseline, and the README quotes only numbers a
  committed run reproduces.

**Acceptance:** each item has a fixture that fails before the fix and passes
after it; a server that lies about its protocol, its method or the shape of
its result is still fingerprinted, still scanned, and either rewritten or
reported; an operator approves a tool for one server and not another.

---

### M4 — The reasoning layer is actually armed

**Effort: ~10 days. The highest-severity claim in the project that is
currently false.**

TraceAudit ships a divergence monitor that, in every configuration the
repository has shipped, was not doing anything. The baseline comes from the
mock backend, so scoring a real model's output against it would terminate
ordinary traffic — the right call — but the gate that disables it exists on
exactly one of the three routes that can produce an answer.

- **Apply one model-bound gate to all three audit call sites** in
  `trace-audit/src/main.py`, not just `/v1/messages`.
- **Make `divergence_enabled` a required keyword-only argument** in
  `stream_proxy.py`, so a caller that forgets it cannot get a divergence
  check scored against a mismatched baseline.
- **Add an Anthropic backend dispatch.** `_backend_stream` falls through to
  the mock for everything it does not recognise, so an Anthropic configuration
  silently produces mock output while claiming to be a real backend.
- **Report the armed state from `/stats`:** `divergence_armed`,
  `baseline_model` and `effective_model`, so an operator can ask the layer
  whether it is armed and get a truthful answer.
- **Make the baseline capture record the model it captured from,** and make
  the two fallback baseline paths real or gone, so a missing baseline is a
  clear error rather than a silent fallback.
- **Make the documentation say what is actually on** — that the shipped
  baseline came from the mock backend, that divergence is therefore disarmed
  against a real model, and how to capture one that matches.
- **Observe the armed path.** A test must exercise a baseline whose recorded
  model matches the answering model, a divergent answer, and the stream
  terminated — and it must fail if the model comparison is inverted. The
  disarmed paths stay covered too.

**Acceptance:** an operator can ask the reasoning layer whether it is armed
and get a truthful answer; no route scores a model's output against a baseline
recorded from a different model; no configuration silently produces mock output
while claiming to be a real backend.

---

### M5 — The memory layer cannot go quietly blind

**Effort: ~10 days.**

The memory layer's state file is where the detection reach lives, and three
things go wrong with it. `detector_state.py` raises on a state file over
`MAX_STATE_BYTES` only after `json.dumps` has already allocated the payload,
and the load path then constructs a *fresh* `Quarantine()` — so an oversized
file destroys the quarantine the layer had earned. The state is persisted
inside the lock and the retrieval event is emitted afterwards, so a failed
write produces a retrieval with no event and no trace. And the flush happens
only when there is a new quarantine, so a crash loses everything unflushed.

- **Preserve the quarantine across every load failure** — a policy mismatch
  and an unreadable state file alike.
- **Trim, don't raise:** check the size before the allocation and trim the
  retained hits to fit the budget.
- **Emit an event on a failed persist,** and do not report a detection whose
  state was not saved.
- **Make shutdown unconditional and act on the flush result** — the service
  must emit its stop event even when the state load failed.
- **Set a flush cadence,** and document it.
- **Measure the state budget.** The 32 MiB ceiling has no measurement behind
  it. Measure the real per-document cost, set the ceiling from the
  measurement, and re-run the calibration and the benchmark as
  `EVALUATION.md` §2a requires.
- **Make a refused retrieval a first-class, ledger-visible outcome** rather
  than a silent drop.

**Acceptance:** a state file that cannot be read, is too large, or cannot be
written produces a ledger entry and a preserved quarantine, never a silent
reset; the memory layer's budget is a number the benchmark produced.

---

### M6 — The Secret Boundary is operable, and the release is cut

**Effort: ~29 days. The largest single block of work, and the one furthest
from the demo.**

The boundary is the strongest capability in the repository and the least
usable: it is not in the shipped deployment path, it has no operator surface,
and its provider interface cannot express caching, rotation, TTL, multi-part
credentials or the cloud secret managers.

- **Wire the boundary into the launcher with a preflight.** The launcher
  cannot turn it on at all today, and it must refuse to start with a clear
  message when the configuration is missing or unparseable — and it must
  never pass the configuration path to the agent.
- **Add a header allowlist** to the outbound request. The headers the tool
  call supplied are copied wholesale today, so a hostile `Authorization`,
  `Cookie` or `X-Forwarded-*` header reaches the upstream.
- **Make the configuration coherent:** a duplicate tool name and a mismatched
  operation id must be rejected with a named error, and there must be one
  construction path rather than two, one of which bypasses the `agent_id`
  check.
- **Emit `policy_version` on live events,** so a decision in the ledger says
  which policy made it.
- **Narrow the zeroization claim.** The crate must not claim memory
  zeroization the adapter does not perform, and the threat model must say
  what is and is not true.
- **Cut `0.3.0-rc.1` with one version in every carrier** — the dashboard,
  the shield, the Secret Boundary crate, the shared Python package and the
  memory layer's MCP server. The changelog's own header names four of the
  five.
- **Cut the changelog and reconcile this roadmap** — a release section that
  lists what changed, and one roadmap rather than two.

**Acceptance:** an operator sets one environment variable and the Secret
Boundary is on, refuses to start on a broken configuration, and shows its
decisions in the ledger with a policy version; the repository has one
version, one changelog and one roadmap.

## Explicitly not in this roadmap

- **A new detection.** The detectors are the part that works; the findings
  are in the enforcement paths around them.
- **A shared library across the four parts.** The layers stay decoupled. The
  one shared package — `python-common/monolith_events` — is the event emitter
  and its outbox, and the Rust side re-implements the same contract against
  the same schema on purpose.
- **Rewriting the launcher.** It is standard library only, it reads `.env` by
  parsing it, and it forwards the agent's own credential untouched. Those are
  properties to keep, not problems to solve.
- **A second telemetry path.** The ledger already carries the numbers and the
  console computes them from it. A metrics endpoint would be a second truth.
- **A production accuracy claim.** The corpora are synthetic and small. The
  goal is evidence, not a number to quote.

## How to work it

Take the milestones in order. M1 is two days and unblocks everything else.
M3 and M4 are independent of each other and can run in parallel with separate
worktrees — M3 touches `mcp-shield/`, M4 touches `trace-audit/`, and they
share no file. M2, M5 and M6 touch the dashboard, the shared Python package
and the Rust spool; they are one writer at a time.

Every item above has an acceptance criterion, and a fix that lands without
its criterion is a fix to the wrong thing. Every milestone changes a
defence, so a regression that turns a fail-closed control into a fail-open
one is worse than the defect it fixes — which is why each acceptance test
runs in CI on every push, and not only on the author's machine.
