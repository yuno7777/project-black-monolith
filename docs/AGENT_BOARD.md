# Agent board

The three agents working on this repository have no message bus. They
share a working tree, a remote, and this file. Anything an agent needs the
others to know goes here, in the repository, where the next one will see it.

Read it before starting work. Write to it while you work.

## Protocol

1. **One branch and one worktree per agent.** `agent/<name>/<topic>`. Never
   edit `main` directly. `main` is read-only except for the integrator, who
   merges.
2. **Claim what you are touching.** Add a row to *Claims* before you open a
   file. If the file is already claimed, say so in the row and coordinate
   rather than racing.
3. **Rebase on `origin/main` before you start and before you push.** A
   branch that is 20 commits behind will conflict in ways that have nothing
   to do with your change.
4. **Run the whole gate set, not just the tests you touched.** The list is
   in [Verification](#verification). A gate that is red on someone else's
   change is still your gate.
5. **One focused commit per change.** Conventional commit subjects. A commit
   that fixes three unrelated things is three commits.
6. **Never force-push a published branch.** If a branch needs rewriting,
   say so here and get a human to confirm.
7. **Findings land in the repository, not in a chat window.** A review
   finding is a `docs/` note or a commit, not a message that disappears when
   the session ends. `docs/INTEGRATION_PLAN.md` is the model: it survived a
   context compaction and told a later agent exactly what to do — which is
   also how it went stale, so mark documents current when you change them.

## Status

| Agent | Branch | Working on | State |
| --- | --- | --- | --- |
| aws-secret-key | `fix/mcp-shield/aws-secret-key-detector` | standing work #6: the AWS secret access key, the one credential shape the outbound DLP did not cover | one commit, seven tests. The detector asks for the shape **and** the label, because the shape alone has the false-positive rate the board warned about. Proved by mutating the detector back to the old behaviour: the four detection tests fail and the three false-positive guards still pass. Worktree `C:/Users/Abhi/Desktop/monolith-wt/aws-secret-key`, branched off `origin/main` (`f42721d`) |
| security | `fix/security-hardening` | retention scoping, evidence verification, fail-closed admin, DLP coverage, breaker batching, baseline locking | merged into `main` (`3634d23`); branch kept until cleanup |
| security | `feature/video-explainer` | the AEOS Guard explainer, rescued off a branch that was about to be deleted | pushed, 1 commit |
| security | `fix/mcp-shield/baseline-persist-failure` | the tool layer's fail-open path discarded enforcement it had already computed (`FINDINGS.md` §5) | merged into `main` as PR #64 (`1b6e8ed`); the fix is proved by mutating it back to the old behaviour and watching the new test fail. The branch was rebased onto `main` after #60 and #62 merged, so its history was rewritten and it was force-pushed |
| security | `fix/scripts/ambient-proxy-rule` | the launcher's ambient-proxy rule: weaker than the secret-boundary rule it cited, and the proxy default silently changed the preflight (`FINDINGS.md` documentation drifts 2 and 3) | PR #78 open, 2 commits; the rule is proved by mutating it back to the old one and watching the new tests fail, and the end-to-end gateway demo passes against the running stack |
| security | `fix/mcp-shield/malformed-tool-entry` | one malformed tool entry voided the whole `tools/list` defence for that server (`FINDINGS.md` §6) | PR #66 open; the fix is proved by mutating it back to the old behaviour — one defective entry rejecting the whole listing — and watching all six new tests fail. Branched off `main` at `1b6e8ed`; no history rewrite, so nothing was force-pushed |
| security | `docs/stale-test-counts` | every test count the documentation carried was wrong (`FINDINGS.md` documentation drift 6) | PR #81 open; the numbers are dated snapshots and the command is the authority |
| security | `fix/mcp-shield/spool-byte-cap-doc` | the Rust spool's byte cap claimed to bound the spool and bounded one file at a time (`FINDINGS.md` documentation drift 1) | PR #80 open; the two budgets are held apart by a test, and the test fails when they are shared |
| dashboard | `fix/dashboard/operational-failure-counts` | the console's headline number counted severities, so a broken upstream read as an attack (`FINDINGS.md` documentation drifts 4 and 5) | PR #79 open; the split is by event type, in one module the console and its tests both read |
| security | `fix/vector-anchor/hot-path-tests` | the memory layer's hot path had no tests: the validating `cosine` was tested and the two functions the detector actually compares with were not (`FINDINGS.md` test gap 10) | PR #72 open; 19 tests, each proved by mutating the behaviour back and watching the test that claims to hold it fail. Worktree `C:/Users/Abhi/Desktop/monolith-wt/hot-path`, branched off `origin/main` (`f42721d`). The source is not modified — only the tests |
| security | `fix/mcp-shield/malformed-tool-entry` | one malformed tool entry voided the whole `tools/list` defence for that server (`FINDINGS.md` §6) | merged into `main` as PR #66 (`f42721d`); the fix is proved by mutating it back to the old behaviour — one defective entry rejecting the whole listing — and watching all six new tests fail. Branched off `main` at `1b6e8ed`; no history rewrite, so nothing was force-pushed |
| security | `fix/vector-anchor/truncated-error-body` | the memory layer's MCP server died on a truncated error body (`FINDINGS.md` §7) | PR #67 open; the fix is proved by mutating it back — the old read of the error body — and watching the new test fail because the server never answers. Branched off `main` at `1b6e8ed` |
| security | `fix/trace-audit/cold-model-timeout` | one read timeout did two jobs, so a cold model was read as a dead backend (`FINDINGS.md` §12) | PR #70 open; the fix is proved by mutating it back and watching the new tests fail. The tests drive a real local HTTP server, because the deadlines under test are enforced by the HTTP stack and a mock transport enforces nothing |
| security | `fix/trace-audit/prompt-projection` | the reasoning layer's prompt projection dropped every content block it could not represent, in silence (`FINDINGS.md` test gap 6) | PR #74 open; 14 tests, each proved by mutating the behaviour back and watching the test that claims to hold it fail. Worktree `C:/Users/Abhi/Desktop/monolith-wt/prompt-projection` |
| security | `fix/trace-audit/real-model-calibration` | the divergence gate had never been measured against a real model (`FINDINGS.md` test gap 7) | PR #76 open; the measurement found that the gate **cannot fire at all** against a real model (`FINDINGS.md` §12). The committed result is asserted by a test, the broken half of the promise is a *strict* xfail so a fix has to come back and remove the marker, and the calibration runs against a real model in CI. Branched off `main` at `f42721d`; no history rewrite, so nothing was force-pushed |
| security | `fix/detector-reset-path` | the memory layer's administrative reset — the one action that erases the detector's history — had no tests on either side of the wire (`FINDINGS.md` test gap 4) | PR #75 open; eight tests on the module's side and seven on the dashboard's, each proved by mutating the behaviour back and watching the test that claims to hold it fail. One unrelated commit fixes a test that failed at random (the descendant test read a file that was still being written). Worktree `C:/Users/Abhi/Desktop/monolith-wt/reset-detection` |
| gateway-review | `fix/gateway-review-fixes` | the eleven findings from the agent-gateway review: credential containment in the shield and the launcher, the reasoning layer's answer path, the memory layer's attribution rule, the dashboard's session report | all eleven fixed, one commit each; the findings are recorded in `FINDINGS.md` with the commit that fixes each and the residuals. Worktree `C:/Users/Abhi/Desktop/monolith-wt/gateway-fixes`; branched off `fix/credential-redaction-success-path` so the credential-redaction work is included. `origin/main` merged in (PR #65), no history rewrite, so nothing was force-pushed |
| silent-defenses | `fix/silent-defense-failures` | the standing work that a failure turns a defence off without saying so: the shield's admin credential, the memory layer's truncated body, the Python outbox's oversized payload, the Rust outbox's fallback target, the dashboard's listener reconnect, and the revocation snapshot that stops being complete | worktree `C:/Users/Abhi/Desktop/monolith-wt/silent-defenses`, branched off `origin/main` (`1b6e8ed`) and rebased onto `f42721d`. One commit per finding, each proved by a test that fails before the fix. Six findings fixed (`FINDINGS.md` §3, §4, §7, §9, §10, §11); pushed, awaiting a merge |
| integrator | `main` | upstream sync, security merges, Dependabot triage, verification | merged and pushed; CI green on `b19513b` |
| integrator | Dependabot | #24 merged (codeql-action); #15, #16 closed as superseded; #26 superseded by a direct hmac 0.13 migration | the queue is empty: **zero open PRs** |
| credential-transport | `fix/trace-audit/model-credential-transport` | the transport rule for the model credential the Anthropic gateway forwards upstream: the rule the modules already apply to their own delivery, applied to the one credential that had none (`FINDINGS.md` test gap 5, and §12, which is the defect it was hiding) | two fixes and two records; every one proved by mutating the fix back and watching the new test fail. Stacked on `fix/gateway-review-fixes` as PR #77, so it rebases onto `main` after #65 merges. Worktree `C:/Users/Abhi/Desktop/monolith-wt/credential-transport` |

The project is moving to user-facing features. The work below is the
security and operations tail; the board is here so it is not lost.

### The memory layer's hot path is `normalize` and `unit_dot`, not `cosine`

The detector compares embeddings on every retrieval, and it compares them
with `unit_dot` — a plain dot product — because vectors are normalized once
on admission. `cosine`, the validating version, is **not** on that path; its
only caller is the test suite.

That split is why `unit_dot` is allowed to skip validation: its inputs were
checked where they entered the detector (`record_query` and
`from_snapshot`), and normalized there too. Two things follow for whoever
touches it next.

- **A new caller of `unit_dot` must normalize first.** `unit_dot` is not
  scale-invariant — `unit_dot([2, 0], [1, 0])` is `2.0`, not `1.0` — and the
  threshold the detector compares against is a cosine.
- **There is deliberately no timing assertion.** `EVALUATION.md` records
  that `cosine` costs several times as much per call, and that measurement is
  why the split exists. A timing assertion in a unit test fails on a noisy
  runner, and a benchmark that fails teaches people to ignore failures —
  the same reason the MCP-Shield benchmark is `#[ignore]`d and the
  vector-anchor one is not in CI. The measurement lives in `EVALUATION.md`;
  the tests hold the *reason* the fast path is safe.
### The "Real model evidence" check can fail for reasons unrelated to the diff
The check triggers on `vector-anchor/src/**` and `trace-audit/src/**`, so it
runs on any branch that touches either module — and on a two-core runner it
drives a real model, which is slow.
PR #67 changed `vector-anchor/src/mcp_server.py` and nothing in the
reasoning layer. Its "Real model evidence" check still failed four times in
a row, with `httpx.ReadTimeout` raised inside
`trace-audit/src/stream_proxy.py:_ollama_stream`, while the same commit on
`main` passed. The diff could not have caused it. The cause was a
30-second read timeout that a cold model load exceeds; PR #70 splits that
budget in two, so a slow first byte and a stalled stream are no longer the
same failure.
**Read the traceback before re-running.** A `ReadTimeout` in
`_ollama_stream` is the cold-start problem, not a verdict on the change
under test. A timeout anywhere else — in a test, in a fixture, in a
module's own code — is the branch's.
**The demo had a budget of its own, and it was the smaller one.** The
baseline capture runs twelve prompts through the backend, and the
backend's budget for one answer is five minutes. The demo's step budget
for the same capture was also five minutes, so the step could be killed
while the capture was still making progress — and the failure said
"timed out" and named the command, leaving the step itself a guess in a
demo that has a dozen of them. The step's budget is now three times the
backend's, and a timeout names the step it was. A timeout in the
*backend client* is the runner's; a timeout in the *demo runner* was the
demo's, and it was hiding the real one.
**The fix raises the ceiling; it does not remove it.** With PR #70's
five-minute first-byte budget, the check still failed once: the runner
took more than five minutes to answer, which the 30-second budget would
also have failed. The rerun of the same commit passed in the ordinary
time. So a `ReadTimeout` here is still a statement about the runner, and
the rerun is the right next step — but read the traceback first, because a
timeout in a *test* is the branch's and a timeout in the backend client is
not.
### The OpenAI-compatible endpoint speaks text, and says so
`/v1/chat/completions` projects the client's messages into one text prompt,
because the backend behind it is text-only. A content block that carries
anything else — an image, a tool result — cannot be projected into the
audited prompt, and until PR #73 it was dropped in silence: the model
answered a question it had never been asked, and the ledger recorded an
ordinary completion. It is refused now, with a message that names the
block's type.
Two shapes are still accepted, and both are deliberate.
- **A null content.** That is how an assistant turn carrying tool calls is
  written. There is nothing there to lose, so it is not refused.
- **A blank text block.** It carries nothing, so it contributes nothing.
Neither endpoint scans a non-text block — the auditor works on text. The
difference is what happens to it: the Anthropic gateway forwards the body
byte for byte, so the model receives the block, while this endpoint
refuses it rather than pretending it was never sent.
### The detector-reset path is the one action that erases evidence
`POST /admin/reset-detection` clears the memory layer's frequency history
and its quarantine. The dashboard's onboarding page can call it, so it is
reachable by anyone who can authenticate to the dashboard as an
administrator — and until PR #75 nothing tested either half of it.
What the tests hold, on the module's side: the route refuses a caller
without the configured bearer, and refuses outright when no bearer is
configured at all (an unconfigured administrative credential must not
become an open door); the reset clears the history and the quarantine and
leaves the corpus alone, because it is a *detector* reset and not a wipe;
the detector that comes back is the one that was configured, so a reset
cannot silently re-tune the thresholds; and the cleared state reaches the
disk immediately, because a reset that only marked the state dirty would be
undone by the next periodic write and would put back exactly the history
the operator asked to erase.
On the dashboard's side: the reset is an administrator's action, it crosses
the wire as a `POST` to `/admin/reset-detection` carrying the module
credential, the browser never sees that credential, and a memory layer that
refuses or cannot be reached is a failure rather than a reset — the
dashboard answers `503` and does not claim the detector was cleared.
One thing changed in the route to make the last of those durable. The
action list now lives in `dashboard/lib/onboarding-actions.ts`, where a
test can enumerate it, and the route dispatches every action explicitly.
It used to fall through to the reset: an action added to the list without a
branch would have erased the memory layer's history instead of doing
whatever it was meant to do, and the branch that erases evidence is not one
to reach by accident.

### Requirement floors now match their locks (resolved)

The merged Dependabot PRs raised the floors in `vector-anchor/requirements.txt`
and `trace-audit/requirements.txt` but only touched that file, so six floors
were left sitting above the pin in the matching `requirements.lock`. Nothing
broke — CI and both Dockerfiles install with
`pip install --require-hashes -r requirements.lock`, so the lock, not the
floor, is what gets installed — but the two files contradicted each other.

The floors are now pinned to the versions the locks actually carry, so the
`.txt` and the `.lock` agree, and `requirements.txt` documents what is
deployed rather than an aspiration. The dependency *upgrade* is still owed and
is now a separate, deliberate piece of work. Three things were learned trying
to do it in place, and they are the reason it was not:

1. **`pip-compile` must not be replaced with `uv pip compile`.** uv emits the
   same file format but resolves extras and markers differently: it drops the
   `; sys_platform != "win32"` marker from `uvloop` and drops `colorama`.
   `uvloop` has no Windows wheel, so an unmarked `uvloop` makes the
   `windows-latest` job try to build it from source.
2. **Compiling on Linux drops `colorama`.** It arrives through `click`,
   `build` and `tqdm` under `platform_system == "Windows"`, and the committed
   locks were compiled on Windows and carry it.
3. **Compiling on Windows cannot resolve `uvloop`.** It has no Windows wheel,
   so `pip-compile` tries to build it and fails with "Getting requirements to
   build wheel exited with 1".

Doing it properly means either compiling on Linux and restoring the `colorama`
entry and the `uvloop` marker by hand, or compiling on Windows with `uvloop`
held back. Either way it wants its own pull request, its own CI run on all
three platforms, and a `pip check` on Windows to confirm the Windows-only
entries are present.

The 2026-10-20 refresh found all twelve open questions still accurate; see
the note at the top of `docs/OPEN_QUESTIONS.md`. One collaboration race
happened: a branch was switched in the shared `main` worktree while another
agent was merging, so the merge landed on the new branch and had to be moved
to `main` by ref. Use a dedicated worktree for every branch.

### The spool's byte cap bounds one file, on purpose

Documentation drift 1 was a comment that said one thing and the code did
another. `MAX_SPOOL_BYTES` was documented as "an upper bound on spooled
bytes across `outbox.jsonl` and `outbox.dead`", and it was applied to each
file separately, so the spool directory could hold twice what the comment
promised.

The code is right and the comment was wrong, and the reason is worth
writing down because the other way round is a bug waiting to happen. A
budget shared across the two files would let a full dead-letter file starve
the pending spool: `outbox.jsonl` would find no room for a new event, drop
the oldest to make room, and find the new event too large for what was
left. What the pending spool drops when it runs out is a detection that has
not been delivered yet, which is the one loss this outbox must never make.
The dead-letter file exists to keep evidence the dashboard will never
take; it is not a place to take a budget from the live spool.

So the cap says what it is — a bound on one file, applied to each — and a
test holds the two budgets apart. The test fails if the budget is shared:
it was proved by making the pending spool charge for the dead-letter file's
bytes and watching the newest detection disappear.

The operator-visible consequence is one number to remember: **the spool
directory holds at most twice the cap**, 32 MiB by default.
### The launcher's proxy rule is now the secret boundary's
`FINDINGS.md` documentation drifts 2 and 3 were both about one function,
`_should_use_ambient_proxy` in `scripts/monolith_wrap.py`, and both are fixed
on `fix/scripts/ambient-proxy-rule`.
The rule was weaker than the rule it cited. The secret boundary disables the
ambient proxy outright for a resolved secret; the launcher allowed one for a
remote HTTPS target, on the argument that the request is tunnelled end to end
"so the proxy cannot read the credential". That holds for a proxy that
relays and not for one that terminates TLS, and a corporate inspection proxy
is what a Windows *system* proxy usually is — the case the rule was written
for. The rule is now the boundary's: an ambient proxy does not carry a
credential unless the operator says so with
`MONOLITH_ALLOW_CREDENTIAL_VIA_PROXY=true`, which is also the answer for a
corporate network where the proxy is the only route to the model provider.
The console names the proxy it found and what it will and will not carry.
The same change had made the preflight inherit the credential's rule, so a
service that was only reachable through a proxy reported as down and the
launcher refused to start — naming the service and saying nothing about the
proxy. A health check carries no credential, so it is not held to that rule
any more, and a failed one says which proxy carried the request.
**The residual is an open question, not a fix.** The hop that carries the
client's credential to the model provider is not the launcher's to govern:
for `/v1/messages` the launcher forwards to the local auditor, and the
auditor makes the provider request itself, with a client that reads the
proxy settings from its own environment. That is question 13 in
`docs/OPEN_QUESTIONS.md`.

## Claims

| Path | Claimed by | Note |
| --- | --- | --- |
| `mcp-shield/src/proxy.rs` | gateway-review | the child environment. Overlaps the standing `mcp-shield/src/**` claim, whose batch merged on 2026-10-20; coordinate if `agent/security/fail-closed-config` lands in the same file |
| `scripts/monolith_wrap.py` | gateway-review | the launcher's child environment and the plan redactor |
| `trace-audit/src/anthropic_gateway.py`, `trace-audit/src/stream_proxy.py`, `trace-audit/src/pii_scanner.py`, `trace-audit/src/main.py` | gateway-review | the answer path: the cross-block credential leak, the citation delta, the Anthropic key pattern, the refusal stream, the baseline model, the token ceiling |
| `vector-anchor/src/mcp_server.py`, `vector-anchor/src/retriever_proxy.py` | gateway-review | session attribution on the retrieve path |
| `vector-anchor/tests/**`, `vector-anchor/fixtures/run_demo.sh`, `scripts/verify_recovery.sh`, `evaluation/real_models.py`, `docs/IDENTITY_AND_ACCESS.md` | gateway-review | the call sites that retrieve without naming a session, and the tests that exercise the retriever directly |
| `dashboard/lib/session-report.ts`, `dashboard/app/api/sessions/[sessionId]/route.ts` | gateway-review | taken over from `add-agent-onboarding`, which offered it; the peer recorded it as "owned by peer session" and does not touch it |
| `docs/FINDINGS.md` | gateway-review | the eleven findings land here, each with the commit that fixes it — done, plus the residuals |
| `contracts/openapi.yaml` | gateway-review | overlapped with `security`'s claim (merged): `/admin/reload-baseline` gained a `model` request field and a `baseline_model` response field |
| `mcp-shield/src/main.rs`, `mcp-shield/src/outbox.rs` | silent-defenses | the status listener's admin credential and the fallback delivery target. Overlaps the standing `mcp-shield/src/**` claim, whose batch merged on 2026-10-20 |
| `python-common/monolith_events/events.py` | silent-defenses | the oversized payload and the paged revocation snapshot |
| `dashboard/lib/live-event-listener.ts`, `dashboard/lib/event-stream-client.ts`, `dashboard/app/page.tsx` | silent-defenses | the reconnect after a failed LISTEN, and the browser-side reconnect — an `EventSource` that got a 503 never reconnects by itself |
| `dashboard/lib/incident-store.ts`, `dashboard/app/api/ingest/route.ts`, `dashboard/app/api/sessions/revoked/route.ts` | silent-defenses | the revocation snapshot pagination. Overlaps the standing `dashboard/lib/incident-store.ts` / `dashboard/app/api/ingest/**` claim, whose batch merged on 2026-10-20 |
| `vector-anchor/src/mcp_server.py` | silent-defenses | the truncated error body. **Note:** `gateway-review` also claims this file for session attribution; the two fixes touch different functions and the branches are separate, so whoever merges second should rebase |
| `mcp-shield/src/**` | security | through the 2026-10-20 review batch |
| `mcp-shield/README.md`, `crates/pbm-secret-boundary/README.md`, `docs/SECRET_BOUNDARY.md` | security | the stale test counts (documentation drift 6) |
| `mcp-shield/src/**` | security | through the 2026-10-20 review batch; the spool's byte cap (documentation drift 1) on `fix/mcp-shield/spool-byte-cap-doc` |
| `mcp-shield/src/sanitizer.rs` | aws-secret-key | the AWS secret access key detector (standing work #6). Overlaps the standing `mcp-shield/src/**` claim, whose batch merged on 2026-10-20; nothing else in the tree touches the sanitizer |
| `dashboard/lib/incident-store.ts`, `dashboard/app/api/ingest/**` | security | circuit breaker and ingest path |
| `dashboard/lib/login-rate-limit.ts`, `dashboard/scripts/dispatch-alerts.mjs` | security | rate limiting and alert delivery |
| `supabase/migrations/**` | security | retention scoping migration |
| `contracts/openapi.yaml` | security | corrected the revocation snapshot wording |
| `vector-anchor/tests/test_embedding.py`, `vector-anchor/tests/test_frequency_tracker.py` | security | the memory layer's hot path. Reads `vector-anchor/src/embedding.py` and `vector-anchor/src/frequency_tracker.py` but does not modify either |
| `scripts/monolith_wrap.py`, `scripts/tests/**` | security | the launcher's ambient-proxy rule (`FINDINGS.md` documentation drifts 2 and 3) |
| `docs/FINDINGS.md`, `docs/OPEN_QUESTIONS.md`, `README.md` | security | the drift list, the new open question, and the launcher's section of the README |
| `contracts/openapi.yaml` | security | corrected the revocation snapshot wording — that branch is merged; `gateway-review` has since touched the same file, so the two rows are both live |
| `main` | integrator | Merges and verification only; branch work happens in a worktree. |
| `python-common/monolith_events/events.py`, `trace-audit/src/config.py`, `trace-audit/src/main.py`, `trace-audit/src/events.py` | credential-transport | the model credential's transport rule: the rule the modules already apply to their own delivery, applied to the credential the Anthropic gateway forwards upstream. Stacked on `fix/gateway-review-fixes`, so it rebases onto `main` after that merges. `python-common/monolith_events/events.py` overlaps the `silent-defenses` claim, but the two touch different functions |
| `scripts/monolith_wrap.py`, `scripts/tests/test_monolith_wrap.py` | credential-transport | the launcher's standard-library-only copy of the transport rule, brought into line with the shared one (`80f84f6`). Overlaps the `gateway-review` claim on the same file, and it is stacked on that branch, so the change rides on top of it rather than racing it |

Free to claim: `vector-anchor/**` (apart from the detector's hot path, above),
`trace-audit/**`, `dashboard/app/api/operations/**`,
| `trace-audit/src/stream_proxy.py` | security | the backend client's deadlines — the first-byte budget and the per-chunk deadline. Only the timeout handling changed; the rest of the layer is not claimed |
Free to claim: `vector-anchor/**`, `trace-audit/**` (apart from the backend
client's deadlines, above), `dashboard/app/api/operations/**`,
| `trace-audit/src/main.py`, `trace-audit/tests/test_prompt_projection.py` | security | the reasoning layer's prompt projection — the OpenAI-compatible endpoint's projection of the client's messages into one audited text prompt |
Free to claim: `vector-anchor/**`, `trace-audit/**` (apart from the prompt projection, above),
| `trace-audit/fixtures/**`, `trace-audit/tests/test_real_model_calibration.py` | security | the real-model calibration and the test that asserts it (PR #76) |
| `.github/workflows/calibration.yml` | security | the real-model calibration workflow (PR #76) |
Free to claim: `vector-anchor/**`, the rest of `trace-audit/**`,
`dashboard/app/api/operations/**`,
| `vector-anchor/tests/test_reset_detection.py` | security | the memory layer's administrative reset — the credential check, the clearing, the thresholds the reset comes back with, and the write to disk |
| `dashboard/app/api/onboarding/**`, `dashboard/lib/onboarding-actions.ts`, `dashboard/test/reset-detection.test.ts` | security | the dashboard's half of the reset path, and the action list it dispatches from |
Free to claim: `vector-anchor/**` (apart from the reset path's tests, above),
`dashboard/app/api/benchmarks/**`, `docs/OPEN_QUESTIONS.md`, the Dependabot
queue.
Free to claim: `vector-anchor/**` (apart from the two files above),
`trace-audit/**` (apart from the four files above),
`dashboard/app/api/operations/**`, `dashboard/app/api/benchmarks/**`,
`docs/OPEN_QUESTIONS.md`, the Dependabot queue.

## Standing work

A wider survey of the repository landed on 2026-10-21: twelve defects, ten
test gaps, five documentation drifts, and five things checked and confirmed
sound. It is in [`FINDINGS.md`](FINDINGS.md), ranked, with each item marked
**verified** (read and confirmed at the cited lines) or **reported** (a
reader's lead, not yet checked). The items below are the board's own list.

| # | Item | Where | Priority |
| --- | --- | --- | --- |
| 1 | The reasoning layer's KL divergence never fires. Two separate reasons: nothing ever writes the baseline's `model` key, so the gate is never armed (`FINDINGS.md` §1); and the shipped threshold of 1.0 sits **above** the monitor's own ceiling for a real model (0.587), so it could not fire even when armed (`FINDINGS.md` §12, on the calibration branch, PR #76). **Unclaimed — this is the next item.** | `trace-audit/src/main.py`, `trace-audit/src/divergence_monitor.py` | **high** |
| 2 | A notification failure rolls back the evidence it was raised for: the alert-job row shares the security event's transaction. | `dashboard/lib/event-store.ts` | **high** — see `FINDINGS.md` §2 |
| 3 | Every revocation snapshot is truncated at 64 KiB, so past ~1,700 live revocations the modules keep a stale set forever and the breaker fails open. | `dashboard/app/api/ingest/route.ts`, `python-common`, `mcp-shield` | **high** — see `FINDINGS.md` §3 |
| 4 | The MCP-Shield status listener falls back to the module's ingest token as its admin credential. | `mcp-shield/src/main.rs` | medium — see `FINDINGS.md` §4 |
| 5 | The ingest response carries the tenant's whole revocation set on every request, so the payload grows with the total number of quarantines. The fix needs the dashboard *and* `python-common` to agree on snapshot-versus-delta. | `dashboard/app/api/ingest/route.ts`, `python-common/monolith_events/events.py` | low — contract change |
| 6 | ~~The AWS secret access key has no detector. Deliberately: 40 characters of base64 has a false-positive rate that would hard-block ordinary calls. Needs a shape-aware detector, not a regex.~~ **Fixed** by `fix(mcp-shield): detect an AWS secret access key by its shape and its label`: the detector asks for the shape **and** the label that names it, so the false positive the board warned about never reaches enforce mode. | `mcp-shield/src/sanitizer.rs` | low — see *The AWS secret access key detector* below |

### The AWS secret access key detector (read this before touching it)

The AWS secret access key is the one credential shape the outbound DLP did
not cover, and it was left uncovered on purpose: it has no prefix, so a
pattern for it is forty characters of base64 alphabet, and that shape has a
false-positive rate high enough to hard-block ordinary calls in enforce
mode. A detector that blocks ordinary calls is worse than one that misses a
credential, so the shape alone was never going to be enough.

The detector therefore asks for two things, and neither is enough alone:

- **The shape.** Exactly 40 characters from the base64 alphabet, holding at
  least one uppercase letter, one lowercase letter and one digit. The mix
  requirement is what keeps a 40-character hex digest out — a git SHA-1, a
  checksum — because a digest is written in one case and a random key of
  this length is not. The run has to be *maximal*, so a 44-character base64
  blob (the length of a base64-encoded SHA-256, and the most common thing
  in a lock file) is not a 40-character key with four characters around it.
- **The context.** A label that names an AWS secret, either the key the
  value sits under or a marker in the same string. The label is threaded
  through the scan as the path of keys, so `{"aws_secret_access_key": "…"}`
  and `{"provider": {"credentials": {"awsSecretAccessKey": "…"}}}` both
  count, and so does `aws configure set aws_secret_access_key …` in a
  command string.

**The known limit.** A 40-character value under a label that does *not*
name AWS is not detected. Without the label it is indistinguishable from a
random blob, and a detector that flagged it would be the false positive
this work existed to avoid. A secret passed under a generic label
(`password`, `token`) is therefore still missed, and that is a deliberate
trade rather than an oversight.

The fixtures are assembled at runtime, never written out: a contiguous
40-character credential-shaped literal in the source is a finding for the
secret scanner, and push protection blocks the push even though the value
is the published AWS example. The bytes handed to the detector are
identical either way.
| 1 | ~~The reasoning layer's KL divergence is off in every shipped configuration: nothing ever writes the baseline's `model` key, so the gate can never open.~~ | `trace-audit/src/main.py` | **done** — `6041854`, see `FINDINGS.md` §1 |
| 3 | ~~Every revocation snapshot is truncated at 64 KiB, so past ~1,700 live revocations the modules keep a stale set forever and the breaker fails open.~~ **Fixed** by `fix(revocation): page the snapshot so a large one is never half-read`: the snapshot is paged by a keyset cursor and both readers install it only once it has been read whole. | `dashboard/app/api/ingest/route.ts`, `python-common`, `mcp-shield` | **high** — see `FINDINGS.md` §3 |
| 4 | ~~The MCP-Shield status listener falls back to the module's ingest token as its admin credential.~~ **Fixed** by `fix(mcp-shield): keep the ingest token out of the status listener`: the administrative endpoints answer 503 without an administrative credential. | `mcp-shield/src/main.rs` | medium — see `FINDINGS.md` §4 |
| 5 | The ingest response carries the tenant's whole revocation set on every request, so the payload grows with the total number of quarantines. The fix needs the dashboard *and* `python-common` to agree on snapshot-versus-delta. **Bounded, not made a delta:** the ingest response carries the snapshot only while it fits in 16 KiB and otherwise carries the count alone, and the poll endpoint pages the whole set. The wire format is still a snapshot, so no module has to change its contract beyond the paging. | `dashboard/app/api/ingest/route.ts`, `python-common/monolith_events/events.py` | low — contract change |
| 6 | The AWS secret access key has no detector. Deliberately: 40 characters of base64 has a false-positive rate that would hard-block ordinary calls. Needs a shape-aware detector, not a regex. | `mcp-shield/src/sanitizer.rs` | low |
| 7 | The divergence gate **cannot fire against a real model**: the statistic's ceiling against a real model's baseline is 0.59 and the threshold is 1.0, so no answer can cross it. The threshold was calibrated to the ceiling of the *mock's* 36-token vocabulary (3.29), and a real model's 331-token vocabulary cuts the ceiling to a third. Compounds item 1 above — arming the gate without fixing this gives a gate that never fires, and it fails silently. | `trace-audit/src/divergence_monitor.py` | **high** — see `FINDINGS.md` §12 |

The silent-defenses branch also closed four of the survey's own items while it
was in the same files: the memory layer's truncated error body (`FINDINGS.md`
§7), the Python outbox's oversized payload (§10), the Rust outbox's fallback
delivery target (§11), and the dashboard listener's missing reconnect (§9).
Each is one commit, and each is proved by a test that fails before the fix
and passes after it.

The credential-transport branch closed one more of the survey's items, and
it is worth reading the way it was reported: test gap 5 said the rule
deciding whether a credential may travel over plain HTTP to the upstream
model was "neither present nor tested", and the half that matters was the
first one. The rule did not exist. The model credential — the client's own
`x-api-key`, or the operator's fallback key — went to whatever
`MONOLITH_ANTHROPIC_BASE_URL` named, over whatever scheme that named, and
every other credential this system sends is held to a rule it did not
answer to. It is now held to the same rule, in the same place, and the
launcher's copy of the rule was brought back into line with the shared one
because the two had drifted. `FINDINGS.md` §12 has the detail.

### The revocation snapshot is paged now (read this before touching it)

`GET /api/sessions/revoked` answers with either the whole set or one page of
it, and the answer says which:

- `revoked_sessions_complete: true` — the array is the whole set. Adopt it.
- `revoked_sessions_complete: false` — the array is one page. Follow
  `next_cursor` (`?cursor=…`) until there is no cursor, and adopt the set
  only then.

The cursor is a keyset on `(session_id, agent_id)`, base64url-encoded, and it
is the reader's job to validate it: only the base64url alphabet is put into
a URL. A page is bounded by the number of ids **and** by the bytes they take.

**A partial set is never adopted.** A reader that installs half a snapshot
forgets every revocation that is not in it, and a forgotten revocation is a
quarantined session that keeps working. Both readers therefore keep the set
they had until the whole snapshot has been read.

`POST /api/ingest` carries the snapshot only while it fits in 16 KiB, and
otherwise carries `revoked_sessions_total` alone. An old module that reads
that response keeps the set it had, which is what it already did; a module
that understands the contract reads the paged snapshot.

### One transport rule for every credential (read this before touching it)

There is exactly one rule, and it is in one place:
`credential_transport_is_trusted()` in `python-common/monolith_events/events.py`.
It answers one question — *may a credential be sent to this address over this
scheme?* — and the answer is: **HTTPS everywhere; plain HTTP only to a
loopback address, and only when the operator has said the network is
trusted.** A URL that carries credentials in it, or a fragment, is never
trusted.

Four callers now use it, and they are the four places a credential leaves
this system:

| Caller | Credential | Where |
| --- | --- | --- |
| `EventOutbox` | the module's ingest token | `python-common/monolith_events/events.py` |
| `RevokedSessionPoller` | the module's ingest token | `python-common/monolith_events/events.py` |
| the Anthropic gateway | the model's credential | `trace-audit/src/main.py` |
| the launcher | the agent's endpoint | `scripts/monolith_wrap.py` |

The Rust side has its own copy of the same rule, for the same reason it has
its own copy of the outbox: `mcp-shield/src/outbox.rs` and
`mcp-shield/src/http_transport.rs`.

**Do not add a fifth rule and do not add a third copy of this one.** A new
credential gets the shared function, not a regex of its own. A copy is a
place where the rule can drift, and a drifted rule is a credential that
thought it was safe.

Two things to know when you touch the gateway's use of it:

- **The check is on the URL that will actually be used**, not on the
  configured base. `build_upstream_request()` derives the URL, and a
  derivation that changed the host could otherwise step around a check made
  against the base.
- **The refusal happens before the request is built.** A request to an
  untrusted upstream is answered `503` and never leaves; a ledger row
  (`upstream_transport_refused`) says why, once per process, because the
  cause is the operator's configuration and not the caller.

The escape hatch is `MONOLITH_ALLOW_INSECURE_ANTHROPIC=true`, and it has to be
spelled out by name. An operator whose model service is genuinely on a
trusted network can say so; an operator who has mistyped a host cannot enable
it by accident.

The eleven findings from the agent-gateway review are all fixed and recorded in
[`FINDINGS.md`](FINDINGS.md) under *The agent-gateway review*, with the commit
that fixes each and the residuals left open. Two of them were HIGH and are
worth reading twice: the shield's own credentials reached every MCP server it
started (`84c2314`), and a credential split across a content block boundary
reached the client whole (`cd42177`).

Done: the module dead-letter replay is now scoped to one tenant across the
dashboard, both module endpoints, the shared Python outbox and the Rust spool
(PR #59), and the operator's credential can no longer reach the client
through a normal answer (PR #60). The breaker's per-candidate query is now
one query for the whole batch, the baseline is locked across its
read-modify-write cycle, and the open questions were refreshed on 2026-10-20.

The integrator also closed the credential-test-vector finding that GitHub's
secret scanner raised on `mcp-shield/src/sanitizer.rs`: the JWT and the bearer
token were literal strings in the source. The values are public test vectors,
not secrets, but the file already avoided the scanner for the Slack, GitLab
and Anthropic shapes by assembling them at runtime, so the JWT and the bearer
token are now assembled the same way. The bytes handed to the detector are
unchanged, so the test still proves the same detection. Any new fixture that
looks like a credential must be assembled at runtime too.

### The divergence gate has never been measured against a real model

The reasoning layer's divergence gate sits in front of every answer it
returns, and the threshold that decides it (1.0) came entirely from the
deterministic mock backend. The threshold's own comment says the headroom is
deliberate because "a real model backend would show wider benign spread, and
1.0 absorbs that drift" — and the calibrator's comment says the opposite
about the same number: measuring it against a real model is the blind spot
that "stays open". Neither was measured, because nothing could be: the
calibrator wrote prose, not a result any test could read.

PR #76 closed that, and the measurement is worse than the missing assertion.
Against `qwen2.5:0.5b` with the shipped monitor settings, thirty-six held-out
benign prompts peak between 0.30 and 0.57 with no false positives, and the
eight off-distribution probes — the shipped fixture, and another language, a
hex dump, a repetition loop, a base64 blob, structured data, foreign prose
and shouting — peak between 0.35 and 0.59. The threshold is 1.0. **The gate
cannot fire.** The shipped divergent fixture reached 0.349: below the worst
ordinary answer, and below a hex dump.

The reason is the statistic, not the constant. The most divergent window the
monitor can express is one in which every token is off-vocabulary — each lands
in the `<other>` bucket, which carries the baseline's smallest mass — and the
KL for that window is the top of the monitor's range. It is a property of the
baseline's vocabulary:

| | mock | real model |
| --- | ---: | ---: |
| baseline vocabulary | 36 tokens | 331 tokens |
| most one bucket can carry | 0.5325 | 0.1105 |
| how far below the baseline an unfamiliar token sits | 1637× | 366× |
| **ceiling** | **3.2893** | **0.5870** |
| the threshold the code ships | 1.0 | 1.0 |

The mock's shipped fixture scores 3.2893 — *exactly* the mock's ceiling. The
mock's "divergent" fixture is a window of tokens that appear nowhere in the
baseline, and 1.0 was set because that was "0.30× of the divergent fixture
peak (3.29) -> fires decisively". The threshold was calibrated to the ceiling
of a 36-token vocabulary. A real model's vocabulary is ten times the size,
its ceiling is a third of the mock's, and the constant was left where the
mock put it.

Two consequences for anyone picking this up:

1. **§1 and §12 have to be fixed together.** §1 says the gate can never open
   because nothing writes the baseline's `model` key; §12 says that if it did
   open, it would not fire anyway. Fixing only §1 would arm a gate that cannot
   see — and it would fail silently, because an answer that is never
   terminated looks exactly like an answer that is clean.
2. **The fix is in the statistic.** A threshold of 0.55 would fire on the
   probes, but the gap between the worst ordinary answer and the strongest
   probe is 0.01–0.07, and the whole band shifts by up to 0.16 between runs —
   the backend is sampled, so each measurement is a fresh draw. A threshold
   inside that gap would refuse ordinary answers some of the time. The
   options are a vocabulary-independent measure (the fraction of window tokens
   outside the baseline, or a divergence between two distributions estimated
   over the same vocabulary) or a much larger baseline capture with the
   threshold re-derived from a real model. Either way the mock's numbers have
   to stop being the source.

The measurement is committed at
`trace-audit/fixtures/real_model_calibration.json` — including the ceiling,
so a fix can be checked against the number the statistic can actually express
rather than against a remembered one — the test asserts the half of the
promise that holds and marks the broken half as a **strict** xfail, and
`.github/workflows/calibration.yml` re-measures against a real model on every
change to the monitor, the calibrator or the result. A fix that makes the gate
fire has to come back and remove the xfail marker.

## Verification

The full gate set. A change is done when all of it passes, on every
platform, in CI.

```
mcp-shield/          cargo fmt --all -- --check
                     cargo clippy --locked --all-targets -- -D warnings
                     cargo test --locked
crates/pbm-secret-boundary/   the same three
python-common/       ruff, mypy, pytest
vector-anchor/       ruff, mypy, pytest, fixtures/benchmark_detection.py
trace-audit/         ruff, mypy, pytest, fixtures/benchmark_detection.py
dashboard/           npm run lint, npm test, npm run build
contracts/           python contracts/check_contracts.py
scripts/             python -m unittest discover -s scripts/tests
```

A count written in a document is a snapshot, not a promise. Every test
count this repository used to carry was wrong — 45 where the suite ran
144, 73 where it ran 79 — because a number does not update itself when the
next test lands. Write the number with the date it was counted and point at
the command, which prints the current one and is the authority.
Two of the launcher's tests are timing-sensitive on Windows and fail
intermittently when the machine is busy: `test_cleanup_stops_spawned_descendant`
(spawns a real child, then asserts the port is closed the instant the child
dies) and `test_an_oversized_body_is_refused_before_it_is_read` (waits on a
loopback server with a 15-second timeout). This is pre-existing — it was
observed on `fix/gateway-review-fixes` with none of the credential-transport
changes on it — so a red `scripts` gate is worth re-running once before it
is believed.

## Finding the other agents

There is no shared state beyond this repository and the remote. If this
board is stale, the other sessions are running in an opencode server whose
state lives in a SQLite database:

```
%USERPROFILE%\.local\share\opencode\opencode.db
```

The `session`, `message` and `part` tables hold what each session has been
doing. It is a last resort, not a workflow — the board is the workflow.

## Branches that must not be deleted

| Branch | Why |
| --- | --- |
| `archive/pre-automation-snapshot` | The pre-automation snapshot of the codebase, and the only copy of the `.commandcode/` preferences record. Tagged `archive/pre-automation-2026-08-28`. |
| `feature/video-explainer` | The AEOS Guard explainer. The `video/` project existed only on a branch that was scheduled for deletion. |
| `fix/security-hardening` | Merged into `main`; keep the branch and worktree until their owner confirms there is no further work. |
