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
| integrator | `main` | upstream sync, security merges, Dependabot triage, verification | merged and pushed; CI green on `b19513b` |
| integrator | Dependabot | #24 merged (codeql-action); #15, #16 closed as superseded; #26 superseded by a direct hmac 0.13 migration | the queue is empty: **zero open PRs** |

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
| `main` | integrator | Merges and verification only; branch work happens in a worktree. |

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
`dashboard/app/api/benchmarks/**`, `docs/OPEN_QUESTIONS.md`, the Dependabot
queue.

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
| 6 | The AWS secret access key has no detector. Deliberately: 40 characters of base64 has a false-positive rate that would hard-block ordinary calls. Needs a shape-aware detector, not a regex. | `mcp-shield/src/sanitizer.rs` | low |
| 7 | The divergence gate **cannot fire against a real model**: the statistic's ceiling against a real model's baseline is 0.59 and the threshold is 1.0, so no answer can cross it. The threshold was calibrated to the ceiling of the *mock's* 36-token vocabulary (3.29), and a real model's 331-token vocabulary cuts the ceiling to a third. Compounds item 1 above — arming the gate without fixing this gives a gate that never fires, and it fails silently. | `trace-audit/src/divergence_monitor.py` | **high** — see `FINDINGS.md` §12 |

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
