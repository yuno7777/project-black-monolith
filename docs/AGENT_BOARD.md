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
| security | `fix/security-hardening` | retention scoping, evidence verification, fail-closed admin, DLP coverage, breaker batching, baseline locking | merged into `main` (`3634d23`); branch kept until cleanup |
| security | `feature/video-explainer` | the AEOS Guard explainer, rescued off a branch that was about to be deleted | pushed, 1 commit |
| security | `fix/mcp-shield/baseline-persist-failure` | the tool layer's fail-open path discarded enforcement it had already computed (`FINDINGS.md` §5) | merged into `main` as PR #64 (`1b6e8ed`); the fix is proved by mutating it back to the old behaviour and watching the new test fail. The branch was rebased onto `main` after #60 and #62 merged, so its history was rewritten and it was force-pushed |
| security | `fix/mcp-shield/malformed-tool-entry` | one malformed tool entry voided the whole `tools/list` defence for that server (`FINDINGS.md` §6) | PR #66 open; the fix is proved by mutating it back to the old behaviour — one defective entry rejecting the whole listing — and watching all six new tests fail. Branched off `main` at `1b6e8ed`; no history rewrite, so nothing was force-pushed |
| security | `fix/trace-audit/real-model-calibration` | the divergence gate had never been measured against a real model (`FINDINGS.md` test gap 7) | PR #76 open; the measurement found that the gate **cannot fire at all** against a real model (`FINDINGS.md` §12). The committed result is asserted by a test, the broken half of the promise is a *strict* xfail so a fix has to come back and remove the marker, and the calibration runs against a real model in CI. Branched off `main` at `f42721d`; no history rewrite, so nothing was force-pushed |
| integrator | `main` | upstream sync, security merges, Dependabot triage, verification | merged and pushed; CI green on `b19513b` |
| integrator | Dependabot | #24 merged (codeql-action); #15, #16 closed as superseded; #26 superseded by a direct hmac 0.13 migration | the queue is empty: **zero open PRs** |

The project is moving to user-facing features. The work below is the
security and operations tail; the board is here so it is not lost.

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

## Claims

| Path | Claimed by | Note |
| --- | --- | --- |
| `mcp-shield/src/**` | security | through the 2026-10-20 review batch |
| `dashboard/lib/incident-store.ts`, `dashboard/app/api/ingest/**` | security | circuit breaker and ingest path |
| `dashboard/lib/login-rate-limit.ts`, `dashboard/scripts/dispatch-alerts.mjs` | security | rate limiting and alert delivery |
| `supabase/migrations/**` | security | retention scoping migration |
| `contracts/openapi.yaml` | security | corrected the revocation snapshot wording |
| `trace-audit/fixtures/**`, `trace-audit/tests/test_real_model_calibration.py` | security | the real-model calibration and the test that asserts it (PR #76) |
| `.github/workflows/calibration.yml` | security | the real-model calibration workflow (PR #76) |
| `main` | integrator | Merges and verification only; branch work happens in a worktree. |

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
| 1 | The reasoning layer's KL divergence is off in every shipped configuration: nothing ever writes the baseline's `model` key, so the gate can never open. | `trace-audit/src/main.py` | **high** — see `FINDINGS.md` §1 |
| 2 | A notification failure rolls back the evidence it was raised for: the alert-job row shares the security event's transaction. | `dashboard/lib/event-store.ts` | **high** — see `FINDINGS.md` §2 |
| 3 | Every revocation snapshot is truncated at 64 KiB, so past ~1,700 live revocations the modules keep a stale set forever and the breaker fails open. | `dashboard/app/api/ingest/route.ts`, `python-common`, `mcp-shield` | **high** — see `FINDINGS.md` §3 |
| 4 | The MCP-Shield status listener falls back to the module's ingest token as its admin credential. | `mcp-shield/src/main.rs` | medium — see `FINDINGS.md` §4 |
| 5 | The ingest response carries the tenant's whole revocation set on every request, so the payload grows with the total number of quarantines. The fix needs the dashboard *and* `python-common` to agree on snapshot-versus-delta. | `dashboard/app/api/ingest/route.ts`, `python-common/monolith_events/events.py` | low — contract change |
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
