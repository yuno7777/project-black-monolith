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
| security | `fix/security-hardening` | retention scoping, evidence verification, fail-closed admin, DLP coverage | 2 commits ahead of `origin/main`, pushed, gates green |
| security | `feature/video-explainer` | the AEOS Guard explainer, rescued off a branch that was about to be deleted | pushed, 1 commit |
| (unassigned) | — | the local `main` tree is 19 commits behind `origin/main` and has an uncommitted file | **needs a `git pull --rebase` before anyone edits `main`** |
| (unassigned) | — | 5 open Dependabot pull requests, all with green CI | merge the green ones, close the rest |
| (unassigned) | — | `docs/OPEN_QUESTIONS.md` — 12 open decisions, several stale | write recommendations; a human decides |

## Claims

| Path | Claimed by | Note |
| --- | --- | --- |
| `mcp-shield/src/**` | security | through the 2026-10-20 review batch |
| `dashboard/lib/incident-store.ts`, `dashboard/app/api/ingest/**` | security | circuit breaker and ingest path |
| `dashboard/lib/login-rate-limit.ts`, `dashboard/scripts/dispatch-alerts.mjs` | security | rate limiting and alert delivery |
| `supabase/migrations/**` | security | retention scoping migration |
| `contracts/openapi.yaml` | security | corrected the revocation snapshot wording |
| `main` | — | **nobody.** The integrator merges; everyone else rebases. |

Free to claim: `vector-anchor/**`, `trace-audit/**`, `dashboard/app/api/operations/**`,
`dashboard/app/api/benchmarks/**`, `docs/OPEN_QUESTIONS.md`, the Dependabot
queue.

## Standing work

| # | Item | Where | Priority |
| --- | --- | --- | --- |
| 1 | The breaker runs one `withTenantDb` transaction per candidate, up to 100 per ingest batch. Batch the layer lookup into a single query. | `dashboard/lib/incident-store.ts` | medium |
| 2 | Module dead-letter replay is global while the database half of the same function is tenant-scoped, so a tenant admin replays other tenants' dead letters. | `dashboard/lib/operations-store.ts` | medium |
| 3 | The live baseline reload reads the file and writes it back with no cross-process lock, so an operator's out-of-band `--approve`/`--revoke` can be reverted by the running proxy. | `mcp-shield/src/fingerprint.rs` | medium |
| 4 | The ingest response carries the tenant's whole revocation set on every request, so the payload grows with the total number of quarantines. The fix needs the dashboard *and* `python-common` to agree on snapshot-versus-delta. | `dashboard/app/api/ingest/route.ts`, `python-common/monolith_events/events.py` | low — contract change |
| 5 | `docs/OPEN_QUESTIONS.md` — refresh against what has landed. | `docs/OPEN_QUESTIONS.md` | medium |
| 6 | The AWS secret access key has no detector. Deliberately: 40 characters of base64 has a false-positive rate that would hard-block ordinary calls. Needs a shape-aware detector, not a regex. | `mcp-shield/src/sanitizer.rs` | low |

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
| `fix/security-hardening` | Until its commits are merged into `main`. |
