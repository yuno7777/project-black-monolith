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
| gateway-review | `fix/gateway-review-fixes` | the eleven findings from the agent-gateway review: credential containment in the shield and the launcher, the reasoning layer's answer path, the memory layer's attribution rule, the dashboard's session report | all eleven fixed, one commit each; the findings are recorded in `FINDINGS.md` with the commit that fixes each and the residuals. Worktree `C:/Users/Abhi/Desktop/monolith-wt/gateway-fixes`; branched off `fix/credential-redaction-success-path` so the credential-redaction work is included. `origin/main` merged in (PR #65), no history rewrite, so nothing was force-pushed |
| silent-defenses | `fix/silent-defense-failures` | the standing work that a failure turns a defence off without saying so: the shield's admin credential, the memory layer's truncated body, the Python outbox's oversized payload, the Rust outbox's fallback target, the dashboard's listener reconnect, and the revocation snapshot that stops being complete | worktree `C:/Users/Abhi/Desktop/monolith-wt/silent-defenses`, branched off `origin/main` (`1b6e8ed`) and rebased onto `f42721d`. One commit per finding, each proved by a test that fails before the fix. Six findings fixed (`FINDINGS.md` §3, §4, §7, §9, §10, §11); pushed, awaiting a merge |
| security | `fix/security-hardening` | retention scoping, evidence verification, fail-closed admin, DLP coverage, breaker batching, baseline locking | merged into `main` (`3634d23`); branch kept until cleanup |
| security | `feature/video-explainer` | the AEOS Guard explainer, rescued off a branch that was about to be deleted | pushed, 1 commit |
| security | `fix/mcp-shield/baseline-persist-failure` | the tool layer's fail-open path discarded enforcement it had already computed (`FINDINGS.md` §5) | merged into `main` as PR #64 (`1b6e8ed`); the fix is proved by mutating it back to the old behaviour and watching the new test fail. The branch was rebased onto `main` after #60 and #62 merged, so its history was rewritten and it was force-pushed |
| security | `fix/mcp-shield/malformed-tool-entry` | one malformed tool entry voided the whole `tools/list` defence for that server (`FINDINGS.md` §6) | merged into `main` as PR #66 (`f42721d`); the fix is proved by mutating it back to the old behaviour — one defective entry rejecting the whole listing — and watching all six new tests fail. Branched off `main` at `1b6e8ed`; no history rewrite, so nothing was force-pushed |
| integrator | `main` | upstream sync, security merges, Dependabot triage, verification | merged and pushed; CI green on `b19513b` |
| integrator | Dependabot | #24 merged (codeql-action); #15, #16 closed as superseded; #26 superseded by a direct hmac 0.13 migration | the queue is empty: **zero open PRs** |
| credential-transport | `fix/trace-audit/model-credential-transport` | the transport rule for the model credential the Anthropic gateway forwards upstream: the rule the modules already apply to their own delivery, applied to the one credential that had none (`FINDINGS.md` test gap 5, and §12, which is the defect it was hiding) | two fixes and two records; every one proved by mutating the fix back and watching the new test fail. Stacked on `fix/gateway-review-fixes` as PR #77, so it rebases onto `main` after #65 merges. Worktree `C:/Users/Abhi/Desktop/monolith-wt/credential-transport` |

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
| `dashboard/lib/incident-store.ts`, `dashboard/app/api/ingest/**` | security | circuit breaker and ingest path |
| `dashboard/lib/login-rate-limit.ts`, `dashboard/scripts/dispatch-alerts.mjs` | security | rate limiting and alert delivery |
| `supabase/migrations/**` | security | retention scoping migration |
| `contracts/openapi.yaml` | security | corrected the revocation snapshot wording — that branch is merged; `gateway-review` has since touched the same file, so the two rows are both live |
| `main` | integrator | Merges and verification only; branch work happens in a worktree. |
| `python-common/monolith_events/events.py`, `trace-audit/src/config.py`, `trace-audit/src/main.py`, `trace-audit/src/events.py` | credential-transport | the model credential's transport rule: the rule the modules already apply to their own delivery, applied to the credential the Anthropic gateway forwards upstream. Stacked on `fix/gateway-review-fixes`, so it rebases onto `main` after that merges. `python-common/monolith_events/events.py` overlaps the `silent-defenses` claim, but the two touch different functions |
| `scripts/monolith_wrap.py`, `scripts/tests/test_monolith_wrap.py` | credential-transport | the launcher's standard-library-only copy of the transport rule, brought into line with the shared one (`80f84f6`). Overlaps the `gateway-review` claim on the same file, and it is stacked on that branch, so the change rides on top of it rather than racing it |

Free to claim: `vector-anchor/**` (apart from the two files above),
`trace-audit/**` (apart from the four files above),
`dashboard/app/api/operations/**`, `dashboard/app/api/benchmarks/**`,
`docs/OPEN_QUESTIONS.md`, the Dependabot queue.

## Standing work

A wider survey of the repository landed on 2026-10-21: eleven defects, ten
test gaps, five documentation drifts, and five things checked and confirmed
sound. It is in [`FINDINGS.md`](FINDINGS.md), ranked, with each item marked
**verified** (read and confirmed at the cited lines) or **reported** (a
reader's lead, not yet checked). The items below are the board's own list.

| # | Item | Where | Priority |
| --- | --- | --- | --- |
| 1 | ~~The reasoning layer's KL divergence is off in every shipped configuration: nothing ever writes the baseline's `model` key, so the gate can never open.~~ | `trace-audit/src/main.py` | **done** — `6041854`, see `FINDINGS.md` §1 |
| 2 | A notification failure rolls back the evidence it was raised for: the alert-job row shares the security event's transaction. | `dashboard/lib/event-store.ts` | **high** — see `FINDINGS.md` §2 |
| 3 | ~~Every revocation snapshot is truncated at 64 KiB, so past ~1,700 live revocations the modules keep a stale set forever and the breaker fails open.~~ **Fixed** by `fix(revocation): page the snapshot so a large one is never half-read`: the snapshot is paged by a keyset cursor and both readers install it only once it has been read whole. | `dashboard/app/api/ingest/route.ts`, `python-common`, `mcp-shield` | **high** — see `FINDINGS.md` §3 |
| 4 | ~~The MCP-Shield status listener falls back to the module's ingest token as its admin credential.~~ **Fixed** by `fix(mcp-shield): keep the ingest token out of the status listener`: the administrative endpoints answer 503 without an administrative credential. | `mcp-shield/src/main.rs` | medium — see `FINDINGS.md` §4 |
| 5 | The ingest response carries the tenant's whole revocation set on every request, so the payload grows with the total number of quarantines. The fix needs the dashboard *and* `python-common` to agree on snapshot-versus-delta. **Bounded, not made a delta:** the ingest response carries the snapshot only while it fits in 16 KiB and otherwise carries the count alone, and the poll endpoint pages the whole set. The wire format is still a snapshot, so no module has to change its contract beyond the paging. | `dashboard/app/api/ingest/route.ts`, `python-common/monolith_events/events.py` | low — contract change |
| 6 | The AWS secret access key has no detector. Deliberately: 40 characters of base64 has a false-positive rate that would hard-block ordinary calls. Needs a shape-aware detector, not a regex. | `mcp-shield/src/sanitizer.rs` | low |

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
