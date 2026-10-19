# Integration plan: the parallel feature branches

This records how the branches built by the other agent's worktrees are being
folded into `main`, and what was decided at each conflict. It exists so the
integration can survive a context compaction, and so a reviewer can see why
each side was chosen where two sides differed.

## The branches

`feat/production-upgrades` is the integration branch. It already contains all
four of the workstream branches as ancestors, plus two commits of its own:

| Commit | What it is |
| --- | --- |
| `2796a34` | `feat(trace-audit)`: OpenAI proxy, split-token PII holdback, hot baseline reload |
| `fc73502` | `feat(vector-anchor,outbox)`: bounded detector state, dead-letter replay, granular quarantine controls |
| `be21a35` | `feat(dashboard,db,infra)`: cross-layer session circuit breaker, signed evidence bundles, operations/retention upgrades |
| `2919a8d` | `feat(mcp-shield)`: outbound tool-call DLP, live baseline reload, outbox replay & status HTTP, `EnvSecretProvider` |
| `44edf06` | merge of the three workstream branches |
| `e8eb1bc` | `test(contracts)`: cover upgraded endpoints, event types, OpenAI-compatible API |
| `864a667` | `feat(circuit-breaker)`: enforce revoked sessions across every layer |

The four workstream branches are therefore **ancestors** of
`feat/production-upgrades` and carry no unique content. They are safe to
delete once the integration lands.

`fix/security-hardening` points at the same commit as
`feat/production-upgrades` (`e8eb1bc`) and is a duplicate. Its worktree
lives at a stale path under the system temp directory and can be removed.

## The merge shape

The merge base of `main` and `feat/production-upgrades` is `268e17f`. From
there:

- `main` is 3 commits ahead: the TLS test-fixture fix, the dependency
  advisory fix, and a log-file cleanup.
- `feat/production-upgrades` is 7 commits ahead.

**Exactly one file is changed on both sides**:
`mcp-shield/src/secret_boundary/tests.rs`. The overlap is small because the
two workstreams touched different parts of the tree.

## Conflict decisions

### `mcp-shield/src/secret_boundary/tests.rs`

Both sides changed this file, in different regions.

**Ours** replaced the test PKI. The old fixture was a single self-signed
certificate with `basicConstraints CA:TRUE` presented directly as the server
certificate. webpki refuses an end-entity certificate that asserts it is a
CA (`CaUsedAsEndEntity`); the Windows platform verifier happens to accept
it, which is why the fixture passed on Windows and failed on Linux and
macOS. It is now a real chain — a root CA the client trusts, and a leaf
certificate for the test hostname signed by that CA — with the key encoded
via `pkcs8 -topk8` because `openssl pkey -outform DER` omits the public key
from the inner `ECPrivateKey` and ring requires it. The client also builds
an explicit rustls configuration rather than relying on
`add_root_certificate`, because the production transport uses the platform
certificate verifier, which ignores added roots.

**Theirs** appended two new tests at the end of the file: one for the
`EnvSecretProvider` and one asserting that the audit event attributes the
operation id as `resource_type`/`resource_id`.

**Resolution:** both are kept. The fixture region and the appended tests do
not overlap, so the merge is textual rather than a judgement call. If it
does conflict, ours wins in the fixture region and theirs wins at the
append point.

### `crates/pbm-secret-boundary/src/event.rs`

No conflict. Both sides had already changed this file before the merge
base — ours removed `to_pbm_shield_event_with_module` (a footgun that
could build an event the shared contract rejects), theirs improved
`generate_uuid_v4` from an XOR mix to FNV-1a plus two SplitMix64 avalanche
steps. Both changes are in the base, so they compose.

### The `EnvSecretProvider`

Additive. `active_provider` gains an `"env"` option that resolves a
credential from a process environment variable, with the variable name
required to carry a `PBM_SECRET_` prefix and validated at configuration
load. A reference without the prefix is rejected — the prefix is what
stops an agent-chosen reference from reading an arbitrary variable out of
the proxy's environment.

## Merge order

1. Merge `feat/production-upgrades` into `main` as a merge commit, so the
   workstream commits keep their own authorship in the history.
2. Resolve the single overlapping file as described above.
3. Re-verify everything locally, then push and let CI confirm across
   ubuntu, macOS and windows.

## Verification checklist

The integration is only landed when all of these pass:

- `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D
  warnings`, `cargo test --locked` for `mcp-shield` and for
  `crates/pbm-secret-boundary`, on Windows and inside a `rust:1.86`
  container (the toolchain CI pins).
- `cargo audit` clean on both crates.
- `python -m pytest`, `ruff`, `mypy` for `python-common`, `vector-anchor`
  and `trace-audit`, plus both detection-accuracy benchmark gates.
- `npm test`, `npm run lint`, `npm run build`, `npm audit --audit-level=high
  --omit=dev` for the dashboard.
- `python contracts/check_contracts.py`.
- The full stack: `docker compose up -d --build --wait`, all five
  integration verification scripts, `run_full_demo.sh`, and
  `fixtures/run_secret_boundary_demo.sh`.
- CI green across all 24 jobs and all three operating systems.

## After the merge

- Delete the four `subagent-*` branches: all four point at `268e17f` and
  carry nothing unique.
- Delete `fix/security-hardening` and remove its stale worktree: it is a
  byte-identical duplicate of `feat/production-upgrades`.
- Move the `video/` explainer project off `codex/preserve-local-work-2026-08-28`
  — that branch is 31 commits stale and is the only place that work
  exists — then delete the branch.
- Triage the 32 open Dependabot pull requests: merge the ones whose CI is
  green, close the rest. That is where the remote branch count actually
  goes.
