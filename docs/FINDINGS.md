# Findings

Defects and gaps found by a read-only survey of the repository, recorded here
so they are not lost when a session ends. This is a **work list, not a set of
decisions** — the open trade-offs live in [`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md),
and what the agents are currently touching lives in
[`AGENT_BOARD.md`](AGENT_BOARD.md).

**How these were produced.** A fan-out of readers inspected each module
separately — the tool layer, the memory layer, the reasoning layer, the
dashboard, the launcher, the operations paths — and each reported what it
found with file and line references. Every item below is a *lead*: the
readers were not given the running code, so a line reference is a pointer to
check, not a proof.

**How to read the labels.**

- **verified** — I read the code at the cited lines and confirmed the
  behaviour. The failure mode is stated as something that happens, not
  something that might.
- **reported** — a reader's finding, not yet independently checked. Confirm it
  before acting on it.

Confirming one of these is cheap and worth doing first: most were cheap to
find precisely because they are simple, and a fix that lands on an
unconfirmed finding is a fix to the wrong thing.

---

## Verified defects

### 1. The reasoning layer's KL divergence is off in every shipped configuration

**Status:** verified. **Where:** `trace-audit/src/main.py`,
`trace-audit/fixtures/baseline_capture.py`. **Effort:** medium.

`_load_baseline_model` is the only reader of the baseline file's `"model"`
key, and `divergence_enabled = bool(baseline_model) and baseline_model ==
effective_model` is its only consumer. **Nothing ever writes that key.**
`_write_baseline_atomic` writes `{counts, total, vocab, distribution}`;
`fixtures/baseline_capture.py` writes `{counts, total, prompts, vocab}`. The
loader can therefore only ever return `None`, and the gate can therefore
never open.

Divergence detection on the Anthropic Messages gateway is silently off in
every shipped configuration. The only trace is an info-level
`divergence_disabled` event, so the ledger shows the reasoning layer running
while the KL check is not applied to the answer.

No test ever puts the gate in the armed state — `test_anthropic_gateway.py`
assigns `app.state.baseline_model` by hand, to `None` and to a mismatched
model, and never to a matching one. A regression in the key name, the file
format, or the model comparison would fail no test.

**What would settle it.** Decide what "the baseline's model" means when the
baseline is captured from one backend and the request is answered by another.
Then either write the key on capture or drop the gate, and cover both the
armed and the disarmed path.

### 2. A notification failure rolls back the evidence it was raised for

**Status:** verified, and fixed. **Where:** `dashboard/lib/event-store.ts`.
**Effort:** small.

`insertWithClient` inserts the security event and then, for a critical event
with alerting enabled, inserts into `monolith.alert_outbox` **using the same
client** — the same transaction. A failure of the second insert aborts the
transaction, so the `monolith.security_events` row is rolled back too. The
error propagates to the ingest route, which answers `503`, and the module
retries and finally dead-letters events that are perfectly valid.

The security-critical path is hostage to the notification path. A transient
`alert_outbox` error — a missing table after a partial migration, an RLS
`WITH CHECK` mismatch, a payload-size failure — destroys critical detections
rather than delaying them.

The coupling is deliberate; the comment at
`supabase/migrations/20260803120000_add_alert_delivery.sql` says "Critical
evidence is committed together with its webhook job". The two must not share
a failure mode: the event commits, and the job is written after, or the job
is written by a path that cannot roll the event back.

### 3. Every revocation snapshot is truncated at 64 KiB, so the breaker goes stale

**Status:** verified. **Where:** `dashboard/app/api/ingest/route.ts`,
`dashboard/app/api/sessions/revoked/route.ts`,
`dashboard/lib/incident-store.ts`, `python-common/monolith_events/events.py`,
`mcp-shield/src/outbox.rs`. **Effort:** medium.

The dashboard returns the tenant's **entire** live revocation list on every
ingest and on every poll. The query behind it —
`where tenant_id = $1 and restored_at is null order by revoked_at desc` — has
**no `LIMIT`**. Every reader caps the body at 64 KiB:
`response.read(64 * 1024)` at both `python-common` call sites, and
`MAX_INGEST_RESPONSE_BYTES = 64 * 1024` in the Rust spool.

A truncated body fails JSON parsing, so `observe_revoked_sessions` returns
`None` and `update_revoked_sessions_from_ingest` returns `-1` — both leave
the **previous, stale** set standing.

At roughly 39 bytes of JSON per session id, 64 KiB is about 1,700
simultaneously-unrevoked sessions in one tenant. Past that point both
channels truncate identically, so the 15-second poll is not a backstop: all
three modules keep a stale revocation set forever, and a session revoked
after the threshold is never refused. Restores require an analyst and
revocations never expire on a timer, so the live set only grows. The
documented design — "fails closed" — fails **open** on new revocations.

### 4. The MCP-Shield status listener falls back to the ingest token as its admin credential

**Status:** verified. **Where:** `mcp-shield/src/main.rs`,
`docker-compose.yml`. **Effort:** small.

`MONOLITH_ADMIN_TOKEN.ok().or_else(|| MONOLITH_EVENT_TOKEN.ok())` — the
status listener's administrative credential falls back to the module's
**ingest** bearer credential, which unlocks `GET /stats` and
`POST /admin/replay-dead-letters` (re-queueing every dead-lettered event).
The listener binds to `MCP_SHIELD_STATUS_BIND`, and `docker-compose.yml`
sets that to `0.0.0.0:8003`.

The shipped compose file sets `MONOLITH_ADMIN_TOKEN`, so the fallback is
inert there. In any deployment that sets only `MONOLITH_EVENT_TOKEN`, the
credential the module transmits on every event also grants dead-letter
replay on a listener bound to every interface. The ingest token is the
broadest-held secret in the module's environment and the worst candidate to
double as an administrative one.

The check itself is sound — `admin_authorized` fails closed on a missing or
short token. The problem is credential conflation, not a missing check.

### 5. The tool layer's fail-open path discards enforcement it has already computed

**Status:** verified, and fixed. **Where:** `mcp-shield/src/proxy.rs`,
`mcp-shield/src/fingerprint.rs`. **Effort:** small.

`store.save_if_dirty()?` runs **after** the sanitizer has dropped a poisoned
tool and **after** a rug-pull mismatch has staged the trusted schema, but
**before** the rewritten response is built. The `?` turns a persistence
error into an `Err` out of the analysis, and the caller fails open on it:
"forwarding response unmodified" discards the enforcement that was already
computed.

The failure is not transient in the way fail-open assumes. `BaselineStore::save`
clears the dirty flag only on success, so a persistently failing target (a
read-only volume, a full disk, a missing parent directory) leaves `dirty`
true and **every** subsequent `tools/list` re-enters the same failing save
and is again forwarded unmodified. Worse, `BaselineStore::check` registers a
never-seen tool as trusted in memory *before* the save is attempted, so the
poisoned definition becomes the in-memory baseline and matches on every
later listing.

A single disk error on the baseline path silently converts enforce mode into
pass-through for the whole MCP server, indefinitely, while the ledger
records a detection that looks like it was enforced.

### 6. One malformed tool entry voids the whole `tools/list` defence for that server

**Status:** verified, and fixed. **Where:** `mcp-shield/src/proxy.rs`. **Effort:** small.

`validate_tool_entries` rejects the **whole list** if any single advertised
tool lacks a non-empty name or an object `inputSchema`. The rejection
returns `Malformed` **before** any tool is fingerprinted or sanitized, and
`Malformed` maps to "do nothing", so the original response is forwarded
verbatim.

A server that appends one decoy tool without an `inputSchema` — a spec
violation many servers make accidentally — permanently turns off both
rug-pull fingerprinting and description sanitization for that server, in
enforce mode, with only a warning-level event. This is a
single-malformed-entry attack on the defence itself: the fail-open rule
applied to the enforcement path without telling the operator enforcement is
off.

**The fix.** The whole-list rejection is gone: every tool is inspected on its
own, and a defect belongs to a tool rather than to the listing. A tool the
shield cannot vouch for — not an object, no usable name, a name that is too
long or claimed twice, a description that is not text — is **withheld** from
the agent and never seeds a baseline, while the rest of the listing is still
fingerprinted, scanned and served. A tool that only breaks the spec (a
missing or non-object `inputSchema`) is **kept**: the shield does not read
the input schema, so nothing stops it from doing its job, and the operator
is told. Both are reported as `tool_malformed`, with `action:
withheld_malformed` (warning) or `action: analysed` (info).

The fix is proved by mutating it back to the old behaviour — one defective
entry rejecting the whole listing — and watching all six new tests fail
while every pre-existing test still passes.

### 7. The VectorAnchor MCP server still dies on a truncated error body

**Status:** verified, and fixed. **Where:** `vector-anchor/src/mcp_server.py`. **Effort:** small.

`except urllib.error.HTTPError as error: detail = error.read()...` reads the
body of a 5xx **inside** the handler, and `error.read()` raises
`http.client.IncompleteRead` when the service stops mid-body. An exception
raised inside an `except` block is not caught by the sibling clause, so it
escapes `_call_service`; `_handle_call` catches only `RuntimeError` and
`main()` has no handler. The MCP server process dies mid-session and takes
the agent's retrieve tool with it.

The existing test covers only the 200 path — it sets the truncation but
leaves `status = 200`.

**The fix.** The error body is read by a helper that cannot raise: the
status code is the fact, the body is a nicety, and a nicety that cannot be
read is reported as such instead of taking the server down. Underneath
that, a retrieve call can no longer kill the session either way — any
exception the clauses above do not name becomes an error result on the
wire, with the traceback on stderr for the operator.

The fix is proved by mutating it back: with the old read of the error body
restored, the new test fails because the server never answers — the
`queue.Empty` is the crashed process.

### 8. The revocation snapshot carries session ids only

**Status:** reported. **Where:** `dashboard/app/api/ingest/route.ts`,
`dashboard/app/api/sessions/revoked/route.ts`, `dashboard/lib/incident-store.ts`,
`mcp-shield/src/outbox.rs`, `python-common/monolith_events/events.py`.
**Effort:** medium.

The ledger's revocation key is `(tenant_id, agent_id, session_id)`, and the
breaker's own query joins on both. The wire format drops the agent: the
snapshot emits `session_id` only, and the module-side check is by session id
alone.

The session id is a client-supplied header the agent framework controls. Two
agents in one tenant that reuse a session id are treated as one by the
modules, so revoking agent A's session also cuts off agent B's traffic. The
direction is over-blocking rather than bypass, but the operator cannot tell
which agent was cut off.

### 9. The live-event listener schedules no reconnect after a failed initial LISTEN

**Status:** reported. **Where:** `dashboard/lib/event-ingest.ts`. **Effort:** small.

A listener failure during the **initial** `LISTEN` schedules no reconnect, so
open SSE streams go silently stale — a client keeps a connection that will
never carry another event and has no way to tell.

### 10. The Python outbox raises out of the emitter on an oversized payload

**Status:** reported. **Where:** `python-common/monolith_events/events.py`.
**Effort:** small.

An oversized event payload raises out of the emitter instead of being
spooled, so the event is lost entirely rather than being delivered late.

### 11. The Rust outbox's fallback target points at the SSE endpoint with an empty token

**Status:** reported. **Where:** `mcp-shield/src/outbox.rs`. **Effort:** small.

When no dashboard URL is configured, the fallback target is the SSE endpoint
with an empty credential, so every event dead-letters.

---

## Test gaps

These are paths the code takes that no test exercises. Each is a place a
regression would be invisible.

| # | Gap | Where | Effort |
| --- | --- | --- | --- |
| 1 | The divergence gate is never tested in its **armed** state. | `trace-audit/tests/test_anthropic_gateway.py` | medium |
| 2 | The entire triage write path is untested: validation, state change, audit trail. | `dashboard/app/api/triage/**` | medium |
| 3 | The incident-queue read path is untested: filter parsing, keyset pagination, counts. | `dashboard/lib/incident-store.ts` | medium |
| 4 | The detector-reset path is untested end to end, on both sides of the wire. | `vector-anchor`, `dashboard` | medium |
| 5 | The rule deciding whether a credential may travel over plain HTTP to the upstream model is neither present nor tested. | `trace-audit/src/anthropic_gateway.py` | medium |
| 6 | TraceAudit's prompt projection drops every non-text content block, and is never tested against one. | `trace-audit/src/anthropic_gateway.py` | medium |
| 7 | The divergence detector's real-model behaviour is asserted by no committed result. | `trace-audit/fixtures/` | medium |
| 8 | The production Postgres branch of the session list is never executed by any test. | `dashboard/app/api/sessions/route.ts` | medium |
| 9 | The benchmark ledger's write and read paths are untested, route included. | `dashboard/lib/benchmark-store.ts` | small |
| 10 | The two functions the memory-layer detector's hot path depends on are untested; the one that is tested is not on the hot path. | `vector-anchor/src/frequency_tracker.py` | small |

---

## Documentation drift

| # | Drift | Where | Effort |
| --- | --- | --- | --- |
| 1 | The Rust spool's byte cap is documented as covering both spool files but is enforced independently on each. | `mcp-shield/src/outbox.rs` | small |
| 2 | The launcher's ambient-proxy rule is weaker than the secret-boundary rule it cites, and its safety argument fails for the Windows system proxy it was written for. | `scripts/monolith_wrap.py` | medium |
| 3 | The proxy default change silently alters the preflight health checks, which can now abort the launcher. | `scripts/monolith_wrap.py` | small |
| 4 | `generation_truncated` reaches the feed but is counted as an "attack" by the overview KPI, and is named in no documentation. | `dashboard/app/page.tsx` | medium |
| 5 | The dashboard fix corrected the session report; the console's headline detection number still counts operational failures. | `dashboard/app/page.tsx` | small |

---

## Confirmed sound

Recorded so they are not re-checked. Each was examined specifically and held
up.

- **The rug-pull fingerprint covers every field an attacker mutates.**
  (`mcp-shield/src/fingerprint.rs`)
- **The slow-drip / cap-flood evasion is closed**, and the residual limit is
  honestly pinned. (`vector-anchor/src/frequency_tracker.py`)
- **Credential mediation and shadowing hold in both modes**; the agent cannot
  obtain a raw secret or choose the destination.
  (`crates/pbm-secret-boundary`, `mcp-shield/src/secret_boundary/`)
- **Inside a streamed answer the auditor sees every token**, and the PII
  buffer's hold-back does not blind it. (`trace-audit/src/stream_proxy.py`)
- **The breaker's per-candidate query is one query for the whole batch**, the
  baseline is locked across its read-modify-write cycle, and the open
  questions were refreshed on 2026-10-20. (`docs/AGENT_BOARD.md`)

---

## Already fixed

- **The module dead-letter replay was global** while the database half of the
  same function was tenant-scoped, so a tenant admin replayed other tenants'
  dead letters and had them counted as their own. Fixed in PR #59, which
  scopes the replay to one tenant across the dashboard, both module
  endpoints, the shared Python outbox and the Rust spool.
- **The operator's credential could reach the client through a normal
  answer.** The literal redaction pass covered only the upstream error body;
  a 200 answer was protected by the pattern scanner alone, and no pattern can
  catch a hyphenated Anthropic key. Fixed in PR #60.
- **A notification failure rolled back the evidence it was raised for** (§2
  above). The security event and its alert job shared one transaction, so a
  transient `alert_outbox` error rolled the detection back too, answered
  `503`, and sent the module into a retry-and-dead-letter loop over an event
  that was perfectly valid. Fixed in PR #63: the event commits, and the job
  is written by a path that cannot roll it back.
- **A mistyped control setting turned the control off.** Two settings failed
  open on a typo, in the quiet direction.
  `MCP_SHIELD_FIRST_CONTACT=aprove` was read as `trust` — the shield warned
  on stderr and then blessed every unseen tool as the baseline, and the
  operator's stderr is the agent host's MCP log, not the console they watch.
  A malformed `MONOLITH_SESSION_POLL_MS` stopped the cross-layer revocation
  poller outright, in both the Rust spool and the shared Python emitter,
  with no log line at all — and the poll is the only way an idle module
  learns that its session was revoked. Fixed in PR #62: an unrecognised
  *explicit* value now resolves to the outcome that cannot lose a
  detection and emits a `configuration_invalid` event, and an unreadable
  cadence falls back to the default and says so. The *unset* defaults are
  unchanged: only the default is in question, and a typo is not an answer to
  that question.
- **The tool layer's fail-open path discarded enforcement it had already
  computed** (§5 above). A failed baseline write aborted the whole analysis
  with a `?`, so the server's original bytes — the poisoned schema — were
  forwarded while the ledger recorded the response as rewritten, and a
  registration that could not be written stood as a trust decision. Fixed in
  PR #64: the rewrite is built before the baseline is written, a failed
  write is reported as `baseline_persist_failed` rather than
  `analysis_error`, a registration that could not be written stops counting
  as a trust decision, and an event's `action` says what the agent was
  actually sent.
- **One malformed tool entry turned off the defence for every tool beside
  it** (§6 above). The `tools/list` validator rejected the whole listing on
  the first broken entry, before a single tool had been fingerprinted or
  scanned, and a rejected listing is forwarded verbatim — so a server
  advertising one decoy tool permanently disarmed both rug-pull
  fingerprinting and description sanitization for that server. Fixed in
  PR #66: each tool is inspected on its own, a tool the shield cannot vouch
  for is withheld, a tool that only breaks the spec is still fully checked
  and served, and the rest of the listing keeps its protection.
- **The memory layer's door died on a truncated error body** (§7 above). The
  body of a 5xx is read inside the handler that caught the error, and an
  exception raised there is not caught by the sibling clauses of the same
  `try` — so a service that answered `500` with a body it never finished
  sending killed the MCP server and took the agent's retrieve tool with it.
  Fixed in PR #67: the error body is read by a helper that cannot raise,
  and a retrieve call that fails in any way comes back as an error result
  on the wire instead of taking the session down.
