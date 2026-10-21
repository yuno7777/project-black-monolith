# CIA trade-off analysis

Project Black Monolith is a detection-and-blocking layer, not a data store of
record. That single fact drives every trade-off below: the system is built so
that **failing closed against an attacker is more important than failing open
for an operator**, and the ledger is an *evidence* log rather than a system of
record for the data it describes.

This document states, per layer of the triad, what the system protects, what
it deliberately gives up, and which failures are acceptable. It is written to
be falsifiable: every claim here names the mechanism that implements it, so a
reviewer can check the claim rather than take it on trust.

---

## Scope and threat model

The protected assets are:

1. **Agent-facing integrity** — the tool schemas, prompts, memory documents
   and reasoning traces that reach a model. A poisoned schema, a bait
   document, a divergent trace, or a reflected secret is the primary risk.
2. **Credential confidentiality** — API tokens, keys and certificates that
   must never enter a model context.
3. **Evidence integrity** — the append-only ledger of what was detected, on
   which incident response and any later audit depend.
4. **Tenant separation** — one operator tenant must not observe or influence
   another's evidence.

Out of scope: the confidentiality of the *data* the agent legitimately
retrieves. The system protects the pipeline, not the payload it carries.

Trust levels, in the sense used throughout the codebase:

| Level | Examples | Assumed |
| --- | --- | --- |
| Untrusted | model output, agent tool arguments, upstream API responses, public web | Fully attacker-controlled |
| Semi-trusted | the agent runtime container | Correctly identifies itself, but its arguments are not |
| Trusted | the policy engine, the credential provider, the operator's browser session | Correctly configured and not tampered with |

---

## Confidentiality

### What is protected, and how

| Asset | Control | Where |
| --- | --- | --- |
| Raw credentials | The agent never receives one. The boundary resolves the secret, injects it into the outbound request internally, and returns only a redacted body. | `crates/pbm-secret-boundary/src/broker.rs`, `src/operation/http.rs:702` |
| Secrets in memory | `SecretString` zeroes its heap buffer on drop; `Debug`/`Display` always print `[REDACTED SECRET]`; `as_raw_bytes` is compiled out of production builds. | `crates/pbm-secret-boundary/src/secret.rs` |
| Secrets in transit | HTTPS only, with certificate and hostname verification via `rustls` and the platform verifier. Cleartext HTTP is rejected at the transport. | `mcp-shield/src/secret_boundary/transport.rs:127` |
| Secrets in logs | Error strings are scrubbed of the secret before they leave the transport; audit events record the *reference path* (`op://vault/item/field`), never the value. | `src/operation/http.rs:724`, `src/event.rs:66` |
| Secrets in the dashboard | The ingest endpoint is authenticated per module; the ledger stores event envelopes, which never carry a secret by construction. | `dashboard/app/api/ingest/route.ts` |
| PII in reasoning traces | `pii_scanner.py` → `redaction.py` redact before the token is forwarded or logged. | `trace-audit/src/` |
| Cross-tenant leakage | Every store operation binds a transaction-local tenant context, and Row Level Security independently checks it on top of the application's explicit predicates. | `supabase/migrations/20260727091512_production_trust_model.sql` |
| Operator credentials | Browser sessions are opaque, HttpOnly, expiring and revocable. Module ingest tokens are scoped by tenant *and* module. | `docs/IDENTITY_AND_ACCESS.md` |

### Deliberate give-ups

- **The boundary cannot extend the TLS trust store.** The production transport
  uses the platform verifier, so an endpoint served by a private CA is not
  reachable. This is a confidentiality *and* availability trade: refusing an
  unverifiable certificate is correct, but it makes some legitimate
  deployments unreachable. There is deliberately no configuration switch for
  it, because a switch that widens the trust store is exactly the kind of
  knob that gets flipped once and forgotten.
- **The mock credential provider ships in the binary.** `active_provider:
  "mock"` with `synthetic_secrets` is a legitimate local-development
  configuration. It is a real footgun: a configuration left in production
  would issue synthetic values to a live endpoint. The mitigation is that the
  values are visibly synthetic and the provider is never the default for a
  non-`mock` selection.
- **Subprocess environment isolation is not total.** The 1Password CLI child
  receives a safe allowlist, but the parent process's own environment still
  holds the service-account token. A compromise of the parent is a compromise
  of the token.
- **The boundary's provider reference is visible in the audit log.**
  `credential_ref` names the vault, item and field. That is a disclosure of
  *structure*, not of value — but it is disclosure, and it is deliberate,
  because an audit trail that cannot say which credential was used is not an
  audit trail.

### Known residual risk

- **Zeroization is best-effort.** `SecretString` overwrites its own buffer,
  but the operating system may have paged it to swap, the allocator may have
  copied it, and a debugger can read it while live. This is documented in
  the crate's `THREAT_MODEL.md` rather than papered over.
- **The shared event contract is an implicit channel.** Every module's
  `details` payload is free-form text. A future contributor who puts a
  credential fragment in `details` would leak it into the ledger, and the
  contract would not object. The contract validates *shape*, not *content*.
  See the open questions in `docs/OPEN_QUESTIONS.md`.

---

## Integrity

### What is protected, and how

Integrity is the property this system actually exists to provide, so it has
the most defences.

| Attack | Control | Where |
| --- | --- | --- |
| Tool-schema rug pull | HMAC-SHA256 over a canonical serialization of every tool in `tools/list`, compared against a stored baseline. The baseline is **never overwritten** on mismatch, so a poisoned schema re-flags on every serving. | `mcp-shield/src/fingerprint.rs` |
| Tool poisoning (description) | Three stateless detector families: instruction-override phrases, shell-command substrings, and invisible Unicode. Statelessness matters: it fires on the *first* sighting, before any baseline exists. | `mcp-shield/src/sanitizer.rs` |
| Poisoned first contact | `MCP_SHIELD_FIRST_CONTACT=approve` withholds an unseen tool and parks it for an operator, so trust-on-first-use becomes an explicit decision. Approval pins the *first* clean sighting, so a server cannot show a clean tool, wait for approval, and swap in a poisoned one. | `mcp-shield/src/proxy.rs` |
| Corpus poisoning (memory) | Per-document frequency tracking clusters the queries a document surfaced for and quarantines one that spans ≥ `min_distinct_topics` mutually dissimilar clusters. The next-best clean result is served instead. | `vector-anchor/src/frequency_tracker.py`, `quarantine.py` |
| Reasoning divergence | Rolling KL divergence against a captured baseline distribution. Off-baseline tokens collapse into an `<other>` bucket with near-zero baseline mass, so divergence spikes instead of being averaged away. The stream terminates early with a safe refusal. | `trace-audit/src/divergence_monitor.py` |
| Credential substitution | The policy engine binds the credential reference to the operation. An agent cannot name a reference, a host, a method, or an `Authorization` header. | `crates/pbm-secret-boundary/src/policy.rs` |
| Destination tampering | Host, port, scheme, method, path prefix and query-parameter allowlists, all evaluated fail-closed. The path check is segment-aware, so `/v1/forecast-admin` does not satisfy a prefix of `/v1/forecast`. | `src/policy.rs:111` |
| SSRF / DNS rebinding | Every resolved address is validated; if *any* address in a multi-address answer is prohibited, the whole request fails closed. The socket then connects only to the validated addresses, so the answer cannot change between validation and connection. | `src/operation/http.rs:621` |
| Credential leak by redirect | `3xx` responses fail the operation. Redirects are the classic way a credential reaches an origin the policy never approved. | `src/operation/http.rs:732` |
| Shadowing / impersonation | A backend tool sharing a name with a secret-bound tool is dropped from the agent-facing catalogue in **both** enforce and monitor mode, and calls to that name are answered locally. | `mcp-shield/src/proxy.rs:835` |
| Injection via the boundary | The boundary's own responses never travel the server-to-agent path, so they never reach the description sanitizer. The upstream body is therefore scanned explicitly before it reaches the model. | `mcp-shield/src/secret_boundary/mod.rs:398` |
| Evidence tampering | The ledger is append-only for events; the incident audit trail rejects `UPDATE` and `DELETE` by construction. Triage never mutates the underlying event. | `supabase/migrations/`, `verify_incidents.sh` |
| Evidence duplication | `event_id` is a UUIDv4 and the insert is `on conflict (event_id) do nothing`, so redelivery after an uncertain failure is a no-op rather than a duplicate row. | `dashboard/lib/event-store.ts:176` |
| Evidence loss | Delivery is durable, not fire-and-forget: every module spools to disk and fsyncs *before* the detection path continues, then retries with backoff and dead-letters permanent rejections rather than dropping them. | `mcp-shield/src/outbox.rs`, `python-common/monolith_events/events.py` |

### Deliberate give-ups

- **Detection is not prevention.** MCP-Shield rewrites the `tools/list` it
  forwards and answers a secret-bound `tools/call` locally, but a compromised
  *backend* can still influence the agent through channels the proxy does not
  inspect, and VectorAnchor and TraceAudit detect after the fact rather than
  refusing the query. The system's claim is "detected and reported", not
  "attacked and stopped", with the exception of the two rewrite paths above.
- **The fingerprint is exact, the sanitizer is statistical.** The fingerprint
  has 100% mutation detection *by construction* — it is an exact comparison,
  not a tuned detector — and that is reported as such. The sanitizer is a
  pattern matcher with an honest recall floor (currently 0.70 on the labelled
  corpus) and it *misses* novel injection phrasings that carry no known
  marker. The benchmark corpus deliberately includes such misses.
- **Monitor mode forwards mutated schemas.** That is the entire point of
  monitor mode: it logs without correcting. An operator who runs monitor mode
  is accepting exposure in exchange for observation.

### Known residual risk

- **The first-contact gate is opt-in.** The default is `trust`. In the
  default configuration, a tool that was *already* poisoned before anyone
  looked is registered as the trusted baseline. The stateless sanitizer
  catches the common cases on first contact, but a payload with no known
  marker will be blessed.
- **A compromised upstream can still exfiltrate through an approved
  operation.** If an approved service accepts arbitrary text, an agent can
  use that operation to send other data outward. The policy constrains
  methods and parameters, not the *meaning* of the payload.
- **The dashboard is a single point of view, not a single point of truth for
  the detection logic.** Each module decides what to detect; the dashboard
  only records and displays. A module that never detects produces an empty,
  healthy-looking feed.

---

## Availability

### What is protected, and how

| Failure | Behaviour | Where |
| --- | --- | --- |
| Dashboard down | Modules keep detecting. Events spool to disk, are retried with jittered exponential backoff, and are delivered when the dashboard returns. | `verify_recovery.sh` |
| Poison-pill event | A malformed `event_id` is a permanent `422`, not a `5xx`, so it dead-letters on arrival instead of blocking the spool behind it. | `dashboard/lib/event-store.ts:20` |
| Unbounded spool | Capped: the Rust spool holds at most 10,000 records and 16 MiB in `outbox.jsonl`, and the same again in `outbox.dead` — the two files keep budgets of their own; the Python outbox holds 10,000 pending / 2,000 dead. The oldest records are dropped first. | `mcp-shield/src/outbox.rs:57`, `events.py:354` |
| Unbounded event size | 256 KB maximum payload; a 5 MB maximum response body on the boundary's outbound requests, enforced incrementally while streaming. | `events.py:24`, `transport.rs:82` |
| Slow upstream | Bounded timeouts on the event delivery path (2 s connect, 3 s response) and on the boundary's outbound requests (10 s default). | `outbox.rs:70`, `http.rs:363` |
| Detector bug in MCP-Shield | **Fail-open**: the message is forwarded unmodified and the error is logged at error level with a structured event. A detector bug must never masquerade as "nothing to flag" — but it must not break the agent either. | `mcp-shield/src/proxy.rs` |
| Detector bug in the boundary | **Fail-closed**: a broken boundary configuration aborts the proxy at startup rather than degrading to a partially enabled boundary. | `mcp-shield/src/secret_boundary/mod.rs:96` |
| Slow response body (boundary) | Streamed with a checked size counter, and the connection is dropped as soon as the bound is exceeded rather than after the body finishes. | `transport.rs:82` |
| Container escape surface | Every service runs `read_only: true` with `no-new-privileges`, a `tmpfs` `/tmp`, a memory limit and a PID limit. | `docker-compose.yml:15` |
| Least-privilege database | The dashboard sheds its migration privileges at runtime and uses a separate least-privilege role. | `20260727091512_production_trust_model.sql` |

### Deliberate give-ups

- **Detection is fail-open; authorization is fail-closed.** These look
  contradictory, and the asymmetry is the point. A *detector* that throws
  must not take the agent down with it — a broken regex should degrade to
  "no finding, plus an error event". An *authorizer* that throws must not
  hand out a credential it could not check — a broken policy engine must
  refuse the operation. Getting this backwards in either direction is a
  serious bug, and the asymmetry is stated here so it is a deliberate
  decision rather than an accident.
- **The ledger is eventually consistent.** A detection is durable before it
  is delivered, but delivery is asynchronous. During a dashboard outage the
  evidence exists only on the module's disk. That is a real limitation: the
  evidence is on the same host as the compromised component.
- **The single-node stack has no failover.** Postgres, the dashboard and the
  three modules run as containers on one host with named volumes. There is
  no replication, no leader election, and no multi-region story. The system
  is designed for a single-operator research deployment, not for a
  high-availability service.
- **The Python modules are long-lived and the Rust proxy is not.** MCP-Shield
  exits when the agent closes stdin, so it cannot retry on a long delay; it
  drains the backlog on startup and force-drains before exit, and a
  resident `--drain-outbox` worker owns the shared spool. This asymmetry is
  why MCP-Shield's delivery guarantees are slightly weaker than the Python
  modules' during the seconds between an agent disconnect and the next
  worker tick.

### Known residual risk

- **The spool cap drops the oldest evidence.** When the 10,000-record cap is
  hit, the oldest undelivered events are dropped, and the newest detections
  are kept because they are the most actionable. Under a sustained ingest
  outage the *earliest* evidence of an attack is the first to be lost. The
  drop is logged at error level, so it is visible — but it is still silent
  loss of evidence, deliberately chosen over unbounded disk growth. The byte
  cap is the same bound in bytes, and it is applied to each spool file on
  its own: `outbox.jsonl` and `outbox.dead` each hold up to 16 MiB, so the
  spool directory holds up to twice that. The two budgets are separate on
  purpose — a shared one would let a full dead-letter file starve the
  pending spool, and what the pending spool drops is a detection that has
  not been delivered yet.
- **No rate limiting on the ingest endpoint.** An authenticated module that
  floods the dashboard degrades it for everyone. The per-module bearer token
  scopes *who* may write, not *how much*.
- **A poisoned upstream body can exhaust CPU in the sanitizer.** The body is
  bounded at 5 MB, but the sanitizer runs a set of regexes over it, and the
  response arrives from a destination the policy approved.

---

## Where the three pull against each other

The triad is not a checklist; the interesting cases are where two
requirements collide and one has to give.

| Tension | Resolution | Cost |
| --- | --- | --- |
| Confidentiality vs. availability | A destination that cannot be verified is refused, even if it is a legitimate internal service. | Some private-CA endpoints are unreachable. No override is provided. |
| Integrity vs. availability | Detection is fail-open, so a broken detector never stops the agent. | A detector bug means an attack goes unblocked, silently, except for an `analysis_error` event. |
| Integrity vs. availability (boundary) | The boundary is fail-closed: a broken configuration refuses to start. | A typo in the config takes the proxy down instead of degrading. That is intentional — a boundary that half-works is worse than one that is visibly absent. |
| Integrity vs. confidentiality | The evidence log records the credential *reference*, not the value. | The audit trail discloses vault structure. |
| Availability vs. evidence completeness | The spool is capped and drops the oldest records. | Under sustained outage, the earliest attack evidence is lost. |
| Integrity vs. operator agency | Monitor mode forwards a mutated schema. | Observation is bought with exposure, and the operator has to know that. |

---

## What "good" looks like for this system

Concretely, the properties a reviewer should be able to confirm:

1. **No raw credential appears in any agent-facing output, any log line, any
   audit event, or the ledger.** Verifiable by the boundary demo and by
   `test_07_zero_secret_leakage_in_responses_and_audit`.
2. **A mutated tool schema is detected on every sighting, not just the
   first.** Verifiable by phase 3 of the rug-pull demo.
3. **A suspicious schema is never silently blessed as a baseline.** Only
   under the opt-in `approve` gate; otherwise the stateless sanitizer is the
   backstop.
4. **A detection survives a dashboard outage.** Verifiable by
   `verify_recovery.sh`.
5. **Evidence cannot be edited or duplicated after the fact.** Verifiable by
   `verify_incidents.sh`.
6. **One tenant's evidence is invisible to another.** Verifiable by the
   isolation checks in `verify_incidents.sh` and `verify_benchmarks.sh`.
7. **A failed detection degrades loudly, not silently.** The `analysis_error`
   event exists for exactly this.
8. **The system's own failure modes are documented, not hidden.** This
   document, the crate's `THREAT_MODEL.md`, and `SECURITY.md` are the
   record; each names the residual risks it does not fix.

---

## Related documents

- [`SECURITY.md`](../SECURITY.md) — reporting a vulnerability, scope notes, known dependency advisories.
- [`IDENTITY_AND_ACCESS.md`](IDENTITY_AND_ACCESS.md) — principals, roles, credentials, route contracts.
- [`OPERATIONS.md`](OPERATIONS.md) — the operator runbook.
- [`SECRET_BOUNDARY.md`](SECRET_BOUNDARY.md) — the credential mediation layer in detail.
- [`crates/pbm-secret-boundary/THREAT_MODEL.md`](../crates/pbm-secret-boundary/THREAT_MODEL.md) — the boundary's own threat model, in more depth than this document.
