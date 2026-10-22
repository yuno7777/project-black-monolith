# Changelog

Every change that alters what the project does is recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
version numbers are the ones the four packages carry — `dashboard/package.json`,
`mcp-shield/Cargo.toml`, `crates/pbm-secret-boundary/Cargo.toml` and
`python-common/pyproject.toml` move together.

The long-form notes for a version live in `docs/RELEASE_*.md`. This file is
the running record of what changed and when.

## [Unreleased]

### Added

- **The agent gateway.** `monolith wrap --claude` puts a real agent session
  behind all three layers at once: every MCP server the agent would have
  started is started through MCP-Shield instead, VectorAnchor is added as a
  server it can call, and the model's traffic is routed through TraceAudit.
  The run's findings are filed under one session id and read back from the
  ledger when the agent exits. (`scripts/monolith_wrap.py`)
- **A dashboard page that onboards an agent.** `/onboarding` checks each
  layer, seeds the demo corpus, lists the sessions the ledger has seen, and
  renders the two commands the browser cannot run. No secret is ever rendered
  into the page.
- **The Anthropic Messages API behind the auditor.** `POST /v1/messages` on
  TraceAudit, so any Anthropic client can be pointed at it. The client's own
  credential is forwarded upstream untouched; the gateway holds no key of its
  own unless one is configured as a fallback.
- **The memory layer as an MCP server.** VectorAnchor serves one `retrieve`
  tool over stdio, and its answer says how many documents were withheld, so
  an agent knows its context is incomplete.
- **Cross-layer session revocation.** Two layers independently flagging a
  session is enough to revoke it everywhere until an analyst restores it. All
  three layers poll for the revoked set.
- **Credential mediation — the Secret Boundary.** An opt-in mode where the
  agent never receives a raw credential: it calls a policy-bound tool, and the
  proxy resolves the secret from a provider, injects it into the outbound
  HTTPS request internally, and returns a sanitized body.
- **A session report.** `GET /api/sessions/<id>` returns every event filed
  under one agent session, plus the counts an operator asks about.
- **Operations pages.** The investigation queue, the delivery backlog and dead
  letters, the evidence age, and the benchmark ledger.
- **A rate limit on the ingest path.** One module credential may file two
  thousand events a minute; past that it is told to wait. The budget belongs
  to the credential rather than to a source address, and it is counted in
  events rather than requests, so a module that posts one event per request
  still meets the limit. The counter lives in Postgres, with an in-memory
  fallback for a dashboard running without a database. A mistyped setting
  keeps the default in force — zero is a mistake, not an off switch.
- **A bounded revocation snapshot.** The live revoked set is capped so the
  body always fits a module's reader, carries a per-tenant revision, and
  says whether it is the whole set or a bounded prefix of it. A module told
  the body is incomplete adds to what it has rather than replacing it, so a
  truncation can no longer un-revoke a session.

### Fixed

- **A failed baseline write no longer forwards the poison.** The rewrite was
  built before the baseline was persisted, so a full disk or a read-only mount
  could not change what the agent received; the failed write is reported as
  `baseline_persist_failed`, and a registration made in that cycle stops
  counting as a trust decision. (#64)
- **The operator's credential can no longer reach the client through a
  normal answer.** The literal redaction pass covered only the upstream error
  body; a 200 answer was protected by the pattern scanner alone. (#60)
- **A mistyped control setting no longer turns the control off.**
  `MCP_SHIELD_FIRST_CONTACT` and `MONOLITH_SESSION_POLL_MS` both failed open
  on a typo, in the quiet direction. An unrecognised *explicit* value now
  resolves to the outcome that cannot lose a detection, and an unreadable
  cadence falls back to the default and says so. (#62)
- **A failed notification no longer destroys the detection it was raised for.**
  The event and its alert job shared one transaction, so a transient
  `alert_outbox` error rolled the detection back, answered `503`, and sent the
  module into a retry-and-dead-letter loop over a valid event.
- **The dead-letter replay is scoped to one tenant** across the dashboard,
  both module endpoints, the shared Python outbox and the Rust spool. A
  tenant admin no longer replays other tenants' dead letters. (#59)
- **The credential stays off the ambient proxy**, and the launcher's
  same-origin and trusted-proxy checks decide on the host the client actually
  addressed.
- **The console tells an operational failure from a detection**, and says when
  a session report was truncated.
- **The console's headline number no longer counts a crash as an attack.**
  "Attacks intercepted" was `critical + warning`, so a truncated generation
  and a broken upstream were attacks. There are three numbers now —
  detections, operational failures and truncated generations — and an event
  type the dashboard does not recognise is counted as unclassified rather
  than folded into the headline.
- **The status listener no longer falls back to the ingest token.** The event
  token is the credential a module POSTs events with, and the listener also
  serves an administrative endpoint, so the fallback conflated two
  credentials. The listener still starts and still answers `/health`; it
  says loudly that it has no administrative credential.
- **The live feed reconnects when it cannot start.** A failed initial
  `LISTEN` released the client and rethrew, so open SSE streams went
  silently stale and the operator watched a feed that was no longer
  updating.
- **A delivery response cut short is an error, not a prefix.** The Rust
  spool used a truncated body as if it were the whole answer, and the shared
  Python package read past its own cap. Both now report the failure, and
  the module's local set is left untouched rather than replaced with
  something half-read.
- **An oversized event is dead-lettered, not lost.** The shared Python
  package raised out of the emitter, so the event vanished instead of being
  spooled and recorded.
- **A module with no configured dashboard gets one record naming what is
  missing,** instead of one dead letter per event against the wrong
  endpoint with no credential.
- **A service that breaks mid-response no longer takes the MCP server down**,
  and a misbehaving upstream is handled honestly rather than silently.

### Changed

- **Every image builds from the repository root**, so the root `.dockerignore`
  is what decides what enters an image. A CI check keeps it in step with
  `.gitignore`, so a file that is not in the repository is not in the image.
- **The integration job has a ceiling.** It builds five images and runs eight
  verification scripts against a live stack; without a timeout, a hung step
  holds a runner for six hours and blocks every pull request behind it.

### Documentation

- The README was rewritten for a first-time reader.
- `docs/AGENT_BOARD.md`, `docs/FINDINGS.md` and `docs/OPEN_QUESTIONS.md`
  record what three concurrent sessions are each doing, which defects have
  been confirmed, and which trade-offs are still open.
- `docs/ROADMAP.md` is the plan for the phase after this one.

## [0.3.0] - 2026-09-20

The release candidate described in
[`docs/RELEASE_0_3.md`](docs/RELEASE_0_3.md): multilingual first-hit
retrieval indicators, paired protected/unprotected agent outcomes, a sustained
request-delivery gate, and portable native bundles with dependency
inventories and provenance. It remains a research prototype.

## [0.2.0] - 2026-09-20

The source release described in
[`docs/RELEASE_0_2.md`](docs/RELEASE_0_2.md): first-retrieval instruction
indicators, independently sourced evaluation, a three-stage protected note
workflow, and resilience tests.
