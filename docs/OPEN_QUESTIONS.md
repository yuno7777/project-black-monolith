# Open questions

Real decisions this repository has not made yet, with the reasoning that led
to leaving them open. Each one names who it affects and what would settle it.
They are written down so they are decisions rather than omissions.

Nothing here is a bug. Every item is either a deliberate trade-off that a
future contributor might reasonably want to revisit, or a genuine ambiguity
that the code currently resolves one way and could resolve another.

**Last refreshed 2026-10-20** against `main` after the production-upgrades
merge. All twelve decisions still describe the current code. Two were
re-checked specifically: the ingest endpoint still has no rate limit (#8),
and `npm audit` still reports five high-severity development-only findings
through `braces` 3.0.3 (#9), so the `--omit=dev` gate stays. Revisit a
question when its decision is made, not when a merge lands.

---

## 1. Should the Secret Boundary crate become a cargo workspace member?

**Status:** open. **Affects:** `crates/pbm-secret-boundary`, `mcp-shield`.

The crate is a path dependency of `mcp-shield` but is **not** a workspace
member, so it resolves independently: `mcp-shield/Cargo.lock` pins what
`mcp-shield` builds, and `crates/pbm-secret-boundary/Cargo.lock` pins what
the crate builds standalone. The two can drift on shared dependencies
(`url`, `serde`, `chrono`) without either build noticing.

**The argument for a workspace:** one lock file, one resolution, one
`cargo test` invocation, and `cargo audit` sees the whole graph at once.

**The argument against:** a workspace makes `mcp-shield` part of a larger
build, which changes how it is built, vendored, and released. The crate's
independence is a feature — it knows nothing about MCP, the dashboard, or the
event transport, and a workspace does not change that, but it does change the
release unit.

**What would settle it:** a decision on whether `mcp-shield` and the crate
are ever released together. If they are, a workspace is the honest model.

---

## 2. Should `details` payloads be content-validated?

**Status:** open. **Affects:** the shared event contract, every module.

`contracts/schemas/event-envelope.v2.schema.json` validates the *shape* of
an event: `details` must be an object, and the envelope's identifiers must
be printable and bounded. It does not validate the *content* of `details`.

That is a deliberate design — `details` is free-form by design, so a module
can add a new detection without a contract change. But it means a future
contributor who puts a credential fragment, a raw prompt, or a PII value into
`details` would write it straight into the durable ledger, and no gate would
object. The ledger has a 7-day-plus retention and is readable by any operator
of the tenant.

**The options:** (a) keep it free-form and rely on review; (b) add a
narrow deny-list of key names (`secret`, `token`, `password`, `api_key`) to
the ingest route; (c) validate `details` per event type in the contract.

**What would settle it:** whether `details` is ever expected to carry
anything resembling a raw value. The current modules do not, but nothing
prevents it.

---

## 3. Should the boundary be a fourth attack in `run_full_demo.sh`?

**Status:** open. **Affects:** `run_full_demo.sh`, the demo narrative.

The Secret Boundary has its own fixture demo
(`mcp-shield/fixtures/run_secret_boundary_demo.sh`) that proves shadowing,
interception, fail-closed outbound, and no credential leakage. The
full-stack demo tells a different story — three attacks, one compromised
agent session, all correlating in the dashboard.

Wiring the boundary into the full demo would make the story complete: a
fourth layer, reporting under the same session, visible in the same feed.

**The argument against:** the full demo is currently three *attacks against
an agent*, and the boundary is a *defense that mediates credentials* — a
different kind of thing. It also needs a destination, and the only
destination available offline is one the SSRF guard blocks, so it would
demonstrate a refusal rather than a successful credential use.

**What would settle it:** whether the demo is meant to show "three attacks
detected" or "the whole defensive surface, exercised".

---

## 4. One boundary per agent identity — is that the right model?

**Status:** open. **Affects:** the boundary's configuration model.

The boundary serves **exactly one** identity, declared as `agent_id` in its
configuration. A policy rule naming any other identity is rejected at load
time as unreachable configuration.

This is right for the current deployment: MCP-Shield is spawned per agent
session, so one invocation *is* one session, and one config file is one
identity. It does not scale to a deployment where one proxy instance serves
many agents — that needs N configs, or a policy set that can name several
agents with a rule per agent.

**What would settle it:** whether the boundary is ever expected to serve more
than one identity from one process. The current `PolicyEngine` already
supports it (it matches on `(agent_id, operation_id)` and holds a rule list);
only the *configuration* is restricted to one.

---

## 5. Should `allow_private_ips` be exposed?

**Status:** deliberately not, but worth revisiting. **Affects:** the boundary's
HTTP adapter.

`HttpAdapterConfig` has an `allow_private_ips` flag, and the boundary uses
`HttpAdapterConfig::default()` — so it is `false` and cannot be changed. A
deployment that legitimately calls an internal service on a private network
therefore **cannot use the boundary at all**: `10.0.0.0/8`, `172.16.0.0/12`
and `192.168.0.0/16` are refused, as are `localhost` and the cloud metadata
addresses.

That is the right default — the flag is a "turn off the SSRF guard" switch,
and switches like that get flipped once and forgotten. But the cost is real:
an internal-only deployment is excluded from the feature entirely rather than
opting in loudly.

**What would settle it:** whether an internal-network deployment is a
supported target. If it is, the flag should be exposed with an
unmistakable name and a startup warning; if it is not, the current silence
is correct and should be documented as a deliberate exclusion.

---

## 6. Should the first-contact default change from `trust`?

**Status:** open. **Affects:** MCP-Shield's default posture.

`MCP_SHIELD_FIRST_CONTACT` defaults to `trust`: the first sighting of a tool
becomes its trusted baseline. `approve` withholds an unseen tool and parks it
for an operator instead.

The `approve` gate closes a real hole — a server can serve a tool that was
*already* poisoned before anyone looked, and under `trust` that poisoned
schema is registered as the baseline. The stateless sanitizer is the
backstop that fires on first contact, but it is a pattern matcher and it
misses novel payloads with no known marker.

**The argument for keeping `trust`:** it is the existing default, changing it
would alter the behaviour of every existing deployment, and the whole design
is built on "the fingerprint proves a schema has not changed".

**The argument for changing it:** a defence-in-depth product should not
default to blessing whatever it sees first.

**What would settle it:** the false-positive cost of `approve` in practice —
how often a legitimate new tool would be withheld and need an operator. That
number is not known, because the gate is opt-in and rarely enabled.

**This question is about the default, not about typos.** An *unrecognised*
value of `MCP_SHIELD_FIRST_CONTACT` now fails closed to `approve` and emits
a `configuration_invalid` event, because a mistyped value must not be the
thing that disarms the gate. The *unset* default is still `trust`, and
changing it is still the open question above.

---

## 7. What should happen to the *oldest* evidence when the spool is full?

**Status:** open. **Affects:** `mcp-shield/src/outbox.rs`, `python-common`.

Both outboxes cap their pending queue (10,000 records) and, when the cap is
hit, **drop the oldest undelivered records**. The reasoning is that the
newest detections are the most actionable.

That is a defensible choice, but it means that under a sustained ingest
outage the *earliest* evidence of an attack is the first thing lost — and
the beginning of an attack is often the most valuable part of the record.
The alternative is to dead-letter the overflow instead of dropping it, which
preserves a record that something was lost without preserving the content.

**What would settle it:** how long a real ingest outage can last before the
cap is reachable, and whether an operator would rather have "we lost 4,000
oldest events" recorded or have those events on disk.

---

## 8. Should the ingest endpoint be rate limited?

**Status:** open. **Affects:** `dashboard/app/api/ingest/route.ts`.

The ingest endpoint authenticates per module and per tenant, but it does not
**rate limit**. An authenticated module that floods the dashboard degrades it
for every other operator. The bearer token scopes *who* may write, not *how
much*.

The operator login route *is* rate limited
(`20260803092707_add_operator_login_rate_limits.sql`), so the asymmetry is
deliberate — but it is an asymmetry worth closing.

**What would settle it:** whether a compromised or malfunctioning module is
in the threat model. It should be: the modules are the components most
likely to be attacked, and a flooding module is a plausible way to blind the
operator before a real attack.

---

## 9. When can the `braces` advisory exemption be dropped?

**Status:** open, time-boxed. **Affects:** the dashboard CI gate.

The dashboard's `braces` advisory (a stack-exhaustion DoS through deeply
nested glob patterns) has **no patched release at any version**, and it is
reachable only through the ESLint plugin's chain. The CI gate therefore
audits production dependencies only (`--omit=dev`), and the reasoning is
recorded in `SECURITY.md`.

**What would settle it:** `braces` publishing a fixed release. At that point
the `--omit=dev` flag should come off, and the gate should cover the whole
tree again.

---

## 10. Should the boundary's outbound TLS trust store be extensible?

**Status:** open. **Affects:** `mcp-shield/src/secret_boundary/transport.rs`.

The production transport uses `rustls` with the **platform verifier**, so
the trust store is whatever the host operating system provides. There is no
way to add a private CA from the boundary's configuration, which means an
endpoint served by an internal CA is unreachable (see question 5 — the same
gap, seen from the certificate side).

Most TLS stacks solve this with an explicit "additional roots" mechanism.
This one does not have one, deliberately or not.

**What would settle it:** whether a private-CA deployment is a supported
target. If it is, the transport needs a documented way to add roots, and the
way it is added matters more than the fact that it is added: a trust store
that a configuration file can widen is a trust store that will be widened.

---

## 11. Is the mock credential provider safe enough to ship in the binary?

**Status:** open. **Affects:** the boundary's provider selection.

`active_provider: "mock"` with `synthetic_secrets` is a supported
configuration, and the provider is compiled into the shipped binary. A
configuration left in production would issue synthetic values to a live
endpoint — the failure mode is a broken integration rather than a leak, but
it is a failure mode.

The counter-argument: the mock provider is what makes the boundary testable
offline and demoable without a vault. Removing it from the binary would mean
the tests could not exercise the production code path.

**What would settle it:** whether a build-time feature flag for the mock
provider is worth the cost of a second build configuration.

---

## 12. Should the event envelope's `module` enum grow?

**Status:** open, low priority. **Affects:** the shared contract.

The boundary emits its events under `module: "mcp-shield"` with
`details.subsystem: "secret-boundary"` as the discriminator, because the
contract enumerates `module` as `["mcp-shield", "vector-anchor",
"trace-audit"]` and the dashboard rejects anything else with a permanent
422.

Registering `"secret-boundary"` as a first-class module would be cleaner
semantically — it *is* a separate capability — and would let the dashboard
show it as its own panel rather than a subsystem of the tool layer. It would
also be a breaking contract change requiring a schema version bump.

**What would settle it:** whether the dashboard wants a separate panel for
the boundary, which is a product decision rather than a technical one.
