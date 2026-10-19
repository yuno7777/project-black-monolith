# Security Policy

## Project intent

Project Black Monolith is **defensive** security tooling: it detects and
blocks attacks against autonomous AI agents (tool poisoning / schema rug
pulls, corpus poisoning, reasoning divergence, and PII leakage). Every
"attack" artifact in this repository — mutated tool schemas, the "universal
bait" document, the divergence prompt, the fake credentials — is a **local,
self-contained detection-test fixture** used only to validate that the
detectors fire. Nothing here targets live systems, third parties, or real
vulnerabilities, and there are no real secrets in the repository.

## Reporting a vulnerability

If you find a security issue in the tooling itself (for example, a detector
that can be bypassed, or a way the proxy could leak data it is meant to
protect), please report it privately rather than opening a public issue:

- Email: **abhisheksatarkar098@gmail.com** with the subject
  `[Black Monolith Security]`.
- Include a description, affected module, and reproduction steps.

You can expect an acknowledgement within a few days. As a single-maintainer
research project there is no formal SLA, but reports are taken seriously.

## Scope notes

- Dashboard reads and writes require a tenant-scoped operator identity.
  Browser sessions are opaque, HttpOnly, expiring, and revocable; API scripts
  may use the configured operator bootstrap token directly.
- Module ingest credentials are scoped by both tenant and module.
  VectorAnchor quarantine/configuration reads and corpus mutations, plus
  TraceAudit detector metadata, use a separate administrative token.
- The dashboard sheds its migration privileges at runtime with a least-
  privilege PostgreSQL role. Every store operation binds a transaction-local
  tenant context; RLS independently checks it in addition to the application's
  explicit tenant predicates.
- VectorAnchor `/retrieve` and TraceAudit `/generate` are service-to-service
  interfaces intended for a trusted network. Their `X-Monolith-*` headers
  provide attribution, not end-user authentication.
- The default MCP-Shield HMAC key and the offline mock model backend are for
  local development only; see the module READMEs before any real use.

## Known dependency advisories

**Dashboard lint toolchain — `braces` (GHSA-vfj7-8cjw-p6xm and related).**
The dashboard's `eslint-config-next` pulls in `@next/eslint-plugin-next` →
`fast-glob` → `micromatch` → `braces`. Every published version of `braces`
(through 3.0.3) is affected by a stack-exhaustion denial of service through
deeply nested glob patterns, and **no patched release exists at any version**,
so the chain cannot be cleared by upgrading. The affected packages are
lint-time only: they are not part of the running service, the patterns they
parse come from this repository's own ESLint configuration rather than from
user input, and the advisory requires an attacker to control those patterns.
CI therefore gates production dependencies with
`npm audit --audit-level=high --omit=dev`, which is what actually ships; a
high or critical advisory in a production dependency still fails the build.
Re-check when `braces` publishes a fixed release, and drop the `--omit=dev`
flag once the chain is clear.

See [Identity and access model](docs/IDENTITY_AND_ACCESS.md) for the exact
principal, role, credential, and route contracts.
