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

See [Identity and access model](docs/IDENTITY_AND_ACCESS.md) for the exact
principal, role, credential, and route contracts.
