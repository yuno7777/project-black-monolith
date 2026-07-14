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

- This is a **single-operator local research/demo system**: it has no
  authentication, user accounts, or multi-tenant isolation by design. Do not
  expose the services to untrusted networks.
- The default MCP-Shield HMAC key and the offline mock model backend are for
  local development only; see the module READMEs before any real use.
