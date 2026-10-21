# PBM Secret Boundary

**PBM Secret Boundary** is an independent, security-focused Rust component designed to serve as a secure credential mediator for Project Black Monolith (PBM) and AI-agent middleware.

It enforces a strict security perimeter: **AI agents are never granted raw access to credentials, but may invoke pre-approved, policy-bound operations that consume those credentials internally.**

---

## Architecture Overview

```
                      ┌────────────────────────────┐
                      │    AI Agent / LLM Shell    │
                      └─────────────┬──────────────┘
                                    │ Request (Operation ID + Public Params)
                                    ▼
       ┌────────────────────────────────────────────────────────┐
       │                 PBM SECRET BOUNDARY                    │
       │                                                        │
       │  1. Policy Engine ────────► Fail-Closed Authorization  │
       │  2. Secret Provider ──────► In-Memory Zeroized Secret  │
       │  3. DNS Resolver ─────────► Controlled Name Resolution │
       │  4. IP Validation ────────► Rejects SSRF / Rebinding   │
       │  5. Connection Pinning ───► Binds Socket Destination   │
       │  6. Operation Adapter ────► Injects Secret Internally  │
       │  7. Sanitizer ────────────► Redacts Response & Logs    │
       │  8. Audit Logger ─────────► PBM Schema v2 Events       │
       └────────────────────────────┬───────────────────────────┘
                                    │ Pinned Outbound Authenticated Call
                                    ▼
                      ┌────────────────────────────┐
                      │    Approved Service FQDN   │
                      └────────────────────────────┘
```

---

## Directory Structure

```
pbm-secret-boundary/
├── Cargo.toml                 # Package definition, minimal dependencies & features
├── Cargo.lock                 # Pinned dependency versions (the crate is CI-locked)
├── config.example.json        # Example configuration for policies and providers
├── README.md                  # Comprehensive architectural and verification documentation
├── THREAT_MODEL.md            # Threat model, SSRF defenses & residual risk analysis
├── INTEGRATION.md             # Integration guide for PBM and MCP Shield
├── src/
│   ├── lib.rs                 # Root library exports
│   ├── error.rs               # Boundary error definitions (strictly sanitized)
│   ├── secret.rs              # Zeroizing SecretString container, redaction & gated test helpers
│   ├── policy.rs              # Fail-closed authorization engine & rule definitions
│   ├── event.rs               # Structured security audit events (PBM Schema v2)
│   ├── broker.rs              # Central SecretBoundaryBroker coordinator
│   ├── provider/
│   │   ├── mod.rs             # SecretProvider trait
│   │   ├── mock.rs            # Default mock provider with synthetic secrets
│   │   └── onepassword.rs     # Documented 1Password CLI provider (op read)
│   ├── operation/
│   │   ├── mod.rs             # Operation traits and request/response models
│   │   ├── http.rs            # HttpOperationAdapter with DNS pinning and SSRF guards
│   │   └── mock.rs            # Offline mock operation backend
│   └── adapter/
│       ├── mod.rs             # Wire adapter module
│       └── json_wire.rs       # External JSON request/response interface
└── tests/
    ├── boundary_tests.rs      # 21 comprehensive security integration tests
    └── onepassword_provider_tests.rs  # 20 provider-focused integration tests
```

### Configuration format

The configuration is **JSON only** — see [`config.example.json`](config.example.json).
The `mcp-shield` integration reads it from `MCP_SHIELD_SECRET_BOUNDARY_CONFIG`
(either a file path or an inline JSON string). Unknown fields are rejected.

Two fields deserve attention:

* `agent_id` is **required**. It is the identity the policy engine authorizes
  against. An implicit default would make the `agent_id` field of every policy
  rule decorative, because every request would present the same constant.
* Every `policy_rule.agent_id` must equal it. A rule naming another agent can
  never be matched by the process, so it is rejected at load time instead of
  surfacing later as a puzzling runtime denial.

---

## Core Security Invariants

1. **No Raw Secrets in Agent Context**: The boundary exposes no `get_secret` tool. Credentials never cross into model tokens, agent memory, or error streams.
2. **Policy-Bound Secrets**: Agents cannot select secret references (`op://...`). The policy engine strictly binds operation names to approved references.
3. **Port and Path Guard**: Destination ports are strictly enforced (preventing non-standard port attacks), and path prefixes require exact segment boundary matching (preventing suffix extension attacks like `/v1/forecast-admin` and directory traversal `..`).
4. **Header Injection Defense**: Rejects CRLF characters (`\r`, `\n`) or null bytes in header keys/values, and bans agent injection of `Host`, `Authorization`, `Proxy-Authorization`, or `Cookie`.
5. **DNS Rebinding & Connection Pinning Defense**:
   - Destination hostnames are resolved via a controlled resolution step (`DnsResolver` trait).
   - **Every** resolved `SocketAddr` is inspected against multi-stack SSRF rules: loopback (`127.0.0.0/8`, `::1`), link-local / cloud metadata (`169.254.169.254`, `fd00:ec2::254`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), CGNAT (`100.64.0.0/10`), multicast, and IPv4-mapped IPv6 (`::ffff:0:0/96`).
   - If **any** address in a multi-address response is dangerous, resolution fails closed immediately.
   - Connections are pinned to the validated socket addresses (`pinned_addrs`), preserving the canonical hostname for the HTTP `Host` header and TLS SNI.
6. **Redirect Defense**: Automated HTTP redirects (301, 302, 303, 307, 308) are strictly rejected to prevent credential leakage to unapproved origins.
7. **Memory Zeroization**: Memory holding secrets (`SecretString`) is actively overwritten with zeroes upon drop using `zeroize`. Direct memory inspection (`as_raw_bytes`) is strictly restricted to test builds (`#[cfg(any(test, feature = "test-utils"))]`) and omitted from production binaries.
8. **PBM Schema Version 2 Compliance**: Emits structured security events strictly compliant with `event-envelope.v2.schema.json`. Emits with `module = "mcp-shield"` and `"details.subsystem" = "secret-boundary"` to satisfy PBM's current schema enum `["mcp-shield", "vector-anchor", "trace-audit"]`.

---

## Verification & Test Results

The crate is validated in CI (`.github/workflows/ci.yml`, job `secret-boundary`):

* `cargo fmt --all -- --check`: **enforced**
* `cargo clippy --locked --all-targets -- -D warnings`: **enforced**
* `cargo build --locked`: **enforced**
* `cargo test --locked`: **79 tests pass** (38 unit tests in `src/`, 21 integration tests in `tests/boundary_tests.rs`, 20 integration tests in `tests/onepassword_provider_tests.rs`) — the 2026-10-21 run; the command prints the current number

### Runtime Limitations & Boundaries:
* **TLS Provider**: The production HTTPS transport is `ReqwestHttpsTransport` (in the `mcp-shield` crate), which uses `reqwest` with `rustls` and the platform certificate verifier. Certificate and hostname verification are enforced; an untrusted or mismatched certificate fails the operation closed. The trust store cannot be extended from the boundary configuration, so an endpoint served by a private CA is not reachable through the boundary. This crate also provides `StdTcpHttpTransport` (which fails closed safely for HTTPS, since it has no TLS engine) and `MockHttpTransport` (for deterministic offline testing).
* **Live 1Password CLI execution**: Disabled by default (`enabled = false`), isolated with purged environment variables, and requires explicit administrative enablement.
