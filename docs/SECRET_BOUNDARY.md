# Project Black Monolith — Secret Boundary Integration

## Overview

The **PBM Secret Boundary** is an integrated security layer within Project Black Monolith (PBM). It isolates sensitive API credentials (tokens, keys, certificates) from AI models and upstream agent workflows while enabling authenticated operations against external services.

The standalone crate lives at [`crates/pbm-secret-boundary`](../crates/pbm-secret-boundary) and is wired directly into the [`mcp-shield`](../mcp-shield) proxy layer.

```
       ┌───────────────────────────────┐
       │ AI Agent / Runtime / Client   │
       └──────────────┬────────────────┘
                      │ stdio JSON-RPC 2.0
                      ▼
       ┌───────────────────────────────┐
       │          MCP-Shield           │
       │                               │
       │   Ordinary Tool Calls         │
       │   ├── tools/list Analysis     │
       │   └── Prompt Sanitizer        │
       │                               │
       │   Secret-Bound Tool Calls     │
       │   └── ShieldSecretBoundary ───┼─────────────┐
       └──────────────┬────────────────┘             │ Intercepted locally;
                      │                              │ never reaches backend
       ┌──────────────┴────────────────┐             ▼
       │      Backend MCP Server       │ ┌───────────────────────────────┐
       │ (e.g. filesystem, calculator) │ │  Secret Boundary Broker       │
       └───────────────────────────────┘ │  ├── Policy Engine            │
                                         │  ├── Secret Provider          │
                                         │  │   (Mock / 1Password CLI)   │
                                         │  ├── HTTPS Transport Adapter  │
                                         │  │   (reqwest + rustls)       │
                                         │  │   (SSRF / Pinning Defense) │
                                         │  └── PBM Schema v2 Audit Log  │
                                         └──────────────┬────────────────┘
                                                        │ HTTPS (TLS SNI + Pinning)
                                                        ▼
                                         ┌───────────────────────────────┐
                                         │  External Service / API       │
                                         └───────────────────────────────┘
```

---

## Core Security Invariants

1. **Zero Secret Leakage to Models or Upstream Callers**: Raw secret values never cross the boundary into agent responses, error messages, or logs.
2. **Fail-Closed Default**: In the absence of explicit configuration, the Secret Boundary remains completely inert. If configuration is provided but unreadable, invalid, or contradictory, `mcp-shield` aborts at startup — *except* on the `--list-pending` / `--approve` operator paths, which deliberately do not build the boundary so that a broken configuration cannot lock an operator out of the commands used to repair it.
3. **Decoupled Parameter Mapping**: Agents can only supply allowlisted parameters defined in `permitted_params`. Callers cannot specify or override destination hosts, credential references, or authorization headers.
4. **Mandatory Secure HTTPS Transport**: Cleartext HTTP (`http://`) is strictly rejected. Outbound requests enforce TLS certificate verification and hostname checking via `reqwest` + `rustls`.
5. **Connection Pinning & SSRF Defense**: Destination hostnames are resolved through validated DNS resolvers. The underlying TCP socket connects exclusively to pre-validated IP addresses using `.resolve_to_addrs()` while preserving the original hostname for TLS SNI and Host header semantics, mitigating DNS rebinding and SSRF.
6. **No Automated Redirects**: Credential-bearing operations reject HTTP redirects (`3xx`) to prevent credential leakage across origins.
7. **PBM Schema Version 2 Compliance**: All security events emitted by the boundary adhere strictly to PBM's Schema Version 2 envelope format, with valid RFC 4122 UUIDv4 event identifiers and millisecond epoch timestamps.
8. **Shadowing Precedence**: If a backend MCP server advertises a tool with the same name as a configured secret-bound tool, the backend tool is shadowed and dropped from the agent-facing catalogue. Calls to that tool are executed locally and never forwarded to the backend child process. This holds in **both** `enforce` and `monitor` mode: monitor mode's promise is about detection, not about leaving a catalogue in which the backend could impersonate a secret-bound tool.
9. **Explicit Agent Identity**: The boundary serves exactly one agent identity, declared in the configuration. Every policy rule must name that same identity, and a rule naming anyone else is rejected at load time — an implicit default would make the `agent_id` field of every rule decorative.
10. **Response Sanitization**: The boundary's own responses never travel the server-to-agent path, so they never reach the description sanitizer. The upstream body is therefore scanned before it reaches the model, and a body that trips the sanitizer is replaced wholesale.

---

## Configuration & Activation

The boundary is activated by setting the `MCP_SHIELD_SECRET_BOUNDARY_CONFIG` environment variable to either a JSON file path or a raw JSON string:

```bash
export MCP_SHIELD_SECRET_BOUNDARY_CONFIG="/etc/pbm/secret_boundary.json"
```

### Configuration Format

The configuration is **JSON only**. Unknown keys are rejected: a mistyped `permitted_params` would otherwise be silently dropped, narrowing the allowlist without anyone noticing.

```json
{
  "enabled": true,
  "agent_id": "demo-agent",
  "active_provider": "mock",
  "synthetic_secrets": {
    "mock://weather/api-key": "synthetic-dev-token-xyz123"
  },
  "onepassword_cli": null,
  "tools": [
    {
      "tool_name": "fetch_weather",
      "operation_id": "op_fetch_weather",
      "description": "Fetch current weather observations securely",
      "input_schema": {
        "type": "object",
        "properties": {
          "city": { "type": "string" },
          "units": { "type": "string" }
        },
        "required": ["city"]
      },
      "url_template": "https://api.weather.example.com/v1/forecast",
      "method": "GET",
      "permitted_params": ["city", "units"],
      "policy_rule": {
        "agent_id": "demo-agent",
        "operation_id": "op_fetch_weather",
        "approved_credential_ref": "mock://weather/api-key",
        "destination_host": "api.weather.example.com",
        "destination_port": 443,
        "allowed_methods": ["GET"],
        "allowed_path_prefix": "/v1/forecast",
        "permitted_query_params": ["city", "units"],
        "valid_until": null,
        "require_https": true
      }
    }
  ]
}
```

### Field notes

| Field | Meaning |
|---|---|
| `enabled` | Must be `true`. A configuration marked disabled is rejected rather than silently ignored. |
| `agent_id` | **Required.** The identity this boundary instance serves. Must be non-empty, at most 128 printable characters. Every `policy_rule.agent_id` must match it. |
| `active_provider` | `"mock"` (synthetic secrets from `synthetic_secrets`) or `"1password-cli"`. |
| `synthetic_secrets` | Map of secret reference → synthetic value, for the mock provider only. |
| `onepassword_cli` | `null` or an object. Required (and must have `enabled: true`) when `active_provider` is `"1password-cli"`. See below. |
| `tools[].permitted_params` | The parameters the agent may supply. For `GET`/`HEAD` these are appended to the query string, so each one must also appear in `policy_rule.permitted_query_params` — otherwise the tool is advertised as usable and then denied on every call. |
| `tools[].url_template` | Must be `https`, must not embed userinfo, and its host and path must match the policy rule. The path check is segment-aware: a template of `/v1/forecast-admin` does **not** satisfy a prefix of `/v1/forecast`. |

### Enabling the 1Password CLI provider

```json
{
  "enabled": true,
  "agent_id": "demo-agent",
  "active_provider": "1password-cli",
  "onepassword_cli": {
    "enabled": true,
    "cli_path": "/usr/local/bin/op",
    "timeout_seconds": 5,
    "max_output_bytes": 65536,
    "account": "my-team",
    "require_absolute_path": true,
    "auth_mode": { "mode": "service_account", "env_var": "OP_SERVICE_ACCOUNT_TOKEN" }
  },
  "tools": [ "..." ]
}
```

`auth_mode` accepts `{"mode":"system_auth"}` (desktop app / keychain), `{"mode":"service_account","env_var":"..."}`, or `{"mode":"session_token","account":"..."}`.

`require_absolute_path: true` is recommended in production: it prevents PATH hijacking, where a malicious `op` binary placed in a searched directory would be executed instead of the real one. The provider also rejects script extensions (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.com`, `.scr`, `.pif`), clears the child environment down to an allowlist, and bounds the subprocess output and runtime.

---

## Component Layout

| Path | Responsibility |
|---|---|
| [`crates/pbm-secret-boundary/`](../crates/pbm-secret-boundary) | Core Secret Boundary library (broker, policy engine, secret types, memory zeroization, providers). |
| [`mcp-shield/src/secret_boundary/transport.rs`](../mcp-shield/src/secret_boundary/transport.rs) | `ReqwestHttpsTransport` leveraging locked `reqwest` + `rustls` stack for connection-pinned HTTPS. |
| [`mcp-shield/src/secret_boundary/mapping.rs`](../mcp-shield/src/secret_boundary/mapping.rs) | `SecretToolRegistry` and `SecretBoundToolDefinition` declarative parameter validation and schema translation. |
| [`mcp-shield/src/secret_boundary/events.rs`](../mcp-shield/src/secret_boundary/events.rs) | `PbmAuditBridge` adapting `AuditLogger` to PBM Schema Version 2 outbox spooling (`outbox.jsonl`). |
| [`mcp-shield/src/secret_boundary/mod.rs`](../mcp-shield/src/secret_boundary/mod.rs) | `ShieldSecretBoundary` controller wiring broker, registry, provider, and tool execution dispatcher. |
| [`mcp-shield/src/proxy.rs`](../mcp-shield/src/proxy.rs) | Interception choke point: tool call interception, `tools/list` shadowing, shared stdout synchronization. |
| [`mcp-shield/src/secret_boundary/tests.rs`](../mcp-shield/src/secret_boundary/tests.rs) | Offline integration tests covering the security and behavioural scenarios. |

---

## Event Types

The boundary emits four new event types through the standard mcp-shield event pipeline. They carry the normal Schema v2 envelope, so the dashboard ingests them with no special handling.

| `event_type` | Severity | Meaning |
|---|---|---|
| `secret_operation_executed` | `info` | The operation ran and the response was returned (sanitized). |
| `secret_operation_failed` | `warning` | The operation was authorized but the execution failed. |
| `secret_operation_aborted` | `warning` | The operation was authorized but not executed. |
| `secret_boundary_denial` | `critical` | The policy refused the request. |

`details` always carries `subsystem: "secret-boundary"`, the `operation_id`, the `destination_host`, the `credential_ref` (the reference path, never the secret), the `decision`, the `outcome`, the `denial_reason` when there is one, and `authorized_agent_id` — the identity the *policy* authorized.

`authorized_agent_id` is separate from the envelope's top-level `agent_id` on purpose. The top-level field is the module-wide identity from `MONOLITH_AGENT_ID`; the boundary serves exactly one identity declared in its own configuration, and the two can disagree (an operator may attribute the session to a fleet while the policy binds a narrower identity). Recording the authorized identity explicitly means the ledger can always answer "who was allowed to use this credential?", and a mismatch between the two is logged as a startup warning rather than left to be discovered in an investigation.

---

## Operational Verification

Run all test suites offline:

```bash
# 1. MCP-Shield test suite (88 tests: 64 existing + 24 secret boundary integration)
cd mcp-shield
cargo test --locked

# 2. Secret Boundary standalone crate test suite (73 tests)
cd ../crates/pbm-secret-boundary
cargo test --locked

# 3. Python common tests (18 tests)
cd ..
python -c "import sys; sys.path.insert(0, 'python-common'); import pytest; sys.exit(pytest.main(['python-common/tests']))"
```

### End-to-end demo

```bash
# From mcp-shield/ — no network, no real credential
bash fixtures/run_secret_boundary_demo.sh
```

The demo proves the properties that are observable outside the process: the backend's impostor tool is shadowed, the secret-bound call is intercepted locally and never reaches the backend, the approved-but-blocked destination produces a clean error, the audit event is emitted, and the synthetic credential appears in neither the agent-facing output nor the log.

The outbound HTTPS **success** path is deliberately not part of the shell demo: the SSRF guard blocks loopback and private destinations by design, so a local server cannot legitimately be the approved destination. That path is covered by the Rust integration suite, which runs a real local TLS server with a trusted certificate.

---

## Production Deployment Caveats & Residual Risks

1. **Provider Verification**: In production deployments, ensure `active_provider` is configured with a verified provider configuration (e.g. 1Password CLI) and that `synthetic_secrets` are omitted. The 1Password CLI provider is disabled by default and requires explicit account and reference allowlisting.
2. **Certificate Authorities**: `rustls` uses the platform verifier (the operating system's trust store). Ensure production hosts have up-to-date CA trust stores. Private-CA endpoints are not currently supported by the boundary's transport — the trust store cannot be extended from the boundary configuration.
3. **DNS Infrastructure**: The transport relies on the system DNS resolver to evaluate IP addresses before pinning. Protect the local DNS resolution path against upstream cache poisoning.
4. **Approved Services**: If an approved operation can carry arbitrary text to an approved external service, an agent could use that operation to exfiltrate other data. Policy rules must constrain permitted methods and parameters.
5. **Ordering**: The boundary answers an intercepted `tools/call` as soon as it arrives, so its response can precede a still-in-flight `tools/list` response. JSON-RPC 2.0 correlates responses by id, so this is legal; a client that requires strictly ordered responses would need to wait for the `tools/list` response before calling a tool.
