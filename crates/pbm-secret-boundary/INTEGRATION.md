# PBM Secret Boundary: Integration Guide

This guide describes how `pbm-secret-boundary` is integrated with Project Black Monolith (PBM) and specifically with its Rust tool-interception component, `mcp-shield`.

---

## 1. PBM Architecture Mapping

* **Tool Layer Defense (`mcp-shield/src/proxy.rs`)**: A transparent JSON-RPC 2.0 stdio proxy that intercepts `tools/list` and `tools/call`.
* **Shared Event Model (`mcp-shield/src/events.rs`)**: Schema Version 2 events (`ShieldEvent`) with an idempotency key (`event_id` as a UUID v4), `timestamp_ms`, `module`, `event_type`, `severity`, and `details`.
* **Outbox Spooling (`mcp-shield/src/outbox.rs`)**: Asynchronously flushes events to `MONOLITH_DASHBOARD_URL` with the token `MONOLITH_EVENT_TOKEN`.

`pbm-secret-boundary` integrates with all three. The crate itself is deliberately decoupled: it knows nothing about MCP, about the dashboard, or about the event envelope's transport. It is a library, and `mcp-shield` is its first consumer.

---

## 2. Integration Patterns

### Pattern A: The MCP-Shield interceptor (the production path)

This is the pattern that actually ships. The controller lives in `mcp-shield/src/secret_boundary/mod.rs`:

```rust
use pbm_secret_boundary::broker::SecretBoundaryBroker;
use pbm_secret_boundary::operation::OperationRequest;
use pbm_secret_boundary::policy::PolicyEngine;
use pbm_secret_boundary::provider::SecretProvider;
use std::collections::HashMap;

pub struct ShieldSecretBoundary {
    broker: Arc<SecretBoundaryBroker>,
    registry: Arc<SecretToolRegistry>,
    /// The identity this boundary serves. Every policy rule must name it.
    agent_id: String,
}

impl ShieldSecretBoundary {
    /// Build a request from an inbound MCP `tools/call`.
    ///
    /// Note what the caller does NOT get to supply: the destination URL, the
    /// HTTP method, the credential reference, and the headers. Those come
    /// from the tool's declarative definition and the policy rule, never from
    /// the agent's arguments. The agent supplies only the parameters listed in
    /// `permitted_params`.
    pub fn build_operation_request(
        &self,
        tool_name: &str,
        agent_id: &str,
        arguments: &serde_json::Value,
    ) -> Result<OperationRequest, BoundaryError> {
        self.registry.build_operation_request(tool_name, agent_id, arguments)
    }
}
```

The `SecretToolRegistry` is what enforces the decoupling. It validates that the tool's declared URL template, host, path prefix, and method agree with its policy rule, rejects any parameter outside the allowlist, rejects control characters in keys and values, and encodes the survivors into the query string (for `GET`/`HEAD`) or the request body.

The broker then applies the fail-closed policy, resolves the credential through the configured provider, injects it internally, and returns a sanitized response.

### Pattern B: JSON Wire Protocol Adapter (STDIO / Subprocess)

For decoupled execution or external script bridges, the crate ships a standalone wire adapter:

```rust
use pbm_secret_boundary::adapter::handle_json_request;
use pbm_secret_boundary::SecretBoundaryBroker;

// Pass strictly validated JSON into the boundary:
let json_input = r#"{
    "agent_id": "agent-researcher",
    "operation_id": "fetch_forecast",
    "destination_url": "https://api.weather.example.com/v1/forecast?city=Seattle",
    "method": "GET"
}"#;

let sanitized_json_output = handle_json_request(&broker, json_input);
println!("{}", sanitized_json_output);
```

This adapter is a **library entry point for callers you control**, not a path for agent-supplied input. The wire request carries a `destination_url`, so the caller is responsible for only ever passing a URL that its own policy authorizes — the broker still checks it against the policy rules, which is what makes the pattern safe to use at all.

### Pattern C: Emitting PBM Schema Version 2 Events

`mcp-shield` implements `AuditLogger` to route boundary audit records into PBM's event pipeline. The implementation is in `mcp-shield/src/secret_boundary/events.rs`:

```rust
use crate::events::{self, Severity};
use pbm_secret_boundary::event::{AuditLogger, ExecutionOutcome, PolicyDecision, SecurityEvent};
use serde_json::json;

pub struct PbmAuditBridge;

impl AuditLogger for PbmAuditBridge {
    fn log_event(&self, event: &SecurityEvent) {
        let (event_type, severity, outcome) = match event.decision {
            PolicyDecision::Allowed => match event.outcome {
                ExecutionOutcome::Success => ("secret_operation_executed", Severity::Info, "allowed"),
                ExecutionOutcome::Failure => ("secret_operation_failed", Severity::Warning, "failure"),
                ExecutionOutcome::NotExecuted => {
                    ("secret_operation_aborted", Severity::Warning, "aborted")
                }
            },
            PolicyDecision::Denied => ("secret_boundary_denial", Severity::Critical, "denied"),
        };

        let details = json!({
            "subsystem": "secret-boundary",
            "operation_id": event.operation_id,
            "destination_host": event.destination_host,
            "credential_ref": event.credential_ref,
            "decision": format!("{:?}", event.decision),
            "outcome": format!("{:?}", event.outcome),
            "denial_reason": event.denial_reason,
            "duration_ms": event.duration_ms,
            "action": outcome,
        });

        // Delegates to PBM's central emitter, which owns the UUIDv4 event id,
        // the tenant/agent identity, the tracing target, and the durable
        // outbox spool.
        events::emit_traced(event_type, severity, details, Some(&event.correlation_id));
    }
}
```

Routing through `events::emit_traced` rather than serializing the event directly is deliberate: the central emitter is what guarantees a valid UUIDv4 `event_id` (the ledger column is a Postgres `uuid`, and anything else fails the insert with `22P02` and is retried forever as a poison pill), the trusted tenant and agent identity, and the durable spool. The crate's own `SecurityEvent::to_pbm_shield_event` is available for callers that are not the mcp-shield module, and it fixes `module` to `"mcp-shield"` because the shared contract enumerates that field.

---

## 3. Transitioning from Mock to 1Password CLI Provider

The default setup uses `MockSecretProvider` with synthetic credentials. To transition to the official 1Password CLI provider in production:

1. Verify the official `op` binary is installed and authenticated on the host:
   ```bash
   op --version
   op whoami
   ```

2. Configure the provider. In the mcp-shield integration this is the `onepassword_cli` object of the boundary configuration:

   ```json
   {
     "onepassword_cli": {
       "enabled": true,
       "cli_path": "/usr/local/bin/op",
       "timeout_seconds": 5,
       "max_output_bytes": 65536,
       "account": "my-team",
       "require_absolute_path": true,
       "auth_mode": { "mode": "service_account", "env_var": "OP_SERVICE_ACCOUNT_TOKEN" }
     }
   }
   ```

   From Rust, the equivalent is:

   ```rust
   use pbm_secret_boundary::provider::{OnePasswordAuthMode, OnePasswordCliConfig, OnePasswordCliProvider};

   let op_config = OnePasswordCliConfig {
       enabled: true,
       cli_path: "/usr/local/bin/op".to_string(),
       timeout_seconds: 5,
       max_output_bytes: 64 * 1024,
       account: Some("my-team".to_string()),
       auth_mode: OnePasswordAuthMode::ServiceAccount {
           env_var: "OP_SERVICE_ACCOUNT_TOKEN".to_string(),
       },
       require_absolute_path: true,
   };
   let provider = Arc::new(OnePasswordCliProvider::new(op_config)?);
   ```

   Set `require_absolute_path: true` in production. It prevents PATH hijacking, where a malicious `op` binary placed in a searched directory would be executed instead of the real one.

3. Update the policy rules to reference the production vault paths:

   ```json
   "approved_credential_ref": "op://production-vault/weather-service/api-key"
   ```

   The reference grammar is validated strictly: `op://<vault>/<item>[/<section>]/<field>`, with no traversal sequences, no leading hyphen (which would be read as a flag), and an allowlisted character set. A malformed reference is rejected before the CLI is ever invoked.

---

## 4. What the boundary deliberately does not do

* It does not extend the TLS trust store. The production transport uses the platform verifier, so an endpoint served by a private CA is not reachable through the boundary.
* It does not expose a way to make a destination reachable that the SSRF guard would otherwise block. There is no configuration switch for that.
* It does not let the agent choose the credential, the destination, the method, or the headers. Those are bound by policy and by the tool's declarative definition.
