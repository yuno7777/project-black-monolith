//! PBM Schema Version 2 Event Adapter for Secret Boundary Audit Events.
//!
//! Bridges `pbm_secret_boundary::event::AuditLogger` to `mcp-shield::events::emit_traced`
//! and durable outbox delivery. Guarantees:
//! 1. `event_id` uses RFC 4122 UUIDv4 format required by Postgres and dashboard.
//! 2. `timestamp_ms` uses Unix epoch milliseconds.
//! 3. `module` is set to `"mcp-shield"` and `"details.subsystem"` is set to `"secret-boundary"`.
//! 4. Trusted tenant and agent correlation identity are attached.
//! 5. Raw credentials never appear in event payloads.

use crate::events::{self, Severity};
use pbm_secret_boundary::event::{AuditLogger, ExecutionOutcome, PolicyDecision, SecurityEvent};
use serde_json::json;

/// Adapter implementing `AuditLogger` by delegating to PBM's central event pipeline.
#[derive(Debug, Clone, Default)]
pub struct PbmAuditBridge;

impl PbmAuditBridge {
    pub fn new() -> Self {
        Self
    }
}

impl AuditLogger for PbmAuditBridge {
    fn log_event(&self, event: &SecurityEvent) {
        let (event_type, severity, outcome) = match event.decision {
            PolicyDecision::Allowed => match event.outcome {
                ExecutionOutcome::Success => {
                    ("secret_operation_executed", Severity::Info, "allowed")
                }
                ExecutionOutcome::Failure => {
                    ("secret_operation_failed", Severity::Warning, "failure")
                }
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
            // The identity the POLICY authorized. The envelope's top-level
            // `agent_id` is the module-wide identity from the environment
            // (MONOLITH_AGENT_ID), which is not necessarily the same thing:
            // the boundary serves exactly one identity, declared in its own
            // configuration, and the two can disagree. Recording the
            // authorized identity here means the audit trail always says who
            // was actually allowed to use the credential, even if the
            // module-level attribution is misconfigured.
            "authorized_agent_id": event.agent_id,
        });

        // Dispatches through PBM's central emit_traced:
        // - Enforces UUIDv4 event_id
        // - Attaches trusted tenant_id, agent_id, and session_id from process environment
        // - Logs under the 'monolith_event' tracing target
        // - Durably spools to outbox.jsonl for dashboard delivery
        events::emit_traced(event_type, severity, details, Some(&event.correlation_id));
    }
}
