use crate::secret::SecretString;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a valid RFC 4122 version 4 UUID formatted string.
pub fn generate_uuid_v4() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();

    // Generate pseudo-random bytes from timestamp, counter, and process ID
    let mut b = [0u8; 16];
    let now_bytes = now.to_le_bytes();
    let count_bytes = count.to_le_bytes();
    let pid_bytes = pid.to_le_bytes();

    for i in 0..16 {
        b[i] = now_bytes[i % now_bytes.len()]
            ^ count_bytes[i % count_bytes.len()]
            ^ pid_bytes[i % pid_bytes.len()]
            ^ ((i as u8).wrapping_mul(31));
    }

    // Set RFC 4122 version 4 (bits 4-7 of byte 6 = 0100)
    b[6] = (b[6] & 0x0f) | 0x40;
    // Set RFC 4122 variant (bits 6-7 of byte 8 = 10)
    b[8] = (b[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Authorization decision emitted by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Allowed,
    Denied,
}

/// Outcome of executing the authorized operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionOutcome {
    Success,
    Failure,
    NotExecuted,
}

/// A structured security audit event emitted for every boundary interaction.
///
/// **Crucial Invariant:** This event NEVER contains raw credential values.
/// Only canonical reference paths (e.g., `op://dev-vault/service/key`) are recorded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEvent {
    /// Unique RFC 4122 v4 event identifier.
    pub event_id: String,

    /// UTC timestamp of event generation.
    pub timestamp: DateTime<Utc>,

    /// Correlation identifier spanning the agent interaction.
    pub correlation_id: String,

    /// Requesting agent or tool identity.
    pub agent_id: String,

    /// Operation identifier.
    pub operation_id: String,

    /// Authorization decision (ALLOWED or DENIED).
    pub decision: PolicyDecision,

    /// Explanation if denied.
    pub denial_reason: Option<String>,

    /// Credential reference identifier (NEVER the raw secret).
    pub credential_ref: Option<String>,

    /// Approved or requested destination host.
    pub destination_host: String,

    /// Execution outcome.
    pub outcome: ExecutionOutcome,

    /// Execution duration in milliseconds, if executed.
    pub duration_ms: Option<u64>,
}

/// Project Black Monolith (PBM) Schema Version 2 event shape.
/// Strictly conforms to `event-envelope.v2.schema.json` in Project Black Monolith contracts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PbmShieldEvent {
    pub event_id: String,
    pub schema_version: u8,
    pub timestamp_ms: u64,
    pub module: &'static str,
    pub event_type: String,
    pub severity: String,
    pub details: serde_json::Value,
    pub source: &'static str,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<&'static str>,
}

impl SecurityEvent {
    /// Converts this event into PBM's canonical Schema Version 2 format.
    ///
    /// The module is fixed to `"mcp-shield"`, which is the only module this
    /// crate is integrated into. It is deliberately not a parameter: the
    /// shared event contract (`contracts/schemas/event-envelope.v2.schema.json`)
    /// enumerates `module` as `mcp-shield | vector-anchor | trace-audit`, and
    /// the dashboard rejects anything else with a permanent 422. A caller
    /// supplied module name would be a way to build an event that can never
    /// be ingested.
    pub fn to_pbm_shield_event(&self, tenant_id: &str) -> PbmShieldEvent {
        let (event_type, severity, outcome) = match self.decision {
            PolicyDecision::Allowed => match self.outcome {
                ExecutionOutcome::Success => ("secret_operation_executed", "info", "allowed"),
                ExecutionOutcome::Failure => ("secret_operation_failed", "warning", "failure"),
                ExecutionOutcome::NotExecuted => ("secret_operation_aborted", "warning", "aborted"),
            },
            PolicyDecision::Denied => ("secret_boundary_denial", "critical", "denied"),
        };

        PbmShieldEvent {
            event_id: self.event_id.clone(),
            schema_version: 2,
            timestamp_ms: self.timestamp.timestamp_millis().max(1) as u64,
            module: "mcp-shield",
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            details: json!({
                "subsystem": "secret-boundary",
                "operation_id": self.operation_id,
                "destination_host": self.destination_host,
                "credential_ref": self.credential_ref,
                "denial_reason": self.denial_reason,
                "duration_ms": self.duration_ms,
            }),
            source: "module",
            tenant_id: tenant_id.to_string(),
            agent_id: Some(self.agent_id.clone()),
            session_id: None,
            trace_id: Some(self.correlation_id.clone()),
            correlation_id: Some(self.correlation_id.clone()),
            resource_type: Some("operation".to_string()),
            resource_id: Some(self.operation_id.clone()),
            outcome: Some(outcome.to_string()),
            policy_version: Some("secret-boundary/1"),
        }
    }
}

/// Trait for security audit loggers.
pub trait AuditLogger: Send + Sync {
    /// Emits a structured security event.
    fn log_event(&self, event: &SecurityEvent);
}

/// Thread-safe in-memory audit logger for development, testing, and memory buffers.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAuditLogger {
    events: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl InMemoryAuditLogger {
    /// Creates a new in-memory audit logger.
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a copy of all recorded security events.
    pub fn get_events(&self) -> Vec<SecurityEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Returns the most recently logged security event.
    pub fn last_event(&self) -> Option<SecurityEvent> {
        self.events.lock().unwrap().last().cloned()
    }

    /// Clears recorded events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

impl AuditLogger for InMemoryAuditLogger {
    fn log_event(&self, event: &SecurityEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

/// Validates that none of the recorded events contain the raw secret in their serialized form.
pub fn verify_no_secrets_in_events(events: &[SecurityEvent], secret: &SecretString) -> bool {
    let raw = secret.expose_secret();
    if raw.trim().is_empty() {
        return true;
    }
    for event in events {
        if let Ok(serialized) = serde_json::to_string(event) {
            if serialized.contains(raw) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_v4_format() {
        let uuid = generate_uuid_v4();
        assert_eq!(uuid.len(), 36);
        assert_eq!(&uuid[14..15], "4");
        assert!(["8", "9", "a", "b"].contains(&&uuid[19..20]));
    }

    #[test]
    fn test_pbm_schema_v2_conversion() {
        let event = SecurityEvent {
            event_id: generate_uuid_v4(),
            timestamp: Utc::now(),
            correlation_id: "trace-xyz".to_string(),
            agent_id: "agent-01".to_string(),
            operation_id: "op_weather".to_string(),
            decision: PolicyDecision::Allowed,
            denial_reason: None,
            credential_ref: Some("op://vault/weather/key".to_string()),
            destination_host: "api.weather.example.com".to_string(),
            outcome: ExecutionOutcome::Success,
            duration_ms: Some(30),
        };

        let pbm_event = event.to_pbm_shield_event("prod-tenant");
        assert_eq!(pbm_event.schema_version, 2);
        assert_eq!(pbm_event.module, "mcp-shield");
        assert_eq!(pbm_event.event_type, "secret_operation_executed");
        assert_eq!(pbm_event.severity, "info");
        assert_eq!(pbm_event.tenant_id, "prod-tenant");
        assert_eq!(pbm_event.correlation_id, Some("trace-xyz".to_string()));
        assert_eq!(pbm_event.details["subsystem"], "secret-boundary");
    }

    /// The shared event contract enumerates `module`; the dashboard rejects
    /// anything outside it with a permanent 422, which dead-letters the event
    /// instead of ingesting it. The module is therefore not caller-selectable.
    #[test]
    fn test_module_is_always_a_contract_valid_value() {
        let event = SecurityEvent {
            event_id: generate_uuid_v4(),
            timestamp: Utc::now(),
            correlation_id: "trace-xyz".to_string(),
            agent_id: "agent-01".to_string(),
            operation_id: "op_weather".to_string(),
            decision: PolicyDecision::Allowed,
            denial_reason: None,
            credential_ref: None,
            destination_host: "api.weather.example.com".to_string(),
            outcome: ExecutionOutcome::Success,
            duration_ms: Some(30),
        };

        let serialized = serde_json::to_value(event.to_pbm_shield_event("prod-tenant")).unwrap();
        let module = serialized["module"].as_str().unwrap();
        assert!(
            ["mcp-shield", "vector-anchor", "trace-audit"].contains(&module),
            "module '{module}' is not in the shared event contract"
        );
    }
}
