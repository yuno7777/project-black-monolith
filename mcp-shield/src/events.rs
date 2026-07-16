//! Structured security-event emission.
//!
//! Every detection is emitted both as a human-readable tracing line *and* as
//! a single-line JSON object in the shared Project Black Monolith event shape:
//!
//! ```json
//! {
//!   "event_id": "6f1c0f6a-2a1e-4b7d-9c3f-2f6b8d4e1a90",
//!   "schema_version": 2,
//!   "timestamp_ms": 1770000000000,
//!   "module": "mcp-shield",
//!   "event_type": "schema_mismatch",
//!   "severity": "critical",
//!   "details": { ... },
//!   "source": "module"
//! }
//! ```
//!
//! VectorAnchor and TraceAudit emit this exact same shape, so the unified
//! dashboard can consume all three modules' feeds uniformly. The JSON lines
//! are logged under the `monolith_event` tracing target, which makes them
//! easy to filter (e.g. `RUST_LOG=monolith_event=info`).
//!
//! `event_id` is the ingest endpoint's idempotency key: redelivering an event
//! after an uncertain failure is a no-op rather than a duplicate row.
//!
//! Dashboard integration: when `MONOLITH_DASHBOARD_URL` and
//! `MONOLITH_EVENT_TOKEN` are set, each event is durably spooled by
//! [`crate::outbox`] and delivered asynchronously. Emission never blocks and
//! never fails the proxy path — a dashboard outage costs delivery latency,
//! not events.

use crate::outbox;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MODULE: &str = "mcp-shield";

/// An id longer than this is a caller error, not a correlation key.
const MAX_ID_LENGTH: usize = 128;

/// Current event-contract version. The dashboard accepts 1 and 2; 2 adds the
/// correlation/evidence fields and `event_id`.
const SCHEMA_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Serialize)]
pub struct ShieldEvent<'a> {
    pub event_id: String,
    pub schema_version: u8,
    pub timestamp_ms: u128,
    pub module: &'static str,
    pub event_type: &'a str,
    pub severity: Severity,
    pub details: Value,
    pub source: &'static str,
    // Correlation identity. Skipped entirely when unknown rather than sent as
    // null: the contract treats these as optional, and a null would claim we
    // looked and found nothing rather than that nobody told us.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

/// Who these detections belong to, read once from the environment.
///
/// Unlike the long-running Python services — which serve many agents and so
/// take this per-request from headers — this proxy is spawned per agent
/// session and exits when the agent closes stdin. One invocation *is* one
/// session, so the environment is the correct and simplest channel.
///
/// Both are `None` unless configured. An invented session id would be worse
/// than none: it would group unrelated agents together, and the grouping is
/// the entire point of having one.
#[derive(Debug, Clone, Default)]
struct Identity {
    agent_id: Option<String>,
    session_id: Option<String>,
}

fn clean_id(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(MAX_ID_LENGTH).collect())
}

fn identity() -> &'static Identity {
    static IDENTITY: OnceLock<Identity> = OnceLock::new();
    IDENTITY.get_or_init(|| Identity {
        agent_id: std::env::var("MONOLITH_AGENT_ID").ok().and_then(clean_id),
        session_id: std::env::var("MONOLITH_SESSION_ID").ok().and_then(clean_id),
    })
}

/// A fresh id for one logical operation (a single `tools/list` exchange).
///
/// Deliberately not the JSON-RPC request id: that is only unique within one
/// connection and is usually a small integer, so `2` would collide across every
/// session in the ledger.
pub fn new_trace_id() -> String {
    new_event_id()
}

/// Milliseconds since the Unix epoch (0 if the system clock is broken —
/// never panic in the event path).
pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Generate a syntactically valid RFC 4122 version-4 UUID.
///
/// The event ledger types `event_id` as a Postgres `uuid`, so any other
/// string shape would be rejected at insert time. MCP-Shield has no `uuid`
/// or `rand` dependency, so the 122 free bits are filled from a SHA-256 of
/// values that cannot repeat within or across runs: the process id, a
/// nanosecond timestamp, a monotonic counter, and an ASLR-provided stack
/// address (which distinguishes two processes started in the same nanosecond
/// after a pid is reused).
///
/// This is a uniqueness primitive, not a secrecy one — event ids are not
/// secrets and nothing authenticates on them.
fn new_event_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stack_marker = &counter as *const u64 as usize;

    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(counter.to_le_bytes());
    hasher.update(stack_marker.to_le_bytes());
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant

    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Emit one structured security event, unattached to any single operation.
///
/// Serialization failures are logged rather than propagated: event emission
/// must never break the proxy path.
pub fn emit(event_type: &str, severity: Severity, details: Value) {
    emit_traced(event_type, severity, details, None);
}

/// Emit an event belonging to one operation.
///
/// Detections from the same `tools/list` exchange share a `trace_id` — a schema
/// mismatch and the suspicious description that came with it are one finding
/// seen twice, not two unrelated ones.
pub fn emit_traced(event_type: &str, severity: Severity, details: Value, trace_id: Option<&str>) {
    let id = identity();
    let event = ShieldEvent {
        event_id: new_event_id(),
        schema_version: SCHEMA_VERSION,
        timestamp_ms: now_ms(),
        module: MODULE,
        event_type,
        severity,
        details,
        source: "module",
        agent_id: id.agent_id.clone(),
        session_id: id.session_id.clone(),
        trace_id: trace_id.map(str::to_owned),
    };
    let json = match serde_json::to_string(&event) {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, event_type, "failed to serialize security event");
            return;
        }
    };
    match severity {
        Severity::Info => tracing::info!(target: "monolith_event", event = %json),
        Severity::Warning => tracing::warn!(target: "monolith_event", event = %json),
        Severity::Critical => tracing::error!(target: "monolith_event", event = %json),
    }
    if let Some(outbox) = outbox::outbox() {
        // stderr already carries the event; a spool failure degrades delivery
        // but must not take down the proxy.
        if let Err(e) = outbox.enqueue(&event.event_id, &json) {
            tracing::error!(error = %e, event_id = %event.event_id, "cannot spool security event for the dashboard");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_uuid_v4(id: &str) -> bool {
        let groups: Vec<&str> = id.split('-').collect();
        if groups.len() != 5 {
            return false;
        }
        if [8, 4, 4, 4, 12] != groups.iter().map(|g| g.len()).collect::<Vec<_>>()[..] {
            return false;
        }
        if !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            return false;
        }
        // Version nibble and variant bits per RFC 4122.
        groups[2].starts_with('4') && matches!(groups[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b')
    }

    #[test]
    fn event_ids_are_valid_v4_uuids() {
        // The ledger's event_id column is a Postgres `uuid`; anything else is
        // rejected at insert time and would retry forever as a poison pill.
        for _ in 0..256 {
            let id = new_event_id();
            assert!(is_uuid_v4(&id), "{id} is not a valid v4 UUID");
        }
    }

    #[test]
    fn event_ids_are_unique() {
        let ids: std::collections::HashSet<String> = (0..10_000).map(|_| new_event_id()).collect();
        assert_eq!(ids.len(), 10_000, "event ids must not collide");
    }

    fn sample_event(
        agent_id: Option<String>,
        session_id: Option<String>,
        trace_id: Option<String>,
    ) -> ShieldEvent<'static> {
        ShieldEvent {
            event_id: new_event_id(),
            schema_version: SCHEMA_VERSION,
            timestamp_ms: 1_770_000_000_000,
            module: MODULE,
            event_type: "schema_mismatch",
            severity: Severity::Critical,
            details: serde_json::json!({ "tool": "read_file" }),
            source: "module",
            agent_id,
            session_id,
            trace_id,
        }
    }

    fn serialized(event: &ShieldEvent) -> Value {
        serde_json::from_str(&serde_json::to_string(event).unwrap()).unwrap()
    }

    #[test]
    fn the_serialized_envelope_matches_the_shared_contract() {
        let value = serialized(&sample_event(None, None, None));
        assert_eq!(value["module"], "mcp-shield");
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["severity"], "critical");
        assert_eq!(value["timestamp_ms"], 1_770_000_000_000_u64);
        assert_eq!(value["source"], "module");
        assert_eq!(value["details"]["tool"], "read_file");
    }

    #[test]
    fn unknown_correlation_fields_are_omitted_not_nulled() {
        // A null would assert "this event belongs to no session"; absence says
        // "nobody told us". The dashboard treats these as optional, and the
        // difference matters when the queue groups by session.
        let value = serialized(&sample_event(None, None, None));
        let object = value.as_object().unwrap();
        assert!(!object.contains_key("agent_id"));
        assert!(!object.contains_key("session_id"));
        assert!(!object.contains_key("trace_id"));
    }

    #[test]
    fn known_correlation_fields_are_serialized() {
        let value = serialized(&sample_event(
            Some("demo-agent".into()),
            Some("session-abc".into()),
            Some("trace-xyz".into()),
        ));
        assert_eq!(value["agent_id"], "demo-agent");
        assert_eq!(value["session_id"], "session-abc");
        assert_eq!(value["trace_id"], "trace-xyz");
    }

    #[test]
    fn ids_are_trimmed_clamped_and_blanks_dropped() {
        assert_eq!(clean_id("  session-1  ".into()), Some("session-1".into()));
        assert_eq!(clean_id("   ".into()), None);
        assert_eq!(clean_id("".into()), None);
        let long = clean_id("x".repeat(500)).unwrap();
        assert_eq!(long.len(), MAX_ID_LENGTH, "an over-long id must be clamped, not dropped");
    }

    #[test]
    fn trace_ids_are_unique_per_operation() {
        // Two tools/list exchanges must not look like one operation.
        assert_ne!(new_trace_id(), new_trace_id());
    }
}
