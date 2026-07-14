//! Structured security-event emission.
//!
//! Every detection is emitted both as a human-readable tracing line *and* as
//! a single-line JSON object in the shared Project Black Monolith event shape:
//!
//! ```json
//! {
//!   "timestamp_ms": 1770000000000,
//!   "module": "mcp-shield",
//!   "event_type": "schema_mismatch",
//!   "severity": "critical",
//!   "details": { ... }
//! }
//! ```
//!
//! VectorAnchor and TraceAudit emit this exact same shape, so the unified
//! dashboard can consume all three modules' feeds uniformly. The JSON lines
//! are logged under the `monolith_event` tracing target, which makes them
//! easy to filter (e.g. `RUST_LOG=monolith_event=info`).
//!
//! Dashboard integration: if `MONOLITH_DASHBOARD_URL` is set (e.g.
//! `http://dashboard:3000/api/ingest`), each event is additionally POSTed to
//! that endpoint on a best-effort, fire-and-forget basis. Delivery failures
//! never affect the proxy path — the dashboard being down just means the
//! event isn't mirrored there.

use serde::Serialize;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

pub const MODULE: &str = "mcp-shield";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Serialize)]
pub struct ShieldEvent<'a> {
    pub timestamp_ms: u128,
    pub module: &'static str,
    pub event_type: &'a str,
    pub severity: Severity,
    pub details: Value,
}

/// Milliseconds since the Unix epoch (0 if the system clock is broken —
/// never panic in the event path).
pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Emit one structured security event. Serialization failures are logged
/// rather than propagated: event emission must never break the proxy path.
pub fn emit(event_type: &str, severity: Severity, details: Value) {
    let event = ShieldEvent {
        timestamp_ms: now_ms(),
        module: MODULE,
        event_type,
        severity,
        details,
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
    forward_to_dashboard(json);
}

/// Parsed `http://host:port/path` dashboard ingest target, resolved once.
struct DashboardTarget {
    host: String,
    port: u16,
    path: String,
}

fn dashboard_target() -> Option<&'static DashboardTarget> {
    static TARGET: OnceLock<Option<DashboardTarget>> = OnceLock::new();
    TARGET
        .get_or_init(|| {
            let url = std::env::var("MONOLITH_DASHBOARD_URL").ok()?;
            parse_http_url(&url).or_else(|| {
                tracing::warn!(url = %url, "MONOLITH_DASHBOARD_URL is not a parseable http:// URL; dashboard forwarding disabled");
                None
            })
        })
        .as_ref()
}

/// Minimal `http://host[:port]/path` parser (no external URL crate).
fn parse_http_url(url: &str) -> Option<DashboardTarget> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80u16),
    };
    if host.is_empty() {
        return None;
    }
    Some(DashboardTarget {
        host,
        port,
        path: path.to_string(),
    })
}

/// Best-effort, fire-and-forget POST of the event JSON to the dashboard.
/// Only runs when a tokio runtime is active (it always is on the proxy
/// path; unit tests that call `emit` outside a runtime simply skip this).
fn forward_to_dashboard(json: String) {
    let Some(target) = dashboard_target() else {
        return;
    };
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        if let Err(e) = post_event(target, &json).await {
            tracing::debug!(error = %e, "dashboard event forwarding failed (best-effort)");
        }
    });
}

async fn post_event(target: &DashboardTarget, body: &str) -> std::io::Result<()> {
    let mut stream =
        tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        target.path,
        target.host,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
