//! Durable, at-least-once dashboard delivery for MCP-Shield security events.
//!
//! # Why this is not a copy of the Python outbox
//!
//! VectorAnchor and TraceAudit are long-lived uvicorn servers, so their
//! outboxes can spool an event and retry it minutes later on a background
//! thread. MCP-Shield is the opposite: it is a **short-lived proxy** that
//! exits as soon as the agent closes stdin (often seconds after start). A
//! retry loop that outlives the process does not exist, so durability here is
//! achieved differently:
//!
//! 1. `enqueue` appends the event to an on-disk spool and fsyncs it *before*
//!    the emitting code proceeds. Delivery never blocks the proxy path.
//! 2. A background flusher drains due records while the proxy runs, so
//!    detections still reach the dashboard live.
//! 3. `drain(.., force = true)` runs once more before exit, ignoring backoff,
//!    to give this run's events a last chance to land.
//! 4. Anything still undelivered stays on the spool (a Docker volume) and is
//!    retried by the **next** invocation of the proxy.
//!
//! The honest limitation of (4): if the dashboard is down and the proxy is
//! never run again, those events are never delivered — they are preserved on
//! disk, not lost, but nothing redelivers them on its own. A short-lived
//! process cannot promise more than that without a separate resident agent.
//!
//! # Storage
//!
//! The spool is newline-delimited JSON (one `SpoolRecord` per line), chosen
//! over SQLite so this module keeps its dependency set to what is already in
//! `Cargo.toml`. Appends are atomic-per-line and fsynced; compaction is a
//! write-to-temp + `rename` over the original, which is atomic within a
//! directory. Permanently rejected events move to a sibling `.dead` file
//! rather than being silently dropped.

use crate::events::now_ms;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpStream;

/// Attempts after which an event is moved to the dead-letter file. Attempts
/// persist across runs, so a permanently broken target cannot grow the spool
/// without bound.
const MAX_ATTEMPTS: u32 = 10;
/// Upper bound on spooled records. Enforced at compaction; the oldest records
/// are dropped first (newest detections are the most actionable).
const MAX_SPOOL_RECORDS: usize = 10_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
/// How often the background flusher looks for due records.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

/// HTTP statuses the ingest endpoint returns for input it will never accept:
/// a bad credential (401/403), a malformed or oversized body (400/413), or an
/// event that fails schema validation (422). Retrying these is pointless, so
/// they are dead-lettered immediately instead of consuming attempts.
fn is_permanent(status: u16) -> bool {
    matches!(status, 400 | 401 | 403 | 413 | 422)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SpoolRecord {
    pub event_id: String,
    /// The serialized event envelope, exactly as it will be POSTed.
    pub payload: String,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub next_attempt_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl SpoolRecord {
    /// Exponential backoff with jitter, mirroring the Python outbox: ~2^n
    /// seconds capped at 5 minutes. Jitter is derived from the event id (no
    /// `rand` dependency) purely to avoid synchronized retry storms.
    fn defer(&mut self, error: String) {
        self.attempts += 1;
        let base_ms = 1_000u128 << self.attempts.min(8);
        let jitter_ms = u128::from(self.event_id.as_bytes().iter().map(|b| u32::from(*b)).sum::<u32>() % 1_000);
        self.next_attempt_ms = now_ms() + base_ms.min(300_000) + jitter_ms;
        self.last_error = Some(error);
    }
}

/// Parsed `http://host[:port]/path` dashboard ingest target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DashboardTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Minimal `http://host[:port]/path` parser (no external URL crate).
pub(crate) fn parse_http_url(url: &str) -> Option<DashboardTarget> {
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

pub(crate) struct Outbox {
    path: PathBuf,
    dead_path: PathBuf,
    target: DashboardTarget,
    token: String,
    /// Serializes every read-modify-write of the spool file. Held only across
    /// synchronous file I/O — never across an `.await`.
    file_lock: Mutex<()>,
}

impl Outbox {
    fn from_env() -> Option<Outbox> {
        let url = std::env::var("MONOLITH_DASHBOARD_URL").ok()?;
        let target = match parse_http_url(&url) {
            Some(t) => t,
            None => {
                tracing::warn!(url = %url, "MONOLITH_DASHBOARD_URL is not a parseable http:// URL; dashboard forwarding disabled");
                return None;
            }
        };
        // The ingest endpoint requires a per-module bearer token. Without one
        // every POST would 401 and be dead-lettered on arrival, so spooling
        // would only burn disk — fail loudly instead.
        let token = match std::env::var("MONOLITH_EVENT_TOKEN") {
            Ok(t) if !t.is_empty() => t,
            _ => {
                tracing::warn!(
                    "MONOLITH_DASHBOARD_URL is set but MONOLITH_EVENT_TOKEN is not; \
                     dashboard forwarding disabled (events still go to stderr)"
                );
                return None;
            }
        };
        let path = PathBuf::from(
            std::env::var("MONOLITH_EVENT_OUTBOX_PATH")
                .unwrap_or_else(|_| "/var/lib/monolith/outbox.jsonl".to_string()),
        );
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                tracing::warn!(error = %e, path = %parent.display(), "cannot create outbox directory; dashboard forwarding disabled");
                return None;
            }
        }
        Some(Outbox {
            dead_path: path.with_extension("dead"),
            path,
            target,
            token,
            file_lock: Mutex::new(()),
        })
    }

    /// Append one event to the spool and fsync it. This is the only operation
    /// on the proxy's hot path; it is synchronous and bounded.
    pub(crate) fn enqueue(&self, event_id: &str, payload: &str) -> std::io::Result<()> {
        let record = SpoolRecord {
            event_id: event_id.to_string(),
            payload: payload.to_string(),
            attempts: 0,
            next_attempt_ms: now_ms(),
            last_error: None,
        };
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        append_record(&self.path, &record)
    }

    async fn post(&self, body: &str) -> Result<u16, String> {
        let connect = TcpStream::connect((self.target.host.as_str(), self.target.port));
        let mut stream = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
            Err(_) => return Err("connect timeout".to_string()),
            Ok(Err(e)) => return Err(format!("connect: {e}")),
            Ok(Ok(s)) => s,
        };
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.target.path,
            self.target.host,
            self.token,
            body.len(),
            body
        );
        let exchange = async {
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            // Read only the status line; the body is irrelevant and the
            // connection closes on its own.
            let mut status_line = String::new();
            AsyncBufReader::new(&mut stream)
                .read_line(&mut status_line)
                .await?;
            Ok::<String, std::io::Error>(status_line)
        };
        match tokio::time::timeout(RESPONSE_TIMEOUT, exchange).await {
            Err(_) => Err("response timeout".to_string()),
            Ok(Err(e)) => Err(format!("io: {e}")),
            Ok(Ok(line)) => parse_status(&line).ok_or_else(|| "unparseable response".to_string()),
        }
    }

    /// Attempt delivery of spooled records within `budget`.
    ///
    /// `force` ignores per-record backoff — used for the final drain before
    /// exit, where a last attempt now beats a scheduled attempt that will
    /// never happen.
    pub(crate) async fn drain(&self, budget: Duration, force: bool) {
        let started = Instant::now();
        let pending = match self.load_pending() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "cannot read event outbox");
                return;
            }
        };
        if pending.is_empty() {
            return;
        }

        let now = now_ms();
        let mut delivered: HashSet<String> = HashSet::new();
        let mut updated: HashMap<String, SpoolRecord> = HashMap::new();
        let mut dead: Vec<SpoolRecord> = Vec::new();

        for mut record in pending {
            if started.elapsed() >= budget {
                break;
            }
            if !force && record.next_attempt_ms > now {
                continue;
            }
            match self.post(&record.payload).await {
                Ok(status) if (200..300).contains(&status) => {
                    delivered.insert(record.event_id);
                    continue;
                }
                Ok(status) if is_permanent(status) => {
                    record.last_error = Some(format!("http {status}"));
                    tracing::error!(
                        event_id = %record.event_id,
                        status,
                        "dashboard permanently rejected a security event; dead-lettering"
                    );
                    dead.push(record);
                    continue;
                }
                Ok(status) => record.defer(format!("http {status}")),
                Err(e) => record.defer(e),
            }
            if record.attempts >= MAX_ATTEMPTS {
                tracing::error!(
                    event_id = %record.event_id,
                    attempts = record.attempts,
                    last_error = ?record.last_error,
                    "security event exceeded delivery attempts; dead-lettering"
                );
                dead.push(record);
            } else {
                updated.insert(record.event_id.clone(), record);
            }
        }

        if delivered.is_empty() && updated.is_empty() && dead.is_empty() {
            return;
        }
        if let Err(e) = self.reconcile(&delivered, &updated, &dead) {
            // The spool is intact; failing to compact only means duplicate
            // delivery attempts later, which the ingest endpoint deduplicates
            // on event_id.
            tracing::warn!(error = %e, "cannot compact event outbox");
        }
        if !delivered.is_empty() {
            tracing::debug!(count = delivered.len(), "delivered spooled security events");
        }
    }

    fn load_pending(&self) -> std::io::Result<Vec<SpoolRecord>> {
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        read_records(&self.path)
    }

    /// Re-read the spool, apply this drain's outcomes, and rewrite it.
    ///
    /// Re-reading under the lock is what makes concurrent `enqueue` calls
    /// safe: events appended while the drain was awaiting network I/O are
    /// still in the file and are preserved here rather than clobbered.
    fn reconcile(
        &self,
        delivered: &HashSet<String>,
        updated: &HashMap<String, SpoolRecord>,
        dead: &[SpoolRecord],
    ) -> std::io::Result<()> {
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        let dead_ids: HashSet<&str> = dead.iter().map(|r| r.event_id.as_str()).collect();

        let mut keep: Vec<SpoolRecord> = read_records(&self.path)?
            .into_iter()
            .filter(|r| !delivered.contains(&r.event_id) && !dead_ids.contains(r.event_id.as_str()))
            .map(|r| updated.get(&r.event_id).cloned().unwrap_or(r))
            .collect();

        if keep.len() > MAX_SPOOL_RECORDS {
            let dropped = keep.len() - MAX_SPOOL_RECORDS;
            tracing::error!(
                dropped,
                cap = MAX_SPOOL_RECORDS,
                "event outbox exceeded its cap; dropping oldest undelivered events"
            );
            keep.drain(..dropped);
        }

        for record in dead {
            if let Err(e) = append_record(&self.dead_path, record) {
                tracing::warn!(error = %e, "cannot write dead-letter record");
            }
        }
        write_records_atomically(&self.path, &keep)
    }
}

fn append_record(path: &Path, record: &SpoolRecord) -> std::io::Result<()> {
    let line = serde_json::to_string(record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn read_records(path: &Path) -> std::io::Result<Vec<SpoolRecord>> {
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<SpoolRecord>(&line) {
            Ok(record) => records.push(record),
            // A torn final line (power loss mid-append) must not poison the
            // whole spool; skip it and keep the rest.
            Err(e) => tracing::warn!(error = %e, "skipping unreadable outbox record"),
        }
    }
    Ok(records)
}

fn write_records_atomically(path: &Path, records: &[SpoolRecord]) -> std::io::Result<()> {
    if records.is_empty() {
        return match fs::remove_file(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other,
        };
    }
    let temp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp)?;
        for record in records {
            let line = serde_json::to_string(record)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
    }
    fs::rename(&temp, path)
}

/// Parse `HTTP/1.1 201 Created` into `201`.
fn parse_status(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

static OUTBOX: OnceLock<Option<Outbox>> = OnceLock::new();

pub(crate) fn outbox() -> Option<&'static Outbox> {
    OUTBOX.get_or_init(Outbox::from_env).as_ref()
}

/// Drain the spool. No-op when dashboard forwarding is not configured.
pub async fn drain(budget: Duration, force: bool) {
    if let Some(outbox) = outbox() {
        outbox.drain(budget, force).await;
    }
}

/// Background flusher: drains the backlog left by previous runs immediately,
/// then keeps delivering this run's events as they are emitted.
pub fn spawn_flusher() -> Option<tokio::task::JoinHandle<()>> {
    let outbox = outbox()?;
    Some(tokio::spawn(async move {
        loop {
            outbox.drain(FLUSH_INTERVAL * 4, false).await;
            tokio::time::sleep(FLUSH_INTERVAL).await;
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mcp-shield-outbox-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn record(id: &str) -> SpoolRecord {
        SpoolRecord {
            event_id: id.to_string(),
            payload: format!(r#"{{"event_id":"{id}"}}"#),
            attempts: 0,
            next_attempt_ms: 0,
            last_error: None,
        }
    }

    #[test]
    fn spool_survives_a_round_trip() {
        let path = temp_dir("roundtrip").join("outbox.jsonl");
        append_record(&path, &record("a")).unwrap();
        append_record(&path, &record("b")).unwrap();
        let read = read_records(&path).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].event_id, "a");
        assert_eq!(read[1].payload, r#"{"event_id":"b"}"#);
    }

    #[test]
    fn a_torn_line_does_not_poison_the_spool() {
        let path = temp_dir("torn").join("outbox.jsonl");
        append_record(&path, &record("good")).unwrap();
        // Simulate a partial append truncated by power loss.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"event_id\":\"trunc\",\"pay").unwrap();
        let read = read_records(&path).unwrap();
        assert_eq!(read.len(), 1, "the intact record must still be readable");
        assert_eq!(read[0].event_id, "good");
    }

    #[test]
    fn compaction_is_atomic_and_removes_an_empty_spool() {
        let path = temp_dir("compact").join("outbox.jsonl");
        append_record(&path, &record("a")).unwrap();
        write_records_atomically(&path, &[record("b")]).unwrap();
        assert_eq!(read_records(&path).unwrap()[0].event_id, "b");
        write_records_atomically(&path, &[]).unwrap();
        assert!(!path.exists(), "an empty spool should leave no file behind");
        assert!(read_records(&path).unwrap().is_empty());
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let mut rec = record("x");
        rec.defer("http 503".to_string());
        let first = rec.next_attempt_ms - now_ms();
        assert!(first >= 2_000 && first <= 3_100, "first retry ~2s, got {first}");
        for _ in 0..12 {
            rec.defer("http 503".to_string());
        }
        let capped = rec.next_attempt_ms - now_ms();
        assert!(capped <= 301_100, "backoff must cap at ~5min, got {capped}");
        assert_eq!(rec.last_error.as_deref(), Some("http 503"));
    }

    #[test]
    fn permanent_statuses_are_not_retried() {
        // The ingest route returns these for a bad token or an invalid event.
        for status in [400, 401, 403, 413, 422] {
            assert!(is_permanent(status), "{status} should dead-letter");
        }
        // A dashboard that is down or restarting must be retried, not dropped.
        for status in [500, 502, 503, 504, 429] {
            assert!(!is_permanent(status), "{status} should be retried");
        }
    }

    #[test]
    fn status_lines_parse() {
        assert_eq!(parse_status("HTTP/1.1 201 Created\r\n"), Some(201));
        assert_eq!(parse_status("HTTP/1.1 503 Service Unavailable\r\n"), Some(503));
        assert_eq!(parse_status("garbage"), None);
        assert_eq!(parse_status(""), None);
    }

    #[test]
    fn urls_parse_with_and_without_a_port() {
        assert_eq!(
            parse_http_url("http://dashboard:3000/api/ingest"),
            Some(DashboardTarget { host: "dashboard".into(), port: 3000, path: "/api/ingest".into() })
        );
        assert_eq!(
            parse_http_url("http://localhost/api/ingest"),
            Some(DashboardTarget { host: "localhost".into(), port: 80, path: "/api/ingest".into() })
        );
        assert_eq!(parse_http_url("https://dashboard:3000/api/ingest"), None);
        assert_eq!(parse_http_url("not a url"), None);
    }
}
