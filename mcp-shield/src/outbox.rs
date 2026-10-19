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
//! 4. Anything still undelivered stays on the spool and is retried by the
//!    next proxy invocation or the resident `--drain-outbox` process.
//!
//! Production runs keep that resident worker on the shared spool so retry
//! progress is independent of any individual agent session.
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
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Attempts after which an event is moved to the dead-letter file. Attempts
/// persist across runs, so a permanently broken target cannot grow the spool
/// without bound.
const MAX_ATTEMPTS: u32 = 10;
/// Upper bound on spooled records. Enforced at compaction; the oldest records
/// are dropped first (newest detections are the most actionable).
pub const MAX_SPOOL_RECORDS: usize = 10_000;
/// Upper bound on spooled bytes across `outbox.jsonl` and `outbox.dead`.
pub const MAX_SPOOL_BYTES: usize = 16 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
/// How often the background flusher looks for due records.
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const MIN_EVENT_TOKEN_LENGTH: usize = 16;
const MAX_EVENT_TOKEN_LENGTH: usize = 512;

/// HTTP statuses the ingest endpoint returns for input it will never accept:
/// a bad credential (401/403), a malformed or oversized body (400/413), or an
/// event that fails schema validation (422). Retrying these is pointless, so
/// they are dead-lettered immediately instead of consuming attempts.
fn is_permanent(status: u16) -> bool {
    matches!(status, 400 | 401 | 403 | 413 | 422)
}

fn valid_event_token(token: &str) -> bool {
    (MIN_EVENT_TOKEN_LENGTH..=MAX_EVENT_TOKEN_LENGTH).contains(&token.len())
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
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
    #[serde(default)]
    pub created_ms: u128,
}

impl SpoolRecord {
    /// Exponential backoff with jitter, mirroring the Python outbox: ~2^n
    /// seconds capped at 5 minutes. Jitter is derived from the event id (no
    /// `rand` dependency) purely to avoid synchronized retry storms.
    fn defer(&mut self, error: String) {
        self.attempts += 1;
        let base_ms = 1_000u128 << self.attempts.min(8);
        let jitter_ms = u128::from(
            self.event_id
                .as_bytes()
                .iter()
                .map(|b| u32::from(*b))
                .sum::<u32>()
                % 1_000,
        );
        self.next_attempt_ms = now_ms() + base_ms.min(300_000) + jitter_ms;
        self.last_error = Some(error);
    }
}

/// Snapshot of outbox queue depths and age for `/stats` reporting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxStats {
    pub outbox_pending: usize,
    pub outbox_dead_letter: usize,
    pub oldest_pending_age_seconds: u64,
}

pub(crate) fn parse_dashboard_url(value: &str, allow_insecure_http: bool) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() == "http" && !loopback && !allow_insecure_http {
        return None;
    }
    Some(url)
}

pub struct Outbox {
    path: PathBuf,
    lock_path: PathBuf,
    dead_path: PathBuf,
    target: reqwest::Url,
    client: reqwest::Client,
    token: String,
    /// Serializes every read-modify-write of the spool file. Held only across
    /// synchronous file I/O — never across an `.await`.
    file_lock: Mutex<()>,
}

impl Outbox {
    /// Construct an `Outbox` backed by `path` for local file operations
    /// (`stats`, `replay_dead_letters`, and unit testing).
    pub fn for_path(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(RESPONSE_TIMEOUT)
            .build()
            .map_err(io::Error::other)?;
        let target = reqwest::Url::parse("http://127.0.0.1:3000/api/events").expect("static url");
        Ok(Self {
            dead_path: path.with_extension("dead"),
            lock_path: path.with_extension("lock"),
            path,
            target,
            client,
            token: String::new(),
            file_lock: Mutex::new(()),
        })
    }

    fn from_env() -> Option<Arc<Outbox>> {
        let url = std::env::var("MONOLITH_DASHBOARD_URL").ok()?;
        let allow_insecure_http =
            std::env::var("MONOLITH_ALLOW_INSECURE_DASHBOARD").is_ok_and(|value| value == "true");
        let target = match parse_dashboard_url(&url, allow_insecure_http) {
            Some(t) => t,
            None => {
                tracing::warn!(url = %url, "MONOLITH_DASHBOARD_URL must use HTTPS (HTTP is loopback-only unless explicitly enabled) and contain no credentials or fragment; dashboard forwarding disabled");
                return None;
            }
        };
        // The ingest endpoint requires a per-module bearer token. Without one
        // every POST would 401 and be dead-lettered on arrival, so spooling
        // would only burn disk — fail loudly instead.
        let token = match std::env::var("MONOLITH_EVENT_TOKEN") {
            Ok(token) if valid_event_token(&token) => token,
            _ => {
                tracing::warn!(
                    min_length = MIN_EVENT_TOKEN_LENGTH,
                    "MONOLITH_DASHBOARD_URL is set but MONOLITH_EVENT_TOKEN is missing, too short, or not a valid bearer token; dashboard forwarding disabled (events still go to stderr)"
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
        let client = match reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(RESPONSE_TIMEOUT)
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "cannot initialize dashboard HTTP client; forwarding disabled");
                return None;
            }
        };
        Some(Arc::new(Outbox {
            dead_path: path.with_extension("dead"),
            lock_path: path.with_extension("lock"),
            path,
            target,
            client,
            token,
            file_lock: Mutex::new(()),
        }))
    }

    pub fn spool_path(&self) -> &Path {
        &self.path
    }

    pub fn dead_letter_path(&self) -> &Path {
        &self.dead_path
    }

    /// Append one event to the spool and fsync it. This is the only operation
    /// on the proxy's hot path; it is synchronous and bounded.
    pub(crate) fn enqueue(&self, event_id: &str, payload: &str) -> io::Result<()> {
        let now = now_ms();
        let record = SpoolRecord {
            event_id: event_id.to_string(),
            payload: payload.to_string(),
            attempts: 0,
            next_attempt_ms: now,
            last_error: None,
            created_ms: now,
        };
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _process_guard = self.acquire_process_lock()?;
        append_record_bounded(&self.path, &record, MAX_SPOOL_RECORDS, MAX_SPOOL_BYTES)
    }

    /// Move all records from `outbox.dead` back into `outbox.jsonl` with
    /// `attempts: 0` and `next_attempt_ms: 0` under the file and process locks.
    /// Returns the number of dead-letter records replayed.
    pub fn replay_dead_letters(&self) -> io::Result<usize> {
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _process_guard = self.acquire_process_lock()?;

        let dead_records = read_records(&self.dead_path)?;
        if dead_records.is_empty() {
            return Ok(0);
        }
        let replayed = dead_records.len();
        let mut pending = read_records(&self.path)?;
        let now = now_ms();
        for mut record in dead_records {
            record.attempts = 0;
            record.next_attempt_ms = 0;
            record.last_error = None;
            if record.created_ms == 0 {
                record.created_ms = now;
            }
            pending.push(record);
        }
        enforce_spool_bounds(&mut pending, MAX_SPOOL_RECORDS, MAX_SPOOL_BYTES);
        write_records_atomically(&self.path, &pending)?;
        write_records_atomically(&self.dead_path, &[])?;
        Ok(replayed)
    }

    /// Inspect current pending and dead-letter counts plus the age in seconds
    /// of the oldest pending record.
    pub fn stats(&self) -> OutboxStats {
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _process_guard = self.acquire_process_lock().ok();
        let pending = read_records(&self.path).unwrap_or_default();
        let dead = read_records(&self.dead_path).unwrap_or_default();
        let now = now_ms();
        let oldest_pending_age_seconds = pending
            .iter()
            .filter_map(record_created_ms)
            .map(|created| (now.saturating_sub(created) / 1000) as u64)
            .max()
            .unwrap_or(0);
        OutboxStats {
            outbox_pending: pending.len(),
            outbox_dead_letter: dead.len(),
            oldest_pending_age_seconds,
        }
    }

    async fn post(&self, body: &str) -> Result<u16, String> {
        self.client
            .post(self.target.clone())
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_owned())
            .send()
            .await
            .map(|response| response.status().as_u16())
            .map_err(|error| error.to_string())
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

    fn load_pending(&self) -> io::Result<Vec<SpoolRecord>> {
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _process_guard = self.acquire_process_lock()?;
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
    ) -> io::Result<()> {
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _process_guard = self.acquire_process_lock()?;
        let dead_ids: HashSet<&str> = dead.iter().map(|r| r.event_id.as_str()).collect();

        let mut keep: Vec<SpoolRecord> = read_records(&self.path)?
            .into_iter()
            .filter(|r| !delivered.contains(&r.event_id) && !dead_ids.contains(r.event_id.as_str()))
            .map(|r| updated.get(&r.event_id).cloned().unwrap_or(r))
            .collect();

        let dropped = enforce_spool_bounds(&mut keep, MAX_SPOOL_RECORDS, MAX_SPOOL_BYTES);
        if dropped > 0 {
            tracing::error!(
                dropped,
                cap_records = MAX_SPOOL_RECORDS,
                cap_bytes = MAX_SPOOL_BYTES,
                "event outbox exceeded its cap; dropping oldest undelivered events"
            );
        }

        if !dead.is_empty() {
            if let Err(e) = append_dead_records_bounded(
                &self.dead_path,
                dead,
                MAX_SPOOL_RECORDS,
                MAX_SPOOL_BYTES,
            ) {
                tracing::warn!(error = %e, "cannot write dead-letter records");
            }
        }
        write_records_atomically(&self.path, &keep)
    }

    /// Serialize spool mutations across proxy processes and the resident
    /// drainer. The in-memory mutex only protects tasks in one process; this
    /// advisory lock protects the shared volume itself.
    fn acquire_process_lock(&self) -> io::Result<std::fs::File> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)?;
        file.lock_exclusive()?;
        Ok(file)
    }
}

fn record_created_ms(record: &SpoolRecord) -> Option<u128> {
    if record.created_ms > 0 {
        return Some(record.created_ms);
    }
    if let Ok(val) = serde_json::from_str::<Value>(&record.payload) {
        if let Some(ts) = val.get("timestamp_ms").and_then(Value::as_u64) {
            if ts > 0 {
                return Some(u128::from(ts));
            }
        }
    }
    if record.attempts == 0 && record.next_attempt_ms > 0 {
        return Some(record.next_attempt_ms);
    }
    None
}

pub(crate) fn enforce_spool_bounds(
    records: &mut Vec<SpoolRecord>,
    max_records: usize,
    max_bytes: usize,
) -> usize {
    let initial_len = records.len();
    if records.len() > max_records {
        let drop_count = records.len() - max_records;
        records.drain(..drop_count);
    }
    let sizes: Vec<usize> = records
        .iter()
        .map(|r| serde_json::to_string(r).map(|s| s.len() + 1).unwrap_or(0))
        .collect();
    let mut total_bytes: usize = sizes.iter().sum();
    let mut byte_drops = 0;
    while total_bytes > max_bytes && byte_drops < records.len() {
        total_bytes = total_bytes.saturating_sub(sizes[byte_drops]);
        byte_drops += 1;
    }
    if byte_drops > 0 {
        records.drain(..byte_drops);
    }
    initial_len - records.len()
}

fn append_record(path: &Path, record: &SpoolRecord) -> io::Result<()> {
    let line =
        serde_json::to_string(record).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn append_record_bounded(
    path: &Path,
    record: &SpoolRecord,
    max_records: usize,
    max_bytes: usize,
) -> io::Result<()> {
    let line =
        serde_json::to_string(record).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let existing_len = fs::metadata(path).map(|m| m.len() as usize).unwrap_or(0);
    if existing_len + line.len() + 1 > max_bytes {
        let mut records = read_records(path)?;
        records.push(record.clone());
        enforce_spool_bounds(&mut records, max_records, max_bytes);
        return write_records_atomically(path, &records);
    }
    append_record(path, record)
}

pub(crate) fn append_dead_records_bounded(
    dead_path: &Path,
    new_dead: &[SpoolRecord],
    max_records: usize,
    max_bytes: usize,
) -> io::Result<()> {
    if new_dead.is_empty() {
        return Ok(());
    }
    let mut records = read_records(dead_path)?;
    records.extend_from_slice(new_dead);
    let dropped = enforce_spool_bounds(&mut records, max_records, max_bytes);
    if dropped > 0 {
        tracing::warn!(
            dropped,
            cap_records = max_records,
            cap_bytes = max_bytes,
            "dead-letter spool exceeded cap; dropping oldest dead-letter records"
        );
    }
    write_records_atomically(dead_path, &records)
}

fn read_records(path: &Path) -> io::Result<Vec<SpoolRecord>> {
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
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

fn write_records_atomically(path: &Path, records: &[SpoolRecord]) -> io::Result<()> {
    if records.is_empty() {
        return match fs::remove_file(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
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
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
    }
    fs::rename(&temp, path)
}

static OUTBOX: OnceLock<Option<Arc<Outbox>>> = OnceLock::new();

pub(crate) fn outbox() -> Option<&'static Arc<Outbox>> {
    OUTBOX.get_or_init(Outbox::from_env).as_ref()
}

/// Resolve the active `Outbox` instance or open the spool file configured via
/// `MONOLITH_EVENT_OUTBOX_PATH` (default `/var/lib/monolith/outbox.jsonl`).
pub fn outbox_or_from_env_path() -> io::Result<Arc<Outbox>> {
    if let Some(configured) = outbox() {
        return Ok(Arc::clone(configured));
    }
    let path = PathBuf::from(
        std::env::var("MONOLITH_EVENT_OUTBOX_PATH")
            .unwrap_or_else(|_| "/var/lib/monolith/outbox.jsonl".to_string()),
    );
    Ok(Arc::new(Outbox::for_path(path)?))
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
    let outbox = Arc::clone(outbox);
    Some(tokio::spawn(async move {
        loop {
            outbox.drain(FLUSH_INTERVAL * 4, false).await;
            tokio::time::sleep(FLUSH_INTERVAL).await;
        }
    }))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn admin_authorized(expected_token: Option<&str>, auth_header: Option<&str>) -> bool {
    let Some(expected) = expected_token.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    let Some(header) = auth_header else {
        return false;
    };
    let Some(supplied) = header.strip_prefix("Bearer ") else {
        return false;
    };
    !supplied.is_empty() && constant_time_eq(supplied.as_bytes(), expected.as_bytes())
}

fn write_http_json_response(
    mut stream: TcpStream,
    status_code: u16,
    reason: &str,
    body: &Value,
) -> io::Result<()> {
    let payload = serde_json::to_string(body).unwrap_or_else(|_| "{}".to_string());
    let response = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

/// Handle a single HTTP connection on the status listener (`/health`, `/stats`,
/// and `POST /admin/replay-dead-letters`).
pub fn handle_status_connection(
    stream: TcpStream,
    outbox: &Outbox,
    admin_token: Option<&str>,
) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let cloned = stream.try_clone()?;
    let mut reader = BufReader::new(cloned);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("");
    let path = raw_target.split('?').next().unwrap_or(raw_target);

    let mut auth_header: Option<String> = None;
    for _ in 0..64 {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                auth_header = Some(value.trim().to_string());
            }
        }
    }

    match (method, path) {
        ("GET", "/health") => write_http_json_response(
            stream,
            200,
            "OK",
            &json!({
                "status": "ok",
                "module": crate::events::MODULE,
            }),
        ),
        ("GET", "/stats") => {
            if !admin_authorized(admin_token, auth_header.as_deref()) {
                return write_http_json_response(
                    stream,
                    401,
                    "Unauthorized",
                    &json!({ "error": "invalid administrative credential" }),
                );
            }
            let s = outbox.stats();
            write_http_json_response(
                stream,
                200,
                "OK",
                &json!({
                    "status": "ok",
                    "module": crate::events::MODULE,
                    "outbox_pending": s.outbox_pending,
                    "outbox_dead_letter": s.outbox_dead_letter,
                    "oldest_pending_age_seconds": s.oldest_pending_age_seconds,
                    "delivery": {
                        "pending": s.outbox_pending,
                        "dead": s.outbox_dead_letter,
                        "oldest_pending_age_seconds": s.oldest_pending_age_seconds,
                        "worker_alive": true,
                        "worker_error": Value::Null,
                    }
                }),
            )
        }
        ("POST", "/admin/replay-dead-letters") => {
            if !admin_authorized(admin_token, auth_header.as_deref()) {
                return write_http_json_response(
                    stream,
                    401,
                    "Unauthorized",
                    &json!({ "error": "invalid administrative credential" }),
                );
            }
            match outbox.replay_dead_letters() {
                Ok(replayed) => {
                    write_http_json_response(stream, 200, "OK", &json!({ "replayed": replayed }))
                }
                Err(error) => write_http_json_response(
                    stream,
                    500,
                    "Internal Server Error",
                    &json!({ "error": error.to_string() }),
                ),
            }
        }
        _ => write_http_json_response(stream, 404, "Not Found", &json!({ "error": "not found" })),
    }
}

/// Spawn a lightweight background `std::net::TcpListener` thread serving
/// `/health`, `/stats`, and `POST /admin/replay-dead-letters`.
pub fn spawn_status_listener(
    bind_addr: &str,
    outbox: Arc<Outbox>,
    admin_token: Option<String>,
) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(bind_addr)?;
    let local_addr = listener.local_addr()?;
    std::thread::Builder::new()
        .name("mcp-shield-status".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let _ = handle_status_connection(stream, &outbox, admin_token.as_deref());
                    }
                    Err(error) => {
                        tracing::debug!(%error, "status listener accept failed");
                    }
                }
            }
        })?;
    Ok(local_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mcp-shield-outbox-{name}-{}", std::process::id()));
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
            created_ms: now_ms(),
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
        assert!(
            (2_000..=3_100).contains(&first),
            "first retry ~2s, got {first}"
        );
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
    fn dashboard_urls_require_secure_transport_or_explicit_opt_in() {
        assert!(parse_dashboard_url("http://dashboard:3000/api/ingest", false).is_none());
        let http = parse_dashboard_url("http://dashboard:3000/api/ingest", true).unwrap();
        assert_eq!(http.as_str(), "http://dashboard:3000/api/ingest");
        assert!(parse_dashboard_url("http://127.0.0.1:3000/api/ingest", false).is_some());

        let https = parse_dashboard_url("https://example.com/api/ingest", false).unwrap();
        assert_eq!(https.scheme(), "https");

        assert!(parse_dashboard_url("ftp://example.com/api/ingest", false).is_none());
        assert!(parse_dashboard_url("https://user:pass@example.com/api/ingest", false).is_none());
        assert!(parse_dashboard_url("https://example.com/api/ingest#secret", false).is_none());
        assert!(parse_dashboard_url("not a url", false).is_none());
    }

    #[test]
    fn event_tokens_must_be_long_and_header_safe() {
        assert!(valid_event_token("abcDEF0123456789-_"));
        assert!(valid_event_token("base64/value+with=padding"));
        assert!(!valid_event_token("short"));
        assert!(!valid_event_token("valid-length-token\r\nInjected: yes"));
        assert!(!valid_event_token("valid length token with spaces"));
        assert!(!valid_event_token(&"x".repeat(MAX_EVENT_TOKEN_LENGTH + 1)));
    }

    #[test]
    fn dead_letter_spool_enforces_record_and_byte_bounds() {
        let dead_path = temp_dir("dead-bounds").join("outbox.dead");
        let batch: Vec<SpoolRecord> = (0..10).map(|i| record(&format!("evt-{i}"))).collect();
        // Enforce max 4 records
        append_dead_records_bounded(&dead_path, &batch, 4, MAX_SPOOL_BYTES).unwrap();
        let kept = read_records(&dead_path).unwrap();
        assert_eq!(kept.len(), 4);
        assert_eq!(kept[0].event_id, "evt-6");
        assert_eq!(kept[3].event_id, "evt-9");

        // Enforce tight byte limit so only the newest 2 records fit
        let new_rec = record("evt-10");
        let two_size = serde_json::to_string(&kept[3]).unwrap().len()
            + 1
            + serde_json::to_string(&new_rec).unwrap().len()
            + 1;
        append_dead_records_bounded(&dead_path, &[new_rec], 10, two_size).unwrap();
        let byte_kept = read_records(&dead_path).unwrap();
        assert_eq!(byte_kept.len(), 2);
        assert_eq!(byte_kept[0].event_id, "evt-9");
        assert_eq!(byte_kept[1].event_id, "evt-10");
    }

    #[test]
    fn replay_dead_letters_and_stats_work_end_to_end() {
        let dir = temp_dir("replay-stats");
        let spool_path = dir.join("outbox.jsonl");
        let outbox = Outbox::for_path(&spool_path).unwrap();

        // Enqueue one pending record aged 5 seconds
        let mut old_pending = record("pending-1");
        old_pending.created_ms = now_ms().saturating_sub(5_200);
        write_records_atomically(outbox.spool_path(), &[old_pending]).unwrap();

        // Add two dead-letter records with non-zero attempts and future next_attempt_ms
        let mut dead1 = record("dead-1");
        dead1.attempts = 10;
        dead1.next_attempt_ms = now_ms() + 60_000;
        dead1.last_error = Some("http 503".to_string());
        let mut dead2 = record("dead-2");
        dead2.attempts = 3;
        dead2.next_attempt_ms = now_ms() + 30_000;
        dead2.last_error = Some("http 401".to_string());
        append_dead_records_bounded(
            outbox.dead_letter_path(),
            &[dead1, dead2],
            MAX_SPOOL_RECORDS,
            MAX_SPOOL_BYTES,
        )
        .unwrap();

        let stats_before = outbox.stats();
        assert_eq!(stats_before.outbox_pending, 1);
        assert_eq!(stats_before.outbox_dead_letter, 2);
        assert!(stats_before.oldest_pending_age_seconds >= 5);

        let replayed = outbox.replay_dead_letters().unwrap();
        assert_eq!(replayed, 2);
        assert!(!outbox.dead_letter_path().exists());

        let stats_after = outbox.stats();
        assert_eq!(stats_after.outbox_pending, 3);
        assert_eq!(stats_after.outbox_dead_letter, 0);

        let pending_records = read_records(outbox.spool_path()).unwrap();
        assert_eq!(pending_records.len(), 3);
        assert_eq!(pending_records[1].event_id, "dead-1");
        assert_eq!(pending_records[1].attempts, 0);
        assert_eq!(pending_records[1].next_attempt_ms, 0);
        assert!(pending_records[1].last_error.is_none());
    }

    #[test]
    fn status_listener_serves_health_stats_and_replay_with_auth() {
        let dir = temp_dir("status-http");
        let outbox = Arc::new(Outbox::for_path(dir.join("outbox.jsonl")).unwrap());
        let mut dead = record("dead-http-1");
        dead.attempts = 10;
        append_dead_records_bounded(
            outbox.dead_letter_path(),
            &[dead],
            MAX_SPOOL_RECORDS,
            MAX_SPOOL_BYTES,
        )
        .unwrap();

        let token = "super-secret-admin-token-123456";
        let addr =
            spawn_status_listener("127.0.0.1:0", Arc::clone(&outbox), Some(token.to_string()))
                .unwrap();

        let send_raw = |raw_req: &str| -> String {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(raw_req.as_bytes()).unwrap();
            stream.flush().unwrap();
            let mut resp = String::new();
            stream.read_to_string(&mut resp).unwrap();
            resp
        };

        // 1. GET /health (no auth required)
        let health_resp = send_raw("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(health_resp.starts_with("HTTP/1.1 200 OK"));
        let health_body: Value =
            serde_json::from_str(health_resp.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(health_body["status"], "ok");
        assert_eq!(health_body["module"], "mcp-shield");

        // 2. GET /stats without token -> 401
        let unauth_stats = send_raw("GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(unauth_stats.starts_with("HTTP/1.1 401 Unauthorized"));

        // 3. GET /stats with valid token -> 200
        let auth_stats = send_raw(&format!(
            "GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n"
        ));
        assert!(auth_stats.starts_with("HTTP/1.1 200 OK"));
        let stats_body: Value =
            serde_json::from_str(auth_stats.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(stats_body["status"], "ok");
        assert_eq!(stats_body["module"], "mcp-shield");
        assert_eq!(stats_body["outbox_pending"], 0);
        assert_eq!(stats_body["outbox_dead_letter"], 1);

        // 4. POST /admin/replay-dead-letters with valid token -> 200 {"replayed": 1}
        let replay_resp = send_raw(&format!(
            "POST /admin/replay-dead-letters HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n"
        ));
        assert!(replay_resp.starts_with("HTTP/1.1 200 OK"));
        let replay_body: Value =
            serde_json::from_str(replay_resp.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(replay_body["replayed"], 1);
        assert_eq!(outbox.stats().outbox_pending, 1);
        assert_eq!(outbox.stats().outbox_dead_letter, 0);
    }
}
