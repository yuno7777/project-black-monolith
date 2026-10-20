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
use std::sync::{Arc, Mutex, OnceLock, RwLock};
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
/// The revocation poll cadence used when the operator did not choose one.
const DEFAULT_POLL_INTERVAL_MS: u64 = 15_000;
/// The shortest cadence the revocation poller will run at.
const MIN_POLL_INTERVAL_MS: u64 = 1_000;

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

/// Upper bound on the ingest response body read back for the revocation
/// snapshot. The real response (ids plus a session list) is a few kilobytes.
const MAX_INGEST_RESPONSE_BYTES: usize = 64 * 1024;

/// How many pages of the revocation snapshot this module will follow.
///
/// The bound is there so a broken or hostile dashboard cannot make the
/// poller fetch forever. A snapshot larger than this is refused rather than
/// half-mirrored: forgetting a revocation lets a quarantined session back in.
const MAX_REVOCATION_PAGES: usize = 64;

/// Sessions the dashboard's cross-layer circuit breaker revoked.
///
/// The dashboard is the authority and does not expire revocations, so neither
/// does this mirror: the snapshot replaces the whole set, and a missing or
/// unparseable snapshot leaves the previous set in place. Fail closed, not
/// open.
fn revoked_session_store() -> &'static RwLock<HashSet<String>> {
    static REVOKED_SESSIONS: OnceLock<RwLock<HashSet<String>>> = OnceLock::new();
    REVOKED_SESSIONS.get_or_init(|| RwLock::new(HashSet::new()))
}

/// The mirror is process-wide, so the tests that read or write it take this
/// lock. Without it two tests interleave and one of them reads the other's
/// snapshot.
#[cfg(test)]
pub(crate) static MIRROR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether `session_id` is currently revoked; an empty id is never revoked.
pub(crate) fn is_session_revoked(session_id: &str) -> bool {
    let session_id = session_id.trim();
    if session_id.is_empty() || session_id.len() > 128 {
        return false;
    }
    revoked_session_store()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains(session_id)
}

/// Read a response body with a hard byte cap; the revocation snapshot is
/// small, and a compromised or misconfigured target must not be able to make
/// the proxy buffer an unbounded body.
async fn read_bounded_response(mut response: reqwest::Response) -> String {
    let mut body: Vec<u8> = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > MAX_INGEST_RESPONSE_BYTES {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8_lossy(&body).into_owned()
}

/// What a response says about the revoked-session set.
enum RevocationSnapshot {
    /// The whole set, inline. It replaces the mirror.
    Complete(Vec<String>),
    /// One page of a larger set, and the cursor of the page after it.
    Page {
        ids: Vec<String>,
        next_cursor: Option<String>,
    },
    /// The response is not a snapshot at all.
    Absent,
}

/// Clean the session ids of a snapshot.
fn clean_revocation_ids(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|id| {
            !id.is_empty() && id.len() <= 128 && !id.chars().any(|character| character.is_control())
        })
        .map(str::to_string)
        .collect()
}

/// Read what a response says about the revoked-session set.
///
/// The snapshot is paged. A module reads a response body under a hard byte
/// cap, and a snapshot larger than that cap cannot be parsed at all: the
/// module keeps the set it already had, and that set is stale. Past a certain
/// number of live revocations every snapshot is too large, so the staleness
/// never ends and the circuit breaker fails open for exactly the sessions it
/// was meant to quarantine. The dashboard therefore sends the whole set when
/// it fits and pages it when it does not.
fn parse_revocation_snapshot(body: &str) -> RevocationSnapshot {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return RevocationSnapshot::Absent;
    };
    let Some(raw) = value.get("revoked_sessions") else {
        return RevocationSnapshot::Absent;
    };
    let ids = match raw.as_array() {
        Some(items) => clean_revocation_ids(items),
        // A response that says the set does not fit carries no ids at all.
        None => Vec::new(),
    };
    let complete = value
        .get("revoked_sessions_complete")
        .and_then(Value::as_bool)
        != Some(false);
    if complete {
        return RevocationSnapshot::Complete(ids);
    }
    let next_cursor = value
        .get("next_cursor")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|cursor| !cursor.is_empty())
        .map(str::to_string);
    RevocationSnapshot::Page { ids, next_cursor }
}

/// Install a complete revocation snapshot, replacing the mirror.
fn apply_revocation_snapshot(ids: Vec<String>) -> usize {
    let cleaned: HashSet<String> = ids.into_iter().collect();
    let count = cleaned.len();
    let mut store = revoked_session_store()
        .write()
        .unwrap_or_else(|e| e.into_inner());
    *store = cleaned;
    count
}

/// Adopt the `revoked_sessions` snapshot of an ingest response.
///
/// Returns `Some(count)` when the body carried a usable snapshot (possibly
/// empty, which correctly lifts local revocations), and `None` when it did
/// not: in which case the previous snapshot stands. A response that says its
/// set is not complete is not a snapshot: installing a partial set would
/// forget every revocation that is not in it.
pub(crate) fn observe_revoked_sessions(body: &str) -> Option<usize> {
    match parse_revocation_snapshot(body) {
        RevocationSnapshot::Complete(ids) => Some(apply_revocation_snapshot(ids)),
        RevocationSnapshot::Page { .. } | RevocationSnapshot::Absent => None,
    }
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
    /// Where the events go. `None` means there is nowhere to go: an outbox
    /// opened by path alone spools and reports, and does not deliver.
    target: Option<reqwest::Url>,
    client: reqwest::Client,
    token: String,
    /// Serializes every read-modify-write of the spool file. Held only across
    /// synchronous file I/O — never across an `.await`.
    file_lock: Mutex<()>,
}

impl Outbox {
    /// Construct an `Outbox` backed by `path` for local file operations
    /// (`stats`, `replay_dead_letters`, and unit testing).
    ///
    /// There is no delivery endpoint and no credential here on purpose. The
    /// endpoint used to be a guess — the dashboard's SSE address — with an
    /// empty credential, which named a route that cannot accept an event
    /// and could not authenticate one. A guessed address is worse than no
    /// address: posting to it turns every event into a dead letter.
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
        Ok(Self {
            dead_path: path.with_extension("dead"),
            lock_path: path.with_extension("lock"),
            path,
            target: None,
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
            target: Some(target),
            client,
            token,
            file_lock: Mutex::new(()),
        }))
    }

    #[cfg(test)]
    pub fn spool_path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
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

    /// Move records from `outbox.dead` back into `outbox.jsonl` with
    /// `attempts: 0` and `next_attempt_ms: 0` under the file and process locks.
    /// Returns the number of dead-letter records replayed.
    ///
    /// A tenant-scoped replay (`Some(tenant)`) moves only that tenant's
    /// records. The spool is shared, and an operator for one tenant has no
    /// authority over another tenant's evidence, so the records that belong
    /// to somebody else stay dead rather than being handed to whoever asked.
    pub fn replay_dead_letters(&self, tenant: Option<&str>) -> io::Result<usize> {
        let _guard = self.file_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _process_guard = self.acquire_process_lock()?;

        let dead_records = read_records(&self.dead_path)?;
        if dead_records.is_empty() {
            return Ok(0);
        }
        let (selected, left_behind): (Vec<SpoolRecord>, Vec<SpoolRecord>) = match tenant {
            Some(scope) => dead_records
                .into_iter()
                .partition(|record| record_tenant(record).as_deref() == Some(scope)),
            None => (dead_records, Vec::new()),
        };
        if selected.is_empty() {
            return Ok(0);
        }
        let replayed = selected.len();
        let mut pending = read_records(&self.path)?;
        // Refuse rather than silently discard. The spool bound drops the
        // oldest records from the front and the replayed dead letters are
        // appended at the end, so replaying into a full spool destroys
        // undelivered evidence — and the operator is told only that N
        // records were replayed.
        let projected_records = pending.len() + selected.len();
        let projected_bytes: usize = pending
            .iter()
            .chain(selected.iter())
            .map(|record| {
                serde_json::to_string(record)
                    .map(|s| s.len() + 1)
                    .unwrap_or(0)
            })
            .sum();
        if projected_records > MAX_SPOOL_RECORDS || projected_bytes > MAX_SPOOL_BYTES {
            return Err(io::Error::other(format!(
                "the outbox spool is at its bound ({projected_records} records, \
                 {projected_bytes} bytes); the dead letters were not replayed and \
                 no pending event was discarded"
            )));
        }
        let now = now_ms();
        for mut record in selected {
            record.attempts = 0;
            record.next_attempt_ms = 0;
            record.last_error = None;
            if record.created_ms == 0 {
                record.created_ms = now;
            }
            pending.push(record);
        }
        let dropped = enforce_spool_bounds(&mut pending, MAX_SPOOL_RECORDS, MAX_SPOOL_BYTES);
        if dropped > 0 {
            tracing::error!(
                dropped,
                "the outbox spool dropped records while replaying dead letters"
            );
        }
        write_records_atomically(&self.path, &pending)?;
        // The dead file is rewritten with what is left, not emptied: the
        // records that belong to another tenant are still evidence.
        write_records_atomically(&self.dead_path, &left_behind)?;
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

    async fn post(&self, body: &str) -> Result<(u16, String), String> {
        let Some(target) = self.target.as_ref() else {
            return Err("no dashboard endpoint is configured for this outbox".to_string());
        };
        let response = self
            .client
            .post(target.clone())
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_owned())
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let text = read_bounded_response(response).await;
        if (200..300).contains(&status) {
            // Ingest responses carry the circuit breaker's revocations; the
            // background poller covers the idle case where no event is sent.
            if let Some(count) = observe_revoked_sessions(&text) {
                if count > 0 {
                    tracing::warn!(revoked_sessions = count, "dashboard revoked sessions");
                }
            }
        }
        Ok((status, text))
    }

    /// Attempt delivery of spooled records within `budget`.
    ///
    /// `force` ignores per-record backoff — used for the final drain before
    /// exit, where a last attempt now beats a scheduled attempt that will
    /// never happen.
    pub(crate) async fn drain(&self, budget: Duration, force: bool) {
        if self.target.is_none() {
            // An outbox opened by path alone has nowhere to deliver: it
            // spools and it reports, and it does not deliver. Attempting a
            // delivery anyway would turn every event into a dead letter,
            // which reads like a rejected event rather than like an
            // endpoint that was never configured.
            tracing::debug!("no dashboard endpoint is configured; the spool is not draining");
            return;
        }
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
                Ok((status, _)) if (200..300).contains(&status) => {
                    delivered.insert(record.event_id);
                    continue;
                }
                Ok((status, _)) if is_permanent(status) => {
                    record.last_error = Some(format!("http {status}"));
                    tracing::error!(
                        event_id = %record.event_id,
                        status,
                        "dashboard permanently rejected a security event; dead-lettering"
                    );
                    dead.push(record);
                    continue;
                }
                Ok((status, _)) => record.defer(format!("http {status}")),
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

/// The tenant a spooled record belongs to, read from the event payload.
///
/// The payload is the event envelope, so the tenant is in it. Reading it back
/// is what lets a record be attributed to a tenant without a second source of
/// truth that could disagree with what actually gets delivered. A record that
/// cannot be read is attributed to nobody, which means a tenant-scoped replay
/// leaves it alone rather than handing it to the wrong tenant.
fn record_tenant(record: &SpoolRecord) -> Option<String> {
    let value: Value = serde_json::from_str(&record.payload).ok()?;
    let tenant = value.get("tenant_id")?.as_str()?.trim();
    if tenant.is_empty() || tenant.len() > 128 {
        return None;
    }
    if tenant.chars().any(|character| character.is_control()) {
        return None;
    }
    Some(tenant.to_string())
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

/// Derive `GET /api/sessions/revoked` from the configured ingest endpoint.
fn revocation_poll_url(target: &reqwest::Url) -> Option<reqwest::Url> {
    let path = target.path().trim_end_matches('/');
    let prefix = path.strip_suffix("/api/ingest")?;
    let mut poll = target.clone();
    poll.set_path(&format!("{prefix}/api/sessions/revoked"));
    poll.set_query(None);
    poll.set_fragment(None);
    Some(poll)
}

/// Revocation poll cadence.
///
/// Zero is the explicit off switch, and the only way to turn polling off. A
/// value that cannot be read as a cadence of at least
/// [`MIN_POLL_INTERVAL_MS`] falls back to the default rather than stopping
/// the poller: the poll is the only way an idle module learns that its
/// session was revoked, so a mistyped interval must not quietly switch that
/// off. The fallback says so, loudly, and keeps the control on.
fn poll_interval_ms() -> Option<u64> {
    let Ok(raw) = std::env::var("MONOLITH_SESSION_POLL_MS") else {
        return Some(DEFAULT_POLL_INTERVAL_MS);
    };
    match raw.trim().parse::<u64>() {
        Ok(0) => {
            tracing::info!(
                "MONOLITH_SESSION_POLL_MS=0: revoked-session polling is disabled for this module"
            );
            None
        }
        Ok(value) if value >= MIN_POLL_INTERVAL_MS => Some(value),
        _ => {
            tracing::warn!(
                value = raw.trim(),
                "unrecognized MONOLITH_SESSION_POLL_MS (expected 0, or a cadence of at least 1000 ms); \
                 using the default cadence of 15000 ms"
            );
            Some(DEFAULT_POLL_INTERVAL_MS)
        }
    }
}

/// The URL of the page that starts after `cursor`.
///
/// The cursor is base64url, and it is checked against the alphabet it is
/// supposed to use: a cursor is a position in the tenant's revocation list,
/// and a position that carries anything else is not one.
fn revocation_page_url(base: &reqwest::Url, cursor: &str) -> Option<reqwest::Url> {
    if cursor.is_empty()
        || cursor.len() > 512
        || !cursor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return None;
    }
    let mut page = base.clone();
    page.set_query(Some(&format!("cursor={cursor}")));
    Some(page)
}

/// Fetch one page of the revocation snapshot.
async fn fetch_revocation_page(
    client: &reqwest::Client,
    base: &reqwest::Url,
    token: &str,
    tenant: &str,
    cursor: &str,
) -> Option<RevocationSnapshot> {
    let url = revocation_page_url(base, cursor)?;
    let response = client
        .get(url)
        .bearer_auth(token)
        .header("x-monolith-tenant-id", tenant)
        .header("x-monolith-module", crate::events::MODULE)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = read_bounded_response(response).await;
    match parse_revocation_snapshot(&body) {
        RevocationSnapshot::Absent => None,
        snapshot => Some(snapshot),
    }
}

/// Read the whole revoked-session snapshot, following the pages of it.
///
/// Returns the ids of the whole set, or `None` when the snapshot could not
/// be read to the end. A partial set is never returned: it would forget
/// every revocation that is not on the pages read so far, and a forgotten
/// revocation is a quarantined session that gets to keep working.
async fn read_revocation_snapshot(
    client: &reqwest::Client,
    url: &reqwest::Url,
    token: &str,
    tenant: &str,
) -> Option<Vec<String>> {
    let response = client
        .get(url.clone())
        .bearer_auth(token)
        .header("x-monolith-tenant-id", tenant)
        .header("x-monolith-module", crate::events::MODULE)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        tracing::debug!(
            status = response.status().as_u16(),
            "revocation snapshot poll rejected"
        );
        return None;
    }
    let body = read_bounded_response(response).await;
    let (mut ids, first_cursor) = match parse_revocation_snapshot(&body) {
        RevocationSnapshot::Complete(ids) => return Some(ids),
        RevocationSnapshot::Page { ids, next_cursor } => (ids, next_cursor),
        RevocationSnapshot::Absent => {
            tracing::debug!("the revocation snapshot poll carried no snapshot");
            return None;
        }
    };
    let Some(mut cursor) = first_cursor else {
        tracing::warn!(
            "the revocation snapshot carried no inline set and no way to page it; \
             the previous set stands"
        );
        return None;
    };
    for _ in 0..MAX_REVOCATION_PAGES {
        let Some(page) = fetch_revocation_page(client, url, token, tenant, &cursor).await else {
            tracing::warn!(
                "a page of the revocation snapshot could not be read; the previous set stands"
            );
            return None;
        };
        match page {
            RevocationSnapshot::Complete(page_ids) => {
                ids.extend(page_ids);
                return Some(ids);
            }
            RevocationSnapshot::Page {
                ids: page_ids,
                next_cursor,
            } => {
                ids.extend(page_ids);
                match next_cursor {
                    Some(next) => cursor = next,
                    None => return Some(ids),
                }
            }
            RevocationSnapshot::Absent => {
                tracing::warn!(
                    "a page of the revocation snapshot was not a snapshot; the previous set stands"
                );
                return None;
            }
        }
    }
    tracing::warn!(
        pages = MAX_REVOCATION_PAGES,
        "the revoked-session snapshot is larger than this module will mirror; \
         the previous set stands"
    );
    None
}

/// Refresh the revoked-session mirror from the whole snapshot.
///
/// The mirror is replaced only once every page has been read.
async fn refresh_revoked_sessions(
    client: &reqwest::Client,
    url: &reqwest::Url,
    token: &str,
    tenant: &str,
) {
    let Some(ids) = read_revocation_snapshot(client, url, token, tenant).await else {
        return;
    };
    let count = apply_revocation_snapshot(ids);
    tracing::debug!(
        revoked_sessions = count,
        "refreshed revoked-session snapshot"
    );
}

/// Background revocation poller.
///
/// A revoked session must be cut off even when this short-lived proxy emits no
/// events of its own: the dashboard's breaker trips from other layers'
/// detections, and an idle proxy would otherwise never see it. Each poll
/// adopts the whole snapshot, so a restore (empty set) also propagates.
pub fn spawn_revocation_poller() -> Option<tokio::task::JoinHandle<()>> {
    let outbox = outbox()?;
    let url = revocation_poll_url(outbox.target.as_ref()?)?;
    let interval_ms = poll_interval_ms()?;
    let tenant = std::env::var("MONOLITH_TENANT_ID").unwrap_or_else(|_| "default".to_string());
    let tenant = tenant.trim().to_string();
    if tenant.is_empty() || tenant.len() > 128 || tenant.chars().any(char::is_control) {
        tracing::warn!(
            "MONOLITH_TENANT_ID is missing or invalid; revoked-session polling disabled"
        );
        return None;
    }
    let token = outbox.token.clone();
    let client = match reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(RESPONSE_TIMEOUT)
        // The bearer credential must never follow a redirect to another host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(%error, "cannot initialize revocation poll client");
            return None;
        }
    };
    Some(tokio::spawn(async move {
        loop {
            refresh_revoked_sessions(&client, &url, &token, &tenant).await;
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
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

/// The outcome of checking an administrative credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminAuth {
    /// The credential is valid.
    Authorized,
    /// A credential was supplied and it does not match.
    Rejected,
    /// No usable administrative credential is configured, so the endpoint
    /// cannot authenticate anyone.
    Unavailable,
}

/// Decide whether an administrative request may proceed.
///
/// This fails closed. Treating "no administrative credential is configured" as
/// "everyone is an administrator" exposed the delivery statistics and the
/// dead-letter replay to anyone who could reach the port, and an empty
/// `MONOLITH_ADMIN_TOKEN` — a common "unset by default" pattern — silently
/// produced exactly that state. The Python modules already refuse the request
/// in this situation; this does the same.
fn admin_authorized(expected_token: Option<&str>, auth_header: Option<&str>) -> AdminAuth {
    let Some(expected) = expected_token.map(str::trim).filter(|s| !s.is_empty()) else {
        return AdminAuth::Unavailable;
    };
    if expected.len() < MIN_ADMIN_TOKEN_LEN {
        return AdminAuth::Unavailable;
    }
    let Some(header) = auth_header else {
        return AdminAuth::Rejected;
    };
    let Some(supplied) = header.strip_prefix("Bearer ") else {
        return AdminAuth::Rejected;
    };
    if supplied.is_empty() || !constant_time_eq(supplied.as_bytes(), expected.as_bytes()) {
        return AdminAuth::Rejected;
    }
    AdminAuth::Authorized
}

/// The shortest administrative credential that may be configured. Matches the
/// Python modules, which refuse a shorter one.
const MIN_ADMIN_TOKEN_LEN: usize = 16;

/// Write the refusal for an administrative request.
fn refuse_admin(stream: TcpStream, auth: AdminAuth) -> io::Result<()> {
    match auth {
        AdminAuth::Authorized => Ok(()),
        AdminAuth::Rejected => write_http_json_response(
            stream,
            401,
            "Unauthorized",
            &json!({ "error": "invalid administrative credential" }),
        ),
        AdminAuth::Unavailable => write_http_json_response(
            stream,
            503,
            "Service Unavailable",
            &json!({ "error": "administrative authentication is unavailable" }),
        ),
    }
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

/// Decode `%XX` escapes and `+` in a query-string value.
fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err("the query string is malformed".to_string());
                }
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .map_err(|_| "the query string is malformed".to_string())?;
                let byte = u8::from_str_radix(hex, 16)
                    .map_err(|_| "the query string is malformed".to_string())?;
                out.push(byte);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "the query string is malformed".to_string())
}

/// The `tenant` query parameter of an admin request.
///
/// `Ok(None)` means the request asked for no scope and `Ok(Some(id))` names
/// the tenant to scope to. `Err` means the parameter was there but could not
/// be read: a scope nobody can read is refused rather than ignored, because a
/// typo must never widen a replay to the whole spool.
fn query_tenant(raw_target: &str) -> Result<Option<String>, String> {
    let Some((_, query)) = raw_target.split_once('?') else {
        return Ok(None);
    };
    let mut found = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| "the query string is malformed".to_string())?;
        if name != "tenant" {
            continue;
        }
        let decoded = percent_decode(value)?;
        let trimmed = decoded.trim();
        if trimmed.is_empty()
            || trimmed.len() > 128
            || trimmed.chars().any(|character| character.is_control())
        {
            return Err("tenant must be 1-128 printable characters".to_string());
        }
        found = Some(trimmed.to_string());
    }
    Ok(found)
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
            let auth = admin_authorized(admin_token, auth_header.as_deref());
            if auth != AdminAuth::Authorized {
                return refuse_admin(stream, auth);
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
            let auth = admin_authorized(admin_token, auth_header.as_deref());
            if auth != AdminAuth::Authorized {
                return refuse_admin(stream, auth);
            }
            // A tenant that cannot be read is refused rather than ignored: an
            // unreadable scope must never fall back to the whole spool.
            let tenant = match query_tenant(raw_target) {
                Ok(tenant) => tenant,
                Err(reason) => {
                    return write_http_json_response(
                        stream,
                        422,
                        "Unprocessable Entity",
                        &json!({ "error": reason }),
                    )
                }
            };
            match outbox.replay_dead_letters(tenant.as_deref()) {
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

    /// A record whose payload carries the tenant it belongs to, the way a
    /// real event envelope does.
    fn record_for_tenant(id: &str, tenant: &str) -> SpoolRecord {
        let mut record = record(id);
        record.payload = format!(
            r#"{{"event_id":"{id}","tenant_id":"{tenant}"}}"#,
            id = id,
            tenant = tenant
        );
        record
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
    fn revocation_poll_url_is_derived_only_from_an_ingest_endpoint() {
        let ingest = reqwest::Url::parse("https://dashboard.example/api/ingest").unwrap();
        assert_eq!(
            revocation_poll_url(&ingest).unwrap().as_str(),
            "https://dashboard.example/api/sessions/revoked"
        );
        let nested = reqwest::Url::parse("https://dashboard.example/base/api/ingest/").unwrap();
        assert_eq!(
            revocation_poll_url(&nested).unwrap().as_str(),
            "https://dashboard.example/base/api/sessions/revoked"
        );
        let unrelated = reqwest::Url::parse("https://dashboard.example/api/events").unwrap();
        assert!(revocation_poll_url(&unrelated).is_none());
    }

    #[test]
    fn revocation_poll_interval_falls_back_to_the_default_when_it_cannot_be_read() {
        std::env::set_var("MONOLITH_SESSION_POLL_MS", "30000");
        assert_eq!(poll_interval_ms(), Some(30_000));
        std::env::set_var("MONOLITH_SESSION_POLL_MS", "0");
        assert_eq!(poll_interval_ms(), None, "zero is the explicit off switch");
        std::env::set_var("MONOLITH_SESSION_POLL_MS", "250");
        assert_eq!(
            poll_interval_ms(),
            Some(15_000),
            "a sub-second cadence falls back to the default instead of stopping the poll"
        );
        std::env::set_var("MONOLITH_SESSION_POLL_MS", "not-a-number");
        assert_eq!(poll_interval_ms(), Some(15_000));
        std::env::set_var("MONOLITH_SESSION_POLL_MS", "15000ms");
        assert_eq!(
            poll_interval_ms(),
            Some(15_000),
            "a value with a unit suffix is not a cadence"
        );
        std::env::set_var("MONOLITH_SESSION_POLL_MS", "-1");
        assert_eq!(poll_interval_ms(), Some(15_000));
        std::env::remove_var("MONOLITH_SESSION_POLL_MS");
        assert_eq!(poll_interval_ms(), Some(15_000), "default is 15s");
    }

    #[test]
    fn revoked_session_snapshot_replaces_wholesale_and_missing_snapshots_do_not_clear() {
        let _guard = MIRROR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let session = "cafebabe-0000-4000-8000-000000000002";
        let snapshot = json!({ "revoked_sessions": [session] }).to_string();
        assert_eq!(observe_revoked_sessions(&snapshot), Some(1));
        assert!(is_session_revoked(session));

        // An ingest response without the field must not read as "nothing is
        // revoked" — the previous snapshot stands.
        assert_eq!(observe_revoked_sessions(r#"{"accepted":1}"#), None);
        assert!(is_session_revoked(session));

        // Malformed values are dropped, not admitted.
        assert_eq!(
            observe_revoked_sessions(r#"{"revoked_sessions":["", 7, {"id":"x"}]}"#),
            Some(0)
        );
        assert!(!is_session_revoked(session));

        // A real empty snapshot is authoritative and lifts the revocation.
        assert_eq!(observe_revoked_sessions(&snapshot), Some(1));
        assert_eq!(
            observe_revoked_sessions(r#"{"revoked_sessions":[]}"#),
            Some(0)
        );
        assert!(!is_session_revoked(session));
        assert!(!is_session_revoked(""));
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

    /// Replaying into a full spool must not quietly destroy undelivered
    /// evidence.
    ///
    /// The bound drops the oldest records from the front, and the replayed
    /// dead letters go to the end, so a replay into a full spool deleted
    /// pending events that had never been delivered. The operator was told
    /// only that N records were replayed.
    #[test]
    fn replay_refuses_rather_than_discarding_pending_events() {
        let dir = temp_dir("replay-full-spool");
        let spool_path = dir.join("outbox.jsonl");
        let outbox = Outbox::for_path(&spool_path).unwrap();

        // Fill the pending spool to its record bound.
        let pending: Vec<SpoolRecord> = (0..MAX_SPOOL_RECORDS)
            .map(|index| record(&format!("pending-{index}")))
            .collect();
        write_records_atomically(outbox.spool_path(), &pending).unwrap();

        let mut dead = record("dead-1");
        dead.attempts = 10;
        append_dead_records_bounded(
            outbox.dead_letter_path(),
            &[dead],
            MAX_SPOOL_RECORDS,
            MAX_SPOOL_BYTES,
        )
        .unwrap();

        let error = outbox
            .replay_dead_letters(None)
            .expect_err("a full spool must refuse the replay");
        assert!(
            error.to_string().contains("at its bound"),
            "the refusal must explain itself: {error}"
        );

        // Nothing was destroyed: the pending events are all still there and
        // the dead letter is still dead-lettered.
        let after = read_records(outbox.spool_path()).unwrap();
        assert_eq!(after.len(), MAX_SPOOL_RECORDS);
        assert_eq!(
            read_records(outbox.dead_letter_path()).unwrap().len(),
            1,
            "the dead letter must not be lost either"
        );
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

        let replayed = outbox.replay_dead_letters(None).unwrap();
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
    fn a_tenant_scoped_replay_leaves_another_tenants_dead_letters_alone() {
        let dir = temp_dir("replay-tenant-scope");
        let outbox = Outbox::for_path(dir.join("outbox.jsonl")).unwrap();

        let mut mine = record_for_tenant("dead-acme", "acme");
        mine.attempts = 10;
        let mut theirs = record_for_tenant("dead-other", "other");
        theirs.attempts = 10;
        append_dead_records_bounded(
            outbox.dead_letter_path(),
            &[mine, theirs],
            MAX_SPOOL_RECORDS,
            MAX_SPOOL_BYTES,
        )
        .unwrap();

        // An operator for one tenant has no authority over another tenant's
        // evidence, and the count they are given is their own.
        let replayed = outbox.replay_dead_letters(Some("acme")).unwrap();
        assert_eq!(replayed, 1);

        let pending = read_records(outbox.spool_path()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, "dead-acme");

        // The other tenant's dead letter is still evidence, and it is still
        // dead: it was not replayed, and it was not discarded either.
        let dead = read_records(outbox.dead_letter_path()).unwrap();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].event_id, "dead-other");
    }

    #[test]
    fn a_tenant_scoped_replay_will_not_hand_over_a_record_it_cannot_attribute() {
        let dir = temp_dir("replay-unattributable");
        let outbox = Outbox::for_path(dir.join("outbox.jsonl")).unwrap();

        let mut orphan = record("dead-orphan");
        orphan.attempts = 10;
        append_dead_records_bounded(
            outbox.dead_letter_path(),
            &[orphan],
            MAX_SPOOL_RECORDS,
            MAX_SPOOL_BYTES,
        )
        .unwrap();

        // The payload says nothing about a tenant, so it cannot be given to
        // one. Leaving it dead is the only answer that cannot be wrong.
        let replayed = outbox.replay_dead_letters(Some("acme")).unwrap();
        assert_eq!(replayed, 0);
        assert_eq!(read_records(outbox.spool_path()).unwrap().len(), 0);
        assert_eq!(read_records(outbox.dead_letter_path()).unwrap().len(), 1);
    }

    #[test]
    fn the_status_listener_replays_only_the_tenant_it_was_asked_for() {
        let dir = temp_dir("status-http-tenant");
        let outbox = Arc::new(Outbox::for_path(dir.join("outbox.jsonl")).unwrap());
        let mut mine = record_for_tenant("dead-acme", "acme");
        mine.attempts = 10;
        let mut theirs = record_for_tenant("dead-other", "other");
        theirs.attempts = 10;
        append_dead_records_bounded(
            outbox.dead_letter_path(),
            &[mine, theirs],
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

        let replay_resp = send_raw(&format!(
            "POST /admin/replay-dead-letters?tenant=acme HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n"
        ));
        assert!(replay_resp.starts_with("HTTP/1.1 200 OK"));
        let replay_body: Value =
            serde_json::from_str(replay_resp.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(replay_body["replayed"], 1);
        assert_eq!(outbox.stats().outbox_pending, 1);
        assert_eq!(outbox.stats().outbox_dead_letter, 1);

        // A tenant that cannot be read is refused rather than ignored: an
        // unreadable scope must never fall back to the whole spool.
        let refused = send_raw(&format!(
            "POST /admin/replay-dead-letters?tenant= HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n"
        ));
        assert!(
            refused.starts_with("HTTP/1.1 422 Unprocessable Entity"),
            "an unreadable tenant must be refused: {refused}"
        );
        assert_eq!(outbox.stats().outbox_dead_letter, 1);
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

    /// The administrative endpoints must fail closed when no usable
    /// administrative credential is configured.
    ///
    /// They used to treat "no token configured" as "every request is
    /// authorized", so an empty `MONOLITH_ADMIN_TOKEN` — a common "unset by
    /// default" pattern — exposed the delivery statistics and the
    /// dead-letter replay to anyone who could reach the port.
    #[test]
    fn admin_endpoints_fail_closed_without_a_configured_credential() {
        let dir = temp_dir("status-http-noauth");
        let outbox = Arc::new(Outbox::for_path(dir.join("outbox.jsonl")).unwrap());

        for configured in [None, Some(String::new()), Some("   ".to_string())] {
            let addr =
                spawn_status_listener("127.0.0.1:0", Arc::clone(&outbox), configured).unwrap();

            let send_raw = |raw_req: &str| -> String {
                let mut stream = TcpStream::connect(addr).unwrap();
                stream.write_all(raw_req.as_bytes()).unwrap();
                stream.flush().unwrap();
                let mut resp = String::new();
                stream.read_to_string(&mut resp).unwrap();
                resp
            };

            let stats = send_raw("GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(
                stats.starts_with("HTTP/1.1 503 Service Unavailable"),
                "stats must not be served without a configured credential: {stats}"
            );
            assert!(!stats.contains("outbox_pending"));

            let replay =
                send_raw("POST /admin/replay-dead-letters HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(
                replay.starts_with("HTTP/1.1 503 Service Unavailable"),
                "replay must not be served without a configured credential: {replay}"
            );

            // The liveness check stays open: it reveals nothing.
            let health = send_raw("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(health.starts_with("HTTP/1.1 200 OK"));
        }
    }

    /// A configured but wrong credential is rejected, not treated as absent.
    #[test]
    fn admin_endpoints_reject_a_wrong_credential() {
        let dir = temp_dir("status-http-wrongauth");
        let outbox = Arc::new(Outbox::for_path(dir.join("outbox.jsonl")).unwrap());
        let token = "super-secret-admin-token-123456";
        let addr =
            spawn_status_listener("127.0.0.1:0", Arc::clone(&outbox), Some(token.to_string()))
                .unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(
                b"GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\n\r\n",
            )
            .unwrap();
        stream.flush().unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 401 Unauthorized"), "{resp}");
    }

    /// A one-shot HTTP server that answers every request with 200.
    ///
    /// The handle is dropped on purpose: the server runs until the test
    /// binary exits.
    fn spawn_ok_server() -> reqwest::Url {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let response =
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
        });
        reqwest::Url::parse(&format!("http://127.0.0.1:{port}/api/ingest")).unwrap()
    }

    /// An outbox opened by path alone has nowhere to deliver.
    ///
    /// It used to name a guessed endpoint — the dashboard's SSE address,
    /// which cannot accept an event and could not authenticate one — with an
    /// empty credential. A guessed address is worse than no address: every
    /// event posted to it is rejected, and a rejection reads like a
    /// rejected event rather than like an endpoint that was never set up.
    #[tokio::test]
    async fn a_path_only_outbox_has_nowhere_to_deliver() {
        let dir = temp_dir("no-delivery-target");
        let outbox = Outbox::for_path(dir.join("outbox.jsonl")).unwrap();

        assert!(
            outbox.target.is_none(),
            "an outbox opened by path alone must not name a delivery endpoint"
        );

        outbox
            .enqueue("event-1", r#"{"event_id":"event-1"}"#)
            .unwrap();
        outbox.drain(Duration::from_secs(5), true).await;

        // The event is still waiting, and no delivery was attempted: there
        // is no endpoint, so there is nothing to fail and nothing to
        // dead-letter.
        let records = read_records(outbox.spool_path()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].attempts, 0);
        assert!(
            records[0].last_error.is_none(),
            "no delivery was attempted, so there is no error to report: {:?}",
            records[0].last_error
        );
    }

    /// An outbox with an endpoint still delivers to it.
    #[tokio::test]
    async fn a_configured_outbox_still_delivers() {
        let dir = temp_dir("with-delivery-target");
        let mut outbox = Outbox::for_path(dir.join("outbox.jsonl")).unwrap();
        outbox.target = Some(spawn_ok_server());
        outbox.token = "test-token-value".to_string();

        outbox
            .enqueue("event-1", r#"{"event_id":"event-1"}"#)
            .unwrap();
        outbox.drain(Duration::from_secs(5), true).await;

        assert!(
            read_records(outbox.spool_path()).unwrap().is_empty(),
            "a delivered event leaves the spool"
        );
    }

    /// A local server that answers the given request targets with the given
    /// bodies, so the paging of the snapshot can be exercised without a
    /// network.
    fn spawn_snapshot_server(pages: Vec<(String, String)>) -> reqwest::Url {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let read = match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(_) => break,
                    };
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request).to_string();
                let target = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = pages
                    .iter()
                    .find(|(path, _)| *path == target)
                    .map(|(_, body)| body.clone())
                    .unwrap_or_else(|| r#"{"error":"no such page"}"#.to_string());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        reqwest::Url::parse(&format!("http://127.0.0.1:{port}/api/sessions/revoked")).unwrap()
    }

    /// A snapshot that does not fit in one response is paged, and every page
    /// has to be read before the set is adopted.
    ///
    /// The module reads a response body under a hard byte cap. A snapshot
    /// past that cap could not be parsed at all, so the module kept the set
    /// it already had — a set that was stale, and stale for good, because
    /// every later snapshot was too large as well. A revoked session then
    /// kept working.
    #[tokio::test]
    async fn a_paged_revocation_snapshot_is_read_to_the_end() {
        let pages = vec![
            (
                "/api/sessions/revoked".to_string(),
                json!({
                    "revoked_sessions": ["session-a"],
                    "revoked_sessions_complete": false,
                    "next_cursor": "cursor-1",
                })
                .to_string(),
            ),
            (
                "/api/sessions/revoked?cursor=cursor-1".to_string(),
                json!({
                    "revoked_sessions": ["session-b"],
                    "revoked_sessions_complete": false,
                    "next_cursor": "cursor-2",
                })
                .to_string(),
            ),
            (
                "/api/sessions/revoked?cursor=cursor-2".to_string(),
                json!({
                    "revoked_sessions": ["session-c"],
                    "revoked_sessions_complete": true,
                })
                .to_string(),
            ),
        ];
        let url = spawn_snapshot_server(pages);
        let client = reqwest::Client::new();

        let ids = read_revocation_snapshot(&client, &url, "token", "tenant")
            .await
            .expect("the whole snapshot must be readable");

        assert!(
            ids.contains(&"session-a".to_string()),
            "the first page must be read"
        );
        assert!(
            ids.contains(&"session-b".to_string()),
            "the second page must be read"
        );
        assert!(
            ids.contains(&"session-c".to_string()),
            "the last page must be read"
        );
    }

    /// A page that cannot be followed is not a snapshot.
    ///
    /// The set that was already known stands: a half-read snapshot would
    /// forget every revocation that is not on the pages read so far, and a
    /// forgotten revocation is a quarantined session that gets to keep
    /// working.
    #[tokio::test]
    async fn a_snapshot_that_cannot_be_read_to_the_end_yields_nothing() {
        let pages = vec![(
            "/api/sessions/revoked".to_string(),
            json!({
                "revoked_sessions": ["session-a"],
                "revoked_sessions_complete": false,
                "next_cursor": "cursor-1",
            })
            .to_string(),
        )];
        let url = spawn_snapshot_server(pages);
        let client = reqwest::Client::new();

        assert!(
            read_revocation_snapshot(&client, &url, "token", "tenant")
                .await
                .is_none(),
            "a snapshot whose pages cannot be read must not be returned"
        );
    }

    /// A page of a larger set is not the set.
    ///
    /// Installing it would forget every revocation that is not on the page,
    /// and a forgotten revocation is a quarantined session that gets to keep
    /// working. The set that was already known stands until the whole
    /// snapshot has been read.
    #[test]
    fn an_incomplete_revocation_snapshot_is_not_installed() {
        let _guard = MIRROR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let session = "cafebabe-0000-4000-8000-000000000003";
        apply_revocation_snapshot(vec![session.to_string()]);

        let page = json!({
            "revoked_sessions": ["someone-else"],
            "revoked_sessions_complete": false,
            "next_cursor": "cursor-1",
        })
        .to_string();
        assert_eq!(observe_revoked_sessions(&page), None);
        assert!(
            is_session_revoked(session),
            "the known set must stand until the whole snapshot has been read"
        );
    }

    /// A cursor is a position in the tenant's revocation list, and it goes
    /// into a URL, so only the alphabet it is supposed to use is accepted.
    #[test]
    fn a_revocation_page_cursor_must_be_base64url() {
        let base = reqwest::Url::parse("https://dashboard.example/api/sessions/revoked").unwrap();
        assert!(revocation_page_url(&base, "eyJhIjoxfQ").is_some());
        for bad in ["", "a b", "a/b", "a?b", "a#b", "a&b=c", "a%2fb"] {
            assert!(
                revocation_page_url(&base, bad).is_none(),
                "{bad} must not be turned into a page URL"
            );
        }
    }
}
