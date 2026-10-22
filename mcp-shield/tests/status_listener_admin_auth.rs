//! The status listener authenticates with the administrative credential only.
//!
//! `MCP_SHIELD_STATUS_BIND` decides where the listener listens, and the
//! shipped `docker-compose.yml` binds it to `0.0.0.0:8003`. The listener
//! serves `GET /stats` and `POST /admin/replay-dead-letters`, so the
//! credential that opens it is an administrative one. `MONOLITH_EVENT_TOKEN`
//! is the module's *ingest* credential — the bearer token every event is
//! POSTed with — and the listener used to fall back to it, which made the
//! broadest-held secret in the module's environment a key to the
//! administrative surface of a port bound to every interface.
//!
//! These tests drive the real binary over a real socket, because the defect
//! was in the wiring that chooses the credential, not in the check that
//! applies it: a unit test of the check alone would still pass with the
//! fallback in place.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A bearer credential assembled at run time, so no secret literal is
/// committed to the repository. The shape is header-safe and long enough to
/// clear the module's own minimum length, like the real thing.
fn credential(purpose: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or_default();
    format!("{purpose}-{}-{nanos}", std::process::id())
}

/// A port nothing is listening on, so the flusher's delivery attempt fails
/// immediately instead of hanging on a socket that accepts and never answers.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().expect("read the port").port()
}

/// A port the listener can take. The window between releasing it and the
/// child binding it is small, and the child is retried until it answers.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().expect("read the port").port()
}

/// Write one dead-lettered record into the spool's sibling `.dead` file.
fn write_dead_letter(spool: &Path, event_id: &str) {
    let record = serde_json::json!({
        "event_id": event_id,
        "payload": serde_json::json!({ "event_id": event_id }).to_string(),
        "attempts": 10,
        "next_attempt_ms": 0,
        "created_ms": 0,
    });
    let mut line = record.to_string();
    line.push('\n');
    fs::write(spool.with_extension("dead"), line).expect("write the dead letter");
}

/// How many dead-lettered records the spool is holding.
fn dead_letter_count(spool: &Path) -> usize {
    match fs::read_to_string(spool.with_extension("dead")) {
        Ok(contents) => contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count(),
        Err(_) => 0,
    }
}

/// `mcp-shield --drain-outbox` with its status listener bound to loopback.
struct StatusListener {
    child: Child,
    port: u16,
}

impl StatusListener {
    /// Start the module with the given credentials. `admin_token` is
    /// `None` for a deployment that configures no administrative credential
    /// at all; the ingest credential is always configured, because the
    /// module cannot deliver events without it.
    fn start(admin_token: Option<&str>, ingest_token: &str, spool: &Path) -> Self {
        let port = free_port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-shield"));
        command
            .arg("--drain-outbox")
            .env("MCP_SHIELD_STATUS_BIND", format!("127.0.0.1:{port}"))
            .env(
                "MONOLITH_DASHBOARD_URL",
                format!("http://127.0.0.1:{}/api/ingest", closed_port()),
            )
            .env("MONOLITH_EVENT_TOKEN", ingest_token)
            .env("MONOLITH_EVENT_OUTBOX_PATH", spool)
            // The ambient environment must not decide the test: the
            // administrative credential is set explicitly, or removed.
            .env_remove("MONOLITH_ADMIN_TOKEN")
            .env_remove("MONOLITH_SESSION_POLL_MS")
            .env_remove("MONOLITH_TENANT_ID")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(admin) = admin_token {
            command.env("MONOLITH_ADMIN_TOKEN", admin);
        }
        let child = command.spawn().expect("the status listener must start");
        let listener = Self { child, port };
        listener.wait_until_up();
        listener
    }

    /// The listener binds after the process starts, so the first connection
    /// can lose the race against it.
    fn wait_until_up(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "the status listener never came up on 127.0.0.1:{}",
            self.port
        );
    }

    /// Send a raw HTTP request and read the whole response.
    fn request(&self, raw: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream.write_all(raw.as_bytes()).expect("write the request");
        stream.flush().expect("flush the request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read the response");
        response
    }

    /// `GET /stats` with the given bearer credential.
    fn stats(&self, bearer: &str) -> String {
        self.request(&format!(
            "GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {bearer}\r\n\r\n"
        ))
    }

    /// `POST /admin/replay-dead-letters` with the given bearer credential.
    fn replay_dead_letters(&self, bearer: &str) -> String {
        self.request(&format!(
            "POST /admin/replay-dead-letters HTTP/1.1\r\nHost: localhost\r\n\
             Authorization: Bearer {bearer}\r\n\r\n"
        ))
    }
}

impl Drop for StatusListener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A deployment that configures only the ingest credential must not get an
/// administrative surface out of it.
#[test]
fn the_ingest_credential_does_not_open_the_administrative_endpoints() {
    let directory = tempfile::tempdir().unwrap();
    let spool = directory.path().join("outbox.jsonl");
    let ingest = credential("ingest");
    write_dead_letter(&spool, "dead-1");

    let listener = StatusListener::start(None, &ingest, &spool);

    // The ingest credential is the only one configured, and it is the one
    // every event is POSTed with. It must not authenticate an administrative
    // request: there is no administrative credential to match it against.
    let stats = listener.stats(&ingest);
    assert!(
        stats.starts_with("HTTP/1.1 503 Service Unavailable"),
        "the ingest credential must not open /stats: {stats}"
    );
    assert!(
        !stats.contains("outbox_pending"),
        "the delivery statistics must not be served: {stats}"
    );

    let replay = listener.replay_dead_letters(&ingest);
    assert!(
        replay.starts_with("HTTP/1.1 503 Service Unavailable"),
        "the ingest credential must not open the dead-letter replay: {replay}"
    );
    assert_eq!(
        dead_letter_count(&spool),
        1,
        "a refused replay must leave the dead letter where it was"
    );

    // The liveness check reveals nothing and stays open.
    let health = listener.request("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        health.starts_with("HTTP/1.1 200 OK"),
        "the liveness check must keep working: {health}"
    );
}

/// With an administrative credential configured, that credential is the only
/// one that opens the administrative endpoints — the ingest credential is
/// refused even though the module holds it.
#[test]
fn only_the_administrative_credential_opens_the_administrative_endpoints() {
    let directory = tempfile::tempdir().unwrap();
    let spool = directory.path().join("outbox.jsonl");
    let ingest = credential("ingest");
    let admin = credential("admin");
    write_dead_letter(&spool, "dead-1");

    let listener = StatusListener::start(Some(&admin), &ingest, &spool);

    // The ingest credential is a real credential of this module, and it is
    // still not an administrative one.
    let stats_with_ingest = listener.stats(&ingest);
    assert!(
        stats_with_ingest.starts_with("HTTP/1.1 401 Unauthorized"),
        "the ingest credential must be refused as an administrative one: {stats_with_ingest}"
    );
    assert!(
        !stats_with_ingest.contains("outbox_pending"),
        "the delivery statistics must not be served: {stats_with_ingest}"
    );

    let replay_with_ingest = listener.replay_dead_letters(&ingest);
    assert!(
        replay_with_ingest.starts_with("HTTP/1.1 401 Unauthorized"),
        "the ingest credential must be refused as an administrative one: {replay_with_ingest}"
    );
    assert_eq!(
        dead_letter_count(&spool),
        1,
        "a refused replay must leave the dead letter where it was"
    );

    // The administrative credential opens them.
    let stats = listener.stats(&admin);
    assert!(
        stats.starts_with("HTTP/1.1 200 OK"),
        "the administrative credential must open /stats: {stats}"
    );
    assert!(
        stats.contains("outbox_pending"),
        "the delivery statistics must be served to an administrator: {stats}"
    );

    let replay = listener.replay_dead_letters(&admin);
    assert!(
        replay.starts_with("HTTP/1.1 200 OK"),
        "the administrative credential must open the dead-letter replay: {replay}"
    );
    assert_eq!(
        dead_letter_count(&spool),
        0,
        "the replayed dead letter must have left the dead file"
    );
}
