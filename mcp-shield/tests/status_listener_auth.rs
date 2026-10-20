//! The status listener's administrative credential is not the ingest
//! credential.
//!
//! `MONOLITH_EVENT_TOKEN` is transmitted on every event the module emits, so
//! it is the broadest-held secret in the process. While it doubled as the
//! administrative credential, anybody who could read the module's environment
//! could read the delivery statistics and re-queue every dead-lettered
//! event — on a listener the shipped compose file binds to `0.0.0.0`.
//!
//! These tests drive the real binary, because the defect was in the wiring
//! between two environment variables and a call site, not in the check
//! itself: `admin_authorized` always failed closed on a missing or short
//! credential.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;

/// A syntactically valid ingest token. A test fixture, not a secret.
const EVENT_TOKEN: &str = "test-event-token-0123456789abcdef";
/// A syntactically valid administrative token, distinct from the ingest one.
const ADMIN_TOKEN: &str = "test-admin-token-0123456789abcdefghi";

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

struct StatusListener {
    child: Child,
    port: u16,
    _directory: TempDir,
}

impl StatusListener {
    fn start(admin_token: Option<&str>) -> Self {
        let port = free_port();
        let directory = tempfile::tempdir().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-shield"));
        command
            .args(["--drain-outbox"])
            .env("MCP_SHIELD_STATUS_BIND", format!("127.0.0.1:{port}"))
            // Loopback HTTP is accepted for the dashboard, and nothing is
            // listening there: the spool is empty, so no delivery is ever
            // attempted and the test never touches the network.
            .env("MONOLITH_DASHBOARD_URL", "http://127.0.0.1:1/api/ingest")
            .env("MONOLITH_EVENT_TOKEN", EVENT_TOKEN)
            .env(
                "MONOLITH_EVENT_OUTBOX_PATH",
                directory.path().join("outbox.jsonl"),
            )
            .env_remove("MONOLITH_ADMIN_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(token) = admin_token {
            command.env("MONOLITH_ADMIN_TOKEN", token);
        }
        let child = command.spawn().unwrap();
        let mut listener = Self {
            child,
            port,
            _directory: directory,
        };
        listener.wait_until_listening();
        listener
    }

    fn wait_until_listening(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("the status listener exited before it bound its port: {status}");
            }
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the status listener never bound 127.0.0.1:{}", self.port);
    }

    fn request(&self, raw: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn status_of(&self, raw: &str) -> u16 {
        let response = self.request(raw);
        response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or_else(|| {
                panic!("the listener did not answer with a status line: {response:?}")
            })
    }
}

impl Drop for StatusListener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stats_request(token: &str) -> String {
    format!("GET /stats HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n")
}

fn replay_request(token: &str) -> String {
    format!(
        "POST /admin/replay-dead-letters HTTP/1.1\r\nHost: localhost\r\n\
         Authorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n"
    )
}

#[test]
fn the_ingest_token_does_not_authorize_the_status_listener() {
    let listener = StatusListener::start(None);

    // The ingest token is the credential the module transmits on every event.
    // It must not open the administrative endpoints.
    assert_eq!(listener.status_of(&stats_request(EVENT_TOKEN)), 503);
    assert_eq!(listener.status_of(&replay_request(EVENT_TOKEN)), 503);
}

#[test]
fn the_administrative_token_still_authorizes_the_status_listener() {
    let listener = StatusListener::start(Some(ADMIN_TOKEN));

    assert_eq!(listener.status_of(&stats_request(ADMIN_TOKEN)), 200);
    // The ingest token is still not an administrative credential.
    assert_eq!(listener.status_of(&stats_request(EVENT_TOKEN)), 401);
}

#[test]
fn the_health_endpoint_stays_unauthenticated() {
    let listener = StatusListener::start(None);

    let response = listener.request("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the health endpoint must stay open: {response:?}"
    );
}
