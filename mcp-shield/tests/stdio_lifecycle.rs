use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn assert_rejected(payload: &[u8], server: &str) {
    let directory = tempfile::tempdir().unwrap();
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python".into());
    let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-shield"))
        .args([&python, "-c", server])
        .env(
            "MCP_SHIELD_BASELINE",
            directory.path().join("baseline.json"),
        )
        .env_remove("MONOLITH_DASHBOARD_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let data = payload.to_vec();
    let writer = thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let deadline = Instant::now() + Duration::from_secs(13);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            writer.join().unwrap();
            assert!(!status.success());
            return;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("proxy failed to terminate a stalled server");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn oversized_agent_message_without_newline_is_rejected() {
    assert_rejected(&vec![b'x'; 1024 * 1024 + 1], "import time; time.sleep(60)");
}

#[test]
fn invalid_utf8_is_rejected() {
    assert_rejected(&[0xff, b'\n'], "import time; time.sleep(60)");
}

#[test]
fn oversized_server_message_is_rejected() {
    assert_rejected(
        b"",
        "import sys,time; sys.stdout.write('x'*1048577); sys.stdout.flush(); time.sleep(60)",
    );
}

#[test]
fn server_that_ignores_eof_is_terminated() {
    assert_rejected(b"", "import time; time.sleep(60)");
}

#[test]
fn server_that_closes_stdout_but_keeps_running_is_terminated() {
    assert_rejected(b"", "import os,time; os.close(1); time.sleep(60)");
}

#[test]
fn malformed_agent_json_is_not_forwarded() {
    assert_rejected(b"not json\n", "import time; time.sleep(60)");
}

#[test]
fn malformed_server_json_is_not_forwarded() {
    assert_rejected(
        b"",
        "import sys,time; print('not json',flush=True); time.sleep(60)",
    );
}

#[test]
fn server_failure_is_not_reported_as_success() {
    assert_rejected(b"", "raise SystemExit(7)");
}
