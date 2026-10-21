//! The environment the wrapped MCP server inherits.
//!
//! The shield is a proxy in front of a *third-party* MCP server, and the
//! child process inherits the shield's environment unless the shield takes
//! the credentials away. The shield holds two capabilities that the child
//! must not have:
//!
//! * `MCP_SHIELD_KEY` — the HMAC key the schema fingerprints are signed
//!   with. A child that holds it can re-sign a poisoned baseline, and the
//!   next agent to connect will trust the poisoned schema.
//! * `MONOLITH_EVENT_TOKEN` — the bearer credential that writes into the
//!   incident ledger. A child that holds it can forge the evidence an
//!   operator reads.
//!
//! The child's stdout is the JSON-RPC stream, so the environment is dumped
//! to a file rather than printed.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A fake MCP server that writes its inherited environment to the file named
/// by its first argument, then waits for stdin to close.
const DUMP_ENVIRONMENT: &str = r#"
import json
import os
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(dict(os.environ), handle)

sys.stdin.read()
"#;

/// Run the shield over a fake server and return the environment the server
/// inherited.
fn environment_the_server_inherits(
    extra: &[(&str, &str)],
) -> (HashMap<String, String>, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let dump_path = directory.path().join("child-environment.json");
    let python = std::env::var("PYTHON").unwrap_or_else(|_| "python".into());

    let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-shield"));
    command
        .args([
            &python,
            "-c",
            DUMP_ENVIRONMENT,
            &dump_path.to_string_lossy(),
        ])
        .env(
            "MCP_SHIELD_BASELINE",
            directory.path().join("baseline.json"),
        )
        // The credentials the shield holds on the agent's behalf.
        .env("MCP_SHIELD_KEY", "shield-hmac-key-the-child-must-not-see")
        .env(
            "MONOLITH_EVENT_TOKEN",
            "ledger-token-the-child-must-not-see",
        )
        .env(
            "MONOLITH_EVENT_TOKEN_MCP_SHIELD",
            "module-token-the-child-must-not-see",
        )
        .env("MONOLITH_ADMIN_TOKEN", "admin-token-the-child-must-not-see")
        .env("PBM_SECRET_TEST", "secret-the-child-must-not-see")
        // The ledger's address. Port 9 is the discard port, so a delivery
        // attempt fails instantly instead of reaching the network.
        .env("MONOLITH_DASHBOARD_URL", "http://127.0.0.1:9/api/ingest")
        .env(
            "MONOLITH_EVENT_OUTBOX_PATH",
            directory.path().join("outbox.jsonl"),
        )
        // The correlation identity, which the server legitimately needs:
        // VectorAnchor's own MCP server is started through the shield and
        // stamps it onto every request.
        .env("MONOLITH_SESSION_ID", "session-the-child-must-see")
        .env("MONOLITH_AGENT_ID", "agent-the-child-must-see")
        .env("MONOLITH_TENANT_ID", "tenant-the-child-must-see")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (name, value) in extra {
        command.env(name, value);
    }

    let mut child = command.spawn().expect("spawn the shield");
    // The shield is killed rather than waited on: the fake server holds
    // stdin open until the agent closes it, and this test is about the
    // environment, not about the shutdown path.
    let deadline = Instant::now() + Duration::from_secs(30);
    let environment = loop {
        if dump_path.exists() {
            let raw = std::fs::read_to_string(&dump_path).expect("read the environment dump");
            break serde_json::from_str::<HashMap<String, String>>(&raw).expect("parse the dump");
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("the shield exited before the server started: {status}");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the wrapped server never wrote its environment");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let _ = child.kill();
    let _ = child.wait();

    (environment, directory)
}

#[test]
fn the_wrapped_server_does_not_inherit_the_shield_credentials() {
    let (environment, _directory) = environment_the_server_inherits(&[]);

    for name in [
        "MCP_SHIELD_KEY",
        "MONOLITH_EVENT_TOKEN",
        "MONOLITH_EVENT_TOKEN_MCP_SHIELD",
        "MONOLITH_ADMIN_TOKEN",
        "PBM_SECRET_TEST",
        "MONOLITH_DASHBOARD_URL",
        "MONOLITH_EVENT_OUTBOX_PATH",
    ] {
        assert!(
            !environment.contains_key(name),
            "{name} reached the wrapped MCP server: the shield must take it away"
        );
    }
}

#[test]
fn the_wrapped_server_still_gets_the_correlation_identity_and_its_own_path() {
    let (environment, _directory) = environment_the_server_inherits(&[]);

    assert_eq!(
        environment.get("MONOLITH_SESSION_ID").map(String::as_str),
        Some("session-the-child-must-see"),
        "the correlation identity must survive: VectorAnchor's MCP server stamps it on every request"
    );
    assert_eq!(
        environment.get("MONOLITH_AGENT_ID").map(String::as_str),
        Some("agent-the-child-must-see")
    );
    assert_eq!(
        environment.get("MONOLITH_TENANT_ID").map(String::as_str),
        Some("tenant-the-child-must-see")
    );
    assert!(
        environment.contains_key("PATH"),
        "the child needs the environment it normally inherits"
    );
}

#[test]
fn the_remote_bridge_configuration_survives() {
    // The `--remote-url` bridge is the shield's own child process, and it is
    // configured entirely through these three variables. A child that is not
    // the bridge does not need them, and holding the token would let it
    // impersonate the shield to the operator's remote MCP server; that
    // residual is recorded in docs/FINDINGS.md rather than fixed here.
    let (environment, _directory) = environment_the_server_inherits(&[(
        "MCP_SHIELD_REMOTE_TOKEN",
        "remote-token-the-child-must-not-see",
    )]);

    assert_eq!(
        environment
            .get("MCP_SHIELD_REMOTE_TOKEN")
            .map(String::as_str),
        Some("remote-token-the-child-must-not-see"),
        "the remote bridge configuration must survive, or --remote-url cannot start"
    );
}
