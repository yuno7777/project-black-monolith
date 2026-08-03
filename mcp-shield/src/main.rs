//! MCP-Shield — Project Black Monolith tool-layer defense.
//!
//! A transparent security proxy for the Model Context Protocol (stdio
//! transport). Sits between an agent and a real MCP server, forwards all
//! JSON-RPC traffic untouched, fingerprints every tool schema seen in
//! `tools/list` responses (HMAC-SHA256 over a canonical serialization), and
//! raises structured security events when a schema mutates after baseline
//! ("rug pull") or when a tool description contains hidden-instruction
//! injection patterns ("tool poisoning").
//!
//! Usage:
//!   mcp-shield <server-command> [server-args...]
//!   mcp-shield --remote-url <https://server.example/mcp>
//!   mcp-shield --drain-outbox
//!   mcp-shield --list-pending
//!   mcp-shield --approve <tool-name>
//!
//! Example:
//!   mcp-shield python fixtures/fake_mcp_server.py
//!
//! All logs and security events go to STDERR; STDOUT is reserved exclusively
//! for the proxied MCP protocol stream.

mod events;
mod fingerprint;
mod http_transport;
mod jsonrpc;
mod outbox;
mod proxy;
mod sanitizer;

use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// Last-chance delivery window for spooled events before the process exits.
/// Anything still undelivered stays on the spool and is retried by the next
/// invocation.
const FINAL_DRAIN_BUDGET: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() -> Result<()> {
    // Logs MUST go to stderr: stdout carries the proxied JSON-RPC stream and
    // any stray log line there would corrupt the protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let mut server_cmd: Vec<String> = std::env::args().skip(1).collect();
    if server_cmd.is_empty() {
        bail!(
            "usage: mcp-shield <server-command> [server-args...]\n\
             or: mcp-shield --remote-url <https://server.example/mcp>\n\
             or: mcp-shield --list-pending | --approve <tool-name>\n\
             example: mcp-shield python fixtures/fake_mcp_server.py"
        );
    }

    // Internal child mode used by `--remote-url`. It deliberately runs before
    // the outbox flusher: the outer proxy owns inspection and event delivery.
    if server_cmd.first().map(String::as_str) == Some("__streamable-http-bridge") {
        if server_cmd.len() != 2 {
            bail!("internal Streamable HTTP bridge expects exactly one URL");
        }
        return http_transport::run(&server_cmd[1]).await;
    }

    if server_cmd.first().map(String::as_str) == Some("--remote-url") {
        if server_cmd.len() != 2 {
            bail!("--remote-url expects exactly one http or https URL");
        }
        let executable = std::env::current_exe().context("locate mcp-shield executable")?;
        server_cmd = vec![
            executable.to_string_lossy().into_owned(),
            "__streamable-http-bridge".to_owned(),
            server_cmd[1].clone(),
        ];
    }

    // Operator commands for the first-contact approval gate. Both act on the
    // baseline file and exit without starting a proxy, so they can be run
    // while an agent is not connected.
    if server_cmd.first().map(String::as_str) == Some("--list-pending") {
        let config = proxy::ShieldConfig::from_env();
        let store = fingerprint::BaselineStore::load(&config.baseline_path, &config.hmac_key)?;
        let pending = store.pending_names();
        if pending.is_empty() {
            eprintln!("no tools are awaiting approval");
        } else {
            eprintln!("tools awaiting approval ({}):", pending.len());
            for name in pending {
                eprintln!("  {name}");
            }
        }
        return Ok(());
    }

    if server_cmd.first().map(String::as_str) == Some("--approve") {
        if server_cmd.len() != 2 {
            bail!("--approve expects exactly one tool name");
        }
        let tool = &server_cmd[1];
        let config = proxy::ShieldConfig::from_env();
        let mut store = fingerprint::BaselineStore::load(&config.baseline_path, &config.hmac_key)?;
        if !store.approve(tool) {
            // Not an error to be swallowed: approving a name that is not
            // pending means the operator approved something other than what
            // they think they did.
            bail!(
                "no tool named {tool:?} is awaiting approval; \
                 run --list-pending to see what is"
            );
        }
        store.save()?;
        eprintln!("approved {tool:?}; it is now the trusted baseline");
        return Ok(());
    }

    if server_cmd == ["--drain-outbox"] {
        tracing::info!(
            module = events::MODULE,
            "starting resident event outbox drainer"
        );
        let flusher = outbox::spawn_flusher().ok_or_else(|| {
            anyhow::anyhow!(
                "outbox delivery is not configured; set MONOLITH_DASHBOARD_URL, \
                 MONOLITH_EVENT_TOKEN, and MONOLITH_EVENT_OUTBOX_PATH"
            )
        })?;
        flusher.await?;
        return Ok(());
    }

    let config = proxy::ShieldConfig::from_env();
    tracing::info!(
        module = events::MODULE,
        server_command = ?server_cmd,
        baseline = %config.baseline_path.display(),
        mode = ?config.mode,
        first_contact = ?config.first_contact,
        "starting MCP-Shield proxy"
    );

    // Drains any backlog left by a previous run (the spool outlives the
    // process on a volume), then keeps this run's events flowing to the
    // dashboard live as they are detected.
    let flusher = outbox::spawn_flusher();

    let result = proxy::run(server_cmd, config).await;

    // This proxy is short-lived: it exits as soon as the agent closes stdin,
    // so there is no long-running retry loop to fall back on. Stop the
    // periodic flusher and make one final forced pass — ignoring backoff,
    // since a scheduled retry after exit would never happen.
    if let Some(flusher) = flusher {
        flusher.abort();
    }
    outbox::drain(FINAL_DRAIN_BUDGET, true).await;

    result
}
