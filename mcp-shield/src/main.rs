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
//!
//! Example:
//!   mcp-shield python fixtures/fake_mcp_server.py
//!
//! All logs and security events go to STDERR; STDOUT is reserved exclusively
//! for the proxied MCP protocol stream.

mod events;
mod fingerprint;
mod jsonrpc;
mod outbox;
mod proxy;
mod sanitizer;

use anyhow::{bail, Result};
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

    let server_cmd: Vec<String> = std::env::args().skip(1).collect();
    if server_cmd.is_empty() {
        bail!(
            "usage: mcp-shield <server-command> [server-args...]\n\
             example: mcp-shield python fixtures/fake_mcp_server.py"
        );
    }

    let config = proxy::ShieldConfig::from_env();
    tracing::info!(
        module = events::MODULE,
        server_command = ?server_cmd,
        baseline = %config.baseline_path.display(),
        mode = ?config.mode,
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
