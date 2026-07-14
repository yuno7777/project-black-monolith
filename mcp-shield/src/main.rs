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
mod proxy;
mod sanitizer;

use anyhow::{bail, Result};
use std::io::IsTerminal;
use tracing_subscriber::EnvFilter;

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

    let result = proxy::run(server_cmd, config).await;

    // This proxy is short-lived (it exits when the agent closes stdin).
    // Dashboard event forwarding is fire-and-forget on background tasks, so
    // give any in-flight POSTs a brief grace period to land before exit.
    if std::env::var("MONOLITH_DASHBOARD_URL").is_ok() {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }

    result
}
