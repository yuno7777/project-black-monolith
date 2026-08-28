//! MCP-Shield — Project Black Monolith tool-layer defense.
//!
//! WHAT THIS FILE IS
//! -----------------
//! The entry point / CLI dispatcher of the Rust module. It decides what mode
//! the binary is being asked to run in, wires up logging, and — in the main
//! "proxy" mode — guarantees that every event spooled during the session gets
//! a last chance to reach the dashboard before the process exits.
//!
//! THE SIMPLE VERSION
//! ------------------
//! `mcp-shield` is a transparent security proxy for the Model Context
//! Protocol (MCP). An agent that wants to use tools talks to `mcp-shield`
//! instead of talking to the tool server directly. The proxy sits in between,
//! forwards every message both ways UNTOUCHED, and inspects one specific
//! message type — the `tools/list` response, where a server advertises its
//! tool schemas. It fingerprints each schema (HMAC-SHA256 over a canonical
//! serialization) and flags a "rug pull" when a schema mutates after its
//! baseline was established, or "tool poisoning" when a description contains
//! hidden-instruction patterns.
//!
//! THE FIVE MODES (what `main` dispatches):
//!   1. `mcp-shield <server-command> [args...]`   — the MAIN mode: proxy a
//!      local MCP server over stdio.
//!   2. `mcp-shield --remote-url <url>`           — proxy a REMOTE MCP server
//!      over HTTP. Internally re-invokes itself with the hidden
//!      `__streamable-http-bridge` argument so the HTTP adapter appears as a
//!      child process with a stdio interface — the exact same inspection code
//!      then runs against it.
//!   3. `mcp-shield --list-pending`               — operator: list tools
//!      awaiting approval (first-contact approve mode).
//!   4. `mcp-shield --approve <tool>`             — operator: approve a
//!      pending tool, making it the trusted baseline.
//!   5. `mcp-shield --drain-outbox`               — resident mode: sit and
//!      deliver any spooled events (docker-compose runs this so delivery does
//!      not depend on any one short-lived proxy session).
//!
//! THE CRITICAL RULE
//! -----------------
//! All logs and security events go to STDERR; STDOUT is reserved exclusively
//! for the proxied MCP protocol stream. A stray print to stdout would corrupt
//! the JSON-RPC conversation and break the agent.
//!
//! Module layout (each `mod` is a file in this directory):
//!   proxy.rs         the bidirectional proxy + tools/list interception
//!   fingerprint.rs   canonical serialization -> HMAC-SHA256 + baseline store
//!   sanitizer.rs     3 detector families for tool descriptions
//!   jsonrpc.rs       minimal JSON-RPC 2.0 message model
//!   http_transport.rs Streamable HTTP adapter (--remote-url bridge)
//!   events.rs        security-event emission (envelope shape)
//!   outbox.rs        durable JSONL spool + delivery (the Rust "outbox")

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
/// invocation (or by the resident `--drain-outbox` worker).
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

    // Everything after the binary name is the "server command" (or a flag).
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
    // This branch is reached when the binary re-invokes itself (see
    // --remote-url below); it just bridges stdio <-> HTTP and returns.
    if server_cmd.first().map(String::as_str) == Some("__streamable-http-bridge") {
        if server_cmd.len() != 2 {
            bail!("internal Streamable HTTP bridge expects exactly one URL");
        }
        return http_transport::run(&server_cmd[1]).await;
    }

    // Rewrite `--remote-url <url>` into a self-invocation:
    //   mcp-shield <current-exe> __streamable-http-bridge <url>
    // The child process (this same binary in bridge mode) does the HTTP
    // translation; the parent runs the normal proxy over stdio, so the remote
    // server gets the exact same fingerprinting path as a local one.
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
    // while an agent is not connected. See fingerprint.rs (FirstContact) and
    // proxy.rs (the approve gate in analyze_tools_list) for the semantics.
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

    // Resident delivery worker: sits on the shared spool volume and delivers
    // whatever the short-lived proxy sessions leave behind. This is how
    // docker-compose runs mcp-shield so retry progress is independent of any
    // single agent session (spawn_flusher loops forever).
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

    // ---- MAIN MODE: run the proxy ---------------------------------------
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

    // The proxy runs until the agent closes stdin (or the server exits).
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
