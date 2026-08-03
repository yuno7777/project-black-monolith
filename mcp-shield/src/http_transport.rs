//! Streamable HTTP transport adapter.
//!
//! The public `--remote-url` option launches this adapter as the child process
//! behind the normal stdio proxy. That keeps every remote JSON-RPC message on
//! the same fingerprinting, poisoning-detection, and enforcement path as a
//! local MCP server.

use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinSet;

const SESSION_HEADER: &str = "mcp-session-id";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";
const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 300;

#[derive(Clone)]
struct Bridge {
    client: reqwest::Client,
    target: reqwest::Url,
    session: Arc<RwLock<Option<HeaderValue>>>,
    stdout: Arc<Mutex<tokio::io::Stdout>>,
    protocol: HeaderValue,
    authorization: Option<HeaderValue>,
}

/// Adapt newline-delimited stdio JSON-RPC to the MCP Streamable HTTP POST
/// transport. Requests are concurrent so a server can issue a reverse
/// JSON-RPC request while another POST's SSE stream remains open.
pub(crate) async fn run(remote_url: &str) -> Result<()> {
    let target = parse_target(remote_url)?;
    let timeout_secs = std::env::var("MCP_SHIELD_REMOTE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("build Streamable HTTP client")?;

    let protocol = header_from_env(
        "MCP_SHIELD_PROTOCOL_VERSION",
        DEFAULT_PROTOCOL_VERSION,
        "MCP protocol version",
    )?;
    let authorization = std::env::var("MCP_SHIELD_REMOTE_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty())
        .map(|token| {
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                .context("MCP_SHIELD_REMOTE_TOKEN contains invalid header characters")?;
            value.set_sensitive(true);
            Ok::<_, anyhow::Error>(value)
        })
        .transpose()?;

    let bridge = Bridge {
        client,
        target,
        session: Arc::new(RwLock::new(None)),
        stdout: Arc::new(Mutex::new(tokio::io::stdout())),
        protocol,
        authorization,
    };

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line.context("read JSON-RPC message from stdin")? {
                    Some(line) if line.trim().is_empty() => continue,
                    Some(line) => {
                        let message: Value = serde_json::from_str(&line)
                            .context("stdin contained invalid JSON-RPC JSON")?;
                        validate_jsonrpc(&message)?;
                        let request_id = message.get("id").cloned();
                        let bridge = bridge.clone();
                        requests.spawn(async move { bridge.post(message, request_id).await });
                    }
                    None => break,
                }
            }
            completed = requests.join_next(), if !requests.is_empty() => {
                completed
                    .expect("join set was checked as non-empty")
                    .context("Streamable HTTP request task panicked")??;
            }
        }
    }

    while let Some(completed) = requests.join_next().await {
        completed.context("Streamable HTTP request task panicked")??;
    }
    bridge.close_session().await;
    Ok(())
}

impl Bridge {
    async fn post(&self, message: Value, request_id: Option<Value>) -> Result<()> {
        let mut request = self
            .client
            .post(self.target.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .header(PROTOCOL_HEADER, self.protocol.clone())
            .body(serde_json::to_vec(&message)?);
        if let Some(session) = self.session.read().await.clone() {
            request = request.header(SESSION_HEADER, session);
        }
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }

        let mut response = request.send().await.context("POST MCP message")?;
        self.remember_session(response.headers().get(SESSION_HEADER))
            .await?;

        if response.status() == reqwest::StatusCode::ACCEPTED {
            if request_id.is_some() {
                bail!("remote returned 202 Accepted for a JSON-RPC request");
            }
            return Ok(());
        }
        if !response.status().is_success() {
            let status = response.status();
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let body = response.text().await.unwrap_or_default();
            bail!(
                "remote MCP server returned {status}{}: {}",
                if challenge.is_empty() {
                    String::new()
                } else {
                    format!(" ({challenge})")
                },
                truncate(&body, 512)
            );
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match content_type.as_str() {
            "application/json" => {
                let body = response.text().await.context("read JSON response")?;
                let value: Value =
                    serde_json::from_str(&body).context("remote returned invalid JSON-RPC JSON")?;
                validate_jsonrpc(&value)?;
                self.emit(&value).await?;
            }
            "text/event-stream" => {
                self.consume_sse(&mut response, request_id.as_ref()).await?;
            }
            other => bail!("unsupported MCP response content type: {other:?}"),
        }
        Ok(())
    }

    async fn consume_sse(
        &self,
        response: &mut reqwest::Response,
        request_id: Option<&Value>,
    ) -> Result<()> {
        let mut pending = String::new();
        while let Some(chunk) = response.chunk().await.context("read MCP SSE response")? {
            pending.push_str(
                std::str::from_utf8(&chunk).context("MCP SSE response was not valid UTF-8")?,
            );
            while let Some((raw_event, consumed)) = next_sse_event(&pending) {
                let event = pending[..raw_event].to_owned();
                pending.drain(..consumed);
                if let Some(data) = parse_sse_data(&event) {
                    let value: Value = serde_json::from_str(&data)
                        .context("MCP SSE data contained invalid JSON")?;
                    validate_jsonrpc(&value)?;
                    let terminal = request_id.is_some_and(|expected| {
                        value.get("id") == Some(expected)
                            && (value.get("result").is_some() || value.get("error").is_some())
                    });
                    self.emit(&value).await?;
                    if terminal {
                        return Ok(());
                    }
                }
            }
        }
        if request_id.is_some() {
            bail!("MCP SSE stream ended before the matching JSON-RPC response");
        }
        Ok(())
    }

    async fn emit(&self, message: &Value) -> Result<()> {
        let mut output = serde_json::to_vec(message)?;
        output.push(b'\n');
        let mut stdout = self.stdout.lock().await;
        stdout.write_all(&output).await?;
        stdout.flush().await?;
        Ok(())
    }

    async fn remember_session(&self, incoming: Option<&HeaderValue>) -> Result<()> {
        let Some(incoming) = incoming else {
            return Ok(());
        };
        let mut session = self.session.write().await;
        match session.as_ref() {
            Some(existing) if existing != incoming => {
                bail!("remote MCP server changed the active session identifier")
            }
            Some(_) => {}
            None => *session = Some(incoming.clone()),
        }
        Ok(())
    }

    async fn close_session(&self) {
        let Some(session) = self.session.read().await.clone() else {
            return;
        };
        let mut request = self
            .client
            .delete(self.target.clone())
            .header(PROTOCOL_HEADER, self.protocol.clone())
            .header(SESSION_HEADER, session);
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        match request.send().await {
            Ok(response)
                if response.status().is_success()
                    || response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED => {}
            Ok(response) => tracing::warn!(
                status = %response.status(),
                "remote MCP session cleanup was not accepted"
            ),
            Err(error) => tracing::warn!(%error, "remote MCP session cleanup failed"),
        }
    }
}

fn parse_target(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("invalid MCP remote URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("MCP remote URL must use http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("MCP remote URL must not contain embedded credentials");
    }
    if url.fragment().is_some() {
        bail!("MCP remote URL must not contain a fragment");
    }
    Ok(url)
}

fn header_from_env(name: &str, fallback: &str, label: &str) -> Result<HeaderValue> {
    let value = std::env::var(name).unwrap_or_else(|_| fallback.to_owned());
    HeaderValue::from_str(&value).with_context(|| format!("invalid {label}"))
}

fn validate_jsonrpc(value: &Value) -> Result<()> {
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        bail!("message is not JSON-RPC 2.0");
    }
    Ok(())
}

fn next_sse_event(value: &str) -> Option<(usize, usize)> {
    let lf = value.find("\n\n").map(|index| (index, index + 2));
    let crlf = value.find("\r\n\r\n").map(|index| (index, index + 4));
    match (lf, crlf) {
        (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
        (Some(found), None) | (None, Some(found)) => Some(found),
        (None, None) => None,
    }
}

fn parse_sse_data(event: &str) -> Option<String> {
    let data = event
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>();
    (!data.is_empty()).then(|| data.join("\n"))
}

fn truncate(value: &str, limit: usize) -> String {
    let mut chars = value.chars();
    let shortened: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        format!("{shortened}...")
    } else {
        shortened
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_safe_http_targets() {
        assert!(parse_target("https://mcp.example.test/v1").is_ok());
        assert!(parse_target("http://127.0.0.1:8787/mcp").is_ok());
    }

    #[test]
    fn rejects_unsafe_or_unsupported_targets() {
        assert!(parse_target("file:///tmp/mcp").is_err());
        assert!(parse_target("https://user:pass@example.test/mcp").is_err());
        assert!(parse_target("https://example.test/mcp#token").is_err());
    }

    #[test]
    fn parses_multiline_sse_data() {
        let event = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1}\r\n";
        assert_eq!(
            parse_sse_data(event).as_deref(),
            Some("{\"jsonrpc\":\"2.0\",\n\"id\":1}")
        );
    }

    #[test]
    fn finds_lf_and_crlf_event_boundaries() {
        assert_eq!(next_sse_event("data: one\n\nrest"), Some((9, 11)));
        assert_eq!(next_sse_event("data: one\r\n\r\nrest"), Some((9, 13)));
    }
}
