//! Minimal JSON-RPC 2.0 message model for the MCP stdio transport.
//!
//! MCP-Shield is a *transparent* proxy: every line is forwarded byte-for-byte
//! untouched. This module only parses a copy of each line so the proxy can
//! log it, correlate requests with responses, and hand `tools/list` results
//! to the fingerprinting / sanitizing layers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A loosely-typed JSON-RPC 2.0 message. All fields are optional so that a
/// single struct can represent requests, notifications, and responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcMessage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jsonrpc: Option<String>,

    /// Request/response correlation id. Per spec this may be a number or a
    /// string, so it is kept as a raw `Value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,

    /// Present on requests and notifications, absent on responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,

    /// Present on successful responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,

    /// Present on error responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl JsonRpcMessage {
    /// Parse one line-delimited JSON-RPC message.
    pub fn parse(line: &str) -> Result<Self> {
        serde_json::from_str(line).context("line is not a valid JSON-RPC message")
    }

    /// True if this message is a response (no method, has result or error).
    pub fn is_response(&self) -> bool {
        self.method.is_none() && (self.result.is_some() || self.error.is_some())
    }

    /// Canonical string form of the id, used as a HashMap/HashSet key when
    /// correlating requests to responses. `1` -> "1", `"abc"` -> "\"abc\"".
    pub fn id_key(&self) -> Option<String> {
        self.id.as_ref().map(|v| v.to_string())
    }

    /// Short human-readable summary used in pass-through log lines.
    pub fn describe(&self) -> String {
        match (&self.method, &self.id) {
            (Some(m), Some(id)) => format!("request {m} (id={id})"),
            (Some(m), None) => format!("notification {m}"),
            (None, Some(id)) => {
                if self.error.is_some() {
                    format!("error-response (id={id})")
                } else {
                    format!("response (id={id})")
                }
            }
            (None, None) => "malformed (no method, no id)".to_string(),
        }
    }
}
