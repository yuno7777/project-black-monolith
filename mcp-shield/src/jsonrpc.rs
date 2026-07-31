//! Minimal JSON-RPC 2.0 message model for the MCP stdio transport.
//!
//! MCP-Shield is a *transparent* proxy: every line is forwarded byte-for-byte
//! untouched. This module only parses a copy of each line so the proxy can
//! log it, correlate requests with responses, and hand `tools/list` results
//! to the fingerprinting / sanitizing layers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_CORRELATION_ID_BYTES: usize = 256;
const MAX_LOG_FIELD_CHARS: usize = 128;

fn safe_log_field(value: &str) -> String {
    value
        .chars()
        .take(MAX_LOG_FIELD_CHARS)
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn safe_log_id(value: &Value) -> String {
    match value {
        Value::String(text) => Value::String(safe_log_field(text)).to_string(),
        Value::Number(number) => number.to_string(),
        _ => "<invalid-id>".to_string(),
    }
}

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

    pub fn is_jsonrpc_2(&self) -> bool {
        self.jsonrpc.as_deref() == Some("2.0")
    }

    /// Canonical string form of the id, used as a HashMap/HashSet key when
    /// correlating requests to responses. `1` -> "1", `"abc"` -> "\"abc\"".
    pub fn id_key(&self) -> Option<String> {
        match self.id.as_ref()? {
            Value::String(value) if value.len() <= MAX_CORRELATION_ID_BYTES => {
                Some(Value::String(value.clone()).to_string())
            }
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        }
    }

    /// Short human-readable summary used in pass-through log lines.
    pub fn describe(&self) -> String {
        match (&self.method, &self.id) {
            (Some(m), Some(id)) => {
                format!("request {} (id={})", safe_log_field(m), safe_log_id(id))
            }
            (Some(m), None) => format!("notification {}", safe_log_field(m)),
            (None, Some(id)) => {
                if self.error.is_some() {
                    format!("error-response (id={})", safe_log_id(id))
                } else {
                    format!("response (id={})", safe_log_id(id))
                }
            }
            (None, None) => "malformed (no method, no id)".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bounded_spec_correlation_ids_become_keys() {
        for raw in [
            r#"{"jsonrpc":"2.0","id":null}"#,
            r#"{"jsonrpc":"2.0","id":{"nested":true}}"#,
            r#"{"jsonrpc":"2.0","id":[1,2]}"#,
        ] {
            assert_eq!(JsonRpcMessage::parse(raw).unwrap().id_key(), None);
        }
        assert_eq!(
            JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","id":"abc"}"#)
                .unwrap()
                .id_key()
                .as_deref(),
            Some("\"abc\"")
        );
        assert_eq!(
            JsonRpcMessage::parse(r#"{"jsonrpc":"2.0","id":42}"#)
                .unwrap()
                .id_key()
                .as_deref(),
            Some("42")
        );
        let oversized = JsonRpcMessage {
            jsonrpc: Some("2.0".into()),
            id: Some(Value::String("x".repeat(MAX_CORRELATION_ID_BYTES + 1))),
            method: None,
            params: None,
            result: None,
            error: None,
        };
        assert_eq!(oversized.id_key(), None);
    }

    #[test]
    fn log_descriptions_strip_controls_and_bound_untrusted_fields() {
        let message = JsonRpcMessage {
            jsonrpc: Some("2.0".into()),
            id: Some(Value::String("id\r\nforged".into())),
            method: Some(format!("method\n{}", "x".repeat(500))),
            params: None,
            result: None,
            error: None,
        };
        let description = message.describe();
        assert!(!description.contains('\n'));
        assert!(description.len() < 400);
    }
}
