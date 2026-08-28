//! Minimal JSON-RPC 2.0 message model for the MCP stdio transport.
//!
//! WHAT THIS FILE IS
//! -----------------
//! The message type the proxy uses to LOOK at the traffic. MCP-Shield is a
//! *transparent* proxy: every line is forwarded byte-for-byte untouched. But
//! to detect a rug pull it must understand what it is forwarding, so it
//! parses a COPY of each line into this struct — enough to log it, correlate
//! requests with responses (via the id), and hand `tools/list` results to the
//! fingerprinting / sanitizing layers.
//!
//! WHY SO LOOSE
//! ------------
//! Real MCP traffic has requests, notifications, and responses, and JSON-RPC
//! ids can be numbers OR strings. Every field is optional so one struct
//! represents all of them. The proxy never re-serializes the original line —
//! the original bytes go through unchanged — so even messages this model
//! cannot fully understand still pass through fine (fail-open transparency).
//!
//! Called from: proxy.rs (both forwarding directions parse every line),
//! http_transport.rs (validates + emits JSON-RPC over HTTP).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_CORRELATION_ID_BYTES: usize = 256;
const MAX_LOG_FIELD_CHARS: usize = 128;

fn safe_log_field(value: &str) -> String {
    /// Bound and sanitize untrusted text before it goes into a log line:
    /// at most 128 chars, and control characters (which could forge log
    /// lines or terminal escapes) are replaced with U+FFFD.
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
    /// Same sanitization for a JSON-RPC id used in a log line.
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
    ///
    /// Returns None for ids this proxy cannot safely correlate with (null,
    /// objects, arrays, or strings longer than the cap). Called from proxy.rs
    /// via msg.id_key() when tracking in-flight requests/responses.
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
    /// Note "request {method} (id={id})" for calls, "notification {method}"
    /// for fire-and-forget messages, and "response"/"error-response" by id.
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

    /// Only bounded, spec-shaped ids become correlation keys. `null`, nested
    /// objects, arrays, and oversized strings must not be usable as keys.
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

    /// Log descriptions must strip control characters and bound untrusted
    /// fields so a hostile method/id cannot forge log lines or blow up logs.
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
