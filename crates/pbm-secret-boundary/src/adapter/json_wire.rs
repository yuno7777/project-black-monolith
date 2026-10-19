use crate::broker::SecretBoundaryBroker;
use crate::operation::OperationRequest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum allowed length for identifier strings (agent_id, operation_id).
const MAX_IDENTIFIER_LEN: usize = 128;
/// Maximum allowed length for destination URLs.
const MAX_URL_LEN: usize = 2048;

/// An external wire request received via stdin, IPC pipe, or socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRequest {
    pub agent_id: String,
    pub operation_id: String,
    pub destination_url: String,
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// A sanitized wire response returned to external callers or AI middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireResponse {
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub response_headers: Option<HashMap<String, String>>,
    pub error_message: Option<String>,
    pub duration_ms: Option<u64>,
}

/// Processes a JSON request string through the `SecretBoundaryBroker` and returns
/// a strictly validated, sanitized JSON response string.
pub fn handle_json_request(broker: &SecretBoundaryBroker, json_str: &str) -> String {
    // 1. Guard against unbounded payload sizes (max 1MB JSON request)
    if json_str.len() > 1024 * 1024 {
        let err_resp = WireResponse {
            success: false,
            status_code: None,
            response_body: None,
            response_headers: None,
            error_message: Some("Request payload exceeds 1MB limit".to_string()),
            duration_ms: None,
        };
        return serde_json::to_string(&err_resp).unwrap_or_default();
    }

    // 2. Deserialize request with strict validation
    let wire_req: WireRequest = match serde_json::from_str(json_str) {
        Ok(r) => r,
        Err(e) => {
            let err_resp = WireResponse {
                success: false,
                status_code: None,
                response_body: None,
                response_headers: None,
                error_message: Some(format!("Invalid JSON wire request schema: {}", e)),
                duration_ms: None,
            };
            return serde_json::to_string(&err_resp).unwrap_or_default();
        }
    };

    // 3. Validate bounds on request parameters
    if wire_req.agent_id.len() > MAX_IDENTIFIER_LEN
        || wire_req.operation_id.len() > MAX_IDENTIFIER_LEN
        || wire_req.destination_url.len() > MAX_URL_LEN
    {
        let err_resp = WireResponse {
            success: false,
            status_code: None,
            response_body: None,
            response_headers: None,
            error_message: Some("Identifier or URL length exceeds safety limits".to_string()),
            duration_ms: None,
        };
        return serde_json::to_string(&err_resp).unwrap_or_default();
    }

    // 4. Convert to internal OperationRequest
    let internal_req = OperationRequest {
        agent_id: wire_req.agent_id,
        operation_id: wire_req.operation_id,
        destination_url: wire_req.destination_url,
        method: wire_req.method,
        headers: wire_req.headers,
        body: wire_req.body.map(|s| s.into_bytes()),
    };

    // 5. Execute through the boundary
    match broker.execute(internal_req) {
        Ok(resp) => {
            let body_str = String::from_utf8(resp.sanitized_body).ok();
            let wire_resp = WireResponse {
                success: true,
                status_code: Some(resp.status_code),
                response_body: body_str,
                response_headers: Some(resp.sanitized_headers),
                error_message: None,
                duration_ms: Some(resp.duration_ms),
            };
            serde_json::to_string(&wire_resp).unwrap_or_default()
        }
        Err(err) => {
            let wire_resp = WireResponse {
                success: false,
                status_code: None,
                response_body: None,
                response_headers: None,
                error_message: Some(err.to_string()),
                duration_ms: None,
            };
            serde_json::to_string(&wire_resp).unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::InMemoryAuditLogger;
    use crate::operation::MockOperationBackend;
    use crate::policy::{PolicyEngine, PolicyRule};
    use crate::provider::MockSecretProvider;
    use std::sync::Arc;

    #[test]
    fn test_handle_json_request_success() {
        let mut policy_engine = PolicyEngine::new();
        let rule = PolicyRule::new(
            "agent_007",
            "op_query",
            "op://dev-vault/weather-service/api-key",
            "api.weather.example.com",
        );
        policy_engine.add_rule(rule).unwrap();

        let broker = SecretBoundaryBroker::new(
            policy_engine,
            Arc::new(MockSecretProvider::new()),
            Arc::new(MockOperationBackend::new()),
            Arc::new(InMemoryAuditLogger::new()),
        );

        let json_input = r#"{
            "agent_id": "agent_007",
            "operation_id": "op_query",
            "destination_url": "https://api.weather.example.com/data",
            "method": "GET"
        }"#;

        let output_json = handle_json_request(&broker, json_input);
        let resp: WireResponse = serde_json::from_str(&output_json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.status_code, Some(200));
        assert!(resp.response_body.unwrap().contains("Sunny"));
    }
}
