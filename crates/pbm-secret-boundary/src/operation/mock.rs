use super::{OperationExecutor, OperationRequest, OperationResponse};
use crate::error::BoundaryError;
use crate::secret::{redact_secret_from_text, SecretString};
use std::collections::HashMap;

/// A mock execution backend simulating third-party services offline without network calls.
#[derive(Debug, Clone)]
pub struct MockOperationBackend {
    simulated_status: u16,
    simulated_body_template: String,
    should_fail: bool,
}

impl MockOperationBackend {
    /// Creates a default `MockOperationBackend` returning 200 OK with sanitized synthetic data.
    pub fn new() -> Self {
        Self {
            simulated_status: 200,
            simulated_body_template:
                r#"{"status":"success","data":{"temperature_c":21.5,"conditions":"Sunny"}}"#
                    .to_string(),
            should_fail: false,
        }
    }

    /// Sets custom simulated response body.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.simulated_body_template = body.into();
        self
    }

    /// Configures the backend to simulate a transport failure.
    pub fn with_failure(mut self, fail: bool) -> Self {
        self.should_fail = fail;
        self
    }
}

impl Default for MockOperationBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationExecutor for MockOperationBackend {
    fn execute(
        &self,
        request: &OperationRequest,
        secret: &SecretString,
    ) -> Result<OperationResponse, BoundaryError> {
        if self.should_fail {
            return Err(BoundaryError::ExecutionFailed(format!(
                "Simulated backend connection failure for operation '{}'",
                request.operation_id
            )));
        }

        // Output sanitization: Verify no reflection of raw secret
        let sanitized = redact_secret_from_text(&self.simulated_body_template, secret);

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-Request-Id".to_string(), "mock-req-001".to_string());

        Ok(OperationResponse {
            status_code: self.simulated_status,
            sanitized_body: sanitized.into_bytes(),
            sanitized_headers: headers,
            duration_ms: 10,
        })
    }
}
