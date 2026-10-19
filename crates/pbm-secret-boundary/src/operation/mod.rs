pub mod http;
pub mod mock;

use crate::error::BoundaryError;
use crate::secret::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use http::{
    DnsResolver, HttpAdapterConfig, HttpOperationAdapter, HttpRequestDetails, HttpTransport,
    MockDnsResolver, MockHttpTransport, RawHttpResponse, StdTcpHttpTransport, SystemDnsResolver,
};
pub use mock::MockOperationBackend;

/// An authorized operation request initiated by an AI agent or middleware caller.
///
/// **Security Notice:** The request contains only public parameters. The credential
/// reference and credentials are NOT passed by the agent; they are bound by policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRequest {
    /// Identifier of the requesting agent.
    pub agent_id: String,

    /// Target approved operation identifier.
    pub operation_id: String,

    /// Full destination URL.
    pub destination_url: String,

    /// HTTP method (e.g., "GET", "POST").
    pub method: String,

    /// Headers provided by caller. Authorization headers are rejected.
    pub headers: HashMap<String, String>,

    /// Optional request payload.
    pub body: Option<Vec<u8>>,
}

/// The sanitized operation response returned back across the agent boundary.
///
/// **Security Invariant:** All response content is filtered to ensure raw credentials
/// or internal authentication tokens are never returned to the model context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResponse {
    /// HTTP status code or operation return code.
    pub status_code: u16,

    /// Filtered body payload safe for agent context.
    pub sanitized_body: Vec<u8>,

    /// Filtered response headers (sensitive headers like Set-Cookie or Auth are stripped).
    pub sanitized_headers: HashMap<String, String>,

    /// Duration of operation execution in milliseconds.
    pub duration_ms: u64,
}

/// Trait implemented by operation adapters that safely consume credentials internally.
pub trait OperationExecutor: Send + Sync {
    /// Executes the approved operation using the injected secret and returns a sanitized response.
    fn execute(
        &self,
        request: &OperationRequest,
        secret: &SecretString,
    ) -> Result<OperationResponse, BoundaryError>;
}
