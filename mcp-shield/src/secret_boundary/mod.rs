//! Secret Boundary integration module for MCP-Shield.
//!
//! Provides the primary integration facade `ShieldSecretBoundary`, wiring together:
//! - The fail-closed `SecretBoundaryBroker`
//! - The declarative `SecretToolRegistry`
//! - The HTTPS-capable `ReqwestHttpsTransport`
//! - The PBM Schema Version 2 `PbmAuditBridge`

pub mod events;
pub mod mapping;
pub mod transport;

use crate::jsonrpc::JsonRpcMessage;
use anyhow::{Context, Result};
use events::PbmAuditBridge;
use mapping::{SecretBoundToolDefinition, SecretToolRegistry};
use pbm_secret_boundary::broker::SecretBoundaryBroker;
use pbm_secret_boundary::operation::http::{
    HttpAdapterConfig, HttpOperationAdapter, SystemDnsResolver,
};
use pbm_secret_boundary::policy::PolicyEngine;
use pbm_secret_boundary::provider::{
    MockSecretProvider, OnePasswordCliConfig, OnePasswordCliProvider, SecretProvider,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use transport::ReqwestHttpsTransport;

/// Configuration for the Secret Boundary integration.
///
/// Unknown fields are rejected: a mistyped key such as `permitted_param`
/// (instead of `permitted_params`) would otherwise be silently dropped, and a
/// silently narrower allowlist is a silently broken tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryConfig {
    /// Whether the secret boundary is active. Defaults to false.
    #[serde(default)]
    pub enabled: bool,

    /// The identity this boundary instance serves.
    ///
    /// This is the identity the policy engine authorizes against, so it must
    /// be declared explicitly: an implicit default would make the
    /// `policy_rule.agent_id` field decorative, because every request would
    /// present the same constant and every rule could be written to match it.
    /// Every configured policy rule must name this same identity.
    pub agent_id: String,

    /// Active credential provider: "mock" or "1password-cli". Defaults to "mock".
    #[serde(default = "default_provider")]
    pub active_provider: String,

    /// Synthetic secrets for the mock provider (used in local testing / demos).
    #[serde(default)]
    pub synthetic_secrets: HashMap<String, String>,

    /// Optional 1Password CLI configuration.
    ///
    /// `null` (or absent) means the 1Password CLI provider is not configured
    /// at all; selecting `active_provider: "1password-cli"` without it is a
    /// configuration error.
    #[serde(default)]
    pub onepassword_cli: Option<OnePasswordCliConfig>,

    /// Declarative tool definitions approved for secret mediation.
    #[serde(default)]
    pub tools: Vec<SecretBoundToolDefinition>,
}

fn default_provider() -> String {
    "mock".to_string()
}

/// What the agent sees when an upstream response body trips the sanitizer.
const REDACTED_BOUNDARY_RESPONSE: &str =
    "[MCP-Shield redacted suspicious secret boundary response]";

impl Default for BoundaryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            agent_id: String::new(),
            active_provider: default_provider(),
            synthetic_secrets: HashMap::new(),
            onepassword_cli: None,
            tools: Vec::new(),
        }
    }
}

/// The active controller managing Secret Boundary mediation in MCP-Shield.
pub struct ShieldSecretBoundary {
    broker: Arc<SecretBoundaryBroker>,
    registry: Arc<SecretToolRegistry>,
    /// The identity every request presents, and the only identity the
    /// configured policy rules may authorize.
    agent_id: String,
}

impl std::fmt::Debug for ShieldSecretBoundary {
    /// Deliberately minimal: the broker and registry hold credential
    /// providers, and a derived `Debug` could one day print a secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShieldSecretBoundary")
            .field("agent_id", &self.agent_id)
            .field("tools", &self.registry.iter().count())
            .finish()
    }
}

impl ShieldSecretBoundary {
    /// Loads the boundary from the environment, if one is configured.
    ///
    /// `MCP_SHIELD_SECRET_BOUNDARY_CONFIG` may hold either a path to a JSON
    /// file or an inline JSON document. Returns `Ok(None)` when the variable
    /// is unset or empty — the boundary is opt-in.
    ///
    /// This is deliberately separate from the rest of the startup
    /// configuration: building the boundary reads the credential provider
    /// and can fail, and the operator commands (`--list-pending`,
    /// `--approve`) must keep working even when the boundary configuration is
    /// broken, otherwise a bad config locks the operator out of the tool they
    /// need to fix it.
    pub fn from_env() -> Result<Option<Arc<Self>>> {
        let raw = match std::env::var("MCP_SHIELD_SECRET_BOUNDARY_CONFIG") {
            Ok(raw) if !raw.trim().is_empty() => raw,
            _ => return Ok(None),
        };
        let trimmed = raw.trim();
        let boundary = if trimmed.starts_with('{') {
            Self::from_config_json(trimmed)
                .context("failed to initialize secret boundary from JSON string")?
        } else {
            let content = std::fs::read_to_string(trimmed).with_context(|| {
                format!("failed to read secret boundary config file: {trimmed}")
            })?;
            Self::from_config_json(&content).with_context(|| {
                format!("failed to initialize secret boundary from config file: {trimmed}")
            })?
        };
        Ok(Some(Arc::new(boundary)))
    }

    /// Loads configuration from a JSON file and builds the controller.
    /// Fails closed if the configuration file is unreadable or malformed.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read Secret Boundary config at {:?}", path))?;
        Self::from_config_json(&content)
    }

    /// Loads configuration from a JSON string and builds the controller.
    pub fn from_config_json(json: &str) -> Result<Self> {
        // The serde error is included in the message rather than chained:
        // it names the offending field ("unknown field `permitted_param`"),
        // and that is exactly what the operator needs to see.
        let config: BoundaryConfig = serde_json::from_str(json)
            .map_err(|e| anyhow::anyhow!("Failed to parse Secret Boundary config JSON: {e}"))?;
        Self::from_config(config)
    }

    /// Builds a controller from a verified `BoundaryConfig`.
    ///
    /// Fails closed: an unreadable, malformed, or internally inconsistent
    /// configuration aborts startup rather than degrading to a partially
    /// enabled boundary.
    pub fn from_config(config: BoundaryConfig) -> Result<Self> {
        if !config.enabled {
            anyhow::bail!("Secret Boundary configuration is marked disabled");
        }

        // The agent identity must be explicit. Without it every request would
        // present the same constant, which would make the `agent_id` field of
        // every policy rule decorative.
        let agent_id = config.agent_id.trim().to_string();
        if agent_id.is_empty() {
            anyhow::bail!(
                "Secret Boundary configuration must declare a non-empty `agent_id`; \
                 it is the identity the policy engine authorizes against"
            );
        }
        if agent_id.len() > 128 || agent_id.chars().any(char::is_control) {
            anyhow::bail!("Secret Boundary `agent_id` must be at most 128 printable characters");
        }

        // The boundary authorizes one identity; the module attributes events
        // to another (MONOLITH_AGENT_ID). They are allowed to differ — an
        // operator may attribute the session to a fleet while the policy
        // binds a narrower identity — but a silent mismatch makes the ledger
        // look like the wrong agent used the credential, so it is worth a
        // line in the log. The audit event records the authorized identity
        // explicitly, so the evidence is never ambiguous either way.
        if let Some(module_agent) = crate::events::identity().agent_id.as_deref() {
            if module_agent != agent_id {
                tracing::warn!(
                    boundary_agent_id = %agent_id,
                    module_agent_id = %module_agent,
                    "Secret Boundary authorizes a different agent identity than the module \
                     attributes its events to; the audit trail records the authorized identity \
                     in details.authorized_agent_id"
                );
            }
        }

        // 1. Configure credential provider
        let provider: Arc<dyn SecretProvider> = match config.active_provider.as_str() {
            "mock" => {
                let mut mock = MockSecretProvider::new();
                for (ref_path, val) in config.synthetic_secrets {
                    mock.insert_synthetic(ref_path, val);
                }
                Arc::new(mock)
            }
            "1password-cli" => {
                let cli_config = config.onepassword_cli.ok_or_else(|| {
                    anyhow::anyhow!(
                        "1Password CLI provider selected but `onepassword_cli` is not configured"
                    )
                })?;
                if !cli_config.enabled {
                    anyhow::bail!(
                        "1Password CLI provider selected but onepassword_cli.enabled is false"
                    );
                }
                let op = OnePasswordCliProvider::new(cli_config)
                    .map_err(|e| anyhow::anyhow!("1Password CLI provider setup error: {}", e))?;
                Arc::new(op)
            }
            other => anyhow::bail!("Unrecognized credential provider: '{}'", other),
        };

        // 2. Configure tool registry and policy engine
        let mut registry = SecretToolRegistry::new();
        let mut policy_engine = PolicyEngine::new();

        for tool_def in config.tools {
            // A rule that names a different agent can never be matched by this
            // process, so it is dead configuration. Rejecting it at load time
            // is better than discovering it as a puzzling runtime denial.
            if tool_def.policy_rule.agent_id != agent_id {
                anyhow::bail!(
                    "Tool '{}' policy rule authorizes agent '{}' but this boundary serves '{}'; \
                     a rule for another agent can never be matched",
                    tool_def.tool_name,
                    tool_def.policy_rule.agent_id,
                    agent_id
                );
            }
            policy_engine
                .add_rule(tool_def.policy_rule.clone())
                .map_err(|e| anyhow::anyhow!("Policy rule registration error: {}", e))?;
            registry
                .register_tool(tool_def)
                .map_err(|e| anyhow::anyhow!("Tool registration error: {}", e))?;
        }

        // 3. Configure HTTPS transport with connection pinning and SSRF defense
        let transport = Arc::new(ReqwestHttpsTransport::new());
        let resolver = Arc::new(SystemDnsResolver);
        let http_adapter = Arc::new(HttpOperationAdapter::with_resolver_and_transport(
            HttpAdapterConfig::default(),
            resolver,
            transport,
        ));

        // 4. Configure audit bridge delegating to PBM Schema v2 outbox pipeline
        let logger = Arc::new(PbmAuditBridge::new());

        // 5. Build central broker
        let broker = Arc::new(SecretBoundaryBroker::new(
            policy_engine,
            provider,
            http_adapter,
            logger,
        ));

        Ok(Self {
            broker,
            registry: Arc::new(registry),
            agent_id,
        })
    }

    /// Constructs a controller with a custom broker and registry (useful for
    /// targeted unit testing).
    pub fn with_broker_and_registry(
        broker: Arc<SecretBoundaryBroker>,
        registry: Arc<SecretToolRegistry>,
        agent_id: impl Into<String>,
    ) -> Self {
        Self {
            broker,
            registry,
            agent_id: agent_id.into(),
        }
    }

    /// The identity this boundary presents to the policy engine.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Returns whether the specified tool name is a policy-bound secret tool.
    pub fn is_secret_tool(&self, tool_name: &str) -> bool {
        self.registry.is_secret_tool(tool_name)
    }

    /// Returns MCP-compliant tool descriptors for advertising in `tools/list`.
    pub fn get_mcp_tool_descriptors(&self) -> Vec<Value> {
        self.registry.get_mcp_descriptors()
    }

    /// Executes an intercepted MCP `tools/call` message, returning a JSON-RPC response line.
    ///
    /// This method is isolated from Tokio worker thread blocking via `spawn_blocking`.
    ///
    /// The response is produced **here**, inside the proxy, and is written
    /// straight to the agent's stdout. It never travels the server-to-agent
    /// path, which is why the upstream body is scanned explicitly before it
    /// is returned: the ordinary sanitizer never sees it.
    ///
    /// The error codes are JSON-RPC's standard ones, with `-32000` (server
    /// error) reserved for a failure inside the boundary itself. A failure
    /// here means the operation did not happen — never a partial success
    /// with the credential half-applied.
    pub async fn execute_mcp_tool_call(&self, msg: &JsonRpcMessage) -> String {
        let req_id = msg.id.clone().unwrap_or(Value::Null);

        let params = match &msg.params {
            Some(Value::Object(map)) => map,
            _ => {
                return serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: tools/call requires a params object"
                    }
                }))
                .unwrap_or_default();
            }
        };

        let tool_name = match params.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => {
                return serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: missing tool name"
                    }
                }))
                .unwrap_or_default();
            }
        };

        let arguments = params.get("arguments").unwrap_or(&Value::Null);

        // The identity is the one this boundary was configured to serve, not
        // anything the caller supplied.
        let agent_id = self.agent_id.clone();

        // 1. Translate arguments to OperationRequest
        let op_request = match self
            .registry
            .build_operation_request(tool_name, &agent_id, arguments)
        {
            Ok(req) => req,
            Err(err) => {
                return serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": format!("Secret boundary validation error: {}", err)
                    }
                }))
                .unwrap_or_default();
            }
        };

        // 2. Execute through broker on blocking thread pool
        let broker = Arc::clone(&self.broker);
        let exec_result = tokio::task::spawn_blocking(move || broker.execute(op_request))
            .await
            .unwrap_or_else(|join_err| {
                Err(pbm_secret_boundary::error::BoundaryError::ExecutionFailed(
                    format!("Broker execution task panicked: {}", join_err),
                ))
            });

        // 3. Format sanitized JSON-RPC response
        match exec_result {
            Ok(resp) => {
                let content_text = self.sanitize_response_body(tool_name, &resp.sanitized_body);
                serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": content_text
                            }
                        ]
                    }
                }))
                .unwrap_or_default()
            }
            Err(err) => serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32000,
                    "message": format!("Secret boundary error: {}", err)
                }
            }))
            .unwrap_or_default(),
        }
    }

    /// Sanitize the upstream response body before it reaches the model.
    ///
    /// The boundary's own responses never travel the server-to-agent path, so
    /// they never reach the description sanitizer that screens ordinary tool
    /// output. Without this, an approved-but-compromised upstream could carry
    /// hidden-instruction text straight into the model context through the
    /// boundary — the one path that is supposed to be the most controlled.
    ///
    /// A body that trips the sanitizer is replaced wholesale rather than
    /// partially edited: a partial rewrite of an injection payload is still
    /// an injection payload.
    fn sanitize_response_body(&self, tool_name: &str, body: &[u8]) -> String {
        let text = String::from_utf8_lossy(body).to_string();
        let findings = crate::sanitizer::scan_description(&text);
        if findings.is_empty() {
            return text;
        }

        tracing::warn!(
            tool = tool_name,
            finding_count = findings.len(),
            "SECRET BOUNDARY RESPONSE REDACTED: upstream body contains hidden-instruction patterns"
        );
        crate::events::emit(
            "suspicious_description",
            crate::events::Severity::Warning,
            json!({
                "tool": tool_name,
                "findings": findings,
                "action": "redacted_secret_boundary_response",
            }),
        );
        REDACTED_BOUNDARY_RESPONSE.to_string()
    }
}

#[cfg(test)]
mod tests;
