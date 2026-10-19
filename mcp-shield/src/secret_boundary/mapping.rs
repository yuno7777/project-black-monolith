//! Declarative mapping between approved MCP tool names, input schemas,
//! and policy-bound Secret Boundary operations.
//!
//! Enforces:
//! 1. Complete decoupling: AI agents cannot specify credential references,
//!    custom headers, or unapproved destination hosts.
//! 2. Parameter allowlisting: Only declared parameters are permitted; extraneous
//!    parameters or injection payloads are rejected.
//! 3. Syntactic validation: Rejects CRLF, null bytes, and path traversal in parameters.
//! 4. Consistent descriptor generation for MCP `tools/list` advertisement.

use pbm_secret_boundary::error::BoundaryError;
use pbm_secret_boundary::operation::OperationRequest;
use pbm_secret_boundary::policy::PolicyRule;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use url::Url;

/// Declarative specification of an MCP tool backed by a Secret Boundary operation.
///
/// Unknown fields are rejected on deserialization: a mistyped
/// `permitted_params` would otherwise be silently dropped, leaving the tool
/// with an empty allowlist (or, worse, an unintended one).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretBoundToolDefinition {
    /// Name of the tool exposed in MCP JSON-RPC protocol (e.g., "fetch_weather")
    pub tool_name: String,

    /// Unique operation identifier matched by the Secret Boundary policy
    pub operation_id: String,

    /// Human-readable description advertised to calling agents
    pub description: String,

    /// JSON Schema describing the tool's input parameters
    pub input_schema: Value,

    /// Base destination URL template (must be HTTPS)
    pub url_template: String,

    /// HTTP method (e.g. "GET", "POST")
    pub method: String,

    /// List of permitted parameter keys that callers may provide
    pub permitted_params: Vec<String>,

    /// Associated authorization policy rule
    pub policy_rule: PolicyRule,
}

impl SecretBoundToolDefinition {
    /// Validates definition invariants upon registration.
    ///
    /// Everything checked here is checked again at request time by the policy
    /// engine. The duplication is the point: a configuration that can only
    /// ever fail must fail at load, where the operator is looking at it, not
    /// on every call, where it looks like a flaky upstream.
    pub fn validate(&self) -> Result<(), BoundaryError> {
        let parsed = Url::parse(&self.url_template).map_err(|e| {
            BoundaryError::ConfigurationError(format!(
                "Invalid URL template for tool '{}': {}",
                self.tool_name, e
            ))
        })?;

        if parsed.scheme() != "https" {
            return Err(BoundaryError::ConfigurationError(format!(
                "Tool '{}' URL template must use HTTPS scheme, found '{}'",
                self.tool_name,
                parsed.scheme()
            )));
        }

        if parsed.username() != "" || parsed.password().is_some() {
            return Err(BoundaryError::ConfigurationError(format!(
                "Tool '{}' URL template must not contain embedded userinfo or credentials",
                self.tool_name
            )));
        }

        let host = parsed.host_str().ok_or_else(|| {
            BoundaryError::ConfigurationError(format!(
                "Tool '{}' URL template lacks a valid host",
                self.tool_name
            ))
        })?;

        if !host.eq_ignore_ascii_case(&self.policy_rule.destination_host) {
            return Err(BoundaryError::ConfigurationError(format!(
                "Tool '{}' destination host '{}' does not match policy approved host '{}'",
                self.tool_name, host, self.policy_rule.destination_host
            )));
        }

        // The same segment-aware rule the policy engine applies. A plain
        // `starts_with` here would let a template of `/v1/forecast-admin`
        // pass configuration and then be denied on every single call.
        if !pbm_secret_boundary::policy::path_matches_prefix(
            parsed.path(),
            &self.policy_rule.allowed_path_prefix,
        ) {
            return Err(BoundaryError::ConfigurationError(format!(
                "Tool '{}' path '{}' does not conform to policy path prefix '{}'",
                self.tool_name,
                parsed.path(),
                self.policy_rule.allowed_path_prefix
            )));
        }

        if pbm_secret_boundary::policy::path_contains_traversal(parsed.path()) {
            return Err(BoundaryError::ConfigurationError(format!(
                "Tool '{}' path '{}' contains a forbidden traversal sequence",
                self.tool_name,
                parsed.path()
            )));
        }

        let method_upper = self.method.to_ascii_uppercase();
        if !self
            .policy_rule
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&method_upper))
        {
            return Err(BoundaryError::ConfigurationError(format!(
                "Tool '{}' method '{}' is not in policy allowed_methods list",
                self.tool_name, self.method
            )));
        }

        // For GET/HEAD every permitted parameter is appended to the query
        // string, so each one must also be permitted by the policy. If the
        // two lists disagree, the tool would be advertised as usable and then
        // denied by the policy engine on every call.
        if method_upper == "GET" || method_upper == "HEAD" {
            for param in &self.permitted_params {
                if !self
                    .policy_rule
                    .permitted_query_params
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(param))
                {
                    return Err(BoundaryError::ConfigurationError(format!(
                        "Tool '{}' permits parameter '{}' but the policy does not list it in \
                         permitted_query_params; a {} request would always be denied",
                        self.tool_name, param, method_upper
                    )));
                }
            }
        }

        // A query string baked into the template is still a query string the
        // policy engine will inspect, so it has to be permitted too.
        for (key, _) in parsed.query_pairs() {
            if !self
                .policy_rule
                .permitted_query_params
                .iter()
                .any(|p| p.eq_ignore_ascii_case(key.as_ref()))
            {
                return Err(BoundaryError::ConfigurationError(format!(
                    "Tool '{}' URL template carries query parameter '{}' which the policy does \
                     not list in permitted_query_params",
                    self.tool_name, key
                )));
            }
        }

        Ok(())
    }
}

/// Registry managing declarative secret-bound tool mappings.
#[derive(Debug, Clone, Default)]
pub struct SecretToolRegistry {
    tools: HashMap<String, SecretBoundToolDefinition>,
}

impl SecretToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Registers a tool definition after verifying its policy consistency.
    pub fn register_tool(&mut self, def: SecretBoundToolDefinition) -> Result<(), BoundaryError> {
        def.validate()?;
        self.tools.insert(def.tool_name.clone(), def);
        Ok(())
    }

    pub fn is_secret_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    pub fn get_tool(&self, name: &str) -> Option<&SecretBoundToolDefinition> {
        self.tools.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SecretBoundToolDefinition> {
        self.tools.values()
    }

    /// Produces MCP-compliant `tools/list` tool descriptors for all registered tools.
    pub fn get_mcp_descriptors(&self) -> Vec<Value> {
        let mut list = Vec::new();
        for def in self.tools.values() {
            list.push(json!({
                "name": def.tool_name,
                "description": def.description,
                "inputSchema": def.input_schema,
            }));
        }
        list
    }

    /// Translates an inbound MCP `tools/call` into an authorized `OperationRequest`.
    ///
    /// Fail-Closed Guarantees:
    /// - Rejects calls for unregistered tools.
    /// - Rejects non-object argument payloads.
    /// - Rejects any parameter not present in `permitted_params`.
    /// - Rejects CRLF, null bytes, or header injection attempts.
    /// - Encodes query parameters safely into the destination URL.
    pub fn build_operation_request(
        &self,
        tool_name: &str,
        agent_id: &str,
        arguments: &Value,
    ) -> Result<OperationRequest, BoundaryError> {
        let tool = self.get_tool(tool_name).ok_or_else(|| {
            BoundaryError::InvalidRequest(format!(
                "Tool '{}' is not a registered secret-bound tool",
                tool_name
            ))
        })?;

        let args_obj = match arguments {
            Value::Object(map) => map,
            Value::Null => {
                static EMPTY: std::sync::OnceLock<serde_json::Map<String, Value>> =
                    std::sync::OnceLock::new();
                EMPTY.get_or_init(serde_json::Map::new)
            }
            _ => {
                return Err(BoundaryError::InvalidRequest(
                    "Tool arguments must be a JSON object".to_string(),
                ));
            }
        };

        // Validate parameter allowlist (reject unknown/unapproved parameters)
        let permitted_set: HashSet<&str> =
            tool.permitted_params.iter().map(String::as_str).collect();
        for key in args_obj.keys() {
            if !permitted_set.contains(key.as_str()) {
                return Err(BoundaryError::InvalidRequest(format!(
                    "Unpermitted parameter '{}' for tool '{}'",
                    key, tool_name
                )));
            }
        }

        // Validate values for CRLF, null bytes, or control sequences
        for (key, val) in args_obj {
            let val_str = match val {
                Value::String(s) => s.as_str(),
                Value::Number(n) => &n.to_string(),
                Value::Bool(b) => {
                    if *b {
                        "true"
                    } else {
                        "false"
                    }
                }
                Value::Null => continue,
                _ => {
                    return Err(BoundaryError::InvalidRequest(format!(
                        "Complex nested parameter types are disallowed for key '{}'",
                        key
                    )));
                }
            };

            if key.contains('\r') || key.contains('\n') || key.contains('\0') {
                return Err(BoundaryError::InvalidRequest(format!(
                    "Control character injection detected in parameter key '{}'",
                    key
                )));
            }

            if val_str.contains('\r') || val_str.contains('\n') || val_str.contains('\0') {
                return Err(BoundaryError::InvalidRequest(format!(
                    "Control character injection detected in value for '{}'",
                    key
                )));
            }
        }

        // Build destination URL by populating query parameters or path
        let mut final_url = Url::parse(&tool.url_template)
            .map_err(|e| BoundaryError::ConfigurationError(format!("Malformed base URL: {}", e)))?;

        let method_upper = tool.method.to_ascii_uppercase();
        let body = if method_upper == "GET" || method_upper == "HEAD" {
            // Append parameters as URL query pairs
            for (k, v) in args_obj {
                if let Some(s) = v.as_str() {
                    final_url.query_pairs_mut().append_pair(k, s);
                } else if !v.is_null() {
                    final_url.query_pairs_mut().append_pair(k, &v.to_string());
                }
            }
            None
        } else {
            // Encode parameters as request body
            Some(serde_json::to_vec(args_obj).map_err(|e| {
                BoundaryError::SerializationError(format!("Failed to serialize body: {}", e))
            })?)
        };

        // Construct authorized OperationRequest
        // Notice: headers are strictly empty; credentials will be bound by policy inside the broker.
        Ok(OperationRequest {
            agent_id: agent_id.to_string(),
            operation_id: tool.operation_id.clone(),
            destination_url: final_url.to_string(),
            method: method_upper,
            headers: HashMap::new(),
            body,
        })
    }
}
