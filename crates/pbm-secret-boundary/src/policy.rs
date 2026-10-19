use crate::error::BoundaryError;
use crate::operation::OperationRequest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

/// Represents an authorization policy rule bounding an approved agent operation.
///
/// **Critical Security Constraint:** The credential reference (`approved_credential_ref`)
/// is defined solely by this policy rule. An AI agent is NEVER permitted to specify,
/// override, or request an arbitrary credential identifier.
///
/// Unknown fields are rejected on deserialization: a mistyped key such as
/// `permitted_query_param` would otherwise be silently dropped, and a rule that
/// silently stops matching is a rule that silently stops authorizing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Identifier of the authorized requesting agent or tool.
    pub agent_id: String,

    /// Unique identifier for the approved operation (e.g., "op_fetch_weather").
    pub operation_id: String,

    /// The exact secret reference (e.g., "op://dev-vault/weather/api-key") bound to this operation.
    pub approved_credential_ref: String,

    /// Approved destination host (FQDN or IP) that this operation may contact.
    pub destination_host: String,

    /// Optional explicit destination port. Defaults to scheme default (443 for HTTPS, 80 for HTTP).
    pub destination_port: Option<u16>,

    /// HTTP methods allowed for this operation (e.g., ["GET"]).
    pub allowed_methods: Vec<String>,

    /// URL path prefix allowed for this operation (e.g., "/api/v1/forecast").
    pub allowed_path_prefix: String,

    /// Permitted query parameter keys. Any parameter outside this list triggers a denial.
    pub permitted_query_params: Vec<String>,

    /// Optional expiration timestamp after which the rule fails closed.
    pub valid_until: Option<DateTime<Utc>>,

    /// Whether HTTPS is strictly required. Defaults to true.
    pub require_https: bool,
}

impl PolicyRule {
    pub fn new(
        agent_id: impl Into<String>,
        operation_id: impl Into<String>,
        approved_credential_ref: impl Into<String>,
        destination_host: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            operation_id: operation_id.into(),
            approved_credential_ref: approved_credential_ref.into(),
            destination_host: destination_host.into(),
            destination_port: None,
            allowed_methods: vec!["GET".to_string()],
            allowed_path_prefix: "/".to_string(),
            permitted_query_params: Vec::new(),
            valid_until: None,
            require_https: true,
        }
    }
}

/// Segment-aware prefix matching for an approved path prefix.
///
/// A plain `starts_with` would let `/v1/forecast-admin` satisfy a rule that
/// only authorizes `/v1/forecast`: the suffix is a different resource, and
/// authorizing it by prefix is how a path allowlist turns into an
/// open-ended grant. The prefix must therefore be followed by a segment
/// boundary (`/`) or be the whole path.
///
/// An empty (or root) prefix authorizes every path.
///
/// This is the single implementation of the rule: the runtime policy engine
/// and the config-time tool validator must agree exactly, or a tool could be
/// advertised as usable and then denied on every call.
pub fn path_matches_prefix(path: &str, allowed_path_prefix: &str) -> bool {
    let prefix = allowed_path_prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    if path == prefix {
        return true;
    }
    path.starts_with(prefix) && path[prefix.len()..].starts_with('/')
}

/// Returns whether a path contains a traversal sequence in raw or encoded form.
///
/// `%2e` and `%2E` are the percent-encoded spellings of `.`, so a naive
/// `..` check can be walked straight past by any agent that knows how to
/// encode a dot.
pub fn path_contains_traversal(path: &str) -> bool {
    path.contains("..") || path.contains("%2e") || path.contains("%2E")
}

/// A fail-closed authorization engine evaluating agent requests against configured policies.
#[derive(Debug, Default, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Creates a new empty `PolicyEngine`.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds an approved policy rule to the engine.
    ///
    /// # Fail-Closed Collision Guard
    /// Rejects rules that introduce duplicate `(agent_id, operation_id)` pairs to prevent
    /// policy ambiguity or shadow overrides.
    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<(), BoundaryError> {
        if self
            .rules
            .iter()
            .any(|r| r.agent_id == rule.agent_id && r.operation_id == rule.operation_id)
        {
            return Err(BoundaryError::ConfigurationError(format!(
                "Ambiguous policy: duplicate rule for agent '{}' and operation '{}'",
                rule.agent_id, rule.operation_id
            )));
        }
        self.rules.push(rule);
        Ok(())
    }

    /// Evaluates an incoming agent operation request against configured policy rules.
    ///
    /// # Fail-Closed Security Guarantees
    /// 1. Denies unknown agent identities or unregistered operations.
    /// 2. Denies any destination host other than `rule.destination_host`.
    /// 3. Enforces expected network port (rejects port tampering/SSRF targeting unusual ports).
    /// 4. Denies unapproved HTTP methods and unapproved path prefixes.
    /// 5. Validates path segmentation (prevents suffix extension attacks like `/path-admin`).
    /// 6. Rejects unnormalized path traversal attempts (`..`, `%2e%2e`).
    /// 7. Denies requests containing forbidden headers (Authorization, Host, Cookie) or CRLF characters.
    /// 8. Denies requests containing unlisted query parameters.
    /// 9. Denies requests evaluated past `rule.valid_until`.
    ///
    /// # Why the order matters
    ///
    /// The checks run cheapest-and-most-hostile-first, and every one of them
    /// returns an error rather than a warning. Two properties are load
    /// bearing:
    ///
    /// * The header checks run **before** the rule lookup. A request carrying
    ///   a forbidden header is rejected on its own merits, so it cannot be
    ///   laundered into a denial by an unrelated rule mismatch. The error the
    ///   caller sees names the actual problem.
    /// * The rule lookup happens **before** the destination is inspected. A
    ///   request for an operation nobody authorized is denied as such, and
    ///   its URL is never parsed — so a malformed URL from an unauthorized
    ///   caller cannot become a parser oracle.
    pub fn evaluate<'a>(
        &'a self,
        request: &OperationRequest,
        now: DateTime<Utc>,
    ) -> Result<&'a PolicyRule, BoundaryError> {
        // 1. Guard against header injection, smuggling, and tampering
        for (header_key, header_val) in &request.headers {
            let key_lower = header_key.to_ascii_lowercase();

            // Guard forbidden headers
            if key_lower == "authorization"
                || key_lower == "proxy-authorization"
                || key_lower == "host"
                || key_lower == "cookie"
            {
                return Err(BoundaryError::PolicyDenied(format!(
                    "Agent is prohibited from supplying header '{}'",
                    header_key
                )));
            }

            // Guard against CRLF injection and null bytes in header keys and values
            if header_key.contains('\r')
                || header_key.contains('\n')
                || header_key.contains('\0')
                || header_val.contains('\r')
                || header_val.contains('\n')
                || header_val.contains('\0')
            {
                return Err(BoundaryError::InvalidRequest(
                    "Header contains forbidden control characters (CRLF / null bytes)".to_string(),
                ));
            }
        }

        // 2. Find matching rule by (agent_id, operation_id)
        let matching_rules: Vec<&PolicyRule> = self
            .rules
            .iter()
            .filter(|r| r.agent_id == request.agent_id && r.operation_id == request.operation_id)
            .collect();

        if matching_rules.is_empty() {
            return Err(BoundaryError::PolicyDenied(format!(
                "No policy rule authorizes agent '{}' for operation '{}'",
                request.agent_id, request.operation_id
            )));
        }

        if matching_rules.len() > 1 {
            return Err(BoundaryError::PolicyDenied(format!(
                "Ambiguous authorization: multiple rules match agent '{}' and operation '{}'",
                request.agent_id, request.operation_id
            )));
        }

        let rule = matching_rules[0];

        // 3. Check expiration
        if let Some(expiry) = rule.valid_until {
            if now > expiry {
                return Err(BoundaryError::PolicyDenied(format!(
                    "Policy authorization for operation '{}' expired at {}",
                    rule.operation_id, expiry
                )));
            }
        }

        // 4. Validate URL destination
        let parsed_url = Url::parse(&request.destination_url).map_err(|e| {
            BoundaryError::DestinationViolation(format!("Malformed destination URL: {}", e))
        })?;

        // Validate scheme
        if rule.require_https && parsed_url.scheme() != "https" {
            return Err(BoundaryError::DestinationViolation(format!(
                "Insecure scheme '{}' rejected; HTTPS is required for operation '{}'",
                parsed_url.scheme(),
                rule.operation_id
            )));
        }

        // Validate host
        let host_str = parsed_url.host_str().ok_or_else(|| {
            BoundaryError::DestinationViolation("Destination URL lacks a valid host".to_string())
        })?;

        if !host_str.eq_ignore_ascii_case(&rule.destination_host) {
            return Err(BoundaryError::DestinationViolation(format!(
                "Destination host '{}' does not match policy approved host '{}'",
                host_str, rule.destination_host
            )));
        }

        // Validate port
        let default_port = match parsed_url.scheme() {
            "https" => 443,
            "http" => 80,
            _ => 0,
        };
        let effective_port = parsed_url.port().unwrap_or(default_port);
        let expected_port = rule.destination_port.unwrap_or(default_port);

        if effective_port != expected_port {
            return Err(BoundaryError::DestinationViolation(format!(
                "Destination port '{}' violates policy expected port '{}'",
                effective_port, expected_port
            )));
        }

        // 5. Validate HTTP method
        let method_upper = request.method.to_ascii_uppercase();
        if !rule
            .allowed_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&method_upper))
        {
            return Err(BoundaryError::OperationNotAllowed(format!(
                "Method '{}' is not in approved list: {:?}",
                request.method, rule.allowed_methods
            )));
        }

        // 6. Validate path and path traversal defense
        let path = parsed_url.path();

        // Check for traversal sequences in decoded or raw path
        if path_contains_traversal(path) {
            return Err(BoundaryError::OperationNotAllowed(
                "Path contains forbidden traversal sequence ('..')".to_string(),
            ));
        }

        // Strict segment-aware path prefix matching
        if !path_matches_prefix(path, &rule.allowed_path_prefix) {
            return Err(BoundaryError::OperationNotAllowed(format!(
                "Path '{}' does not match approved prefix '{}'",
                path, rule.allowed_path_prefix
            )));
        }

        // 7. Validate permitted query parameter keys
        for (query_key, _) in parsed_url.query_pairs() {
            if !rule
                .permitted_query_params
                .iter()
                .any(|p| p.eq_ignore_ascii_case(query_key.as_ref()))
            {
                return Err(BoundaryError::InvalidRequest(format!(
                    "Query parameter '{}' is not permitted by policy for operation '{}'",
                    query_key, rule.operation_id
                )));
            }
        }

        Ok(rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_request(url: &str) -> OperationRequest {
        OperationRequest {
            agent_id: "agent_alpha".to_string(),
            operation_id: "op_weather".to_string(),
            destination_url: url.to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    #[test]
    fn test_authorized_request_succeeds() {
        let mut engine = PolicyEngine::new();
        let mut rule = PolicyRule::new(
            "agent_alpha",
            "op_weather",
            "op://dev-vault/weather/api-key",
            "api.weather.example.com",
        );
        rule.allowed_path_prefix = "/v1/forecast".to_string();
        rule.permitted_query_params = vec!["city".to_string()];
        engine.add_rule(rule).unwrap();

        let req = sample_request("https://api.weather.example.com/v1/forecast?city=london");
        let res = engine.evaluate(&req, Utc::now());
        assert!(res.is_ok());
    }

    #[test]
    fn test_path_prefix_suffix_extension_blocked() {
        let mut engine = PolicyEngine::new();
        let mut rule = PolicyRule::new(
            "agent_alpha",
            "op_weather",
            "op://dev-vault/weather/api-key",
            "api.weather.example.com",
        );
        rule.allowed_path_prefix = "/v1/forecast".to_string();
        engine.add_rule(rule).unwrap();

        // Attempting to hit /v1/forecast-admin must be rejected!
        let req = sample_request("https://api.weather.example.com/v1/forecast-admin");
        let res = engine.evaluate(&req, Utc::now());
        assert!(matches!(res, Err(BoundaryError::OperationNotAllowed(_))));
    }

    #[test]
    fn test_port_tampering_blocked() {
        let mut engine = PolicyEngine::new();
        let rule = PolicyRule::new(
            "agent_alpha",
            "op_weather",
            "op://dev-vault/weather/api-key",
            "api.weather.example.com",
        );
        engine.add_rule(rule).unwrap();

        // Target trying to hit port 8443 when standard 443 is expected
        let req = sample_request("https://api.weather.example.com:8443/forecast");
        let res = engine.evaluate(&req, Utc::now());
        assert!(matches!(res, Err(BoundaryError::DestinationViolation(_))));
    }

    #[test]
    fn test_header_crlf_injection_blocked() {
        let mut engine = PolicyEngine::new();
        let rule = PolicyRule::new(
            "agent_alpha",
            "op_weather",
            "op://dev-vault/weather/api-key",
            "api.weather.example.com",
        );
        engine.add_rule(rule).unwrap();

        let mut req = sample_request("https://api.weather.example.com/");
        req.headers.insert(
            "X-Custom".to_string(),
            "injected\r\nSet-Cookie: evil=1".to_string(),
        );

        let res = engine.evaluate(&req, Utc::now());
        assert!(matches!(res, Err(BoundaryError::InvalidRequest(_))));
    }

    #[test]
    fn test_prefix_matching_is_segment_aware() {
        // The suffix-extension case: `/v1/forecast-admin` is a different
        // resource from `/v1/forecast` and must not match.
        assert!(path_matches_prefix("/v1/forecast", "/v1/forecast"));
        assert!(path_matches_prefix("/v1/forecast/today", "/v1/forecast"));
        assert!(!path_matches_prefix("/v1/forecast-admin", "/v1/forecast"));
        assert!(!path_matches_prefix("/v1/forecastx", "/v1/forecast"));
        assert!(!path_matches_prefix("/v1", "/v1/forecast"));
        // A trailing slash on the prefix is the same prefix.
        assert!(path_matches_prefix("/v1/forecast/today", "/v1/forecast/"));
        // An empty (root) prefix authorizes everything.
        assert!(path_matches_prefix("/anything", ""));
        assert!(path_matches_prefix("/anything", "/"));
    }

    #[test]
    fn test_encoded_traversal_is_detected() {
        // `%2e` and `%2E` are the percent-encoded spellings of `.`, so a
        // naive `..` check can be walked straight past.
        assert!(path_contains_traversal("/v1/../admin"));
        assert!(path_contains_traversal("/v1/%2e%2e/admin"));
        assert!(path_contains_traversal("/v1/%2E%2E/admin"));
        assert!(!path_contains_traversal("/v1/forecast"));
    }

    #[test]
    fn test_policy_rules_reject_unknown_fields() {
        // A mistyped key would otherwise be silently dropped, and a rule that
        // silently stops matching is a rule that silently stops authorizing.
        let json = r#"{
            "agent_id": "agent_alpha",
            "operation_id": "op_weather",
            "approved_credential_ref": "op://vault/item/key",
            "destination_host": "api.example.com",
            "allowed_methods": ["GET"],
            "allowed_path_prefix": "/v1",
            "permitted_query_params": [],
            "require_https": true,
            "permitted_query_param": ["city"]
        }"#;
        let err = serde_json::from_str::<PolicyRule>(json)
            .expect_err("an unknown policy field must be rejected");
        assert!(
            err.to_string().contains("permitted_query_param"),
            "the error must name the unknown field: {err}"
        );
    }
}
