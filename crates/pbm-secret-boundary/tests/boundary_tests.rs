use chrono::{Duration, Utc};
use pbm_secret_boundary::broker::SecretBoundaryBroker;
use pbm_secret_boundary::error::BoundaryError;
use pbm_secret_boundary::event::{
    verify_no_secrets_in_events, InMemoryAuditLogger, PolicyDecision,
};
use pbm_secret_boundary::operation::{
    HttpAdapterConfig, HttpOperationAdapter, MockDnsResolver, MockHttpTransport,
    MockOperationBackend, OperationRequest, RawHttpResponse,
};
use pbm_secret_boundary::policy::{PolicyEngine, PolicyRule};
use pbm_secret_boundary::provider::MockSecretProvider;
use pbm_secret_boundary::secret::SecretString;
use pbm_secret_boundary::SecretProvider;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;
use zeroize::Zeroize;

/// Helper to set up a standard test broker with a mock secret provider and in-memory logger.
fn setup_test_broker() -> (
    SecretBoundaryBroker,
    PolicyEngine,
    Arc<InMemoryAuditLogger>,
    Arc<MockSecretProvider>,
) {
    let mut policy_engine = PolicyEngine::new();

    let mut rule = PolicyRule::new(
        "agent-researcher",
        "fetch_forecast",
        "op://dev-vault/weather-service/api-key",
        "api.weather.example.com",
    );
    rule.allowed_methods = vec!["GET".to_string()];
    rule.allowed_path_prefix = "/v1/forecast".to_string();
    rule.permitted_query_params = vec!["city".to_string(), "units".to_string()];
    policy_engine.add_rule(rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let executor =
        Arc::new(MockOperationBackend::new().with_body(
            r#"{"temperature_c": 19.5, "condition": "Partly Cloudy", "city": "Seattle"}"#,
        ));
    let logger = Arc::new(InMemoryAuditLogger::new());

    let broker = SecretBoundaryBroker::new(
        policy_engine.clone(),
        provider.clone(),
        executor,
        logger.clone(),
    );

    (broker, policy_engine, logger, provider)
}

// 1. Authorized operation succeeds
#[test]
fn test_1_authorized_operation_succeeds() {
    let (broker, _, logger, _) = setup_test_broker();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast?city=Seattle&units=metric"
            .to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.status_code, 200);

    let body_str = String::from_utf8(response.sanitized_body).unwrap();
    assert!(body_str.contains("Partly Cloudy"));

    let events = logger.get_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, PolicyDecision::Allowed);
}

// 2. Unauthorized operation is denied
#[test]
fn test_2_unauthorized_operation_denied() {
    let (broker, _, logger, _) = setup_test_broker();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "unapproved_admin_wipe".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::PolicyDenied(_))));

    let events = logger.get_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, PolicyDecision::Denied);
}

// 3. An agent cannot select an arbitrary credential reference
#[test]
fn test_3_agent_cannot_select_arbitrary_credential_reference() {
    let (broker, _, _, _) = setup_test_broker();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "get_payment_token".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::PolicyDenied(_))));
}

// 4. An unapproved destination is rejected
#[test]
fn test_4_unapproved_destination_rejected() {
    let (broker, _, logger, _) = setup_test_broker();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://attacker.exfiltration-sink.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(
        result,
        Err(BoundaryError::DestinationViolation(_))
    ));

    let events = logger.get_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, PolicyDecision::Denied);
}

// 5. Malicious redirect and SSRF blocked across IPv4 and IPv6 variants
#[test]
fn test_5_malicious_redirect_and_ssrf_blocked() {
    let adapter = HttpOperationAdapter::new();

    // IPv4 loopback
    let loopback = Url::parse("https://127.0.0.1/admin/debug").unwrap();
    assert!(matches!(
        adapter.validate_ssrf_safety(&loopback),
        Err(BoundaryError::SsrfBlocked(_))
    ));

    // IPv4 cloud metadata
    let metadata_v4 = Url::parse("https://169.254.169.254/latest/meta-data").unwrap();
    assert!(matches!(
        adapter.validate_ssrf_safety(&metadata_v4),
        Err(BoundaryError::SsrfBlocked(_))
    ));

    // IPv6 loopback
    let loopback_v6 = Url::parse("https://[::1]/debug").unwrap();
    assert!(matches!(
        adapter.validate_ssrf_safety(&loopback_v6),
        Err(BoundaryError::SsrfBlocked(_))
    ));

    // IPv4-mapped IPv6 loopback
    let mapped_loopback = Url::parse("https://[::ffff:127.0.0.1]/debug").unwrap();
    assert!(matches!(
        adapter.validate_ssrf_safety(&mapped_loopback),
        Err(BoundaryError::SsrfBlocked(_))
    ));

    // IPv4-mapped IPv6 metadata
    let mapped_meta = Url::parse("https://[::ffff:169.254.169.254]/latest/meta-data").unwrap();
    assert!(matches!(
        adapter.validate_ssrf_safety(&mapped_meta),
        Err(BoundaryError::SsrfBlocked(_))
    ));

    // AWS IMDSv6
    let imdsv6 = Url::parse("https://[fd00:ec2::254]/latest/api/token").unwrap();
    assert!(matches!(
        adapter.validate_ssrf_safety(&imdsv6),
        Err(BoundaryError::SsrfBlocked(_))
    ));
}

// 6. Invalid policy configuration fails safely (fail-closed)
#[test]
fn test_6_invalid_policy_fails_safely() {
    let empty_engine = PolicyEngine::new();
    let provider = Arc::new(MockSecretProvider::new());
    let executor = Arc::new(MockOperationBackend::new());
    let logger = Arc::new(InMemoryAuditLogger::new());

    let broker = SecretBoundaryBroker::new(empty_engine, provider, executor, logger);

    let req = OperationRequest {
        agent_id: "any-agent".to_string(),
        operation_id: "any-op".to_string(),
        destination_url: "https://example.com/api".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::PolicyDenied(_))));

    // Ambiguous policy collision check
    let mut collision_engine = PolicyEngine::new();
    let rule1 = PolicyRule::new("agent-1", "op-1", "op://vault/a", "example.com");
    let rule2 = PolicyRule::new("agent-1", "op-1", "op://vault/b", "example.com");
    assert!(collision_engine.add_rule(rule1).is_ok());
    assert!(collision_engine.add_rule(rule2).is_err());
}

// 7. Provider failures do not disclose credential values
#[test]
fn test_7_provider_failure_does_not_disclose_credential() {
    let mut policy_engine = PolicyEngine::new();
    let rule = PolicyRule::new(
        "agent-researcher",
        "fetch_forecast",
        "op://nonexistent-vault/missing-item/secret",
        "api.weather.example.com",
    );
    policy_engine.add_rule(rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let executor = Arc::new(MockOperationBackend::new());
    let logger = Arc::new(InMemoryAuditLogger::new());

    let broker = SecretBoundaryBroker::new(policy_engine, provider, executor, logger);

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::SecretNotFound(_))));

    if let Err(BoundaryError::SecretNotFound(ref_name)) = result {
        assert_eq!(ref_name, "op://nonexistent-vault/missing-item/secret");
    }
}

// 8. Credential values never appear in audit events or agent-facing responses
#[test]
fn test_8_credential_values_never_appear_in_audit_or_response() {
    let (broker, _, logger, provider) = setup_test_broker();
    let secret = provider
        .get_secret("op://dev-vault/weather-service/api-key")
        .unwrap();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast?city=Seattle".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req).unwrap();
    let body_str = String::from_utf8(result.sanitized_body).unwrap();

    assert!(!body_str.contains(secret.expose_secret()));

    let events = logger.get_events();
    assert!(verify_no_secrets_in_events(&events, &secret));
}

// 9. Tool or transport errors do not leak secrets
#[test]
fn test_9_transport_error_does_not_leak_secrets() {
    let mut policy_engine = PolicyEngine::new();
    let rule = PolicyRule::new(
        "agent-researcher",
        "fetch_forecast",
        "op://dev-vault/weather-service/api-key",
        "api.weather.example.com",
    );
    policy_engine.add_rule(rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let executor = Arc::new(MockOperationBackend::new().with_failure(true));
    let logger = Arc::new(InMemoryAuditLogger::new());

    let broker =
        SecretBoundaryBroker::new(policy_engine, provider.clone(), executor, logger.clone());
    let secret = provider
        .get_secret("op://dev-vault/weather-service/api-key")
        .unwrap();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::ExecutionFailed(_))));

    let err_msg = format!("{}", result.unwrap_err());
    assert!(!err_msg.contains(secret.expose_secret()));

    let events = logger.get_events();
    assert!(verify_no_secrets_in_events(&events, &secret));
}

// 10. Authorization expiry behaves as specified
#[test]
fn test_10_authorization_expiry_fails_closed() {
    let mut policy_engine = PolicyEngine::new();

    let mut expired_rule = PolicyRule::new(
        "agent-researcher",
        "fetch_forecast",
        "op://dev-vault/weather-service/api-key",
        "api.weather.example.com",
    );
    expired_rule.valid_until = Some(Utc::now() - Duration::hours(1));
    policy_engine.add_rule(expired_rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let executor = Arc::new(MockOperationBackend::new());
    let logger = Arc::new(InMemoryAuditLogger::new());

    let broker = SecretBoundaryBroker::new(policy_engine, provider, executor, logger);

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::PolicyDenied(_))));
    if let Err(BoundaryError::PolicyDenied(msg)) = result {
        assert!(msg.contains("expired"));
    }
}

// 11. Port tampering is blocked
#[test]
fn test_11_port_tampering_blocked() {
    let (broker, _, _, _) = setup_test_broker();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com:8443/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(
        result,
        Err(BoundaryError::DestinationViolation(_))
    ));
}

// 12. Path suffix extension and traversal are blocked
#[test]
fn test_12_path_suffix_extension_and_traversal_blocked() {
    let (broker, _, _, _) = setup_test_broker();

    // Suffix extension attack (/v1/forecast-admin trying to match /v1/forecast)
    let req_suffix = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast-admin/keys".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };
    assert!(matches!(
        broker.execute(req_suffix),
        Err(BoundaryError::OperationNotAllowed(_))
    ));

    // Traversal attack
    let req_traversal = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast/../admin".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };
    assert!(matches!(
        broker.execute(req_traversal),
        Err(BoundaryError::OperationNotAllowed(_))
    ));
}

// 13. Header CRLF injection is blocked
#[test]
fn test_13_header_crlf_injection_blocked() {
    let (broker, _, _, _) = setup_test_broker();

    let mut headers = HashMap::new();
    headers.insert(
        "X-Injected".to_string(),
        "attack\r\nAuthorization: Bearer stolen".to_string(),
    );

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers,
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::InvalidRequest(_))));
}

// 14. Memory zeroization clears the internal buffer
#[test]
fn test_14_memory_zeroization_clears_buffer() {
    let mut secret = SecretString::new("super-secret-temporary-token-1234");
    assert!(!secret.as_raw_bytes().iter().all(|&b| b == 0));

    secret.zeroize();
    assert!(secret.as_raw_bytes().iter().all(|&b| b == 0));
}

// 15. Conversion to PBM Schema Version 2 format produces compliant event
#[test]
fn test_15_pbm_schema_version_2_compliance() {
    let (broker, _, logger, _) = setup_test_broker();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast?city=Seattle".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    assert!(broker.execute(req).is_ok());

    let events = logger.get_events();
    assert_eq!(events.len(), 1);

    let pbm_event = events[0].to_pbm_shield_event("tenant-production");
    assert_eq!(pbm_event.schema_version, 2);
    // Emitted under mcp-shield to satisfy PBM schema enum: ["mcp-shield", "vector-anchor", "trace-audit"]
    assert_eq!(pbm_event.module, "mcp-shield");
    assert_eq!(pbm_event.outcome, Some("allowed".to_string()));
    assert_eq!(pbm_event.policy_version, Some("secret-boundary/1"));
    assert_eq!(pbm_event.details["subsystem"], "secret-boundary");

    let serialized = serde_json::to_string(&pbm_event).unwrap();
    assert!(serialized.contains(r#""schema_version":2"#));
    assert!(serialized.contains(r#""module":"mcp-shield""#));
    assert!(serialized.contains(r#""subsystem":"secret-boundary""#));

    // The module is not caller-selectable: the shared event contract
    // enumerates it, and the dashboard rejects anything else with a
    // permanent 422, which would dead-letter the event instead of
    // ingesting it. A caller-supplied module name would be a way to build
    // an event that can never arrive.
    assert!(
        ["mcp-shield", "vector-anchor", "trace-audit"].contains(&pbm_event.module),
        "module '{}' is not in the shared event contract",
        pbm_event.module
    );
}

// 16. DNS rebinding simulation fails closed
#[test]
fn test_16_dns_rebinding_simulation_fails_closed() {
    let mock_resolver = Arc::new(MockDnsResolver::new());
    let mock_transport = Arc::new(MockHttpTransport::new());

    // Adversarial DNS rebinding: approved domain resolves to loopback
    mock_resolver.insert(
        "rebind-target.example.com",
        443,
        vec![SocketAddr::from(([127, 0, 0, 1], 443))],
    );

    let adapter = Arc::new(HttpOperationAdapter::with_resolver_and_transport(
        HttpAdapterConfig::default(),
        mock_resolver.clone(),
        mock_transport.clone(),
    ));

    let mut policy_engine = PolicyEngine::new();
    let mut rule = PolicyRule::new(
        "agent-researcher",
        "fetch_data",
        "op://dev-vault/weather-service/api-key",
        "rebind-target.example.com",
    );
    rule.allowed_methods = vec!["GET".to_string()];
    rule.allowed_path_prefix = "/v1/data".to_string();
    policy_engine.add_rule(rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let logger = Arc::new(InMemoryAuditLogger::new());
    let broker = SecretBoundaryBroker::new(policy_engine, provider, adapter, logger);

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_data".to_string(),
        destination_url: "https://rebind-target.example.com/v1/data".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::SsrfBlocked(_))));
}

// 17. Multi-IP DNS response with one unsafe IP fails closed
#[test]
fn test_17_multi_ip_dns_response_with_one_unsafe_ip_fails_closed() {
    let mock_resolver = Arc::new(MockDnsResolver::new());
    let mock_transport = Arc::new(MockHttpTransport::new());

    // Adversarial split response: benign public IP + AWS IMDS IP
    mock_resolver.insert(
        "split-horizon.example.com",
        443,
        vec![
            SocketAddr::from(([93, 184, 216, 34], 443)),
            SocketAddr::from(([169, 254, 169, 254], 443)),
        ],
    );

    let adapter = Arc::new(HttpOperationAdapter::with_resolver_and_transport(
        HttpAdapterConfig::default(),
        mock_resolver,
        mock_transport,
    ));

    let url = Url::parse("https://split-horizon.example.com/v1/data").unwrap();
    let result = adapter.resolve_and_pin_destination(&url);
    assert!(matches!(result, Err(BoundaryError::SsrfBlocked(_))));
}

// 18. Connection pinning provides validated socket addresses to transport
#[test]
fn test_18_connection_pinning_prevents_secondary_dns_lookup() {
    let mock_resolver = Arc::new(MockDnsResolver::new());
    let mock_transport = Arc::new(MockHttpTransport::new());

    let safe_addr = SocketAddr::from(([93, 184, 216, 34], 443));
    mock_resolver.insert("safe-pinned.example.com", 443, vec![safe_addr]);

    let adapter = Arc::new(HttpOperationAdapter::with_resolver_and_transport(
        HttpAdapterConfig::default(),
        mock_resolver,
        mock_transport.clone(),
    ));

    let mut policy_engine = PolicyEngine::new();
    let mut rule = PolicyRule::new(
        "agent-researcher",
        "fetch_pinned",
        "op://dev-vault/weather-service/api-key",
        "safe-pinned.example.com",
    );
    rule.allowed_methods = vec!["GET".to_string()];
    rule.allowed_path_prefix = "/v1/pinned".to_string();
    policy_engine.add_rule(rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let logger = Arc::new(InMemoryAuditLogger::new());
    let broker = SecretBoundaryBroker::new(policy_engine, provider, adapter, logger);

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_pinned".to_string(),
        destination_url: "https://safe-pinned.example.com/v1/pinned".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(result.is_ok());

    let recorded = mock_transport.get_recorded_requests();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].pinned_addrs, vec![safe_addr]);
    assert_eq!(recorded[0].host_header, "safe-pinned.example.com");
}

// 19. HTTP redirects are strictly rejected without following
#[test]
fn test_19_redirect_response_is_rejected_without_following() {
    let mock_resolver = Arc::new(MockDnsResolver::new());
    let mock_transport = Arc::new(MockHttpTransport::new());

    mock_resolver.insert(
        "redirect-src.example.com",
        443,
        vec![SocketAddr::from(([93, 184, 216, 34], 443))],
    );

    // Mock upstream returns HTTP 302 redirect
    mock_transport.set_response(
        "/v1/redirect",
        Ok(RawHttpResponse {
            status_code: 302,
            headers: HashMap::from([(
                "Location".to_string(),
                "https://attacker.com/harvest".to_string(),
            )]),
            body: b"Redirecting...".to_vec(),
        }),
    );

    let adapter = Arc::new(HttpOperationAdapter::with_resolver_and_transport(
        HttpAdapterConfig::default(),
        mock_resolver,
        mock_transport,
    ));

    let mut policy_engine = PolicyEngine::new();
    let mut rule = PolicyRule::new(
        "agent-researcher",
        "fetch_redirect",
        "op://dev-vault/weather-service/api-key",
        "redirect-src.example.com",
    );
    rule.allowed_methods = vec!["GET".to_string()];
    rule.allowed_path_prefix = "/v1/redirect".to_string();
    policy_engine.add_rule(rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let logger = Arc::new(InMemoryAuditLogger::new());
    let broker = SecretBoundaryBroker::new(policy_engine, provider, adapter, logger);

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_redirect".to_string(),
        destination_url: "https://redirect-src.example.com/v1/redirect".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(
        result,
        Err(BoundaryError::DestinationViolation(_))
    ));
}

// 20. Transport response size limit is enforced
#[test]
fn test_20_transport_response_size_limit_enforced() {
    let mock_resolver = Arc::new(MockDnsResolver::new());
    let mock_transport = Arc::new(MockHttpTransport::new());

    mock_resolver.insert(
        "large-resp.example.com",
        443,
        vec![SocketAddr::from(([93, 184, 216, 34], 443))],
    );

    // Simulate 2000 byte response
    mock_transport.set_response(
        "/v1/large",
        Ok(RawHttpResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: vec![b'A'; 2000],
        }),
    );

    let config = HttpAdapterConfig {
        max_response_bytes: 1000, // 1000 byte limit
        ..Default::default()
    };
    let adapter = Arc::new(HttpOperationAdapter::with_resolver_and_transport(
        config,
        mock_resolver,
        mock_transport,
    ));

    let mut policy_engine = PolicyEngine::new();
    let mut rule = PolicyRule::new(
        "agent-researcher",
        "fetch_large",
        "op://dev-vault/weather-service/api-key",
        "large-resp.example.com",
    );
    rule.allowed_methods = vec!["GET".to_string()];
    rule.allowed_path_prefix = "/v1/large".to_string();
    policy_engine.add_rule(rule).unwrap();

    let provider = Arc::new(MockSecretProvider::new());
    let logger = Arc::new(InMemoryAuditLogger::new());
    let broker = SecretBoundaryBroker::new(policy_engine, provider, adapter, logger);

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_large".to_string(),
        destination_url: "https://large-resp.example.com/v1/large".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    let result = broker.execute(req);
    assert!(matches!(result, Err(BoundaryError::TransportError(_))));
}

// 21. Strict PBM Schema Version 2 JSON contract verification
#[test]
fn test_21_pbm_schema_v2_strict_json_contract_validation() {
    let (broker, _, logger, _) = setup_test_broker();

    let req = OperationRequest {
        agent_id: "agent-researcher".to_string(),
        operation_id: "fetch_forecast".to_string(),
        destination_url: "https://api.weather.example.com/v1/forecast".to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
    };

    assert!(broker.execute(req).is_ok());

    let events = logger.get_events();
    let pbm_event = events[0].to_pbm_shield_event("prod-tenant-01");
    let json_val = serde_json::to_value(&pbm_event).unwrap();
    let obj = json_val.as_object().unwrap();

    // 1. Check all required properties according to event-envelope.v2.schema.json
    let required = [
        "event_id",
        "schema_version",
        "timestamp_ms",
        "module",
        "event_type",
        "severity",
        "details",
        "source",
        "tenant_id",
    ];
    for req_field in &required {
        assert!(
            obj.contains_key(*req_field),
            "Missing required field: {}",
            req_field
        );
    }

    // 2. Additional properties check (additionalProperties: false in schema)
    let allowed_properties = [
        "event_id",
        "schema_version",
        "timestamp_ms",
        "module",
        "event_type",
        "severity",
        "details",
        "source",
        "tenant_id",
        "agent_id",
        "session_id",
        "trace_id",
        "correlation_id",
        "resource_type",
        "resource_id",
        "outcome",
        "policy_version",
    ];
    for key in obj.keys() {
        assert!(
            allowed_properties.contains(&key.as_str()),
            "Unexpected property '{}' violates additionalProperties: false",
            key
        );
    }

    // 3. Check enum constraints
    let module_enum = ["mcp-shield", "vector-anchor", "trace-audit"];
    assert!(module_enum.contains(&obj["module"].as_str().unwrap()));

    let severity_enum = ["info", "warning", "critical"];
    assert!(severity_enum.contains(&obj["severity"].as_str().unwrap()));

    // 4. Check schema_version const == 2
    assert_eq!(obj["schema_version"].as_i64().unwrap(), 2);

    // 5. Check timestamp_ms integer range
    let ts = obj["timestamp_ms"].as_u64().unwrap();
    assert!((1..=32503680000000).contains(&ts));

    // 6. Check UUID format
    let uuid_str = obj["event_id"].as_str().unwrap();
    let uuid_re =
        regex::Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .unwrap();
    assert!(
        uuid_re.is_match(uuid_str),
        "event_id is not a valid RFC 4122 v4 UUID: {}",
        uuid_str
    );
}
