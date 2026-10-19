use crate::error::BoundaryError;
use crate::event::{
    generate_uuid_v4, AuditLogger, ExecutionOutcome, InMemoryAuditLogger, PolicyDecision,
    SecurityEvent,
};
use crate::operation::{
    MockOperationBackend, OperationExecutor, OperationRequest, OperationResponse,
};
use crate::policy::PolicyEngine;
use crate::provider::{MockSecretProvider, SecretProvider};
use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use url::Url;

static CORRELATION_COUNTER: AtomicU64 = AtomicU64::new(1000);

/// Central security broker coordinating policy evaluation, credential resolution,
/// operation execution, and security event auditing.
pub struct SecretBoundaryBroker {
    policy_engine: PolicyEngine,
    provider: Arc<dyn SecretProvider>,
    executor: Arc<dyn OperationExecutor>,
    logger: Arc<dyn AuditLogger>,
}

impl SecretBoundaryBroker {
    /// Creates a new `SecretBoundaryBroker`.
    pub fn new(
        policy_engine: PolicyEngine,
        provider: Arc<dyn SecretProvider>,
        executor: Arc<dyn OperationExecutor>,
        logger: Arc<dyn AuditLogger>,
    ) -> Self {
        Self {
            policy_engine,
            provider,
            executor,
            logger,
        }
    }

    /// Creates a default broker configured for offline mock development and testing.
    pub fn default_mock() -> (Self, Arc<InMemoryAuditLogger>) {
        let logger = Arc::new(InMemoryAuditLogger::new());
        let broker = Self {
            policy_engine: PolicyEngine::new(),
            provider: Arc::new(MockSecretProvider::new()),
            executor: Arc::new(MockOperationBackend::new()),
            logger: logger.clone(),
        };
        (broker, logger)
    }

    /// Primary entry point: Handles an agent operation request through the secret boundary.
    ///
    /// # Workflow & Security Invariants
    /// 1. Evaluates fail-closed policy against caller identity and target operation.
    /// 2. If policy denies, an audit event is emitted and execution halts.
    /// 3. Resolves the policy-mandated credential reference via the configured provider.
    /// 4. Executes the approved operation adapter with internal secret injection.
    /// 5. Cleans and zeroizes secret buffers in memory.
    /// 6. Sanitizes and returns the response without exposing raw credentials.
    pub fn execute(&self, request: OperationRequest) -> Result<OperationResponse, BoundaryError> {
        let now = Utc::now();
        let counter = CORRELATION_COUNTER.fetch_add(1, Ordering::Relaxed);
        let correlation_id = format!("corr-{}-{}", now.timestamp_millis(), counter);

        let parsed_host = Url::parse(&request.destination_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_else(|| "unknown-host".to_string());

        // Step 1: Policy Evaluation
        let policy_rule = match self.policy_engine.evaluate(&request, now) {
            Ok(rule) => rule,
            Err(err) => {
                let event = SecurityEvent {
                    event_id: generate_uuid_v4(),
                    timestamp: now,
                    correlation_id,
                    agent_id: request.agent_id,
                    operation_id: request.operation_id,
                    decision: PolicyDecision::Denied,
                    denial_reason: Some(err.to_string()),
                    credential_ref: None,
                    destination_host: parsed_host,
                    outcome: ExecutionOutcome::NotExecuted,
                    duration_ms: Some(0),
                };
                self.logger.log_event(&event);
                return Err(err);
            }
        };

        let credential_ref = policy_rule.approved_credential_ref.clone();

        // Step 2: Credential Resolution
        let secret = match self.provider.get_secret(&credential_ref) {
            Ok(sec) => sec,
            Err(err) => {
                let event = SecurityEvent {
                    event_id: generate_uuid_v4(),
                    timestamp: now,
                    correlation_id,
                    agent_id: request.agent_id,
                    operation_id: request.operation_id,
                    decision: PolicyDecision::Allowed,
                    denial_reason: None,
                    credential_ref: Some(credential_ref),
                    destination_host: parsed_host,
                    outcome: ExecutionOutcome::Failure,
                    duration_ms: Some(0),
                };
                self.logger.log_event(&event);
                return Err(err);
            }
        };

        // Step 3: Approved Operation Execution
        let execution_result = self.executor.execute(&request, &secret);

        // Explicit drop to guarantee immediate memory zeroization
        drop(secret);

        match execution_result {
            Ok(response) => {
                let event = SecurityEvent {
                    event_id: generate_uuid_v4(),
                    timestamp: now,
                    correlation_id,
                    agent_id: request.agent_id,
                    operation_id: request.operation_id,
                    decision: PolicyDecision::Allowed,
                    denial_reason: None,
                    credential_ref: Some(credential_ref),
                    destination_host: parsed_host,
                    outcome: ExecutionOutcome::Success,
                    duration_ms: Some(response.duration_ms),
                };
                self.logger.log_event(&event);
                Ok(response)
            }
            Err(err) => {
                let event = SecurityEvent {
                    event_id: generate_uuid_v4(),
                    timestamp: now,
                    correlation_id,
                    agent_id: request.agent_id,
                    operation_id: request.operation_id,
                    decision: PolicyDecision::Allowed,
                    denial_reason: None,
                    credential_ref: Some(credential_ref),
                    destination_host: parsed_host,
                    outcome: ExecutionOutcome::Failure,
                    duration_ms: Some(0),
                };
                self.logger.log_event(&event);
                Err(err)
            }
        }
    }
}
