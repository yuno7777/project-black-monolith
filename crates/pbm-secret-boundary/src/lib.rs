//! # PBM Secret Boundary
//!
//! An independent, security-focused Rust boundary component designed to integrate
//! with Project Black Monolith (PBM) AI-agent security middleware.
//!
//! ## Core Security Invariants
//! 1. **No Raw Secrets to Models**: AI models and agent runtimes never receive raw credential strings.
//! 2. **Explicit Operation Allowlist**: Agents only trigger pre-approved, parameterized operations.
//! 3. **Policy-Bound Secrets**: Agents cannot specify or choose credential identifiers; secrets are bound by policy.
//! 4. **Zeroization & Redaction**: Sensitive secret bytes are memory-zeroized upon drop, and Debug/Display representations are redacted.
//! 5. **SSRF & Redirect Defense**: Strict host allowlisting, safe URL validation, and refusal of unauthorized redirects.
//! 6. **Sanitized Auditing**: Audit logs and security event streams record reference keys and hashes, never plaintext secrets.

pub mod adapter;
pub mod broker;
pub mod error;
pub mod event;
pub mod operation;
pub mod policy;
pub mod provider;
pub mod secret;

pub use broker::SecretBoundaryBroker;
pub use chrono;
pub use error::BoundaryError;
pub use event::{AuditLogger, InMemoryAuditLogger, PbmShieldEvent, PolicyDecision, SecurityEvent};
pub use operation::{
    HttpOperationAdapter, MockOperationBackend, OperationExecutor, OperationRequest,
    OperationResponse,
};
pub use policy::{path_contains_traversal, path_matches_prefix, PolicyEngine, PolicyRule};
pub use provider::{
    validate_account_identifier, validate_cli_path, validate_secret_reference,
    validate_trusted_cli_path, EnvSecretProvider, MockInvocation, MockSecretProvider,
    MockSubprocessRunner, OnePasswordAuthMode, OnePasswordCliConfig, OnePasswordCliProvider,
    ParsedSecretReference, SecretProvider, StandardSubprocessRunner, SubprocessOutput,
    SubprocessRunner, DEFAULT_ENV_SECRET_PREFIX,
};
pub use secret::SecretString;
