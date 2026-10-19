pub mod mock;
pub mod onepassword;

use crate::error::BoundaryError;
use crate::secret::SecretString;

pub use mock::MockSecretProvider;
pub use onepassword::{
    validate_account_identifier, validate_cli_path, validate_secret_reference,
    validate_trusted_cli_path, MockInvocation, MockSubprocessRunner, OnePasswordAuthMode,
    OnePasswordCliConfig, OnePasswordCliProvider, ParsedSecretReference, StandardSubprocessRunner,
    SubprocessOutput, SubprocessRunner,
};

/// Abstraction for retrieving an authorized secret from an external or local provider.
///
/// Implementations must uphold the invariant that errors returned from `get_secret`
/// never contain actual credential values.
pub trait SecretProvider: Send + Sync {
    /// Human-readable identifier for the provider (e.g., "mock", "1password-cli").
    fn name(&self) -> &'static str;

    /// Retrieves the secret identified by the canonical reference URI (e.g. `op://...`).
    fn get_secret(&self, secret_ref: &str) -> Result<SecretString, BoundaryError>;
}
