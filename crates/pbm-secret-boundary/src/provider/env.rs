use super::SecretProvider;
use crate::error::BoundaryError;
use crate::secret::SecretString;
use zeroize::Zeroize;

/// Default required environment variable prefix for [`EnvSecretProvider`].
pub const DEFAULT_ENV_SECRET_PREFIX: &str = "PBM_SECRET_";

/// Credential provider that resolves policy-bound secrets from process environment variables.
///
/// # Security Invariants
/// - Only environment variables beginning with the configured prefix (`PBM_SECRET_` by default)
///   and consisting exclusively of uppercase ASCII alphanumeric characters and underscores
///   (`[A-Z0-9_]+`) may be read.
/// - Accepts references formatted either as `env://<VAR_NAME>` or `<VAR_NAME>`.
/// - Trims trailing whitespace/newlines (`\r`, `\n`, `' '`, `'\t'`) from the resolved value
///   and rejects empty values as [`BoundaryError::SecretNotFound`].
/// - Rejects values containing control characters as [`BoundaryError::InvalidRequest`]:
///   a secret is injected into an HTTP header value, and a control character
///   would end that header early and inject further headers into the request.
/// - Error messages never include raw secret values.
#[derive(Debug, Clone)]
pub struct EnvSecretProvider {
    prefix: String,
}

impl EnvSecretProvider {
    /// Creates an [`EnvSecretProvider`] enforcing the default `"PBM_SECRET_"` prefix.
    pub fn new() -> Self {
        Self {
            prefix: DEFAULT_ENV_SECRET_PREFIX.to_string(),
        }
    }

    /// Creates an [`EnvSecretProvider`] with a custom required environment variable prefix.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Returns the configured environment variable prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Validates a secret reference (`env://<VAR_NAME>` or `<VAR_NAME>`) and returns the
    /// underlying environment variable name if valid.
    pub fn validate_var_name<'a>(&self, secret_ref: &'a str) -> Result<&'a str, BoundaryError> {
        let var_name = secret_ref.strip_prefix("env://").unwrap_or(secret_ref);

        if var_name.is_empty() || var_name.len() > 256 {
            return Err(BoundaryError::InvalidRequest(format!(
                "Environment secret reference '{}' is empty or exceeds maximum length",
                secret_ref
            )));
        }

        if !var_name.starts_with(&self.prefix) || var_name.len() <= self.prefix.len() {
            return Err(BoundaryError::InvalidRequest(format!(
                "Environment secret variable '{}' must begin with prefix '{}'",
                var_name, self.prefix
            )));
        }

        if !var_name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(BoundaryError::InvalidRequest(format!(
                "Environment secret variable '{}' must contain only [A-Z0-9_]",
                var_name
            )));
        }

        Ok(var_name)
    }
}

impl Default for EnvSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for EnvSecretProvider {
    fn name(&self) -> &'static str {
        "env"
    }

    fn get_secret(&self, secret_ref: &str) -> Result<SecretString, BoundaryError> {
        let var_name = self.validate_var_name(secret_ref)?;

        match std::env::var(var_name) {
            Ok(mut raw_val) => {
                let trimmed = raw_val.trim_end_matches(['\r', '\n', ' ', '\t']);
                if trimmed.is_empty() {
                    raw_val.zeroize();
                    return Err(BoundaryError::SecretNotFound(format!(
                        "Environment secret '{}' is empty",
                        secret_ref
                    )));
                }
                // A secret is injected into an HTTP header value. A value that
                // carries a control character cannot be placed in one: it
                // would terminate the header early and inject headers of the
                // caller's choosing into the outbound request. Rejecting it
                // here fails loudly at the source instead of producing a
                // malformed request later.
                if trimmed.chars().any(char::is_control) {
                    raw_val.zeroize();
                    return Err(BoundaryError::InvalidRequest(format!(
                        "Environment secret '{}' contains control characters and cannot be used as a header value",
                        secret_ref
                    )));
                }
                let secret = SecretString::new(trimmed);
                raw_val.zeroize();
                Ok(secret)
            }
            Err(std::env::VarError::NotPresent) => {
                Err(BoundaryError::SecretNotFound(secret_ref.to_string()))
            }
            Err(std::env::VarError::NotUnicode(_)) => Err(BoundaryError::ProviderError(format!(
                "Environment variable '{}' is not valid UTF-8",
                var_name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_env_provider_resolves_prefixed_and_uri_references() {
        let _guard = ENV_LOCK.lock().unwrap();
        let var_name = "PBM_SECRET_WEATHER_API_KEY";
        std::env::set_var(var_name, "live-secret-token-4455\r\n");

        let provider = EnvSecretProvider::new();
        assert_eq!(provider.name(), "env");

        let s1 = provider
            .get_secret("env://PBM_SECRET_WEATHER_API_KEY")
            .unwrap();
        assert_eq!(s1.expose_secret(), "live-secret-token-4455");

        let s2 = provider.get_secret("PBM_SECRET_WEATHER_API_KEY").unwrap();
        assert_eq!(s2.expose_secret(), "live-secret-token-4455");

        std::env::remove_var(var_name);
    }

    #[test]
    fn test_env_provider_rejects_unprefixed_or_malformed_names() {
        let provider = EnvSecretProvider::new();

        // Missing PBM_SECRET_ prefix
        assert!(matches!(
            provider.get_secret("env://PATH"),
            Err(BoundaryError::InvalidRequest(_))
        ));
        assert!(matches!(
            provider.get_secret("AWS_SECRET_ACCESS_KEY"),
            Err(BoundaryError::InvalidRequest(_))
        ));
        // Only the bare prefix with no variable suffix
        assert!(matches!(
            provider.get_secret("env://PBM_SECRET_"),
            Err(BoundaryError::InvalidRequest(_))
        ));
        // Lowercase or special chars
        assert!(matches!(
            provider.get_secret("env://PBM_SECRET_lower"),
            Err(BoundaryError::InvalidRequest(_))
        ));
        assert!(matches!(
            provider.get_secret("env://PBM_SECRET_KEY-1"),
            Err(BoundaryError::InvalidRequest(_))
        ));
    }

    #[test]
    fn test_env_provider_rejects_values_with_control_characters() {
        let _guard = ENV_LOCK.lock().unwrap();
        let var_name = "PBM_SECRET_MULTILINE_TEST_TOKEN";
        // A value with an embedded newline would end the Authorization header
        // early and inject a header of its own choosing into the request.
        std::env::set_var(var_name, "first-line\r\nX-Injected: yes");

        let provider = EnvSecretProvider::new();
        let error = provider
            .get_secret("env://PBM_SECRET_MULTILINE_TEST_TOKEN")
            .unwrap_err();
        assert!(matches!(error, BoundaryError::InvalidRequest(_)));
        // The message must not carry the value.
        assert!(!error.to_string().contains("X-Injected"));

        std::env::remove_var(var_name);
    }

    #[test]
    fn test_env_provider_rejects_missing_or_empty_values_without_leaking() {
        let _guard = ENV_LOCK.lock().unwrap();
        let empty_var = "PBM_SECRET_EMPTY_TEST_TOKEN";
        std::env::set_var(empty_var, "   \r\n");

        let provider = EnvSecretProvider::new();
        let err_empty = provider
            .get_secret("env://PBM_SECRET_EMPTY_TEST_TOKEN")
            .unwrap_err();
        assert!(matches!(err_empty, BoundaryError::SecretNotFound(_)));

        std::env::remove_var(empty_var);

        let err_missing = provider
            .get_secret("env://PBM_SECRET_DOES_NOT_EXIST_999")
            .unwrap_err();
        assert!(matches!(err_missing, BoundaryError::SecretNotFound(_)));
    }
}
