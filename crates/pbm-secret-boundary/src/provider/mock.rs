use super::SecretProvider;
use crate::error::BoundaryError;
use crate::secret::SecretString;
use std::collections::HashMap;

/// Development provider returning synthetic credentials for testing and offline environments.
///
/// This is the default provider used by PBM Secret Boundary. It avoids requiring any
/// live accounts, licenses, or network access.
#[derive(Debug, Clone)]
pub struct MockSecretProvider {
    secrets: HashMap<String, SecretString>,
}

impl MockSecretProvider {
    /// Creates a new `MockSecretProvider` populated with standard synthetic development credentials.
    pub fn new() -> Self {
        let mut secrets = HashMap::new();
        secrets.insert(
            "op://dev-vault/weather-service/api-key".to_string(),
            SecretString::new("synthetic-weather-dev-token-9988"),
        );
        secrets.insert(
            "op://dev-vault/metrics-pipeline/token".to_string(),
            SecretString::new("synthetic-metrics-dev-token-5544"),
        );
        secrets.insert(
            "op://dev-vault/payment-gateway/test-key".to_string(),
            SecretString::new("synthetic-payment-dev-token-1122"),
        );
        Self { secrets }
    }

    /// Inserts a synthetic credential mapping for testing scenarios.
    pub fn insert_synthetic(&mut self, secret_ref: impl Into<String>, value: impl AsRef<str>) {
        self.secrets
            .insert(secret_ref.into(), SecretString::new(value));
    }
}

impl Default for MockSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for MockSecretProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn get_secret(&self, secret_ref: &str) -> Result<SecretString, BoundaryError> {
        self.secrets
            .get(secret_ref)
            .cloned()
            .ok_or_else(|| BoundaryError::SecretNotFound(secret_ref.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_provider_retrieval() {
        let provider = MockSecretProvider::new();
        let secret = provider
            .get_secret("op://dev-vault/weather-service/api-key")
            .unwrap();
        assert_eq!(secret.expose_secret(), "synthetic-weather-dev-token-9988");
    }

    #[test]
    fn test_mock_provider_missing_secret() {
        let provider = MockSecretProvider::new();
        let err = provider
            .get_secret("op://dev-vault/non-existent")
            .unwrap_err();
        assert_eq!(
            err,
            BoundaryError::SecretNotFound("op://dev-vault/non-existent".to_string())
        );
    }
}
