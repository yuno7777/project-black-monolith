use crate::error::BoundaryError;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A memory-zeroizing container for sensitive secret strings.
///
/// # Security Invariants
/// 1. **Debug & Display Redaction**: `Debug` and `Display` implementations always print `"[REDACTED SECRET]"`
///    to prevent inadvertent logging, tracing, or agent-facing serialization.
/// 2. **Zeroize on Drop**: The internal byte buffer is actively overwritten with zeroes
///    when this struct is dropped.
/// 3. **Controlled Exposure**: Raw secret values are accessible only via explicit `expose_secret()`.
///
/// # Limitations of In-Memory Zeroization
/// While `SecretString` zeroes its heap buffer upon drop:
/// - Operating system paging/swap may write pages containing secret bytes to disk.
/// - Prior allocations or heap reallocations before wrapping in `SecretString` may leave residue in allocator caches.
/// - Compiler optimizations, CPU registers, and stack frames may transiently retain fragments.
/// - Process core dumps or debugger inspection can inspect memory while the secret is live.
pub struct SecretString {
    inner: Vec<u8>,
}

impl SecretString {
    /// Creates a new `SecretString` from a string or string slice.
    pub fn new(s: impl AsRef<str>) -> Self {
        let bytes = s.as_ref().as_bytes().to_vec();
        Self { inner: bytes }
    }

    /// Creates a new `SecretString` from a byte buffer, validating UTF-8 and safely
    /// zeroizing the buffer if validation fails. Strips single trailing newline/CRLF if present.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, BoundaryError> {
        if bytes.ends_with(b"\r\n") {
            let len = bytes.len();
            bytes.truncate(len - 2);
        } else if bytes.ends_with(b"\n") {
            let len = bytes.len();
            bytes.truncate(len - 1);
        }

        if std::str::from_utf8(&bytes).is_err() {
            bytes.zeroize();
            return Err(BoundaryError::ProviderError(
                "Secret bytes contained invalid UTF-8".to_string(),
            ));
        }

        Ok(Self { inner: bytes })
    }

    /// Explicitly reveals the secret as a string slice for internal operation adapters.
    ///
    /// # Safety and Hygiene
    /// This method should ONLY be called by approved operation adapters when constructing
    /// outbound requests. Never pass the resulting slice to loggers, serializers, or error builders.
    pub fn expose_secret(&self) -> &str {
        std::str::from_utf8(&self.inner).unwrap_or("<invalid utf-8 secret>")
    }

    /// Returns the length of the secret in bytes without exposing the content.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns a direct slice of the internal bytes for testing zeroization.
    ///
    /// # Security Restriction
    /// This method is strictly restricted to test builds (`#[cfg(any(test, feature = "test-utils"))]`).
    /// In production builds, this method is omitted to prevent caller code or agent tools
    /// from bypassing redaction, Display, Debug, or memory boundary protections.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn as_raw_bytes(&self) -> &[u8] {
        &self.inner
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for SecretString {}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED SECRET])")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED SECRET]")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for SecretString {}

/// Utility to scan text and replace any occurrence of the raw secret value with `"[REDACTED]"`.
/// Useful for output sanitization when third-party servers echo back input headers or parameters.
pub fn redact_secret_from_text(text: &str, secret: &SecretString) -> String {
    let raw = secret.expose_secret();
    if raw.trim().is_empty() {
        return text.to_string();
    }
    text.replace(raw, "[REDACTED]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_display_and_debug_are_redacted() {
        let secret = SecretString::new("super-secret-api-key-12345");
        let display = format!("{}", secret);
        let debug = format!("{:?}", secret);

        assert_eq!(display, "[REDACTED SECRET]");
        assert_eq!(debug, "SecretString([REDACTED SECRET])");
        assert!(!display.contains("super-secret"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn test_secret_exposure_is_accurate() {
        let secret = SecretString::new("test-token");
        assert_eq!(secret.expose_secret(), "test-token");
    }

    #[test]
    fn test_zeroize_clears_buffer() {
        let mut secret = SecretString::new("sensitive-bytes-to-zeroize");
        assert!(!secret.as_raw_bytes().iter().all(|&b| b == 0));

        secret.zeroize();
        assert!(secret.as_raw_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_redaction_helper() {
        let secret = SecretString::new("secret-value-xyz");
        let sample = "Error: Authentication header 'Bearer secret-value-xyz' was rejected";
        let redacted = redact_secret_from_text(sample, &secret);
        assert_eq!(
            redacted,
            "Error: Authentication header 'Bearer [REDACTED]' was rejected"
        );
        assert!(!redacted.contains("secret-value-xyz"));
    }

    #[test]
    fn test_from_bytes_valid_and_strips_newline() {
        let bytes = b"my-secret-token\r\n".to_vec();
        let secret = SecretString::from_bytes(bytes).unwrap();
        assert_eq!(secret.expose_secret(), "my-secret-token");

        let bytes_unix = b"unix-secret\n".to_vec();
        let secret_unix = SecretString::from_bytes(bytes_unix).unwrap();
        assert_eq!(secret_unix.expose_secret(), "unix-secret");
    }

    #[test]
    fn test_from_bytes_invalid_utf8_zeroizes_and_errors() {
        let invalid = vec![0xFF, 0xFE, 0xFD];
        let res = SecretString::from_bytes(invalid);
        assert!(matches!(res, Err(BoundaryError::ProviderError(_))));
    }
}
