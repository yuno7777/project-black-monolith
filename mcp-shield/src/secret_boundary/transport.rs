//! HTTPS transport adapter for PBM Secret Boundary using `reqwest` and `rustls`.
//!
//! Enforces:
//! 1. HTTPS scheme requirement for credential-bearing operations.
//! 2. Connection pinning: TCP socket connects strictly to pre-validated IP addresses.
//! 3. Preservation of original hostname for TLS SNI and certificate validation.
//! 4. Refusal of automated redirects (3xx) to prevent cross-origin credential leaks.
//! 5. Response payload size limits and request timeouts.
//! 6. Error sanitization ensuring raw secrets are never reflected in error messages.

use pbm_secret_boundary::error::BoundaryError;
use pbm_secret_boundary::operation::{HttpRequestDetails, HttpTransport, RawHttpResponse};
use std::collections::HashMap;

/// An HTTPS-capable transport using `reqwest` with Rustls and connection pinning.
#[derive(Debug, Clone, Default)]
pub struct ReqwestHttpsTransport {
    #[cfg(test)]
    test_root_cert: Option<Vec<u8>>,
}

impl ReqwestHttpsTransport {
    pub fn new() -> Self {
        Self {
            #[cfg(test)]
            test_root_cert: None,
        }
    }

    /// Creates a transport instance configured with a test root certificate.
    ///
    /// Available strictly in test builds to enable end-to-end testing against ephemeral
    /// local TLS test servers without disabling certificate or hostname verification.
    #[cfg(test)]
    pub fn with_test_root_certificate(cert_der_or_pem: &[u8]) -> Self {
        Self {
            test_root_cert: Some(cert_der_or_pem.to_vec()),
        }
    }

    /// Builds a pinned, proxy-disabled `reqwest::Client` adhering to PBM secret boundary policies.
    pub fn build_client(
        host: &str,
        pinned_addrs: &[std::net::SocketAddr],
        timeout: std::time::Duration,
    ) -> Result<reqwest::Client, BoundaryError> {
        Self::build_client_with_cert(host, pinned_addrs, timeout, None)
    }

    /// Builds a pinned, proxy-disabled `reqwest::Client` with optional test root certificate.
    pub fn build_client_with_cert(
        host: &str,
        pinned_addrs: &[std::net::SocketAddr],
        timeout: std::time::Duration,
        #[allow(unused_variables)] root_cert: Option<&[u8]>,
    ) -> Result<reqwest::Client, BoundaryError> {
        #[allow(unused_mut)]
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .timeout(timeout)
            .resolve_to_addrs(host, pinned_addrs);

        #[cfg(test)]
        if let Some(cert_bytes) = root_cert {
            builder = builder.use_preconfigured_tls(test_client_config(cert_bytes)?);
        }

        builder.build().map_err(|e| {
            BoundaryError::TransportError(format!("Failed to build HTTPS client: {}", e))
        })
    }
}

/// A TLS configuration that trusts exactly one certificate.
///
/// This exists because the production client uses the **platform
/// certificate verifier**, which validates against the operating system's
/// trust store and therefore ignores any root added through
/// `add_root_certificate`. A test that trusts its own ephemeral root needs
/// a configuration that actually contains it, and building one explicitly is
/// the only way to get that on every platform.
///
/// The root store is empty apart from the supplied certificate, so a test
/// server presenting anything else is rejected — which is exactly what the
/// "untrusted certificate" test needs to observe.
#[cfg(test)]
fn test_client_config(cert_der: &[u8]) -> Result<rustls::ClientConfig, BoundaryError> {
    // The client config is built with an explicit provider. Without this,
    // rustls would try to infer one, and the crate has both `ring` (the
    // dev-dependency) and `aws-lc-rs` (pulled in by reqwest) compiled in,
    // which is ambiguous. Installing the provider explicitly makes the
    // choice deterministic. `install_default` fails if a provider is already
    // installed, which is not an error here — the first one wins.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der.to_vec()))
        .map_err(|error| {
            BoundaryError::ConfigurationError(format!(
                "Failed to trust the supplied test root certificate: {}",
                error
            ))
        })?;

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Incrementally streams the HTTP response body using `resp.chunk()`, enforcing
/// response size limits safely before allocating unbounded memory.
pub(crate) async fn read_bounded_response_body(
    mut resp: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, BoundaryError> {
    // 1. Early rejection optimization: if upstream declares a Content-Length exceeding the limit,
    // reject immediately before streaming any body bytes.
    if let Some(content_length) = resp.content_length() {
        if content_length > max_response_bytes as u64 {
            return Err(BoundaryError::TransportError(format!(
                "Response declared Content-Length ({} bytes) exceeds maximum bound ({} bytes)",
                content_length, max_response_bytes
            )));
        }
    }

    let mut body_bytes = Vec::new();

    // 2. Incrementally stream body chunks using resp.chunk()
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        BoundaryError::TransportError(format!("Failed reading response chunk: {}", e))
    })? {
        // 3. Checked arithmetic for prospective accumulated size
        let prospective_len = body_bytes.len().checked_add(chunk.len()).ok_or_else(|| {
            BoundaryError::TransportError(
                "Response payload size calculation overflowed".to_string(),
            )
        })?;

        // 4. Abort further reading as soon as accumulated size exceeds limit
        if prospective_len > max_response_bytes {
            return Err(BoundaryError::TransportError(format!(
                "Response payload size (at least {} bytes) exceeded maximum bound ({} bytes)",
                prospective_len, max_response_bytes
            )));
        }

        body_bytes.extend_from_slice(&chunk);
    }

    Ok(body_bytes)
}

impl HttpTransport for ReqwestHttpsTransport {
    fn execute_request(&self, req: &HttpRequestDetails) -> Result<RawHttpResponse, BoundaryError> {
        // 1. Enforce HTTPS scheme for credential-bearing operations
        if req.url.scheme() != "https" {
            return Err(BoundaryError::DestinationViolation(format!(
                "Insecure scheme '{}' rejected: credential-bearing operations strictly require HTTPS",
                req.url.scheme()
            )));
        }

        // 2. Validate non-empty connection pinning
        if req.pinned_addrs.is_empty() {
            return Err(BoundaryError::DestinationViolation(
                "Connection pinning required: no pre-validated socket addresses provided"
                    .to_string(),
            ));
        }

        // 3. Build pinned reqwest client:
        // - Disables ambient proxies (.no_proxy())
        // - Disables automated redirects
        // - Resolves destination hostname exclusively to the pre-validated pinned SocketAddrs
        // - Enforces connect and request timeouts
        // - Preserves host header for TLS SNI and certificate verification
        #[cfg(test)]
        let test_cert = self.test_root_cert.as_deref();
        #[cfg(not(test))]
        let test_cert = None;

        let client = Self::build_client_with_cert(
            &req.host_header,
            &req.pinned_addrs,
            req.timeout,
            test_cert,
        )?;

        // 4. Execute request synchronously across the Tokio runtime boundary
        let fut = async {
            let mut req_builder = match req.method.to_ascii_uppercase().as_str() {
                "GET" => client.get(req.url.clone()),
                "POST" => client.post(req.url.clone()),
                "PUT" => client.put(req.url.clone()),
                "DELETE" => client.delete(req.url.clone()),
                "HEAD" => client.head(req.url.clone()),
                "PATCH" => client.patch(req.url.clone()),
                other => {
                    return Err(BoundaryError::OperationNotAllowed(format!(
                        "Unsupported HTTP method '{}'",
                        other
                    )));
                }
            };

            for (k, v) in &req.headers {
                // A header that cannot be represented is a failure, not
                // something to skip: dropping the Authorization header would
                // send the credential-less request to the approved
                // destination and surface as an unrelated upstream error.
                let hname =
                    reqwest::header::HeaderName::from_bytes(k.as_bytes()).map_err(|_| {
                        BoundaryError::InvalidRequest(format!(
                            "Header name '{}' is not a valid HTTP header name",
                            k
                        ))
                    })?;
                let hval = reqwest::header::HeaderValue::from_str(v).map_err(|_| {
                    BoundaryError::InvalidRequest(format!(
                        "Header '{}' has a value that is not a valid HTTP header value",
                        k
                    ))
                })?;
                req_builder = req_builder.header(hname, hval);
            }

            if let Some(body) = &req.body {
                req_builder = req_builder.body(body.clone());
            }

            let resp = req_builder.send().await.map_err(|e| {
                // reqwest's own message — "error sending request" — says
                // nothing about *why*. The source chain does: a TLS
                // verification failure, a refused connection, a timeout, a
                // name that would not resolve. An operator reading a
                // detection event needs that distinction, so it is carried
                // rather than discarded.
                let mut detail = format!("HTTPS request failed: {e}");
                let mut cause = std::error::Error::source(&e);
                while let Some(source) = cause {
                    detail.push_str(&format!("; caused by: {source}"));
                    cause = source.source();
                }
                BoundaryError::TransportError(detail)
            })?;

            let status_code = resp.status().as_u16();

            // Extract response headers
            let mut headers = HashMap::new();
            for (k, v) in resp.headers() {
                if let Ok(v_str) = v.to_str() {
                    headers.insert(k.as_str().to_string(), v_str.to_string());
                }
            }

            // Stream / read response body with strict upper bound and incremental enforcement
            let body = read_bounded_response_body(resp, req.max_response_bytes).await?;

            Ok(RawHttpResponse {
                status_code,
                headers,
                body,
            })
        };

        // If called inside an asynchronous Tokio runtime context:
        // - On MultiThread runtimes, execute via block_in_place to prevent starvation of reactor worker threads.
        // - On CurrentThread runtimes (where block_in_place is unsupported), drive future on a dedicated worker thread.
        // Otherwise, construct a single-threaded runtime to drive the future to completion.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => {
                    tokio::task::block_in_place(|| handle.block_on(fut))
                }
                _ => std::thread::scope(|s| {
                    s.spawn(|| {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .map_err(|e| {
                                BoundaryError::TransportError(format!(
                                    "Tokio runtime creation error: {}",
                                    e
                                ))
                            })?;
                        rt.block_on(fut)
                    })
                    .join()
                    .map_err(|_| {
                        BoundaryError::TransportError(
                            "Transport worker thread panicked".to_string(),
                        )
                    })?
                }),
            },
            Err(_) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        BoundaryError::TransportError(format!(
                            "Tokio runtime creation error: {}",
                            e
                        ))
                    })?;
                rt.block_on(fut)
            }
        }
    }
}
