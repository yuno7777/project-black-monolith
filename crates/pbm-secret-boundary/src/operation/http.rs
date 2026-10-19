use super::{OperationExecutor, OperationRequest, OperationResponse};
use crate::error::BoundaryError;
use crate::secret::{redact_secret_from_text, SecretString};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

/// Trait for DNS resolution allowing testable simulation of adversarial DNS rebinding
/// and multi-address responses without requiring external network access.
pub trait DnsResolver: Send + Sync {
    /// Resolves a hostname and port into one or more `SocketAddr` destinations.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, BoundaryError>;
}

/// Default system DNS resolver using standard library `ToSocketAddrs`.
#[derive(Debug, Clone, Default)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, BoundaryError> {
        let addr_str = format!("{}:{}", host, port);
        let addrs = addr_str.to_socket_addrs().map_err(|e| {
            BoundaryError::DestinationViolation(format!(
                "DNS resolution failed for {}: {}",
                host, e
            ))
        })?;
        let list: Vec<SocketAddr> = addrs.collect();
        if list.is_empty() {
            return Err(BoundaryError::DestinationViolation(format!(
                "DNS resolution returned no addresses for {}",
                host
            )));
        }
        Ok(list)
    }
}

/// In-memory mock DNS resolver for deterministic testing of DNS rebinding,
/// multi-IP responses, and resolution failures.
#[derive(Debug, Default)]
pub struct MockDnsResolver {
    records: Mutex<HashMap<(String, u16), Vec<SocketAddr>>>,
}

impl MockDnsResolver {
    /// Creates a new empty `MockDnsResolver`.
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
        }
    }

    /// Registers a mapping from `(host, port)` to a list of resolved `SocketAddr`s.
    pub fn insert(&self, host: &str, port: u16, addrs: Vec<SocketAddr>) {
        self.records
            .lock()
            .unwrap()
            .insert((host.to_string(), port), addrs);
    }
}

impl DnsResolver for MockDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, BoundaryError> {
        let lock = self.records.lock().unwrap();
        if let Some(addrs) = lock.get(&(host.to_string(), port)) {
            if addrs.is_empty() {
                return Err(BoundaryError::DestinationViolation(format!(
                    "Mock DNS returned no addresses for {}:{}",
                    host, port
                )));
            }
            Ok(addrs.clone())
        } else {
            Err(BoundaryError::DestinationViolation(format!(
                "Mock DNS resolution found no record for {}:{}",
                host, port
            )))
        }
    }
}

/// Request details passed to the transport layer with verified, pinned destinations.
#[derive(Debug, Clone)]
pub struct HttpRequestDetails {
    pub url: Url,
    pub host_header: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub pinned_addrs: Vec<SocketAddr>,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

/// Raw response returned from the HTTP transport layer.
#[derive(Debug, Clone)]
pub struct RawHttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Pluggable HTTP transport interface enforcing connection pinning and redirect controls.
pub trait HttpTransport: Send + Sync {
    /// Executes the HTTP request strictly through the validated pinned address(es).
    fn execute_request(&self, req: &HttpRequestDetails) -> Result<RawHttpResponse, BoundaryError>;
}

/// In-memory mock HTTP transport for deterministic offline testing.
#[derive(Debug, Default)]
pub struct MockHttpTransport {
    recorded_requests: Mutex<Vec<HttpRequestDetails>>,
    simulated_responses: Mutex<HashMap<String, Result<RawHttpResponse, String>>>,
}

impl MockHttpTransport {
    /// Creates a new `MockHttpTransport`.
    pub fn new() -> Self {
        Self {
            recorded_requests: Mutex::new(Vec::new()),
            simulated_responses: Mutex::new(HashMap::new()),
        }
    }

    /// Sets a simulated response for a specific operation path or URL.
    pub fn set_response(&self, url: &str, response: Result<RawHttpResponse, String>) {
        self.simulated_responses
            .lock()
            .unwrap()
            .insert(url.to_string(), response);
    }

    /// Returns recorded requests.
    pub fn get_recorded_requests(&self) -> Vec<HttpRequestDetails> {
        self.recorded_requests.lock().unwrap().clone()
    }
}

impl HttpTransport for MockHttpTransport {
    fn execute_request(&self, req: &HttpRequestDetails) -> Result<RawHttpResponse, BoundaryError> {
        // Enforce invariant: connection pinning must have provided non-empty pinned addresses
        if req.pinned_addrs.is_empty() {
            return Err(BoundaryError::DestinationViolation(
                "Transport received unpinned request: no socket addresses provided".to_string(),
            ));
        }

        self.recorded_requests.lock().unwrap().push(req.clone());

        let url_str = req.url.as_str();
        let path = req.url.path();
        let responses = self.simulated_responses.lock().unwrap();

        if let Some(resp) = responses.get(url_str).or_else(|| responses.get(path)) {
            match resp {
                Ok(r) => Ok(r.clone()),
                Err(err_msg) => Err(BoundaryError::TransportError(err_msg.clone())),
            }
        } else {
            // Default safe simulated upstream response
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("Server".to_string(), "Protected-Backend".to_string());

            let body = format!(
                r#"{{"status":"ok","path":"{}","message":"executed_safely"}}"#,
                path
            )
            .into_bytes();

            Ok(RawHttpResponse {
                status_code: 200,
                headers,
                body,
            })
        }
    }
}

/// Direct TCP-based HTTP transport connecting strictly to pinned socket addresses.
///
/// # TLS & Offline Notice
/// Since external TLS engine dependencies cannot be resolved offline without network crate downloads,
/// requests with scheme `https` fail closed safely with a descriptive `ConfigurationError`.
/// Plain `http` connections to approved destinations connect directly to the pinned `SocketAddr`.
#[derive(Debug, Clone, Default)]
pub struct StdTcpHttpTransport;

impl HttpTransport for StdTcpHttpTransport {
    fn execute_request(&self, req: &HttpRequestDetails) -> Result<RawHttpResponse, BoundaryError> {
        if req.pinned_addrs.is_empty() {
            return Err(BoundaryError::DestinationViolation(
                "No validated socket addresses available for pinned connection".to_string(),
            ));
        }

        if req.url.scheme() == "https" {
            return Err(BoundaryError::ConfigurationError(
                "Direct TLS network transport is unavailable offline without external TLS provider; failing closed for safety"
                    .to_string(),
            ));
        }

        // Connect strictly to one of the pinned addresses
        let mut stream_opt = None;
        let mut last_conn_err = None;

        for addr in &req.pinned_addrs {
            match TcpStream::connect_timeout(addr, req.timeout) {
                Ok(stream) => {
                    stream_opt = Some(stream);
                    break;
                }
                Err(e) => {
                    last_conn_err = Some(e);
                }
            }
        }

        let mut stream = stream_opt.ok_or_else(|| {
            BoundaryError::TransportError(format!(
                "Failed to connect to pinned address(es): {:?}",
                last_conn_err
            ))
        })?;

        stream.set_read_timeout(Some(req.timeout)).map_err(|e| {
            BoundaryError::TransportError(format!("Failed to set read timeout: {}", e))
        })?;
        stream.set_write_timeout(Some(req.timeout)).map_err(|e| {
            BoundaryError::TransportError(format!("Failed to set write timeout: {}", e))
        })?;

        // Format minimal HTTP/1.1 request
        let path_and_query = match req.url.query() {
            Some(q) => format!("{}?{}", req.url.path(), q),
            None => req.url.path().to_string(),
        };

        let mut wire = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            req.method, path_and_query, req.host_header
        );

        for (k, v) in &req.headers {
            // Defence in depth: the caller of this transport is checked
            // before the request reaches it, but this is the code that writes
            // the raw wire format, so it refuses to emit a header that would
            // terminate the header block early.
            if k.is_empty()
                || k.contains('\r')
                || k.contains('\n')
                || v.contains('\r')
                || v.contains('\n')
                || v.contains('\0')
            {
                return Err(BoundaryError::InvalidRequest(format!(
                    "Header '{}' cannot be represented in an HTTP request",
                    k
                )));
            }
            wire.push_str(&format!("{}: {}\r\n", k, v));
        }

        if let Some(body) = &req.body {
            wire.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
            stream
                .write_all(wire.as_bytes())
                .map_err(|e| BoundaryError::TransportError(format!("Socket write error: {}", e)))?;
            stream.write_all(body).map_err(|e| {
                BoundaryError::TransportError(format!("Socket body write error: {}", e))
            })?;
        } else {
            wire.push_str("\r\n");
            stream
                .write_all(wire.as_bytes())
                .map_err(|e| BoundaryError::TransportError(format!("Socket write error: {}", e)))?;
        }

        stream
            .flush()
            .map_err(|e| BoundaryError::TransportError(format!("Socket flush error: {}", e)))?;

        // Read response bounded by max_response_bytes
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&chunk[..n]);
                    if buffer.len() > req.max_response_bytes {
                        return Err(BoundaryError::TransportError(format!(
                            "Response exceeded maximum configured size of {} bytes",
                            req.max_response_bytes
                        )));
                    }
                }
                Err(e) => {
                    return Err(BoundaryError::TransportError(format!(
                        "Socket read error: {}",
                        e
                    )));
                }
            }
        }

        // Parse minimal HTTP response (status code and headers)
        parse_raw_http_response(&buffer)
    }
}

/// Minimal HTTP/1.1 response parser for standard library transport.
fn parse_raw_http_response(raw: &[u8]) -> Result<RawHttpResponse, BoundaryError> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            BoundaryError::TransportError("Incomplete HTTP response headers".to_string())
        })?;

    let header_bytes = &raw[..header_end];
    let body_bytes = &raw[header_end + 4..];

    let header_str = std::str::from_utf8(header_bytes).map_err(|_| {
        BoundaryError::TransportError("Invalid UTF-8 in HTTP response headers".to_string())
    })?;

    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| BoundaryError::TransportError("Empty HTTP response".to_string()))?;

    let mut parts = status_line.split_whitespace();
    let _version = parts
        .next()
        .ok_or_else(|| BoundaryError::TransportError("Missing HTTP version".to_string()))?;
    let status_str = parts
        .next()
        .ok_or_else(|| BoundaryError::TransportError("Missing HTTP status code".to_string()))?;
    let status_code: u16 = status_str
        .parse()
        .map_err(|_| BoundaryError::TransportError("Invalid HTTP status code".to_string()))?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    Ok(RawHttpResponse {
        status_code,
        headers,
        body: body_bytes.to_vec(),
    })
}

/// Configuration for the HTTP operation adapter.
#[derive(Debug, Clone)]
pub struct HttpAdapterConfig {
    /// Maximum response payload size in bytes (default 5 MB).
    pub max_response_bytes: usize,

    /// Request timeout in seconds.
    pub timeout_seconds: u64,

    /// Whether to permit connections to private IP addresses (default false).
    pub allow_private_ips: bool,
}

impl Default for HttpAdapterConfig {
    fn default() -> Self {
        Self {
            max_response_bytes: 5 * 1024 * 1024,
            timeout_seconds: 10,
            allow_private_ips: false,
        }
    }
}

/// HTTP operation adapter that injects authorized credentials internally and enforces
/// comprehensive SSRF, DNS-rebinding, connection-pinning, and redirect defenses.
#[derive(Clone)]
pub struct HttpOperationAdapter {
    config: HttpAdapterConfig,
    resolver: Arc<dyn DnsResolver>,
    transport: Arc<dyn HttpTransport>,
}

impl HttpOperationAdapter {
    /// Creates a new `HttpOperationAdapter` with default configuration,
    /// standard DNS resolution, and mock offline transport.
    pub fn new() -> Self {
        Self {
            config: HttpAdapterConfig::default(),
            resolver: Arc::new(SystemDnsResolver),
            transport: Arc::new(MockHttpTransport::new()),
        }
    }

    /// Creates a new `HttpOperationAdapter` with custom configuration,
    /// standard DNS resolution, and mock offline transport.
    pub fn with_config(config: HttpAdapterConfig) -> Self {
        Self {
            config,
            resolver: Arc::new(SystemDnsResolver),
            transport: Arc::new(MockHttpTransport::new()),
        }
    }

    /// Creates an `HttpOperationAdapter` with custom resolver and transport.
    pub fn with_resolver_and_transport(
        config: HttpAdapterConfig,
        resolver: Arc<dyn DnsResolver>,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            config,
            resolver,
            transport,
        }
    }

    /// Evaluates IPv4 address against SSRF boundaries.
    pub fn is_dangerous_ipv4(&self, ipv4: Ipv4Addr) -> bool {
        let octets = ipv4.octets();

        // 127.0.0.0/8 (Loopback)
        if ipv4.is_loopback() || octets[0] == 127 {
            return true;
        }

        // 0.0.0.0/8 (Current network)
        if octets[0] == 0 {
            return true;
        }

        // 169.254.0.0/16 (Link-local / Cloud metadata)
        if ipv4.is_link_local() || (octets[0] == 169 && octets[1] == 254) {
            return true;
        }

        // 255.255.255.255 (Broadcast)
        if ipv4.is_broadcast() {
            return true;
        }

        // 224.0.0.0/4 (Multicast)
        if octets[0] >= 224 && octets[0] <= 239 {
            return true;
        }

        // 240.0.0.0/4 (Reserved / Future use)
        if octets[0] >= 240 {
            return true;
        }

        // Documentation blocks (RFC 5737)
        if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        {
            return true;
        }

        // Benchmarking block (RFC 2544)
        if octets[0] == 198 && (octets[1] & 0xFE) == 18 {
            return true;
        }

        // If private IPs are forbidden, check RFC 1918 and CGNAT (100.64.0.0/10)
        if !self.config.allow_private_ips {
            if ipv4.is_private() {
                return true;
            }
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                return true;
            }
        }

        false
    }

    /// Evaluates IPv6 address against SSRF boundaries (including IPv4-mapped and IPv4-compatible IPv6).
    pub fn is_dangerous_ipv6(&self, ipv6: Ipv6Addr) -> bool {
        // Loopback (::1) and Unspecified (::)
        if ipv6.is_loopback() || ipv6.is_unspecified() {
            return true;
        }

        let segments = ipv6.segments();

        // IPv4-mapped IPv6: ::ffff:a.b.c.d
        if let Some(mapped_v4) = ipv6.to_ipv4_mapped() {
            return self.is_dangerous_ipv4(mapped_v4);
        }

        // IPv4-compatible IPv6: ::a.b.c.d (deprecated, leading 96 bits are zero)
        if segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0
        {
            let octets = ipv6.octets();
            let compat_v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
            return self.is_dangerous_ipv4(compat_v4);
        }

        // Link-local IPv6 (fe80::/10)
        if (segments[0] & 0xffc0) == 0xfe80 {
            return true;
        }

        // Multicast IPv6 (ff00::/8)
        if (segments[0] & 0xff00) == 0xff00 {
            return true;
        }

        // Cloud metadata IPv6 (e.g. AWS IMDSv6: fd00:ec2::254)
        if segments[0] == 0xfd00 && segments[1] == 0x0ec2 {
            return true;
        }

        // Unique Local IPv6 (fc00::/7 - private network)
        if !self.config.allow_private_ips && (segments[0] & 0xfe00) == 0xfc00 {
            return true;
        }

        // Documentation IPv6 (2001:db8::/32)
        if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            return true;
        }

        false
    }

    /// Validates an IP address against SSRF and private network boundaries.
    pub fn validate_ip_safety(&self, ip: IpAddr) -> Result<(), BoundaryError> {
        match ip {
            IpAddr::V4(ipv4) => {
                if self.is_dangerous_ipv4(ipv4) {
                    return Err(BoundaryError::SsrfBlocked(format!(
                        "Destination IPv4 '{}' is blocked by SSRF defense",
                        ipv4
                    )));
                }
            }
            IpAddr::V6(ipv6) => {
                if self.is_dangerous_ipv6(ipv6) {
                    return Err(BoundaryError::SsrfBlocked(format!(
                        "Destination IPv6 '{}' is blocked by SSRF defense",
                        ipv6
                    )));
                }
            }
        }
        Ok(())
    }

    /// Performs syntactic URL validation, controlled DNS resolution, comprehensive IP safety
    /// checks on every resolved address, and connection pinning to prevent DNS rebinding.
    ///
    /// # Why the returned addresses, not just a verdict
    ///
    /// This returns the *addresses to connect to*, not merely a yes/no. The
    /// caller passes them to the transport, which pins the TCP connection to
    /// exactly these addresses while keeping the original hostname for TLS
    /// SNI and the `Host` header. That is what closes the DNS-rebinding
    /// window: without pinning, a name that resolved to a public address
    /// during validation could resolve to `127.0.0.1` a millisecond later,
    /// and the credential would be sent to whatever the second answer
    /// pointed at.
    ///
    /// The name-level rejections (loopback hostnames, cloud metadata
    /// hostnames) come before resolution because they cost nothing and catch
    /// the cases that a resolver would otherwise answer for us.
    pub fn resolve_and_pin_destination(
        &self,
        url: &Url,
    ) -> Result<(String, u16, Vec<SocketAddr>), BoundaryError> {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(BoundaryError::DestinationViolation(format!(
                "Unsupported URL scheme '{}'. Only 'http' and 'https' are permitted",
                scheme
            )));
        }

        let host = url.host_str().ok_or_else(|| {
            BoundaryError::DestinationViolation(
                "Destination URL is missing a valid host".to_string(),
            )
        })?;

        let port = url.port_or_known_default().ok_or_else(|| {
            BoundaryError::DestinationViolation(
                "Unable to determine port for destination".to_string(),
            )
        })?;

        let host_lower = host.to_ascii_lowercase();

        // 1. Prohibit loopback hostnames
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "127.0.0.1"
            || host_lower == "::1"
            || host_lower == "0.0.0.0"
        {
            return Err(BoundaryError::SsrfBlocked(format!(
                "Loopback destination '{}' is forbidden by SSRF policy",
                host
            )));
        }

        // 2. Prohibit known cloud metadata endpoints
        if host_lower == "169.254.169.254"
            || host_lower == "metadata.google.internal"
            || host_lower == "instance-data"
            || host_lower == "metadata.tencentyun.com"
        {
            return Err(BoundaryError::SsrfBlocked(format!(
                "Cloud metadata endpoint '{}' is strictly prohibited",
                host
            )));
        }

        // 3. Literal IP handling
        let host_trimmed = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host_trimmed.parse::<IpAddr>() {
            self.validate_ip_safety(ip)?;
            let pinned_addr = SocketAddr::new(ip, port);
            return Ok((host.to_string(), port, vec![pinned_addr]));
        }

        // 4. Controlled DNS Resolution Step (Mitigating DNS Rebinding)
        let resolved_addrs = self.resolver.resolve(host, port)?;
        if resolved_addrs.is_empty() {
            return Err(BoundaryError::DestinationViolation(format!(
                "DNS resolution returned no addresses for '{}'",
                host
            )));
        }

        // 5. Enforce safety on EVERY resolved address (fail closed on any prohibited IP)
        for addr in &resolved_addrs {
            self.validate_ip_safety(addr.ip())?;
        }

        Ok((host.to_string(), port, resolved_addrs))
    }

    /// Validates destination URL for potential Server-Side Request Forgery (SSRF) vulnerabilities
    /// and performs DNS resolution validation.
    pub fn validate_ssrf_safety(&self, url: &Url) -> Result<(), BoundaryError> {
        self.resolve_and_pin_destination(url).map(|_| ())
    }

    /// Filters sensitive HTTP headers from responses.
    pub fn filter_response_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
        let sensitive = [
            "set-cookie",
            "authorization",
            "www-authenticate",
            "proxy-authenticate",
            "x-amz-security-token",
            "proxy-authorization",
        ];

        headers
            .iter()
            .filter(|(k, _)| {
                let lower = k.to_ascii_lowercase();
                !sensitive.contains(&lower.as_str())
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl Default for HttpOperationAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl OperationExecutor for HttpOperationAdapter {
    fn execute(
        &self,
        request: &OperationRequest,
        secret: &SecretString,
    ) -> Result<OperationResponse, BoundaryError> {
        let start = std::time::Instant::now();

        let parsed_url = Url::parse(&request.destination_url).map_err(|e| {
            BoundaryError::DestinationViolation(format!("Invalid URL syntax: {}", e))
        })?;

        // 1. Destination validation, controlled DNS resolution, and connection pinning
        let (host_str, _port, pinned_addrs) = self.resolve_and_pin_destination(&parsed_url)?;

        // 2. Reject prohibited headers from untrusted caller
        let mut request_headers = HashMap::new();
        for (k, v) in &request.headers {
            let lower = k.to_ascii_lowercase();
            if lower == "authorization"
                || lower == "proxy-authorization"
                || lower == "cookie"
                || lower == "host"
            {
                return Err(BoundaryError::InvalidRequest(format!(
                    "Disallowed client-supplied header '{}'",
                    k
                )));
            }
            if k.contains('\r') || k.contains('\n') || v.contains('\r') || v.contains('\n') {
                return Err(BoundaryError::InvalidRequest(format!(
                    "CRLF injection attempt in header '{}'",
                    k
                )));
            }
            request_headers.insert(k.clone(), v.clone());
        }

        // 3. Inject policy-mandated credential internally
        //
        // The composed value must be a valid HTTP header value. The CRLF guard
        // above only covers caller-supplied headers, so a secret carrying a
        // newline would otherwise terminate this header early and inject
        // further headers into the outbound request. The secret is validated
        // here rather than at the provider so that every provider is covered.
        let authorization = format!("Bearer {}", secret.expose_secret());
        if authorization
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
        {
            return Err(BoundaryError::InvalidRequest(
                "Resolved secret contains characters that are not valid in an HTTP header value"
                    .to_string(),
            ));
        }
        request_headers.insert("Authorization".to_string(), authorization);

        let details = HttpRequestDetails {
            url: parsed_url.clone(),
            host_header: host_str,
            method: request.method.clone(),
            headers: request_headers,
            body: request.body.clone(),
            pinned_addrs,
            timeout: Duration::from_secs(self.config.timeout_seconds),
            max_response_bytes: self.config.max_response_bytes,
        };

        // 4. Execute request via transport
        let raw_response = match self.transport.execute_request(&details) {
            Ok(resp) => resp,
            Err(e) => {
                // Ensure error message NEVER exposes raw secret bytes
                let err_str = e.to_string();
                let sanitized_msg = redact_secret_from_text(&err_str, secret);
                return Err(BoundaryError::TransportError(sanitized_msg));
            }
        };

        // 5. Redirect Defense:
        // Automated redirects MUST NEVER be followed with credentials attached.
        // Fail closed immediately if an HTTP 3xx redirect status is returned.
        if (300..=399).contains(&raw_response.status_code) {
            return Err(BoundaryError::DestinationViolation(format!(
                "HTTP redirect status {} received: automated redirects are prohibited to prevent credential exfiltration",
                raw_response.status_code
            )));
        }

        // 6. Response size limit enforcement
        if raw_response.body.len() > self.config.max_response_bytes {
            return Err(BoundaryError::TransportError(format!(
                "Response size {} bytes exceeds configured maximum of {} bytes",
                raw_response.body.len(),
                self.config.max_response_bytes
            )));
        }

        // 7. Sanitize response body to verify no reflected secrets
        let body_str = String::from_utf8_lossy(&raw_response.body);
        let sanitized_body_str = redact_secret_from_text(&body_str, secret);

        // 8. Filter upstream response headers
        let filtered_headers = Self::filter_response_headers(&raw_response.headers);

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(OperationResponse {
            status_code: raw_response.status_code,
            sanitized_body: sanitized_body_str.into_bytes(),
            sanitized_headers: filtered_headers,
            duration_ms: duration_ms.max(1),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_blocks_ipv4_loopback_and_metadata() {
        let adapter = HttpOperationAdapter::new();
        assert!(adapter
            .validate_ip_safety(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .is_err());
        assert!(adapter
            .validate_ip_safety(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))
            .is_err());
    }

    #[test]
    fn test_ssrf_blocks_ipv6_loopback_and_mapped_ipv4() {
        let adapter = HttpOperationAdapter::new();

        // Standard IPv6 loopback
        let ipv6_loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(adapter.validate_ip_safety(ipv6_loopback).is_err());

        // IPv4-mapped IPv6 targeting loopback
        let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(adapter.validate_ip_safety(mapped_loopback).is_err());

        // IPv4-mapped IPv6 targeting metadata
        let mapped_meta: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(adapter.validate_ip_safety(mapped_meta).is_err());

        // AWS IMDSv6
        let imdsv6: IpAddr = "fd00:ec2::254".parse().unwrap();
        assert!(adapter.validate_ip_safety(imdsv6).is_err());
    }

    #[test]
    fn test_ssrf_ipv4_compatible_ipv6_classification() {
        let adapter = HttpOperationAdapter::new();

        // 1. IPv4-compatible IPv6 carrying loopback (::127.0.0.1)
        let compat_loopback: IpAddr = "::127.0.0.1".parse().unwrap();
        assert!(adapter.validate_ip_safety(compat_loopback).is_err());

        // 2. IPv4-compatible IPv6 carrying cloud metadata (::169.254.169.254)
        let compat_metadata: IpAddr = "::169.254.169.254".parse().unwrap();
        assert!(adapter.validate_ip_safety(compat_metadata).is_err());

        // 3. IPv4-compatible IPv6 carrying private addresses (default: blocked)
        let compat_private_10: IpAddr = "::10.0.0.1".parse().unwrap();
        let compat_private_192: IpAddr = "::192.168.1.1".parse().unwrap();
        assert!(adapter.validate_ip_safety(compat_private_10).is_err());
        assert!(adapter.validate_ip_safety(compat_private_192).is_err());

        // 4. When private IPs are explicitly allowed, private IPv4-compatible addresses are allowed
        let permissive_config = HttpAdapterConfig {
            allow_private_ips: true,
            ..Default::default()
        };
        let permissive_adapter = HttpOperationAdapter::with_config(permissive_config);
        assert!(permissive_adapter
            .validate_ip_safety(compat_private_10)
            .is_ok());
        assert!(permissive_adapter
            .validate_ip_safety(compat_private_192)
            .is_ok());
        // But loopback and metadata MUST remain blocked even with allow_private_ips = true
        assert!(permissive_adapter
            .validate_ip_safety(compat_loopback)
            .is_err());
        assert!(permissive_adapter
            .validate_ip_safety(compat_metadata)
            .is_err());

        // 5. IPv4-compatible representation of an allowed public address (::93.184.216.34)
        // Confirms classification follows IPv4 policy rather than indiscriminately rejecting all
        let compat_public: IpAddr = "::93.184.216.34".parse().unwrap();
        assert!(adapter.validate_ip_safety(compat_public).is_ok());

        // 6. Existing IPv4-mapped IPv6 cases remain blocked / allowed consistently
        let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let mapped_metadata: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        let mapped_private: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let mapped_public: IpAddr = "::ffff:93.184.216.34".parse().unwrap();
        assert!(adapter.validate_ip_safety(mapped_loopback).is_err());
        assert!(adapter.validate_ip_safety(mapped_metadata).is_err());
        assert!(adapter.validate_ip_safety(mapped_private).is_err());
        assert!(adapter.validate_ip_safety(mapped_public).is_ok());
    }

    #[test]
    fn test_response_headers_do_not_contain_request_auth() {
        let mut resp_headers = HashMap::new();
        resp_headers.insert("Content-Type".to_string(), "application/json".to_string());
        resp_headers.insert("Set-Cookie".to_string(), "secret-cookie".to_string());
        resp_headers.insert("Authorization".to_string(), "Bearer leak".to_string());

        let filtered = HttpOperationAdapter::filter_response_headers(&resp_headers);
        assert!(filtered.contains_key("Content-Type"));
        assert!(!filtered.contains_key("Set-Cookie"));
        assert!(!filtered.contains_key("Authorization"));
    }

    #[test]
    fn test_dns_rebinding_defense_with_mock_resolver() {
        let mock_resolver = Arc::new(MockDnsResolver::new());
        let mock_transport = Arc::new(MockHttpTransport::new());

        // Host resolves to loopback IP (DNS rebinding attempt)
        mock_resolver.insert(
            "rebind.attacker.com",
            443,
            vec![SocketAddr::from(([127, 0, 0, 1], 443))],
        );

        let adapter = HttpOperationAdapter::with_resolver_and_transport(
            HttpAdapterConfig::default(),
            mock_resolver,
            mock_transport,
        );

        let url = Url::parse("https://rebind.attacker.com/api").unwrap();
        let result = adapter.resolve_and_pin_destination(&url);
        assert!(matches!(result, Err(BoundaryError::SsrfBlocked(_))));
    }

    #[test]
    fn test_dns_multi_address_with_prohibited_ip_fails_closed() {
        let mock_resolver = Arc::new(MockDnsResolver::new());
        let mock_transport = Arc::new(MockHttpTransport::new());

        // Host returns dual records: one public IP and one cloud metadata IP
        mock_resolver.insert(
            "split-horizon.attacker.com",
            443,
            vec![
                SocketAddr::from(([93, 184, 216, 34], 443)),
                SocketAddr::from(([169, 254, 169, 254], 443)),
            ],
        );

        let adapter = HttpOperationAdapter::with_resolver_and_transport(
            HttpAdapterConfig::default(),
            mock_resolver,
            mock_transport,
        );

        let url = Url::parse("https://split-horizon.attacker.com/api").unwrap();
        let result = adapter.resolve_and_pin_destination(&url);
        // Must fail closed because one of the addresses is dangerous!
        assert!(matches!(result, Err(BoundaryError::SsrfBlocked(_))));
    }

    #[test]
    fn test_redirect_refusal_blocks_credential_leak() {
        let mock_resolver = Arc::new(MockDnsResolver::new());
        let mock_transport = Arc::new(MockHttpTransport::new());

        mock_resolver.insert(
            "api.service.example.com",
            443,
            vec![SocketAddr::from(([93, 184, 216, 34], 443))],
        );

        // Configure mock transport to return a 302 redirect
        mock_transport.set_response(
            "https://api.service.example.com/redirect-target",
            Ok(RawHttpResponse {
                status_code: 302,
                headers: HashMap::from([(
                    "Location".to_string(),
                    "https://evil.attacker.com/harvest".to_string(),
                )]),
                body: b"Redirecting...".to_vec(),
            }),
        );

        let adapter = HttpOperationAdapter::with_resolver_and_transport(
            HttpAdapterConfig::default(),
            mock_resolver,
            mock_transport,
        );

        let req = OperationRequest {
            agent_id: "agent-01".to_string(),
            operation_id: "op-test".to_string(),
            destination_url: "https://api.service.example.com/redirect-target".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
        };
        let secret = SecretString::new("secret-token-1234");

        let result = adapter.execute(&req, &secret);
        assert!(matches!(
            result,
            Err(BoundaryError::DestinationViolation(_))
        ));
    }

    /// A secret that carries a newline would terminate the `Authorization`
    /// header early and inject a header of its own choosing into the request
    /// to the approved destination. The request must never be sent.
    #[test]
    fn test_secret_with_crlf_is_rejected_before_the_request_is_sent() {
        let mock_resolver = Arc::new(MockDnsResolver::new());
        let mock_transport = Arc::new(MockHttpTransport::new());

        mock_resolver.insert(
            "api.service.example.com",
            443,
            vec![SocketAddr::from(([93, 184, 216, 34], 443))],
        );

        let adapter = HttpOperationAdapter::with_resolver_and_transport(
            HttpAdapterConfig::default(),
            mock_resolver,
            mock_transport.clone(),
        );

        let req = OperationRequest {
            agent_id: "agent-01".to_string(),
            operation_id: "op-test".to_string(),
            destination_url: "https://api.service.example.com/v1/data".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
        };
        let secret = SecretString::new("token-1234\r\nX-Injected: yes");

        let result = adapter.execute(&req, &secret);
        assert!(matches!(result, Err(BoundaryError::InvalidRequest(_))));
        assert!(
            mock_transport.get_recorded_requests().is_empty(),
            "the request must not reach the transport"
        );
    }

    #[test]
    fn test_pinned_transport_receives_pinned_socket_addrs() {
        let mock_resolver = Arc::new(MockDnsResolver::new());
        let mock_transport = Arc::new(MockHttpTransport::new());

        let expected_addr = SocketAddr::from(([93, 184, 216, 34], 443));
        mock_resolver.insert("safe.example.com", 443, vec![expected_addr]);

        let adapter = HttpOperationAdapter::with_resolver_and_transport(
            HttpAdapterConfig::default(),
            mock_resolver,
            mock_transport.clone(),
        );

        let req = OperationRequest {
            agent_id: "agent-01".to_string(),
            operation_id: "op-test".to_string(),
            destination_url: "https://safe.example.com/v1/data".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
        };
        let secret = SecretString::new("my-token");

        let result = adapter.execute(&req, &secret);
        assert!(result.is_ok());

        let recorded = mock_transport.get_recorded_requests();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].pinned_addrs, vec![expected_addr]);
        assert_eq!(recorded[0].host_header, "safe.example.com");
    }
}
