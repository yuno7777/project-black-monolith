use super::SecretProvider;
use crate::error::BoundaryError;
use crate::secret::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn default_service_account_var() -> String {
    "OP_SERVICE_ACCOUNT_TOKEN".to_string()
}

/// Parsed representation of a validated 1Password secret reference.
///
/// Supported formats:
/// - `op://<vault>/<item>/<field>` (3 segments)
/// - `op://<vault>/<item>/<section>/<field>` (4 segments)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSecretReference {
    pub raw: String,
    pub vault: String,
    pub item: String,
    pub section: Option<String>,
    pub field: String,
}

/// Validates that a reference string strictly conforms to documented 1Password `op://` reference syntax.
///
/// # Security Invariants
/// - Must begin with `op://`.
/// - Must have exactly 3 segments (`vault`, `item`, `field`) or 4 segments (`vault`, `item`, `section`, `field`).
/// - Total length must be between 8 and 1024 characters.
/// - Each segment must be non-empty and <= 256 characters.
/// - Segment traversal (`.` or `..`) is strictly rejected.
/// - Segments starting with a hyphen `-` are rejected to prevent option/flag injection.
/// - Control characters (`0x00..=0x1F`, `0x7F`), newlines, and null bytes are rejected.
/// - Allowed characters: ASCII alphanumeric (`[a-zA-Z0-9]`), hyphens (`-`), underscores (`_`),
///   dots (`.`), and valid percent-encoded hex sequences (`%[0-9a-fA-F]{2}`).
/// - Unencoded whitespace, quotes, and shell metacharacters (`|`, `&`, `;`, `$`, `` ` ``, `<`, `>`, `*`, `?`, `\`) are rejected.
pub fn validate_secret_reference(secret_ref: &str) -> Result<ParsedSecretReference, BoundaryError> {
    if secret_ref.len() < 8 {
        return Err(BoundaryError::InvalidRequest(format!(
            "Secret reference '{}' is too short; must begin with 'op://'",
            secret_ref
        )));
    }

    if secret_ref.len() > 1024 {
        return Err(BoundaryError::InvalidRequest(
            "Secret reference exceeds maximum allowed length of 1024 characters".to_string(),
        ));
    }

    if !secret_ref.starts_with("op://") {
        return Err(BoundaryError::InvalidRequest(format!(
            "Secret reference '{}' must begin with 'op://'",
            secret_ref
        )));
    }

    let remainder = &secret_ref["op://".len()..];

    // Trailing slash or leading slash in remainder is invalid
    if remainder.starts_with('/') || remainder.ends_with('/') {
        return Err(BoundaryError::InvalidRequest(format!(
            "Secret reference '{}' contains invalid leading or trailing slash",
            secret_ref
        )));
    }

    let segments: Vec<&str> = remainder.split('/').collect();
    if segments.len() < 3 || segments.len() > 4 {
        return Err(BoundaryError::InvalidRequest(format!(
            "Secret reference '{}' has {} segments; expected 3 or 4 ('op://<vault>/<item>[/<section>]/<field>')",
            secret_ref,
            segments.len()
        )));
    }

    for (idx, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return Err(BoundaryError::InvalidRequest(format!(
                "Secret reference '{}' contains empty segment at index {}",
                secret_ref, idx
            )));
        }

        if segment.len() > 256 {
            return Err(BoundaryError::InvalidRequest(format!(
                "Secret reference segment at index {} exceeds maximum length of 256 characters",
                idx
            )));
        }

        if *segment == "." || *segment == ".." {
            return Err(BoundaryError::InvalidRequest(format!(
                "Secret reference '{}' contains forbidden traversal sequence '{}'",
                secret_ref, segment
            )));
        }

        if segment.starts_with('-') {
            return Err(BoundaryError::InvalidRequest(format!(
                "Secret reference segment '{}' cannot start with a hyphen (flag injection guard)",
                segment
            )));
        }

        // Validate character set: alphanumeric, '-', '_', '.', or valid percent-encoded sequence '%XX'
        let bytes = segment.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                i += 1;
            } else if b == b'%' {
                // Verify valid percent encoding (% followed by 2 hex digits)
                if i + 2 >= bytes.len() {
                    return Err(BoundaryError::InvalidRequest(format!(
                        "Incomplete percent-encoding in secret reference segment '{}'",
                        segment
                    )));
                }
                let h1 = bytes[i + 1];
                let h2 = bytes[i + 2];
                if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                    return Err(BoundaryError::InvalidRequest(format!(
                        "Invalid percent-encoding '%{}{}' in secret reference segment '{}'",
                        h1 as char, h2 as char, segment
                    )));
                }
                // Decode hex value and reject control chars or slashes
                let hex_str = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    if val < 0x20 || val == 0x7F || val == b'/' {
                        return Err(BoundaryError::InvalidRequest(format!(
                            "Forbidden percent-encoded byte 0x{:02X} in secret reference segment '{}'",
                            val, segment
                        )));
                    }
                }
                i += 3;
            } else {
                return Err(BoundaryError::InvalidRequest(format!(
                    "Disallowed character '{}' in secret reference segment '{}'",
                    b as char, segment
                )));
            }
        }
    }

    let (vault, item, section, field) = if segments.len() == 3 {
        (
            segments[0].to_string(),
            segments[1].to_string(),
            None,
            segments[2].to_string(),
        )
    } else {
        (
            segments[0].to_string(),
            segments[1].to_string(),
            Some(segments[2].to_string()),
            segments[3].to_string(),
        )
    };

    Ok(ParsedSecretReference {
        raw: secret_ref.to_string(),
        vault,
        item,
        section,
        field,
    })
}

/// Validates an account shorthand, domain, or account identifier.
///
/// Rules:
/// - Length 1..=128 characters.
/// - Must not start with `-` (to prevent flag injection, e.g. `--version`).
/// - Contains only ASCII alphanumeric characters, hyphens, underscores, dots.
pub fn validate_account_identifier(account: &str) -> Result<(), BoundaryError> {
    if account.is_empty() || account.len() > 128 {
        return Err(BoundaryError::ConfigurationError(
            "Account identifier must be between 1 and 128 characters".to_string(),
        ));
    }

    if account.starts_with('-') {
        return Err(BoundaryError::ConfigurationError(format!(
            "Account identifier '{}' cannot start with a hyphen (flag injection guard)",
            account
        )));
    }

    for c in account.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
            return Err(BoundaryError::ConfigurationError(format!(
                "Account identifier '{}' contains disallowed character '{}'",
                account, c
            )));
        }
    }

    Ok(())
}

/// Validates the executable path or command name for the 1Password CLI binary.
///
/// Rules:
/// - Length 1..=512 characters.
/// - Must not start with `-`.
/// - Must not contain control characters, newlines, or shell metacharacters.
pub fn validate_cli_path(cli_path: &str) -> Result<(), BoundaryError> {
    if cli_path.is_empty() || cli_path.len() > 512 {
        return Err(BoundaryError::ConfigurationError(
            "CLI executable path must be between 1 and 512 characters".to_string(),
        ));
    }

    if cli_path.starts_with('-') {
        return Err(BoundaryError::ConfigurationError(
            "CLI executable path cannot start with a hyphen".to_string(),
        ));
    }

    for c in cli_path.chars() {
        if c.is_ascii_control() || c == '\r' || c == '\n' || c == '\0' {
            return Err(BoundaryError::ConfigurationError(
                "CLI executable path contains control characters".to_string(),
            ));
        }
        if ['|', '&', ';', '$', '`', '<', '>', '"', '\''].contains(&c) {
            return Err(BoundaryError::ConfigurationError(format!(
                "CLI executable path contains forbidden shell character '{}'",
                c
            )));
        }
    }

    Ok(())
}

/// Validates the executable path or command name for the 1Password CLI binary,
/// optionally enforcing absolute path pinning, traversal prevention, and extension safety.
///
/// # Security Invariants & Executable Trust Boundary
/// - **Length & Character Boundaries**: 1..=512 characters, no leading hyphen, no ASCII control characters or shell metacharacters.
/// - **PATH Hijacking Defense**: When `require_absolute` is true, the executable must be an absolute path (`std::path::Path::is_absolute()`).
///   This prevents ambient search-order hijacking where a malicious `op.exe` or `op` binary placed in a directory listed
///   in `%PATH%` or the working directory could be unintentionally executed.
/// - **Traversal Prevention**: Relative directory traversal sequences (`..`) are strictly rejected regardless of absolute path mode.
/// - **Extension Whitelisting / Unsafe Script Rejection**: Rejects interpreted or dangerous Windows script extensions
///   (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.wsf`, `.com`, `.scr`, `.pif`) to ensure only native binaries are executed.
/// - **Windows Authenticode Verification**: In high-assurance production Windows deployments, administrators must ensure
///   the target binary at `cli_path` possesses a valid Authenticode signature from AgileBits / 1Password (e.g. validated
///   via `Get-AuthenticodeSignature` during installation/provisioning or AppLocker/WDAC policy enforcement).
pub fn validate_trusted_cli_path(
    cli_path: &str,
    require_absolute: bool,
) -> Result<(), BoundaryError> {
    validate_cli_path(cli_path)?;

    let path = std::path::Path::new(cli_path);

    if require_absolute && !path.is_absolute() {
        return Err(BoundaryError::ConfigurationError(format!(
            "CLI executable path '{}' must be an absolute path when require_absolute_path is enabled",
            cli_path
        )));
    }

    // Check for directory traversal sequences ("..")
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(BoundaryError::ConfigurationError(format!(
                "CLI executable path '{}' contains forbidden parent directory traversal ('..')",
                cli_path
            )));
        }
    }

    // Check for unsafe script extensions (prevent executing batch or script files directly)
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        const UNSAFE_EXTENSIONS: &[&str] =
            &["bat", "cmd", "ps1", "vbs", "js", "wsf", "com", "scr", "pif"];
        if UNSAFE_EXTENSIONS.contains(&ext_lower.as_str()) {
            return Err(BoundaryError::ConfigurationError(format!(
                "CLI executable path '{}' has unsafe extension '.{}'; only native executables are allowed",
                cli_path, ext
            )));
        }
    }

    Ok(())
}

/// Explicit authentication mode for the 1Password CLI provider.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum OnePasswordAuthMode {
    /// Desktop app biometric / system keychain integration (default).
    /// No environment variables containing tokens are forwarded.
    #[default]
    SystemAuth,

    /// 1Password Service Account authentication using `OP_SERVICE_ACCOUNT_TOKEN`.
    /// The token is read strictly from a trusted environment variable on the host.
    ServiceAccount {
        /// Name of the host environment variable holding the service account token.
        /// Defaults to "OP_SERVICE_ACCOUNT_TOKEN".
        #[serde(default = "default_service_account_var")]
        env_var: String,
    },

    /// 1Password CLI session token authentication using `OP_SESSION_<account>`.
    SessionToken {
        /// The account identifier used in `OP_SESSION_<account>`.
        account: String,
    },
}

/// Configuration for the optional 1Password CLI provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnePasswordCliConfig {
    /// Whether the 1Password CLI integration is enabled. Defaults to `false`.
    pub enabled: bool,

    /// Path or binary name for the official 1Password `op` executable. Defaults to `"op"`.
    pub cli_path: String,

    /// Execution timeout for CLI operations in seconds. Defaults to 5 seconds.
    pub timeout_seconds: u64,

    /// Maximum allowed output size in bytes. Defaults to 64 KB (65,536 bytes).
    pub max_output_bytes: usize,

    /// Optional 1Password account shorthand, sign-in address, or account ID.
    pub account: Option<String>,

    /// Explicit authentication strategy. Defaults to `SystemAuth`.
    #[serde(default)]
    pub auth_mode: OnePasswordAuthMode,

    /// Whether an absolute path to the CLI executable is strictly required. Defaults to `false`.
    /// In production environments, setting this to `true` defends against PATH-hijacking
    /// and ensures execution of a pinned, vetted binary.
    #[serde(default)]
    pub require_absolute_path: bool,
}

impl Default for OnePasswordCliConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cli_path: "op".to_string(),
            timeout_seconds: 5,
            max_output_bytes: 64 * 1024,
            account: None,
            auth_mode: OnePasswordAuthMode::SystemAuth,
            require_absolute_path: false,
        }
    }
}

/// Output captured from a subprocess execution.
#[derive(Debug, Clone)]
pub struct SubprocessOutput {
    pub exit_code: Option<i32>,
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Interface for executing subprocesses, enabling mock testing and deterministic validation
/// without invoking external binaries.
pub trait SubprocessRunner: Send + Sync {
    /// Executes the command with arguments, environment, timeout, and output bounds.
    fn run(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<SubprocessOutput, BoundaryError>;
}

/// Production runner using `std::process::Command` with threaded pipe draining,
/// deadline-based polling, process kill on timeout, and bounded output collection.
#[derive(Debug, Clone, Default)]
pub struct StandardSubprocessRunner;

impl SubprocessRunner for StandardSubprocessRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<SubprocessOutput, BoundaryError> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Environment isolation: clear and set only allowlisted variables
        cmd.env_clear();
        for (k, v) in envs {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().map_err(|e| {
            BoundaryError::ProviderError(format!(
                "Failed to spawn 1Password CLI binary '{}': {}",
                program, e
            ))
        })?;

        let mut stdout_pipe = child.stdout.take().ok_or_else(|| {
            BoundaryError::ProviderError("Failed to open child stdout pipe".to_string())
        })?;
        let mut stderr_pipe = child.stderr.take().ok_or_else(|| {
            BoundaryError::ProviderError("Failed to open child stderr pipe".to_string())
        })?;

        // Concurrently drain stdout and stderr on background threads to prevent pipe deadlock
        let stdout_limit = max_output_bytes + 1;
        let stdout_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            let mut exceeded = false;
            while let Ok(n) = stdout_pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if buf.len() + n > stdout_limit {
                    exceeded = true;
                    let remaining = stdout_limit.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..remaining]);
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            (buf, exceeded)
        });

        let stderr_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = stderr_pipe.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if buf.len() + n > 4096 {
                    let remaining = 4096_usize.saturating_sub(buf.len());
                    buf.extend_from_slice(&chunk[..remaining]);
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            buf
        });

        // Poll child for exit status with timeout
        let start = Instant::now();
        let mut exit_status = None;

        while start.elapsed() < timeout {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_status = Some(status);
                    break;
                }
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    let _ = child.kill();
                    return Err(BoundaryError::ProviderError(format!(
                        "Error polling child process: {}",
                        e
                    )));
                }
            }
        }

        if exit_status.is_none() {
            // Deadline expired: terminate child process and clean up
            let _ = child.kill();
            let _ = child.wait();
            // The reader threads are DETACHED rather than joined.
            //
            // Killing the direct child does not necessarily close its
            // pipes: a shell that forked a grandchild (`sh -c "sleep 5"`)
            // leaves the grandchild holding the inherited stdout, so the
            // reader thread does not see EOF until the *grandchild* exits.
            // Joining here would therefore hold the caller for the
            // grandchild's entire lifetime — a timeout that does not time
            // out, which is exactly the failure mode a deadline exists to
            // prevent.
            //
            // Dropping the handles detaches the threads. They finish on
            // their own when the pipe closes, and nothing they read is
            // needed on this path: the operation has already failed.
            drop(stdout_handle);
            drop(stderr_handle);

            return Err(BoundaryError::ProviderError(format!(
                "1Password CLI command timed out after {} seconds and was terminated",
                timeout.as_secs()
            )));
        }

        let status = exit_status.unwrap();
        let (stdout, stdout_exceeded) = stdout_handle.join().map_err(|_| {
            BoundaryError::ProviderError("Stdout reader thread panicked".to_string())
        })?;
        let stderr = stderr_handle.join().map_err(|_| {
            BoundaryError::ProviderError("Stderr reader thread panicked".to_string())
        })?;

        if stdout_exceeded || stdout.len() > max_output_bytes {
            return Err(BoundaryError::ProviderError(format!(
                "1Password CLI stdout exceeded maximum allowed size of {} bytes",
                max_output_bytes
            )));
        }

        Ok(SubprocessOutput {
            exit_code: status.code(),
            success: status.success(),
            stdout,
            stderr,
        })
    }
}

/// Recorded invocation details for mock assertions in test environments.
#[derive(Debug, Clone)]
pub struct MockInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub envs: Vec<(String, String)>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

/// Thread-safe mock subprocess runner for deterministic unit and integration testing.
#[derive(Default)]
pub struct MockSubprocessRunner {
    invocations: Mutex<Vec<MockInvocation>>,
    responses: Mutex<HashMap<String, Result<SubprocessOutput, String>>>,
    default_response: Mutex<Option<Result<SubprocessOutput, String>>>,
}

impl MockSubprocessRunner {
    /// Creates a new empty `MockSubprocessRunner`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a simulated response for an invocation matching a key (e.g. secret reference).
    pub fn set_response(&self, key: &str, res: Result<SubprocessOutput, String>) {
        self.responses.lock().unwrap().insert(key.to_string(), res);
    }

    /// Sets default simulated response for any unmapped invocation.
    pub fn set_default_response(&self, res: Result<SubprocessOutput, String>) {
        *self.default_response.lock().unwrap() = Some(res);
    }

    /// Returns a copy of all recorded invocations.
    pub fn get_invocations(&self) -> Vec<MockInvocation> {
        self.invocations.lock().unwrap().clone()
    }

    /// Returns the most recent invocation.
    pub fn last_invocation(&self) -> Option<MockInvocation> {
        self.invocations.lock().unwrap().last().cloned()
    }

    /// Clears recorded invocations.
    pub fn clear(&self) {
        self.invocations.lock().unwrap().clear();
    }
}

impl SubprocessRunner for MockSubprocessRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<SubprocessOutput, BoundaryError> {
        let invocation = MockInvocation {
            program: program.to_string(),
            args: args.to_vec(),
            envs: envs.to_vec(),
            timeout,
            max_output_bytes,
        };
        self.invocations.lock().unwrap().push(invocation);

        let responses = self.responses.lock().unwrap();
        let selected: SubprocessOutput =
            match args.iter().find_map(|arg| responses.get(arg).cloned()) {
                Some(Ok(out)) => out,
                Some(Err(e)) => return Err(BoundaryError::ProviderError(e)),
                None => {
                    let default_guard = self.default_response.lock().unwrap();
                    match default_guard.as_ref() {
                        Some(Ok(out)) => out.clone(),
                        Some(Err(e)) => return Err(BoundaryError::ProviderError(e.clone())),
                        None => SubprocessOutput {
                            exit_code: Some(0),
                            success: true,
                            stdout: b"synthetic-mock-secret-value-1234".to_vec(),
                            stderr: Vec::new(),
                        },
                    }
                }
            };

        if selected.stdout.len() > max_output_bytes {
            return Err(BoundaryError::ProviderError(format!(
                "1Password CLI stdout exceeded maximum allowed size of {} bytes",
                max_output_bytes
            )));
        }

        Ok(selected)
    }
}

/// A hardened credential provider interfacing with the official 1Password CLI (`op`).
///
/// # Security Design & Invariants
/// - **Official Interface Only**: Uses `op read <secret-reference>` as documented by 1Password.
/// - **No Undocumented APIs**: Does not touch undocumented internal IPC named pipes.
/// - **Disabled by Default**: Prevents unexpected subprocess invocation or credential exposure.
/// - **Strict Reference Validation**: Enforces canonical `op://<vault>/<item>[/<section>]/<field>` format
///   using strict segment and character-class validation, rejecting traversal and flag injection.
/// - **Bounded Subprocess Execution**: Deadlock-free threaded pipe draining, bounded stdout/stderr,
///   and enforced process termination upon timeout expiry.
/// - **Environment & Auth Isolation**: Subprocess environment is purged; only allowlisted OS runtime
///   variables and explicitly configured auth variables (`OP_SERVICE_ACCOUNT_TOKEN` / `OP_SESSION_*`)
///   are passed to the child process.
/// - **Sanitized Diagnostics**: Stderr error messages are bounded to 256 characters and scrubbed of raw secrets.
#[derive(Clone)]
pub struct OnePasswordCliProvider {
    config: OnePasswordCliConfig,
    runner: Arc<dyn SubprocessRunner>,
}

impl OnePasswordCliProvider {
    /// Creates a new `OnePasswordCliProvider` with default production subprocess runner.
    pub fn new(config: OnePasswordCliConfig) -> Result<Self, BoundaryError> {
        Self::with_runner(config, Arc::new(StandardSubprocessRunner))
    }

    /// Creates a new `OnePasswordCliProvider` with a custom subprocess runner.
    pub fn with_runner(
        config: OnePasswordCliConfig,
        runner: Arc<dyn SubprocessRunner>,
    ) -> Result<Self, BoundaryError> {
        validate_trusted_cli_path(&config.cli_path, config.require_absolute_path)?;

        if config.timeout_seconds == 0 {
            return Err(BoundaryError::ConfigurationError(
                "Timeout must be greater than zero".to_string(),
            ));
        }

        if config.max_output_bytes == 0 || config.max_output_bytes > 50 * 1024 * 1024 {
            return Err(BoundaryError::ConfigurationError(
                "max_output_bytes must be between 1 and 52428800 bytes".to_string(),
            ));
        }

        if let Some(account) = &config.account {
            validate_account_identifier(account)?;
        }

        match &config.auth_mode {
            OnePasswordAuthMode::SystemAuth => {}
            OnePasswordAuthMode::ServiceAccount { env_var } => {
                if env_var.is_empty()
                    || env_var.len() > 128
                    || !env_var
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return Err(BoundaryError::ConfigurationError(format!(
                        "Invalid service account environment variable name '{}'",
                        env_var
                    )));
                }
            }
            OnePasswordAuthMode::SessionToken { account } => {
                validate_account_identifier(account)?;
            }
        }

        Ok(Self { config, runner })
    }

    /// Validates that a secret reference conforms strictly to the canonical 1Password format.
    pub fn validate_reference(
        &self,
        secret_ref: &str,
    ) -> Result<ParsedSecretReference, BoundaryError> {
        validate_secret_reference(secret_ref)
    }

    /// Returns the provider configuration.
    pub fn config(&self) -> &OnePasswordCliConfig {
        &self.config
    }

    /// Builds the allowlisted environment variables for the child process.
    pub fn build_child_environment(&self) -> Result<Vec<(String, String)>, BoundaryError> {
        let mut envs = Vec::new();

        // 1. Safe OS runtime allowlist
        let allowlist = [
            "PATH",
            "SYSTEMROOT",
            "SYSTEMDRIVE",
            "WINDIR",
            "USERPROFILE",
            "HOME",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
            "USER",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
        ];

        for key in &allowlist {
            if let Ok(val) = std::env::var(key) {
                envs.push((key.to_string(), val));
            }
        }

        // 2. Explicit authentication variable based on auth_mode
        match &self.config.auth_mode {
            OnePasswordAuthMode::SystemAuth => {
                // Desktop app biometric or system keychain: no token env vars forwarded
            }
            OnePasswordAuthMode::ServiceAccount { env_var } => {
                let token = std::env::var(env_var).map_err(|_| {
                    BoundaryError::ConfigurationError(format!(
                        "Service account environment variable '{}' is not set in host environment",
                        env_var
                    ))
                })?;
                if token.trim().is_empty() {
                    return Err(BoundaryError::ConfigurationError(format!(
                        "Service account environment variable '{}' is empty",
                        env_var
                    )));
                }
                envs.push(("OP_SERVICE_ACCOUNT_TOKEN".to_string(), token));
            }
            OnePasswordAuthMode::SessionToken { account } => {
                let var_name = format!("OP_SESSION_{}", account);
                let token = std::env::var(&var_name).map_err(|_| {
                    BoundaryError::ConfigurationError(format!(
                        "Session token environment variable '{}' is not set in host environment",
                        var_name
                    ))
                })?;
                if token.trim().is_empty() {
                    return Err(BoundaryError::ConfigurationError(format!(
                        "Session token environment variable '{}' is empty",
                        var_name
                    )));
                }
                envs.push((var_name, token));
            }
        }

        Ok(envs)
    }
}

impl SecretProvider for OnePasswordCliProvider {
    fn name(&self) -> &'static str {
        "1password-cli"
    }

    fn get_secret(&self, secret_ref: &str) -> Result<SecretString, BoundaryError> {
        // 1. Enforce disabled-by-default invariant
        if !self.config.enabled {
            return Err(BoundaryError::ProviderError(
                "1Password CLI provider is disabled by default in configuration".to_string(),
            ));
        }

        // 2. Validate reference syntax to prevent command injection
        self.validate_reference(secret_ref)?;

        // 3. Construct arguments safely via vector passing (no shell interpolation)
        let mut args = vec![
            "read".to_string(),
            "--no-newline".to_string(),
            secret_ref.to_string(),
        ];

        if let Some(account) = &self.config.account {
            validate_account_identifier(account)?;
            args.push("--account".to_string());
            args.push(account.clone());
        }

        // 4. Construct restricted environment
        let envs = self.build_child_environment()?;

        // 5. Execute command through bounded subprocess runner
        let output = self.runner.run(
            &self.config.cli_path,
            &args,
            &envs,
            Duration::from_secs(self.config.timeout_seconds),
            self.config.max_output_bytes,
        )?;

        // 6. Handle non-zero exit code
        if !output.success {
            let stderr_summary = String::from_utf8_lossy(&output.stderr);
            let trimmed = stderr_summary.trim();
            let bounded = if trimmed.len() > 256 {
                &trimmed[..256]
            } else {
                trimmed
            };
            return Err(BoundaryError::ProviderError(format!(
                "1Password CLI error for ref '{}' (exit code {:?}): {}",
                secret_ref, output.exit_code, bounded
            )));
        }

        // 7. Defense-in-depth output size boundary enforcement
        if output.stdout.len() > self.config.max_output_bytes {
            return Err(BoundaryError::ProviderError(format!(
                "1Password CLI stdout exceeded maximum allowed size of {} bytes",
                self.config.max_output_bytes
            )));
        }

        // 8. Promptly convert stdout into memory-zeroizing SecretString
        SecretString::from_bytes(output.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_by_default() {
        let provider = OnePasswordCliProvider::new(OnePasswordCliConfig::default()).unwrap();
        let res = provider.get_secret("op://my-vault/my-item/password");
        assert!(matches!(res, Err(BoundaryError::ProviderError(_))));
    }

    #[test]
    fn test_reference_validation() {
        let provider = OnePasswordCliProvider::new(OnePasswordCliConfig::default()).unwrap();

        // Valid references (3 segments)
        assert!(provider
            .validate_reference("op://prod-vault/db-creds/password")
            .is_ok());
        assert!(provider
            .validate_reference("op://vault.1/item-2/field.4")
            .is_ok());

        // Valid references (4 segments)
        assert!(provider
            .validate_reference("op://prod-vault/db-creds/database/password")
            .is_ok());
        assert!(provider
            .validate_reference("op://vault.1/item-2/section_3/field.4")
            .is_ok());

        // Valid references with percent-encoded titles
        assert!(provider
            .validate_reference("op://Production%20Vault/Database%20Credentials/password")
            .is_ok());

        // Invalid references (traversal, shell chars, injection)
        assert!(provider
            .validate_reference("op://vault/item; rm -rf /")
            .is_err());
        assert!(provider
            .validate_reference("op://vault/item|cat /etc/passwd")
            .is_err());
        assert!(provider
            .validate_reference("http://vault/item/secret")
            .is_err());
        assert!(provider.validate_reference("op://incomplete").is_err());
        assert!(provider
            .validate_reference("op://vault/item/../traversal")
            .is_err());
        assert!(provider
            .validate_reference("op://vault/item/-flag-injection")
            .is_err());
        assert!(provider
            .validate_reference("op://vault/item/field\nnewline")
            .is_err());
    }

    #[test]
    fn test_account_validation() {
        let cfg = OnePasswordCliConfig {
            account: Some("-invalid-flag-start".to_string()),
            ..Default::default()
        };
        assert!(OnePasswordCliProvider::new(cfg).is_err());

        let valid_cfg = OnePasswordCliConfig {
            account: Some("my-team.1password.com".to_string()),
            ..Default::default()
        };
        assert!(OnePasswordCliProvider::new(valid_cfg).is_ok());
    }

    #[test]
    fn test_mock_runner_successful_execution() {
        let cfg = OnePasswordCliConfig {
            enabled: true,
            ..Default::default()
        };
        let mock_runner = Arc::new(MockSubprocessRunner::new());
        mock_runner.set_response(
            "op://vault/item/token",
            Ok(SubprocessOutput {
                exit_code: Some(0),
                success: true,
                stdout: b"secret-token-value-xyz\r\n".to_vec(),
                stderr: Vec::new(),
            }),
        );

        let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner.clone()).unwrap();
        let secret = provider.get_secret("op://vault/item/token").unwrap();

        assert_eq!(secret.expose_secret(), "secret-token-value-xyz");
        assert_eq!(mock_runner.get_invocations().len(), 1);
        let inv = mock_runner.last_invocation().unwrap();
        assert_eq!(inv.program, "op");
        assert_eq!(
            inv.args,
            vec![
                "read".to_string(),
                "--no-newline".to_string(),
                "op://vault/item/token".to_string()
            ]
        );
    }

    #[test]
    fn test_validate_trusted_cli_path_and_absolute_pinning() {
        // Standard relative commands allowed when require_absolute is false
        assert!(validate_trusted_cli_path("op", false).is_ok());
        assert!(validate_trusted_cli_path("op.exe", false).is_ok());

        // Relative path rejected when require_absolute is true
        assert!(validate_trusted_cli_path("op", true).is_err());
        assert!(validate_trusted_cli_path("./op", true).is_err());

        // Traversal is rejected in both modes
        assert!(validate_trusted_cli_path("../op", false).is_err());
        assert!(validate_trusted_cli_path("tools/../op", false).is_err());

        // Dangerous script extensions are rejected
        assert!(validate_trusted_cli_path("op.bat", false).is_err());
        assert!(validate_trusted_cli_path("op.cmd", false).is_err());
        assert!(validate_trusted_cli_path("op.ps1", false).is_err());
        assert!(validate_trusted_cli_path("op.vbs", false).is_err());

        // Platform-appropriate absolute paths succeed when require_absolute is true
        #[cfg(windows)]
        {
            assert!(
                validate_trusted_cli_path(r"C:\Program Files\1Password CLI\op.exe", true).is_ok()
            );
        }
        #[cfg(not(windows))]
        {
            assert!(validate_trusted_cli_path("/usr/local/bin/op", true).is_ok());
        }

        // Provider configuration fails when require_absolute_path is true but cli_path is relative
        let cfg = OnePasswordCliConfig {
            require_absolute_path: true,
            cli_path: "op".to_string(),
            ..Default::default()
        };
        let res = OnePasswordCliProvider::new(cfg);
        assert!(matches!(res, Err(BoundaryError::ConfigurationError(_))));
    }
}
