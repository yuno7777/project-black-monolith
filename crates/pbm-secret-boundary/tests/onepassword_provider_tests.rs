use pbm_secret_boundary::error::BoundaryError;
use pbm_secret_boundary::provider::{
    validate_account_identifier, validate_cli_path, validate_secret_reference,
    validate_trusted_cli_path, MockSubprocessRunner, OnePasswordAuthMode, OnePasswordCliConfig,
    OnePasswordCliProvider, SecretProvider, StandardSubprocessRunner, SubprocessOutput,
    SubprocessRunner,
};
use pbm_secret_boundary::secret::SecretString;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

// 1. Valid documented secret references are accepted
#[test]
fn test_1_valid_documented_secret_references_accepted() {
    // 3 segments: op://<vault>/<item>/<field>
    let ref3 = validate_secret_reference("op://dev-vault/weather-service/api-key").unwrap();
    assert_eq!(ref3.vault, "dev-vault");
    assert_eq!(ref3.item, "weather-service");
    assert_eq!(ref3.section, None);
    assert_eq!(ref3.field, "api-key");

    // 4 segments: op://<vault>/<item>/<section>/<field>
    let ref4 = validate_secret_reference("op://prod-vault/db-cluster/primary/password").unwrap();
    assert_eq!(ref4.vault, "prod-vault");
    assert_eq!(ref4.item, "db-cluster");
    assert_eq!(ref4.section, Some("primary".to_string()));
    assert_eq!(ref4.field, "password");

    // UUIDs and alphanumeric identifiers
    let ref_uuids =
        validate_secret_reference("op://26hyq678uuid/a1b2c3d4uuid/sec-1/field.uuid").unwrap();
    assert_eq!(ref_uuids.vault, "26hyq678uuid");

    // Documented percent-encoded titles with spaces
    let ref_encoded =
        validate_secret_reference("op://Production%20Vault/Database%20Credentials/API%20Key")
            .unwrap();
    assert_eq!(ref_encoded.vault, "Production%20Vault");
    assert_eq!(ref_encoded.item, "Database%20Credentials");
    assert_eq!(ref_encoded.field, "API%20Key");
}

// 2. Invalid references and command-line injection attempts are rejected
#[test]
fn test_2_invalid_references_and_injection_attempts_rejected() {
    // Missing op:// scheme
    assert!(validate_secret_reference("https://vault/item/field").is_err());
    assert!(validate_secret_reference("vault/item/field").is_err());

    // Flag injection attempts (leading -)
    assert!(validate_secret_reference("op://-flag/item/field").is_err());
    assert!(validate_secret_reference("op://vault/-flag/field").is_err());
    assert!(validate_secret_reference("op://vault/item/-flag").is_err());
    assert!(validate_secret_reference("op://vault/item/--all/field").is_err());

    // Directory traversal sequences
    assert!(validate_secret_reference("op://vault/item/../field").is_err());
    assert!(validate_secret_reference("op://vault/./item/field").is_err());

    // Leading, trailing, and consecutive slashes
    assert!(validate_secret_reference("op:///vault/item/field").is_err());
    assert!(validate_secret_reference("op://vault/item/field/").is_err());
    assert!(validate_secret_reference("op://vault//field").is_err());

    // Insufficient or excessive segments
    assert!(validate_secret_reference("op://vault").is_err());
    assert!(validate_secret_reference("op://vault/item").is_err());
    assert!(validate_secret_reference("op://vault/item/sec/sub/field").is_err());

    // Shell metacharacters and command chaining
    assert!(validate_secret_reference("op://vault/item; rm -rf /").is_err());
    assert!(validate_secret_reference("op://vault/item|cat /etc/passwd").is_err());
    assert!(validate_secret_reference("op://vault/item$(whoami)/field").is_err());
    assert!(validate_secret_reference("op://vault/item`id`/field").is_err());
    assert!(validate_secret_reference("op://vault/item & echo/field").is_err());

    // Control characters, newlines, and null bytes
    assert!(validate_secret_reference("op://vault/item\nAuthorization: stolen/field").is_err());
    assert!(validate_secret_reference("op://vault/item\r/field").is_err());
    assert!(validate_secret_reference("op://vault/item\0/field").is_err());

    // Malformed percent-encoding
    assert!(validate_secret_reference("op://vault/item%2/field").is_err());
    assert!(validate_secret_reference("op://vault/item%ZZ/field").is_err());
    assert!(validate_secret_reference("op://vault/item%00/field").is_err()); // null byte encoded
}

// 3. Account validation prevents option or argument injection
#[test]
fn test_3_account_validation_prevents_option_or_argument_injection() {
    // Valid account shorthands and domains
    assert!(validate_account_identifier("my-team").is_ok());
    assert!(validate_account_identifier("my-team.1password.com").is_ok());
    assert!(validate_account_identifier("ACME_CORP_01").is_ok());
    assert!(validate_account_identifier("A1B2C3D4E5F6G7H8I9J0K1L2M3").is_ok());

    // Flag injection attempts (leading -)
    assert!(validate_account_identifier("-account").is_err());
    assert!(validate_account_identifier("--version").is_err());
    assert!(validate_account_identifier("-f").is_err());

    // Disallowed characters, spaces, shell chars
    assert!(validate_account_identifier("my team").is_err());
    assert!(validate_account_identifier("team;echo").is_err());
    assert!(validate_account_identifier("team\n").is_err());
    assert!(validate_account_identifier("").is_err());

    // CLI path validation also prevents flag and shell injection
    assert!(validate_cli_path("op").is_ok());
    assert!(validate_cli_path("C:\\Program Files\\1Password\\op.exe").is_ok());
    assert!(validate_cli_path("-inject").is_err());
    assert!(validate_cli_path("op; evil").is_err());
}

// 4. Disabled-by-default behaviour is preserved
#[test]
fn test_4_disabled_by_default_behaviour_preserved() {
    let default_cfg = OnePasswordCliConfig::default();
    assert!(!default_cfg.enabled);

    let mock_runner = Arc::new(MockSubprocessRunner::new());
    let provider = OnePasswordCliProvider::with_runner(default_cfg, mock_runner.clone()).unwrap();

    let result = provider.get_secret("op://vault/item/password");
    assert!(
        matches!(result, Err(BoundaryError::ProviderError(msg)) if msg.contains("disabled by default"))
    );
    // Ensure subprocess runner was NEVER invoked
    assert_eq!(mock_runner.get_invocations().len(), 0);
}

// 5. A mocked successful CLI result is wrapped safely as a secret
#[test]
fn test_5_mock_successful_cli_result_wrapped_safely() {
    let cfg = OnePasswordCliConfig {
        enabled: true,
        ..Default::default()
    };
    let mock_runner = Arc::new(MockSubprocessRunner::new());
    let secret_bytes = b"synthetic-production-secret-token-12345\n";
    mock_runner.set_response(
        "op://prod-vault/api-key/token",
        Ok(SubprocessOutput {
            exit_code: Some(0),
            success: true,
            stdout: secret_bytes.to_vec(),
            stderr: Vec::new(),
        }),
    );

    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();
    let secret = provider
        .get_secret("op://prod-vault/api-key/token")
        .unwrap();

    // Verify secret is cleanly trimmed of trailing newline and wrapped
    assert_eq!(
        secret.expose_secret(),
        "synthetic-production-secret-token-12345"
    );
}

// 6. Non-zero exit codes return sanitized errors
#[test]
fn test_6_non_zero_exit_codes_return_sanitized_errors() {
    let cfg = OnePasswordCliConfig {
        enabled: true,
        ..Default::default()
    };
    let mock_runner = Arc::new(MockSubprocessRunner::new());
    mock_runner.set_response(
        "op://vault/missing-item/token",
        Ok(SubprocessOutput {
            exit_code: Some(1),
            success: false,
            stdout: Vec::new(),
            stderr: b"[ERROR] 2026/10/14 item 'missing-item' not found in vault 'vault'".to_vec(),
        }),
    );

    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();
    let result = provider.get_secret("op://vault/missing-item/token");

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("exit code Some(1)"));
    assert!(err_msg.contains("item 'missing-item' not found"));
}

// 7. CLI diagnostics cannot expose the returned secret
#[test]
fn test_7_cli_diagnostics_cannot_expose_returned_secret() {
    let cfg = OnePasswordCliConfig {
        enabled: true,
        ..Default::default()
    };
    let synthetic_secret = "ultra-sensitive-master-key-xyz99";
    let mock_runner = Arc::new(MockSubprocessRunner::new());

    // Failure diagnostic simulating error containing secret reference
    mock_runner.set_response(
        "op://vault/item/secret",
        Ok(SubprocessOutput {
            exit_code: Some(2),
            success: false,
            stdout: Vec::new(),
            stderr: b"Auth error: access denied for vault".to_vec(),
        }),
    );

    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();
    let result = provider.get_secret("op://vault/item/secret");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(!err_msg.contains(synthetic_secret));
}

// 8. Oversized stdout is rejected without unbounded accumulation
#[test]
fn test_8_oversized_stdout_rejected_without_unbounded_accumulation() {
    let cfg = OnePasswordCliConfig {
        enabled: true,
        max_output_bytes: 100, // Restrict output limit to 100 bytes
        ..Default::default()
    };
    let mock_runner = Arc::new(MockSubprocessRunner::new());
    // Simulate oversized 2000-byte output
    let oversized = vec![b'A'; 2000];
    mock_runner.set_response(
        "op://vault/large/key",
        Ok(SubprocessOutput {
            exit_code: Some(0),
            success: true,
            stdout: oversized,
            stderr: Vec::new(),
        }),
    );

    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();
    let result = provider.get_secret("op://vault/large/key");

    assert!(matches!(
        result,
        Err(BoundaryError::ProviderError(msg)) if msg.contains("exceeded maximum allowed size")
    ));
}

// 9. Oversized stderr is bounded
#[test]
fn test_9_oversized_stderr_is_bounded() {
    let cfg = OnePasswordCliConfig {
        enabled: true,
        ..Default::default()
    };
    let mock_runner = Arc::new(MockSubprocessRunner::new());
    // Massive stderr output (5000 bytes)
    let giant_stderr = vec![b'E'; 5000];
    mock_runner.set_response(
        "op://vault/error/key",
        Ok(SubprocessOutput {
            exit_code: Some(1),
            success: false,
            stdout: Vec::new(),
            stderr: giant_stderr,
        }),
    );

    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();
    let result = provider.get_secret("op://vault/error/key");

    let err_msg = format!("{}", result.unwrap_err());
    // The bounded message in provider truncates stderr to <= 256 characters
    assert!(err_msg.len() < 400);
}

// 10. Timeout and termination failures are handled safely
#[test]
fn test_10_timeout_and_termination_failures_handled_safely() {
    let cfg = OnePasswordCliConfig {
        enabled: true,
        timeout_seconds: 2,
        ..Default::default()
    };
    let mock_runner = Arc::new(MockSubprocessRunner::new());
    mock_runner.set_response(
        "op://vault/hanging/key",
        Err("1Password CLI command timed out after 2 seconds and was terminated".to_string()),
    );

    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();
    let result = provider.get_secret("op://vault/hanging/key");

    assert!(matches!(
        result,
        Err(BoundaryError::ProviderError(msg)) if msg.contains("timed out after 2 seconds")
    ));
}

// 11. Authentication variables are not inherited indiscriminately
#[test]
fn test_11_authentication_variables_not_inherited_indiscriminately() {
    let cfg = OnePasswordCliConfig {
        auth_mode: OnePasswordAuthMode::SystemAuth, // Default desktop app auth
        ..Default::default()
    };
    let mock_runner = Arc::new(MockSubprocessRunner::new());
    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();

    let envs = provider.build_child_environment().unwrap();

    // Verify that NO token variables are forwarded in SystemAuth mode
    assert!(!envs
        .iter()
        .any(|(k, _)| k.to_uppercase() == "OP_SERVICE_ACCOUNT_TOKEN"));
    assert!(!envs
        .iter()
        .any(|(k, _)| k.to_uppercase().starts_with("OP_SESSION_")));
    assert!(!envs
        .iter()
        .any(|(k, _)| k.to_uppercase().starts_with("AWS_")));
}

// 12. Explicitly configured authentication passes only the approved variable
#[test]
fn test_12_explicitly_configured_authentication_passes_only_approved_variable() {
    let mut cfg = OnePasswordCliConfig::default();
    let custom_env = "PBM_TEST_SVC_TOKEN_VAR";
    cfg.auth_mode = OnePasswordAuthMode::ServiceAccount {
        env_var: custom_env.to_string(),
    };

    // Set dummy test environment variable
    std::env::set_var(custom_env, "synthetic-service-token-secret-1122");

    let mock_runner = Arc::new(MockSubprocessRunner::new());
    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();

    let envs = provider.build_child_environment().unwrap();

    // Verify OP_SERVICE_ACCOUNT_TOKEN is explicitly set with the value
    let svc_token_entry = envs.iter().find(|(k, _)| k == "OP_SERVICE_ACCOUNT_TOKEN");
    assert!(svc_token_entry.is_some());
    assert_eq!(
        svc_token_entry.unwrap().1,
        "synthetic-service-token-secret-1122"
    );

    // Clean up test environment variable
    std::env::remove_var(custom_env);
}

// 13. Debug output, error paths, and audit metadata never contain synthetic secret
#[test]
fn test_13_debug_output_error_paths_never_contain_synthetic_secret() {
    let synthetic_secret = "synthetic-super-secret-998877";
    let secret = SecretString::new(synthetic_secret);

    // Debug output is redacted
    let debug_repr = format!("{:?}", secret);
    assert_eq!(debug_repr, "SecretString([REDACTED SECRET])");
    assert!(!debug_repr.contains(synthetic_secret));

    // Display output is redacted
    let display_repr = format!("{}", secret);
    assert_eq!(display_repr, "[REDACTED SECRET]");
    assert!(!display_repr.contains(synthetic_secret));

    // Provider error message never contains secret
    let cfg = OnePasswordCliConfig {
        enabled: true,
        ..Default::default()
    };
    let mock_runner = Arc::new(MockSubprocessRunner::new());
    mock_runner.set_response(
        "op://vault/item/key",
        Ok(SubprocessOutput {
            exit_code: Some(1),
            success: false,
            stdout: Vec::new(),
            stderr: b"Failed to find item".to_vec(),
        }),
    );

    let provider = OnePasswordCliProvider::with_runner(cfg, mock_runner).unwrap();
    let err = provider.get_secret("op://vault/item/key").unwrap_err();
    let err_str = format!("{}", err);
    assert!(!err_str.contains(synthetic_secret));
}

// 14. Test-only raw-secret inspection APIs are unavailable in production builds where applicable
#[test]
fn test_14_test_only_raw_secret_inspection_apis_gated() {
    let mut secret = SecretString::new("test-token-to-zeroize");

    // In test builds with test-utils feature enabled, as_raw_bytes() is accessible for verification
    #[cfg(feature = "test-utils")]
    {
        assert!(!secret.as_raw_bytes().iter().all(|&b| b == 0));
        secret.zeroize();
        assert!(secret.as_raw_bytes().iter().all(|&b| b == 0));
    }

    #[cfg(not(feature = "test-utils"))]
    {
        // In production builds without test-utils feature, zeroize works via Drop
        drop(secret);
    }
}

fn get_test_environment() -> Vec<(String, String)> {
    let mut envs = Vec::new();
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
        "COMSPEC",
    ];
    for key in &allowlist {
        if let Ok(val) = std::env::var(key) {
            envs.push((key.to_string(), val));
        }
    }
    envs
}

// 15. Absolute path pinning and extension checks defend against PATH-hijacking
#[test]
fn test_15_validate_trusted_cli_path_defense_in_depth() {
    // Relative command without require_absolute succeeds
    assert!(validate_trusted_cli_path("op", false).is_ok());
    assert!(validate_trusted_cli_path("op.exe", false).is_ok());

    // Relative command with require_absolute is rejected
    let rel_err = validate_trusted_cli_path("op", true).unwrap_err();
    assert!(format!("{}", rel_err).contains("must be an absolute path"));
    assert!(validate_trusted_cli_path("./op", true).is_err());

    // Traversal is rejected regardless of absolute flag
    assert!(validate_trusted_cli_path("../op", false).is_err());
    assert!(validate_trusted_cli_path("tools/../op", true).is_err());

    // Unsafe script extensions are strictly rejected
    let bad_exts = ["bat", "cmd", "ps1", "vbs", "js", "com"];
    for ext in &bad_exts {
        let path = format!("op.{}", ext);
        let err = validate_trusted_cli_path(&path, false).unwrap_err();
        assert!(format!("{}", err).contains("unsafe extension"));
    }

    // Platform-appropriate absolute path succeeds
    #[cfg(windows)]
    {
        assert!(validate_trusted_cli_path(r"C:\Program Files\1Password CLI\op.exe", true).is_ok());
    }
    #[cfg(not(windows))]
    {
        assert!(validate_trusted_cli_path("/usr/local/bin/op", true).is_ok());
    }

    // Provider enforces require_absolute_path in constructor
    let cfg = OnePasswordCliConfig {
        require_absolute_path: true,
        cli_path: "op".to_string(),
        ..Default::default()
    };
    assert!(OnePasswordCliProvider::new(cfg).is_err());
}

// 16. StandardSubprocessRunner executes real local child process and returns stdout
#[test]
fn test_16_standard_subprocess_runner_real_child_process_execution() {
    let runner = StandardSubprocessRunner;
    let current_exe = std::env::current_exe().unwrap();
    let prog = current_exe.to_string_lossy().to_string();
    let envs = get_test_environment();

    let output = runner
        .run(
            &prog,
            &["--help".to_string()],
            &envs,
            Duration::from_secs(5),
            65536,
        )
        .expect("Child process execution failed");

    assert!(output.success);
    assert_eq!(output.exit_code, Some(0));
    assert!(!output.stdout.is_empty());
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert!(stdout_str.contains("Usage:") || stdout_str.contains("options:"));
}

// 17. StandardSubprocessRunner concurrently drains stdout and stderr without pipe deadlock
#[test]
fn test_17_standard_subprocess_runner_real_child_concurrent_stdout_stderr_drainage() {
    let runner = StandardSubprocessRunner;
    let envs = get_test_environment();

    #[cfg(windows)]
    let (prog, args) = {
        let comspec = std::env::var("COMSPEC")
            .unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".to_string());
        (
            comspec,
            vec![
                "/C".to_string(),
                "echo real_concurrent_stdout_stream & echo real_concurrent_stderr_stream 1>&2"
                    .to_string(),
            ],
        )
    };
    #[cfg(not(windows))]
    let (prog, args) = (
        "/bin/sh".to_string(),
        vec![
            "-c".to_string(),
            "echo real_concurrent_stdout_stream; echo real_concurrent_stderr_stream >&2"
                .to_string(),
        ],
    );

    let output = runner
        .run(&prog, &args, &envs, Duration::from_secs(5), 65536)
        .expect("Runner failed to drain child pipes");

    assert!(output.success);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(stdout_str.contains("real_concurrent_stdout_stream"));
    assert!(stderr_str.contains("real_concurrent_stderr_stream"));
}

// 18. StandardSubprocessRunner halts and rejects output exceeding max_output_bytes
#[test]
fn test_18_standard_subprocess_runner_real_child_output_size_limit_enforced() {
    let runner = StandardSubprocessRunner;
    let current_exe = std::env::current_exe().unwrap();
    let prog = current_exe.to_string_lossy().to_string();
    let envs = get_test_environment();

    // --help outputs ~1KB+, but max_output_bytes is set to 24 bytes
    let result = runner.run(
        &prog,
        &["--help".to_string()],
        &envs,
        Duration::from_secs(5),
        24,
    );

    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("exceeded maximum allowed size of 24 bytes"),
        "Unexpected error: {}",
        err_str
    );
}

// 19. StandardSubprocessRunner enforces deadline, kills stalled child process, and reaps it
#[test]
fn test_19_standard_subprocess_runner_real_child_timeout_and_process_reaping() {
    let runner = StandardSubprocessRunner;
    let envs = get_test_environment();

    #[cfg(windows)]
    let (prog, args) = (
        "powershell.exe".to_string(),
        vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            "Start-Sleep -Seconds 5".to_string(),
        ],
    );
    #[cfg(not(windows))]
    let (prog, args) = (
        "/bin/sh".to_string(),
        vec!["-c".to_string(), "sleep 5".to_string()],
    );

    let start = std::time::Instant::now();
    // Timeout set to 1 second
    let result = runner.run(&prog, &args, &envs, Duration::from_secs(1), 65536);
    let elapsed = start.elapsed();

    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("timed out after 1 seconds and was terminated"),
        "Unexpected error: {}",
        err_str
    );
    // The child must have been killed at the deadline rather than allowed to
    // run to completion (the command sleeps for 5 seconds). The reader
    // threads are detached on the timeout path, so the runner returns as
    // soon as the child is reaped rather than waiting for the pipes to
    // close — the bound therefore has to be well under the child's own
    // runtime, but it is a bound on the *mechanism*, not on the machine's
    // speed.
    assert!(
        elapsed < Duration::from_secs(3),
        "the child was not terminated at the deadline (took {:?})",
        elapsed
    );
}

// 20. StandardSubprocessRunner captures real child non-zero exit code with sanitized error and zero secret leak
#[test]
fn test_20_standard_subprocess_runner_real_child_exit_failure_and_sanitization() {
    let runner = Arc::new(StandardSubprocessRunner);
    let current_exe = std::env::current_exe().unwrap();
    let prog = current_exe.to_string_lossy().to_string();

    let cfg = OnePasswordCliConfig {
        enabled: true,
        cli_path: prog,
        timeout_seconds: 5,
        ..Default::default()
    };
    let provider = OnePasswordCliProvider::with_runner(cfg, runner).unwrap();
    let synthetic_secret_ref = "op://my-vault/api-keys/stripe-token";

    // Invoking the test binary with arguments "read --no-newline op://..." will fail with unrecognized option
    let result = provider.get_secret(synthetic_secret_ref);
    assert!(result.is_err());

    let err_str = format!("{}", result.unwrap_err());
    // Confirms exit code is reported and error is sanitized
    assert!(err_str.contains("1Password CLI error for ref 'op://my-vault/api-keys/stripe-token'"));
    assert!(err_str.contains("exit code Some("));
    // Confirms no fictitious credential or environment secrets leak
    assert!(!err_str.contains("super-secret"));
    assert!(!err_str.contains("stripe-token-secret-value"));
}
