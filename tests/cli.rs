//! Runs the real binary with a controlled environment, so environment variables are tested
//! without touching this process's environment.

use std::process::{Command, Output};

fn gateway(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_radius-gateway"))
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_lists_every_setting_with_its_environment_variable() {
    let output = gateway(&["--help"], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let help = stdout(&output);
    for (flag, env) in [
        ("--listen", "LISTEN"),
        ("--admin-listen", "ADMIN_LISTEN"),
        ("--upstream", "UPSTREAM"),
        ("--upstream-timeout", "UPSTREAM_TIMEOUT"),
        ("--upstream-connect-timeout", "UPSTREAM_CONNECT_TIMEOUT"),
        ("--platform-api-url", "PLATFORM_API_URL"),
        ("--platform-api-key", "PLATFORM_API_KEY"),
        ("--organization-id", "ORGANIZATION_ID"),
        ("--project-id", "PROJECT_ID"),
        ("--poll-interval", "POLL_INTERVAL"),
        ("--startup-policy-wait", "STARTUP_POLICY_WAIT"),
        ("--public-url", "PUBLIC_URL"),
        ("--no-policy", "NO_POLICY"),
        ("--max-timeout-seconds", "MAX_TIMEOUT_SECONDS"),
        ("--facilitator-timeout", "FACILITATOR_TIMEOUT"),
        ("--paid-body-limit", "PAID_BODY_LIMIT"),
        ("--claim-ttl", "CLAIM_TTL"),
        ("--pages-dir", "PAGES_DIR"),
        ("--brand", "BRAND"),
        ("--brand-url", "BRAND_URL"),
        ("--log-filter", "RUST_LOG"),
        ("--log-format", "LOG_FORMAT"),
    ] {
        assert!(help.contains(flag), "missing {flag}");
        assert!(help.contains(&format!("[env: {env}")), "missing {env}");
    }
}

#[test]
fn version_names_the_commit() {
    let output = gateway(&["--version"], &[]);
    assert!(output.status.success());
    let text = stdout(&output);
    let id = text.trim().rsplit(' ').next().unwrap_or_default();
    let (version, commit) = id.split_once('+').expect("<version>+<commit>");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert!(
        commit == "unknown"
            || commit
                .trim_end_matches("-dirty")
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
        "{text}"
    );
}

#[test]
fn export_pages_writes_the_defaults_and_exits() {
    let dir = std::env::temp_dir().join(format!("radius-gateway-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let output = gateway(&["--export-pages", dir.to_str().unwrap()], &[]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("wrote 3 files"));
    for file in ["402.html", "assets/style.css", "assets/pay.js"] {
        assert!(dir.join(file).is_file(), "missing {file}");
    }
    assert!(stdout(&gateway(&["--help"], &[])).contains("--export-pages"));
    // A second export refuses to overwrite.
    let again = gateway(&["--export-pages", dir.to_str().unwrap()], &[]);
    assert!(!again.status.success());
    assert!(stderr(&again).contains("not overwriting"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_missing_pages_dir_fails_at_startup() {
    let output = gateway(
        &["--pages-dir", "/nonexistent/radius-gateway-pages"],
        &[
            ("UPSTREAM", "http://127.0.0.1:1"),
            ("PLATFORM_API_KEY", "sk_test"),
            ("ORGANIZATION_ID", "org_1"),
            ("PROJECT_ID", "01a1c14b-cc9f-7033-92d3-bd51d003d97e"),
            ("STARTUP_POLICY_WAIT", "0s"),
            ("LISTEN", "127.0.0.1:0"),
            ("ADMIN_LISTEN", "127.0.0.1:0"),
        ],
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a directory"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn help_never_prints_the_platform_api_key() {
    let output = gateway(&["--help"], &[("PLATFORM_API_KEY", "sk_live_secret")]);
    assert!(output.status.success());
    assert!(!stdout(&output).contains("sk_live_secret"));
}

#[test]
fn required_settings_are_reported() {
    let output = gateway(&[], &[]);
    assert!(!output.status.success());
    let err = stderr(&output);
    for flag in [
        "--upstream",
        "--platform-api-key",
        "--organization-id",
        "--project-id",
    ] {
        assert!(err.contains(flag), "missing {flag} in:\n{err}");
    }
}

#[test]
fn settings_come_from_the_environment() {
    // An invalid poll interval proves the variable was read, without starting a server.
    let output = gateway(
        &[],
        &[
            ("UPSTREAM", "http://127.0.0.1:1"),
            ("PLATFORM_API_KEY", "sk_test"),
            ("ORGANIZATION_ID", "org_1"),
            ("PROJECT_ID", "01a1c14b-cc9f-7033-92d3-bd51d003d97e"),
            ("POLL_INTERVAL", "100ms"),
        ],
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("at least 1s"),
        "{}",
        stderr(&output)
    );
}
