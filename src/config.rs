//! Configuration, read from command-line flags or environment variables. Every setting has both;
//! flags win. Secrets are [`Secret`]s with `hide_env_values = true`, so `--help` never prints them
//! and nothing that debug-prints the configuration leaks them.

use std::convert::Infallible;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use http::Uri;
use uuid::Uuid;

/// The gateway's settings.
#[derive(Debug, Clone, Parser)]
#[command(name = "radius-gateway", version, about)]
pub struct Config {
    /// Address the proxy listens on for the traffic nginx (or clients) send it.
    #[arg(long, env = "LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// Address of the admin listener (`/healthz`, `/readyz`, `/policy`). Keep it private: it's
    /// unauthenticated.
    #[arg(long, env = "ADMIN_LISTEN", default_value = "127.0.0.1:9901")]
    pub admin_listen: SocketAddr,

    /// The seller's API the gateway proxies to, e.g. `http://127.0.0.1:3000` or
    /// `https://api.internal/v1`. A path is used as a prefix for every forwarded request.
    #[arg(long, env = "UPSTREAM", value_parser = parse_upstream, required_unless_present = "export_pages")]
    pub upstream: Option<Uri>,

    /// How long to wait for the upstream's response headers, and again for the part of a paid
    /// response's body that is buffered before settlement.
    #[arg(long, env = "UPSTREAM_TIMEOUT", default_value = "30s", value_parser = parse_duration)]
    pub upstream_timeout: Duration,

    /// How long to wait for a TCP connection to the upstream.
    #[arg(long, env = "UPSTREAM_CONNECT_TIMEOUT", default_value = "5s", value_parser = parse_duration)]
    pub upstream_connect_timeout: Duration,

    /// The Radius Platform API the compiled policy is fetched from.
    #[arg(
        long,
        env = "PLATFORM_API_URL",
        default_value = "https://platform-api.radiustech.xyz",
        value_parser = parse_origin_with_prefix
    )]
    pub platform_api_url: String,

    /// An organization API key with `endpoints:read`.
    #[arg(
        long,
        env = "PLATFORM_API_KEY",
        hide_env_values = true,
        required_unless_present = "export_pages"
    )]
    pub platform_api_key: Option<Secret>,

    /// The organization the project belongs to (`org_…`).
    #[arg(
        long,
        env = "ORGANIZATION_ID",
        required_unless_present = "export_pages"
    )]
    pub organization_id: Option<String>,

    /// The project whose policy this gateway enforces.
    #[arg(long, env = "PROJECT_ID", required_unless_present = "export_pages")]
    pub project_id: Option<Uuid>,

    /// How often to ask the platform for a newer policy. The gate standard allows 1s at most; 30
    /// to 60 seconds is right for most deployments.
    #[arg(long, env = "POLL_INTERVAL", default_value = "30s", value_parser = parse_poll_interval)]
    pub poll_interval: Duration,

    /// How long startup waits for the first policy before serving. `0` serves at once, under
    /// `--no-policy` until the first fetch succeeds.
    #[arg(long, env = "STARTUP_POLICY_WAIT", default_value = "5s", value_parser = parse_duration)]
    pub startup_policy_wait: Duration,

    /// The URL buyers reach this gateway at, e.g. `https://api.example.com` or
    /// `https://example.com/api`: the base of the `resource.url` in payment challenges. Without
    /// it the URL is rebuilt from `X-Forwarded-Proto`, `X-Forwarded-Host` and `Host`.
    #[arg(long, env = "PUBLIC_URL", value_parser = parse_origin_with_prefix)]
    pub public_url: Option<String>,

    /// What to do with requests while no policy has ever been loaded (gate standard,
    /// `failure.no_policy`): pass them through, or answer 503 `policy_unavailable`.
    #[arg(long, env = "NO_POLICY", value_enum, default_value_t = NoPolicy::Deny, ignore_case = true)]
    pub no_policy: NoPolicy,

    /// `maxTimeoutSeconds` offered in payment challenges: how long a signed payment stays valid.
    #[arg(long, env = "MAX_TIMEOUT_SECONDS", default_value_t = 60)]
    pub max_timeout_seconds: u32,

    /// Timeout of each facilitator call (`/verify`, `/settle`).
    #[arg(long, env = "FACILITATOR_TIMEOUT", default_value = "20s", value_parser = parse_duration)]
    pub facilitator_timeout: Duration,

    /// How much of a paid upstream response is buffered before settling, in bytes. A larger
    /// response is settled once its status is known and streamed.
    #[arg(long, env = "PAID_BODY_LIMIT", default_value_t = 10 * 1024 * 1024)]
    pub paid_body_limit: usize,

    /// How long a used payment stays claimed, so it can't pay for a second request.
    #[arg(long, env = "CLAIM_TTL", default_value = "24h", value_parser = parse_duration)]
    pub claim_ttl: Duration,

    /// A directory of page files that override the built-in ones: `402.html`, the payment
    /// page a browser gets, and anything under `assets/`, served at `/_radius/assets/`. Start
    /// from the built-in files with `--export-pages`.
    #[arg(long, env = "PAGES_DIR", value_name = "DIR")]
    pub pages_dir: Option<PathBuf>,

    /// Write the built-in page files to this directory and exit.
    #[arg(long, value_name = "DIR")]
    pub export_pages: Option<PathBuf>,

    /// A name shown at the top of the payment page.
    #[arg(long, env = "BRAND")]
    pub brand: Option<String>,

    /// Where the brand name links to.
    #[arg(long, env = "BRAND_URL", value_parser = parse_http_url)]
    pub brand_url: Option<String>,

    /// How long a browser's ticket for a page it paid for stays valid.
    #[arg(long, env = "TICKET_TTL", default_value = "60s", value_parser = parse_duration, hide = true)]
    pub ticket_ttl: Duration,

    /// Log filter, in `tracing_subscriber::EnvFilter` syntax.
    #[arg(long, env = "RUST_LOG", default_value = "info,radius_gateway=debug")]
    pub log_filter: String,

    /// Log format.
    #[arg(long, env = "LOG_FORMAT", value_enum, default_value_t = LogFormat::Text, ignore_case = true)]
    pub log_format: LogFormat,
}

/// The settings a running gateway can't do without. They're optional on the command line only
/// so `--export-pages` can run without them.
pub struct Required<'a> {
    pub upstream: &'a Uri,
    pub platform_api_key: &'a Secret,
    pub organization_id: &'a str,
    pub project_id: Uuid,
}

impl Config {
    pub fn required(&self) -> anyhow::Result<Required<'_>> {
        let missing = |flag: &str| anyhow::anyhow!("{flag} is required (unless --export-pages)");
        Ok(Required {
            upstream: self
                .upstream
                .as_ref()
                .ok_or_else(|| missing("--upstream"))?,
            platform_api_key: self
                .platform_api_key
                .as_ref()
                .ok_or_else(|| missing("--platform-api-key"))?,
            organization_id: self
                .organization_id
                .as_deref()
                .ok_or_else(|| missing("--organization-id"))?,
            project_id: self.project_id.ok_or_else(|| missing("--project-id"))?,
        })
    }
}

/// `defaults.failure.no_policy`, which the gate reads from its own configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NoPolicy {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

/// A configuration value that must never be printed, like an API key. Its `Debug` output is
/// redacted. Pair it with `hide_env_values = true` on the clap argument.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The secret value, for the one place that needs it (an `Authorization` header).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl FromStr for Secret {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value.trim()).map_err(|error| format!("{error}, e.g. `30s` or `5m`"))
}

fn parse_poll_interval(value: &str) -> Result<Duration, String> {
    let duration = parse_duration(value)?;
    if duration < Duration::from_secs(1) {
        return Err("must be at least 1s: gates must not poll the platform more often".to_owned());
    }
    Ok(duration)
}

/// An `http` or `https` URL with a host and an optional path prefix, without a query or fragment,
/// with any trailing slash dropped.
fn parse_origin_with_prefix(value: &str) -> Result<String, String> {
    let url = value.trim().trim_end_matches('/');
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| format!("must start with `https://` or `http://`, e.g. `https://{url}`"))?;
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() || rest.contains(['?', '#']) {
        return Err(
            "must be a URL with a host and no query, e.g. `https://api.example.com`".to_owned(),
        );
    }
    Ok(url.to_owned())
}

/// An `http` or `https` URL, as given.
fn parse_http_url(value: &str) -> Result<String, String> {
    let url = value.trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) || url.len() < 9 {
        return Err("must be an http:// or https:// URL".to_owned());
    }
    Ok(url.to_owned())
}

/// The upstream as a URI with a scheme and an authority: `host:port` gets `http://`.
fn parse_upstream(value: &str) -> Result<Uri, String> {
    let text = value.trim();
    let text = if text.contains("://") {
        text.to_owned()
    } else {
        format!("http://{text}")
    };
    let uri: Uri = text.parse().map_err(|error| format!("{error}"))?;
    match uri.scheme_str() {
        Some("http" | "https") => {}
        _ => return Err("must be an http:// or https:// URL".to_owned()),
    }
    if uri.authority().is_none() {
        return Err("must name a host, e.g. `http://127.0.0.1:3000`".to_owned());
    }
    if uri.query().is_some() {
        return Err("must not have a query string".to_owned());
    }
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only flags here: clap also reads the real environment, which unit tests don't control.
    // Environment variables are covered by `tests/cli.rs`, which runs the binary with a cleared
    // environment.
    fn parse(extra: &[&str]) -> Result<Config, clap::Error> {
        parse_with_upstream("http://127.0.0.1:3000", extra)
    }

    fn parse_with_upstream(upstream: &str, extra: &[&str]) -> Result<Config, clap::Error> {
        let mut args = vec![
            "radius-gateway",
            "--upstream",
            upstream,
            "--platform-api-key",
            "sk_test",
            "--organization-id",
            "org_1",
            "--project-id",
            "01a1c14b-cc9f-7033-92d3-bd51d003d97e",
        ];
        args.extend_from_slice(extra);
        Config::try_parse_from(args)
    }

    #[test]
    fn defaults() {
        let config = parse(&[]).unwrap();
        assert_eq!(config.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        assert_eq!(config.no_policy, NoPolicy::Deny);
        assert_eq!(config.paid_body_limit, 10 * 1024 * 1024);
        assert_eq!(
            config.platform_api_url,
            "https://platform-api.radiustech.xyz"
        );
    }

    #[test]
    fn secrets_are_redacted() {
        let config = parse(&[]).unwrap();
        assert_eq!(
            format!("{:?}", config.platform_api_key),
            "Some(Secret([redacted]))"
        );
        assert!(!format!("{config:?}").contains("sk_test"));
        assert_eq!(
            config.required().unwrap().platform_api_key.expose(),
            "sk_test"
        );
    }

    #[test]
    fn upstream_accepts_host_port_and_urls() {
        for (flag, expected) in [
            ("127.0.0.1:3000", "http://127.0.0.1:3000/"),
            ("http://api.internal", "http://api.internal/"),
            ("https://api.internal/v1", "https://api.internal/v1"),
        ] {
            let config = parse_with_upstream(flag, &[]).unwrap();
            assert_eq!(
                config.required().unwrap().upstream.to_string(),
                expected,
                "{flag}"
            );
        }
        for flag in ["ftp://x", "http://api.internal/?a=b", "http://"] {
            assert!(parse_with_upstream(flag, &[]).is_err(), "{flag}");
        }
    }

    #[test]
    fn export_pages_needs_nothing_else() {
        let config =
            Config::try_parse_from(["radius-gateway", "--export-pages", "/tmp/pages"]).unwrap();
        assert!(config.export_pages.is_some());
        assert!(config.required().is_err());
        assert!(Config::try_parse_from(["radius-gateway"]).is_err());
    }

    #[test]
    fn poll_interval_has_a_floor() {
        assert!(parse(&["--poll-interval", "500ms"]).is_err());
        assert_eq!(
            parse(&["--poll-interval", "1m"]).unwrap().poll_interval,
            Duration::from_secs(60)
        );
    }

    #[test]
    fn public_url_allows_a_prefix() {
        for (flag, expected) in [
            ("https://api.example.com/", "https://api.example.com"),
            ("https://example.com/api/", "https://example.com/api"),
        ] {
            let config = parse(&["--public-url", flag]).unwrap();
            assert_eq!(config.public_url.as_deref(), Some(expected), "{flag}");
        }
        for flag in ["api.example.com", "https://", "https://a.example/x?y=1"] {
            assert!(parse(&["--public-url", flag]).is_err(), "{flag}");
        }
    }
}
