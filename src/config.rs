use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

/// Masking strategies understood by the interceptor. Anything else is rejected
/// at config load / rule ingest so a typo cannot silently degrade to "MASKED".
pub const KNOWN_STRATEGIES: &[&str] = &[
    "email",
    "phone",
    "address",
    "name",
    "text",
    "credit_card",
    "ssn",
    "ip",
    "dob",
    "passport",
    "hash",
    "json",
];

/// Heuristic detector names accepted in `heuristics.types`.
pub const KNOWN_HEURISTIC_TYPES: &[&str] = &[
    "email",
    "phone",
    "ssn",
    "credit_card",
    "ip",
    "dob",
    "passport",
];

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default = "default_masking_enabled")]
    pub masking_enabled: bool,
    pub rules: Vec<MaskingRule>,
    /// Secret used to key the deterministic masking functions (fake-data seeds
    /// and the `hash` strategy). When unset, a random per-process key is used,
    /// which keeps masking deterministic within a run but not across restarts.
    /// Can also be supplied via the IRONVEIL_MASKING_SECRET env var, which
    /// takes precedence over this field.
    #[serde(default)]
    pub masking_secret: Option<String>,
    /// Heuristic (rule-less) PII detection settings.
    #[serde(default)]
    pub heuristics: Option<HeuristicsConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub telemetry: Option<TelemetryConfig>,
    /// Where the proxy's own listener binds. Overridden by --bind/--port and
    /// by IRONVEIL_BIND/IRONVEIL_PORT.
    #[serde(default)]
    pub listen: Option<ListenConfig>,
    /// MySQL authentication handling: passthrough (default) or terminate.
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub api: Option<ApiConfig>,
    #[serde(default)]
    pub limits: Option<LimitsConfig>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub audit: Option<AuditConfig>,
}

/// Controls the heuristic scanner that masks values in columns with no
/// explicit rule. Only the detectors listed in `types` run; the ambiguous
/// detectors (`credit_card`, `ip`, `dob`, `passport`) are opt-in because they
/// rewrite legitimate data (order numbers, config addresses, every date
/// column) when enabled on a schema that stores such values.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HeuristicsConfig {
    #[serde(default = "default_heuristics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_heuristic_types")]
    pub types: Vec<String>,
}

impl Default for HeuristicsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            types: default_heuristic_types(),
        }
    }
}

fn default_heuristics_enabled() -> bool {
    true
}

fn default_heuristic_types() -> Vec<String> {
    vec!["email".to_string(), "phone".to_string(), "ssn".to_string()]
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum number of concurrent connections (default: unlimited)
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Rate limit: max new connections per second (default: unlimited)
    #[serde(default)]
    pub connections_per_second: Option<u32>,

    /// Timeout for establishing upstream connection in seconds (default: 30)
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,

    /// Idle timeout in seconds - close connection after no activity (default: 300)
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Maximum concurrent upstream sessions (default: unlimited)
    #[serde(default)]
    pub upstream_pool_size: Option<usize>,

    /// Max time to wait for an upstream slot before rejecting (default: 5)
    #[serde(default = "default_upstream_pool_wait_timeout")]
    pub upstream_pool_wait_timeout_secs: u64,
}

fn default_connect_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    300 // 5 minutes
}

fn default_upstream_pool_wait_timeout() -> u64 {
    5
}

/// Health check configuration for upstream database
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// Enable upstream health checks (default: true)
    #[serde(default = "default_health_enabled")]
    pub enabled: bool,

    /// Interval between health checks in seconds (default: 10)
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,

    /// Timeout for health check connection in seconds (default: 5)
    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u64,

    /// Number of consecutive failures before marking unhealthy (default: 3)
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of consecutive successes before marking healthy (default: 1)
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 1,
        }
    }
}

fn default_health_enabled() -> bool {
    true
}

fn default_health_interval() -> u64 {
    10
}

fn default_health_timeout() -> u64 {
    5
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    1
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Whether to run the management API at all (default: true).
    ///
    /// Set false to drop the control plane entirely. The management API is a
    /// global masking kill-switch and re-serves the log ring, so a deployment
    /// that does not consume `/health` or `/metrics` over HTTP — the localhost
    /// sidecar shape — is strictly better off without it listening.
    #[serde(default = "default_api_enabled")]
    pub enabled: bool,

    /// API key for authenticating management API requests.
    /// If set, all sensitive endpoints require `X-API-Key` header.
    #[serde(default)]
    pub api_key: Option<String>,

    /// JWT secret for token-based authentication.
    /// If set, endpoints also accept `Authorization: Bearer <token>` header.
    #[serde(default)]
    pub jwt_secret: Option<String>,

    /// Address the management API binds to (default: 127.0.0.1). Binding a
    /// non-loopback address requires api_key or jwt_secret to be configured.
    #[serde(default)]
    pub bind: Option<String>,

    /// Port the management API binds to (default: 3001).
    #[serde(default)]
    pub port: Option<u16>,

    /// Browser origins allowed to call the management API (CORS). Defaults to
    /// the local dashboard dev origins when unset.
    #[serde(default)]
    pub cors_origins: Option<Vec<String>>,
}

fn default_api_enabled() -> bool {
    true
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_key: None,
            jwt_secret: None,
            bind: None,
            port: None,
            cors_origins: None,
        }
    }
}

/// How the proxy handles MySQL authentication.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    /// Credential-transparent: the client's own MySQL credentials are
    /// forwarded verbatim upstream. The default, and the only behaviour before
    /// 0.3.0 — but it means the process exposed to clients necessarily handles
    /// the real database password.
    #[default]
    Passthrough,
    /// The proxy holds the upstream credential and authenticates its clients
    /// against a separate local one. MySQL only.
    Terminate,
}

/// Credentials for `auth.mode: terminate`.
///
/// Every secret can be given inline, from a file (for Kubernetes secret mounts
/// and Docker secrets), or from the environment. Precedence for each secret is
/// environment > file > inline, so a deployment can override a baked-in value
/// without rewriting the config.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub mode: AuthMode,

    /// Username clients must present. Env: IRONVEIL_CLIENT_USERNAME.
    #[serde(default)]
    pub client_username: Option<String>,
    /// Password clients must present. Env: IRONVEIL_CLIENT_PASSWORD.
    #[serde(default)]
    pub client_password: Option<String>,
    /// File to read the client password from (trailing newline trimmed).
    #[serde(default)]
    pub client_password_file: Option<String>,
    /// Auth plugin offered to clients: `caching_sha2_password` (default) or
    /// `mysql_native_password` for clients that lack the former.
    #[serde(default)]
    pub client_auth_plugin: Option<String>,

    /// Username the proxy authenticates upstream with.
    /// Env: IRONVEIL_UPSTREAM_USERNAME.
    #[serde(default)]
    pub upstream_username: Option<String>,
    /// Password the proxy authenticates upstream with.
    /// Env: IRONVEIL_UPSTREAM_PASSWORD.
    #[serde(default)]
    pub upstream_password: Option<String>,
    /// File to read the upstream password from (trailing newline trimmed).
    #[serde(default)]
    pub upstream_password_file: Option<String>,
    /// Default schema to select upstream when the client does not name one.
    #[serde(default)]
    pub upstream_database: Option<String>,
}

/// Auth settings with every secret resolved, built once at startup.
///
/// Deliberately not re-read on config hot-reload: swapping the credential out
/// from under connections mid-flight has no coherent meaning, and a reload that
/// silently changed who may connect would be a poor security property.
#[derive(Debug, Clone)]
pub struct ResolvedAuth {
    pub client_username: String,
    pub client_password: String,
    pub client_auth_plugin: String,
    pub upstream_username: String,
    pub upstream_password: String,
    pub upstream_database: Option<String>,
}

/// Resolve one secret from environment > file > inline.
fn resolve_secret(
    env: Option<String>,
    file: Option<&str>,
    inline: Option<&str>,
    what: &str,
) -> Result<Option<String>> {
    if let Some(value) = env {
        return Ok(Some(value));
    }
    if let Some(path) = file {
        let raw = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read {what} from '{path}': {e}"))?;
        // Secret files are almost always written with a trailing newline;
        // including it in the password is never what the operator meant.
        return Ok(Some(raw.trim_end_matches(['\n', '\r']).to_string()));
    }
    Ok(inline.map(|s| s.to_string()))
}

impl AuthConfig {
    /// Resolve credentials from the config, the named files and the
    /// environment. `env` is passed in rather than read here so the precedence
    /// rules can be tested without mutating process-global state.
    pub fn resolve_with(
        &self,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<ResolvedAuth>> {
        if self.mode == AuthMode::Passthrough {
            return Ok(None);
        }

        let client_username = env("IRONVEIL_CLIENT_USERNAME")
            .or_else(|| self.client_username.clone())
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("auth.mode is 'terminate' but auth.client_username is not set")
            })?;

        let client_password = resolve_secret(
            env("IRONVEIL_CLIENT_PASSWORD"),
            self.client_password_file.as_deref(),
            self.client_password.as_deref(),
            "auth.client_password",
        )?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "auth.mode is 'terminate' but no client password is configured \
                 (auth.client_password, auth.client_password_file or IRONVEIL_CLIENT_PASSWORD)"
            )
        })?;

        // An empty password on a listening port authenticates anyone who can
        // reach it. The local credential is a throwaway, but it is the only
        // thing standing between a co-located process and unmasked-adjacent
        // access, so refuse rather than warn.
        if client_password.is_empty() {
            anyhow::bail!("auth.client_password must not be empty in 'terminate' mode");
        }

        let upstream_username = env("IRONVEIL_UPSTREAM_USERNAME")
            .or_else(|| self.upstream_username.clone())
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("auth.mode is 'terminate' but auth.upstream_username is not set")
            })?;

        // The upstream password may legitimately be empty (socket-auth style
        // accounts), so its absence is not an error.
        let upstream_password = resolve_secret(
            env("IRONVEIL_UPSTREAM_PASSWORD"),
            self.upstream_password_file.as_deref(),
            self.upstream_password.as_deref(),
            "auth.upstream_password",
        )?
        .unwrap_or_default();

        let client_auth_plugin = self
            .client_auth_plugin
            .clone()
            .unwrap_or_else(|| "caching_sha2_password".to_string());
        if !KNOWN_CLIENT_AUTH_PLUGINS.contains(&client_auth_plugin.as_str()) {
            anyhow::bail!(
                "unknown auth.client_auth_plugin '{client_auth_plugin}' (known: {})",
                KNOWN_CLIENT_AUTH_PLUGINS.join(", ")
            );
        }

        Ok(Some(ResolvedAuth {
            client_username,
            client_password,
            client_auth_plugin,
            upstream_username,
            upstream_password,
            upstream_database: self.upstream_database.clone(),
        }))
    }

    /// Resolve against the real process environment.
    pub fn resolve(&self) -> Result<Option<ResolvedAuth>> {
        self.resolve_with(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
    }
}

/// Auth plugins the proxy can offer to its own clients.
pub const KNOWN_CLIENT_AUTH_PLUGINS: &[&str] = &["caching_sha2_password", "mysql_native_password"];

/// Where the proxy's own listener binds. Every field is optional so the CLI
/// flag and the environment can override it — see `resolve_listen_addr`.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// Address the proxy listener binds to (default: 0.0.0.0). Set 127.0.0.1
    /// for the localhost-sidecar deployment, where the only client shares the
    /// network namespace.
    #[serde(default)]
    pub bind: Option<String>,

    /// Port the proxy listener binds to (default: 6543).
    #[serde(default)]
    pub port: Option<u16>,
}

/// Audit event types to log
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    AuthAttempt,
    ConfigChange,
    RuleAdded,
    RuleDeleted,
    RulesImported,
    ConfigReload,
    DatabaseScan,
    SchemaQuery,
}

/// Configuration for audit logging
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Enable audit logging (default: true)
    #[serde(default = "default_audit_enabled")]
    pub enabled: bool,

    /// Log to stdout in addition to file (default: false)
    #[serde(default)]
    pub log_to_stdout: bool,

    /// Path to audit log file (optional)
    #[serde(default)]
    pub log_file: Option<String>,

    /// Enable log rotation (default: true)
    #[serde(default = "default_audit_rotation")]
    pub rotation_enabled: bool,

    /// Maximum log file size in bytes before rotation (default: 10MB)
    #[serde(default = "default_audit_max_size")]
    pub max_file_size_bytes: u64,

    /// Maximum number of rotated files to keep (default: 5)
    #[serde(default = "default_audit_max_files")]
    pub max_rotated_files: usize,

    /// Events to log (if empty, logs all events)
    #[serde(default)]
    pub events: Vec<AuditEventType>,
}

fn default_audit_enabled() -> bool {
    true
}

fn default_audit_rotation() -> bool {
    true
}

fn default_audit_max_size() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

fn default_audit_max_files() -> usize {
    5
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_to_stdout: false,
            log_file: None,
            rotation_enabled: true,
            max_file_size_bytes: default_audit_max_size(),
            max_rotated_files: default_audit_max_files(),
            events: vec![],
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,

    /// PEM bundle of CA certificates that a client certificate must chain to.
    ///
    /// Setting this alone enables *optional* mTLS: a client that presents a
    /// certificate must present a valid one, but a client that presents none is
    /// still admitted. Combine with `require_client_cert` to make it mandatory.
    #[serde(default)]
    pub client_ca_path: Option<String>,

    /// Reject clients that do not present a certificate chaining to
    /// `client_ca_path`. Off by default; requires `client_ca_path`.
    #[serde(default)]
    pub require_client_cert: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Trace sampling ratio in [0.0, 1.0] (default: 0.05).
    #[serde(default)]
    pub sample_ratio: Option<f64>,
}

fn default_otlp_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_service_name() -> String {
    "iron-veil".to_string()
}

fn default_masking_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MaskingRule {
    pub table: Option<String>,
    pub column: String,
    pub strategy: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            masking_enabled: true,
            rules: vec![],
            masking_secret: None,
            heuristics: None,
            tls: None,
            upstream_tls: false,
            telemetry: None,
            listen: None,
            auth: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        }
    }
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut config: AppConfig = serde_yaml_ng::from_str(&content)?;
        if let Ok(secret) = std::env::var("IRONVEIL_MASKING_SECRET")
            && !secret.is_empty()
        {
            config.masking_secret = Some(secret);
        }
        config.validate()?;
        Ok(config)
    }

    /// Reject configs that would silently misbehave at runtime.
    pub fn validate(&self) -> Result<()> {
        for rule in &self.rules {
            if !KNOWN_STRATEGIES.contains(&rule.strategy.as_str()) {
                anyhow::bail!(
                    "unknown masking strategy '{}' for column '{}' (known: {})",
                    rule.strategy,
                    rule.column,
                    KNOWN_STRATEGIES.join(", ")
                );
            }
        }
        if let Some(heuristics) = &self.heuristics {
            for t in &heuristics.types {
                if !KNOWN_HEURISTIC_TYPES.contains(&t.as_str()) {
                    anyhow::bail!(
                        "unknown heuristic type '{}' (known: {})",
                        t,
                        KNOWN_HEURISTIC_TYPES.join(", ")
                    );
                }
            }
        }
        if let Some(tls) = &self.tls {
            // Silently admitting every client would be the opposite of what
            // this setting says, so refuse the incoherent config outright.
            if tls.require_client_cert && tls.client_ca_path.is_none() {
                anyhow::bail!(
                    "tls.require_client_cert is set but tls.client_ca_path is not: there is \
                     no CA to verify client certificates against"
                );
            }
            if tls.client_ca_path.is_some() && !tls.enabled {
                anyhow::bail!(
                    "tls.client_ca_path is set but tls.enabled is false: client certificates \
                     are only verified on a TLS connection"
                );
            }
        }
        Ok(())
    }
}

// ============================================================================
// Listener resolution
// ============================================================================
//
// Every listen setting can come from four places. Precedence is uniform:
//
//   CLI flag  >  environment variable  >  config file  >  built-in default
//
// The CLI wins because it is the most explicit and the least likely to be
// inherited by accident; the environment beats the file so a container image
// shipping a baked-in proxy.yaml can still be re-pointed at deploy time.
//
// These take the environment value as a parameter instead of reading it, so
// the precedence rules are testable without mutating process-global state.

/// Resolve a listen address from CLI / env / config file / default.
pub fn resolve_listen_addr(
    cli: Option<std::net::IpAddr>,
    env: Option<&str>,
    file: Option<&str>,
    default: std::net::IpAddr,
    what: &str,
) -> Result<std::net::IpAddr> {
    if let Some(addr) = cli {
        return Ok(addr);
    }
    if let Some(raw) = env.filter(|v| !v.is_empty()) {
        return raw
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid {what} address '{raw}' from environment: {e}"));
    }
    if let Some(raw) = file.filter(|v| !v.is_empty()) {
        return raw
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid {what} address '{raw}' in config: {e}"));
    }
    Ok(default)
}

/// Resolve a listen port from CLI / env / config file / default.
pub fn resolve_listen_port(
    cli: Option<u16>,
    env: Option<&str>,
    file: Option<u16>,
    default: u16,
    what: &str,
) -> Result<u16> {
    if let Some(port) = cli {
        return Ok(port);
    }
    if let Some(raw) = env.filter(|v| !v.is_empty()) {
        return raw
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid {what} port '{raw}' from environment: {e}"));
    }
    if let Some(port) = file {
        return Ok(port);
    }
    Ok(default)
}

/// Resolve a boolean toggle from CLI / env / config file / default.
/// Accepts the usual spellings so `IRONVEIL_API_ENABLED=0` behaves as expected.
pub fn resolve_flag(
    cli: Option<bool>,
    env: Option<&str>,
    file: Option<bool>,
    default: bool,
    what: &str,
) -> Result<bool> {
    if let Some(value) = cli {
        return Ok(value);
    }
    if let Some(raw) = env.filter(|v| !v.is_empty()) {
        return match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(anyhow::anyhow!(
                "invalid {what} value '{other}' from environment (expected true/false)"
            )),
        };
    }
    if let Some(value) = file {
        return Ok(value);
    }
    Ok(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const V4_ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    const V4_LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn test_listen_addr_precedence_is_cli_env_file_default() {
        let cli: IpAddr = "10.0.0.1".parse().unwrap();

        // CLI beats everything.
        assert_eq!(
            resolve_listen_addr(
                Some(cli),
                Some("10.0.0.2"),
                Some("10.0.0.3"),
                V4_ANY,
                "proxy"
            )
            .unwrap(),
            cli
        );
        // Env beats the file.
        assert_eq!(
            resolve_listen_addr(None, Some("10.0.0.2"), Some("10.0.0.3"), V4_ANY, "proxy").unwrap(),
            "10.0.0.2".parse::<IpAddr>().unwrap()
        );
        // File beats the default.
        assert_eq!(
            resolve_listen_addr(None, None, Some("10.0.0.3"), V4_ANY, "proxy").unwrap(),
            "10.0.0.3".parse::<IpAddr>().unwrap()
        );
        // Nothing set -> default.
        assert_eq!(
            resolve_listen_addr(None, None, None, V4_ANY, "proxy").unwrap(),
            V4_ANY
        );
    }

    #[test]
    fn test_listen_addr_ignores_empty_strings() {
        // An unset-but-exported env var must not shadow the config file.
        assert_eq!(
            resolve_listen_addr(None, Some(""), Some("127.0.0.1"), V4_ANY, "proxy").unwrap(),
            V4_LOCAL
        );
    }

    #[test]
    fn test_listen_addr_rejects_garbage() {
        let err = resolve_listen_addr(None, Some("not-an-ip"), None, V4_ANY, "proxy").unwrap_err();
        assert!(err.to_string().contains("not-an-ip"), "got: {err}");
    }

    #[test]
    fn test_listen_port_precedence() {
        assert_eq!(
            resolve_listen_port(Some(1), Some("2"), Some(3), 4, "proxy").unwrap(),
            1
        );
        assert_eq!(
            resolve_listen_port(None, Some("2"), Some(3), 4, "proxy").unwrap(),
            2
        );
        assert_eq!(
            resolve_listen_port(None, None, Some(3), 4, "proxy").unwrap(),
            3
        );
        assert_eq!(
            resolve_listen_port(None, None, None, 4, "proxy").unwrap(),
            4
        );
        assert!(resolve_listen_port(None, Some("70000"), None, 4, "proxy").is_err());
    }

    #[test]
    fn test_flag_precedence_and_spellings() {
        assert!(!resolve_flag(Some(false), Some("true"), Some(true), true, "api").unwrap());
        assert!(!resolve_flag(None, Some("0"), Some(true), true, "api").unwrap());
        assert!(!resolve_flag(None, Some("OFF"), None, true, "api").unwrap());
        assert!(resolve_flag(None, Some("yes"), None, false, "api").unwrap());
        assert!(!resolve_flag(None, None, Some(false), true, "api").unwrap());
        assert!(resolve_flag(None, None, None, true, "api").unwrap());
        assert!(resolve_flag(None, Some("maybe"), None, true, "api").is_err());
    }

    fn terminate_config() -> AuthConfig {
        AuthConfig {
            mode: AuthMode::Terminate,
            client_username: Some("door".to_string()),
            client_password: Some("inline-client".to_string()),
            upstream_username: Some("support_ro".to_string()),
            upstream_password: Some("inline-upstream".to_string()),
            ..Default::default()
        }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn test_auth_defaults_to_passthrough_and_resolves_to_nothing() {
        let config: AppConfig = serde_yaml_ng::from_str("rules: []\n").unwrap();
        assert!(config.auth.is_none());

        let parsed: AppConfig = serde_yaml_ng::from_str("rules: []\nauth: {}\n").unwrap();
        let auth = parsed.auth.expect("auth section");
        assert_eq!(auth.mode, AuthMode::Passthrough);
        assert!(
            auth.resolve_with(no_env).unwrap().is_none(),
            "passthrough must not resolve credentials"
        );
    }

    #[test]
    fn test_terminate_resolves_inline_credentials() {
        let resolved = terminate_config()
            .resolve_with(no_env)
            .unwrap()
            .expect("terminate mode should resolve credentials");

        assert_eq!(resolved.client_username, "door");
        assert_eq!(resolved.client_password, "inline-client");
        assert_eq!(resolved.upstream_username, "support_ro");
        assert_eq!(resolved.upstream_password, "inline-upstream");
        assert_eq!(resolved.client_auth_plugin, "caching_sha2_password");
    }

    #[test]
    fn test_environment_overrides_inline_credentials() {
        let resolved = terminate_config()
            .resolve_with(|name| match name {
                "IRONVEIL_CLIENT_PASSWORD" => Some("from-env".to_string()),
                "IRONVEIL_UPSTREAM_USERNAME" => Some("env_user".to_string()),
                _ => None,
            })
            .unwrap()
            .unwrap();

        assert_eq!(resolved.client_password, "from-env");
        assert_eq!(resolved.upstream_username, "env_user");
        // Untouched fields still come from the file.
        assert_eq!(resolved.upstream_password, "inline-upstream");
    }

    #[test]
    fn test_password_file_is_read_and_trailing_newline_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.pw");
        std::fs::write(&path, "secret-from-file\n").unwrap();

        let mut config = terminate_config();
        config.client_password_file = Some(path.to_string_lossy().into_owned());

        let resolved = config.resolve_with(no_env).unwrap().unwrap();
        assert_eq!(
            resolved.client_password, "secret-from-file",
            "the trailing newline a secret file always has must not be part of the password"
        );
    }

    #[test]
    fn test_environment_beats_the_password_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.pw");
        std::fs::write(&path, "from-file").unwrap();

        let mut config = terminate_config();
        config.client_password_file = Some(path.to_string_lossy().into_owned());

        let resolved = config
            .resolve_with(|name| {
                (name == "IRONVEIL_CLIENT_PASSWORD").then(|| "from-env".to_string())
            })
            .unwrap()
            .unwrap();
        assert_eq!(resolved.client_password, "from-env");
    }

    #[test]
    fn test_missing_password_file_is_an_error_not_a_silent_empty_password() {
        let mut config = terminate_config();
        config.client_password = None;
        config.client_password_file = Some("/nonexistent/iron-veil/client.pw".to_string());

        let err = config.resolve_with(no_env).unwrap_err();
        assert!(err.to_string().contains("failed to read"), "got: {err}");
    }

    #[test]
    fn test_terminate_rejects_incomplete_configuration() {
        let mut missing_client_user = terminate_config();
        missing_client_user.client_username = None;
        assert!(missing_client_user.resolve_with(no_env).is_err());

        let mut missing_client_pw = terminate_config();
        missing_client_pw.client_password = None;
        assert!(missing_client_pw.resolve_with(no_env).is_err());

        // An empty client password would authenticate anyone who can reach
        // the port.
        let mut empty_client_pw = terminate_config();
        empty_client_pw.client_password = Some(String::new());
        assert!(empty_client_pw.resolve_with(no_env).is_err());

        let mut missing_upstream_user = terminate_config();
        missing_upstream_user.upstream_username = None;
        assert!(missing_upstream_user.resolve_with(no_env).is_err());
    }

    #[test]
    fn test_empty_upstream_password_is_allowed() {
        let mut config = terminate_config();
        config.upstream_password = None;
        let resolved = config.resolve_with(no_env).unwrap().unwrap();
        assert_eq!(resolved.upstream_password, "");
    }

    #[test]
    fn test_unknown_client_auth_plugin_is_rejected() {
        let mut config = terminate_config();
        config.client_auth_plugin = Some("sha256_password".to_string());
        let err = config.resolve_with(no_env).unwrap_err();
        assert!(err.to_string().contains("sha256_password"), "got: {err}");
    }

    #[test]
    fn test_auth_section_parses_from_yaml() {
        let yaml = r#"
rules: []
auth:
  mode: terminate
  client_username: door
  client_password: local-throwaway
  client_auth_plugin: mysql_native_password
  upstream_username: support_ro
  upstream_password_file: /run/secrets/db
  upstream_database: wms
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let auth = config.auth.expect("auth section");
        assert_eq!(auth.mode, AuthMode::Terminate);
        assert_eq!(auth.client_username.as_deref(), Some("door"));
        assert_eq!(
            auth.upstream_password_file.as_deref(),
            Some("/run/secrets/db")
        );
        assert_eq!(auth.upstream_database.as_deref(), Some("wms"));
    }

    #[test]
    fn test_listen_section_parses() {
        let yaml = r#"
rules: []
listen:
  bind: 127.0.0.1
  port: 7000
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let listen = config.listen.expect("listen section should be present");
        assert_eq!(listen.bind.as_deref(), Some("127.0.0.1"));
        assert_eq!(listen.port, Some(7000));
    }

    #[test]
    fn test_api_is_enabled_by_default_and_can_be_disabled() {
        let enabled: AppConfig = serde_yaml_ng::from_str("rules: []\napi: {}\n").unwrap();
        assert!(
            enabled.api.expect("api section").enabled,
            "omitting api.enabled must keep the management API on"
        );

        let disabled: AppConfig =
            serde_yaml_ng::from_str("rules: []\napi:\n  enabled: false\n").unwrap();
        assert!(!disabled.api.expect("api section").enabled);
    }

    #[test]
    fn test_config_load_valid_yaml() {
        let yaml = r#"
masking_enabled: true
upstream_tls: false
rules:
  - table: "users"
    column: "email"
    strategy: "email"
  - column: "phone"
    strategy: "phone"
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();

        assert!(config.masking_enabled);
        assert!(!config.upstream_tls);
        assert_eq!(config.rules.len(), 2);
        assert_eq!(config.rules[0].table, Some("users".to_string()));
        assert_eq!(config.rules[0].column, "email");
        assert_eq!(config.rules[0].strategy, "email");
        assert_eq!(config.rules[1].table, None);
    }

    #[test]
    fn test_config_defaults() {
        let yaml = r#"
rules: []
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();

        assert!(config.masking_enabled); // Should default to true
        assert!(!config.upstream_tls); // Should default to false
        assert!(config.tls.is_none()); // Should default to None
    }

    #[test]
    fn test_config_with_tls() {
        let yaml = r#"
masking_enabled: true
upstream_tls: true
tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
rules: []
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();

        assert!(config.upstream_tls);
        assert!(config.tls.is_some());

        let tls = config.tls.unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.cert_path, "certs/server.crt");
        assert_eq!(tls.key_path, "certs/server.key");
    }

    #[test]
    fn test_invalid_yaml_fails() {
        let yaml = r#"
invalid yaml content {{
"#;
        let result: Result<AppConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_fields_fails() {
        let yaml = r#"
masking_enabled: true
"#;
        let result: Result<AppConfig, _> = serde_yaml_ng::from_str(yaml);
        assert!(result.is_err()); // Should fail because 'rules' is missing
    }

    #[test]
    fn test_limits_defaults_include_upstream_pool_settings() {
        let yaml = r#"
rules: []
limits: {}
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let limits = config.limits.expect("limits should be present");

        assert_eq!(limits.connect_timeout_secs, 30);
        assert_eq!(limits.idle_timeout_secs, 300);
        assert_eq!(limits.upstream_pool_wait_timeout_secs, 5);
        assert_eq!(limits.upstream_pool_size, None);
    }

    #[test]
    fn test_limits_parses_upstream_pool_settings() {
        let yaml = r#"
rules: []
limits:
  upstream_pool_size: 50
  upstream_pool_wait_timeout_secs: 12
"#;
        let config: AppConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let limits = config.limits.expect("limits should be present");

        assert_eq!(limits.upstream_pool_size, Some(50));
        assert_eq!(limits.upstream_pool_wait_timeout_secs, 12);
    }
}
