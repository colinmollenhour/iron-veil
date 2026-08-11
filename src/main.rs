use anyhow::Result;
use clap::{Parser, ValueEnum};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info, info_span, warn};

use iron_veil::{api, auth, config, interceptor, metrics, protocol, state, telemetry};

use crate::config::AppConfig;
use crate::interceptor::{Anonymizer, MySqlAnonymizer, MySqlPacketInterceptor, PacketInterceptor};
use crate::protocol::mysql::{MySqlCodec, MySqlMessage};
use crate::protocol::postgres::{DataRow, PgMessage, PostgresCodec, QueryMessage};
use crate::state::{AppState, DbProtocol as StateDbProtocol, LogEntry};
use bytes::{BufMut, Bytes};
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use rustls_platform_verifier::Verifier;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ServerConfig, pki_types::CertificateDer, pki_types::PrivateKeyDer};
use tokio_util::codec::Framed;

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum DbProtocol {
    #[default]
    Postgres,
    Mysql,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on [env: IRONVEIL_PORT, config: listen.port, default: 6543]
    #[arg(short, long)]
    port: Option<u16>,

    /// Upstream database host
    #[arg(long, default_value = "127.0.0.1")]
    upstream_host: String,

    /// Upstream database port
    #[arg(long, default_value_t = 5432)]
    upstream_port: u16,

    /// Path to configuration file
    #[arg(long, default_value = "proxy.yaml")]
    config: String,

    /// Address the proxy listener binds to. Use 127.0.0.1 for the
    /// localhost-sidecar deployment.
    /// [env: IRONVEIL_BIND, config: listen.bind, default: 0.0.0.0]
    #[arg(long)]
    bind: Option<std::net::IpAddr>,

    /// Management API port
    /// [env: IRONVEIL_API_PORT, config: api.port, default: 3001]
    #[arg(long)]
    api_port: Option<u16>,

    /// Address the management API binds to. Binding a non-loopback address
    /// requires api.api_key or api.jwt_secret.
    /// [env: IRONVEIL_API_BIND, config: api.bind, default: 127.0.0.1]
    #[arg(long)]
    api_bind: Option<std::net::IpAddr>,

    /// Do not start the management API at all. The proxy then serves no HTTP
    /// control plane, /health or /metrics.
    /// [env: IRONVEIL_API_ENABLED, config: api.enabled]
    #[arg(long, conflicts_with_all = ["api_bind", "api_port"])]
    no_api: bool,

    /// Database protocol to proxy
    #[arg(long, value_enum, default_value_t = DbProtocol::Postgres)]
    protocol: DbProtocol,

    /// Graceful shutdown timeout in seconds: how long SIGTERM waits for
    /// in-flight connections to drain before aborting them and exiting.
    #[arg(long, default_value_t = 10)]
    shutdown_timeout: u64,
}

/// Read an environment variable, treating "set but empty" as unset so an
/// exported-but-blank var in a compose file cannot shadow the config file.
fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Waits for a shutdown signal (SIGTERM, SIGINT, or Ctrl+C).
///
/// The signal receivers are created *inside* this future, so it must be polled
/// to completion by a dedicated task — see `spawn_shutdown_watcher`. Selecting
/// on a freshly-built `shutdown_signal()` on every accept-loop iteration drops
/// the receivers each time a connection arrives, and a SIGTERM delivered in
/// that window is lost: tokio's process-wide handler records it against a
/// registration that no longer exists. That is why `docker stop` on a busy
/// proxy hit the grace period and needed SIGKILL.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler");
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("Failed to install SIGINT handler");
        tokio::select! {
            _ = terminate.recv() => info!("Received SIGTERM, initiating shutdown..."),
            _ = interrupt.recv() => info!("Received SIGINT, initiating shutdown..."),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Received Ctrl+C, initiating shutdown...");
    }
}

/// Install the signal handlers once, up front, and surface them as a token.
/// Returns immediately; the returned token is cancelled when a signal lands.
fn spawn_shutdown_watcher() -> CancellationToken {
    let token = CancellationToken::new();
    let signalled = token.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signalled.cancel();
    });
    token
}

/// Wait for in-flight connections to finish, up to `timeout`. Returns true when
/// the count reached zero in time, false when the deadline forced an abort.
async fn drain_connections(active: &std::sync::atomic::AtomicUsize, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while active.load(Ordering::Relaxed) > 0 {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25).min(deadline - Instant::now())).await;
    }
    true
}

/// Background task that periodically checks upstream database connectivity
async fn run_health_check_task(
    state: AppState,
    upstream_host: String,
    upstream_port: u16,
    config: Option<crate::config::HealthCheckConfig>,
) {
    let config = config.unwrap_or_default();
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);

    info!(
        "Starting upstream health check task (interval: {}s, timeout: {}s)",
        config.interval_secs, config.timeout_secs
    );

    loop {
        let start = Instant::now();

        // Try to connect to upstream
        let connect_result = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(format!("{}:{}", upstream_host, upstream_port)),
        )
        .await;

        let latency = start.elapsed().as_millis() as u64;

        match connect_result {
            Ok(Ok(_stream)) => {
                // Connection successful
                state.update_health_status(true, Some(latency), None).await;
                metrics::record_health_check(true, Some(latency));
                tracing::debug!(
                    "Health check passed: upstream {}:{} ({}ms)",
                    upstream_host,
                    upstream_port,
                    latency
                );
            }
            Ok(Err(e)) => {
                // Connection failed
                let error = format!("Connection failed: {}", e);
                state
                    .update_health_status(false, None, Some(error.clone()))
                    .await;
                metrics::record_health_check(false, None);
                warn!(
                    "Health check failed: upstream {}:{} - {}",
                    upstream_host, upstream_port, error
                );
            }
            Err(_) => {
                // Timeout
                let error = format!("Connection timeout after {}s", config.timeout_secs);
                state
                    .update_health_status(false, None, Some(error.clone()))
                    .await;
                metrics::record_health_check(false, None);
                metrics::record_upstream_timeout();
                warn!(
                    "Health check timeout: upstream {}:{} - {}",
                    upstream_host, upstream_port, error
                );
            }
        }

        tokio::time::sleep(interval).await;
    }
}

fn update_upstream_pool_metrics(pool: &Semaphore, max_size: usize) {
    let active = max_size.saturating_sub(pool.available_permits());
    metrics::set_upstream_pool_state(active, max_size);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamPoolAcquireError {
    Closed,
    Timeout,
}

#[derive(Clone)]
struct UpstreamSlotManager {
    pool: Arc<Semaphore>,
    size: usize,
}

impl UpstreamSlotManager {
    fn new(size: usize) -> Self {
        let pool = Arc::new(Semaphore::new(size));
        update_upstream_pool_metrics(&pool, size);
        Self { pool, size }
    }

    #[cfg(test)]
    fn available_slots(&self) -> usize {
        self.pool.available_permits()
    }

    async fn acquire(
        &self,
        timeout: Duration,
    ) -> std::result::Result<UpstreamSlotLease, UpstreamPoolAcquireError> {
        match tokio::time::timeout(timeout, self.pool.clone().acquire_owned()).await {
            Ok(Ok(permit)) => {
                update_upstream_pool_metrics(&self.pool, self.size);
                Ok(UpstreamSlotLease {
                    pool: self.pool.clone(),
                    size: self.size,
                    permit: Some(permit),
                })
            }
            Ok(Err(_)) => Err(UpstreamPoolAcquireError::Closed),
            Err(_) => Err(UpstreamPoolAcquireError::Timeout),
        }
    }
}

struct UpstreamSlotLease {
    pool: Arc<Semaphore>,
    size: usize,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for UpstreamSlotLease {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            drop(permit);
            update_upstream_pool_metrics(&self.pool, self.size);
        }
    }
}

/// Replace SQL string-literal contents with `?` before logging: query text in
/// INSERT/WHERE clauses routinely carries the exact PII this proxy exists to
/// suppress, and the log ring is re-served by GET /logs.
///
/// `double_quoted_is_string` must be true for MySQL, where `"..."` is a string
/// literal unless ANSI_QUOTES is set — so `WHERE email = "a@b.com"` wrote the
/// address straight into the ring. It must be false for PostgreSQL, where
/// `"..."` is a quoted identifier and redacting it would erase the table and
/// column names that make the log useful without suppressing anything.
///
/// Redaction is deliberately greedy: an unterminated or oddly-escaped literal
/// swallows the rest of the statement rather than resuming in cleartext.
fn redact_sql_literals(sql: &str, double_quoted_is_string: bool) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' || (double_quoted_is_string && c == '"') {
            let quote = c;
            out.push(quote);
            out.push('?');
            out.push(quote);
            let mut escaped = false;
            while let Some(n) = chars.next() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if n == '\\' {
                    escaped = true;
                } else if n == quote {
                    // A doubled quote is an escaped quote inside the literal.
                    if chars.peek() == Some(&quote) {
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn resolve_timeout_limits(
    limits: Option<&crate::config::LimitsConfig>,
) -> (Duration, Duration, Duration) {
    (
        Duration::from_secs(limits.map_or(30, |l| l.connect_timeout_secs)),
        Duration::from_secs(limits.map_or(300, |l| l.idle_timeout_secs)),
        Duration::from_secs(limits.map_or(5, |l| l.upstream_pool_wait_timeout_secs)),
    )
}

async fn connect_upstream_with_timeout(
    upstream_host: &str,
    upstream_port: u16,
    connect_timeout: Duration,
) -> Result<tokio::net::TcpStream> {
    match tokio::time::timeout(
        connect_timeout,
        tokio::net::TcpStream::connect(format!("{upstream_host}:{upstream_port}")),
    )
    .await
    {
        Ok(Ok(socket)) => Ok(socket),
        Ok(Err(err)) => Err(err.into()),
        Err(_) => {
            metrics::record_upstream_timeout();
            Err(anyhow::anyhow!(
                "Upstream connection timeout after {:?}",
                connect_timeout
            ))
        }
    }
}

fn build_postgres_fatal_error_packet(sqlstate: &str, message: &str) -> Vec<u8> {
    fn push_field(payload: &mut Vec<u8>, key: u8, value: &str) {
        payload.push(key);
        payload.extend_from_slice(value.as_bytes());
        payload.push(0);
    }

    let mut payload = Vec::new();
    push_field(&mut payload, b'S', "FATAL");
    push_field(&mut payload, b'V', "FATAL");
    push_field(&mut payload, b'C', sqlstate);
    push_field(&mut payload, b'M', message);
    payload.push(0);

    let mut packet = Vec::with_capacity(1 + 4 + payload.len());
    packet.push(b'E');
    packet.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
    packet.extend_from_slice(&payload);
    packet
}

/// Build a FATAL ErrorResponse as a codec-level RegularMessage (for use on an
/// already-framed connection, e.g. during graceful shutdown).
fn build_postgres_fatal_regular_message(
    sqlstate: &str,
    message: &str,
) -> crate::protocol::postgres::RegularMessage {
    let mut payload = bytes::BytesMut::new();
    for (key, value) in [
        (b'S', "FATAL"),
        (b'V', "FATAL"),
        (b'C', sqlstate),
        (b'M', message),
    ] {
        payload.put_u8(key);
        payload.put_slice(value.as_bytes());
        payload.put_u8(0);
    }
    payload.put_u8(0);
    crate::protocol::postgres::RegularMessage {
        message_type: b'E',
        payload,
    }
}

fn build_mysql_err_packet(error_code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + 2 + 1 + 5 + message.len());
    payload.push(0xFF);
    payload.extend_from_slice(&error_code.to_le_bytes());
    payload.push(b'#');

    let mut state = *b"HY000";
    let provided = sql_state.as_bytes();
    if provided.len() == 5 {
        state.copy_from_slice(provided);
    }
    payload.extend_from_slice(&state);
    payload.extend_from_slice(message.as_bytes());

    let len = payload.len();
    let mut packet = Vec::with_capacity(4 + len);
    packet.push((len & 0xFF) as u8);
    packet.push(((len >> 8) & 0xFF) as u8);
    packet.push(((len >> 16) & 0xFF) as u8);
    packet.push(0); // sequence id
    packet.extend_from_slice(&payload);
    packet
}

async fn send_postgres_fatal_error_response<S>(
    client_socket: &mut S,
    sqlstate: &str,
    message: &str,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let packet = build_postgres_fatal_error_packet(sqlstate, message);
    client_socket.write_all(&packet).await?;
    client_socket.flush().await?;
    Ok(())
}

async fn send_mysql_err_response<S>(
    client_socket: &mut S,
    error_code: u16,
    sql_state: &str,
    message: &str,
) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let packet = build_mysql_err_packet(error_code, sql_state, message);
    client_socket.write_all(&packet).await?;
    client_socket.flush().await?;
    Ok(())
}

/// Background task that watches the config file for changes and reloads.
/// The notify callback feeds a tokio channel: blocking recv on a std channel
/// parked a runtime worker thread for seconds at a time.
async fn run_config_watcher(state: AppState, config_path: String) {
    use std::path::Path;

    let path = Path::new(&config_path);
    let parent = path.parent().unwrap_or(Path::new("."));

    // Create a channel to receive events
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    // Create a watcher with debounce
    let mut watcher: RecommendedWatcher = match Watcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
    ) {
        Ok(w) => w,
        Err(e) => {
            warn!(
                "Failed to create config file watcher: {}. Hot reload disabled.",
                e
            );
            return;
        }
    };

    // Watch the config file's parent directory
    if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
        warn!(
            "Failed to watch config directory: {}. Hot reload disabled.",
            e
        );
        return;
    }

    info!("Config file watcher started for {}", config_path);

    let filename = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("proxy.yaml");
    let mut last_reload = Instant::now();
    let debounce_duration = Duration::from_secs(1);

    while let Some(event) = rx.recv().await {
        // Check if this event is for our config file
        let is_config_file = event.paths.iter().any(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .map(|f| f == filename)
                .unwrap_or(false)
        });

        if is_config_file && last_reload.elapsed() > debounce_duration {
            info!("Config file changed, reloading...");
            match state.reload_config().await {
                Ok(rules_count) => {
                    info!("Configuration reloaded: {} rules", rules_count);
                }
                Err(e) => {
                    warn!("Failed to reload configuration: {}", e);
                }
            }
            last_reload = Instant::now();
        }
    }
    warn!("Config watcher channel disconnected, stopping watcher");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = AppConfig::load(&args.config)?;

    // Initialize telemetry (must be done before any tracing calls)
    let _telemetry_guard = telemetry::init_telemetry(config.telemetry.as_ref())?;

    info!(
        "Loaded {} masking rules from {}",
        config.rules.len(),
        args.config
    );

    // Initialize Prometheus metrics
    let metrics_handle = metrics::init_metrics();
    info!("Prometheus metrics initialized");

    // Load TLS config if enabled
    let tls_acceptor = if let Some(tls_config) = &config.tls {
        if tls_config.enabled {
            info!("TLS enabled. Loading certs from {}", tls_config.cert_path);
            let certs = load_certs(&tls_config.cert_path)?;
            let key = load_keys(&tls_config.key_path)?;
            let server_config = build_client_tls_config(tls_config, certs, key)?;
            Some(TlsAcceptor::from(Arc::new(server_config)))
        } else {
            info!("TLS disabled in config.");
            None
        }
    } else {
        info!("TLS not configured.");
        None
    };

    // Initialize shared state
    let db_protocol = match args.protocol {
        DbProtocol::Postgres => StateDbProtocol::Postgres,
        DbProtocol::Mysql => StateDbProtocol::MySql,
    };
    let state = AppState::new(
        config.clone(),
        args.config.clone(),
        args.upstream_host.clone(),
        args.upstream_port,
        db_protocol,
    )
    .with_metrics(metrics_handle);

    // Resolve where both listeners bind: CLI > env > config file > default.
    let listen_cfg = config.listen.as_ref();
    let proxy_bind = config::resolve_listen_addr(
        args.bind,
        env_var("IRONVEIL_BIND").as_deref(),
        listen_cfg.and_then(|l| l.bind.as_deref()),
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        "proxy listener",
    )?;
    let proxy_port = config::resolve_listen_port(
        args.port,
        env_var("IRONVEIL_PORT").as_deref(),
        listen_cfg.and_then(|l| l.port),
        6543,
        "proxy listener",
    )?;

    let api_cfg = config.api.as_ref();
    let api_enabled = config::resolve_flag(
        // --no-api is a one-way switch: its absence is not a request to enable.
        if args.no_api { Some(false) } else { None },
        env_var("IRONVEIL_API_ENABLED").as_deref(),
        api_cfg.map(|a| a.enabled),
        true,
        "api.enabled",
    )?;
    let api_bind = config::resolve_listen_addr(
        args.api_bind,
        env_var("IRONVEIL_API_BIND").as_deref(),
        api_cfg.and_then(|a| a.bind.as_deref()),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "management API",
    )?;
    let api_port = config::resolve_listen_port(
        args.api_port,
        env_var("IRONVEIL_API_PORT").as_deref(),
        api_cfg.and_then(|a| a.port),
        3001,
        "management API",
    )?;

    // Start Management API in a separate task
    if api_enabled {
        let api_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = api::start_api_server(api_bind, api_port, api_state).await {
                // The API carries /health, /metrics and the masking control
                // plane; running blind without it is worse than restarting.
                tracing::error!("management API server failed: {}", e);
                std::process::exit(1);
            }
        });
    } else {
        info!("Management API disabled; no HTTP control plane, /health or /metrics will be served");
    }

    // Start upstream health check task
    let health_check_enabled = config
        .health_check
        .as_ref()
        .map(|h| h.enabled)
        .unwrap_or(true);

    if health_check_enabled {
        let health_state = state.clone();
        let health_host = args.upstream_host.clone();
        let health_port = args.upstream_port;
        let health_config = config.health_check.clone();
        tokio::spawn(async move {
            run_health_check_task(health_state, health_host, health_port, health_config).await;
        });
    }

    // Start config file watcher for hot reload
    let watch_state = state.clone();
    let config_path = args.config.clone();
    tokio::spawn(async move {
        run_config_watcher(watch_state, config_path).await;
    });

    // Start stats history recorder (every 5 seconds)
    let stats_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            stats_state.record_history_snapshot().await;
        }
    });

    info!("Starting DB Proxy on {}:{}", proxy_bind, proxy_port);
    info!(
        "Forwarding to upstream at {}:{}",
        args.upstream_host, args.upstream_port
    );
    info!("Protocol: {:?}", args.protocol);

    // Loud rail: this proxy exists to protect PII, and with both TLS legs off
    // it crosses the network in cleartext on both hops.
    let client_tls_on = config.tls.as_ref().map(|t| t.enabled).unwrap_or(false);
    if config.masking_enabled && !client_tls_on && !config.upstream_tls {
        warn!(
            "masking is enabled but both tls.enabled and upstream_tls are false: \
             client and upstream traffic are cleartext. Acceptable only on a trusted network."
        );
    }

    // Resolve the terminating-auth credentials once, at startup: a credential
    // that changed under a hot config reload would silently change who may
    // connect, and mid-flight connections could not act on it anyway.
    let terminating_auth = match config.auth.as_ref().map(|a| a.resolve()).transpose()? {
        Some(Some(resolved)) => {
            if !matches!(args.protocol, DbProtocol::Mysql) {
                anyhow::bail!(
                    "auth.mode 'terminate' is MySQL-only; this instance is proxying {:?}",
                    args.protocol
                );
            }
            info!(
                client_user = %resolved.client_username,
                client_plugin = %resolved.client_auth_plugin,
                upstream_user = %resolved.upstream_username,
                "Terminating MySQL authentication at the proxy; \
                 clients never see the upstream credential"
            );
            if !config.upstream_tls {
                // Not fatal: the credential may already be cached upstream, or
                // the account may use mysql_native_password. But full auth will
                // fail, and that failure is confusing without this warning.
                warn!(
                    "auth.mode is 'terminate' but upstream_tls is false: the proxy's own \
                     credential can only authenticate if the upstream has it cached or the \
                     account uses mysql_native_password"
                );
            }
            Some(Arc::new(TerminatingAuth::from_resolved(&resolved)?))
        }
        _ => None,
    };

    // Build the upstream TLS client config once: it loads the OS trust store,
    // which is too expensive (and too panic-prone) for the per-connection path.
    let upstream_tls_config = if config.upstream_tls {
        Some(Arc::new(create_upstream_tls_config()?))
    } else {
        None
    };

    let listener = tokio::net::TcpListener::bind((proxy_bind, proxy_port)).await?;
    let protocol = args.protocol;

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let shutdown_timeout = args.shutdown_timeout;

    // Install signal handlers before the first accept: a SIGTERM that arrives
    // while the loop is busy servicing an accept must still be observed.
    let shutdown = spawn_shutdown_watcher();

    // Connection limiting
    let max_connections = config.limits.as_ref().and_then(|l| l.max_connections);
    let connection_semaphore = max_connections.map(|max| {
        info!("Connection limit set to {}", max);
        Arc::new(Semaphore::new(max))
    });

    // Upstream pool guardrails
    let upstream_pool = config
        .limits
        .as_ref()
        .and_then(|l| l.upstream_pool_size)
        .map(|size| {
            info!("Upstream pool size set to {}", size);
            UpstreamSlotManager::new(size)
        });

    // Rate limiting state
    let rate_limit = config
        .limits
        .as_ref()
        .and_then(|l| l.connections_per_second);
    if let Some(rate) = rate_limit {
        info!("Rate limit set to {} connections/second", rate);
    }
    let mut rate_limit_tokens: u32 = rate_limit.unwrap_or(0);
    let mut last_refill = Instant::now();

    // Accept connections until shutdown signal
    loop {
        tokio::select! {
            // Wait for new connection
            accept_result = listener.accept() => {
                let (client_socket, client_addr) = match accept_result {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        // accept() returns transient errors (EMFILE/ENFILE on
                        // fd exhaustion, ECONNABORTED, ENOBUFS); none of them
                        // justify taking the whole proxy down.
                        warn!("accept() failed: {}", e);
                        metrics::record_connection_rejected("accept_error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // Rate limiting check
                if let Some(max_rate) = rate_limit {
                    // Refill tokens based on elapsed time
                    let elapsed = last_refill.elapsed();
                    if elapsed >= Duration::from_secs(1) {
                        rate_limit_tokens = max_rate;
                        last_refill = Instant::now();
                    }

                    if rate_limit_tokens == 0 {
                        warn!("Rate limit exceeded, rejecting connection from {}", client_addr);
                        metrics::record_connection_rejected("rate_limit");
                        drop(client_socket);
                        continue;
                    }
                    rate_limit_tokens = rate_limit_tokens.saturating_sub(1);
                }

                // Connection limit check
                let permit = if let Some(ref sem) = connection_semaphore {
                    match sem.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            warn!("Connection limit reached, rejecting connection from {}", client_addr);
                            metrics::record_connection_rejected("max_connections");
                            drop(client_socket);
                            continue;
                        }
                    }
                } else {
                    None
                };

                info!("Accepted connection from {}", client_addr);

                let upstream_host = args.upstream_host.clone();
                let upstream_port = args.upstream_port;
                let state = state.clone();
                let tls_acceptor = tls_acceptor.clone();
                let upstream_pool = upstream_pool.clone();
                let upstream_tls_config = upstream_tls_config.clone();
                let terminating_auth = terminating_auth.clone();
                let conn_cancel = cancel_token.child_token();

                tokio::spawn(async move {
                    // Hold the permit for the duration of the connection
                    let _inbound_permit = permit;
                    let mut client_socket = client_socket;

                    let span = info_span!(
                        "connection",
                        client.addr = %client_addr,
                        upstream.host = %upstream_host,
                        upstream.port = %upstream_port,
                        protocol = ?protocol
                    );

                    async {
                        let mut _upstream_pool_lease = None;
                        if matches!(protocol, DbProtocol::Mysql)
                            && let Some(pool) = upstream_pool.clone()
                        {
                            let wait_timeout = {
                                let config = state.config.read().await;
                                let (_, _, pool_wait_timeout) =
                                    resolve_timeout_limits(config.limits.as_ref());
                                pool_wait_timeout
                            };
                            let wait_started = Instant::now();
                            match pool.acquire(wait_timeout).await {
                                Ok(lease) => {
                                    metrics::record_upstream_pool_wait(
                                        wait_started.elapsed().as_secs_f64(),
                                    );
                                    _upstream_pool_lease = Some(lease);
                                }
                                Err(UpstreamPoolAcquireError::Closed) => {
                                    warn!(
                                        "Upstream pool closed while acquiring slot for {}",
                                        client_addr
                                    );
                                    metrics::record_connection_rejected("upstream_pool_closed");
                                    let _ = send_mysql_err_response(
                                        &mut client_socket,
                                        1040,
                                        "08004",
                                        "upstream pool unavailable",
                                    )
                                    .await;
                                    return;
                                }
                                Err(UpstreamPoolAcquireError::Timeout) => {
                                    warn!(
                                        "Timed out waiting for upstream pool slot after {:?} for {}",
                                        wait_timeout, client_addr
                                    );
                                    metrics::record_upstream_pool_acquire_timeout();
                                    metrics::record_connection_rejected(
                                        "upstream_pool_wait_timeout",
                                    );
                                    let message = format!(
                                        "upstream pool is at capacity; timed out after {}s waiting for an available slot",
                                        wait_timeout.as_secs()
                                    );
                                    let _ = send_mysql_err_response(
                                        &mut client_socket,
                                        1040,
                                        "08004",
                                        &message,
                                    )
                                    .await;
                                    return;
                                }
                            }
                        }

                        state.active_connections.fetch_add(1, Ordering::Relaxed);
                        metrics::record_connection_opened();
                        state.record_connection().await;
                        let result = match protocol {
                            DbProtocol::Postgres => {
                                process_postgres_connection(
                                    client_socket,
                                    upstream_host,
                                    upstream_port,
                                    state.clone(),
                                    tls_acceptor,
                                    upstream_pool.clone(),
                                    upstream_tls_config,
                                    conn_cancel,
                                )
                                .await
                            }
                            DbProtocol::Mysql => {
                                process_mysql_connection(
                                    client_socket,
                                    upstream_host,
                                    upstream_port,
                                    state.clone(),
                                    tls_acceptor,
                                    upstream_tls_config,
                                    terminating_auth,
                                    conn_cancel,
                                )
                                .await
                            }
                        };
                        state.active_connections.fetch_sub(1, Ordering::Relaxed);
                        metrics::record_connection_closed();

                        if let Err(e) = result {
                            tracing::error!(error = %e, "Connection error");
                        }
                    }
                    .instrument(span)
                    .await
                });
            }

            // Wait for shutdown signal
            _ = shutdown.cancelled() => {
                info!("Shutdown signal received, stopping accept loop...");
                break;
            }
        }
    }

    // Graceful shutdown: stop accepting, then let in-flight connections close.
    info!(
        "Waiting for {} active connections to close (timeout: {}s)...",
        state.active_connections.load(Ordering::Relaxed),
        shutdown_timeout
    );

    // Signal all connections to shutdown
    cancel_token.cancel();

    if !drain_connections(
        &state.active_connections,
        Duration::from_secs(shutdown_timeout),
    )
    .await
    {
        warn!(
            "Shutdown timeout reached, aborting {} connections still active",
            state.active_connections.load(Ordering::Relaxed)
        );
    }

    info!("Shutdown complete.");
    Ok(())
}

// ============================================================================
// PostgreSQL Connection Handling
// ============================================================================

/// Deadline for the pre-protocol phase (startup peek, SSLRequest, TLS
/// handshake): unauthenticated peers must not be able to pin a task and an fd
/// by connecting and sending nothing.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);

/// Await one step of the authentication exchange under the handshake deadline,
/// bailing out early when the proxy is shutting down.
///
/// Without the cancel arm a connection still negotiating auth ignores SIGTERM
/// for up to `HANDSHAKE_DEADLINE`, which is longer than the default shutdown
/// timeout — so a rollout that catches a connecting client always ends in a
/// forced abort instead of a clean drain.
async fn auth_step<T>(
    cancel: &CancellationToken,
    what: &str,
    fut: impl std::future::Future<Output = T>,
) -> Result<T> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            Err(anyhow::anyhow!("proxy is shutting down while waiting for {what}"))
        }
        result = tokio::time::timeout(HANDSHAKE_DEADLINE, fut) => {
            result.map_err(|_| anyhow::anyhow!("{what} timed out"))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_postgres_connection(
    mut client_socket: tokio::net::TcpStream,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    upstream_pool: Option<UpstreamSlotManager>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    cancel: CancellationToken,
) -> Result<()> {
    // Buffer the whole 8-byte prelude before routing. `peek` returns whatever
    // is in the socket buffer at first readability, so a segmented client
    // write used to skip the TLS-aware branch entirely and get an
    // unconditional 'N' from the codec path — silently cleartext against a
    // proxy the operator had configured for TLS.
    let mut buffer = [0u8; 8];
    let n = tokio::time::timeout(HANDSHAKE_DEADLINE, async {
        loop {
            let n = client_socket.peek(&mut buffer).await?;
            if n >= 8 || n == 0 {
                return Ok::<usize, std::io::Error>(n);
            }
            // Nothing else to wait on but more data arriving.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("client handshake timed out"))??;
    if n >= 8 {
        let len = u32::from_be_bytes(
            buffer[0..4]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid startup message length"))?,
        );
        let code = u32::from_be_bytes(
            buffer[4..8]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid startup message code"))?,
        );

        if len == 8 && code == 80877103 {
            // It is an SSLRequest
            let mut trash = [0u8; 8];
            client_socket.read_exact(&mut trash).await?;

            if let Some(acceptor) = tls_acceptor {
                info!("Received SSLRequest, accepting...");
                client_socket.write_all(b"S").await?;

                let tls_stream =
                    tokio::time::timeout(HANDSHAKE_DEADLINE, acceptor.accept(client_socket))
                        .await
                        .map_err(|_| anyhow::anyhow!("client TLS handshake timed out"))??;
                return handle_postgres_protocol(
                    tls_stream,
                    upstream_host,
                    upstream_port,
                    state,
                    upstream_pool,
                    upstream_tls_config,
                    cancel,
                )
                .await;
            } else {
                info!("Received SSLRequest, denying (TLS not configured)...");
                client_socket.write_all(b"N").await?;
            }
        }
    }

    handle_postgres_protocol(
        client_socket,
        upstream_host,
        upstream_port,
        state,
        upstream_pool,
        upstream_tls_config,
        cancel,
    )
    .await
}

/// Build the client-facing rustls ServerConfig, wiring up mTLS when configured.
///
/// Without `client_ca_path` this is the historical behaviour: TLS with no
/// client authentication. With it, client certificates are verified against the
/// configured CA bundle — required when `require_client_cert` is set, optional
/// otherwise, which is the shape needed to roll mTLS out to existing clients
/// without a flag day.
fn build_client_tls_config(
    tls_config: &crate::config::TlsConfig,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let Some(ca_path) = tls_config.client_ca_path.as_deref() else {
        return Ok(ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?);
    };

    let ca_certs = load_certs(ca_path)
        .map_err(|e| anyhow::anyhow!("failed to read tls.client_ca_path '{ca_path}': {e}"))?;
    if ca_certs.is_empty() {
        anyhow::bail!("tls.client_ca_path '{ca_path}' contains no certificates");
    }
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert)
            .map_err(|e| anyhow::anyhow!("invalid CA certificate in '{ca_path}': {e}"))?;
    }

    // Build against an explicit provider rather than the process default: the
    // default is only installed if something else installed it first, and a
    // missing one surfaces as a panic at connection time rather than at boot.
    let builder = tokio_rustls::rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(default_provider()),
    );
    let verifier = if tls_config.require_client_cert {
        info!("mTLS: client certificates are required, verified against {ca_path}");
        builder.build()
    } else {
        info!("mTLS: client certificates are optional, verified against {ca_path} when presented");
        builder.allow_unauthenticated().build()
    }
    .map_err(|e| anyhow::anyhow!("failed to build the client certificate verifier: {e}"))?;

    Ok(ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?)
}

/// Creates a TLS ClientConfig that uses the OS native certificate verifier.
pub fn create_upstream_tls_config() -> Result<ClientConfig> {
    // Initialize the platform-specific verifier
    let provider = Arc::new(default_provider());
    let verifier = Arc::new(
        Verifier::new(provider)
            .map_err(|e| anyhow::anyhow!("failed to create platform TLS verifier: {}", e))?,
    );

    Ok(ClientConfig::builder()
        // .dangerous() is required because we are overriding the default
        // WebPki verifier with a custom one (the platform verifier).
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

async fn handle_postgres_protocol<S>(
    client_socket: S,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    upstream_pool: Option<UpstreamSlotManager>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    cancel: CancellationToken,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut client_socket = client_socket;

    // Get timeout configuration
    let (connect_timeout, idle_timeout, pool_wait_timeout) = {
        let config = state.config.read().await;
        resolve_timeout_limits(config.limits.as_ref())
    };

    let mut _upstream_pool_lease = None;
    if let Some(pool) = upstream_pool {
        let wait_started = Instant::now();
        match pool.acquire(pool_wait_timeout).await {
            Ok(lease) => {
                metrics::record_upstream_pool_wait(wait_started.elapsed().as_secs_f64());
                _upstream_pool_lease = Some(lease);
            }
            Err(UpstreamPoolAcquireError::Closed) => {
                metrics::record_connection_rejected("upstream_pool_closed");
                let _ = send_postgres_fatal_error_response(
                    &mut client_socket,
                    "08006",
                    "upstream pool unavailable",
                )
                .await;
                return Ok(());
            }
            Err(UpstreamPoolAcquireError::Timeout) => {
                metrics::record_upstream_pool_acquire_timeout();
                metrics::record_connection_rejected("upstream_pool_wait_timeout");
                let message = format!(
                    "upstream pool is at capacity; timed out after {}s waiting for an available slot",
                    pool_wait_timeout.as_secs()
                );
                let _ =
                    send_postgres_fatal_error_response(&mut client_socket, "53300", &message).await;
                return Ok(());
            }
        }
    }

    // Create upstream connection with timeout
    let mut upstream_socket =
        connect_upstream_with_timeout(&upstream_host, upstream_port, connect_timeout).await?;

    // Check if upstream TLS is enabled
    let upstream_tls_enabled = {
        let config = state.config.read().await;
        config.upstream_tls
    };

    if upstream_tls_enabled {
        info!(
            "Upstream TLS enabled. Attempting handshake with {}:{}",
            upstream_host, upstream_port
        );

        // 1. Send SSLRequest to upstream
        let mut ssl_request = bytes::BytesMut::with_capacity(8);
        ssl_request.put_u32(8); // Length
        ssl_request.put_u32(80877103); // SSLRequest code
        upstream_socket.write_all(&ssl_request).await?;

        // 2. Read response (1 byte)
        let mut response = [0u8; 1];
        upstream_socket.read_exact(&mut response).await?;

        if response[0] == b'S' {
            info!("Upstream accepted SSLRequest. Upgrading connection...");

            // 3. Upgrade to TLS
            let client_config = match upstream_tls_config {
                Some(config) => config,
                None => Arc::new(create_upstream_tls_config()?),
            };
            let connector = TlsConnector::from(client_config);

            let domain = ServerName::try_from(upstream_host.as_str())
                .map_err(|_| anyhow::anyhow!("Invalid DNS name for upstream host"))?
                .to_owned();

            let upstream_tls_stream = connector.connect(domain, upstream_socket).await?;

            // 4. Continue with TLS stream
            let result = handle_postgres_protocol_inner(
                client_socket,
                upstream_tls_stream,
                state,
                idle_timeout,
                cancel,
            )
            .await;
            return result;
        } else {
            // upstream_tls: true means required. Silently downgrading to
            // cleartext turned a one-byte response (or an on-path rewrite)
            // into credentials and unmasked data crossing the wire in plain.
            let _ = send_postgres_fatal_error_response(
                &mut client_socket,
                "08006",
                "upstream refused TLS but upstream_tls is required",
            )
            .await;
            anyhow::bail!("upstream denied SSLRequest while upstream_tls is enabled");
        }
    }

    // Cleartext connection
    handle_postgres_protocol_inner(client_socket, upstream_socket, state, idle_timeout, cancel)
        .await
}

async fn handle_postgres_protocol_inner<S, U>(
    client_socket: S,
    upstream_socket: U,
    state: AppState,
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut client_framed = Framed::new(client_socket, PostgresCodec::new());
    let mut upstream_framed = Framed::new(upstream_socket, PostgresCodec::new_upstream());

    let connection_id = rand::random::<u64>() as usize;
    let mut interceptor = Anonymizer::new(state.clone(), connection_id);
    let mut postgres_oid_bootstrap_done = false;
    // Start of the in-flight query, for the round-trip latency histogram.
    let mut query_started_at: Option<Instant> = None;

    loop {
        tokio::select! {
            // Client -> Upstream
            msg = client_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        match msg {
                            PgMessage::SSLRequest => {
                                info!("Received SSLRequest, denying...");
                                // Deny SSL, force cleartext
                                client_framed.get_mut().write_all(b"N").await?;
                            }
                            PgMessage::Query(ref q) => {
                                let query_str = String::from_utf8_lossy(&q.query).to_string();
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "Query".to_string(),
                                    content: redact_sql_literals(&query_str, false),
                                    details: None,
                                }).await;

                                // Record query type stats
                                let query_type = query_str
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("OTHER")
                                    .to_uppercase();
                                state.record_query(&query_type).await;
                                query_started_at = Some(Instant::now());

                                // Drop any stale index->strategy map from a previous
                                // statement before its result set arrives.
                                interceptor.reset_columns();

                                upstream_framed.send(msg).await?;
                            }
                            PgMessage::Parse(ref p) => {
                                let query_str = String::from_utf8_lossy(&p.query).to_string();
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "Parse".to_string(),
                                    content: redact_sql_literals(&query_str, false),
                                    details: None,
                                }).await;

                                // Record query type stats for prepared statements
                                let query_type = query_str
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("OTHER")
                                    .to_uppercase();
                                state.record_query(&query_type).await;
                                query_started_at = Some(Instant::now());

                                interceptor.reset_columns();

                                upstream_framed.send(msg).await?;
                            }
                            _ => {
                                // Forward other messages (Startup, Query, etc.)
                                upstream_framed.send(msg).await?;
                            }
                        }
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()), // Client disconnected
                }
            }
            // Upstream -> Client
            msg = upstream_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        match msg {
                            PgMessage::Regular(regular)
                                if regular.message_type == b'Z' && !postgres_oid_bootstrap_done =>
                            {
                                client_framed.send(PgMessage::Regular(regular)).await?;

                                let needs_bootstrap = {
                                    let config = state.config.read().await;
                                    !config.rules.is_empty()
                                };
                                if !needs_bootstrap {
                                    postgres_oid_bootstrap_done = true;
                                } else {
                                    match bootstrap_postgres_table_oid_map(&mut upstream_framed, &mut interceptor).await {
                                        Ok(loaded) => {
                                            // Mark done only on success so a transient failure
                                            // retries at the next ReadyForQuery instead of
                                            // leaving table-scoped rules silently inert.
                                            postgres_oid_bootstrap_done = true;
                                            info!("Loaded {} PostgreSQL table/column mappings for rule matching", loaded);
                                        }
                                        Err(err) => {
                                            warn!("Failed to bootstrap PostgreSQL OID mappings (will retry): {}", err);
                                        }
                                    }
                                }
                            }
                            PgMessage::RowDescription(rd) => {
                                interceptor.on_row_description(&rd).await;
                                client_framed.send(PgMessage::RowDescription(rd)).await?;
                            }
                            PgMessage::DataRow(dr) => {
                                let new_dr = interceptor.on_data_row(dr).await?;
                                client_framed.send(PgMessage::DataRow(new_dr)).await?;
                            }
                            other => {
                                // ReadyForQuery ends the query round trip.
                                if let PgMessage::Regular(ref regular) = other
                                    && regular.message_type == b'Z'
                                    && let Some(started) = query_started_at.take()
                                {
                                    state.record_query_latency(started);
                                }
                                // COPY TO STDOUT bypasses the DataRow interceptor entirely.
                                // Make the unmasked path visible instead of silent.
                                if let PgMessage::Regular(ref regular) = other
                                    && regular.message_type == b'H'
                                {
                                    warn!(
                                        "PostgreSQL COPY-out response forwarded without masking: \
                                         COPY data does not pass through the row interceptor"
                                    );
                                    metrics::record_copy_passthrough();
                                }
                                client_framed.send(other).await?;
                            }
                        }
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()), // Upstream disconnected
                }
            }
            // Graceful shutdown
            _ = cancel.cancelled() => {
                info!("Shutdown requested; closing PostgreSQL connection");
                let _ = client_framed.send(PgMessage::Regular(build_postgres_fatal_regular_message(
                    "57P01",
                    "proxy is shutting down",
                ))).await;
                return Ok(());
            }
            // Idle timeout
            _ = tokio::time::sleep(idle_timeout) => {
                info!("Connection idle timeout after {:?}", idle_timeout);
                metrics::record_idle_timeout();
                return Ok(());
            }
        }
    }
}

fn decode_postgres_data_row_text_value(row: &DataRow, index: usize) -> Option<String> {
    row.values
        .get(index)
        .and_then(|v| v.as_ref())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(|value| value.trim().to_string())
}

async fn bootstrap_postgres_table_oid_map<U>(
    upstream_framed: &mut Framed<U, PostgresCodec>,
    interceptor: &mut Anonymizer,
) -> Result<usize>
where
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Read all regular tables, partitions, views and foreign tables that appear in result sets,
    // including their column names/attnums so rules can match true provenance
    // (table_oid + column_index) rather than the aliasable result-set label.
    const OID_LOOKUP_QUERY: &str = "
        SELECT c.oid::text, n.nspname, c.relname, a.attnum::text, a.attname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_attribute a
          ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
        WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
    ";

    upstream_framed
        .send(PgMessage::Query(QueryMessage {
            query: Bytes::copy_from_slice(OID_LOOKUP_QUERY.as_bytes()),
        }))
        .await?;

    let mut loaded = 0usize;

    loop {
        match upstream_framed.next().await {
            Some(Ok(PgMessage::DataRow(row))) => {
                let oid = decode_postgres_data_row_text_value(&row, 0)
                    .and_then(|raw| raw.parse::<u32>().ok());
                let schema = decode_postgres_data_row_text_value(&row, 1);
                let table = decode_postgres_data_row_text_value(&row, 2);
                let attnum = decode_postgres_data_row_text_value(&row, 3)
                    .and_then(|raw| raw.parse::<i16>().ok());
                let column = decode_postgres_data_row_text_value(&row, 4);

                if let (Some(oid), Some(schema), Some(table)) = (oid, schema, table) {
                    interceptor.register_postgres_table_oid(oid, &schema, &table);
                    if let (Some(attnum), Some(column)) = (attnum, column) {
                        interceptor.register_postgres_column(oid, attnum, &column);
                    }
                    loaded += 1;
                }
            }
            Some(Ok(PgMessage::Regular(msg))) if msg.message_type == b'Z' => break,
            Some(Ok(_)) => {}
            Some(Err(err)) => return Err(err),
            None => {
                return Err(anyhow::anyhow!(
                    "Upstream disconnected during OID map bootstrap"
                ));
            }
        }
    }

    Ok(loaded)
}

// ============================================================================
// MySQL Connection Handling
// ============================================================================

/// Any stream the proxy can run a protocol over. Boxing keeps the plain and
/// TLS-wrapped variants of both legs from multiplying into a type explosion.
trait ProxyStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ProxyStream for T {}
type BoxedStream = Box<dyn ProxyStream + 'static>;

/// A stream with bytes already read into a buffer put back in front of it.
/// Framed may have buffered the client's TLS ClientHello together with the
/// SSLRequest packet; those bytes must survive the switch to a TLS stream.
struct PrefixedStream<S> {
    prefix: bytes::BytesMut,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: bytes::BytesMut, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix.split_to(n));
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_mysql_connection(
    client_socket: tokio::net::TcpStream,
    upstream_host: String,
    upstream_port: u16,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    terminating_auth: Option<Arc<TerminatingAuth>>,
    cancel: CancellationToken,
) -> Result<()> {
    // Get timeout configuration
    let (connect_timeout, idle_timeout) = {
        let config = state.config.read().await;
        let (connect_timeout, idle_timeout, _) = resolve_timeout_limits(config.limits.as_ref());
        (connect_timeout, idle_timeout)
    };

    // Connect to upstream MySQL server with timeout
    let upstream_socket =
        connect_upstream_with_timeout(&upstream_host, upstream_port, connect_timeout).await?;

    handle_mysql_protocol(
        Box::new(client_socket),
        Box::new(upstream_socket),
        upstream_host,
        state,
        idle_timeout,
        tls_acceptor,
        upstream_tls_config,
        terminating_auth,
        cancel,
    )
    .await
}

/// Credentials for `auth.mode: terminate`, resolved once at startup.
#[derive(Debug, Clone)]
struct TerminatingAuth {
    client_username: String,
    client_password: String,
    client_plugin: crate::auth::AuthPlugin,
    upstream_username: String,
    upstream_password: String,
    upstream_database: Option<String>,
}

impl TerminatingAuth {
    fn from_resolved(resolved: &crate::config::ResolvedAuth) -> Result<Self> {
        let client_plugin = crate::auth::AuthPlugin::from_name(&resolved.client_auth_plugin)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported auth.client_auth_plugin '{}'",
                    resolved.client_auth_plugin
                )
            })?;
        Ok(Self {
            client_username: resolved.client_username.clone(),
            client_password: resolved.client_password.clone(),
            client_plugin,
            upstream_username: resolved.upstream_username.clone(),
            upstream_password: resolved.upstream_password.clone(),
            upstream_database: resolved.upstream_database.clone(),
        })
    }
}

/// Capability flags for the proxy's own upstream handshake response.
///
/// Shape-affecting bits — CLIENT_DEPRECATE_EOF above all, but also
/// CLIENT_PROTOCOL_41 and the multi-result bits — must match what the client
/// negotiated. If the two legs disagree, the upstream sends packets in a layout
/// the client is not expecting, and since column definitions and result-set
/// terminators are forwarded verbatim the mismatch surfaces as a corrupt result
/// set rather than a clean error. Starting from the client's own flags and
/// intersecting with the server's keeps them in step by construction.
///
/// The proxy then overrides the handful of bits it owns regardless of what
/// either side asked for: it never negotiates compression (the codec cannot
/// frame a compressed stream, so masking would silently stop applying), it
/// decides its own TLS, and it re-encodes the response from fields — so the
/// CONNECT_ATTRS bit must be off, since there is no attribute block to match it.
fn negotiate_upstream_capabilities(
    client_caps: u32,
    server_caps: u32,
    with_database: bool,
    tls: bool,
) -> u32 {
    use crate::protocol::mysql::{
        CLIENT_COMPRESS, CLIENT_CONNECT_ATTRS, CLIENT_CONNECT_WITH_DB, CLIENT_PLUGIN_AUTH,
        CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION, CLIENT_SSL,
    };

    let mut caps = client_caps & server_caps;
    caps &= !(CLIENT_SSL | CLIENT_COMPRESS | CLIENT_CONNECT_WITH_DB | CLIENT_CONNECT_ATTRS);
    caps |= CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
    if with_database {
        caps |= CLIENT_CONNECT_WITH_DB;
    }
    if tls {
        caps |= CLIENT_SSL;
    }
    caps
}

/// Verify the client's credential against the locally-configured one.
///
/// Returns the sequence id of the last client packet on success, or `None`
/// after writing an access-denied ERR (the caller should close the connection).
async fn authenticate_client(
    client_framed: &mut Framed<BoxedStream, MySqlCodec>,
    auth: &TerminatingAuth,
    response: &crate::protocol::mysql::HandshakeResponse,
    nonce: &[u8],
    first_seq: u8,
    cancel: &CancellationToken,
) -> Result<Option<u8>> {
    let mut seq = first_seq;
    let mut scramble = response.auth_response.clone();

    // A client that guessed a different plugin — because it defaulted, or
    // because it cached the upstream's choice — is asked to switch. This is the
    // ordinary MySQL flow, not an error.
    let offered = response.auth_plugin_name.as_deref().unwrap_or_default();
    if offered != auth.client_plugin.name() {
        tracing::debug!(
            requested = offered,
            switching_to = auth.client_plugin.name(),
            "asking client to switch auth plugin"
        );
        seq = seq.wrapping_add(1);
        client_framed.codec_mut().set_auth_response_state();
        client_framed
            .send(MySqlMessage::Generic(
                crate::protocol::mysql::GenericPacket {
                    sequence_id: seq,
                    payload: bytes::BytesMut::from(
                        &crate::auth::build_auth_switch_request(auth.client_plugin, nonce)[..],
                    ),
                },
            ))
            .await?;

        match auth_step(
            cancel,
            "the client auth-switch response",
            client_framed.next(),
        )
        .await?
        {
            Some(Ok(MySqlMessage::Generic(g))) => {
                seq = g.sequence_id;
                scramble = g.payload.to_vec();
            }
            Some(Ok(other)) => {
                anyhow::bail!("expected an auth-switch response, got {other:?}")
            }
            Some(Err(e)) => return Err(e),
            None => return Ok(None),
        }
    }

    let username_ok = response.username == auth.client_username;
    let password_ok =
        crate::auth::verify_scramble(auth.client_plugin, &auth.client_password, nonce, &scramble);

    // Deliberately one message for both failures: distinguishing "no such user"
    // from "wrong password" turns the port into a username oracle, and MySQL
    // itself does not distinguish them either.
    if !username_ok || !password_ok {
        tracing::warn!(
            username = %response.username,
            "client authentication rejected"
        );
        metrics::record_client_auth(false);
        client_framed
            .send(MySqlMessage::Err(
                crate::protocol::mysql::ErrPacket::proxy_error(
                    seq.wrapping_add(1),
                    1045, // ER_ACCESS_DENIED_ERROR
                    b"28000",
                    &format!("Access denied for user '{}' (iron-veil)", response.username),
                ),
            ))
            .await?;
        return Ok(None);
    }

    metrics::record_client_auth(true);
    Ok(Some(seq))
}

/// Authenticate to the upstream server with the proxy's own credential.
#[allow(clippy::too_many_arguments)]
async fn authenticate_upstream(
    upstream_framed: &mut Framed<BoxedStream, MySqlCodec>,
    auth: &TerminatingAuth,
    handshake: &crate::protocol::mysql::HandshakeV10,
    capabilities: u32,
    database: Option<String>,
    character_set: u8,
    max_packet_size: u32,
    response_seq: u8,
    tls: bool,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut nonce = crate::auth::nonce_from_handshake(
        &handshake.auth_plugin_data_part1,
        &handshake.auth_plugin_data_part2,
    );
    // An upstream advertising a plugin this build does not implement (e.g.
    // sha256_password) still usually accepts caching_sha2_password, and will
    // send an AuthSwitchRequest if it does not — which the loop below handles.
    let mut plugin = crate::auth::AuthPlugin::from_name(&handshake.auth_plugin_name)
        .unwrap_or(crate::auth::AuthPlugin::CachingSha2Password);

    let payload = crate::protocol::mysql::build_handshake_response_payload(
        &crate::protocol::mysql::HandshakeResponse {
            capability_flags: capabilities,
            max_packet_size,
            character_set,
            username: auth.upstream_username.clone(),
            auth_response: crate::auth::scramble(plugin, &auth.upstream_password, &nonce),
            database,
            auth_plugin_name: Some(plugin.name().to_string()),
            raw: Bytes::new(),
        },
    );
    upstream_framed.codec_mut().set_auth_response_state();
    upstream_framed
        .send(MySqlMessage::Generic(
            crate::protocol::mysql::GenericPacket {
                sequence_id: response_seq,
                payload,
            },
        ))
        .await?;

    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > 20 {
            anyhow::bail!("upstream authentication exceeded 20 round trips");
        }

        match auth_step(cancel, "the upstream auth response", upstream_framed.next()).await? {
            Some(Ok(MySqlMessage::Ok(_))) => return Ok(()),
            Some(Ok(MySqlMessage::Err(e))) => {
                anyhow::bail!(
                    "upstream rejected the proxy credential for user '{}': {} ({})",
                    auth.upstream_username,
                    e.error_message,
                    e.error_code
                )
            }
            Some(Ok(MySqlMessage::Generic(g))) => {
                let reply_seq = g.sequence_id.wrapping_add(1);

                if let Ok((name, new_nonce)) = crate::auth::parse_auth_switch_request(&g.payload) {
                    plugin = crate::auth::AuthPlugin::from_name(&name).ok_or_else(|| {
                        anyhow::anyhow!(
                            "upstream asked for auth plugin '{name}', which iron-veil does not \
                             implement; grant the proxy account caching_sha2_password or \
                             mysql_native_password"
                        )
                    })?;
                    nonce = new_nonce;
                    let scramble = crate::auth::scramble(plugin, &auth.upstream_password, &nonce);
                    upstream_framed
                        .send(MySqlMessage::Generic(
                            crate::protocol::mysql::GenericPacket {
                                sequence_id: reply_seq,
                                payload: bytes::BytesMut::from(&scramble[..]),
                            },
                        ))
                        .await?;
                    continue;
                }

                match crate::auth::classify_auth_more_data(&g.payload) {
                    // The server had the credential cached; OK follows with no
                    // reply from us.
                    Some(crate::auth::AuthMoreData::FastAuthSuccess) => continue,
                    Some(crate::auth::AuthMoreData::FullAuthRequired) => {
                        // Full auth sends the password in the clear. MySQL only
                        // accepts that on a secure channel, and iron-veil will
                        // not send it on an insecure one regardless.
                        if !tls {
                            anyhow::bail!(
                                "upstream requires full authentication for user '{}' but \
                                 upstream_tls is false; full auth transmits the password in \
                                 cleartext, so set upstream_tls: true",
                                auth.upstream_username
                            );
                        }
                        let payload =
                            crate::auth::build_cleartext_password(&auth.upstream_password);
                        upstream_framed
                            .send(MySqlMessage::Generic(
                                crate::protocol::mysql::GenericPacket {
                                    sequence_id: reply_seq,
                                    payload: bytes::BytesMut::from(&payload[..]),
                                },
                            ))
                            .await?;
                        continue;
                    }
                    Some(crate::auth::AuthMoreData::Other) | None => {
                        anyhow::bail!(
                            "unexpected packet during upstream authentication (first byte {:#04x})",
                            g.payload.first().copied().unwrap_or_default()
                        )
                    }
                }
            }
            Some(Ok(other)) => anyhow::bail!("unexpected message during upstream auth: {other:?}"),
            Some(Err(e)) => return Err(e),
            None => anyhow::bail!("upstream closed the connection during authentication"),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_mysql_protocol(
    client_socket: BoxedStream,
    upstream_socket: BoxedStream,
    upstream_host: String,
    state: AppState,
    idle_timeout: Duration,
    tls_acceptor: Option<TlsAcceptor>,
    upstream_tls_config: Option<Arc<ClientConfig>>,
    terminating_auth: Option<Arc<TerminatingAuth>>,
    cancel: CancellationToken,
) -> Result<()> {
    let upstream_tls_required = {
        let config = state.config.read().await;
        config.upstream_tls
    };

    let mut client_framed = Framed::new(client_socket, MySqlCodec::new_server());
    let mut upstream_framed = Framed::new(upstream_socket, MySqlCodec::new_client());

    let connection_id = rand::random::<u64>() as usize;
    let mut interceptor = MySqlAnonymizer::new(state.clone(), connection_id);
    // Start of the in-flight query, for the round-trip latency histogram.
    let mut query_started_at: Option<Instant> = None;

    // Phase 1: build the handshake the client sees from the upstream one.
    //
    // Reusing the upstream's capability flags is deliberate even in terminating
    // mode: the shape-affecting bits (CLIENT_DEPRECATE_EOF above all) must be
    // consistent across both legs or the verbatim passthrough of column
    // definitions and result-set terminators breaks. Only the auth material and
    // the bits the proxy itself must control are changed.
    let (handshake, client_nonce) = match upstream_framed.next().await {
        Some(Ok(MySqlMessage::Handshake(h))) => {
            info!(server_version = %h.server_version, "Received MySQL handshake from upstream");
            // Advertise to the client only what this proxy can actually serve:
            // CLIENT_SSL only when a TLS acceptor is configured (otherwise a
            // TLS-preferring client attempts an upgrade nothing answers), and
            // never CLIENT_COMPRESS (the codec cannot frame a compressed
            // stream, so masking would be bypassed).
            let mut client_handshake = h.clone();
            client_handshake.capability_flags &= !crate::protocol::mysql::CLIENT_COMPRESS;
            if tls_acceptor.is_some() {
                client_handshake.capability_flags |= crate::protocol::mysql::CLIENT_SSL;
            } else {
                client_handshake.capability_flags &= !crate::protocol::mysql::CLIENT_SSL;
            }

            // In terminating mode the client authenticates against the proxy,
            // so it gets the proxy's own nonce and plugin — never the
            // upstream's, which would let it compute a scramble valid upstream.
            let nonce = match terminating_auth.as_ref() {
                Some(auth) => {
                    let nonce = crate::auth::generate_nonce();
                    client_handshake
                        .auth_plugin_data_part1
                        .copy_from_slice(&nonce[..8]);
                    client_handshake.auth_plugin_data_part2 = nonce[8..].to_vec();
                    client_handshake.auth_plugin_name = auth.client_plugin.name().to_string();
                    client_handshake.capability_flags |= crate::protocol::mysql::CLIENT_PLUGIN_AUTH
                        | crate::protocol::mysql::CLIENT_SECURE_CONNECTION
                        | crate::protocol::mysql::CLIENT_PROTOCOL_41;
                    // The surgical encoder path only patches capability bits;
                    // changed auth material has to be re-encoded from fields.
                    client_handshake.raw = Bytes::new();
                    Some(nonce)
                }
                None => None,
            };

            client_framed
                .send(MySqlMessage::Handshake(client_handshake))
                .await?;
            (h, nonce)
        }
        Some(Ok(other)) => {
            tracing::warn!("Expected handshake, got {:?}", other);
            return Err(anyhow::anyhow!("Protocol error: expected handshake"));
        }
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    };

    // Update codec capability flags
    client_framed
        .codec_mut()
        .set_capability_flags(handshake.capability_flags);
    upstream_framed
        .codec_mut()
        .set_capability_flags(handshake.capability_flags);

    // Phase 2: client handshake response, upgrading to TLS if the client asks
    let mut client_response = match auth_step(
        &cancel,
        "the client handshake response",
        client_framed.next(),
    )
    .await?
    {
        Some(Ok(MySqlMessage::HandshakeResponse(r))) => r,
        Some(Ok(other)) => {
            tracing::warn!("Expected handshake response, got {:?}", other);
            return Err(anyhow::anyhow!(
                "Protocol error: expected handshake response"
            ));
        }
        Some(Err(e)) => return Err(e),
        None => return Ok(()),
    };

    let mut client_used_tls = false;
    if client_response.is_ssl_request() {
        let Some(acceptor) = tls_acceptor else {
            anyhow::bail!("client requested TLS but no TLS acceptor is configured");
        };
        client_used_tls = true;
        let negotiated_caps = client_response.capability_flags;

        // Re-wrap the client socket, carrying over anything Framed had already
        // buffered past the SSLRequest packet.
        let parts = client_framed.into_parts();
        let prefixed = PrefixedStream::new(parts.read_buf, parts.io);
        let tls_stream = auth_step(
            &cancel,
            "the client TLS handshake",
            acceptor.accept(prefixed),
        )
        .await??;
        info!("MySQL client connection upgraded to TLS");

        client_framed = Framed::new(
            Box::new(tls_stream) as BoxedStream,
            MySqlCodec::new_server_awaiting_handshake_response(negotiated_caps),
        );

        client_response = match auth_step(
            &cancel,
            "the client handshake response after TLS",
            client_framed.next(),
        )
        .await?
        {
            Some(Ok(MySqlMessage::HandshakeResponse(r))) => r,
            Some(Ok(other)) => {
                anyhow::bail!("expected handshake response after TLS, got {:?}", other);
            }
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        };
    }

    info!(username = %client_response.username, database = ?client_response.database,
          "Received client handshake response");

    // Terminating mode: authenticate the client against the local credential
    // here, before a single byte of the proxy's own credential is used. The
    // client is not told the outcome yet — a client that says OK and then
    // immediately errors because the *upstream* rejected the proxy is worse
    // than one that simply never authenticated — so success only unlocks the
    // upstream leg below.
    let client_auth_seq = if let Some(auth) = terminating_auth.as_ref() {
        client_framed
            .codec_mut()
            .set_capability_flags(client_response.capability_flags);
        let nonce = client_nonce
            .as_deref()
            .expect("terminating mode always generates a client nonce");
        // Handshake is sequence 0, so the client's response is 1 — or 2 when
        // an SSLRequest went first.
        let first_seq = if client_used_tls { 2 } else { 1 };

        match authenticate_client(
            &mut client_framed,
            auth,
            &client_response,
            nonce,
            first_seq,
            &cancel,
        )
        .await?
        {
            Some(seq) => Some(seq),
            // Rejected; the ERR packet is already on the wire.
            None => return Ok(()),
        }
    } else {
        None
    };

    // Upstream TLS leg. MySQL 8.4's default caching_sha2_password sends the
    // password in cleartext during full auth and the server rejects that on an
    // insecure connection, so a TLS-terminating proxy must re-originate TLS
    // upstream for a non-cached credential to authenticate at all.
    if upstream_tls_required {
        if handshake.capability_flags & crate::protocol::mysql::CLIENT_SSL == 0 {
            anyhow::bail!("upstream_tls is enabled but the upstream does not offer CLIENT_SSL");
        }
        let ssl_request = crate::protocol::mysql::build_ssl_request(
            client_response.capability_flags,
            client_response.max_packet_size,
            client_response.character_set,
        );
        upstream_framed
            .send(MySqlMessage::Generic(ssl_request))
            .await?;

        let parts = upstream_framed.into_parts();
        if !parts.read_buf.is_empty() {
            anyhow::bail!("upstream sent data before the TLS handshake");
        }
        let client_config = match upstream_tls_config {
            Some(config) => config,
            None => Arc::new(create_upstream_tls_config()?),
        };
        let connector = TlsConnector::from(client_config);
        let domain = ServerName::try_from(upstream_host.as_str())
            .map_err(|_| anyhow::anyhow!("Invalid DNS name for upstream host"))?
            .to_owned();
        let tls_stream = connector.connect(domain, parts.io).await?;
        info!("MySQL upstream connection upgraded to TLS");

        upstream_framed = Framed::new(
            Box::new(tls_stream) as BoxedStream,
            MySqlCodec::new_client_awaiting_auth(client_response.capability_flags),
        );
    } else if client_response.capability_flags & crate::protocol::mysql::CLIENT_SSL != 0 {
        warn!(
            "client connected over TLS but upstream_tls is false: caching_sha2_password \
             full authentication will fail for credentials the server has not cached"
        );
    }

    // Update capability flags based on what the client actually negotiated
    client_framed
        .codec_mut()
        .set_capability_flags(client_response.capability_flags);

    // Phase 3: authentication upstream.
    match terminating_auth.as_ref() {
        // Terminating mode: the proxy is the client here, using its own
        // credential. The real client never sees the upstream nonce and never
        // sends a scramble that would be valid against the database.
        Some(auth) => {
            let database = client_response
                .database
                .clone()
                .filter(|db| !db.is_empty())
                .or_else(|| auth.upstream_database.clone());
            let upstream_caps = negotiate_upstream_capabilities(
                client_response.capability_flags,
                handshake.capability_flags,
                database.is_some(),
                upstream_tls_required,
            );
            upstream_framed
                .codec_mut()
                .set_capability_flags(upstream_caps);

            if let Err(err) = authenticate_upstream(
                &mut upstream_framed,
                auth,
                &handshake,
                upstream_caps,
                database,
                client_response.character_set,
                client_response.max_packet_size,
                // Handshake is 0, so our response is 1 — or 2 when we sent an
                // SSLRequest first.
                if upstream_tls_required { 2 } else { 1 },
                upstream_tls_required,
                &cancel,
            )
            .await
            {
                // The client authenticated fine; it is the proxy's own upstream
                // credential that failed. Say so plainly rather than echoing the
                // server's access-denied, which names the *proxy's* account and
                // reads as if the client's own credential was rejected.
                tracing::error!(error = %err, "upstream authentication failed");
                let seq = client_auth_seq.unwrap_or(1).wrapping_add(1);
                let _ = client_framed
                    .send(MySqlMessage::Err(
                        crate::protocol::mysql::ErrPacket::proxy_error(
                            seq,
                            1045,
                            b"28000",
                            "iron-veil could not authenticate to the upstream database",
                        ),
                    ))
                    .await;
                return Err(err);
            }

            // Both legs are up. Only now is the client told it is in.
            let mut seq = client_auth_seq.unwrap_or(1).wrapping_add(1);
            if auth.client_plugin == crate::auth::AuthPlugin::CachingSha2Password {
                client_framed
                    .send(MySqlMessage::Generic(
                        crate::protocol::mysql::GenericPacket {
                            sequence_id: seq,
                            payload: bytes::BytesMut::from(
                                &crate::auth::build_fast_auth_success()[..],
                            ),
                        },
                    ))
                    .await?;
                seq = seq.wrapping_add(1);
            }
            client_framed
                .send(MySqlMessage::Ok(crate::protocol::mysql::OkPacket {
                    sequence_id: seq,
                    affected_rows: 0,
                    last_insert_id: 0,
                    status_flags: crate::protocol::mysql::SERVER_STATUS_AUTOCOMMIT,
                    warnings: 0,
                    info: Bytes::new(),
                    raw: Bytes::new(),
                }))
                .await?;
            info!(
                client_user = %auth.client_username,
                upstream_user = %auth.upstream_username,
                "MySQL authentication terminated at the proxy"
            );
        }

        // Passthrough mode: relay the authentication exchange verbatim until it
        // resolves. caching_sha2_password needs several round trips (auth
        // switch, fast-auth result, public-key request, full auth); handling
        // only one packet left every non-cached credential unable to connect.
        None => {
            upstream_framed
                .codec_mut()
                .set_capability_flags(client_response.capability_flags);
            // The response's sequence id is 2, not 1, when the proxy sent an
            // SSLRequest first; MySQL answers a mismatch with
            // ER_NET_PACKETS_OUT_OF_ORDER and drops the connection.
            let raw = client_response.raw.clone();
            upstream_framed
                .send(MySqlMessage::Generic(
                    crate::protocol::mysql::GenericPacket {
                        sequence_id: if upstream_tls_required { 2 } else { 1 },
                        payload: bytes::BytesMut::from(&raw[..]),
                    },
                ))
                .await?;

            let mut auth_rounds = 0;
            loop {
                auth_rounds += 1;
                if auth_rounds > 20 {
                    anyhow::bail!("MySQL authentication exceeded 20 round trips");
                }

                match auth_step(
                    &cancel,
                    "the upstream auth response",
                    upstream_framed.next(),
                )
                .await?
                {
                    Some(Ok(msg @ MySqlMessage::Ok(_))) => {
                        info!("MySQL authentication successful");
                        client_framed.send(msg).await?;
                        break;
                    }
                    Some(Ok(MySqlMessage::Err(e))) => {
                        tracing::warn!(error_code = e.error_code, "MySQL authentication failed");
                        client_framed.send(MySqlMessage::Err(e)).await?;
                        return Ok(());
                    }
                    Some(Ok(other)) => {
                        // Intermediate auth packet (AuthMoreData / AuthSwitchRequest).
                        // Forward to the client, but only wait for a client reply when
                        // the protocol actually requires one. caching_sha2_password
                        // fast-auth success (0x01 0x03) is followed immediately by OK
                        // with no client bytes — waiting hangs every successful MySQL 8
                        // login through the proxy.
                        let expects_reply = match &other {
                            MySqlMessage::Generic(g) => {
                                crate::protocol::mysql::auth_packet_expects_client_reply(&g.payload)
                            }
                            // Parsed OK/ERR are handled above; anything else during auth
                            // is treated as needing a client reply.
                            _ => true,
                        };
                        client_framed.send(other).await?;
                        if expects_reply {
                            match auth_step(
                                &cancel,
                                "the client auth response",
                                client_framed.next(),
                            )
                            .await?
                            {
                                Some(Ok(reply)) => upstream_framed.send(reply).await?,
                                Some(Err(e)) => return Err(e),
                                None => return Ok(()),
                            }
                        }
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()),
                }
            }
        }
    }

    // Authentication is done; both codecs resume the command phase.
    client_framed.codec_mut().set_command_state();
    upstream_framed.codec_mut().set_command_state();

    // Phase 4: Command phase - bidirectional proxy with interception
    loop {
        tokio::select! {
            // Client -> Upstream
            msg = client_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        match &msg {
                            MySqlMessage::Query(q) => {
                                let query_str = String::from_utf8_lossy(&q.query).to_string();
                                let id = format!("{:x}", rand::random::<u128>());
                                state.add_log(LogEntry {
                                    id,
                                    timestamp: Utc::now(),
                                    connection_id,
                                    event_type: "MySqlQuery".to_string(),
                                    content: redact_sql_literals(&query_str, true),
                                    details: None,
                                }).await;

                                // Record query type stats
                                let query_type = query_str
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("OTHER")
                                    .to_uppercase();
                                state.record_query(&query_type).await;
                                query_started_at = Some(Instant::now());

                                // Reset interceptor and response codec for the
                                // new result set — a desynced response stream
                                // must not survive past the next command.
                                interceptor.reset_columns();
                                upstream_framed.codec_mut().set_command_state();
                            }
                            MySqlMessage::Generic(g) => {
                                // COM_STMT_PREPARE / COM_STMT_EXECUTE / COM_STMT_FETCH: the
                                // binary protocol is unsupported — its result rows would
                                // bypass masking entirely. Reject visibly with ER_UNSUPPORTED_PS
                                // (most connectors fall back to client-side statements) instead
                                // of forwarding a stream the codec would misparse.
                                if let Some(cmd @ (0x16 | 0x17 | 0x1c)) = g.payload.first() {
                                    tracing::warn!(
                                        command = format!("0x{cmd:02x}"),
                                        "rejecting MySQL binary-protocol command; \
                                         iron-veil masks the text protocol only"
                                    );
                                    metrics::record_binary_protocol_rejected();
                                    let err = crate::protocol::mysql::ErrPacket::proxy_error(
                                        1,
                                        1295, // ER_UNSUPPORTED_PS
                                        b"HY000",
                                        "iron-veil: server-side prepared statements (binary \
                                         protocol) are not supported; use the text protocol",
                                    );
                                    client_framed.send(MySqlMessage::Err(err)).await?;
                                    continue;
                                }
                                upstream_framed.codec_mut().set_command_state();
                            }
                            _ => {}
                        }
                        upstream_framed.send(msg).await?;
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()),
                }
            }
            // Upstream -> Client
            msg = upstream_framed.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        // A result-set terminator, OK or ERR ends the round trip.
                        if matches!(
                            msg,
                            MySqlMessage::Ok(_) | MySqlMessage::Err(_) | MySqlMessage::Generic(_)
                        ) && let Some(started) = query_started_at.take()
                        {
                            state.record_query_latency(started);
                        }

                        let msg_to_send = match msg {
                            MySqlMessage::ColumnDefinition(ref col) => {
                                interceptor.on_column_definition(col).await;
                                msg
                            }
                            MySqlMessage::ResultRow(row) => {
                                let new_row = interceptor.on_result_row(row).await?;
                                MySqlMessage::ResultRow(new_row)
                            }
                            MySqlMessage::Eof(_) => {
                                // EOF after columns means we're about to get rows
                                // EOF after rows means result set is done
                                msg
                            }
                            _ => msg,
                        };
                        client_framed.send(msg_to_send).await?;
                    }
                    Some(Err(e)) => return Err(e),
                    None => return Ok(()),
                }
            }
            // Graceful shutdown
            _ = cancel.cancelled() => {
                info!("Shutdown requested; closing MySQL connection");
                let err = crate::protocol::mysql::ErrPacket::proxy_error(
                    0,
                    1053, // ER_SERVER_SHUTDOWN
                    b"08S01",
                    "proxy is shutting down",
                );
                let _ = client_framed.send(MySqlMessage::Err(err)).await;
                return Ok(());
            }
            // Idle timeout
            _ = tokio::time::sleep(idle_timeout) => {
                info!("MySQL connection idle timeout after {:?}", idle_timeout);
                metrics::record_idle_timeout();
                return Ok(());
            }
        }
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_keys(path: &str) -> Result<PrivateKeyDer<'static>> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{
        UpstreamPoolAcquireError, UpstreamSlotManager, auth_step, build_mysql_err_packet,
        build_postgres_fatal_error_packet, drain_connections, negotiate_upstream_capabilities,
        redact_sql_literals, resolve_timeout_limits,
    };
    use crate::config::LimitsConfig;
    use anyhow::Result;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tokio_util::sync::CancellationToken;

    #[test]
    fn test_build_postgres_fatal_error_packet_format() {
        let packet = build_postgres_fatal_error_packet("53300", "pool timeout");

        assert_eq!(packet[0], b'E');
        let length = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) as usize;
        assert_eq!(length, packet.len() - 1);

        let payload = &packet[5..];
        assert_eq!(payload[0], b'S');
        assert!(payload.ends_with(&[0]));
        assert!(payload.windows("FATAL\0".len()).any(|w| w == b"FATAL\0"));
        assert!(payload.windows("53300\0".len()).any(|w| w == b"53300\0"));
        assert!(
            payload
                .windows("pool timeout\0".len())
                .any(|w| w == b"pool timeout\0")
        );
    }

    #[test]
    fn test_build_mysql_err_packet_format() {
        let packet = build_mysql_err_packet(1040, "08004", "upstream pool timeout");

        // Packet header: 3-byte payload length + 1-byte sequence
        let payload_len =
            (packet[0] as usize) | ((packet[1] as usize) << 8) | ((packet[2] as usize) << 16);
        assert_eq!(payload_len, packet.len() - 4);
        assert_eq!(packet[3], 0);

        let payload = &packet[4..];
        assert_eq!(payload[0], 0xFF);
        assert_eq!(u16::from_le_bytes([payload[1], payload[2]]), 1040);
        assert_eq!(payload[3], b'#');
        assert_eq!(&payload[4..9], b"08004");
        assert_eq!(&payload[9..], b"upstream pool timeout");
    }

    #[test]
    fn test_resolve_timeout_limits_defaults() {
        let (connect, idle, pool_wait) = resolve_timeout_limits(None);
        assert_eq!(connect, Duration::from_secs(30));
        assert_eq!(idle, Duration::from_secs(300));
        assert_eq!(pool_wait, Duration::from_secs(5));
    }

    #[test]
    fn test_resolve_timeout_limits_from_config() {
        let limits = LimitsConfig {
            max_connections: None,
            connections_per_second: None,
            connect_timeout_secs: 12,
            idle_timeout_secs: 34,
            upstream_pool_size: Some(10),
            upstream_pool_wait_timeout_secs: 7,
        };
        let (connect, idle, pool_wait) = resolve_timeout_limits(Some(&limits));
        assert_eq!(connect, Duration::from_secs(12));
        assert_eq!(idle, Duration::from_secs(34));
        assert_eq!(pool_wait, Duration::from_secs(7));
    }

    #[tokio::test]
    async fn test_upstream_slot_manager_acquire_and_release() {
        let manager = UpstreamSlotManager::new(1);
        assert_eq!(manager.available_slots(), 1);

        let lease = manager
            .acquire(Duration::from_millis(20))
            .await
            .expect("first acquire should succeed");
        assert_eq!(manager.available_slots(), 0);

        drop(lease);
        assert_eq!(manager.available_slots(), 1);
    }

    // ------------------------------------------------------------------
    // Client-facing TLS / mTLS
    // ------------------------------------------------------------------

    /// A CA plus a leaf certificate signed by it, as PEM.
    struct TestPki {
        ca_pem: String,
        server_cert_pem: String,
        server_key_pem: String,
        client_cert_pem: String,
        client_key_pem: String,
    }

    fn build_test_pki() -> TestPki {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose,
        };

        let mut ca_params = CertificateParams::new(vec!["iron-veil-test-ca".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.clone().self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

        let mut client_params = CertificateParams::new(vec!["door".to_string()]).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

        TestPki {
            ca_pem: ca_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    fn write_temp(dir: &std::path::Path, name: &str, contents: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn tls_config_for(
        dir: &std::path::Path,
        pki: &TestPki,
        client_ca: Option<&str>,
        require: bool,
    ) -> crate::config::TlsConfig {
        crate::config::TlsConfig {
            enabled: true,
            cert_path: write_temp(dir, "server.crt", &pki.server_cert_pem),
            key_path: write_temp(dir, "server.key", &pki.server_key_pem),
            client_ca_path: client_ca.map(|s| s.to_string()),
            require_client_cert: require,
        }
    }

    fn acceptor_for(tls: &crate::config::TlsConfig) -> Result<TlsAcceptor> {
        let certs = super::load_certs(&tls.cert_path)?;
        let key = super::load_keys(&tls.key_path)?;
        Ok(TlsAcceptor::from(Arc::new(super::build_client_tls_config(
            tls, certs, key,
        )?)))
    }

    /// Drive a real TLS handshake over an in-memory duplex, optionally with a
    /// client certificate. Returns whether the handshake completed.
    async fn tls_handshake_succeeds(
        acceptor: TlsAcceptor,
        ca_pem: &str,
        client_identity: Option<(String, String)>,
    ) -> bool {
        use tokio_rustls::rustls::pki_types::pem::PemObject;

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder = ClientConfig::builder().with_root_certificates(roots);
        let client_config = match client_identity {
            Some((cert_pem, key_pem)) => {
                let chain: Vec<_> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .map(|c| c.unwrap())
                    .collect();
                let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
                builder.with_client_auth_cert(chain, key).unwrap()
            }
            None => builder.with_no_client_auth(),
        };

        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(async move {
            // Hold the accepted stream for the life of the task: dropping it
            // closes the duplex under the client.
            acceptor.accept(server_io).await.map_err(|e| e.to_string())
        });
        let connector = TlsConnector::from(Arc::new(client_config));
        let domain = ServerName::try_from("localhost").unwrap();
        // Bind the stream rather than discarding it — dropping the client half
        // here closes the duplex before the server has read the client's
        // Finished, and every handshake then "fails" with a broken pipe.
        let client = connector.connect(domain, client_io).await;

        // Both ends must agree. Under TLS 1.3 the client can complete its side
        // before the server has validated the client certificate, so a rejected
        // certificate shows up only as a server-side failure.
        let server = server.await.unwrap();
        if let Err(err) = &server {
            eprintln!("server handshake failed: {err}");
        }
        if let Err(err) = &client {
            eprintln!("client handshake failed: {err}");
        }
        server.is_ok() && client.is_ok()
    }

    #[tokio::test]
    async fn test_tls_without_client_ca_admits_clients_with_no_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let pki = build_test_pki();
        let tls = tls_config_for(dir.path(), &pki, None, false);

        assert!(
            tls_handshake_succeeds(acceptor_for(&tls).unwrap(), &pki.ca_pem, None).await,
            "the default (no mTLS) must keep working"
        );
    }

    #[tokio::test]
    async fn test_required_client_cert_rejects_a_client_without_one() {
        let dir = tempfile::tempdir().unwrap();
        let pki = build_test_pki();
        let ca_path = write_temp(dir.path(), "ca.crt", &pki.ca_pem);
        let tls = tls_config_for(dir.path(), &pki, Some(&ca_path), true);

        assert!(
            !tls_handshake_succeeds(acceptor_for(&tls).unwrap(), &pki.ca_pem, None).await,
            "require_client_cert must reject an unauthenticated client"
        );
    }

    #[tokio::test]
    async fn test_required_client_cert_accepts_a_cert_from_the_configured_ca() {
        let dir = tempfile::tempdir().unwrap();
        let pki = build_test_pki();
        let ca_path = write_temp(dir.path(), "ca.crt", &pki.ca_pem);
        let tls = tls_config_for(dir.path(), &pki, Some(&ca_path), true);

        assert!(
            tls_handshake_succeeds(
                acceptor_for(&tls).unwrap(),
                &pki.ca_pem,
                Some((pki.client_cert_pem.clone(), pki.client_key_pem.clone())),
            )
            .await,
            "a client cert chaining to the configured CA must be accepted"
        );
    }

    #[tokio::test]
    async fn test_client_cert_from_another_ca_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let pki = build_test_pki();
        let other = build_test_pki();
        let ca_path = write_temp(dir.path(), "ca.crt", &pki.ca_pem);
        let tls = tls_config_for(dir.path(), &pki, Some(&ca_path), true);

        assert!(
            !tls_handshake_succeeds(
                acceptor_for(&tls).unwrap(),
                &pki.ca_pem,
                Some((other.client_cert_pem, other.client_key_pem)),
            )
            .await,
            "a client cert from an unrelated CA must not be accepted"
        );
    }

    #[tokio::test]
    async fn test_optional_client_cert_admits_both_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let pki = build_test_pki();
        let ca_path = write_temp(dir.path(), "ca.crt", &pki.ca_pem);
        let tls = tls_config_for(dir.path(), &pki, Some(&ca_path), false);

        assert!(
            tls_handshake_succeeds(acceptor_for(&tls).unwrap(), &pki.ca_pem, None).await,
            "optional mTLS must still admit a client with no certificate"
        );
        assert!(
            tls_handshake_succeeds(
                acceptor_for(&tls).unwrap(),
                &pki.ca_pem,
                Some((pki.client_cert_pem.clone(), pki.client_key_pem.clone())),
            )
            .await,
            "optional mTLS must accept a valid certificate"
        );
    }

    #[test]
    fn test_empty_client_ca_bundle_is_rejected_at_startup() {
        // An empty CA file would build a verifier that trusts nothing, turning
        // "require client certs" into "reject everyone" at connection time.
        let dir = tempfile::tempdir().unwrap();
        let pki = build_test_pki();
        let ca_path = write_temp(dir.path(), "ca.crt", "");
        let tls = tls_config_for(dir.path(), &pki, Some(&ca_path), true);

        let err = match acceptor_for(&tls) {
            Ok(_) => panic!("an empty CA bundle must be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("no certificates"), "got: {err}");
    }

    #[test]
    fn test_upstream_capabilities_track_the_client_for_shape_bits() {
        use crate::protocol::mysql::{
            CLIENT_DEPRECATE_EOF, CLIENT_PLUGIN_AUTH, CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION,
        };

        let server = u32::MAX;

        // A client that negotiated DEPRECATE_EOF must have it negotiated
        // upstream too: the terminator's shape differs, and it is forwarded
        // verbatim, so a mismatch corrupts every result set.
        let caps = negotiate_upstream_capabilities(
            CLIENT_PROTOCOL_41 | CLIENT_DEPRECATE_EOF,
            server,
            false,
            false,
        );
        assert_ne!(caps & CLIENT_DEPRECATE_EOF, 0);

        // ...and a client that did not must not have it set upstream.
        let caps = negotiate_upstream_capabilities(CLIENT_PROTOCOL_41, server, false, false);
        assert_eq!(caps & CLIENT_DEPRECATE_EOF, 0);

        // The bits the proxy always needs are added regardless.
        assert_ne!(caps & CLIENT_PROTOCOL_41, 0);
        assert_ne!(caps & CLIENT_SECURE_CONNECTION, 0);
        assert_ne!(caps & CLIENT_PLUGIN_AUTH, 0);
    }

    #[test]
    fn test_upstream_capabilities_never_exceed_what_the_server_offers() {
        use crate::protocol::mysql::CLIENT_DEPRECATE_EOF;

        // Client wants DEPRECATE_EOF, server does not support it.
        let caps = negotiate_upstream_capabilities(u32::MAX, !CLIENT_DEPRECATE_EOF, false, false);
        assert_eq!(caps & CLIENT_DEPRECATE_EOF, 0);
    }

    #[test]
    fn test_upstream_capabilities_are_owned_by_the_proxy() {
        use crate::protocol::mysql::{
            CLIENT_COMPRESS, CLIENT_CONNECT_ATTRS, CLIENT_CONNECT_WITH_DB, CLIENT_SSL,
        };

        // Even if the client negotiated all of these, the proxy decides.
        let caps = negotiate_upstream_capabilities(u32::MAX, u32::MAX, false, false);
        assert_eq!(
            caps & CLIENT_COMPRESS,
            0,
            "compression would stop the codec framing packets, silently bypassing masking"
        );
        assert_eq!(caps & CLIENT_SSL, 0);
        assert_eq!(caps & CLIENT_CONNECT_WITH_DB, 0);
        assert_eq!(
            caps & CLIENT_CONNECT_ATTRS,
            0,
            "the re-encoded response carries no attribute block"
        );

        // ...and are set when the proxy does need them.
        let caps = negotiate_upstream_capabilities(0, u32::MAX, true, true);
        assert_ne!(caps & CLIENT_CONNECT_WITH_DB, 0);
        assert_ne!(caps & CLIENT_SSL, 0);
        assert_eq!(caps & CLIENT_COMPRESS, 0);
    }

    #[test]
    fn test_redact_sql_literals_scrubs_single_quoted_strings() {
        let redacted = redact_sql_literals(
            "SELECT * FROM users WHERE email = 'alice@example.com' AND city = 'Vienna'",
            false,
        );
        assert!(!redacted.contains("alice@example.com"), "got: {redacted}");
        assert!(!redacted.contains("Vienna"), "got: {redacted}");
        // The shape of the statement survives — that is the audit value.
        assert!(redacted.starts_with("SELECT * FROM users WHERE email = '?'"));
    }

    #[test]
    fn test_redact_sql_literals_scrubs_mysql_double_quoted_strings() {
        // In MySQL (without ANSI_QUOTES) "..." is a string literal, so this
        // used to write the address straight into the log ring.
        let sql = r#"SELECT * FROM users WHERE email = "alice@example.com""#;
        assert!(!redact_sql_literals(sql, true).contains("alice@example.com"));
    }

    #[test]
    fn test_redact_sql_literals_keeps_postgres_quoted_identifiers() {
        // In PostgreSQL "..." is an identifier; redacting it would erase the
        // table and column names without suppressing anything.
        let redacted = redact_sql_literals(r#"SELECT "Email" FROM "Users""#, false);
        assert_eq!(redacted, r#"SELECT "Email" FROM "Users""#);
    }

    #[test]
    fn test_redact_sql_literals_handles_escapes() {
        // Doubled quote inside a literal must not end it early.
        let redacted = redact_sql_literals("SELECT 'O''Brien secret' , 1", false);
        assert!(!redacted.contains("Brien"), "got: {redacted}");
        assert!(redacted.contains(", 1"), "got: {redacted}");

        // Backslash-escaped quote likewise.
        let redacted = redact_sql_literals(r"SELECT 'a\'b secret' , 2", false);
        assert!(!redacted.contains("secret"), "got: {redacted}");

        // An unterminated literal swallows the tail rather than resuming in
        // cleartext.
        let redacted = redact_sql_literals("SELECT 'dangling alice@example.com", false);
        assert!(!redacted.contains("alice@example.com"), "got: {redacted}");
    }

    #[tokio::test]
    async fn test_drain_returns_immediately_when_no_connections() {
        let active = AtomicUsize::new(0);
        assert!(drain_connections(&active, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn test_drain_waits_for_connections_to_close() {
        let active = Arc::new(AtomicUsize::new(2));
        let closer = active.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            closer.store(0, Ordering::Relaxed);
        });

        assert!(
            drain_connections(&active, Duration::from_secs(5)).await,
            "drain should report success once the count reaches zero"
        );
    }

    #[tokio::test]
    async fn test_drain_gives_up_at_the_deadline() {
        // A connection that never closes must not hold the process past the
        // shutdown timeout — that is exactly the k8s rollout stall in B-5.
        let active = AtomicUsize::new(1);
        let started = std::time::Instant::now();

        assert!(!drain_connections(&active, Duration::from_millis(50)).await);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "drain must abort promptly at the deadline, took {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn test_auth_step_aborts_when_shutting_down() {
        // An in-auth connection blocked on a peer that never answers must
        // observe cancellation rather than sit out the full handshake deadline.
        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = auth_step(&cancel, "a reply", std::future::pending::<()>()).await;
        let err = result.expect_err("cancelled auth step should fail");
        assert!(
            err.to_string().contains("shutting down"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_auth_step_passes_through_the_value() {
        let cancel = CancellationToken::new();
        let value = auth_step(&cancel, "a reply", async { 42u8 })
            .await
            .expect("uncancelled auth step should succeed");
        assert_eq!(value, 42);
    }

    #[tokio::test]
    async fn test_upstream_slot_manager_acquire_times_out_when_full() {
        let manager = UpstreamSlotManager::new(1);
        let _lease = manager
            .acquire(Duration::from_millis(20))
            .await
            .expect("first acquire should succeed");

        let result = manager.acquire(Duration::from_millis(20)).await;
        assert!(matches!(result, Err(UpstreamPoolAcquireError::Timeout)));
    }
}
