use crate::audit::{AuditEventType, AuditLogger, AuditOutcome, AuthMethod};
use crate::config::MaskingRule;
use crate::db_scanner::{DbScanner, ScanConfig, ScanError};
use crate::state::{AppState, DbProtocol};
use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject (user identifier)
    sub: String,
    /// Expiration time (Unix timestamp)
    exp: usize,
    /// Issued at (Unix timestamp)
    #[serde(default)]
    iat: usize,
}

/// Validates a JWT token and returns the claims if valid
fn validate_jwt(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

/// Middleware to validate API key or JWT for protected endpoints
async fn api_auth(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    let config = state.config.read().await;
    let endpoint = request.uri().path().to_string();
    let method = request.method().to_string();

    let api_config = config.api.as_ref();
    let api_key = api_config.and_then(|c| c.api_key.as_ref());
    let jwt_secret = api_config.and_then(|c| c.jwt_secret.as_ref());

    // If neither API key nor JWT is configured, allow all requests
    if api_key.is_none() && jwt_secret.is_none() {
        drop(config);
        return next.run(request).await;
    }

    // Try API key authentication first
    if let Some(expected_key) = api_key
        && let Some(provided_key) = request
            .headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
    {
        if provided_key == expected_key {
            drop(config);
            // Log successful API key auth
            state
                .audit_logger
                .log(
                    AuditLogger::auth_success(AuthMethod::ApiKey, None)
                        .with_endpoint(&endpoint)
                        .with_method(&method),
                )
                .await;
            return next.run(request).await;
        } else {
            drop(config);
            // Log failed API key auth
            state
                .audit_logger
                .log(
                    AuditLogger::auth_failure(AuthMethod::ApiKey, "Invalid API key")
                        .with_endpoint(&endpoint)
                        .with_method(&method),
                )
                .await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Invalid API key"
                })),
            )
                .into_response();
        }
    }

    // Try JWT authentication
    if let Some(secret) = jwt_secret
        && let Some(auth_header) = request
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
        && let Some(token) = auth_header.strip_prefix("Bearer ")
    {
        match validate_jwt(token, secret) {
            Ok(claims) => {
                drop(config);
                // Log successful JWT auth
                state
                    .audit_logger
                    .log(
                        AuditLogger::auth_success(AuthMethod::Jwt, Some(claims.sub))
                            .with_endpoint(&endpoint)
                            .with_method(&method),
                    )
                    .await;
                return next.run(request).await;
            }
            Err(e) => {
                tracing::debug!("JWT validation failed: {}", e);
                drop(config);
                // Log failed JWT auth
                state
                    .audit_logger
                    .log(
                        AuditLogger::auth_failure(
                            AuthMethod::Jwt,
                            format!("JWT validation failed: {}", e),
                        )
                        .with_endpoint(&endpoint)
                        .with_method(&method),
                    )
                    .await;
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "Invalid or expired JWT token"
                    })),
                )
                    .into_response();
            }
        }
    }

    drop(config);
    // Log denied access (no credentials)
    state
        .audit_logger
        .log(
            AuditLogger::auth_denied()
                .with_endpoint(&endpoint)
                .with_method(&method),
        )
        .await;

    // No valid authentication provided
    let config = state.config.read().await;
    let api_config = config.api.as_ref();
    let api_key = api_config.and_then(|c| c.api_key.as_ref());
    let jwt_secret = api_config.and_then(|c| c.jwt_secret.as_ref());
    let auth_methods: Vec<&str> = [
        api_key.map(|_| "X-API-Key header"),
        jwt_secret.map(|_| "Authorization: Bearer <token>"),
    ]
    .into_iter()
    .flatten()
    .collect();

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "Authentication required",
            "methods": auth_methods
        })),
    )
        .into_response()
}

pub async fn start_api_server(port: u16, state: AppState) -> anyhow::Result<()> {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/metrics", get(get_metrics));

    // Protected routes (require API key or JWT if configured)
    let protected_routes = Router::new()
        .route("/rules", get(get_rules).post(add_rule))
        .route("/rules/delete", post(delete_rule))
        .route("/rules/export", get(export_rules))
        .route("/rules/import", post(import_rules))
        .route("/config", get(get_config).post(update_config))
        .route("/config/reload", post(reload_config))
        .route("/scan", post(scan_database))
        .route("/connections", get(get_connections))
        .route("/stats", get(get_stats))
        .route("/schema", post(get_schema))
        .route("/logs", get(get_logs))
        .route("/audit", get(get_audit_logs))
        .layer(middleware::from_fn_with_state(state.clone(), api_auth));

    // Combine routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Management API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to bind API server to {}: {}", addr, e))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("API server error: {}", e))?;
    Ok(())
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let health_status = state.health_status.read().await;
    let active_connections = state.active_connections.load(Ordering::Relaxed);
    let protocol = match state.db_protocol {
        DbProtocol::Postgres => "postgres",
        DbProtocol::MySql => "mysql",
    };

    let response = json!({
        "status": if health_status.healthy { "ok" } else { "degraded" },
        "service": "ironveil",
        "version": env!("CARGO_PKG_VERSION"),
        "upstream": {
            "host": state.upstream_host.as_ref(),
            "port": state.upstream_port,
            "protocol": protocol,
            "healthy": health_status.healthy,
            "last_check": health_status.last_check,
            "last_error": health_status.last_error,
            "latency_ms": health_status.latency_ms,
            "consecutive_failures": health_status.consecutive_failures,
            "consecutive_successes": health_status.consecutive_successes
        },
        "connections": {
            "active": active_connections
        }
    });

    if health_status.healthy {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

async fn get_rules(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!({
        "rules": config.rules
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleMutationOutcome {
    Added,
    Updated,
    Unchanged,
}

impl RuleMutationOutcome {
    fn as_str(self) -> &'static str {
        match self {
            RuleMutationOutcome::Added => "added",
            RuleMutationOutcome::Updated => "updated",
            RuleMutationOutcome::Unchanged => "unchanged",
        }
    }
}

fn normalized_rule_key(rule: &MaskingRule) -> (Option<String>, String) {
    let table = rule.table.as_ref().map(|t| t.trim().to_ascii_lowercase());
    let column = rule.column.trim().to_ascii_lowercase();
    (table, column)
}

fn dedupe_rules(rules: &mut Vec<MaskingRule>) -> usize {
    let original_len = rules.len();
    let mut seen = HashSet::new();
    rules.retain(|rule| seen.insert(normalized_rule_key(rule)));
    original_len - rules.len()
}

fn upsert_rule(rules: &mut Vec<MaskingRule>, incoming: MaskingRule) -> RuleMutationOutcome {
    let incoming_key = normalized_rule_key(&incoming);
    if let Some(existing) = rules
        .iter_mut()
        .find(|rule| normalized_rule_key(rule) == incoming_key)
    {
        if existing.strategy == incoming.strategy {
            RuleMutationOutcome::Unchanged
        } else {
            existing.strategy = incoming.strategy;
            RuleMutationOutcome::Updated
        }
    } else {
        rules.push(incoming);
        RuleMutationOutcome::Added
    }
}

async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<MaskingRule>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    let rule_json = serde_json::to_value(&rule).unwrap_or_default();
    let deduplicated_existing = dedupe_rules(&mut config.rules);
    let result = upsert_rule(&mut config.rules, rule);
    let rules_count = config.rules.len();
    drop(config);

    // Persist to file
    if let Err(e) = state.save_config().await {
        tracing::error!("Failed to save config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": format!("Failed to persist rule: {}", e),
                "rules_count": rules_count
            })),
        );
    }

    // Log audit event
    state
        .audit_logger
        .log(AuditLogger::rule_added(json!({
            "rule": rule_json,
            "result": result.as_str(),
            "deduplicated_existing": deduplicated_existing
        })))
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "result": result.as_str(),
            "rules_count": rules_count,
            "deduplicated_existing": deduplicated_existing
        })),
    )
}

/// Delete rule request payload
#[derive(Debug, Deserialize, Serialize)]
struct DeleteRuleRequest {
    /// Index of the rule to delete (0-based)
    index: Option<usize>,
    /// Or match by column name
    column: Option<String>,
    /// And optionally by table name
    table: Option<String>,
}

async fn delete_rule(
    State(state): State<AppState>,
    Json(req): Json<DeleteRuleRequest>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;

    let original_len = config.rules.len();
    let delete_details = serde_json::to_value(&req).unwrap_or_default();

    if let Some(index) = req.index {
        if index >= config.rules.len() {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "status": "error",
                    "error": format!("Rule index {} out of bounds (have {} rules)", index, config.rules.len())
                })),
            );
        }
        config.rules.remove(index);
    } else if let Some(ref column) = req.column {
        config.rules.retain(|rule| {
            if &rule.column != column {
                return true;
            }
            if let Some(ref table) = req.table {
                rule.table.as_ref() != Some(table)
            } else {
                false
            }
        });
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "error": "Must provide either 'index' or 'column' to identify rule to delete"
            })),
        );
    }

    let deleted_count = original_len - config.rules.len();
    let rules_count = config.rules.len();
    drop(config);

    // Persist to file
    if let Err(e) = state.save_config().await {
        tracing::error!("Failed to save config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": format!("Failed to persist changes: {}", e)
            })),
        );
    }

    // Log audit event
    state
        .audit_logger
        .log(AuditLogger::rule_deleted(json!({
            "request": delete_details,
            "deleted_count": deleted_count
        })))
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "deleted": deleted_count,
            "rules_count": rules_count
        })),
    )
}

/// Export rules as JSON
async fn export_rules(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config.read().await;
    let rules_json =
        serde_json::to_string_pretty(&config.rules).unwrap_or_else(|_| "[]".to_string());

    (
        StatusCode::OK,
        [
            ("content-type", "application/json"),
            (
                "content-disposition",
                "attachment; filename=\"ironveil-rules.json\"",
            ),
        ],
        rules_json,
    )
}

/// Import rules from JSON
async fn import_rules(
    State(state): State<AppState>,
    Json(rules): Json<Vec<MaskingRule>>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    let imported_count = rules.len();
    let deduplicated_existing = dedupe_rules(&mut config.rules);
    let mut added = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;
    for rule in rules {
        match upsert_rule(&mut config.rules, rule) {
            RuleMutationOutcome::Added => added += 1,
            RuleMutationOutcome::Updated => updated += 1,
            RuleMutationOutcome::Unchanged => unchanged += 1,
        }
    }
    let total_count = config.rules.len();
    drop(config);

    // Persist to file
    if let Err(e) = state.save_config().await {
        tracing::error!("Failed to save config: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": format!("Failed to persist imported rules: {}", e)
            })),
        );
    }

    // Log audit event
    state
        .audit_logger
        .log(AuditLogger::rules_imported(imported_count))
        .await;

    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "imported": imported_count,
            "rules_count": total_count,
            "added": added,
            "updated": updated,
            "unchanged": unchanged,
            "deduplicated_existing": deduplicated_existing
        })),
    )
}

async fn get_config(State(state): State<AppState>) -> Json<Value> {
    let config = state.config.read().await;
    Json(json!({
        "masking_enabled": config.masking_enabled,
        "rules_count": config.rules.len()
    }))
}

async fn update_config(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    let mut changes = serde_json::Map::new();

    if let Some(enabled) = payload.get("masking_enabled").and_then(|v| v.as_bool()) {
        let old_value = config.masking_enabled;
        config.masking_enabled = enabled;
        changes.insert(
            "masking_enabled".to_string(),
            json!({
                "old": old_value,
                "new": enabled
            }),
        );
    }
    drop(config);

    // Log audit event if there were changes
    if !changes.is_empty() {
        state
            .audit_logger
            .log(AuditLogger::config_change(Value::Object(changes)))
            .await;

        if let Err(e) = state.save_config().await {
            tracing::error!("Failed to persist config: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "status": "error",
                    "error": format!("Failed to persist config: {}", e)
                })),
            );
        }
    }

    let config = state.config.read().await;
    (
        StatusCode::OK,
        Json(json!({ "status": "success", "masking_enabled": config.masking_enabled })),
    )
}

/// Reload configuration from disk
async fn reload_config(State(state): State<AppState>) -> impl IntoResponse {
    match state.reload_config().await {
        Ok(rules_count) => {
            // Log audit event
            state
                .audit_logger
                .log(AuditLogger::config_reload(rules_count))
                .await;
            (
                StatusCode::OK,
                Json(json!({
                    "status": "success",
                    "message": "Configuration reloaded successfully",
                    "rules_count": rules_count
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": e
            })),
        ),
    }
}

async fn scan_database(
    State(state): State<AppState>,
    Json(config): Json<ScanConfig>,
) -> impl IntoResponse {
    let scanner = DbScanner::new(
        state.upstream_host.to_string(),
        state.upstream_port,
        state.db_protocol,
    );

    match scanner.scan(&config).await {
        Ok(result) => {
            // Log audit event
            state
                .audit_logger
                .log(AuditLogger::database_scan(
                    &config.database,
                    result.findings.len(),
                ))
                .await;
            (StatusCode::OK, Json(json!(result)))
        }
        Err(e) => scan_error_response(e),
    }
}

async fn get_connections(State(state): State<AppState>) -> Json<Value> {
    let count = state.active_connections.load(Ordering::Relaxed);
    Json(json!({
        "active_connections": count
    }))
}

/// Get application statistics (queries, masking, connections)
async fn get_stats(State(state): State<AppState>) -> Json<Value> {
    let stats = state.get_stats().await;
    let history = state.get_connection_history().await;
    let active_connections = state.active_connections.load(Ordering::Relaxed);

    Json(json!({
        "active_connections": active_connections,
        "total_connections": stats.total_connections,
        "masking": {
            "email": stats.masking.email,
            "phone": stats.masking.phone,
            "address": stats.masking.address,
            "credit_card": stats.masking.credit_card,
            "ssn": stats.masking.ssn,
            "ip": stats.masking.ip,
            "dob": stats.masking.dob,
            "passport": stats.masking.passport,
            "hash": stats.masking.hash,
            "json": stats.masking.json,
            "other": stats.masking.other,
            "total": stats.masking.total()
        },
        "queries": {
            "total": stats.queries.total_queries,
            "select": stats.queries.select_count,
            "insert": stats.queries.insert_count,
            "update": stats.queries.update_count,
            "delete": stats.queries.delete_count,
            "other": stats.queries.other_count
        },
        "history": history.iter().map(|p| json!({
            "timestamp": p.timestamp.to_rfc3339(),
            "active_connections": p.active_connections,
            "total_queries": p.total_queries,
            "total_masked": p.total_masked
        })).collect::<Vec<_>>()
    }))
}

async fn get_schema(
    State(state): State<AppState>,
    Json(config): Json<ScanConfig>,
) -> impl IntoResponse {
    let scanner = DbScanner::new(
        state.upstream_host.to_string(),
        state.upstream_port,
        state.db_protocol,
    );

    match scanner.get_schema(&config).await {
        Ok(schema) => {
            // Log audit event
            state
                .audit_logger
                .log(AuditLogger::schema_query(
                    &config.database,
                    schema.tables.len(),
                ))
                .await;
            (StatusCode::OK, Json(json!(schema)))
        }
        Err(e) => scan_error_response(e),
    }
}

fn scan_error_response(error: ScanError) -> (StatusCode, Json<Value>) {
    match error {
        ScanError::UnsupportedProtocol(protocol) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "status": "error",
                "error": format!("Unsupported database protocol: {:?}", protocol),
                "code": "unsupported_protocol"
            })),
        ),
        ScanError::AuthRequired => (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "status": "error",
                "error": "Authentication required: please provide database credentials",
                "code": "auth_required"
            })),
        ),
        ScanError::ConnectionFailed(message) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "status": "error",
                "error": message,
                "code": "connection_failed"
            })),
        ),
        ScanError::QueryFailed(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "status": "error",
                "error": message,
                "code": "query_failed"
            })),
        ),
    }
}

async fn get_logs(State(state): State<AppState>) -> Json<Value> {
    let logs = state.logs.read().await;
    Json(json!({
        "logs": *logs
    }))
}

/// Query parameters for audit log retrieval
#[derive(Debug, Deserialize)]
struct AuditQuery {
    /// Maximum number of entries to return
    limit: Option<usize>,
    /// Filter by event type
    event_type: Option<String>,
    /// Filter by outcome
    outcome: Option<String>,
}

/// Get audit logs with optional filtering
async fn get_audit_logs(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<AuditQuery>,
) -> Json<Value> {
    let limit = query.limit.unwrap_or(100);

    let entries = if let Some(event_type) = query.event_type {
        // Parse event type
        let event = match event_type.as_str() {
            "auth_attempt" => Some(AuditEventType::AuthAttempt),
            "config_change" => Some(AuditEventType::ConfigChange),
            "rule_added" => Some(AuditEventType::RuleAdded),
            "rule_deleted" => Some(AuditEventType::RuleDeleted),
            "rules_imported" => Some(AuditEventType::RulesImported),
            "config_reload" => Some(AuditEventType::ConfigReload),
            "database_scan" => Some(AuditEventType::DatabaseScan),
            "schema_query" => Some(AuditEventType::SchemaQuery),
            "api_access" => Some(AuditEventType::ApiAccess),
            _ => None,
        };
        if let Some(e) = event {
            state.audit_logger.get_entries_by_type(e, Some(limit)).await
        } else {
            state.audit_logger.get_entries(Some(limit)).await
        }
    } else if let Some(outcome) = query.outcome {
        // Parse outcome
        let out = match outcome.as_str() {
            "success" => Some(AuditOutcome::Success),
            "failure" => Some(AuditOutcome::Failure),
            "denied" => Some(AuditOutcome::Denied),
            _ => None,
        };
        if let Some(o) = out {
            state
                .audit_logger
                .get_entries_by_outcome(o, Some(limit))
                .await
        } else {
            state.audit_logger.get_entries(Some(limit)).await
        }
    } else {
        state.audit_logger.get_entries(Some(limit)).await
    };

    Json(json!({
        "count": entries.len(),
        "entries": entries
    }))
}

/// Prometheus metrics endpoint
async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    match &state.metrics_handle {
        Some(handle) => {
            let metrics = handle.render();
            (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
                metrics,
            )
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            [("content-type", "text/plain; charset=utf-8")],
            "Metrics not enabled".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiConfig, AppConfig};
    use crate::state::DbProtocol;
    use axum::body::to_bytes;
    use axum::extract::State;
    use tempfile::{NamedTempFile, tempdir};

    #[tokio::test]
    async fn test_health_check() {
        let config = AppConfig::default();
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let response = health_check(State(state)).await;
        let (status, _json) = response.into_response().into_parts();

        // For default state (healthy), we should get 200 OK
        assert_eq!(status.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_includes_upstream_runtime_info() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "db.internal".to_string(),
            6432,
            DbProtocol::MySql,
        );

        let response = health_check(State(state)).await.into_response();
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, StatusCode::OK);

        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(payload["upstream"]["host"], "db.internal");
        assert_eq!(payload["upstream"]["port"], 6432);
        assert_eq!(payload["upstream"]["protocol"], "mysql");
    }

    #[tokio::test]
    async fn test_api_key_config_parsing() {
        // Test that API key is correctly parsed from config
        let config = AppConfig {
            api: Some(ApiConfig {
                api_key: Some("my-secret-key".to_string()),
                jwt_secret: None,
            }),
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let config_guard = state.config.read().await;

        let required_key = config_guard
            .api
            .as_ref()
            .and_then(|api| api.api_key.as_ref());

        assert_eq!(required_key, Some(&"my-secret-key".to_string()));
    }

    #[tokio::test]
    async fn test_api_key_none_when_not_configured() {
        // Test that no API key means None
        let config = AppConfig::default();
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let config_guard = state.config.read().await;

        let required_key = config_guard
            .api
            .as_ref()
            .and_then(|api| api.api_key.as_ref());

        assert_eq!(required_key, None);
    }

    #[tokio::test]
    async fn test_jwt_validation_valid_token() {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let secret = "test-jwt-secret";
        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let result = validate_jwt(&token, secret);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "test-user");
    }

    #[tokio::test]
    async fn test_jwt_validation_expired_token() {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let secret = "test-jwt-secret";
        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as usize,
            iat: (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap();

        let result = validate_jwt(&token, secret);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_validation_wrong_secret() {
        use jsonwebtoken::{EncodingKey, Header, encode};

        let claims = Claims {
            sub: "test-user".to_string(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"correct-secret"),
        )
        .unwrap();

        let result = validate_jwt(&token, "wrong-secret");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jwt_config_parsing() {
        let config = AppConfig {
            api: Some(ApiConfig {
                api_key: None,
                jwt_secret: Some("my-jwt-secret".to_string()),
            }),
            ..Default::default()
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());
        let config_guard = state.config.read().await;

        let jwt_secret = config_guard
            .api
            .as_ref()
            .and_then(|api| api.jwt_secret.as_ref());

        assert_eq!(jwt_secret, Some(&"my-jwt-secret".to_string()));
    }

    #[tokio::test]
    async fn test_get_config() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "email".to_string(),
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        let response = get_config(State(state)).await;
        let json = response.0;

        assert_eq!(json["masking_enabled"], true);
        assert_eq!(json["rules_count"], 1);
    }

    #[tokio::test]
    async fn test_update_config() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(
            &config_path,
            "masking_enabled: true\nupstream_tls: false\nrules: []\n",
        )
        .unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, config_path);

        let payload = json!({ "masking_enabled": false });
        let response = update_config(State(state.clone()), Json(payload))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify state was actually updated
        let config = state.config.read().await;
        assert!(!config.masking_enabled);
    }

    #[tokio::test]
    async fn test_add_rule() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(
            &config_path,
            "masking_enabled: true\nupstream_tls: false\nrules: []\n",
        )
        .unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, config_path);

        let new_rule = MaskingRule {
            table: Some("users".to_string()),
            column: "phone".to_string(),
            strategy: "phone".to_string(),
        };

        // Call add_rule and verify rule was added to state
        let _ = add_rule(State(state.clone()), Json(new_rule)).await;

        // Verify rule was added
        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].column, "phone");
    }

    #[tokio::test]
    async fn test_add_rule_upserts_existing_rule_for_same_table_and_column() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(&config_path, "masking_enabled: true\nrules: []\n").unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "email".to_string(),
            }],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path);

        let updated_rule = MaskingRule {
            table: Some("Users".to_string()),
            column: "EMAIL".to_string(),
            strategy: "hash".to_string(),
        };

        let response = add_rule(State(state.clone()), Json(updated_rule))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].strategy, "hash");
    }

    #[tokio::test]
    async fn test_import_rules_deduplicates_existing_and_imported_rules() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(&config_path, "masking_enabled: true\nrules: []\n").unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "email".to_string(),
                    strategy: "email".to_string(),
                },
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "email".to_string(),
                    strategy: "phone".to_string(),
                },
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "phone".to_string(),
                    strategy: "phone".to_string(),
                },
            ],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path);

        let imported = vec![
            MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "hash".to_string(),
            },
            MaskingRule {
                table: Some("users".to_string()),
                column: "email".to_string(),
                strategy: "hash".to_string(),
            },
            MaskingRule {
                table: Some("users".to_string()),
                column: "PHONE".to_string(),
                strategy: "phone".to_string(),
            },
            MaskingRule {
                table: None,
                column: "address".to_string(),
                strategy: "address".to_string(),
            },
        ];

        let response = import_rules(State(state.clone()), Json(imported))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 3);
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("users")
                    && r.column == "email"
                    && r.strategy == "hash")
        );
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("users")
                    && r.column == "phone"
                    && r.strategy == "phone")
        );
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.is_none() && r.column == "address" && r.strategy == "address")
        );
    }

    #[tokio::test]
    async fn test_get_rules() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![MaskingRule {
                table: None,
                column: "email".to_string(),
                strategy: "email".to_string(),
            }],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        let response = get_rules(State(state)).await;
        let json = response.0;

        assert!(json["rules"].is_array());
        assert_eq!(json["rules"].as_array().unwrap().len(), 1);
        assert!(
            json.get("masking_enabled").is_none(),
            "GET /rules should return rules only, not full config"
        );
    }

    #[tokio::test]
    async fn test_delete_rule_by_column_and_table_only_deletes_matching_rule() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(&config_path, "masking_enabled: true\nrules: []\n").unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "email".to_string(),
                    strategy: "email".to_string(),
                },
                MaskingRule {
                    table: Some("accounts".to_string()),
                    column: "email".to_string(),
                    strategy: "email".to_string(),
                },
                MaskingRule {
                    table: Some("users".to_string()),
                    column: "phone".to_string(),
                    strategy: "phone".to_string(),
                },
            ],
            ..Default::default()
        };

        let state = AppState::new_for_test(config, config_path);
        let request = DeleteRuleRequest {
            index: None,
            column: Some("email".to_string()),
            table: Some("users".to_string()),
        };

        let _ = delete_rule(State(state.clone()), Json(request)).await;

        let config = state.config.read().await;
        assert_eq!(config.rules.len(), 2);
        assert!(
            !config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("users") && r.column == "email")
        );
        assert!(
            config
                .rules
                .iter()
                .any(|r| r.table.as_deref() == Some("accounts") && r.column == "email")
        );
    }

    #[tokio::test]
    async fn test_update_config_persists_to_disk() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_string_lossy().to_string();
        std::fs::write(
            &config_path,
            "masking_enabled: true\nupstream_tls: false\nrules: []\n",
        )
        .unwrap();

        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let state = AppState::new_for_test(config, config_path.clone());

        let payload = json!({ "masking_enabled": false });
        let _ = update_config(State(state), Json(payload)).await;

        let persisted = AppConfig::load(&config_path).unwrap();
        assert!(!persisted.masking_enabled);
    }

    #[tokio::test]
    async fn test_update_config_returns_500_when_persist_fails() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            ..Default::default()
        };
        let dir = tempdir().unwrap();
        let config_path = dir.path().to_string_lossy().to_string();
        let state = AppState::new_for_test(config, config_path);

        let payload = json!({ "masking_enabled": false });
        let response = update_config(State(state), Json(payload))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_get_connections() {
        let config = AppConfig {
            masking_enabled: true,
            rules: vec![],
            tls: None,
            upstream_tls: false,
            telemetry: None,
            api: None,
            limits: None,
            health_check: None,
            audit: None,
        };
        let state = AppState::new_for_test(config, "proxy.yaml".to_string());

        // Simulate some connections
        state.active_connections.fetch_add(3, Ordering::Relaxed);

        let response = get_connections(State(state)).await;
        let json = response.0;

        assert_eq!(json["active_connections"], 3);
    }

    #[tokio::test]
    async fn test_scan_database_returns_not_implemented_for_unsupported_protocol() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            3306,
            DbProtocol::MySql,
        );

        let request = ScanConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = scan_database(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_get_schema_returns_not_implemented_for_unsupported_protocol() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            3306,
            DbProtocol::MySql,
        );

        let request = ScanConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = get_schema(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_scan_database_returns_unauthorized_for_missing_credentials() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            5432,
            DbProtocol::Postgres,
        );

        let request = ScanConfig {
            username: "".to_string(),
            password: "".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = scan_database(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_schema_returns_unauthorized_for_missing_credentials() {
        let config = AppConfig::default();
        let state = AppState::new(
            config,
            "proxy.yaml".to_string(),
            "localhost".to_string(),
            5432,
            DbProtocol::Postgres,
        );

        let request = ScanConfig {
            username: "".to_string(),
            password: "".to_string(),
            database: "db".to_string(),
            sample_size: 10,
            schema: "public".to_string(),
            exclude_tables: vec![],
            confidence_threshold: 0.5,
        };

        let response = get_schema(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
