//! Integration tests for IronVeil database proxy
//!
//! These tests require running database containers. To run:
//! ```bash
//! docker compose up -d
//! cargo test --test integration_test
//! ```

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Test configuration
const PROXY_HOST: &str = "127.0.0.1";
const PROXY_PORT: u16 = 6543;
const API_PORT: u16 = 3001;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn test_strict_service_mode_defaults_to_non_strict() {
    assert!(!strict_service_mode(None, None));
}

#[test]
fn test_strict_service_mode_enabled_by_ci() {
    assert!(strict_service_mode(Some("true"), None));
}

#[test]
fn test_strict_service_mode_enabled_by_explicit_flag() {
    assert!(strict_service_mode(None, Some("1")));
}

fn env_flag_enabled(value: Option<&str>) -> bool {
    value
        .map(str::trim)
        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

fn strict_service_mode(ci: Option<&str>, explicit: Option<&str>) -> bool {
    env_flag_enabled(ci) || env_flag_enabled(explicit)
}

fn should_require_services() -> bool {
    let ci = std::env::var("CI").ok();
    let explicit = std::env::var("IRONVEIL_REQUIRE_SERVICES").ok();
    strict_service_mode(ci.as_deref(), explicit.as_deref())
}

async fn ensure_api_running(test_name: &str) -> bool {
    if is_api_running().await {
        return true;
    }

    let message = format!("API not running on port {}", API_PORT);
    if should_require_services() {
        panic!("{test_name}: {message}. Start required services before running integration tests.");
    }

    eprintln!("Skipping test: {test_name} ({message})");
    false
}

async fn ensure_proxy_running(test_name: &str) -> bool {
    if is_proxy_running().await {
        return true;
    }

    let message = format!("Proxy not running on port {}", PROXY_PORT);
    if should_require_services() {
        panic!("{test_name}: {message}. Start required services before running integration tests.");
    }

    eprintln!("Skipping test: {test_name} ({message})");
    false
}

/// Helper to check if the proxy is running.
/// `timeout(..).await.is_ok()` was true for a *refused* connection
/// (Ok(Err(ConnectionRefused))), so strict mode never fired and CI passed
/// against a proxy that had never started.
async fn is_proxy_running() -> bool {
    matches!(
        timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, PROXY_PORT)),
        )
        .await,
        Ok(Ok(_))
    )
}

/// Helper to check if API is running
async fn is_api_running() -> bool {
    matches!(
        timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, API_PORT)),
        )
        .await,
        Ok(Ok(_))
    )
}

async fn assert_protected_json_response(
    resp: reqwest::Response,
    expected_success_key: &str,
    endpoint_name: &str,
) {
    let status = resp.status().as_u16();
    if status == 200 {
        let body: serde_json::Value = resp.json().await.expect("Failed to parse JSON body");
        assert!(
            body.get(expected_success_key).is_some(),
            "Expected '{}' key in {} success response",
            expected_success_key,
            endpoint_name
        );
    } else if status == 401 {
        let body: serde_json::Value = resp.json().await.expect("Failed to parse JSON body");
        assert_eq!(
            body.get("error").and_then(|v| v.as_str()),
            Some("Authentication required"),
            "{} unauthorized response should include auth error",
            endpoint_name
        );
        assert!(
            body.get("methods").is_some(),
            "{} unauthorized response should include auth methods",
            endpoint_name
        );
    } else {
        panic!("{} should return 200 or 401, got {}", endpoint_name, status);
    }
}

mod api_tests {
    use super::*;

    /// Test health endpoint contract (healthy or degraded).
    #[tokio::test]
    async fn test_health_endpoint() {
        if !ensure_api_running("test_health_endpoint").await {
            return;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}:{}/health", PROXY_HOST, API_PORT))
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .expect("Failed to send request");

        let status = resp.status();
        assert!(
            status.as_u16() == 200 || status.as_u16() == 503,
            "Health endpoint should return 200 or 503, got {}",
            status
        );

        let body: serde_json::Value = resp.json().await.expect("Failed to parse JSON");
        let reported_status = body.get("status").and_then(|v| v.as_str());
        if status.as_u16() == 200 {
            assert_eq!(
                reported_status,
                Some("ok"),
                "200 health response should report status=ok"
            );
        } else {
            assert_eq!(
                reported_status,
                Some("degraded"),
                "503 health response should report status=degraded"
            );
        }

        assert_eq!(
            body.get("service").and_then(|v| v.as_str()),
            Some("ironveil"),
            "Health response should report service name"
        );
        assert!(
            body.get("upstream").is_some(),
            "Health response should include upstream details"
        );
    }

    /// Test metrics endpoint returns Prometheus format (when available)
    #[tokio::test]
    async fn test_metrics_endpoint() {
        if !ensure_api_running("test_metrics_endpoint").await {
            return;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}:{}/metrics", PROXY_HOST, API_PORT))
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .expect("Failed to send request");

        // Metrics endpoint should return data (200) or service unavailable (503) if disabled.
        let status = resp.status().as_u16();
        assert!(
            status == 200 || status == 503,
            "Metrics endpoint should return 200 or 503, got: {}",
            status
        );

        if status == 200 {
            let body = resp.text().await.expect("Failed to get response text");
            // Prometheus metrics should contain HELP or TYPE comments or be empty
            assert!(
                body.contains("ironveil_") || body.contains("# ") || body.is_empty(),
                "Metrics should contain ironveil_ prefix, Prometheus comments, or be empty"
            );
        } else {
            let body = resp.text().await.expect("Failed to get response text");
            assert!(
                body.contains("Metrics not enabled"),
                "503 response should indicate metrics are disabled"
            );
        }
    }

    /// Test rules endpoint - verifies it responds (auth behavior depends on config)
    #[tokio::test]
    async fn test_rules_endpoint_responds() {
        if !ensure_api_running("test_rules_endpoint_responds").await {
            return;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}:{}/rules", PROXY_HOST, API_PORT))
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .expect("Failed to send request");

        assert_protected_json_response(resp, "rules", "/rules").await;
    }

    /// Test rules endpoint with API key
    #[tokio::test]
    async fn test_rules_with_api_key() {
        if !ensure_api_running("test_rules_with_api_key").await {
            return;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}:{}/rules", PROXY_HOST, API_PORT))
            .header("X-API-Key", "test-api-key-12345")
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .expect("Failed to send request");

        assert_protected_json_response(resp, "rules", "/rules (api key)").await;
    }

    /// Test config endpoint
    #[tokio::test]
    async fn test_config_endpoint() {
        if !ensure_api_running("test_config_endpoint").await {
            return;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}:{}/config", PROXY_HOST, API_PORT))
            .header("X-API-Key", "test-api-key-12345")
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .expect("Failed to send request");

        assert_protected_json_response(resp, "masking_enabled", "/config").await;
    }

    /// Test connections endpoint
    #[tokio::test]
    async fn test_connections_endpoint() {
        if !ensure_api_running("test_connections_endpoint").await {
            return;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}:{}/connections", PROXY_HOST, API_PORT))
            .header("X-API-Key", "test-api-key-12345")
            .timeout(CONNECTION_TIMEOUT)
            .send()
            .await
            .expect("Failed to send request");

        assert_protected_json_response(resp, "active_connections", "/connections").await;
    }
}

mod postgres_tests {
    use super::*;

    /// PostgreSQL startup message
    fn build_startup_message(user: &str, database: &str) -> Vec<u8> {
        let mut params = Vec::new();
        params.extend_from_slice(b"user\0");
        params.extend_from_slice(user.as_bytes());
        params.push(0);
        params.extend_from_slice(b"database\0");
        params.extend_from_slice(database.as_bytes());
        params.push(0);
        params.push(0); // Null terminator for params

        let length = 4 + 4 + params.len(); // length field + version + params
        let mut msg = Vec::new();
        msg.extend_from_slice(&(length as u32).to_be_bytes());
        msg.extend_from_slice(&0x00030000u32.to_be_bytes()); // Protocol version 3.0
        msg.extend_from_slice(&params);
        msg
    }

    /// Test basic PostgreSQL proxy connection
    #[tokio::test]
    async fn test_postgres_connection() {
        if !ensure_proxy_running("test_postgres_connection").await {
            return;
        }

        // Past this point the proxy answered a TCP connect, so a failure is
        // a real defect: fail rather than skip.
        let mut stream = timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, PROXY_PORT)),
        )
        .await
        .expect("connection to a live proxy timed out")
        .expect("connection to a live proxy failed");

        // Send startup message
        let startup = build_startup_message("postgres", "postgres");
        stream
            .write_all(&startup)
            .await
            .expect("failed to send startup message");

        // Read response (should get authentication request or error)
        let mut buf = [0u8; 1024];
        let n = timeout(CONNECTION_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("read from a live proxy timed out")
            .expect("read from a live proxy failed");
        assert!(n > 0, "proxy closed the connection without responding");

        let msg_type = buf[0] as char;
        assert!(
            msg_type == 'R' || msg_type == 'E' || msg_type == 'S',
            "Should receive Authentication (R), Error (E), or SSL (S) response, got: {}",
            msg_type
        );
    }

    /// Test SSL request handling
    #[tokio::test]
    async fn test_postgres_ssl_request() {
        if !ensure_proxy_running("test_postgres_ssl_request").await {
            return;
        }

        let mut stream = timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, PROXY_PORT)),
        )
        .await
        .expect("connection to a live proxy timed out")
        .expect("connection to a live proxy failed");

        // Send SSL request (8 bytes: length 8 + SSL code 80877103)
        let ssl_request = [
            0x00, 0x00, 0x00, 0x08, // Length: 8
            0x04, 0xd2, 0x16, 0x2f, // SSL request code: 80877103
        ];

        stream
            .write_all(&ssl_request)
            .await
            .expect("failed to send SSL request");

        // Read response (should be 'S' for SSL supported or 'N' for not supported)
        let mut buf = [0u8; 1];
        let n = timeout(CONNECTION_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("SSL response timed out")
            .expect("failed to read SSL response");
        assert_eq!(n, 1, "expected a one-byte SSL response");

        let response = buf[0] as char;
        assert!(
            response == 'S' || response == 'N',
            "SSL response should be 'S' or 'N', got: {}",
            response
        );
    }

    /// Test connection rejection when upstream is unavailable
    #[tokio::test]
    async fn test_postgres_upstream_unavailable() {
        // This test connects to a port where no upstream is available
        // The proxy should handle this gracefully

        let mut stream = match timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, PROXY_PORT)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return, // Proxy not running, skip test
        };

        // Send startup message
        let startup = build_startup_message("postgres", "postgres");
        if stream.write_all(&startup).await.is_err() {
            return;
        }

        // Read response - might be error if upstream is down
        let mut buf = [0u8; 1024];
        match timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                // Got a response, proxy is handling the connection
                // Could be auth request (upstream available) or error (upstream down)
                println!("Received {} bytes response", n);
            }
            _ => {
                // Connection closed or timeout - also valid behavior
                println!("Connection closed or timed out");
            }
        }
    }
}

mod mysql_tests {
    use super::*;

    const MYSQL_PROXY_PORT: u16 = 3307; // Default MySQL proxy port

    async fn is_mysql_proxy_running() -> bool {
        matches!(
            timeout(
                CONNECTION_TIMEOUT,
                TcpStream::connect(format!("{}:{}", PROXY_HOST, MYSQL_PROXY_PORT)),
            )
            .await,
            Ok(Ok(_))
        )
    }

    /// Test MySQL proxy connection (if MySQL mode is running)
    #[tokio::test]
    async fn test_mysql_connection() {
        if !is_mysql_proxy_running().await {
            if should_require_services() {
                panic!(
                    "test_mysql_connection: MySQL proxy not running on port {}. Start required services before running integration tests.",
                    MYSQL_PROXY_PORT
                );
            }
            eprintln!(
                "Skipping test: MySQL proxy not running on port {}",
                MYSQL_PROXY_PORT
            );
            return;
        }

        let mut stream = timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, MYSQL_PROXY_PORT)),
        )
        .await
        .expect("connection to a live MySQL proxy timed out")
        .expect("connection to a live MySQL proxy failed");

        // MySQL server should send initial handshake packet
        let mut buf = [0u8; 1024];
        let n = timeout(CONNECTION_TIMEOUT, stream.read(&mut buf))
            .await
            .expect("MySQL handshake read timed out")
            .expect("MySQL handshake read failed");
        assert!(
            n >= 5,
            "MySQL handshake should be at least 5 bytes, got {n}"
        );

        // MySQL packet header: 3 bytes length + 1 byte sequence
        let length = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16);
        assert!(length > 0, "MySQL handshake packet should have content");
        assert_eq!(buf[3], 0, "Initial handshake should have sequence 0");
        assert_eq!(
            buf[4], 10,
            "MySQL protocol version should be 10, got: {}",
            buf[4]
        );
    }
}

// The previous `masking_tests` and `protocol_tests` modules asserted against
// inline regexes and hand-rolled byte arithmetic that had already drifted from
// production (their credit-card test accepted a 15-digit Amex the shipped
// scanner rejected). They are replaced here with tests that drive the real
// scanner and codecs through the library crate.
mod scanner_tests {
    use iron_veil::scanner::{PiiScanner, PiiType};

    #[test]
    fn test_real_scanner_detects_expected_types() {
        let scanner = PiiScanner::shared();

        assert_eq!(scanner.scan("test@example.com"), Some(PiiType::Email));
        assert_eq!(scanner.scan("123-45-6789"), Some(PiiType::Ssn));
        assert_eq!(scanner.scan("+1-555-123-4567"), Some(PiiType::Phone));
        assert_eq!(scanner.scan("192.168.1.1"), Some(PiiType::IpAddress));
        assert_eq!(scanner.scan("1990-01-15"), Some(PiiType::DateOfBirth));
        // Luhn-valid Visa and Amex
        assert_eq!(scanner.scan("4532015112830366"), Some(PiiType::CreditCard));
        assert_eq!(scanner.scan("378282246310005"), Some(PiiType::CreditCard));

        // Non-PII must survive untouched
        assert_eq!(scanner.scan("not-an-email"), None);
        assert_eq!(scanner.scan("John Doe"), None);
        // A Luhn-failing 16-digit identifier is an order number, not a card
        assert_eq!(scanner.scan("1234567890123456"), None);
    }
}

mod codec_tests {
    use bytes::BytesMut;
    use iron_veil::protocol::mysql::{MySqlCodec, MySqlMessage};
    use iron_veil::protocol::postgres::{PgMessage, PostgresCodec};
    use tokio_util::codec::Decoder;

    #[test]
    fn test_postgres_codec_decodes_a_real_query() {
        let payload = b"SELECT 1\0";
        let mut src = BytesMut::new();
        src.extend_from_slice(b"Q");
        src.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
        src.extend_from_slice(payload);

        let mut codec = PostgresCodec::new_upstream();
        let msg = codec.decode(&mut src).unwrap().unwrap();
        match msg {
            PgMessage::Query(q) => assert_eq!(&q.query[..], b"SELECT 1"),
            other => panic!("expected Query, got {:?}", other),
        }
    }

    #[test]
    fn test_postgres_codec_rejects_an_oversized_frame() {
        // Four bytes of 0xFF used to force a ~4 GiB reservation pre-auth.
        let mut src = BytesMut::new();
        src.extend_from_slice(b"Q");
        src.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut codec = PostgresCodec::new_upstream();
        assert!(codec.decode(&mut src).is_err());
    }

    #[test]
    fn test_mysql_codec_decodes_a_real_com_query() {
        let mut payload = vec![0x03];
        payload.extend_from_slice(b"SELECT email FROM users");
        let mut src = BytesMut::new();
        src.extend_from_slice(&[
            (payload.len() & 0xff) as u8,
            ((payload.len() >> 8) & 0xff) as u8,
            ((payload.len() >> 16) & 0xff) as u8,
            0,
        ]);
        src.extend_from_slice(&payload);

        let mut codec = MySqlCodec::new_server_awaiting_command();
        let msg = codec.decode(&mut src).unwrap().unwrap();
        match msg {
            MySqlMessage::Query(q) => assert_eq!(&q.query[..], b"SELECT email FROM users"),
            other => panic!("expected Query, got {:?}", other),
        }
    }
}
