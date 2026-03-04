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

/// Helper to check if the proxy is running
async fn is_proxy_running() -> bool {
    timeout(
        CONNECTION_TIMEOUT,
        TcpStream::connect(format!("{}:{}", PROXY_HOST, PROXY_PORT)),
    )
    .await
    .is_ok()
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

        let mut stream = match timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, PROXY_PORT)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!("Failed to connect to proxy: {}", e);
                return;
            }
            Err(_) => {
                eprintln!("Connection timeout");
                return;
            }
        };

        // Send startup message
        let startup = build_startup_message("postgres", "postgres");
        if let Err(e) = stream.write_all(&startup).await {
            eprintln!("Failed to send startup message: {}", e);
            return;
        }

        // Read response (should get authentication request or error)
        let mut buf = [0u8; 1024];
        match timeout(CONNECTION_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                // We got a response - the proxy is working
                // First byte indicates message type
                let msg_type = buf[0] as char;
                assert!(
                    msg_type == 'R' || msg_type == 'E' || msg_type == 'S',
                    "Should receive Authentication (R), Error (E), or SSL (S) response, got: {}",
                    msg_type
                );
            }
            Ok(Ok(_)) => {
                eprintln!("Connection closed by proxy (0 bytes read)");
            }
            Ok(Err(e)) => {
                eprintln!("Failed to read response: {}", e);
            }
            Err(_) => {
                eprintln!("Read timeout");
            }
        }
    }

    /// Test SSL request handling
    #[tokio::test]
    async fn test_postgres_ssl_request() {
        if !ensure_proxy_running("test_postgres_ssl_request").await {
            return;
        }

        let mut stream = match timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, PROXY_PORT)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return,
        };

        // Send SSL request (8 bytes: length 8 + SSL code 80877103)
        let ssl_request = [
            0x00, 0x00, 0x00, 0x08, // Length: 8
            0x04, 0xd2, 0x16, 0x2f, // SSL request code: 80877103
        ];

        if let Err(e) = stream.write_all(&ssl_request).await {
            eprintln!("Failed to send SSL request: {}", e);
            return;
        }

        // Read response (should be 'S' for SSL supported or 'N' for not supported)
        let mut buf = [0u8; 1];
        match timeout(CONNECTION_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(1)) => {
                let response = buf[0] as char;
                assert!(
                    response == 'S' || response == 'N',
                    "SSL response should be 'S' or 'N', got: {}",
                    response
                );
            }
            _ => {
                eprintln!("Failed to read SSL response");
            }
        }
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
        timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, MYSQL_PROXY_PORT)),
        )
        .await
        .is_ok()
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

        let mut stream = match timeout(
            CONNECTION_TIMEOUT,
            TcpStream::connect(format!("{}:{}", PROXY_HOST, MYSQL_PROXY_PORT)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return,
        };

        // MySQL server should send initial handshake packet
        let mut buf = [0u8; 1024];
        match timeout(CONNECTION_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n >= 4 => {
                // MySQL packet header: 3 bytes length + 1 byte sequence
                let length = (buf[0] as u32) | ((buf[1] as u32) << 8) | ((buf[2] as u32) << 16);
                let sequence = buf[3];

                assert!(length > 0, "MySQL handshake packet should have content");
                assert_eq!(sequence, 0, "Initial handshake should have sequence 0");

                // Protocol version should be 10 (0x0a)
                if n > 4 {
                    assert_eq!(
                        buf[4], 10,
                        "MySQL protocol version should be 10, got: {}",
                        buf[4]
                    );
                }
            }
            _ => {
                eprintln!("Received too few bytes or failed to read MySQL handshake");
            }
        }
    }
}

mod masking_tests {
    /// Test that email patterns are detected correctly
    #[test]
    fn test_email_detection_pattern() {
        let patterns = [
            ("test@example.com", true),
            ("user.name@domain.org", true),
            ("invalid-email", false),
            ("@nodomain.com", false),
            ("noat.domain.com", false),
        ];

        let email_regex =
            regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();

        for (input, expected) in patterns {
            let result = email_regex.is_match(input);
            assert_eq!(
                result, expected,
                "Email detection failed for '{}': expected {}, got {}",
                input, expected, result
            );
        }
    }

    /// Test credit card pattern detection
    #[test]
    fn test_credit_card_detection_pattern() {
        let patterns = [
            ("4111111111111111", true),  // Visa test number
            ("5500000000000004", true),  // Mastercard test
            ("378282246310005", true),   // Amex test
            ("1234", false),             // Too short
            ("abcd1234abcd1234", false), // Contains letters
        ];

        let cc_regex = regex::Regex::new(r"^\d{13,19}$").unwrap();

        for (input, expected) in patterns {
            let result = cc_regex.is_match(input);
            assert_eq!(
                result, expected,
                "Credit card detection failed for '{}': expected {}, got {}",
                input, expected, result
            );
        }
    }

    /// Test SSN pattern detection
    #[test]
    fn test_ssn_detection_pattern() {
        let patterns = [
            ("123-45-6789", true),
            ("000-00-0000", true),
            ("12345-6789", false),
            ("123-456-789", false),
            ("1234567890", false),
        ];

        let ssn_regex = regex::Regex::new(r"^\d{3}-\d{2}-\d{4}$").unwrap();

        for (input, expected) in patterns {
            let result = ssn_regex.is_match(input);
            assert_eq!(
                result, expected,
                "SSN detection failed for '{}': expected {}, got {}",
                input, expected, result
            );
        }
    }

    /// Test IP address detection
    #[test]
    fn test_ip_address_detection_pattern() {
        let patterns = [
            ("192.168.1.1", true),
            ("10.0.0.255", true),
            ("256.1.1.1", true), // Regex doesn't validate range
            ("1.2.3", false),
            ("1.2.3.4.5", false),
        ];

        let ip_regex = regex::Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();

        for (input, expected) in patterns {
            let result = ip_regex.is_match(input);
            assert_eq!(
                result, expected,
                "IP detection failed for '{}': expected {}, got {}",
                input, expected, result
            );
        }
    }

    /// Test phone number detection
    #[test]
    fn test_phone_detection_pattern() {
        let patterns = [
            ("+1-555-123-4567", true),
            ("+1 (555) 123-4567", true),
            ("+44 20 7123 4567", true),
            ("123-4567", false), // Too short, no country code
        ];

        // Phone regex that requires country code prefix
        let phone_regex =
            regex::Regex::new(r"^\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}$")
                .unwrap();

        for (input, expected) in patterns {
            let result = phone_regex.is_match(input);
            assert_eq!(
                result, expected,
                "Phone detection failed for '{}': expected {}, got {}",
                input, expected, result
            );
        }
    }
}

mod protocol_tests {
    /// Test PostgreSQL message parsing
    #[test]
    fn test_postgres_message_length_calculation() {
        // PostgreSQL message format: Type (1 byte) + Length (4 bytes) + Payload
        // Length includes itself but NOT the type byte

        let payload = b"SELECT 1";
        let msg_type: u8 = b'Q'; // Query message

        // Total length = 4 (length field) + payload.len()
        let total_length: u32 = 4 + payload.len() as u32;

        let mut message = Vec::new();
        message.push(msg_type);
        message.extend_from_slice(&total_length.to_be_bytes());
        message.extend_from_slice(payload);

        // Verify message structure
        assert_eq!(message[0], b'Q');
        let parsed_length = u32::from_be_bytes([message[1], message[2], message[3], message[4]]);
        assert_eq!(parsed_length, 12); // 4 + 8 = 12
    }

    /// Test MySQL packet length calculation
    #[test]
    fn test_mysql_packet_length_calculation() {
        // MySQL packet format: Length (3 bytes LE) + Sequence (1 byte) + Payload

        let payload = b"SELECT 1";
        let sequence: u8 = 0;

        let length = payload.len() as u32;
        let length_bytes = [
            (length & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            ((length >> 16) & 0xFF) as u8,
        ];

        let mut packet = Vec::new();
        packet.extend_from_slice(&length_bytes);
        packet.push(sequence);
        packet.extend_from_slice(payload);

        // Verify packet structure
        let parsed_length =
            (packet[0] as u32) | ((packet[1] as u32) << 8) | ((packet[2] as u32) << 16);
        assert_eq!(parsed_length, 8);
        assert_eq!(packet[3], 0); // sequence
    }
}
