//! MySQL authentication, for the mode where iron-veil terminates it.
//!
//! In the default *passthrough* mode the proxy is credential-transparent: the
//! client's own MySQL credentials cross it untouched, so whatever process is
//! exposed to the network necessarily holds the real database password.
//!
//! In *terminate* mode the proxy holds the upstream credential itself and
//! authenticates its clients against a separately-configured local one. That
//! restores the process-boundary property the sidecar deployment depends on:
//! the exposed door process only ever learns a throwaway credential that is
//! good for nothing but the loopback hop into the proxy.
//!
//! ## Why the client leg never needs full authentication
//!
//! MySQL's `caching_sha2_password` requires a full-auth round trip (cleartext
//! over TLS, or an RSA-encrypted password) the first time an account connects,
//! and only then can it answer later connections from its in-memory cache.
//! That is a property of *MySQL's storage*, not of the protocol: `mysql.user`
//! holds a salted, multi-round SHA256-crypt digest, which is not the value the
//! fast-auth check needs. The cache holds `SHA256(SHA256(password))`, which is.
//!
//! iron-veil is configured with the cleartext client password, so it can derive
//! `SHA256(SHA256(password))` at startup and satisfy fast auth on the very
//! first connection. The client leg therefore never enters full auth, needs no
//! RSA key pair, and works with or without client TLS.
//!
//! The upstream leg is an ordinary MySQL client and does hit full auth when the
//! server has not cached the credential; there the password goes out as
//! cleartext, which MySQL only permits over a secure channel — hence the
//! requirement that `upstream_tls` be on for that path.

use anyhow::Result;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Length of the auth-plugin nonce ("scramble") MySQL exchanges. Fixed by the
/// protocol at 20 bytes for both plugins implemented here.
pub const NONCE_LEN: usize = 20;

/// The client-facing authentication plugins iron-veil can serve, and the
/// upstream-facing ones it can satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPlugin {
    /// MySQL 8's default. Preferred: every current client speaks it.
    CachingSha2Password,
    /// Legacy SHA1-based plugin, removed from the MySQL 8.4 *server* but still
    /// implemented by most clients. Offered so an old client can still reach
    /// the proxy even though the upstream no longer accepts it.
    MysqlNativePassword,
}

impl AuthPlugin {
    pub fn name(self) -> &'static str {
        match self {
            Self::CachingSha2Password => "caching_sha2_password",
            Self::MysqlNativePassword => "mysql_native_password",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "caching_sha2_password" => Some(Self::CachingSha2Password),
            "mysql_native_password" => Some(Self::MysqlNativePassword),
            _ => None,
        }
    }

    /// Length of a well-formed scramble for this plugin.
    fn scramble_len(self) -> usize {
        match self {
            Self::CachingSha2Password => 32,
            Self::MysqlNativePassword => 20,
        }
    }
}

/// Compare two byte strings without leaking where they diverge.
///
/// The comparisons here are over digests rather than secrets, so a timing
/// oracle would be of limited use, but an auth check is exactly the place not
/// to rely on that reasoning.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

/// Produce the scramble a *client* sends for `plugin`.
///
/// caching_sha2_password:
///   `XOR( SHA256(pw), SHA256( SHA256(SHA256(pw)) || nonce ) )`
/// mysql_native_password:
///   `XOR( SHA1(pw), SHA1( nonce || SHA1(SHA1(pw)) ) )`
///
/// An empty password is always an empty response, for both plugins.
pub fn scramble(plugin: AuthPlugin, password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    match plugin {
        AuthPlugin::CachingSha2Password => {
            let stage1 = sha256(&[password.as_bytes()]);
            let stage2 = sha256(&[&stage1]);
            let token = sha256(&[&stage2, nonce]);
            xor(&stage1, &token)
        }
        AuthPlugin::MysqlNativePassword => {
            let stage1 = sha1(&[password.as_bytes()]);
            let stage2 = sha1(&[&stage1]);
            let token = sha1(&[nonce, &stage2]);
            xor(&stage1, &token)
        }
    }
}

/// Verify a client's scramble as a *server* would, from the cleartext password.
///
/// This is the inverse of `scramble`: recover the first-stage digest by XORing
/// the token back out, then check that hashing it once more reproduces the
/// stored second-stage digest.
pub fn verify_scramble(plugin: AuthPlugin, password: &str, nonce: &[u8], response: &[u8]) -> bool {
    if password.is_empty() {
        // An account with no password accepts only an empty response —
        // never treat "client sent nothing" as a pass for a real password.
        return response.is_empty();
    }
    if response.len() != plugin.scramble_len() {
        return false;
    }
    match plugin {
        AuthPlugin::CachingSha2Password => {
            let stage2 = sha256(&[&sha256(&[password.as_bytes()])]);
            let token = sha256(&[&stage2, nonce]);
            let stage1 = xor(response, &token);
            constant_time_eq(&sha256(&[&stage1]), &stage2)
        }
        AuthPlugin::MysqlNativePassword => {
            let stage2 = sha1(&[&sha1(&[password.as_bytes()])]);
            let token = sha1(&[nonce, &stage2]);
            let stage1 = xor(response, &token);
            constant_time_eq(&sha1(&[&stage1]), &stage2)
        }
    }
}

/// Generate a fresh 20-byte nonce.
///
/// Bytes are drawn from the printable ASCII range, as MySQL's own
/// `create_random_string` does. That is not cosmetic: the handshake encodes the
/// nonce as a NUL-terminated string, so an embedded zero byte silently
/// truncates it and both ends then hash different data.
pub fn generate_nonce() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..NONCE_LEN)
        .map(|_| rng.random_range(0x21..=0x7e))
        .collect()
}

/// Read a plugin's nonce out of a server handshake, trimming the trailing NUL
/// that MySQL appends to the second part.
pub fn nonce_from_handshake(part1: &[u8; 8], part2: &[u8]) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(NONCE_LEN);
    nonce.extend_from_slice(part1);
    nonce.extend_from_slice(part2);
    while nonce.last() == Some(&0) {
        nonce.pop();
    }
    nonce.truncate(NONCE_LEN);
    nonce
}

/// Parse an AuthSwitchRequest payload (`0xFE <plugin> NUL <nonce> [NUL]`).
pub fn parse_auth_switch_request(payload: &[u8]) -> Result<(String, Vec<u8>)> {
    if payload.first() != Some(&0xfe) {
        anyhow::bail!("not an AuthSwitchRequest packet");
    }
    let rest = &payload[1..];
    let nul = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow::anyhow!("AuthSwitchRequest has no plugin name terminator"))?;
    let plugin = String::from_utf8_lossy(&rest[..nul]).into_owned();
    let mut nonce = rest[nul + 1..].to_vec();
    while nonce.last() == Some(&0) {
        nonce.pop();
    }
    nonce.truncate(NONCE_LEN);
    Ok((plugin, nonce))
}

/// Build an AuthSwitchRequest payload asking the client to use `plugin`.
pub fn build_auth_switch_request(plugin: AuthPlugin, nonce: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + plugin.name().len() + 1 + nonce.len() + 1);
    payload.push(0xfe);
    payload.extend_from_slice(plugin.name().as_bytes());
    payload.push(0);
    payload.extend_from_slice(nonce);
    payload.push(0);
    payload
}

/// caching_sha2_password fast-auth-success AuthMoreData (`0x01 0x03`).
/// The server sends OK straight after, with no client reply in between.
pub fn build_fast_auth_success() -> Vec<u8> {
    vec![
        0x01,
        crate::protocol::mysql::AUTH_MORE_DATA_FAST_AUTH_SUCCESS,
    ]
}

/// The reply to a full-auth request on a secure channel: the password as a
/// NUL-terminated cleartext string. MySQL rejects this on an insecure
/// connection, which is why the upstream leg requires TLS to reach it.
pub fn build_cleartext_password(password: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(password.len() + 1);
    payload.extend_from_slice(password.as_bytes());
    payload.push(0);
    payload
}

/// What an AuthMoreData packet from the server is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMoreData {
    /// `0x03` — the cached fast path succeeded; OK follows with no reply.
    FastAuthSuccess,
    /// `0x04` — send the real password (cleartext over TLS, or RSA-encrypted).
    FullAuthRequired,
    /// Anything else the server may send mid-exchange.
    Other,
}

/// Classify an AuthMoreData payload (`0x01 <status> ...`).
pub fn classify_auth_more_data(payload: &[u8]) -> Option<AuthMoreData> {
    use crate::protocol::mysql::{
        AUTH_MORE_DATA_FAST_AUTH_SUCCESS, AUTH_MORE_DATA_FULL_AUTH_REQUIRED,
    };
    if payload.first() != Some(&0x01) {
        return None;
    }
    Some(match payload.get(1).copied() {
        Some(AUTH_MORE_DATA_FAST_AUTH_SUCCESS) => AuthMoreData::FastAuthSuccess,
        Some(AUTH_MORE_DATA_FULL_AUTH_REQUIRED) => AuthMoreData::FullAuthRequired,
        _ => AuthMoreData::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &[u8] = b"abcdefghijklmnopqrst";

    #[test]
    fn test_caching_sha2_roundtrip() {
        let plugin = AuthPlugin::CachingSha2Password;
        let response = scramble(plugin, "hunter2", NONCE);
        assert_eq!(response.len(), 32);
        assert!(verify_scramble(plugin, "hunter2", NONCE, &response));
    }

    #[test]
    fn test_native_roundtrip() {
        let plugin = AuthPlugin::MysqlNativePassword;
        let response = scramble(plugin, "hunter2", NONCE);
        assert_eq!(response.len(), 20);
        assert!(verify_scramble(plugin, "hunter2", NONCE, &response));
    }

    #[test]
    fn test_wrong_password_is_rejected() {
        for plugin in [
            AuthPlugin::CachingSha2Password,
            AuthPlugin::MysqlNativePassword,
        ] {
            let response = scramble(plugin, "hunter2", NONCE);
            assert!(
                !verify_scramble(plugin, "hunter3", NONCE, &response),
                "{plugin:?} accepted the wrong password"
            );
        }
    }

    #[test]
    fn test_scramble_is_bound_to_the_nonce() {
        // Replaying a scramble captured against a different nonce must fail,
        // otherwise a recorded handshake is a reusable credential.
        for plugin in [
            AuthPlugin::CachingSha2Password,
            AuthPlugin::MysqlNativePassword,
        ] {
            let response = scramble(plugin, "hunter2", NONCE);
            assert!(
                !verify_scramble(plugin, "hunter2", b"tsrqponmlkjihgfedcba", &response),
                "{plugin:?} accepted a scramble from another nonce"
            );
        }
    }

    #[test]
    fn test_empty_password_requires_empty_response() {
        for plugin in [
            AuthPlugin::CachingSha2Password,
            AuthPlugin::MysqlNativePassword,
        ] {
            assert!(scramble(plugin, "", NONCE).is_empty());
            assert!(verify_scramble(plugin, "", NONCE, &[]));
            // A client that sends nothing must not authenticate against a
            // real password.
            assert!(!verify_scramble(plugin, "hunter2", NONCE, &[]));
            // ...and a passworded response must not satisfy an empty account.
            let response = scramble(plugin, "hunter2", NONCE);
            assert!(!verify_scramble(plugin, "", NONCE, &response));
        }
    }

    #[test]
    fn test_malformed_response_lengths_are_rejected() {
        for plugin in [
            AuthPlugin::CachingSha2Password,
            AuthPlugin::MysqlNativePassword,
        ] {
            assert!(!verify_scramble(plugin, "hunter2", NONCE, &[0u8; 8]));
            assert!(!verify_scramble(plugin, "hunter2", NONCE, &[0u8; 64]));
        }
    }

    #[test]
    fn test_generate_nonce_has_no_zero_bytes() {
        // A zero byte would truncate the NUL-terminated handshake field and
        // silently desynchronise the two ends' hashes.
        for _ in 0..64 {
            let nonce = generate_nonce();
            assert_eq!(nonce.len(), NONCE_LEN);
            assert!(
                nonce.iter().all(|&b| b != 0),
                "nonce contained a NUL: {nonce:?}"
            );
        }
    }

    #[test]
    fn test_generate_nonce_is_not_constant() {
        assert_ne!(generate_nonce(), generate_nonce());
    }

    #[test]
    fn test_nonce_from_handshake_strips_the_trailing_nul() {
        let part1 = *b"12345678";
        let part2 = b"901234567890\0".to_vec();
        let nonce = nonce_from_handshake(&part1, &part2);
        assert_eq!(nonce.len(), NONCE_LEN);
        assert_eq!(&nonce, b"12345678901234567890");
    }

    #[test]
    fn test_auth_switch_request_roundtrip() {
        let payload = build_auth_switch_request(AuthPlugin::CachingSha2Password, NONCE);
        let (plugin, nonce) = parse_auth_switch_request(&payload).unwrap();
        assert_eq!(plugin, "caching_sha2_password");
        assert_eq!(nonce, NONCE);

        assert!(parse_auth_switch_request(b"\x00nope").is_err());
    }

    #[test]
    fn test_classify_auth_more_data() {
        assert_eq!(
            classify_auth_more_data(&[0x01, 0x03]),
            Some(AuthMoreData::FastAuthSuccess)
        );
        assert_eq!(
            classify_auth_more_data(&[0x01, 0x04]),
            Some(AuthMoreData::FullAuthRequired)
        );
        assert_eq!(
            classify_auth_more_data(&[0x01, 0x99]),
            Some(AuthMoreData::Other)
        );
        assert_eq!(classify_auth_more_data(&[0xfe]), None);
    }

    #[test]
    fn test_cleartext_password_is_nul_terminated() {
        assert_eq!(build_cleartext_password("pw"), b"pw\0");
        assert_eq!(build_cleartext_password(""), b"\0");
    }

    #[test]
    fn test_plugin_names_round_trip() {
        for plugin in [
            AuthPlugin::CachingSha2Password,
            AuthPlugin::MysqlNativePassword,
        ] {
            assert_eq!(AuthPlugin::from_name(plugin.name()), Some(plugin));
        }
        assert_eq!(AuthPlugin::from_name("sha256_password"), None);
    }
}
