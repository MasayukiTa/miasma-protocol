/// HTTP bridge rate limiting and abuse resistance.
///
/// Provides:
/// - Token-bucket rate limiter per endpoint class
/// - Origin/Referer validation for cross-origin abuse prevention
/// - Request validation (size, field constraints)
use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

// ─── Token bucket rate limiter ──────────────────────────────────────────────

/// A token-bucket rate limiter.
///
/// Tokens are added at a fixed rate up to a maximum burst size.
/// Each request consumes one token. If no tokens are available,
/// the request is rejected.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Maximum tokens (burst size).
    capacity: u32,
    /// Current token count.
    tokens: f64,
    /// Tokens added per second.
    rate: f64,
    /// Last time tokens were replenished.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// - `capacity`: maximum burst size (also the initial token count)
    /// - `rate_per_sec`: tokens added per second
    pub fn new(capacity: u32, rate_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            rate: rate_per_sec,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate-limited.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Current number of available tokens.
    pub fn available(&mut self) -> u32 {
        self.refill();
        self.tokens as u32
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity as f64);
        self.last_refill = now;
    }
}

// ─── Rate limiter registry ──────────────────────────────────────────────────

/// Rate limit class — different endpoint groups get different limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RateLimitClass {
    /// Read-only API calls (status, ping, inbox, outbox).
    ReadApi,
    /// Write/mutation API calls (publish, send, confirm, revoke).
    WriteApi,
    /// Heavyweight operations (retrieve, wipe).
    HeavyApi,
}

/// Default rate limits per class (requests per minute).
impl RateLimitClass {
    pub fn default_rpm(self) -> u32 {
        match self {
            Self::ReadApi => 120,   // 2/sec
            Self::WriteApi => 30,   // 0.5/sec
            Self::HeavyApi => 10,   // ~1 per 6 sec
        }
    }
}

/// Manages rate limits across endpoint classes.
#[derive(Debug)]
pub struct RateLimiter {
    buckets: HashMap<RateLimitClass, TokenBucket>,
    /// Total requests rejected since startup.
    pub rejections: u64,
}

impl Default for RateLimiter {
    fn default() -> Self {
        let mut buckets = HashMap::new();
        for class in [
            RateLimitClass::ReadApi,
            RateLimitClass::WriteApi,
            RateLimitClass::HeavyApi,
        ] {
            let rpm = class.default_rpm();
            buckets.insert(
                class,
                TokenBucket::new(rpm, rpm as f64 / 60.0),
            );
        }
        Self {
            buckets,
            rejections: 0,
        }
    }
}

impl RateLimiter {
    /// Check if a request of the given class is allowed.
    pub fn check(&mut self, class: RateLimitClass) -> bool {
        if let Some(bucket) = self.buckets.get_mut(&class) {
            if bucket.try_consume() {
                true
            } else {
                self.rejections += 1;
                false
            }
        } else {
            true // Unknown class → allow
        }
    }

    /// Get available tokens for a class.
    pub fn available(&mut self, class: RateLimitClass) -> u32 {
        self.buckets
            .get_mut(&class)
            .map(|b| b.available())
            .unwrap_or(0)
    }
}

// ─── Origin validation ──────────────────────────────────────────────────────

/// Allowed localhost origins for the HTTP bridge.
const ALLOWED_ORIGINS: &[&str] = &[
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
    "https://localhost",
    "https://127.0.0.1",
    "https://[::1]",
    "null", // file:// and some WebView origins
];

/// Validate that an Origin header is from localhost.
///
/// Returns true if:
/// - No Origin header present (non-browser client, always OK)
/// - Origin is a known localhost variant
/// - Origin starts with an allowed prefix
pub fn validate_origin(origin: Option<&str>) -> bool {
    match origin {
        None => true, // No Origin → non-browser client, OK
        Some(o) => {
            let normalized = o.trim().to_lowercase();
            ALLOWED_ORIGINS.iter().any(|allowed| {
                normalized == *allowed || normalized.starts_with(&format!("{allowed}:"))
            })
        }
    }
}

/// Classify an HTTP path into its rate limit class.
pub fn classify_endpoint(method: &str, path: &str) -> RateLimitClass {
    match (method, path) {
        // Read-only
        ("GET", "/api/ping")
        | ("GET", "/api/status")
        | ("GET", "/api/sharing-key")
        | ("GET", "/api/directed/inbox")
        | ("GET", "/api/directed/outbox") => RateLimitClass::ReadApi,

        // Heavyweight
        ("POST", "/api/retrieve")
        | ("POST", "/api/directed/retrieve")
        | ("POST", "/api/wipe") => RateLimitClass::HeavyApi,

        // All other POST endpoints are write operations
        _ => RateLimitClass::WriteApi,
    }
}

// ─── Request validation ─────────────────────────────────────────────────────

/// Maximum allowed lengths for various string fields in API requests.
pub const MAX_CONTACT_LEN: usize = 256;
pub const MAX_PASSWORD_LEN: usize = 1024;
pub const MAX_FILENAME_LEN: usize = 512;
pub const MAX_MID_LEN: usize = 128;
pub const MAX_ENVELOPE_ID_LEN: usize = 128;
pub const MAX_CHALLENGE_LEN: usize = 32;

/// Validate a string field against a maximum length.
pub fn validate_field_length(field_name: &str, value: &str, max: usize) -> Result<(), String> {
    if value.len() > max {
        Err(format!(
            "{field_name} too long: {} bytes (max {max})",
            value.len()
        ))
    } else {
        Ok(())
    }
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

/// Rate limiter status for diagnostics export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatus {
    pub total_rejections: u64,
    pub read_api_available: u32,
    pub write_api_available: u32,
    pub heavy_api_available: u32,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── TokenBucket ─────────────────────────────────────────────────────

    #[test]
    fn bucket_allows_burst() {
        let mut b = TokenBucket::new(5, 1.0);
        for _ in 0..5 {
            assert!(b.try_consume());
        }
        // 6th should fail (burst exhausted)
        assert!(!b.try_consume());
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = TokenBucket::new(5, 100.0); // 100/sec for fast test
        // Exhaust all tokens
        for _ in 0..5 {
            b.try_consume();
        }
        assert!(!b.try_consume());
        // Wait for refill
        std::thread::sleep(Duration::from_millis(60));
        assert!(b.try_consume());
    }

    #[test]
    fn bucket_doesnt_exceed_capacity() {
        let mut b = TokenBucket::new(3, 100.0);
        std::thread::sleep(Duration::from_millis(100)); // Would add ~10 tokens
        assert_eq!(b.available(), 3); // Capped at capacity
    }

    // ── RateLimiter ─────────────────────────────────────────────────────

    #[test]
    fn rate_limiter_default() {
        let mut rl = RateLimiter::default();
        // Should allow a burst of requests
        for _ in 0..10 {
            assert!(rl.check(RateLimitClass::ReadApi));
        }
        assert_eq!(rl.rejections, 0);
    }

    #[test]
    fn rate_limiter_rejects_excess() {
        let mut rl = RateLimiter::default();
        // HeavyApi allows 10 burst. Exhaust them.
        for _ in 0..10 {
            rl.check(RateLimitClass::HeavyApi);
        }
        // 11th should be rejected
        assert!(!rl.check(RateLimitClass::HeavyApi));
        assert_eq!(rl.rejections, 1);
    }

    // ── Origin validation ───────────────────────────────────────────────

    #[test]
    fn origin_none_allowed() {
        assert!(validate_origin(None));
    }

    #[test]
    fn origin_localhost_allowed() {
        assert!(validate_origin(Some("http://localhost")));
        assert!(validate_origin(Some("http://localhost:17842")));
        assert!(validate_origin(Some("http://127.0.0.1")));
        assert!(validate_origin(Some("http://127.0.0.1:17842")));
        assert!(validate_origin(Some("https://localhost")));
        assert!(validate_origin(Some("http://[::1]")));
        assert!(validate_origin(Some("null"))); // file:// origins
    }

    #[test]
    fn origin_external_rejected() {
        assert!(!validate_origin(Some("http://evil.com")));
        assert!(!validate_origin(Some("https://attacker.local")));
        assert!(!validate_origin(Some("http://192.168.1.100")));
    }

    #[test]
    fn origin_case_insensitive() {
        assert!(validate_origin(Some("HTTP://LOCALHOST")));
        assert!(validate_origin(Some("Http://127.0.0.1:8080")));
    }

    // ── Endpoint classification ─────────────────────────────────────────

    #[test]
    fn classify_read_endpoints() {
        assert_eq!(classify_endpoint("GET", "/api/ping"), RateLimitClass::ReadApi);
        assert_eq!(classify_endpoint("GET", "/api/status"), RateLimitClass::ReadApi);
        assert_eq!(
            classify_endpoint("GET", "/api/directed/inbox"),
            RateLimitClass::ReadApi
        );
    }

    #[test]
    fn classify_heavy_endpoints() {
        assert_eq!(
            classify_endpoint("POST", "/api/retrieve"),
            RateLimitClass::HeavyApi
        );
        assert_eq!(classify_endpoint("POST", "/api/wipe"), RateLimitClass::HeavyApi);
    }

    #[test]
    fn classify_write_endpoints() {
        assert_eq!(
            classify_endpoint("POST", "/api/publish"),
            RateLimitClass::WriteApi
        );
        assert_eq!(
            classify_endpoint("POST", "/api/directed/send"),
            RateLimitClass::WriteApi
        );
    }

    // ── Field validation ────────────────────────────────────────────────

    #[test]
    fn field_length_ok() {
        assert!(validate_field_length("test", "hello", 10).is_ok());
    }

    #[test]
    fn field_length_exceeded() {
        let result = validate_field_length("password", &"x".repeat(2000), 1024);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too long"));
    }

    // ── RateLimitStatus serialization ───────────────────────────────────

    #[test]
    fn status_serialization() {
        let status = RateLimitStatus {
            total_rejections: 42,
            read_api_available: 100,
            write_api_available: 25,
            heavy_api_available: 8,
        };
        let json = serde_json::to_string(&status).unwrap();
        let de: RateLimitStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(de.total_rejections, 42);
    }

    use std::time::Duration;
}
