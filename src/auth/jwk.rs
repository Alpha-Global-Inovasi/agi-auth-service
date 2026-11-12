//! JWK fetching and caching logic for Google's Firebase Auth public keys
//!
//! - Keys are cached for the `max-age` Google sends (1 hour if absent).
//! - Only one refresh runs at a time; concurrent callers wait for it and reuse the result.
//! - If Google cannot be reached, expired keys keep being served for up to [`MAX_STALE`].
//! - Fetch attempts are rate limited to one per [`MIN_FETCH_INTERVAL`], so tokens with an
//!   unknown `kid` cannot be used to hammer Google.

use crate::errors::{AuthError, AuthResult};
use jsonwebtoken::DecodingKey;
use reqwest::header::{CACHE_CONTROL, HeaderMap};
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

/// Google's public key endpoint for Firebase Auth
const GOOGLE_CERTS_URL: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

/// TTL used when Google's response carries no usable `Cache-Control: max-age`
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Minimum interval between fetch attempts
const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(60);

/// How long past their expiry cached keys may still be used while Google is unreachable
const MAX_STALE: Duration = Duration::from_secs(24 * 3600);

/// Timeout for the request to Google
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    /// Time of the last successful fetch
    fetched_at: Option<Instant>,
    /// Time of the last fetch attempt, successful or not
    last_attempt: Option<Instant>,
    ttl: Duration,
}

enum Lookup {
    Fresh(DecodingKey),
    Stale(DecodingKey),
    Missing,
}

impl KeyCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            fetched_at: None,
            last_attempt: None,
            ttl: DEFAULT_CACHE_TTL,
        }
    }

    fn age(&self, now: Instant) -> Option<Duration> {
        self.fetched_at.map(|t| now.saturating_duration_since(t))
    }

    fn is_fresh(&self, now: Instant) -> bool {
        self.age(now).is_some_and(|age| age < self.ttl)
    }

    fn attempted_recently(&self, now: Instant) -> bool {
        self.last_attempt
            .is_some_and(|t| now.saturating_duration_since(t) < MIN_FETCH_INTERVAL)
    }

    fn lookup(&self, kid: &str, now: Instant) -> Lookup {
        let (Some(key), Some(age)) = (self.keys.get(kid), self.age(now)) else {
            return Lookup::Missing;
        };
        if age < self.ttl {
            Lookup::Fresh(key.clone())
        } else if age < self.ttl + MAX_STALE {
            Lookup::Stale(key.clone())
        } else {
            Lookup::Missing
        }
    }

    /// Error for a `kid` that could not be resolved without fetching.
    ///
    /// With a fresh key set the `kid` is simply unknown (bad token); otherwise we
    /// cannot tell, because the key set itself is unavailable.
    fn missing_error(&self, kid: &str, now: Instant) -> AuthError {
        if self.is_fresh(now) {
            AuthError::KeyNotFound {
                kid: kid.to_string(),
            }
        } else {
            AuthError::JwkFetchError("Google public keys are unavailable".into())
        }
    }
}

static CACHE: LazyLock<RwLock<KeyCache>> = LazyLock::new(|| RwLock::new(KeyCache::new()));

/// Serializes refreshes so concurrent cache misses trigger a single fetch
static REFRESH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .expect("failed to build HTTP client")
});

fn read_cache() -> AuthResult<RwLockReadGuard<'static, KeyCache>> {
    CACHE
        .read()
        .map_err(|_| AuthError::ConfigError("JWK cache lock poisoned".into()))
}

fn write_cache() -> AuthResult<RwLockWriteGuard<'static, KeyCache>> {
    CACHE
        .write()
        .map_err(|_| AuthError::ConfigError("JWK cache lock poisoned".into()))
}

/// Get a decoding key for the given Key ID (kid)
///
/// Checks cache first, only fetches from Google if the key is not found or expired.
pub async fn get_decoding_key(kid: &str) -> AuthResult<DecodingKey> {
    if let Lookup::Fresh(key) = read_cache()?.lookup(kid, Instant::now()) {
        tracing::debug!("JWK cache hit for kid: {}", kid);
        return Ok(key);
    }

    let _guard = REFRESH_LOCK.lock().await;

    // Another task may have refreshed the cache while we waited for the lock
    let now = Instant::now();
    let stale = {
        let cache = read_cache()?;
        match cache.lookup(kid, now) {
            Lookup::Fresh(key) => return Ok(key),
            Lookup::Stale(key) if cache.attempted_recently(now) => {
                tracing::debug!("Serving stale JWK for kid {} (refresh rate limited)", kid);
                return Ok(key);
            }
            Lookup::Missing if cache.attempted_recently(now) => {
                return Err(cache.missing_error(kid, now));
            }
            Lookup::Stale(key) => Some(key),
            Lookup::Missing => None,
        }
    };

    tracing::info!("Refreshing JWKs from Google (kid: {})", kid);
    match fetch_and_store().await {
        Ok(()) => {
            let now = Instant::now();
            let cache = read_cache()?;
            match cache.lookup(kid, now) {
                Lookup::Fresh(key) | Lookup::Stale(key) => Ok(key),
                Lookup::Missing => Err(cache.missing_error(kid, now)),
            }
        }
        Err(e) => match stale {
            Some(key) => {
                tracing::warn!(
                    "JWK refresh failed, serving stale key for kid {}: {}",
                    kid,
                    e
                );
                Ok(key)
            }
            None => Err(e),
        },
    }
}

/// Fetch Google's public keys and replace the cache contents.
///
/// Callers must hold `REFRESH_LOCK`.
async fn fetch_and_store() -> AuthResult<()> {
    write_cache()?.last_attempt = Some(Instant::now());

    let response = HTTP_CLIENT
        .get(GOOGLE_CERTS_URL)
        .send()
        .await
        .map_err(|e| AuthError::JwkFetchError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AuthError::JwkFetchError(format!(
            "HTTP {} from Google",
            response.status()
        )));
    }

    let ttl = parse_max_age(response.headers()).unwrap_or(DEFAULT_CACHE_TTL);

    let certs: HashMap<String, String> = response
        .json()
        .await
        .map_err(|e| AuthError::JwkFetchError(format!("Failed to parse JWK response: {}", e)))?;

    let mut keys = HashMap::new();
    for (kid, pem) in certs {
        match DecodingKey::from_rsa_pem(pem.as_bytes()) {
            Ok(key) => {
                keys.insert(kid, key);
            }
            Err(e) => {
                tracing::warn!("Failed to parse RSA key for kid {}: {}", kid, e);
            }
        }
    }

    if keys.is_empty() {
        return Err(AuthError::JwkFetchError(
            "No valid keys found in Google response".into(),
        ));
    }

    let key_count = keys.len();
    {
        let mut cache = write_cache()?;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        cache.ttl = ttl;
    }

    tracing::info!("Refreshed {} JWKs from Google (ttl {:?})", key_count, ttl);
    Ok(())
}

/// Extract `max-age` from a `Cache-Control` header
fn parse_max_age(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(CACHE_CONTROL)?
        .to_str()
        .ok()?
        .split(',')
        .find_map(|directive| directive.trim().strip_prefix("max-age="))
        .and_then(|secs| secs.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map(Duration::from_secs)
}

/// Force refresh the JWK cache (for testing or manual refresh), bypassing rate limiting
pub async fn force_refresh_jwks() -> AuthResult<()> {
    let _guard = REFRESH_LOCK.lock().await;
    fetch_and_store().await
}

/// Add a key to the cache and mark the cache freshly fetched, so lookups never hit Google.
#[cfg(test)]
pub(crate) fn insert_test_key(kid: &str, key: DecodingKey) {
    let now = Instant::now();
    let mut cache = CACHE.write().unwrap();
    cache.keys.insert(kid.to_string(), key);
    cache.fetched_at = Some(now);
    cache.last_attempt = Some(now);
    cache.ttl = DEFAULT_CACHE_TTL;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_fetched_ago(ago: Duration) -> (KeyCache, Instant) {
        let fetched_at = Instant::now();
        let mut cache = KeyCache::new();
        cache
            .keys
            .insert("kid1".into(), DecodingKey::from_secret(b"secret"));
        cache.fetched_at = Some(fetched_at);
        cache.last_attempt = Some(fetched_at);
        (cache, fetched_at + ago)
    }

    #[test]
    fn lookup_fresh_within_ttl() {
        let (cache, now) = cache_fetched_ago(Duration::from_secs(10));
        assert!(matches!(cache.lookup("kid1", now), Lookup::Fresh(_)));
    }

    #[test]
    fn lookup_stale_after_ttl() {
        let (cache, now) = cache_fetched_ago(DEFAULT_CACHE_TTL + Duration::from_secs(1));
        assert!(matches!(cache.lookup("kid1", now), Lookup::Stale(_)));
    }

    #[test]
    fn lookup_missing_after_max_stale() {
        let (cache, now) = cache_fetched_ago(DEFAULT_CACHE_TTL + MAX_STALE);
        assert!(matches!(cache.lookup("kid1", now), Lookup::Missing));
    }

    #[test]
    fn lookup_unknown_kid() {
        let (cache, now) = cache_fetched_ago(Duration::from_secs(10));
        assert!(matches!(cache.lookup("other", now), Lookup::Missing));
    }

    #[test]
    fn missing_error_depends_on_freshness() {
        let (cache, now) = cache_fetched_ago(Duration::from_secs(10));
        assert!(matches!(
            cache.missing_error("x", now),
            AuthError::KeyNotFound { .. }
        ));

        let empty = KeyCache::new();
        assert!(matches!(
            empty.missing_error("x", Instant::now()),
            AuthError::JwkFetchError(_)
        ));
    }

    #[test]
    fn parse_max_age_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CACHE_CONTROL,
            "public, max-age=19302, must-revalidate, no-transform"
                .parse()
                .unwrap(),
        );
        assert_eq!(parse_max_age(&headers), Some(Duration::from_secs(19302)));

        headers.insert(CACHE_CONTROL, "no-cache".parse().unwrap());
        assert_eq!(parse_max_age(&headers), None);

        headers.insert(CACHE_CONTROL, "max-age=0".parse().unwrap());
        assert_eq!(parse_max_age(&headers), None);

        assert_eq!(parse_max_age(&HeaderMap::new()), None);
    }

    /// Hits Google's real endpoint. Ignored by default because it needs network access and
    /// replaces the global cache, which would race with tests that install local keys.
    /// Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires network access to Google"]
    async fn test_refresh_jwks() {
        let result = force_refresh_jwks().await;
        assert!(result.is_ok(), "Failed to refresh JWKs: {:?}", result);

        let cache = CACHE.read().unwrap();
        assert!(
            !cache.keys.is_empty(),
            "Cache should not be empty after refresh"
        );
    }
}
