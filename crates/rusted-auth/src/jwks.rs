//! Per-issuer signing key cache.
//!
//! - Keys are cached for the `max-age` the issuer sends (1 hour if absent).
//! - Only one refresh runs at a time; concurrent callers wait for it and reuse the result.
//! - Fetch attempts are rate limited, so tokens with an unknown `kid` cannot be used to
//!   hammer the issuer.
//! - If the issuer cannot be reached, expired keys keep being served for a grace period.
//!
//! Each [`Jwks`] belongs to exactly one issuer. Keys are never shared between issuers.

use crate::algorithm::Algorithm;
use crate::error::{AuthError, AuthResult};
use crate::http;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, PublicKeyUse};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

/// Cache timing. Fixed in production; tests shrink it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timings {
    /// TTL when the response carries no usable `Cache-Control: max-age`.
    pub default_ttl: Duration,
    /// Minimum interval between fetch attempts.
    pub min_fetch_interval: Duration,
    /// How long past their expiry keys may still be used while the issuer is unreachable.
    pub max_stale: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(3600),
            min_fetch_interval: Duration::from_secs(60),
            max_stale: Duration::from_secs(24 * 3600),
        }
    }
}

/// A verification key and the algorithm its JWK is restricted to, if any.
#[derive(Clone)]
pub(crate) struct SigningKey {
    pub key: DecodingKey,
    pub alg: Option<Algorithm>,
}

enum Source {
    Static,
    Remote {
        url: String,
        client: reqwest::Client,
    },
}

struct KeyCache {
    keys: HashMap<String, SigningKey>,
    /// Time of the last successful fetch
    fetched_at: Option<Instant>,
    /// Time of the last fetch attempt, successful or not
    last_attempt: Option<Instant>,
    ttl: Duration,
}

enum Lookup {
    Fresh(SigningKey),
    Stale(SigningKey),
    Missing,
}

pub(crate) struct Jwks {
    source: Source,
    timings: Timings,
    cache: RwLock<KeyCache>,
    /// Serializes refreshes so concurrent cache misses trigger a single fetch
    refresh_lock: tokio::sync::Mutex<()>,
}

impl KeyCache {
    fn age(&self, now: Instant) -> Option<Duration> {
        self.fetched_at.map(|t| now.saturating_duration_since(t))
    }

    fn is_fresh(&self, now: Instant) -> bool {
        self.age(now).is_some_and(|age| age < self.ttl)
    }

    fn lookup(&self, kid: &str, now: Instant, max_stale: Duration) -> Lookup {
        let (Some(key), Some(age)) = (self.keys.get(kid), self.age(now)) else {
            return Lookup::Missing;
        };
        if age < self.ttl {
            Lookup::Fresh(key.clone())
        } else if age < self.ttl.saturating_add(max_stale) {
            Lookup::Stale(key.clone())
        } else {
            Lookup::Missing
        }
    }

    /// Error for a `kid` that could not be resolved without fetching.
    ///
    /// With a fresh key set the `kid` is simply unknown (a bad token); otherwise we cannot
    /// tell, because the key set itself is unavailable.
    fn missing_error(&self, kid: &str, now: Instant) -> AuthError {
        if self.is_fresh(now) {
            AuthError::KeyNotFound {
                kid: kid.to_string(),
            }
        } else {
            AuthError::KeysUnavailable("issuer signing keys could not be fetched".into())
        }
    }
}

impl Jwks {
    /// Keys from a JWKS document supplied in configuration. Never refreshed.
    pub fn from_static(json: &str) -> AuthResult<Self> {
        let keys = parse_jwks(json.as_bytes()).map_err(AuthError::Config)?;
        Ok(Self::with(Source::Static, Timings::default(), keys))
    }

    /// Keys fetched on demand from `url`.
    pub fn remote(url: String, client: reqwest::Client, timings: Timings) -> Self {
        Self::with(Source::Remote { url, client }, timings, HashMap::new())
    }

    fn with(source: Source, timings: Timings, keys: HashMap<String, SigningKey>) -> Self {
        Self {
            source,
            timings,
            cache: RwLock::new(KeyCache {
                keys,
                fetched_at: None,
                last_attempt: None,
                ttl: timings.default_ttl,
            }),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    // A poisoned lock only means another thread panicked mid-update; the map is replaced
    // wholesale on every write, so its contents are still consistent.
    fn read(&self) -> RwLockReadGuard<'_, KeyCache> {
        self.cache.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, KeyCache> {
        self.cache.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Resolve the key for `kid`, fetching from the issuer only when needed.
    pub async fn get(&self, kid: &str) -> AuthResult<SigningKey> {
        let Source::Remote { url, client } = &self.source else {
            return self
                .read()
                .keys
                .get(kid)
                .cloned()
                .ok_or_else(|| AuthError::KeyNotFound {
                    kid: kid.to_string(),
                });
        };
        let Timings {
            min_fetch_interval,
            max_stale,
            ..
        } = self.timings;

        if let Lookup::Fresh(key) = self.read().lookup(kid, Instant::now(), max_stale) {
            return Ok(key);
        }

        let _guard = self.refresh_lock.lock().await;

        // Another task may have refreshed the cache while we waited for the lock
        let now = Instant::now();
        let stale = {
            let cache = self.read();
            let attempted_recently = cache
                .last_attempt
                .is_some_and(|t| now.saturating_duration_since(t) < min_fetch_interval);

            match cache.lookup(kid, now, max_stale) {
                Lookup::Fresh(key) => return Ok(key),
                Lookup::Stale(key) if attempted_recently => return Ok(key),
                Lookup::Missing if attempted_recently => {
                    return Err(cache.missing_error(kid, now));
                }
                Lookup::Stale(key) => Some(key),
                Lookup::Missing => None,
            }
        };

        match self.fetch_and_store(url, client).await {
            Ok(()) => {
                let now = Instant::now();
                let cache = self.read();
                match cache.lookup(kid, now, max_stale) {
                    Lookup::Fresh(key) | Lookup::Stale(key) => Ok(key),
                    Lookup::Missing => Err(cache.missing_error(kid, now)),
                }
            }
            Err(e) => match stale {
                Some(key) => {
                    tracing::warn!(jwks_uri = %url, error = %e, "JWKS refresh failed, serving stale key");
                    Ok(key)
                }
                None => Err(e),
            },
        }
    }

    /// Fetch now, ignoring the rate limit. No-op for static keys.
    pub async fn refresh(&self) -> AuthResult<()> {
        let Source::Remote { url, client } = &self.source else {
            return Ok(());
        };
        let _guard = self.refresh_lock.lock().await;
        self.fetch_and_store(url, client).await
    }

    /// Callers must hold `refresh_lock`.
    async fn fetch_and_store(&self, url: &str, client: &reqwest::Client) -> AuthResult<()> {
        self.write().last_attempt = Some(Instant::now());

        let fetched = http::get(client, url)
            .await
            .map_err(AuthError::KeysUnavailable)?;
        let keys = parse_jwks(&fetched.body).map_err(AuthError::KeysUnavailable)?;
        let ttl = fetched.max_age.unwrap_or(self.timings.default_ttl);

        let key_count = keys.len();
        {
            let mut cache = self.write();
            cache.keys = keys;
            cache.fetched_at = Some(Instant::now());
            cache.ttl = ttl;
        }

        tracing::info!(jwks_uri = %url, key_count, ttl_secs = ttl.as_secs(), "refreshed JWKS");
        Ok(())
    }
}

/// Parse a JWKS document into usable verification keys.
///
/// Keys are skipped, not fatal, when they have no `kid`, are symmetric (`oct`), are marked
/// for encryption, name an algorithm we do not accept, or fail to parse. An issuer's set
/// commonly mixes signing keys with others, and one odd entry must not disable the rest.
fn parse_jwks(json: &[u8]) -> Result<HashMap<String, SigningKey>, String> {
    crate::algorithm::ensure_crypto_provider();
    #[derive(Deserialize)]
    struct RawSet {
        keys: Vec<serde_json::Value>,
    }

    let raw: RawSet =
        serde_json::from_slice(json).map_err(|e| format!("invalid JWKS document: {e}"))?;

    let mut keys = HashMap::new();
    for value in raw.keys {
        let Ok(jwk) = serde_json::from_value::<Jwk>(value) else {
            continue;
        };
        let Some(kid) = jwk.common.key_id.clone() else {
            continue;
        };
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_))
            || matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption))
        {
            continue;
        }
        let alg = match jwk.common.key_algorithm {
            None => None,
            Some(named) => {
                let known = named.to_string().parse::<jsonwebtoken::Algorithm>().ok();
                match known.and_then(Algorithm::from_jwt) {
                    Some(alg) => Some(alg),
                    None => continue,
                }
            }
        };
        match DecodingKey::from_jwk(&jwk) {
            Ok(key) => {
                keys.insert(kid, SigningKey { key, alg });
            }
            Err(e) => tracing::warn!(%kid, error = %e, "skipping unusable JWK"),
        }
    }

    if keys.is_empty() {
        return Err("JWKS document contains no usable signing keys".into());
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::JWKS_JSON;

    fn cache_fetched_ago(ago: Duration) -> (KeyCache, Instant) {
        let fetched_at = Instant::now();
        let cache = KeyCache {
            keys: parse_jwks(JWKS_JSON.as_bytes()).unwrap(),
            fetched_at: Some(fetched_at),
            last_attempt: Some(fetched_at),
            ttl: Duration::from_secs(3600),
        };
        (cache, fetched_at + ago)
    }

    const MAX_STALE: Duration = Duration::from_secs(24 * 3600);

    #[test]
    fn lookup_by_age() {
        let (cache, now) = cache_fetched_ago(Duration::from_secs(10));
        assert!(matches!(
            cache.lookup("test-kid", now, MAX_STALE),
            Lookup::Fresh(_)
        ));
        assert!(matches!(
            cache.lookup("other", now, MAX_STALE),
            Lookup::Missing
        ));

        let (cache, now) = cache_fetched_ago(Duration::from_secs(3601));
        assert!(matches!(
            cache.lookup("test-kid", now, MAX_STALE),
            Lookup::Stale(_)
        ));

        let (cache, now) = cache_fetched_ago(Duration::from_secs(3600) + MAX_STALE);
        assert!(matches!(
            cache.lookup("test-kid", now, MAX_STALE),
            Lookup::Missing
        ));
    }

    #[test]
    fn missing_error_depends_on_freshness() {
        let (cache, now) = cache_fetched_ago(Duration::from_secs(10));
        assert!(matches!(
            cache.missing_error("x", now),
            AuthError::KeyNotFound { .. }
        ));

        let (cache, now) = cache_fetched_ago(Duration::from_secs(3601));
        assert!(matches!(
            cache.missing_error("x", now),
            AuthError::KeysUnavailable(_)
        ));
    }

    #[test]
    fn parse_skips_unusable_keys() {
        let test_key: serde_json::Value = serde_json::from_str(JWKS_JSON).unwrap();
        let rsa = test_key["keys"][0].clone();

        let mut no_kid = rsa.clone();
        no_kid.as_object_mut().unwrap().remove("kid");
        let mut for_encryption = rsa.clone();
        for_encryption["kid"] = "enc".into();
        for_encryption["use"] = "enc".into();
        let mut hmac_alg = rsa.clone();
        hmac_alg["kid"] = "hs".into();
        hmac_alg["alg"] = "HS256".into();
        let symmetric = serde_json::json!({"kty": "oct", "kid": "oct", "k": "c2VjcmV0"});
        let unknown_type = serde_json::json!({"kty": "FUTURE", "kid": "future"});

        let set = serde_json::json!({
            "keys": [rsa, no_kid, for_encryption, hmac_alg, symmetric, unknown_type]
        });
        let keys = parse_jwks(set.to_string().as_bytes()).unwrap();

        assert_eq!(keys.keys().collect::<Vec<_>>(), ["test-kid"]);
        assert_eq!(keys["test-kid"].alg, Some(Algorithm::RS256));
    }

    #[test]
    fn parse_rejects_empty_or_invalid_sets() {
        assert!(parse_jwks(br#"{"keys": []}"#).is_err());
        assert!(parse_jwks(br#"{"keys": [{"kty": "oct", "kid": "a", "k": "c2VjcmV0"}]}"#).is_err());
        assert!(parse_jwks(b"not json").is_err());
    }

    #[tokio::test]
    async fn static_keys_never_fetch() {
        let jwks = Jwks::from_static(JWKS_JSON).unwrap();
        assert!(jwks.get("test-kid").await.is_ok());
        assert!(matches!(
            jwks.get("nope").await,
            Err(AuthError::KeyNotFound { .. })
        ));
        jwks.refresh().await.unwrap();
    }
}
