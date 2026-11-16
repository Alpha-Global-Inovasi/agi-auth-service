//! Rate limits per client address, counted in an [`AttemptStore`].

use crate::failure::AuthFailure;
use hmac::{Hmac, Mac as _};
use rusted_auth::session::{AttemptScope, AttemptStore, MemoryAttemptStore, StoreError, Uuid};
use sha2::Sha256;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

/// A group of routes that share one limit per client address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Bucket {
    /// `/login`, `/mobile/login` and `/mfa/verify`.
    Login,
    /// `/register` and `/username-available`.
    Register,
    /// `/password/forgot` and `/email/verify/resend`: requests that send email.
    Email,
    /// `POST /email/verify` and `POST /password/reset`: requests that use a link token.
    Token,
}

impl Bucket {
    /// A stable name, part of the stored key.
    pub fn name(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Register => "register",
            Self::Email => "email",
            Self::Token => "token",
        }
    }
}

/// At most `max` requests per `window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Requests allowed in one window. `0` switches the limit off.
    pub max: u32,
    /// Length of the window. A window starts with the first request after the last
    /// one ended.
    pub window: Duration,
}

impl Limit {
    /// `max` requests per `window`.
    pub const fn new(max: u32, window: Duration) -> Self {
        Self { max, window }
    }
}

/// The limit of each [`Bucket`].
///
/// | Bucket | Default |
/// |---|---|
/// | [`Login`](Bucket::Login) | 30 per 5 minutes |
/// | [`Register`](Bucket::Register) | 10 per hour |
/// | [`Email`](Bucket::Email) | 10 per 15 minutes |
/// | [`Token`](Bucket::Token) | 30 per 15 minutes |
///
/// The defaults are generous because many users can share one address behind a NAT;
/// lockout and the email limit per account remain the main protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    login: Limit,
    register: Limit,
    email: Limit,
    token: Limit,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            login: Limit::new(30, Duration::from_secs(5 * 60)),
            register: Limit::new(10, Duration::from_secs(60 * 60)),
            email: Limit::new(10, Duration::from_secs(15 * 60)),
            token: Limit::new(30, Duration::from_secs(15 * 60)),
        }
    }
}

impl RateLimits {
    /// Set the limit of `bucket`.
    #[must_use]
    pub fn set(mut self, bucket: Bucket, limit: Limit) -> Self {
        *self.slot(bucket) = limit;
        self
    }

    /// The limit of `bucket`.
    pub fn get(&self, bucket: Bucket) -> Limit {
        match bucket {
            Bucket::Login => self.login,
            Bucket::Register => self.register,
            Bucket::Email => self.email,
            Bucket::Token => self.token,
        }
    }

    fn slot(&mut self, bucket: Bucket) -> &mut Limit {
        match bucket {
            Bucket::Login => &mut self.login,
            Bucket::Register => &mut self.register,
            Bucket::Email => &mut self.email,
            Bucket::Token => &mut self.token,
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

trait DynAttempts: Send + Sync {
    fn begin(
        &self,
        key: Uuid,
        limit: u32,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> BoxFuture<'_, Result<Option<u32>, StoreError>>;
}

impl<A: AttemptStore> DynAttempts for A {
    fn begin(
        &self,
        key: Uuid,
        limit: u32,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> BoxFuture<'_, Result<Option<u32>, StoreError>> {
        Box::pin(AttemptStore::begin(
            self,
            AttemptScope::ClientAddress,
            key,
            limit,
            expires_at,
            now,
        ))
    }
}

/// Counts requests per client address and [`Bucket`], and refuses those over the
/// [`RateLimits`] with 429 `rate_limited`.
///
/// Counters live in an [`AttemptStore`] under the scope `client_address`, so a shared
/// store (such as `rusted-auth-sea-orm`'s) gives every process one limit in total.
/// Every request counts, successful or not.
///
/// # Keys
///
/// The store is never given the address itself. The key is the first 16 bytes of
/// HMAC-SHA-256, under a secret key, of the bucket name and the address, so a copy of
/// the table does not tell which addresses made requests: without the key, the
/// whole IPv4 space could be hashed and matched in minutes. Before hashing, an IPv4
/// address (also when mapped into IPv6) is used as it is, and an IPv6 address is cut
/// to its /64 prefix, since one customer usually gets a whole /64 and can move within
/// it at will.
///
/// Every process that shares a store must use the same key ([`shared`](Self::shared));
/// [`memory`](Self::memory) makes a random one, which is enough for a store of its own.
///
/// # Failures
///
/// When the store fails, the request is refused with 503 (fail closed). That does not
/// reveal anything about accounts, since the counter does not depend on the account a
/// request names.
#[derive(Clone)]
pub struct RateLimiter {
    store: Arc<dyn DynAttempts>,
    key: Arc<Zeroizing<[u8; 32]>>,
    limits: RateLimits,
}

impl fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl RateLimiter {
    /// Counters in this process's memory, with a random key. With several processes
    /// each one counts on its own, so the limits apply per process.
    pub fn memory() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        // Without randomness the key stays zero; the counters still work, the keys are
        // only easier to reverse, and they never leave this process.
        if let Err(error) = getrandom::fill(key.as_mut_slice()) {
            tracing::warn!(%error, "no randomness for the rate limit key");
        }
        Self {
            store: Arc::new(MemoryAttemptStore::new()),
            key: Arc::new(key),
            limits: RateLimits::default(),
        }
    }

    /// Counters in `store`, shared by every process that uses it, under `key`. All of
    /// them must use the same key. Keep it secret, like other keys of the application.
    pub fn shared(store: impl AttemptStore, key: [u8; 32]) -> Self {
        Self {
            store: Arc::new(store),
            key: Arc::new(Zeroizing::new(key)),
            limits: RateLimits::default(),
        }
    }

    /// Replace the limits.
    #[must_use]
    pub fn limits(mut self, limits: RateLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The configured limits.
    pub fn configured(&self) -> RateLimits {
        self.limits
    }

    /// Count a request from `client` in `bucket`. An unknown address shares one
    /// counter with all other unknown addresses.
    pub async fn check(&self, bucket: Bucket, client: Option<IpAddr>) -> Result<(), AuthFailure> {
        let limit = self.limits.get(bucket);
        if limit.max == 0 {
            return Ok(());
        }
        let now = SystemTime::now();
        let expires_at = now + limit.window;
        match self
            .store
            .begin(self.key(bucket, client), limit.max, expires_at, now)
            .await
        {
            Ok(Some(_)) => Ok(()),
            Ok(None) => {
                tracing::info!(bucket = bucket.name(), "client address over its rate limit");
                Err(AuthFailure::rate_limited(limit.window))
            }
            Err(error) => Err(AuthFailure::unavailable(error)),
        }
    }

    /// The store key for `client` in `bucket`.
    pub(crate) fn key(&self, bucket: Bucket, client: Option<IpAddr>) -> Uuid {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.key.as_slice())
            .expect("HMAC takes keys of any length");
        mac.update(b"rusted-auth-actix rate limit\0");
        mac.update(bucket.name().as_bytes());
        mac.update(&[0]);
        match client.map(|ip| ip.to_canonical()) {
            Some(IpAddr::V4(ip)) => {
                mac.update(&[4]);
                mac.update(&ip.octets());
            }
            Some(IpAddr::V6(ip)) => {
                mac.update(&[6]);
                mac.update(&ip.octets()[..8]);
            }
            None => mac.update(&[0]),
        }
        let digest = mac.finalize().into_bytes();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Uuid::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn keys_group_ipv6_by_64_and_depend_on_bucket_and_secret() {
        let limiter = RateLimiter::shared(MemoryAttemptStore::new(), [7; 32]);
        let key = |bucket, s| limiter.key(bucket, Some(ip(s)));
        assert_eq!(
            key(Bucket::Login, "2001:db8:1:2::1"),
            key(Bucket::Login, "2001:db8:1:2:ffff::9")
        );
        assert_ne!(
            key(Bucket::Login, "2001:db8:1:2::1"),
            key(Bucket::Login, "2001:db8:1:3::1")
        );
        assert_eq!(
            key(Bucket::Login, "192.0.2.1"),
            key(Bucket::Login, "::ffff:192.0.2.1")
        );
        assert_ne!(
            key(Bucket::Login, "192.0.2.1"),
            key(Bucket::Login, "192.0.2.2")
        );
        assert_ne!(
            key(Bucket::Login, "192.0.2.1"),
            key(Bucket::Email, "192.0.2.1")
        );
        let other = RateLimiter::shared(MemoryAttemptStore::new(), [8; 32]);
        assert_ne!(
            key(Bucket::Login, "192.0.2.1"),
            other.key(Bucket::Login, Some(ip("192.0.2.1")))
        );
    }

    #[tokio::test]
    async fn refuses_requests_over_the_limit() {
        let limiter = RateLimiter::memory().limits(
            RateLimits::default().set(Bucket::Email, Limit::new(2, Duration::from_secs(60))),
        );
        let client = Some(ip("198.51.100.4"));
        limiter.check(Bucket::Email, client).await.unwrap();
        limiter.check(Bucket::Email, client).await.unwrap();
        let failure = limiter.check(Bucket::Email, client).await.unwrap_err();
        assert_eq!(failure.code(), "rate_limited");
        assert_eq!(failure.retry_after(), Some(Duration::from_secs(60)));
        limiter
            .check(Bucket::Email, Some(ip("198.51.100.5")))
            .await
            .expect("another address has its own counter");
        limiter
            .check(Bucket::Login, client)
            .await
            .expect("another bucket has its own counter");
    }
}
