//! Counters of failed attempts, such as wrong second-factor codes.

use super::user::StoreError;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;
use uuid::Uuid;

/// Size of the memory table above which entries that have ended are dropped.
const PRUNE_AT: usize = 1024;

/// What an attempt counter counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptScope {
    /// Codes for the second step of one login. The key is the pending session.
    Login,
    /// Codes that confirm a change to an account's second factor. The key is the
    /// account.
    Change,
}

impl AttemptScope {
    /// The name to store: `login` or `change`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Change => "change",
        }
    }
}

/// Shared counters of failed attempts, for example an `auth_attempts` table
/// (`scope`, `key`, `count`, `expires_at`, primary key `(scope, key)`).
///
/// `mfa::Mfa` counts each code before checking it, gives the attempt back
/// when the check failed on the server's side, and clears the counter when a code is
/// accepted or the login is cancelled. Without a store of its own it uses a
/// [`MemoryAttemptStore`], whose counters each process keeps for itself. With several
/// processes behind a load balancer, give them one shared store, so that a login gets
/// the configured number of attempts in total rather than in each process.
///
/// # Contract
///
/// [`begin`](Self::begin) is one atomic step, so that concurrent requests in any
/// process cannot pass the limit together. In Postgres:
///
/// ```sql
/// INSERT INTO auth_attempts (scope, key, count, expires_at)
/// VALUES ($1, $2, 1, $4)
/// ON CONFLICT (scope, key) DO UPDATE SET
///     count = CASE WHEN auth_attempts.expires_at <= $5 THEN 1
///                  ELSE auth_attempts.count + 1 END,
///     expires_at = CASE WHEN auth_attempts.expires_at <= $5 THEN $4
///                       ELSE auth_attempts.expires_at END
/// WHERE auth_attempts.expires_at <= $5 OR auth_attempts.count < $3
/// RETURNING count
/// ```
///
/// No row returned means the limit is reached. Rows past `expires_at` are no longer
/// needed; delete them from time to time.
pub trait AttemptStore: Send + Sync + 'static {
    /// Count one attempt for `key`, unless `limit` attempts are already counted.
    ///
    /// A counter that does not exist or whose `expires_at` is not later than `now`
    /// starts over: it is set to 1 with the given `expires_at`. Otherwise it is raised
    /// by one, keeping its `expires_at`, but only while it is below `limit`. Returns the
    /// new count, or `None`, changing nothing, when the limit was already reached.
    fn begin(
        &self,
        scope: AttemptScope,
        key: Uuid,
        limit: u32,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> impl Future<Output = Result<Option<u32>, StoreError>> + Send;

    /// Lower the counter by one, not below zero: the attempt was not the user's fault.
    fn give_back(
        &self,
        scope: AttemptScope,
        key: Uuid,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Delete the counter.
    fn clear(
        &self,
        scope: AttemptScope,
        key: Uuid,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// An in-memory [`AttemptStore`], the default of `mfa::Mfa`.
///
/// The counters belong to this process; see [`AttemptStore`] for when that is not
/// enough. Clones share the same counters. Counters that have ended are dropped once
/// there are many of them.
#[derive(Debug, Clone, Default)]
pub struct MemoryAttemptStore {
    counters: Arc<Mutex<HashMap<(AttemptScope, Uuid), Counter>>>,
}

#[derive(Debug, Clone, Copy)]
struct Counter {
    count: u32,
    expires_at: SystemTime,
}

impl MemoryAttemptStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current count for `key`, whether or not it has ended.
    pub fn count(&self, scope: AttemptScope, key: Uuid) -> Option<u32> {
        self.lock().get(&(scope, key)).map(|c| c.count)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(AttemptScope, Uuid), Counter>> {
        self.counters.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AttemptStore for MemoryAttemptStore {
    async fn begin(
        &self,
        scope: AttemptScope,
        key: Uuid,
        limit: u32,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<Option<u32>, StoreError> {
        let mut counters = self.lock();
        if counters.len() >= PRUNE_AT {
            counters.retain(|_, counter| counter.expires_at > now);
        }
        let counter = counters.entry((scope, key)).or_insert(Counter {
            count: 0,
            expires_at,
        });
        if counter.expires_at <= now {
            *counter = Counter {
                count: 0,
                expires_at,
            };
        }
        if counter.count >= limit {
            return Ok(None);
        }
        counter.count += 1;
        Ok(Some(counter.count))
    }

    async fn give_back(&self, scope: AttemptScope, key: Uuid) -> Result<(), StoreError> {
        if let Some(counter) = self.lock().get_mut(&(scope, key)) {
            counter.count = counter.count.saturating_sub(1);
        }
        Ok(())
    }

    async fn clear(&self, scope: AttemptScope, key: Uuid) -> Result<(), StoreError> {
        self.lock().remove(&(scope, key));
        Ok(())
    }
}

#[cfg_attr(not(feature = "mfa"), allow(dead_code))]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// [`AttemptStore`] without its type, so that the services using it keep their type
/// parameters.
#[cfg_attr(not(feature = "mfa"), allow(dead_code))]
pub(crate) trait DynAttemptStore: Send + Sync {
    fn dyn_begin(
        &self,
        scope: AttemptScope,
        key: Uuid,
        limit: u32,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> BoxFuture<'_, Result<Option<u32>, StoreError>>;
    fn dyn_give_back(
        &self,
        scope: AttemptScope,
        key: Uuid,
    ) -> BoxFuture<'_, Result<(), StoreError>>;
    fn dyn_clear(&self, scope: AttemptScope, key: Uuid) -> BoxFuture<'_, Result<(), StoreError>>;
}

impl<A: AttemptStore> DynAttemptStore for A {
    fn dyn_begin(
        &self,
        scope: AttemptScope,
        key: Uuid,
        limit: u32,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> BoxFuture<'_, Result<Option<u32>, StoreError>> {
        Box::pin(AttemptStore::begin(
            self, scope, key, limit, expires_at, now,
        ))
    }

    fn dyn_give_back(
        &self,
        scope: AttemptScope,
        key: Uuid,
    ) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(AttemptStore::give_back(self, scope, key))
    }

    fn dyn_clear(&self, scope: AttemptScope, key: Uuid) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(AttemptStore::clear(self, scope, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn counts_up_to_the_limit_then_refuses() {
        let store = MemoryAttemptStore::new();
        let key = Uuid::new_v4();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let later = now + Duration::from_secs(300);
        let login = AttemptScope::Login;
        for expected in 1..=3 {
            assert_eq!(
                store.begin(login, key, 3, later, now).await.unwrap(),
                Some(expected)
            );
        }
        assert_eq!(store.begin(login, key, 3, later, now).await.unwrap(), None);
        assert_eq!(store.count(login, key), Some(3));
        // Scopes and keys are separate.
        assert_eq!(
            store
                .begin(AttemptScope::Change, key, 3, later, now)
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            store
                .begin(login, Uuid::new_v4(), 3, later, now)
                .await
                .unwrap(),
            Some(1)
        );

        store.give_back(login, key).await.unwrap();
        assert_eq!(
            store.begin(login, key, 3, later, now).await.unwrap(),
            Some(3)
        );
        store.clear(login, key).await.unwrap();
        assert_eq!(store.count(login, key), None);
        assert_eq!(
            store.begin(login, key, 3, later, now).await.unwrap(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn an_ended_counter_starts_over() {
        let store = MemoryAttemptStore::new();
        let key = Uuid::new_v4();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let end = now + Duration::from_secs(300);
        let scope = AttemptScope::Change;
        assert_eq!(store.begin(scope, key, 1, end, now).await.unwrap(), Some(1));
        assert_eq!(
            store
                .begin(scope, key, 1, end + Duration::from_secs(9), now)
                .await
                .unwrap(),
            None
        );
        let next_end = end + Duration::from_secs(300);
        assert_eq!(
            store.begin(scope, key, 1, next_end, end).await.unwrap(),
            Some(1)
        );
        assert_eq!(
            store.begin(scope, key, 1, next_end, end).await.unwrap(),
            None
        );
        assert_eq!(AttemptScope::Login.as_str(), "login");
        assert_eq!(scope.as_str(), "change");
    }
}
