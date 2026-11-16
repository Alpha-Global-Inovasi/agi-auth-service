//! Deleting rows that are no longer needed.

use crate::SeaOrmStore;
use crate::convert::{backend, statement, timestamp};
use rusted_auth::session::StoreError;
use sea_orm::ConnectionTrait;
use std::time::{Duration, SystemTime};

/// How long [`SeaOrmStore::cleanup`] keeps rows after they stopped being useful.
///
/// | | Default |
/// |---|---|
/// | Expired and revoked sessions | deleted at once |
/// | Used and expired single-use tokens | deleted at once |
/// | Ended attempt counters | deleted at once |
/// | Audit events | 365 days |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Retention {
    /// How long expired and revoked sessions are kept, for example to show them on a
    /// "recent sessions" page.
    pub sessions: Duration,
    /// How long used and expired single-use tokens are kept.
    pub one_time_tokens: Duration,
    /// How long `auth_events` rows are kept.
    pub events: Duration,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            sessions: Duration::ZERO,
            one_time_tokens: Duration::ZERO,
            events: Duration::from_secs(365 * 24 * 60 * 60),
        }
    }
}

impl Retention {
    /// Set [`sessions`](Self::sessions).
    pub fn sessions(mut self, keep: Duration) -> Self {
        self.sessions = keep;
        self
    }

    /// Set [`one_time_tokens`](Self::one_time_tokens).
    pub fn one_time_tokens(mut self, keep: Duration) -> Self {
        self.one_time_tokens = keep;
        self
    }

    /// Set [`events`](Self::events).
    pub fn events(mut self, keep: Duration) -> Self {
        self.events = keep;
        self
    }
}

/// Rows deleted by [`SeaOrmStore::cleanup`], per table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CleanupReport {
    /// `sessions` rows.
    pub sessions: u64,
    /// `one_time_tokens` rows.
    pub one_time_tokens: u64,
    /// `auth_attempts` rows.
    pub attempts: u64,
    /// `auth_events` rows.
    pub events: u64,
}

/// `now - keep`, or the earliest representable time.
fn cutoff(now: SystemTime, keep: Duration) -> SystemTime {
    now.checked_sub(keep).unwrap_or(SystemTime::UNIX_EPOCH)
}

impl SeaOrmStore {
    async fn delete(&self, sql: &str, before: SystemTime) -> Result<u64, StoreError> {
        let result = self
            .db
            .execute_raw(statement(sql, [timestamp(before)?.into()]))
            .await
            .map_err(backend)?;
        Ok(result.rows_affected())
    }

    /// Delete sessions that ended before `before`: revoked, idle for too long, or past
    /// their absolute lifetime. Returns the number of rows deleted.
    pub async fn delete_ended_sessions(&self, before: SystemTime) -> Result<u64, StoreError> {
        self.delete(
            "DELETE FROM sessions \
             WHERE revoked_at < $1 OR idle_expires_at < $1 OR absolute_expires_at < $1",
            before,
        )
        .await
    }

    /// Delete single-use tokens that were used, invalidated or expired before `before`.
    pub async fn delete_ended_one_time_tokens(
        &self,
        before: SystemTime,
    ) -> Result<u64, StoreError> {
        self.delete(
            "DELETE FROM one_time_tokens WHERE used_at < $1 OR expires_at < $1",
            before,
        )
        .await
    }

    /// Delete attempt counters whose window ended at or before `now`. Such a counter
    /// would start over at its next attempt anyway.
    pub async fn delete_ended_attempts(&self, now: SystemTime) -> Result<u64, StoreError> {
        self.delete("DELETE FROM auth_attempts WHERE expires_at <= $1", now)
            .await
    }

    /// Delete audit events recorded before `before`.
    pub async fn delete_events_before(&self, before: SystemTime) -> Result<u64, StoreError> {
        self.delete("DELETE FROM auth_events WHERE created_at < $1", before)
            .await
    }

    /// Delete what is no longer needed from every table, keeping rows as long as
    /// `retention` says.
    ///
    /// The library has no scheduler: run this from a periodic job of the application,
    /// for example once an hour. Each table is cleaned with one `DELETE`; on a large
    /// backlog the first run can take a while.
    pub async fn cleanup(
        &self,
        now: SystemTime,
        retention: Retention,
    ) -> Result<CleanupReport, StoreError> {
        Ok(CleanupReport {
            sessions: self
                .delete_ended_sessions(cutoff(now, retention.sessions))
                .await?,
            one_time_tokens: self
                .delete_ended_one_time_tokens(cutoff(now, retention.one_time_tokens))
                .await?,
            attempts: self.delete_ended_attempts(now).await?,
            events: self
                .delete_events_before(cutoff(now, retention.events))
                .await?,
        })
    }
}
