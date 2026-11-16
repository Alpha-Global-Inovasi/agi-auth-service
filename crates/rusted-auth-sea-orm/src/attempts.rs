//! [`AttemptStore`] on the `auth_attempts` table.

use crate::SeaOrmStore;
use crate::convert::{backend, get, statement, timestamp};
use rusted_auth::session::{AttemptScope, AttemptStore, StoreError, Uuid};
use sea_orm::ConnectionTrait;
use std::time::SystemTime;

impl AttemptStore for SeaOrmStore {
    async fn begin(
        &self,
        scope: AttemptScope,
        key: Uuid,
        limit: u32,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<Option<u32>, StoreError> {
        // The statement from the trait documentation. `ON CONFLICT ... DO UPDATE` locks
        // the row, so concurrent attempts in any process are counted one after another.
        if limit == 0 {
            // The statement would still start a new counter at one.
            return Ok(None);
        }
        let limit = i32::try_from(limit).unwrap_or(i32::MAX);
        let row = self
            .db
            .query_one_raw(statement(
                "INSERT INTO auth_attempts (scope, key, count, expires_at) \
                 VALUES ($1, $2, 1, $4) \
                 ON CONFLICT (scope, key) DO UPDATE SET \
                     count = CASE WHEN auth_attempts.expires_at <= $5 THEN 1 \
                                  ELSE auth_attempts.count + 1 END, \
                     expires_at = CASE WHEN auth_attempts.expires_at <= $5 THEN $4 \
                                       ELSE auth_attempts.expires_at END \
                 WHERE auth_attempts.expires_at <= $5 OR auth_attempts.count < $3 \
                 RETURNING count",
                [
                    scope.as_str().into(),
                    key.into(),
                    limit.into(),
                    timestamp(expires_at)?.into(),
                    timestamp(now)?.into(),
                ],
            ))
            .await
            .map_err(backend)?;
        row.map(|row| {
            u32::try_from(get::<i32>(&row, "count")?)
                .map_err(|_| StoreError::backend("attempt count is negative"))
        })
        .transpose()
    }

    async fn give_back(&self, scope: AttemptScope, key: Uuid) -> Result<(), StoreError> {
        self.db
            .execute_raw(statement(
                "UPDATE auth_attempts SET count = GREATEST(count - 1, 0) \
                 WHERE scope = $1 AND key = $2",
                [scope.as_str().into(), key.into()],
            ))
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn clear(&self, scope: AttemptScope, key: Uuid) -> Result<(), StoreError> {
        self.db
            .execute_raw(statement(
                "DELETE FROM auth_attempts WHERE scope = $1 AND key = $2",
                [scope.as_str().into(), key.into()],
            ))
            .await
            .map_err(backend)?;
        Ok(())
    }
}
