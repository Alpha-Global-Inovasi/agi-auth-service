//! [`UserStore`] on the `users` table.

use crate::SeaOrmStore;
use crate::convert::{backend, get, get_optional_time, statement, timestamp};
use rusted_auth::session::{NewUser, StoreError, User, UserRecord, UserStore, Uuid};
use sea_orm::{ConnectionTrait, QueryResult, Value};
use std::time::SystemTime;

/// The columns [`user_from_row`] reads, with `prefix` before each name.
///
/// `citext` columns are read as `text`.
pub(crate) fn user_columns(table: &str, prefix: &str) -> String {
    format!(
        "{table}.id AS {prefix}id, {table}.username::text AS {prefix}username, \
         {table}.email::text AS {prefix}email, {table}.email_verified_at AS {prefix}email_verified_at, \
         {table}.name AS {prefix}name, {table}.disabled_at AS {prefix}disabled_at"
    )
}

/// The account in a row selected with [`user_columns`].
pub(crate) fn user_from_row(row: &QueryResult, prefix: &str) -> Result<User, StoreError> {
    let column = |name: &str| format!("{prefix}{name}");
    Ok(User {
        id: get(row, &column("id"))?,
        username: get(row, &column("username"))?,
        email: get(row, &column("email"))?,
        email_verified_at: get_optional_time(row, &column("email_verified_at"))?,
        name: get(row, &column("name"))?,
        disabled_at: get_optional_time(row, &column("disabled_at"))?,
    })
}

fn record_from_row(row: &QueryResult) -> Result<UserRecord, StoreError> {
    let failed: i32 = get(row, "failed_login_count")?;
    Ok(UserRecord {
        user: user_from_row(row, "")?,
        password_hash: get(row, "password_hash")?,
        failed_login_count: u32::try_from(failed)
            .map_err(|_| StoreError::backend("failed_login_count is negative"))?,
        locked_until: get_optional_time(row, "locked_until")?,
    })
}

impl SeaOrmStore {
    async fn find_user(&self, column: &str, value: &str) -> Result<Option<UserRecord>, StoreError> {
        let sql = format!(
            "SELECT {}, users.password_hash, users.failed_login_count, users.locked_until \
             FROM users WHERE users.{column} = $1::citext",
            user_columns("users", "")
        );
        let row = self
            .db
            .query_one_raw(statement(&sql, [value.into()]))
            .await
            .map_err(backend)?;
        row.as_ref().map(record_from_row).transpose()
    }

    /// Run an `UPDATE users ... WHERE id = $1`, mapping "no row" to
    /// [`StoreError::NotFound`].
    async fn update_user(&self, sql: &str, values: Vec<Value>) -> Result<(), StoreError> {
        let result = self
            .db
            .execute_raw(statement(sql, values))
            .await
            .map_err(backend)?;
        if result.rows_affected() == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Run a conditional update written as `WITH updated AS (UPDATE users ... WHERE id =
    /// $1 AND <condition> RETURNING 1)`, and tell an account that does not exist from one
    /// whose condition did not hold.
    async fn update_user_if(&self, update: &str, values: Vec<Value>) -> Result<bool, StoreError> {
        let sql = format!(
            "WITH updated AS ({update} RETURNING 1) \
             SELECT EXISTS (SELECT 1 FROM updated) AS changed, \
                    EXISTS (SELECT 1 FROM users WHERE id = $1) AS found"
        );
        let row = self
            .db
            .query_one_raw(statement(&sql, values))
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::backend("conditional update returned no row"))?;
        if get::<bool>(&row, "changed")? {
            Ok(true)
        } else if get::<bool>(&row, "found")? {
            Ok(false)
        } else {
            Err(StoreError::NotFound)
        }
    }
}

impl UserStore for SeaOrmStore {
    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, StoreError> {
        self.find_user("username", username).await
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, StoreError> {
        self.find_user("email", email).await
    }

    async fn insert(&self, user: NewUser) -> Result<User, StoreError> {
        // `ON CONFLICT DO NOTHING` covers both unique columns; which one conflicted is
        // looked up afterwards, so that a username conflict is reported when both do.
        let sql = format!(
            "INSERT INTO users (id, username, email, name, password_hash) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING {}",
            user_columns("users", "")
        );
        let values = [
            Uuid::new_v4().into(),
            user.username.clone().into(),
            user.email.clone().into(),
            user.name.into(),
            user.password_hash.into(),
        ];
        let inserted = self
            .db
            .query_one_raw(statement(&sql, values))
            .await
            .map_err(backend)?;
        if let Some(row) = inserted {
            return user_from_row(&row, "");
        }
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1::citext) AS username_taken",
                [user.username.into()],
            ))
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::backend("EXISTS returned no row"))?;
        if get::<bool>(&row, "username_taken")? {
            Err(StoreError::UsernameTaken)
        } else {
            Err(StoreError::EmailTaken)
        }
    }

    async fn record_failed_login(&self, id: Uuid) -> Result<u32, StoreError> {
        // Saturates instead of overflowing the `integer` column.
        let row = self
            .db
            .query_one_raw(statement(
                "UPDATE users SET failed_login_count = LEAST(failed_login_count, 2147483646) + 1, \
                 updated_at = now() WHERE id = $1 RETURNING failed_login_count",
                [id.into()],
            ))
            .await
            .map_err(backend)?
            .ok_or(StoreError::NotFound)?;
        let count: i32 = get(&row, "failed_login_count")?;
        u32::try_from(count).map_err(|_| StoreError::backend("failed_login_count is negative"))
    }

    async fn set_locked_until(
        &self,
        id: Uuid,
        until: Option<SystemTime>,
    ) -> Result<(), StoreError> {
        let until = until.map(timestamp).transpose()?;
        self.update_user(
            "UPDATE users SET locked_until = $2, updated_at = now() WHERE id = $1",
            vec![id.into(), until.into()],
        )
        .await
    }

    async fn record_successful_login(&self, id: Uuid) -> Result<(), StoreError> {
        self.update_user(
            "UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = now() \
             WHERE id = $1",
            vec![id.into()],
        )
        .await
    }

    async fn replace_password_hash(
        &self,
        id: Uuid,
        current: &str,
        new: String,
    ) -> Result<bool, StoreError> {
        self.update_user_if(
            "UPDATE users SET password_hash = $3, updated_at = now() \
             WHERE id = $1 AND password_hash = $2",
            vec![id.into(), current.into(), new.into()],
        )
        .await
    }

    async fn mark_email_verified(&self, id: Uuid, at: SystemTime) -> Result<bool, StoreError> {
        self.update_user_if(
            "UPDATE users SET email_verified_at = $2, updated_at = now() \
             WHERE id = $1 AND email_verified_at IS NULL",
            vec![id.into(), timestamp(at)?.into()],
        )
        .await
    }

    async fn reset_password(&self, id: Uuid, password_hash: String) -> Result<(), StoreError> {
        self.update_user(
            "UPDATE users SET password_hash = $2, failed_login_count = 0, locked_until = NULL, \
             updated_at = now() WHERE id = $1",
            vec![id.into(), password_hash.into()],
        )
        .await
    }
}
