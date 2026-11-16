//! [`OneTimeTokenStore`] on the `one_time_tokens` table.

use crate::SeaOrmStore;
use crate::convert::{backend, get, is_foreign_key_violation, statement, timestamp};
use rusted_auth::session::{
    ConsumedToken, NewOneTimeToken, OneTimeTokenHash, OneTimeTokenStore, StoreError, TokenPurpose,
    Uuid,
};
use sea_orm::ConnectionTrait;
use std::time::SystemTime;

impl OneTimeTokenStore for SeaOrmStore {
    async fn insert(&self, token: NewOneTimeToken) -> Result<(), StoreError> {
        self.db
            .execute_raw(statement(
                "INSERT INTO one_time_tokens (token_hash, user_id, purpose, email, expires_at) \
                 VALUES ($1, $2, $3, $4, $5)",
                [
                    token.token_hash.as_bytes().to_vec().into(),
                    token.user_id.into(),
                    token.purpose.as_str().into(),
                    token.email.into(),
                    timestamp(token.expires_at)?.into(),
                ],
            ))
            .await
            .map_err(|error| {
                if is_foreign_key_violation(&error) {
                    StoreError::NotFound
                } else {
                    backend(error)
                }
            })?;
        Ok(())
    }

    async fn consume(
        &self,
        token_hash: &OneTimeTokenHash,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> Result<Option<ConsumedToken>, StoreError> {
        // The statement from the trait documentation: the row lock makes a second,
        // concurrent call find `used_at` set.
        let row = self
            .db
            .query_one_raw(statement(
                "UPDATE one_time_tokens SET used_at = $3 \
                 WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3 \
                 RETURNING user_id, email",
                [
                    token_hash.as_bytes().to_vec().into(),
                    purpose.as_str().into(),
                    timestamp(now)?.into(),
                ],
            ))
            .await
            .map_err(backend)?;
        row.map(|row| {
            Ok(ConsumedToken::new(
                get(&row, "user_id")?,
                get::<String>(&row, "email")?,
            ))
        })
        .transpose()
    }

    async fn invalidate(
        &self,
        user_id: Uuid,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        self.db
            .execute_raw(statement(
                "UPDATE one_time_tokens SET used_at = $3 \
                 WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL",
                [
                    user_id.into(),
                    purpose.as_str().into(),
                    timestamp(now)?.into(),
                ],
            ))
            .await
            .map_err(backend)?;
        Ok(())
    }
}
