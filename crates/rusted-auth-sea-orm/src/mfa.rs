//! [`MfaStore`] on the `mfa_totp` and `mfa_recovery_codes` tables.

use crate::SeaOrmStore;
use crate::convert::{
    backend, get, get_hash, get_optional_time, is_foreign_key_violation, statement, timestamp,
};
use rusted_auth::mfa::{MfaStore, RecoveryCodeHash, TotpRecord};
use rusted_auth::session::{StoreError, Uuid};
use sea_orm::{ConnectionTrait, DatabaseTransaction, TransactionTrait, Value};
use std::time::SystemTime;

/// A time step for a `bigint` column.
fn step_value(step: u64) -> Result<i64, StoreError> {
    i64::try_from(step).map_err(|_| StoreError::backend("time step does not fit in bigint"))
}

/// Insert `codes` as the account's unused recovery codes.
async fn insert_codes(
    txn: &DatabaseTransaction,
    user_id: Uuid,
    codes: Vec<RecoveryCodeHash>,
) -> Result<(), StoreError> {
    if codes.is_empty() {
        return Ok(());
    }
    let placeholders: Vec<String> = (0..codes.len())
        .map(|i| format!("($1, ${})", i + 2))
        .collect();
    let sql = format!(
        "INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES {}",
        placeholders.join(", ")
    );
    let mut values: Vec<Value> = vec![user_id.into()];
    values.extend(codes.iter().map(|code| code.as_bytes().to_vec().into()));
    txn.execute_raw(statement(&sql, values))
        .await
        .map_err(backend)?;
    Ok(())
}

async fn delete_codes(txn: &DatabaseTransaction, user_id: Uuid) -> Result<(), StoreError> {
    txn.execute_raw(statement(
        "DELETE FROM mfa_recovery_codes WHERE user_id = $1",
        [user_id.into()],
    ))
    .await
    .map_err(backend)?;
    Ok(())
}

impl MfaStore for SeaOrmStore {
    async fn find_totp(&self, user_id: Uuid) -> Result<Option<TotpRecord>, StoreError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT secret_enc, confirmed_at, last_used_step FROM mfa_totp WHERE user_id = $1",
                [user_id.into()],
            ))
            .await
            .map_err(backend)?;
        row.map(|row| {
            let step = get::<Option<i64>>(&row, "last_used_step")?
                .map(|step| {
                    u64::try_from(step)
                        .map_err(|_| StoreError::backend("last_used_step is negative"))
                })
                .transpose()?;
            Ok(TotpRecord::new(
                user_id,
                get(&row, "secret_enc")?,
                get_optional_time(&row, "confirmed_at")?,
                step,
            ))
        })
        .transpose()
    }

    async fn save_unconfirmed_totp(
        &self,
        user_id: Uuid,
        secret_enc: Vec<u8>,
    ) -> Result<bool, StoreError> {
        // The `WHERE` of `DO UPDATE` leaves a confirmed record alone; no row comes back
        // then.
        let row = self
            .db
            .query_one_raw(statement(
                "INSERT INTO mfa_totp (user_id, secret_enc) VALUES ($1, $2) \
                 ON CONFLICT (user_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, \
                     confirmed_at = NULL, last_used_step = NULL, updated_at = now() \
                 WHERE mfa_totp.confirmed_at IS NULL \
                 RETURNING user_id",
                [user_id.into(), secret_enc.into()],
            ))
            .await
            .map_err(|error| {
                if is_foreign_key_violation(&error) {
                    StoreError::NotFound
                } else {
                    backend(error)
                }
            })?;
        Ok(row.is_some())
    }

    async fn confirm_totp(
        &self,
        user_id: Uuid,
        secret_enc: &[u8],
        used_step: u64,
        at: SystemTime,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, StoreError> {
        let txn = self.db.begin().await.map_err(backend)?;
        // The UPDATE locks the record until the transaction ends, so a concurrent
        // confirmation or restart of the setup waits and then sees the new state.
        let confirmed = txn
            .execute_raw(statement(
                "UPDATE mfa_totp SET confirmed_at = $3, last_used_step = $4, updated_at = now() \
                 WHERE user_id = $1 AND confirmed_at IS NULL AND secret_enc = $2",
                [
                    user_id.into(),
                    secret_enc.to_vec().into(),
                    timestamp(at)?.into(),
                    step_value(used_step)?.into(),
                ],
            ))
            .await
            .map_err(backend)?
            .rows_affected()
            > 0;
        if !confirmed {
            txn.rollback().await.map_err(backend)?;
            return Ok(false);
        }
        delete_codes(&txn, user_id).await?;
        insert_codes(&txn, user_id, recovery_codes).await?;
        txn.commit().await.map_err(backend)?;
        Ok(true)
    }

    async fn record_totp_step(&self, user_id: Uuid, step: u64) -> Result<bool, StoreError> {
        let result = self
            .db
            .execute_raw(statement(
                "UPDATE mfa_totp SET last_used_step = $2, updated_at = now() \
                 WHERE user_id = $1 AND confirmed_at IS NOT NULL \
                   AND (last_used_step IS NULL OR last_used_step < $2)",
                [user_id.into(), step_value(step)?.into()],
            ))
            .await
            .map_err(backend)?;
        Ok(result.rows_affected() > 0)
    }

    async fn replace_totp_secret(
        &self,
        user_id: Uuid,
        current: &[u8],
        new: Vec<u8>,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .execute_raw(statement(
                "UPDATE mfa_totp SET secret_enc = $3, updated_at = now() \
                 WHERE user_id = $1 AND secret_enc = $2",
                [user_id.into(), current.to_vec().into(), new.into()],
            ))
            .await
            .map_err(backend)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_totp(&self, user_id: Uuid) -> Result<bool, StoreError> {
        let result = self
            .db
            .execute_raw(statement(
                "WITH codes AS (DELETE FROM mfa_recovery_codes WHERE user_id = $1) \
                 DELETE FROM mfa_totp WHERE user_id = $1",
                [user_id.into()],
            ))
            .await
            .map_err(backend)?;
        Ok(result.rows_affected() > 0)
    }

    async fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, StoreError> {
        let txn = self.db.begin().await.map_err(backend)?;
        // Locking the confirmed record keeps a concurrent `delete_totp` from leaving
        // codes behind without a record.
        let confirmed = txn
            .query_one_raw(statement(
                "SELECT 1 AS confirmed FROM mfa_totp \
                 WHERE user_id = $1 AND confirmed_at IS NOT NULL FOR UPDATE",
                [user_id.into()],
            ))
            .await
            .map_err(backend)?
            .is_some();
        if !confirmed {
            txn.rollback().await.map_err(backend)?;
            return Ok(false);
        }
        delete_codes(&txn, user_id).await?;
        insert_codes(&txn, user_id, recovery_codes).await?;
        txn.commit().await.map_err(backend)?;
        Ok(true)
    }

    async fn find_unused_recovery_code(
        &self,
        user_id: Uuid,
        candidates: &[RecoveryCodeHash],
    ) -> Result<Option<RecoveryCodeHash>, StoreError> {
        if candidates.is_empty() {
            return Ok(None);
        }
        let placeholders: Vec<String> = (0..candidates.len())
            .map(|i| format!("${}", i + 2))
            .collect();
        let sql = format!(
            "SELECT code_hash FROM mfa_recovery_codes \
             WHERE user_id = $1 AND used_at IS NULL AND code_hash IN ({})",
            placeholders.join(", ")
        );
        let mut values: Vec<Value> = vec![user_id.into()];
        values.extend(candidates.iter().map(|c| c.as_bytes().to_vec().into()));
        let rows = self
            .db
            .query_all_raw(statement(&sql, values))
            .await
            .map_err(backend)?;
        let found = rows
            .iter()
            .map(|row| get_hash(row, "code_hash").map(RecoveryCodeHash::from_bytes))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(candidates
            .iter()
            .copied()
            .find(|candidate| found.contains(candidate)))
    }

    async fn use_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &RecoveryCodeHash,
        at: SystemTime,
    ) -> Result<bool, StoreError> {
        let result = self
            .db
            .execute_raw(statement(
                "UPDATE mfa_recovery_codes SET used_at = $3 \
                 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
                [
                    user_id.into(),
                    code_hash.as_bytes().to_vec().into(),
                    timestamp(at)?.into(),
                ],
            ))
            .await
            .map_err(backend)?;
        Ok(result.rows_affected() > 0)
    }

    async fn count_unused_recovery_codes(&self, user_id: Uuid) -> Result<usize, StoreError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT count(*) AS unused FROM mfa_recovery_codes \
                 WHERE user_id = $1 AND used_at IS NULL",
                [user_id.into()],
            ))
            .await
            .map_err(backend)?
            .ok_or_else(|| StoreError::backend("count returned no row"))?;
        usize::try_from(get::<i64>(&row, "unused")?)
            .map_err(|_| StoreError::backend("negative count"))
    }
}
