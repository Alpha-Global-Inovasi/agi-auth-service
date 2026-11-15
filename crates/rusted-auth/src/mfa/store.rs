//! Persistence for second factors.

use super::recovery::RecoveryCodeHash;
use crate::session::StoreError;
use std::fmt;
use std::future::Future;
use std::time::SystemTime;
use uuid::Uuid;

/// An account's TOTP authenticator, as stored in an `mfa_totp` table (one row per
/// account, keyed by `user_id`).
///
/// The `Debug` output does not include the encrypted secret.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TotpRecord {
    /// The account.
    pub user_id: Uuid,
    /// The secret, encrypted with the [`Keyring`](crate::encryption::Keyring). Store it
    /// as bytes (`bytea`).
    pub secret_enc: Vec<u8>,
    /// When the authenticator was confirmed with a correct code. `None` while setup is
    /// unfinished; such a record has no effect on login.
    pub confirmed_at: Option<SystemTime>,
    /// The newest time step whose code was accepted. Codes for this step and older ones
    /// are refused, so a code cannot be used twice.
    pub last_used_step: Option<u64>,
}

impl TotpRecord {
    /// A record as a store read it.
    pub fn new(
        user_id: Uuid,
        secret_enc: Vec<u8>,
        confirmed_at: Option<SystemTime>,
        last_used_step: Option<u64>,
    ) -> Self {
        Self {
            user_id,
            secret_enc,
            confirmed_at,
            last_used_step,
        }
    }

    /// `true` once the authenticator was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }
}

impl fmt::Debug for TotpRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpRecord")
            .field("user_id", &self.user_id)
            .field(
                "secret_enc",
                &format_args!("<{} bytes>", self.secret_enc.len()),
            )
            .field("confirmed_at", &self.confirmed_at)
            .field("last_used_step", &self.last_used_step)
            .finish()
    }
}

/// Persistence for TOTP authenticators (`mfa_totp`) and recovery codes
/// (`mfa_recovery_codes`: `user_id`, `code_hash`, `used_at`).
///
/// Implement this for your database. [`MemoryMfaStore`](super::MemoryMfaStore) is an
/// in-memory implementation for tests.
///
/// # Contract
///
/// - Each method is one atomic step. The conditions in their descriptions belong in the
///   `WHERE` clause of the statement that makes the change, so that concurrent requests
///   cannot both pass them: a TOTP code or a recovery code must never be accepted twice.
/// - Time steps are stored as a 64-bit integer; they fit in a signed `bigint`.
/// - Only keyed hashes of recovery codes are stored, never the codes. Store them as 32
///   bytes (`bytea`), with an index on `(user_id, code_hash)`.
pub trait MfaStore: Send + Sync + 'static {
    /// The account's TOTP record, confirmed or not.
    fn find_totp(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Option<TotpRecord>, StoreError>> + Send;

    /// Save an unconfirmed TOTP record with `secret_enc`, replacing an earlier
    /// unconfirmed one. Does nothing and returns `false` when the account already has a
    /// confirmed record.
    fn save_unconfirmed_totp(
        &self,
        user_id: Uuid,
        secret_enc: Vec<u8>,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Confirm the TOTP record: set `confirmed_at = at` and `last_used_step = used_step`,
    /// and replace all recovery codes of the account with `recovery_codes`, unused.
    ///
    /// Only applies when the record is unconfirmed and its `secret_enc` still equals
    /// `secret_enc` (setup may have been restarted meanwhile). Returns whether it
    /// applied.
    fn confirm_totp(
        &self,
        user_id: Uuid,
        secret_enc: &[u8],
        used_step: u64,
        at: SystemTime,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Set `last_used_step = step`, but only on a confirmed record whose
    /// `last_used_step` is empty or smaller than `step`. Returns whether it applied; a
    /// `false` means the code was used by a concurrent request.
    fn record_totp_step(
        &self,
        user_id: Uuid,
        step: u64,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Replace `secret_enc` with `new`, but only if it still equals `current`. Used to
    /// re-encrypt a secret with the active key after a key rotation. Returns whether it
    /// applied.
    fn replace_totp_secret(
        &self,
        user_id: Uuid,
        current: &[u8],
        new: Vec<u8>,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Delete the account's TOTP record and all its recovery codes. Returns whether
    /// there was a TOTP record.
    fn delete_totp(&self, user_id: Uuid) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Replace all recovery codes of the account, used or not, with `recovery_codes`,
    /// but only when the account has a confirmed TOTP record. Returns whether it
    /// applied.
    fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// The first of `candidates` that is an unused recovery code of the account, without
    /// changing anything. `candidates` holds the hashes of one entered code under each
    /// key of the keyring, so at most one of them can match (`code_hash = ANY($2)`).
    fn find_unused_recovery_code(
        &self,
        user_id: Uuid,
        candidates: &[RecoveryCodeHash],
    ) -> impl Future<Output = Result<Option<RecoveryCodeHash>, StoreError>> + Send;

    /// Mark the account's unused recovery code with this hash as used at `at`. Returns
    /// whether such a code existed; a code that was already used returns `false`.
    fn use_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &RecoveryCodeHash,
        at: SystemTime,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Number of the account's recovery codes that are not used yet.
    fn count_unused_recovery_codes(
        &self,
        user_id: Uuid,
    ) -> impl Future<Output = Result<usize, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_omits_the_secret() {
        let record = TotpRecord::new(Uuid::nil(), vec![0xab; 70], None, Some(3));
        let debug = format!("{record:?}");
        assert!(debug.contains("<70 bytes>"), "{debug}");
        assert!(!debug.contains("171"), "{debug}");
        assert!(!record.is_confirmed());
    }
}
