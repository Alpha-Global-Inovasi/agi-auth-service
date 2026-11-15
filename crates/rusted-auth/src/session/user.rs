use super::error::BoxError;
use std::fmt;
use std::future::Future;
use std::time::SystemTime;
use thiserror::Error;
use uuid::Uuid;

/// An account, without its credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Stable identifier.
    pub id: Uuid,
    /// Unique, case-insensitive login name.
    pub username: String,
    /// Unique, case-insensitive email address.
    pub email: String,
    /// When the email address was confirmed, if it has been.
    pub email_verified_at: Option<SystemTime>,
    /// Display name.
    pub name: String,
    /// When the account was disabled, if it has been. Disabled accounts cannot log in.
    pub disabled_at: Option<SystemTime>,
}

/// A [`User`] together with the credential and lockout state kept by the store.
///
/// The `Debug` output does not include the password hash.
#[derive(Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// The account.
    pub user: User,
    /// Password hash in PHC string format, or `None` for an account that can only sign in
    /// through an external identity provider.
    pub password_hash: Option<String>,
    /// Consecutive failed logins since the last successful one.
    pub failed_login_count: u32,
    /// Logins are rejected until this time.
    pub locked_until: Option<SystemTime>,
}

impl fmt::Debug for UserRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRecord")
            .field("user", &self.user)
            .field("has_password", &self.password_hash.is_some())
            .field("failed_login_count", &self.failed_login_count)
            .field("locked_until", &self.locked_until)
            .finish()
    }
}

/// The account a [`UserStore`] is asked to create.
///
/// The `Debug` output does not include the password hash.
#[derive(Clone)]
#[non_exhaustive]
pub struct NewUser {
    /// Validated username, with the capitalization the user typed.
    pub username: String,
    /// Validated email address, with the capitalization the user typed.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Password hash in PHC string format.
    pub password_hash: Option<String>,
}

impl fmt::Debug for NewUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewUser")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("has_password", &self.password_hash.is_some())
            .finish()
    }
}

/// Errors a [`UserStore`] reports.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// [`UserStore::insert`]: the username belongs to another account.
    #[error("username is already taken")]
    UsernameTaken,

    /// [`UserStore::insert`]: the email address belongs to another account.
    #[error("email is already registered")]
    EmailTaken,

    /// The account to update, or to create a session for, does not exist.
    #[error("user not found")]
    NotFound,

    /// The backend failed. The message is logged, never sent to clients.
    #[error("{0}")]
    Backend(#[source] BoxError),
}

impl StoreError {
    /// Wrap a backend error.
    pub fn backend(error: impl Into<BoxError>) -> Self {
        Self::Backend(error.into())
    }
}

/// Persistence for accounts.
///
/// Implement this for your database. [`MemoryUserStore`](super::MemoryUserStore) is an
/// in-memory implementation for tests.
///
/// # Contract
///
/// - Usernames and email addresses are matched **case-insensitively** and each is unique
///   across accounts.
/// - [`insert`](Self::insert) enforces both uniqueness rules atomically, so two concurrent
///   registrations cannot both succeed.
/// - [`record_failed_login`](Self::record_failed_login) increments atomically,
///   [`replace_password_hash`](Self::replace_password_hash) compares and replaces
///   atomically, and [`reset_password`](Self::reset_password) is one atomic update.
pub trait UserStore: Send + Sync + 'static {
    /// Look up an account by username.
    fn find_by_username(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    /// Look up an account by email address.
    fn find_by_email(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<UserRecord>, StoreError>> + Send;

    /// Create an account and return it with its new identifier.
    ///
    /// Returns [`StoreError::UsernameTaken`] or [`StoreError::EmailTaken`] on a conflict.
    /// When both are taken, report the username.
    fn insert(&self, user: NewUser) -> impl Future<Output = Result<User, StoreError>> + Send;

    /// Add one to the account's failed login counter and return the new value.
    fn record_failed_login(&self, id: Uuid)
    -> impl Future<Output = Result<u32, StoreError>> + Send;

    /// Set or clear the time until which logins are rejected.
    fn set_locked_until(
        &self,
        id: Uuid,
        until: Option<SystemTime>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Reset the failed login counter to zero and clear the lock.
    fn record_successful_login(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Replace the account's password hash with `new`, but only if the stored hash still
    /// equals `current`. Returns whether it was replaced.
    ///
    /// Used to upgrade a hash made with outdated parameters after a successful login.
    /// The comparison keeps a password change that happened in the meantime from being
    /// undone, so it must be one atomic step, such as
    /// `UPDATE users SET password_hash = $new WHERE id = $id AND password_hash = $current`.
    fn replace_password_hash(
        &self,
        id: Uuid,
        current: &str,
        new: String,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Record that the account's email address was verified at `at`, unless a time is
    /// already recorded. Returns whether the account changed.
    ///
    /// For example
    /// `UPDATE users SET email_verified_at = $at WHERE id = $id AND email_verified_at IS NULL`.
    /// Returns [`StoreError::NotFound`] when the account does not exist.
    fn mark_email_verified(
        &self,
        id: Uuid,
        at: SystemTime,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Set a new password hash after a password reset and clear the lockout state, in
    /// one step: `password_hash = $hash, failed_login_count = 0, locked_until = NULL`.
    ///
    /// Unlike [`replace_password_hash`](Self::replace_password_hash) this does not
    /// compare first: the user proved control of the email address, so the new
    /// password wins. A rehash at login that runs at the same time then fails its
    /// comparison and leaves the new hash in place, as it should.
    /// Returns [`StoreError::NotFound`] when the account does not exist.
    fn reset_password(
        &self,
        id: Uuid,
        password_hash: String,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_omits_password_hash() {
        let new_user = NewUser {
            username: "budi".into(),
            email: "budi@example.com".into(),
            name: String::new(),
            password_hash: Some("$argon2id$secret-hash".into()),
        };
        assert!(!format!("{new_user:?}").contains("secret-hash"));

        let record = UserRecord {
            user: User {
                id: Uuid::nil(),
                username: new_user.username.clone(),
                email: new_user.email.clone(),
                email_verified_at: None,
                name: String::new(),
                disabled_at: None,
            },
            password_hash: new_user.password_hash.clone(),
            failed_login_count: 0,
            locked_until: None,
        };
        assert!(!format!("{record:?}").contains("secret-hash"));
    }
}
