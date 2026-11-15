use super::error::{BoxError, LocalError};
use std::fmt;
use std::future::Future;
use std::time::SystemTime;
use thiserror::Error;
use uuid::Uuid;

/// A local account, without its credentials.
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
    /// Display name. May be empty.
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
    /// Display name. May be empty.
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

    /// The account to update does not exist.
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

impl From<StoreError> for LocalError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::UsernameTaken => Self::UsernameTaken,
            StoreError::EmailTaken => Self::EmailTaken,
            other => Self::Store(Box::new(other)),
        }
    }
}

/// Persistence for local accounts.
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
/// - [`record_failed_login`](Self::record_failed_login) increments atomically.
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

    #[test]
    fn conflicts_keep_their_meaning_and_backend_errors_stay_private() {
        assert!(matches!(
            LocalError::from(StoreError::UsernameTaken),
            LocalError::UsernameTaken
        ));
        let error = LocalError::from(StoreError::backend("pool timed out"));
        assert!(matches!(error, LocalError::Store(_)));
        assert!(!error.public_message().contains("pool"));
    }
}
