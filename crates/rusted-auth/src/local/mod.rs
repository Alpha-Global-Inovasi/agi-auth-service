//! Local accounts: registration and login with a password.
//!
//! Enabled by the `local` cargo feature. Nothing here depends on a web framework or a
//! database: accounts are reached through the [`UserStore`] trait, which the application
//! (or an adapter crate) implements for its database. [`MemoryUserStore`] is an in-memory
//! implementation for tests.
//!
//! [`LocalAuth`] is the entry point:
//!
//! - [`LocalAuth::register`] creates an account. By default it behaves the same whether
//!   or not the email address is already registered, so it cannot be used to find out who
//!   has an account ([`RegistrationOutcome`]).
//! - [`LocalAuth::username_available`] checks a username.
//! - [`LocalAuth::login`] checks a username or email address and a password. Unknown
//!   accounts cost the same hashing work as known ones, every rejection carries the same
//!   public message, and repeated failures lock the account for a growing period
//!   ([`LockoutPolicy`]).
//!
//! # Passwords
//!
//! Passwords are 8 to 128 characters with no composition rules ([`validate_password`])
//! and are hashed with argon2id using the OWASP parameters m = 19 MiB, t = 2, p = 1.
//! [`PasswordHasher`] runs at most 8 hashes at once on its own threads; a request that
//! waits more than 2 seconds for a slot fails with [`LocalError::Busy`]. Both limits are
//! set with [`HashLimits`].
//!
//! # Errors
//!
//! [`LocalError`] follows the same convention as [`AuthError`](crate::AuthError):
//! `Display` is for logs, [`LocalError::public_message`] is for clients, and
//! [`LocalError::kind`] picks a status code. Passwords and password hashes never appear
//! in errors, logs or `Debug` output.
//!
//! # What the caller still has to do
//!
//! - Rate limit login, registration and the username check per client address.
//! - Issue a session after a successful login.
//! - Send the verification email for a new account, and the notice to the owner when
//!   someone registers an address that already has an account.

mod error;
mod memory;
mod password;
mod service;
mod user;
mod validate;

pub use error::{BoxError, LocalError, LocalErrorKind};
pub use memory::MemoryUserStore;
pub use password::{
    HashLimits, MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS, PasswordHasher, validate_password,
};
pub use service::{LocalAuth, LocalAuthBuilder, LockoutPolicy, Registration, RegistrationOutcome};
pub use user::{NewUser, StoreError, User, UserRecord, UserStore};
pub use uuid::Uuid;
