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
//! - [`LocalAuth::username_available`] checks a username. It is only available when the
//!   application chose to reveal existing email addresses, because the two together
//!   would undo the protection above.
//! - [`LocalAuth::login`] checks a username or email address and a password. Unknown
//!   accounts cost the same hashing work as known ones, every rejection carries the same
//!   public message, and repeated failures lock the account for a growing period
//!   ([`LockoutPolicy`]). The email address must be verified before the first login.
//!
//! # Limits of hiding registered email addresses
//!
//! Registration does not reveal directly whether an email address has an account, but a
//! determined caller can still find out at the cost of one registration per address:
//! register with the address and a new username, then try to register that username
//! again. If it is now taken, the first call created an account, so the address was new.
//! Usernames are public and must be unique, so this cannot be hidden without reserving
//! them. Rate limit registration per client address to keep it expensive.
//!
//! # Passwords
//!
//! Passwords are 8 to 128 characters with no composition rules; the minimum can be raised
//! with [`PasswordPolicy`]. They are normalized to Unicode NFKC and hashed with argon2id
//! using the OWASP parameters m = 19 MiB, t = 2, p = 1.
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
//! - Mark the email address as verified once its owner has proven control of it.
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
    HashLimits, MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS, PasswordHasher, PasswordPolicy,
    validate_password,
};
pub use service::{LocalAuth, LocalAuthBuilder, LockoutPolicy, Registration, RegistrationOutcome};
pub use user::{NewUser, StoreError, User, UserRecord, UserStore};
pub use uuid::Uuid;
