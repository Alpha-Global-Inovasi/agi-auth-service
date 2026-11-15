//! Local accounts: registration, login with a password, and sessions.
//!
//! Enabled by the `local` cargo feature, which turns on the `session` feature as well.
//! Nothing here depends on a web framework, a database or an async runtime: accounts and
//! sessions are reached through the [`UserStore`] and [`SessionStore`] traits of the
//! [`session`](crate::session) module, which the application (or an adapter crate)
//! implements for its database. [`MemoryUserStore`] and [`MemorySessionStore`] are
//! in-memory implementations for tests.
//!
//! Sessions, accounts and audit events live in [`session`](crate::session), because
//! every way of signing in ends in the same kind of session. This module adds what is
//! specific to passwords.
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
//!   A successful login creates a new session and returns its token ([`Login`]).
//! - [`LocalAuth::sessions`] gives the [`SessionManager`], which checks the token on
//!   later requests, lists an account's sessions and revokes them. Sessions are
//!   described in the [`session`](crate::session) module.
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
//! set with [`HashLimits`]. A hash made with other parameters is replaced at the next
//! successful login.
//!
//! # Errors
//!
//! [`LocalError`] and [`SessionError`] follow the same convention as
//! [`AuthError`](crate::AuthError): `Display` is for logs, `public_message()` is for
//! clients, and `kind()` picks a status code. Passwords, password hashes, session tokens
//! and their hashes never appear in errors, logs or `Debug` output.
//!
//! # What the caller still has to do
//!
//! - Rate limit login, registration and the username check per client address.
//! - Mark the email address as verified once its owner has proven control of it.
//! - Deliver the session token to the client and read it back on later requests (a
//!   cookie for browsers, a header for mobile apps), including CSRF protection for
//!   cookies.
//! - Call [`SessionManager::revoke_others`] when a password is changed or reset.
//! - Delete expired and revoked sessions from the store from time to time.
//! - Send the verification email for a new account, and the notice to the owner when
//!   someone registers an address that already has an account.
//!
//! [`MemorySessionStore`]: crate::session::MemorySessionStore
//! [`MemoryUserStore`]: crate::session::MemoryUserStore
//! [`SessionError`]: crate::session::SessionError
//! [`SessionManager`]: crate::session::SessionManager
//! [`SessionManager::revoke_others`]: crate::session::SessionManager::revoke_others
//! [`SessionStore`]: crate::session::SessionStore
//! [`UserStore`]: crate::session::UserStore

mod error;
mod password;
mod service;
mod validate;

pub use error::{LocalError, LocalErrorKind};
pub use password::{
    HashLimits, MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS, PasswordHasher, PasswordPolicy,
    validate_password,
};
pub use service::{
    LocalAuth, LocalAuthBuilder, LockoutPolicy, Login, Registration, RegistrationOutcome,
};
