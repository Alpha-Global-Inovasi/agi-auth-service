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
//!   A successful login creates a new session and returns its token ([`Login`]). With
//!   second factors configured (`LocalAuthBuilder::mfa`, `mfa` feature), an account
//!   with TOTP gets a session that waits for the second step instead
//!   ([`Login::mfa_required`]).
//! - [`LocalAuth::verify_email`] takes the token from the verification link sent at
//!   registration; [`LocalAuth::resend_verification`] sends a new link.
//! - [`LocalAuth::request_password_reset`] sends a reset link and
//!   [`LocalAuth::reset_password`] sets the new password with it, signing out every
//!   session. [`LocalAuth::change_password`] changes it from a signed-in session and
//!   signs out the others.
//! - [`LocalAuth::sessions`] gives the [`SessionManager`], which checks the token on
//!   later requests, lists an account's sessions and revokes them. Sessions are
//!   described in the [`session`](crate::session) module.
//!
//! # Emails
//!
//! [`LocalAuth`] decides which emails to send and hands them to the application's
//! [`Mailer`] as [`AuthEmail`] values: a verification link for a new account, a reset
//! link, and notices when someone registers an address that already has an account,
//! when the account is locked, and when the password changes. The application renders
//! them and builds the links. The mailer is required; [`NoMailer`] sends nothing.
//!
//! The mailer must queue emails rather than wait for delivery, and its errors are not
//! returned to the caller: otherwise the time or the outcome of a password reset
//! request would tell whether the address is registered. The emails others can cause
//! (registration notices, reset links, verification links sent again, lockout notices)
//! are limited per account ([`EmailPolicy`]): 3 in 15 minutes by default.
//!
//! Links carry single-use tokens ([`OneTimeToken`]) with the prefix `rusted_t_`, which
//! secret scanners can match with `rusted_t_[A-Za-z0-9_-]{43}`. Only their SHA-256
//! hash is stored, in the [`OneTimeTokenStore`] given to the builder. A verification
//! link works for 24 hours and a reset link for 1 hour; a new link replaces the
//! account's earlier one, and a token only works while the account still has the
//! address it was sent to. Neither link signs the user in.
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
//! - Deliver the session token to the client and read it back on later requests (a
//!   cookie for browsers, a header for mobile apps), including CSRF protection for
//!   cookies.
//! - Implement [`Mailer`] by queueing the emails, render them, and build the links.
//!   Open a link with a page that sends the token back with a POST request, not with
//!   the GET request itself: mail scanners follow links and would use the token up.
//!   Serve that page with `Referrer-Policy: no-referrer`.
//! - Rate limit the password reset and resend forms per client address.
//! - Delete expired and revoked sessions, and used and expired tokens, from the stores
//!   from time to time.
//!
//! [`MemorySessionStore`]: crate::session::MemorySessionStore
//! [`OneTimeToken`]: crate::session::OneTimeToken
//! [`OneTimeTokenStore`]: crate::session::OneTimeTokenStore
//! [`MemoryUserStore`]: crate::session::MemoryUserStore
//! [`SessionError`]: crate::session::SessionError
//! [`SessionManager`]: crate::session::SessionManager
//! [`SessionManager::revoke_others`]: crate::session::SessionManager::revoke_others
//! [`SessionStore`]: crate::session::SessionStore
//! [`UserStore`]: crate::session::UserStore

mod error;
mod mail;
mod password;
mod service;
mod validate;

pub use error::{LocalError, LocalErrorKind};
#[cfg(any(test, feature = "test-util"))]
pub use mail::RecordingMailer;
pub use mail::{AuthEmail, Mailer, NoMailer, PasswordChangeVia};
pub use password::{
    HashLimits, MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS, PasswordHasher, PasswordPolicy,
    validate_password,
};
pub use service::{
    EmailPolicy, LocalAuth, LocalAuthBuilder, LockoutPolicy, Login, MAX_RESET_PASSWORD_TTL,
    PasswordChangePolicy, Registration, RegistrationOutcome,
};
