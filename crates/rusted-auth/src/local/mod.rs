//! Local accounts: registration, login with a password, and sessions.
//!
//! Enabled by the `local` cargo feature. Nothing here depends on a web framework, a
//! database or an async runtime: accounts and sessions are reached through the
//! [`UserStore`] and [`SessionStore`] traits, which the application (or an adapter crate)
//! implements for its database. [`MemoryUserStore`] and [`MemorySessionStore`] are
//! in-memory implementations for tests.
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
//!   later requests, lists an account's sessions and revokes them.
//!
//! # Sessions
//!
//! A session token is [`SESSION_TOKEN_PREFIX`] followed by 256 random bits in base64url
//! without padding. Secret scanners can match it with `rusted_s_[A-Za-z0-9_-]{43}`. The
//! token is returned once, when the session is created; only its SHA-256 hash is stored,
//! and neither appears in logs, events, errors or `Debug` output.
//!
//! | Session | Ends after |
//! |---|---|
//! | Web | 7 days without use, or 30 days in total |
//! | Mobile | 30 days without use, or 90 days in total |
//! | Waiting for the second authentication step | 5 minutes |
//!
//! The lifetimes are set with [`SessionConfig`].
//!
//! [`SessionManager::validate`] keeps a validated session in memory for 30 seconds, so
//! most requests do not reach the store, and writes `last_seen_at` at most once per
//! minute. In exchange, **a session revoked by another process, or an account disabled
//! outside this process, keeps working here for up to 30 seconds**. A revocation made
//! through the same [`SessionManager`] takes effect in that process at once. See
//! [`SessionManager`] for details.
//!
//! [`SessionManager::revoke`] ends one session, [`SessionManager::revoke_all`] all
//! sessions of an account, and [`SessionManager::revoke_others`] all but the one in use.
//! [`SessionManager::list`] returns an account's usable sessions without their tokens.
//!
//! Sessions in state [`SessionState::PendingMfa`] exist for a second authentication
//! step. This module can create, check and activate them
//! ([`SessionManager::validate_pending_mfa`], [`SessionManager::activate`]), but login
//! does not produce them yet.
//!
//! # Audit events and metrics
//!
//! Implement [`EventSink`] to be told about successful and failed logins, lockouts,
//! sessions being created and revoked, and how long password hashing requests wait in
//! the queue. Nothing is recorded without a sink.
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

mod error;
mod event;
mod manager;
mod memory;
mod password;
mod service;
mod session;
mod token;
mod user;
mod validate;

pub use error::{BoxError, LocalError, LocalErrorKind, SessionError, SessionErrorKind};
pub use event::{AuthEvent, AuthEventKind, EventSink, HashQueueOutcome, LoginFailure};
pub use manager::{AuthenticatedSession, IssuedSession, SessionManager, SessionManagerBuilder};
pub use memory::{MemorySessionStore, MemoryUserStore};
pub use password::{
    HashLimits, MAX_PASSWORD_CHARS, MIN_PASSWORD_CHARS, PasswordHasher, PasswordPolicy,
    validate_password,
};
pub use service::{
    LocalAuth, LocalAuthBuilder, LockoutPolicy, Login, Registration, RegistrationOutcome,
};
pub use session::{
    LAST_SEEN_WRITE_INTERVAL, MAX_SESSION_CACHE_TTL, MAX_USER_AGENT_CHARS, NewSession, Session,
    SessionConfig, SessionContext, SessionKind, SessionLifetime, SessionRecord, SessionState,
    SessionStore,
};
pub use token::{SESSION_TOKEN_PREFIX, SessionToken, SessionTokenHash};
pub use user::{NewUser, StoreError, User, UserRecord, UserStore};
pub use uuid::Uuid;
