//! Accounts and sessions, whichever way the user signed in.
//!
//! Enabled by the `session` cargo feature. Every way of signing in (a password with the
//! `local` module when the `local` feature is on, or an external identity
//! provider) ends in the same kind of session, so the session types, the [`User`]
//! account and the audit hook live here and do not depend on any password code.
//!
//! Nothing here depends on a web framework, a database or an async runtime: accounts and
//! sessions are reached through the [`UserStore`] and [`SessionStore`] traits, which the
//! application (or an adapter crate) implements for its database. [`MemoryUserStore`] and
//! [`MemorySessionStore`] are in-memory implementations for tests.
//!
//! [`SessionManager`] creates sessions, checks the token on later requests, lists an
//! account's sessions and revokes them.
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
//! # Errors
//!
//! [`SessionError`] follows the same convention as [`AuthError`](crate::AuthError):
//! `Display` is for logs, `public_message()` is for clients, and `kind()` picks a status
//! code. Session tokens and their hashes never appear in errors, logs or `Debug` output.

mod error;
pub(crate) mod event;
pub(crate) mod manager;
mod memory;
pub(crate) mod model;
pub(crate) mod token;
pub(crate) mod user;

pub use error::{BoxError, SessionError, SessionErrorKind};
pub use event::{AuthEvent, AuthEventKind, EventSink, HashQueueOutcome, LoginFailure};
pub use manager::{AuthenticatedSession, IssuedSession, SessionManager, SessionManagerBuilder};
pub use memory::{MemorySessionStore, MemoryUserStore};
pub use model::{
    LAST_SEEN_WRITE_INTERVAL, MAX_SESSION_CACHE_TTL, MAX_USER_AGENT_CHARS, NewSession, Session,
    SessionConfig, SessionContext, SessionKind, SessionLifetime, SessionRecord, SessionState,
    SessionStore,
};
pub use token::{SESSION_TOKEN_PREFIX, SessionToken, SessionTokenHash};
pub use user::{NewUser, StoreError, User, UserRecord, UserStore};
pub use uuid::Uuid;
