//! Second factor: TOTP authenticators (RFC 6238) and single-use recovery codes.
//!
//! Enabled by the `mfa` cargo feature, which turns on `session` and `encryption`.
//! Nothing here depends on a web framework, a database or an async runtime: TOTP records
//! and recovery codes are kept through the [`MfaStore`] trait, which the application (or
//! an adapter crate) implements for its database. [`MemoryMfaStore`] is an in-memory
//! implementation for tests.
//!
//! [`Mfa`] is the entry point. With the `local` feature, pass it to
//! `local::LocalAuthBuilder::mfa` so that password logins of accounts with TOTP wait
//! for the second step.
//!
//! # Setting up TOTP
//!
//! 1. [`Mfa::start_totp`] creates a random secret, stores it encrypted, and returns it
//!    once with its `otpauth://` URI ([`TotpSetup`]). The client shows the URI as a QR
//!    code; making the image is up to the client.
//! 2. The user scans it and types the code the app shows. [`Mfa::confirm_totp`] checks
//!    it, switches TOTP on, and returns the recovery codes once ([`RecoveryCodes`]).
//!
//! Until step 2 succeeds, the account logs in with the password alone. Starting again
//! replaces an unconfirmed secret.
//!
//! # Logging in
//!
//! 1. A password login of an account with confirmed TOTP returns a session in state
//!    [`PendingMfa`](crate::session::SessionState::PendingMfa), which lasts 5 minutes
//!    and cannot be used for anything but the second step.
//! 2. [`Mfa::complete_login`] takes that session's token and a TOTP code or a recovery
//!    code. When the code is right, the pending session is revoked and a new active
//!    session with a **new token** is returned ([`MfaLogin`]); the client must replace
//!    the old token. The new session's absolute lifetime counts from the password login.
//! 3. After 5 wrong codes for one login ([`MfaConfig::max_attempts`]), its session is
//!    revoked and the user has to log in with the password again.
//!
//! A TOTP code is accepted once: each account remembers the newest time step it
//! accepted, and codes for that step or older ones are refused. Codes are compared in
//! constant time, for the current step and one step either way (±30 seconds) by
//! default. A code is used up only once the new session exists, so a login that fails
//! for another reason leaves it valid.
//!
//! # Recovery codes
//!
//! Ten distinct six-digit codes such as `482019` are made when TOTP is confirmed. A code
//! of the same length as a TOTP code is checked as a TOTP code first, then as a recovery
//! code. Six digits are easy to guess from a plain hash, so codes are stored as
//! HMAC-SHA-256 under a key derived from the [`Keyring`](crate::encryption::Keyring),
//! bound to the account: a copy of the database alone does not reveal them. Removing a
//! key from the keyring therefore voids the codes made while it was active; replace them
//! with [`Mfa::regenerate_recovery_codes`] before retiring the key.
//!
//! [`Mfa::regenerate_recovery_codes`] replaces the whole set, and [`Mfa::disable_totp`]
//! deletes the secret and all codes. Both need a current TOTP code or an unused recovery
//! code, which is used up. After 5 wrong codes for such changes, both are refused for 5
//! minutes.
//!
//! # Secrets at rest
//!
//! TOTP secrets are encrypted with the [`Keyring`](crate::encryption::Keyring) the
//! application supplies, bound to the account they belong to. After a key rotation a
//! secret is re-encrypted with the active key the next time it is used to log in. See
//! [`encryption`](crate::encryption).
//!
//! # Defaults
//!
//! | | Default | Set with |
//! |---|---|---|
//! | TOTP algorithm, digits, period | HMAC-SHA-1, 6 digits, 30 seconds | [`TotpConfig`] |
//! | Accepted clock difference | 1 step either way | [`TotpConfig::skew_steps`] |
//! | TOTP secret | 20 bytes (160 bits) | [`TotpConfig::secret_bytes`] |
//! | Recovery codes | 10 per set | [`MfaConfig::recovery_codes`] |
//! | Recovery code length | 6 digits (6 to 12) | [`MfaConfig::recovery_code_digits`] |
//! | Wrong codes per login, and per account for changes in 5 minutes | 5 | [`MfaConfig::max_attempts`] |
//! | Wrong login codes per account across logins, in 1 hour | 20 | [`MfaConfig::max_account_attempts`] |
//!
//! # What the caller still has to do
//!
//! - Call [`start_totp`](Mfa::start_totp), [`confirm_totp`](Mfa::confirm_totp),
//!   [`regenerate_recovery_codes`](Mfa::regenerate_recovery_codes) and
//!   [`disable_totp`](Mfa::disable_totp) only for a fully authenticated session of the
//!   account. The last two take a code from the user.
//! - Rate limit the second step per client address, like login.
//! - With several processes, give [`MfaBuilder::attempts`] an [`AttemptStore`] they
//!   share; the default counts wrong codes in each process separately.
//! - Replace the client's token with the one [`Mfa::complete_login`] returns.
//! - Load the encryption keys and build the keyring; keep the keys backed up, since
//!   secrets cannot be decrypted without them.
//!
//! Secrets, TOTP codes and recovery codes never appear in logs, events, errors or
//! `Debug` output.
//!
//! [`AttemptStore`]: crate::session::AttemptStore

#[cfg(any(test, feature = "test-util"))]
pub mod conformance;
mod error;
mod memory;
mod recovery;
mod service;
mod store;
mod totp;

pub use error::{MfaError, MfaErrorKind};
pub use memory::MemoryMfaStore;
pub use recovery::{
    MAX_RECOVERY_CODE_DIGITS, MAX_RECOVERY_CODES, MIN_RECOVERY_CODE_DIGITS, RecoveryCode,
    RecoveryCodeHash, RecoveryCodes,
};
#[cfg(feature = "local")]
pub(crate) use service::SecondFactor;
pub use service::{Mfa, MfaBuilder, MfaConfig, MfaLogin, MfaStatus, TotpSetup};
pub use store::{MfaStore, TotpRecord};
pub use totp::{
    MAX_TOTP_SECRET_BYTES, MAX_TOTP_SKEW_STEPS, MIN_TOTP_SECRET_BYTES, TotpAlgorithm, TotpConfig,
};
