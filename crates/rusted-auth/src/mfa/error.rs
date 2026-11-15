use crate::session::{BoxError, SessionError, SessionErrorKind, StoreError};
use thiserror::Error;

/// Errors returned by [`Mfa`](super::Mfa).
///
/// Like the other errors of this crate, `Display` is for logs and
/// [`public_message`](Self::public_message) is for clients. Neither ever contains a
/// secret, a code or a recovery code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MfaError {
    /// The code is wrong, malformed or already used, or the recovery code does not exist
    /// or was used.
    #[error("invalid verification code")]
    InvalidCode,

    /// Too many wrong codes were entered for this login. Its session was revoked, so the
    /// user has to log in again with their password.
    #[error("too many verification attempts")]
    TooManyAttempts,

    /// The account has no confirmed TOTP authenticator.
    #[error("two-factor authentication is not enabled")]
    NotEnabled,

    /// The account already has a confirmed TOTP authenticator. Disable it first to set
    /// up another one.
    #[error("two-factor authentication is already enabled")]
    AlreadyEnabled,

    /// There is no unfinished TOTP setup to confirm.
    #[error("no two-factor setup in progress")]
    NoSetupInProgress,

    /// The session of the login is not usable for the second step: unknown, expired,
    /// revoked, already active, or its account was disabled.
    #[error("session: {0}")]
    Session(#[source] SessionError),

    /// The configuration is out of range. Returned by
    /// [`MfaBuilder::build`](super::MfaBuilder::build).
    #[error("invalid MFA configuration: {0}")]
    Config(String),

    /// The storage backend failed.
    #[error("storage error: {0}")]
    Store(#[source] BoxError),

    /// An unexpected internal failure, such as a stored secret that cannot be decrypted
    /// with any key of the keyring, or the system random number generator failing.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Coarse classification of an [`MfaError`], for mapping to a transport status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MfaErrorKind {
    /// The code was rejected; the user may try again (HTTP 401 or 422).
    InvalidCode,
    /// There is no usable login to continue, and the user has to log in again (HTTP 401).
    Unauthenticated,
    /// The account's second factor is not in a state that allows the operation
    /// (HTTP 409).
    Conflict,
    /// Storage, configuration or internal failure (HTTP 500).
    Server,
}

impl MfaError {
    /// The class of failure, for choosing a status code.
    pub fn kind(&self) -> MfaErrorKind {
        match self {
            Self::InvalidCode => MfaErrorKind::InvalidCode,
            Self::TooManyAttempts => MfaErrorKind::Unauthenticated,
            Self::Session(error) => match error.kind() {
                SessionErrorKind::Server => MfaErrorKind::Server,
                _ => MfaErrorKind::Unauthenticated,
            },
            Self::NotEnabled | Self::AlreadyEnabled | Self::NoSetupInProgress => {
                MfaErrorKind::Conflict
            }
            Self::Config(_) | Self::Store(_) | Self::Internal(_) => MfaErrorKind::Server,
        }
    }

    /// `true` when the failure is on the server side rather than caused by the request.
    pub fn is_server_error(&self) -> bool {
        self.kind() == MfaErrorKind::Server
    }

    /// A short message that is safe to return to clients. A wrong, malformed and reused
    /// code all get the same message.
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::InvalidCode => "Invalid verification code",
            Self::TooManyAttempts => "Too many attempts, sign in again",
            Self::NotEnabled => "Two-factor authentication is not enabled",
            Self::AlreadyEnabled => "Two-factor authentication is already enabled",
            Self::NoSetupInProgress => "No two-factor setup in progress",
            Self::Session(error) => match error.kind() {
                SessionErrorKind::Server => error.public_message(),
                _ => "Not authenticated",
            },
            Self::Config(_) | Self::Store(_) | Self::Internal(_) => {
                "Authentication service unavailable"
            }
        }
    }
}

impl From<StoreError> for MfaError {
    fn from(error: StoreError) -> Self {
        Self::Store(Box::new(error))
    }
}

impl From<SessionError> for MfaError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_and_public_messages() {
        assert_eq!(MfaError::InvalidCode.kind(), MfaErrorKind::InvalidCode);
        assert_eq!(
            MfaError::TooManyAttempts.kind(),
            MfaErrorKind::Unauthenticated
        );
        for session in [
            SessionError::Invalid,
            SessionError::Expired,
            SessionError::Revoked,
            SessionError::MfaRequired,
        ] {
            let error = MfaError::from(session);
            assert_eq!(error.kind(), MfaErrorKind::Unauthenticated);
            assert_eq!(error.public_message(), "Not authenticated");
        }
        let error = MfaError::from(SessionError::Store("db at 10.0.0.1 down".into()));
        assert!(error.is_server_error());
        assert!(!error.public_message().contains("10.0.0.1"));

        let error = MfaError::from(StoreError::backend("db at 10.0.0.1 down"));
        assert!(error.is_server_error());
        assert_eq!(error.public_message(), "Authentication service unavailable");
        assert_eq!(MfaError::AlreadyEnabled.kind(), MfaErrorKind::Conflict);
        assert!(!MfaError::InvalidCode.is_server_error());
    }
}
