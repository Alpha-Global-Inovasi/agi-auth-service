use thiserror::Error;

/// Boxed error from a storage backend.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors returned when a session is created, validated or revoked.
///
/// The `Display` output is for logs and
/// [`SessionError::public_message`] is for clients. An unknown token, an expired session,
/// a revoked session and a session of a disabled account all get the same public message.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The token is malformed, or no session exists for it.
    #[error("invalid session token")]
    Invalid,

    /// The session was idle for too long or reached its absolute lifetime.
    #[error("session has expired")]
    Expired,

    /// The session was revoked, for example by logging out.
    #[error("session has been revoked")]
    Revoked,

    /// The account the session belongs to has been disabled.
    #[error("account is disabled")]
    UserDisabled,

    /// The session exists but its second authentication step has not been completed, so
    /// it cannot be used yet.
    #[error("session is waiting for multi-factor authentication")]
    MfaRequired,

    /// The storage backend failed.
    #[error("storage error: {0}")]
    Store(#[source] BoxError),

    /// An unexpected internal failure, such as the system random number generator being
    /// unavailable.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Coarse classification of a [`SessionError`], for mapping to a transport status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionErrorKind {
    /// There is no usable session (HTTP 401).
    Unauthenticated,
    /// The session still needs its second authentication step (HTTP 401 or 403, with a
    /// hint for the client to continue with that step).
    MfaRequired,
    /// Storage or internal failure (HTTP 500).
    Server,
}

impl SessionError {
    /// The class of failure, for choosing a status code.
    pub fn kind(&self) -> SessionErrorKind {
        match self {
            Self::Invalid | Self::Expired | Self::Revoked | Self::UserDisabled => {
                SessionErrorKind::Unauthenticated
            }
            Self::MfaRequired => SessionErrorKind::MfaRequired,
            Self::Store(_) | Self::Internal(_) => SessionErrorKind::Server,
        }
    }

    /// `true` when the failure is on the server side rather than caused by the request.
    pub fn is_server_error(&self) -> bool {
        self.kind() == SessionErrorKind::Server
    }

    /// A short message that is safe to return to clients. It does not say why a session
    /// was refused, and never contains storage errors or other internals.
    pub fn public_message(&self) -> &'static str {
        match self.kind() {
            SessionErrorKind::Unauthenticated => "Not authenticated",
            SessionErrorKind::MfaRequired => "Additional verification required",
            SessionErrorKind::Server => "Authentication service unavailable",
        }
    }
}
