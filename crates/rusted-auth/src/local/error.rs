use std::time::SystemTime;
use thiserror::Error;

/// Boxed error from a storage backend.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors returned by local registration and login.
///
/// The `Display` output is meant for logs. Use [`LocalError::public_message`] for anything
/// sent to a client: it gives the same text for a wrong password, an unknown account, a
/// locked account and a disabled account, so a response cannot be used to find out which
/// accounts exist.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LocalError {
    /// The account does not exist, has no password, or the password is wrong.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// The account is temporarily locked after repeated failed logins.
    #[error("account is locked")]
    AccountLocked {
        /// When the lock ends.
        until: SystemTime,
    },

    /// The account has been disabled.
    #[error("account is disabled")]
    AccountDisabled,

    /// The username is not 3 to 32 characters of ASCII letters, digits, `.`, `_` or `-`
    /// starting with a letter or digit.
    #[error("invalid username")]
    InvalidUsername,

    /// The email address is not well formed.
    #[error("invalid email address")]
    InvalidEmail,

    /// The display name is too long or contains control characters.
    #[error("invalid name")]
    InvalidName,

    /// The password has fewer than [`MIN_PASSWORD_CHARS`](super::MIN_PASSWORD_CHARS)
    /// characters.
    #[error("password is too short")]
    PasswordTooShort,

    /// The password has more than [`MAX_PASSWORD_CHARS`](super::MAX_PASSWORD_CHARS)
    /// characters.
    #[error("password is too long")]
    PasswordTooLong,

    /// Another account already uses this username.
    #[error("username is already taken")]
    UsernameTaken,

    /// Another account already uses this email address.
    ///
    /// Only returned when the application opted in with
    /// [`LocalAuthBuilder::reveal_existing_email`](super::LocalAuthBuilder::reveal_existing_email).
    #[error("email is already registered")]
    EmailTaken,

    /// Too many passwords are being hashed; the request waited too long or the queue is
    /// full. Adapters answer with HTTP 503.
    #[error("password hashing is at capacity")]
    Busy,

    /// The storage backend failed.
    #[error("storage error: {0}")]
    Store(#[source] BoxError),

    /// An unexpected internal failure, such as a stored hash that cannot be parsed.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Coarse classification of a [`LocalError`], for mapping to a transport status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LocalErrorKind {
    /// The login was rejected (HTTP 401).
    Credentials,
    /// The input does not satisfy a format or length rule (HTTP 422 or 400).
    Validation,
    /// The username or email is already in use (HTTP 409).
    Conflict,
    /// The service is at capacity (HTTP 503).
    Busy,
    /// Storage or internal failure (HTTP 500).
    Server,
}

impl LocalError {
    /// The class of failure, for choosing a status code.
    pub fn kind(&self) -> LocalErrorKind {
        match self {
            Self::InvalidCredentials | Self::AccountLocked { .. } | Self::AccountDisabled => {
                LocalErrorKind::Credentials
            }
            Self::InvalidUsername
            | Self::InvalidEmail
            | Self::InvalidName
            | Self::PasswordTooShort
            | Self::PasswordTooLong => LocalErrorKind::Validation,
            Self::UsernameTaken | Self::EmailTaken => LocalErrorKind::Conflict,
            Self::Busy => LocalErrorKind::Busy,
            Self::Store(_) | Self::Internal(_) => LocalErrorKind::Server,
        }
    }

    /// `true` when the failure is on the server side rather than caused by the request.
    pub fn is_server_error(&self) -> bool {
        matches!(self.kind(), LocalErrorKind::Busy | LocalErrorKind::Server)
    }

    /// A short message that is safe to return to clients.
    ///
    /// It never contains storage errors or other internals, and every rejected login gets
    /// the same message whatever the reason.
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::InvalidCredentials | Self::AccountLocked { .. } | Self::AccountDisabled => {
                "Invalid username or password"
            }
            Self::InvalidUsername => {
                "Username must be 3 to 32 characters: letters, digits, '.', '_' or '-'"
            }
            Self::InvalidEmail => "Invalid email address",
            Self::InvalidName => "Invalid name",
            Self::PasswordTooShort => "Password must be at least 8 characters",
            Self::PasswordTooLong => "Password must be at most 128 characters",
            Self::UsernameTaken => "Username is already taken",
            Self::EmailTaken => "Email is already registered",
            Self::Busy => "Service is busy, try again shortly",
            Self::Store(_) | Self::Internal(_) => "Authentication service unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_logins_share_one_public_message() {
        let locked = LocalError::AccountLocked {
            until: SystemTime::now(),
        };
        let expected = LocalError::InvalidCredentials.public_message();
        assert_eq!(locked.public_message(), expected);
        assert_eq!(LocalError::AccountDisabled.public_message(), expected);
        assert_eq!(locked.kind(), LocalErrorKind::Credentials);
    }

    #[test]
    fn public_message_hides_internals() {
        let e = LocalError::Store("connection to 10.0.0.1 refused".into());
        assert_eq!(e.public_message(), "Authentication service unavailable");
        assert!(e.is_server_error());

        let e = LocalError::Internal("stored hash is malformed".into());
        assert_eq!(e.public_message(), "Authentication service unavailable");
        assert_eq!(e.kind(), LocalErrorKind::Server);
    }

    #[test]
    fn kinds_separate_client_and_server_failures() {
        assert_eq!(LocalError::Busy.kind(), LocalErrorKind::Busy);
        assert!(LocalError::Busy.is_server_error());
        assert_eq!(
            LocalError::PasswordTooShort.kind(),
            LocalErrorKind::Validation
        );
        assert_eq!(LocalError::UsernameTaken.kind(), LocalErrorKind::Conflict);
        assert!(!LocalError::InvalidCredentials.is_server_error());
    }
}
