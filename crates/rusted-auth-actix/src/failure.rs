//! [`AuthFailure`]: every error this crate answers, with its status, code and message.

// Helpers for the routes of the `local` feature.
#![cfg_attr(not(feature = "local"), allow(dead_code))]

use actix_web::http::StatusCode;
use rusted_auth::AuthError;
use serde_json::{Map, Value};
use std::fmt;
use std::time::Duration;

#[cfg(feature = "local")]
use rusted_auth::local::{LocalError, LocalErrorKind};
#[cfg(feature = "mfa")]
use rusted_auth::mfa::MfaError;
#[cfg(feature = "session")]
use rusted_auth::session::{SessionError, SessionErrorKind};

type Source = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A failed request, ready to be turned into a response by an
/// [`AuthResponder`](crate::AuthResponder).
///
/// It wraps the errors of `rusted-auth` (token verification, sessions, local accounts,
/// second factors) and the adapter's own (CSRF, rate limits, unreadable bodies), and
/// says how to answer them:
///
/// - [`status`](Self::status): the HTTP status.
/// - [`code`](Self::code): a stable `snake_case` identifier for clients, such as
///   `invalid_credentials` or `validation_failed`.
/// - [`public_message`](Self::public_message): a short English text that is safe to
///   show. It never says whether an account exists and never contains internals.
/// - [`field_errors`](Self::field_errors): for 422, what is wrong with which input.
/// - [`retry_after`](Self::retry_after): for 429 and 503, when to try again.
///
/// The `Display` output includes the underlying error and is for logs only.
#[derive(Debug)]
pub struct AuthFailure {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    fields: Vec<FieldError>,
    retry_after: Option<Duration>,
    challenge: Option<&'static str>,
    source: Option<Source>,
}

/// One problem with one input field of a request, for 422 responses.
///
/// Serializes as `{ "code": "...", "message": "...", "params": { ... } }`, the entry
/// format of the `errors` member in the default responder.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FieldError {
    /// The field, as named in the request body, such as `password`.
    #[serde(skip)]
    pub field: &'static str,
    /// Stable identifier: `invalid`, `too_short`, `too_long`, `taken` or `incorrect`.
    pub code: &'static str,
    /// English fallback text.
    pub message: &'static str,
    /// Values for building a message, such as `{ "min": 8 }`.
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub params: Map<String, Value>,
}

impl FieldError {
    fn new(field: &'static str, code: &'static str, message: &'static str) -> Self {
        Self {
            field,
            code,
            message,
            params: Map::new(),
        }
    }

    #[cfg(feature = "local")]
    fn param(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.params.insert(name.to_owned(), value.into());
        self
    }
}

impl AuthFailure {
    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            fields: Vec::new(),
            retry_after: None,
            challenge: None,
            source: None,
        }
    }

    fn with_source(mut self, source: impl Into<Source>) -> Self {
        self.source = Some(source.into());
        self
    }

    fn validation(field: FieldError) -> Self {
        let mut failure = Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            "Validation failed",
        );
        failure.fields.push(field);
        failure
    }

    fn internal(source: impl Into<Source>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Authentication service unavailable",
        )
        .with_source(source)
    }

    /// The HTTP status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Stable identifier for clients.
    ///
    /// | Code | Status |
    /// |---|---|
    /// | `invalid_credentials` | 401 |
    /// | `unauthenticated`, `mfa_required`, `invalid_code`, `mfa_attempts_exceeded` | 401 |
    /// | `email_not_verified`, `csrf_failed` | 403 |
    /// | `not_found` | 404 |
    /// | `mfa_already_enabled`, `mfa_not_enabled`, `mfa_setup_not_started` | 409 |
    /// | `invalid_token`, `bad_request` | 400 |
    /// | `validation_failed` | 422 |
    /// | `too_many_attempts`, `rate_limited` | 429 |
    /// | `internal` | 500 |
    /// | `busy`, `unavailable` | 503 |
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Short English text that is safe to send to the client.
    pub fn public_message(&self) -> &'static str {
        self.message
    }

    /// What is wrong with which field; only for `validation_failed`.
    pub fn field_errors(&self) -> &[FieldError] {
        &self.fields
    }

    /// How long the client should wait before trying again, for 429 and 503.
    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// `true` for failures on the server's side (5xx).
    pub fn is_server_error(&self) -> bool {
        self.status.is_server_error()
    }

    /// The `WWW-Authenticate` challenge for 401 answers to bearer-token requests.
    pub(crate) fn challenge(&self) -> Option<&'static str> {
        self.challenge
    }

    pub(crate) fn with_challenge(mut self, challenge: &'static str) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// The request failed the `Origin` or CSRF token check.
    pub(crate) fn csrf(reason: &'static str) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "csrf_failed",
            "Request could not be verified",
        )
        .with_source(reason)
    }

    /// Too many requests from the client's address.
    pub(crate) fn rate_limited(retry_after: Duration) -> Self {
        let mut failure = Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many requests, try again later",
        );
        failure.retry_after = Some(retry_after);
        failure
    }

    /// A store needed to answer the request is unreachable.
    pub(crate) fn unavailable(source: impl Into<Source>) -> Self {
        let mut failure = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Authentication service unavailable",
        )
        .with_source(source);
        failure.retry_after = Some(Duration::from_secs(1));
        failure
    }

    /// The body or query could not be read.
    pub(crate) fn bad_request(source: impl Into<Source>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", "Malformed request").with_source(source)
    }

    /// There is no usable session.
    #[cfg(feature = "session")]
    pub(crate) fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Not authenticated",
        )
    }

    #[cfg(feature = "local")]
    pub(crate) fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "Not found")
    }

    /// A wrong second-factor code on an operation of a signed-in user.
    #[cfg(feature = "mfa")]
    fn wrong_code() -> Self {
        Self::validation(FieldError::new(
            "code",
            "invalid",
            "Invalid verification code",
        ))
    }

    /// An error of [`LocalAuth`](rusted_auth::local::LocalAuth), for a request whose
    /// new password, if it has one, is in the field `password_field`.
    ///
    /// Wrong credentials are 401; for a password change use
    /// [`change_password`](Self::change_password) instead.
    #[cfg(feature = "local")]
    pub fn local(error: LocalError, password_field: &'static str) -> Self {
        let field = |name, code, message| Self::validation(FieldError::new(name, code, message));
        let failure = match &error {
            LocalError::EmailNotVerified => Self::new(
                StatusCode::FORBIDDEN,
                "email_not_verified",
                error.public_message(),
            ),
            LocalError::InvalidUsername => field("username", "invalid", error.public_message()),
            LocalError::InvalidEmail => field("email", "invalid", error.public_message()),
            LocalError::InvalidName => field("name", "invalid", error.public_message()),
            LocalError::PasswordTooShort { min } => Self::validation(
                FieldError::new(password_field, "too_short", error.public_message())
                    .param("min", *min),
            ),
            LocalError::PasswordTooLong { max } => Self::validation(
                FieldError::new(password_field, "too_long", error.public_message())
                    .param("max", *max),
            ),
            LocalError::UsernameTaken => field("username", "taken", error.public_message()),
            LocalError::EmailTaken => field("email", "taken", error.public_message()),
            LocalError::UsernameCheckDisabled => Self::not_found(),
            LocalError::TooManyAttempts => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_attempts",
                error.public_message(),
            ),
            _ => match error.kind() {
                LocalErrorKind::Credentials => Self::new(
                    StatusCode::UNAUTHORIZED,
                    "invalid_credentials",
                    error.public_message(),
                ),
                LocalErrorKind::Token => Self::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_token",
                    error.public_message(),
                ),
                LocalErrorKind::Busy => {
                    let mut failure = Self::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "busy",
                        error.public_message(),
                    );
                    failure.retry_after = Some(Duration::from_secs(1));
                    failure
                }
                _ => Self::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    error.public_message(),
                ),
            },
        };
        failure.with_source(error)
    }

    /// An error of `LocalAuth::change_password`. The caller is signed in, so a wrong
    /// current password is a 422 on `current_password` rather than a 401, which would
    /// read as a lost session.
    #[cfg(feature = "local")]
    pub fn change_password(error: LocalError) -> Self {
        match error {
            LocalError::InvalidCredentials => Self::validation(FieldError::new(
                "current_password",
                "incorrect",
                "Current password is incorrect",
            ))
            .with_source(error),
            error => Self::local(error, "new_password"),
        }
    }

    /// An error of the second login step (`Mfa::complete_login`): a wrong code is 401
    /// `invalid_code`, too many of them 401 `mfa_attempts_exceeded`.
    #[cfg(feature = "mfa")]
    pub fn mfa_login(error: MfaError) -> Self {
        let failure = match &error {
            MfaError::InvalidCode => Self::new(
                StatusCode::UNAUTHORIZED,
                "invalid_code",
                error.public_message(),
            ),
            MfaError::TooManyAttempts => Self::new(
                StatusCode::UNAUTHORIZED,
                "mfa_attempts_exceeded",
                error.public_message(),
            ),
            MfaError::Session(_) if !error.is_server_error() => Self::unauthenticated(),
            _ => return Self::mfa_change(error),
        };
        failure.with_source(error)
    }

    /// An error of an operation on the signed-in user's second factor: a wrong code is
    /// 422 on `code`, too many of them 429.
    #[cfg(feature = "mfa")]
    pub fn mfa_change(error: MfaError) -> Self {
        let failure = match &error {
            MfaError::InvalidCode => Self::wrong_code(),
            MfaError::TooManyAttempts => {
                let mut failure = Self::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too_many_attempts",
                    error.public_message(),
                );
                // ADR-0014: changes are refused for 5 minutes after too many codes.
                failure.retry_after = Some(Duration::from_secs(300));
                failure
            }
            MfaError::AlreadyEnabled => Self::new(
                StatusCode::CONFLICT,
                "mfa_already_enabled",
                error.public_message(),
            ),
            MfaError::NotEnabled => Self::new(
                StatusCode::CONFLICT,
                "mfa_not_enabled",
                error.public_message(),
            ),
            MfaError::NoSetupInProgress => Self::new(
                StatusCode::CONFLICT,
                "mfa_setup_not_started",
                error.public_message(),
            ),
            MfaError::Session(_) if !error.is_server_error() => Self::unauthenticated(),
            _ => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                error.public_message(),
            ),
        };
        failure.with_source(error)
    }
}

#[cfg(feature = "session")]
impl From<SessionError> for AuthFailure {
    /// No usable session is 401 `unauthenticated`; a session that still waits for its
    /// second factor is 401 `mfa_required`.
    fn from(error: SessionError) -> Self {
        let failure = match error.kind() {
            SessionErrorKind::MfaRequired => Self::new(
                StatusCode::UNAUTHORIZED,
                "mfa_required",
                error.public_message(),
            ),
            SessionErrorKind::Server => return Self::internal(error),
            _ => Self::unauthenticated(),
        };
        failure.with_source(error)
    }
}

impl From<AuthError> for AuthFailure {
    /// Token verification: 503 when the issuer's keys cannot be fetched, 500 for
    /// misconfiguration, 401 `unauthenticated` otherwise, with a bearer challenge.
    fn from(error: AuthError) -> Self {
        let failure = match &error {
            AuthError::KeysUnavailable(_) => {
                let mut failure = Self::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "unavailable",
                    error.public_message(),
                );
                failure.retry_after = Some(Duration::from_secs(1));
                failure
            }
            e if e.is_server_error() => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                error.public_message(),
            ),
            AuthError::MissingCredentials => Self::new(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                error.public_message(),
            )
            .with_challenge("Bearer"),
            _ => Self::new(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                error.public_message(),
            )
            .with_challenge("Bearer error=\"invalid_token\""),
        };
        failure.with_source(error)
    }
}

impl fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code, self.status.as_u16())?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AuthFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}
