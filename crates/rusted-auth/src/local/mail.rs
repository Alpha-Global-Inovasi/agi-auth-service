//! The emails local accounts send, and the [`Mailer`] that delivers them.

use crate::session::attempts::BoxFuture;
use crate::session::{BoxError, EmailKind, OneTimeToken, User};
use std::future::Future;
use std::time::SystemTime;

/// An email [`LocalAuth`](super::LocalAuth) wants sent to an account owner.
///
/// The library decides when to send what; the application renders the text (for
/// example with a Handlebars template) and builds links from the tokens, since only it
/// knows the address of its front end. Every field is about the receiving account:
/// nothing typed by whoever caused the email (a username, a name, a `User-Agent`) is
/// included, so it cannot be used to put text in someone else's inbox.
///
/// The `Debug` output does not contain tokens.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthEmail {
    /// Asks the owner to verify the address, after registration or when asked again.
    VerifyEmail {
        /// The receiving account. Send to `to.email`.
        to: User,
        /// Put this in the verification link; it goes back to
        /// [`LocalAuth::verify_email`](super::LocalAuth::verify_email).
        token: OneTimeToken,
        /// When the link stops working.
        expires_at: SystemTime,
    },
    /// A password reset link, after
    /// [`LocalAuth::request_password_reset`](super::LocalAuth::request_password_reset).
    PasswordReset {
        /// The receiving account. Send to `to.email`.
        to: User,
        /// Put this in the reset link; it goes back to
        /// [`LocalAuth::reset_password`](super::LocalAuth::reset_password).
        token: OneTimeToken,
        /// When the link stops working.
        expires_at: SystemTime,
    },
    /// The account was locked after repeated failed logins. Sent once per series of
    /// failures, at the first lock.
    AccountLocked {
        /// The receiving account. Send to `to.email`.
        to: User,
        /// When the lock ends.
        until: SystemTime,
    },
    /// Someone tried to register a new account with this address. The owner may want to
    /// sign in or reset the password instead.
    RegistrationAttempt {
        /// The existing account. Send to `to.email`.
        to: User,
    },
    /// The password was changed or reset. A security notice for the owner.
    PasswordChanged {
        /// The receiving account. Send to `to.email`.
        to: User,
        /// Whether it was changed from a session or reset with a link.
        via: PasswordChangeVia,
        /// When it happened.
        at: SystemTime,
    },
}

/// How a password was changed, for the wording of [`AuthEmail::PasswordChanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PasswordChangeVia {
    /// From a signed-in session, with the current password.
    Change,
    /// With a reset link.
    Reset,
}

impl AuthEmail {
    /// The receiving account.
    pub fn recipient(&self) -> &User {
        match self {
            Self::VerifyEmail { to, .. }
            | Self::PasswordReset { to, .. }
            | Self::AccountLocked { to, .. }
            | Self::RegistrationAttempt { to }
            | Self::PasswordChanged { to, .. } => to,
        }
    }

    /// Which email this is, for logs, metrics and choosing a template.
    pub fn kind(&self) -> EmailKind {
        match self {
            Self::VerifyEmail { .. } => EmailKind::VerifyEmail,
            Self::PasswordReset { .. } => EmailKind::PasswordReset,
            Self::AccountLocked { .. } => EmailKind::AccountLocked,
            Self::RegistrationAttempt { .. } => EmailKind::RegistrationAttempt,
            Self::PasswordChanged { .. } => EmailKind::PasswordChanged,
        }
    }

    /// The link token, for the emails that carry one.
    pub fn token(&self) -> Option<&OneTimeToken> {
        match self {
            Self::VerifyEmail { token, .. } | Self::PasswordReset { token, .. } => Some(token),
            _ => None,
        }
    }
}

/// Delivers the emails of local accounts. The `rusted-email` crate, or any other mail
/// library, sits behind it.
///
/// Required by [`LocalAuthBuilder::mailer`](super::LocalAuthBuilder::mailer). An
/// application that sends no email at all, such as a development setup with
/// `require_verified_email(false)`, passes [`NoMailer`].
///
/// # Contract
///
/// **`send` returns quickly and does not wait for delivery.** Put the email on a queue
/// (a job table, a channel read by another task) and deliver it from there. Several
/// operations send an email only when an account exists (a password reset, a
/// registration with a known address, a login that locks an account), so a `send` that
/// waits for an SMTP server makes those responses slower for registered addresses and
/// tells anyone with a stopwatch who has an account.
///
/// An error from `send` is logged and reported as
/// [`AuthEventKind::EmailSendFailed`](crate::session::AuthEventKind::EmailSendFailed);
/// the operation that sent the email still succeeds, for the same reason. The library
/// does not retry. Tokens in the email must not be logged.
///
/// ```rust
/// use rusted_auth::local::{AuthEmail, Mailer};
/// use rusted_auth::session::BoxError;
///
/// struct Queue(std::sync::mpsc::Sender<AuthEmail>);
///
/// impl Mailer for Queue {
///     async fn send(&self, email: AuthEmail) -> Result<(), BoxError> {
///         // Hand the email to a worker that renders and delivers it.
///         self.0.send(email).map_err(|_| "mail queue is closed".into())
///     }
/// }
/// ```
pub trait Mailer: Send + Sync + 'static {
    /// Queue `email` for delivery.
    fn send(&self, email: AuthEmail) -> impl Future<Output = Result<(), BoxError>> + Send;
}

/// A [`Mailer`] that sends nothing, for applications that deliberately send no email.
///
/// With it, new accounts never receive a verification link, so they can only log in
/// with [`require_verified_email(false)`](super::LocalAuthBuilder::require_verified_email)
/// or when the application verifies addresses itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoMailer;

impl Mailer for NoMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), BoxError> {
        tracing::debug!(
            email = email.kind().name(),
            "no mailer configured; email dropped"
        );
        Ok(())
    }
}

/// A [`Mailer`] that keeps every email in memory, for tests.
///
/// Available with the `test-util` cargo feature. Clones share the same emails.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, Default)]
pub struct RecordingMailer {
    state: std::sync::Arc<std::sync::Mutex<Recorded>>,
}

#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Default)]
struct Recorded {
    emails: Vec<AuthEmail>,
    fail: bool,
}

#[cfg(any(test, feature = "test-util"))]
impl RecordingMailer {
    /// A mailer that accepts every email.
    pub fn new() -> Self {
        Self::default()
    }

    /// Refuse every following email with an error (`true`), or accept them again.
    /// Refused emails are not kept.
    pub fn fail(&self, fail: bool) {
        self.lock().fail = fail;
    }

    /// Remove and return the emails received so far, oldest first.
    pub fn take(&self) -> Vec<AuthEmail> {
        std::mem::take(&mut self.lock().emails)
    }

    /// Number of emails received and not yet taken.
    pub fn len(&self) -> usize {
        self.lock().emails.len()
    }

    /// `true` when no email is waiting to be taken.
    pub fn is_empty(&self) -> bool {
        self.lock().emails.is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Recorded> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Mailer for RecordingMailer {
    async fn send(&self, email: AuthEmail) -> Result<(), BoxError> {
        let mut state = self.lock();
        if state.fail {
            return Err("mail queue is unavailable".into());
        }
        state.emails.push(email);
        Ok(())
    }
}

/// [`Mailer`] without its type, so that [`LocalAuth`](super::LocalAuth) keeps two type
/// parameters.
pub(crate) trait DynMailer: Send + Sync {
    fn dyn_send(&self, email: AuthEmail) -> BoxFuture<'_, Result<(), BoxError>>;
}

impl<M: Mailer> DynMailer for M {
    fn dyn_send(&self, email: AuthEmail) -> BoxFuture<'_, Result<(), BoxError>> {
        Box::pin(Mailer::send(self, email))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "budi".into(),
            email: "budi@example.com".into(),
            email_verified_at: None,
            name: "Budi".into(),
            disabled_at: None,
        }
    }

    #[test]
    fn debug_output_hides_the_token() {
        let token = OneTimeToken::generate().unwrap();
        let text = token.expose().to_owned();
        let email = AuthEmail::PasswordReset {
            to: user(),
            token,
            expires_at: SystemTime::now(),
        };
        let debug = format!("{email:?}");
        assert!(!debug.contains(&text[9..]), "{debug}");
        assert_eq!(email.kind(), EmailKind::PasswordReset);
        assert_eq!(email.recipient().username, "budi");
        assert_eq!(email.token().unwrap().expose(), text);
    }

    #[tokio::test]
    async fn recording_mailer_keeps_or_refuses_emails() {
        let mailer = RecordingMailer::new();
        let locked = || AuthEmail::AccountLocked {
            to: user(),
            until: SystemTime::now(),
        };
        mailer.send(locked()).await.unwrap();
        mailer.fail(true);
        assert!(mailer.send(locked()).await.is_err());
        assert_eq!(mailer.len(), 1);
        assert_eq!(mailer.take().len(), 1);
        assert!(mailer.is_empty());
        NoMailer.send(locked()).await.unwrap();
    }
}
