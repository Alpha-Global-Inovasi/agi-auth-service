//! Hooks for audit events and metrics.

use super::session::{SessionKind, SessionState};
use std::fmt;
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Receives audit events and measurements from this module.
///
/// This is the connection point for an audit log (an `auth_events` table) and for
/// metrics. The crate ships no implementation and depends on no metrics library; without
/// a sink nothing is recorded. Both methods do nothing by default, so implement only the
/// one you need.
///
/// Register a sink with
/// [`SessionManagerBuilder::events`](super::SessionManagerBuilder::events).
/// [`LocalAuth`](super::LocalAuth) reports to the sink of the session manager it was
/// built with, and so does the password hasher it creates. A hasher you build yourself
/// takes its sink from [`PasswordHasher::with_events`](super::PasswordHasher::with_events).
///
/// # Contract
///
/// - Methods are called inline, on the task handling the request or on a password
///   hashing thread. **They must return quickly and must not block**: to write to a
///   database, push the event onto a channel and write from another task.
/// - A sink that panics is caught and logged; the operation that reported the event is
///   not affected.
/// - Events never contain passwords, password hashes, session tokens or token hashes, and
///   never the identifier typed into a failed login (it may be a mistyped password).
///
/// ```rust
/// use rusted_auth::local::{AuthEvent, AuthEventKind, EventSink};
/// use std::sync::atomic::{AtomicU64, Ordering};
///
/// #[derive(Default)]
/// struct LoginCounters {
///     succeeded: AtomicU64,
///     failed: AtomicU64,
/// }
///
/// impl EventSink for LoginCounters {
///     fn auth_event(&self, event: &AuthEvent) {
///         match event.kind {
///             AuthEventKind::LoginSucceeded { .. } => {
///                 self.succeeded.fetch_add(1, Ordering::Relaxed);
///             }
///             AuthEventKind::LoginFailed { .. } => {
///                 self.failed.fetch_add(1, Ordering::Relaxed);
///             }
///             _ => {}
///         }
///     }
/// }
/// ```
pub trait EventSink: Send + Sync + 'static {
    /// Something worth an audit record happened: a login, a lockout, a session being
    /// created or revoked.
    fn auth_event(&self, event: &AuthEvent) {
        let _ = event;
    }

    /// A password hashing request left the queue after `waited`, either to be computed
    /// or, with [`HashQueueOutcome::Rejected`], because it waited too long or the queue
    /// was full. Called once per request; meant for a histogram.
    fn hash_queue_wait(&self, waited: Duration, outcome: HashQueueOutcome) {
        let _ = (waited, outcome);
    }
}

impl<T: EventSink + ?Sized> EventSink for Arc<T> {
    fn auth_event(&self, event: &AuthEvent) {
        (**self).auth_event(event);
    }

    fn hash_queue_wait(&self, waited: Duration, outcome: HashQueueOutcome) {
        (**self).hash_queue_wait(waited, outcome);
    }
}

/// What happened to a password hashing request when it left the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HashQueueOutcome {
    /// A worker picked the request up.
    Started,
    /// The request was refused with [`LocalError::Busy`](super::LocalError::Busy).
    Rejected,
}

/// An event for the audit log, passed to [`EventSink::auth_event`].
///
/// The fields match the columns of an `auth_events` table; [`AuthEventKind::name`] gives
/// the event name and the variant's fields are the metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthEvent {
    /// When it happened.
    pub at: SystemTime,
    /// The account concerned. `None` for a login attempt on an account that does not
    /// exist.
    pub user_id: Option<Uuid>,
    /// Client address, when the caller supplied one.
    pub ip: Option<IpAddr>,
    /// Client `User-Agent`, when the caller supplied one.
    pub user_agent: Option<String>,
    /// What happened.
    pub kind: AuthEventKind,
}

/// What an [`AuthEvent`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthEventKind {
    /// A login with a password succeeded and a session was issued.
    LoginSucceeded {
        /// The new session.
        session_id: Uuid,
    },
    /// A login was rejected.
    LoginFailed {
        /// Why. Never shown to the client.
        reason: LoginFailure,
    },
    /// Repeated failed logins locked the account. Reported in addition to the
    /// [`LoginFailed`](Self::LoginFailed) event of the attempt that caused it.
    AccountLocked {
        /// When the lock ends.
        until: SystemTime,
        /// Consecutive failed logins so far.
        failed_logins: u32,
    },
    /// The stored password hash was replaced during login because it had been made with
    /// outdated parameters.
    PasswordRehashed,
    /// A session was created.
    SessionCreated {
        /// The session.
        session_id: Uuid,
        /// Web or mobile.
        kind: SessionKind,
        /// The state it started in.
        state: SessionState,
    },
    /// A session waiting for its second authentication step became active.
    SessionActivated {
        /// The session.
        session_id: Uuid,
    },
    /// A session was revoked. Revoking several sessions reports one event each.
    SessionRevoked {
        /// The session.
        session_id: Uuid,
    },
}

impl AuthEventKind {
    /// A stable snake_case name for the event, suitable for an `event` column or a
    /// metric label.
    pub fn name(&self) -> &'static str {
        match self {
            Self::LoginSucceeded { .. } => "login_succeeded",
            Self::LoginFailed { .. } => "login_failed",
            Self::AccountLocked { .. } => "account_locked",
            Self::PasswordRehashed => "password_rehashed",
            Self::SessionCreated { .. } => "session_created",
            Self::SessionActivated { .. } => "session_activated",
            Self::SessionRevoked { .. } => "session_revoked",
        }
    }
}

/// Why a login was rejected. For logs and metrics only: the client gets the same message
/// for all of them except an unverified email address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LoginFailure {
    /// No account matches the identifier, or the account has no password.
    UnknownAccount,
    /// The password is wrong.
    WrongPassword,
    /// The account is locked after repeated failures.
    AccountLocked,
    /// The account is disabled.
    AccountDisabled,
    /// The password is right but the email address is not verified.
    EmailNotVerified,
}

impl LoginFailure {
    /// A stable snake_case name, suitable for event metadata or a metric label.
    pub fn name(self) -> &'static str {
        match self {
            Self::UnknownAccount => "unknown_account",
            Self::WrongPassword => "wrong_password",
            Self::AccountLocked => "account_locked",
            Self::AccountDisabled => "account_disabled",
            Self::EmailNotVerified => "email_not_verified",
        }
    }
}

/// The configured sink, if any. Calls are no-ops without one and never propagate a panic.
#[derive(Clone, Default)]
pub(crate) struct Events(Option<Arc<dyn EventSink>>);

impl Events {
    pub(crate) fn new(sink: impl EventSink) -> Self {
        Self(Some(Arc::new(sink)))
    }

    /// Report an event. `build` only runs when a sink is configured.
    pub(crate) fn emit(&self, build: impl FnOnce() -> AuthEvent) {
        if let Some(sink) = &self.0 {
            let event = build();
            guarded(|| sink.auth_event(&event));
        }
    }

    pub(crate) fn hash_queue_wait(&self, waited: Duration, outcome: HashQueueOutcome) {
        if let Some(sink) = &self.0 {
            guarded(|| sink.hash_queue_wait(waited, outcome));
        }
    }
}

impl fmt::Debug for Events {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() {
            "Events(configured)"
        } else {
            "Events(none)"
        })
    }
}

fn guarded(call: impl FnOnce()) {
    if catch_unwind(AssertUnwindSafe(call)).is_err() {
        tracing::error!("auth event sink panicked");
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Mutex;

    /// Collects everything it is given.
    #[derive(Clone, Default)]
    pub(crate) struct Recorder {
        events: Arc<Mutex<Vec<AuthEvent>>>,
        waits: Arc<Mutex<Vec<(Duration, HashQueueOutcome)>>>,
    }

    impl Recorder {
        pub(crate) fn events(&self) -> Vec<AuthEvent> {
            self.events.lock().unwrap().clone()
        }

        /// Event names in order, then forgets them.
        pub(crate) fn take_names(&self) -> Vec<&'static str> {
            let events = std::mem::take(&mut *self.events.lock().unwrap());
            events.iter().map(|e| e.kind.name()).collect()
        }

        pub(crate) fn take(&self) -> Vec<AuthEvent> {
            std::mem::take(&mut *self.events.lock().unwrap())
        }

        pub(crate) fn waits(&self) -> Vec<(Duration, HashQueueOutcome)> {
            self.waits.lock().unwrap().clone()
        }
    }

    impl EventSink for Recorder {
        fn auth_event(&self, event: &AuthEvent) {
            self.events.lock().unwrap().push(event.clone());
        }

        fn hash_queue_wait(&self, waited: Duration, outcome: HashQueueOutcome) {
            self.waits.lock().unwrap().push((waited, outcome));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Panics;

    impl EventSink for Panics {
        fn auth_event(&self, _: &AuthEvent) {
            panic!("sink failure");
        }

        fn hash_queue_wait(&self, _: Duration, _: HashQueueOutcome) {
            panic!("sink failure");
        }
    }

    fn event() -> AuthEvent {
        AuthEvent {
            at: SystemTime::UNIX_EPOCH,
            user_id: None,
            ip: None,
            user_agent: None,
            kind: AuthEventKind::LoginFailed {
                reason: LoginFailure::UnknownAccount,
            },
        }
    }

    #[test]
    fn nothing_is_built_without_a_sink() {
        let events = Events::default();
        events.emit(|| unreachable!("no sink, so the event must not be built"));
        events.hash_queue_wait(Duration::ZERO, HashQueueOutcome::Started);
    }

    #[test]
    fn a_panicking_sink_does_not_reach_the_caller() {
        let events = Events::new(Panics);
        events.emit(event);
        events.hash_queue_wait(Duration::ZERO, HashQueueOutcome::Rejected);
    }

    #[test]
    fn shared_sinks_and_names() {
        let recorder = Arc::new(testing::Recorder::default());
        let events = Events::new(Arc::clone(&recorder));
        events.emit(event);
        assert_eq!(recorder.events(), vec![event()]);
        assert_eq!(event().kind.name(), "login_failed");
        assert_eq!(LoginFailure::WrongPassword.name(), "wrong_password");

        // The default methods do nothing.
        struct Silent;
        impl EventSink for Silent {}
        Events::new(Silent).emit(event);
    }
}
