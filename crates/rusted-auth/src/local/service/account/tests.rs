use super::*;
use crate::local::{
    EmailPolicy, HashLimits, LocalErrorKind, PasswordChangePolicy, PasswordHasher, RecordingMailer,
    Registration,
};
use crate::session::event::testing::Recorder;
use crate::session::{
    AttemptStore, MemoryAttemptStore, MemoryOneTimeTokenStore, MemorySessionStore, MemoryUserStore,
    SessionManager, SessionState, StoreError,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a whole new passphrase";

type TestAuth = LocalAuth<MemoryUserStore, MemorySessionStore>;

/// A clock the test moves by hand.
#[derive(Clone)]
struct TestClock(Arc<Mutex<SystemTime>>);

impl TestClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

struct Fixture {
    auth: TestAuth,
    users: MemoryUserStore,
    sessions: MemorySessionStore,
    tokens: MemoryOneTimeTokenStore,
    attempts: MemoryAttemptStore,
    mailer: RecordingMailer,
    recorder: Recorder,
    clock: TestClock,
}

fn fixture() -> Fixture {
    fixture_with(|builder| builder)
}

fn fixture_with(
    configure: impl FnOnce(
        super::super::LocalAuthBuilder<MemoryUserStore, MemorySessionStore>,
    ) -> super::super::LocalAuthBuilder<MemoryUserStore, MemorySessionStore>,
) -> Fixture {
    let clock = TestClock(Arc::new(Mutex::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    )));
    let recorder = Recorder::default();
    let users = MemoryUserStore::new();
    let sessions = MemorySessionStore::new(users.clone());
    let tokens = MemoryOneTimeTokenStore::new();
    let attempts = MemoryAttemptStore::new();
    let mailer = RecordingMailer::new();
    let for_sessions = clock.clone();
    let manager = SessionManager::builder(sessions.clone())
        .events(recorder.clone())
        .clock(move || for_sessions.now())
        .build();
    let for_auth = clock.clone();
    let builder = LocalAuth::builder(users.clone(), manager)
        .mailer(mailer.clone())
        .tokens(tokens.clone())
        .attempts(attempts.clone())
        .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
        .clock(move || for_auth.now());
    Fixture {
        auth: configure(builder).build().unwrap(),
        users,
        sessions,
        tokens,
        attempts,
        mailer,
        recorder,
        clock,
    }
}

fn registration(username: &str, email: &str) -> Registration {
    Registration {
        username: username.into(),
        email: email.into(),
        name: "Budi Santoso".into(),
        password: PASSWORD.into(),
    }
}

impl Fixture {
    /// Register budi and return the account and the token of the verification email.
    async fn register(&self) -> (User, String) {
        let outcome = self
            .auth
            .register(registration("budi", "budi@example.com"))
            .await
            .unwrap();
        let user = outcome.created().unwrap().clone();
        let mut emails = self.mailer.take();
        assert_eq!(emails.len(), 1);
        let email = emails.remove(0);
        assert_eq!(email.kind(), EmailKind::VerifyEmail);
        assert_eq!(email.recipient().id, user.id);
        (user, email.token().unwrap().expose().to_owned())
    }

    /// Register budi and verify the address.
    async fn verified(&self) -> User {
        let (_, token) = self.register().await;
        self.auth
            .verify_email(&token, SessionContext::web())
            .await
            .unwrap()
    }

    async fn login(&self, password: &str) -> Result<crate::local::Login, LocalError> {
        self.auth
            .login("budi", password, SessionContext::web())
            .await
    }

    async fn validate(&self, token: &str) -> AuthenticatedSession {
        self.auth.sessions().validate(token).await.unwrap()
    }

    async fn request_reset(&self) -> String {
        self.auth
            .request_password_reset("budi@example.com", SessionContext::web())
            .await
            .unwrap();
        let mut emails = self.mailer.take();
        assert_eq!(emails.len(), 1, "one reset email");
        let email = emails.remove(0);
        assert_eq!(email.kind(), EmailKind::PasswordReset);
        email.token().unwrap().expose().to_owned()
    }

    fn event_names(&self) -> Vec<&'static str> {
        self.recorder.take_names()
    }
}

#[tokio::test]
async fn the_builder_requires_a_mailer_and_a_token_store() {
    let users = MemoryUserStore::new();
    let sessions = || SessionManager::new(MemorySessionStore::new(users.clone()));
    let hasher = || PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap();

    let no_mailer = LocalAuth::builder(users.clone(), sessions())
        .tokens(MemoryOneTimeTokenStore::new())
        .hasher(hasher())
        .build();
    assert!(matches!(no_mailer, Err(LocalError::Configuration(_))));
    let no_tokens = LocalAuth::builder(users.clone(), sessions())
        .mailer(crate::local::NoMailer)
        .hasher(hasher())
        .build();
    let error = no_tokens.unwrap_err();
    assert!(matches!(error, LocalError::Configuration(_)));
    assert_eq!(error.kind(), LocalErrorKind::Server);
    assert_eq!(error.public_message(), "Authentication service unavailable");
}

#[tokio::test]
async fn registration_sends_a_link_that_verifies_the_address_once() {
    let f = fixture();
    let (user, token) = f.register().await;
    assert!(token.starts_with("rusted_t_"));
    let stored = f.tokens.tokens_for(user.id);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].email, "budi@example.com");
    assert_eq!(
        stored[0].expires_at,
        f.clock.now() + Duration::from_secs(24 * 60 * 60)
    );
    assert!(matches!(
        f.login(PASSWORD).await,
        Err(LocalError::EmailNotVerified)
    ));
    f.recorder.take();

    let verified = f
        .auth
        .verify_email(&token, SessionContext::web())
        .await
        .unwrap();
    assert_eq!(verified.email_verified_at, Some(f.clock.now()));
    assert!(f.sessions.is_empty(), "verification does not sign in");
    assert_eq!(f.event_names(), ["email_verified"]);

    let again = f.auth.verify_email(&token, SessionContext::web()).await;
    assert!(matches!(again, Err(LocalError::InvalidToken)));
    assert_eq!(
        LocalError::InvalidToken.kind(),
        LocalErrorKind::Token,
        "a distinct status for links"
    );
    assert!(f.login(PASSWORD).await.is_ok());
}

#[tokio::test]
async fn malformed_expired_and_foreign_tokens_are_rejected_alike() {
    let f = fixture();
    let (user, token) = f.register().await;
    for wrong in [
        "",
        "rusted_t_short",
        "rusted_s_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        let result = f.auth.verify_email(wrong, SessionContext::web()).await;
        assert!(matches!(result, Err(LocalError::InvalidToken)), "{wrong}");
    }
    // A verification token does not reset a password.
    let reset = f
        .auth
        .reset_password(&token, NEW_PASSWORD, SessionContext::web())
        .await;
    assert!(matches!(reset, Err(LocalError::InvalidToken)));

    f.clock.advance(Duration::from_secs(24 * 60 * 60));
    let expired = f.auth.verify_email(&token, SessionContext::web()).await;
    assert!(matches!(expired, Err(LocalError::InvalidToken)));
    assert_eq!(f.users.get(user.id).unwrap().user.email_verified_at, None);
}

#[tokio::test]
async fn a_token_stops_working_when_the_address_changes() {
    let f = fixture();
    let (user, token) = f.register().await;
    f.users
        .update(user.id, |r| r.user.email = "other@example.com".into());

    let result = f.auth.verify_email(&token, SessionContext::web()).await;
    assert!(matches!(result, Err(LocalError::InvalidToken)));
    assert_eq!(f.users.get(user.id).unwrap().user.email_verified_at, None);
}

#[tokio::test]
async fn resending_verification_only_mails_unverified_accounts() {
    let f = fixture();
    let context = SessionContext::web;
    f.auth
        .resend_verification("nobody@example.com", context())
        .await
        .unwrap();
    assert!(f.mailer.is_empty());
    let invalid = f
        .auth
        .resend_verification("not an address", context())
        .await;
    assert!(matches!(invalid, Err(LocalError::InvalidEmail)));

    let (_, first) = f.register().await;
    f.auth
        .resend_verification("BUDI@example.com", context())
        .await
        .unwrap();
    let emails = f.mailer.take();
    assert_eq!(emails.len(), 1);
    let second = emails[0].token().unwrap().expose().to_owned();
    assert_ne!(first, second);

    // Only the latest link works.
    let old = f.auth.verify_email(&first, context()).await;
    assert!(matches!(old, Err(LocalError::InvalidToken)));
    f.auth.verify_email(&second, context()).await.unwrap();

    f.auth
        .resend_verification("budi@example.com", context())
        .await
        .unwrap();
    assert!(f.mailer.is_empty(), "already verified");
}

#[tokio::test]
async fn a_second_registration_notifies_the_owner_within_the_limit() {
    let f = fixture();
    let owner = f.verified().await;
    f.recorder.take();

    for attempt in 0..4 {
        let outcome = f
            .auth
            .register(registration(
                &format!("intruder{attempt}"),
                "Budi@Example.com",
            ))
            .await
            .unwrap();
        assert!(outcome.created().is_none());
    }
    let emails = f.mailer.take();
    assert_eq!(emails.len(), 3, "3 per 15 minutes");
    for email in &emails {
        assert!(matches!(email, AuthEmail::RegistrationAttempt { to } if to.id == owner.id));
        // Nothing the requester typed reaches the owner.
        assert!(!format!("{email:?}").contains("intruder"));
    }
    assert_eq!(f.event_names(), ["email_throttled"]);

    f.clock.advance(Duration::from_secs(15 * 60));
    f.auth
        .register(registration("intruder9", "budi@example.com"))
        .await
        .unwrap();
    assert_eq!(f.mailer.len(), 1, "the limit starts over");
}

#[tokio::test]
async fn a_refusing_mailer_does_not_fail_the_operation() {
    let f = fixture();
    f.mailer.fail(true);
    let outcome = f
        .auth
        .register(registration("budi", "budi@example.com"))
        .await
        .unwrap();
    let user = outcome.created().unwrap().clone();
    let events = f.recorder.take();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].kind,
        AuthEventKind::EmailSendFailed {
            email: EmailKind::VerifyEmail
        }
    );
    assert_eq!(events[0].user_id, Some(user.id));

    f.auth
        .request_password_reset("budi@example.com", SessionContext::web())
        .await
        .unwrap();
    assert_eq!(
        f.event_names(),
        ["password_reset_requested", "email_send_failed"]
    );
}

#[tokio::test]
async fn a_failing_email_counter_sends_nothing_and_reports_no_error() {
    #[derive(Clone)]
    struct Down;

    impl AttemptStore for Down {
        async fn begin(
            &self,
            _: AttemptScope,
            _: Uuid,
            _: u32,
            _: SystemTime,
            _: SystemTime,
        ) -> Result<Option<u32>, StoreError> {
            Err(StoreError::backend("counter is down"))
        }

        async fn give_back(&self, _: AttemptScope, _: Uuid) -> Result<(), StoreError> {
            Ok(())
        }

        async fn clear(&self, _: AttemptScope, _: Uuid) -> Result<(), StoreError> {
            Ok(())
        }
    }

    let f = fixture_with(|builder| builder.attempts(Down));
    let user = f.verified().await;
    f.recorder.take();

    f.auth
        .request_password_reset("budi@example.com", SessionContext::web())
        .await
        .unwrap();
    assert!(f.mailer.is_empty());
    assert!(
        f.tokens
            .tokens_for(user.id)
            .iter()
            .all(|t| t.purpose != TokenPurpose::ResetPassword)
    );
    assert_eq!(f.event_names(), ["email_throttled"]);

    // The counter of password changes fails closed: the caller is signed in.
    let login = f.login(PASSWORD).await.unwrap();
    let session = f.validate(login.token.expose()).await;
    let result = f
        .auth
        .change_password(&session, PASSWORD, NEW_PASSWORD, SessionContext::web())
        .await;
    assert!(matches!(result, Err(LocalError::Store(_))));
}

#[tokio::test]
async fn password_reset_requests_are_silent_for_unknown_and_disabled_accounts() {
    let f = fixture();
    f.auth
        .request_password_reset("nobody@example.com", SessionContext::web())
        .await
        .unwrap();
    assert!(f.mailer.is_empty());

    let user = f.verified().await;
    f.users.update(user.id, |r| {
        r.user.disabled_at = Some(SystemTime::UNIX_EPOCH)
    });
    f.auth
        .request_password_reset("budi@example.com", SessionContext::web())
        .await
        .unwrap();
    assert!(f.mailer.is_empty());

    let invalid = f
        .auth
        .request_password_reset("budi", SessionContext::web())
        .await;
    assert!(matches!(invalid, Err(LocalError::InvalidEmail)));
}

#[tokio::test]
async fn reset_sets_the_password_and_signs_out_everywhere() {
    let f = fixture();
    let user = f.verified().await;
    let web = f.login(PASSWORD).await.unwrap();
    let phone = f.login(PASSWORD).await.unwrap();
    // A partial lockout and an unverified address are both settled by the reset.
    f.users.update(user.id, |r| {
        r.failed_login_count = 3;
        r.user.email_verified_at = None;
    });
    let first = f.request_reset().await;
    let token = f.request_reset().await;
    assert_ne!(first, token);
    let stored = f.tokens.tokens_for(user.id);
    let reset = stored.last().unwrap();
    assert_eq!(
        reset.expires_at,
        f.clock.now() + Duration::from_secs(60 * 60)
    );
    f.recorder.take();

    let reset_user = f
        .auth
        .reset_password(&token, NEW_PASSWORD, SessionContext::web())
        .await
        .unwrap();
    assert_eq!(reset_user.id, user.id);
    assert_eq!(reset_user.email_verified_at, Some(f.clock.now()));
    let record = f.users.get(user.id).unwrap();
    assert_eq!(record.failed_login_count, 0);
    assert_eq!(record.locked_until, None);
    for login in [&web, &phone] {
        let session = f.sessions.get(login.session.id).unwrap();
        assert!(session.revoked_at.is_some());
    }
    let names = f.event_names();
    assert_eq!(names.iter().filter(|n| **n == "session_revoked").count(), 2);
    assert_eq!(names.last(), Some(&"password_reset"));

    let emails = f.mailer.take();
    assert_eq!(emails.len(), 1);
    assert!(matches!(
        emails[0],
        AuthEmail::PasswordChanged {
            via: PasswordChangeVia::Reset,
            ..
        }
    ));
    assert!(f.sessions.len() == 2, "the reset does not sign in");

    assert!(matches!(
        f.login(PASSWORD).await,
        Err(LocalError::InvalidCredentials)
    ));
    assert!(f.login(NEW_PASSWORD).await.is_ok());
    let again = f
        .auth
        .reset_password(&token, PASSWORD, SessionContext::web())
        .await;
    assert!(matches!(again, Err(LocalError::InvalidToken)));
    let replaced = f
        .auth
        .reset_password(&first, PASSWORD, SessionContext::web())
        .await;
    assert!(matches!(replaced, Err(LocalError::InvalidToken)));
}

#[tokio::test]
async fn a_rejected_new_password_keeps_the_link_usable() {
    let f = fixture();
    f.verified().await;
    let token = f.request_reset().await;

    let short = f
        .auth
        .reset_password(&token, "short", SessionContext::web())
        .await;
    assert!(matches!(short, Err(LocalError::PasswordTooShort { .. })));
    f.auth
        .reset_password(&token, NEW_PASSWORD, SessionContext::web())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_disabled_account_cannot_use_its_reset_link() {
    let f = fixture();
    let user = f.verified().await;
    let token = f.request_reset().await;
    f.users.update(user.id, |r| {
        r.user.disabled_at = Some(SystemTime::UNIX_EPOCH)
    });

    let result = f
        .auth
        .reset_password(&token, NEW_PASSWORD, SessionContext::web())
        .await;
    assert!(matches!(result, Err(LocalError::InvalidToken)));
    assert!(f.mailer.is_empty());
}

#[tokio::test]
async fn reset_requests_are_limited_and_keep_the_last_link() {
    let f = fixture();
    let user = f.verified().await;
    let mut sent = Vec::new();
    for _ in 0..3 {
        sent.push(f.request_reset().await);
    }
    f.recorder.take();
    f.auth
        .request_password_reset("budi@example.com", SessionContext::web())
        .await
        .unwrap();
    assert!(f.mailer.is_empty());
    assert_eq!(f.event_names(), ["email_throttled"]);
    let resets = f
        .tokens
        .tokens_for(user.id)
        .into_iter()
        .filter(|t| t.purpose == TokenPurpose::ResetPassword)
        .count();
    assert_eq!(resets, 3, "no token is created over the limit");
    // The last link sent still works.
    f.auth
        .reset_password(sent.last().unwrap(), NEW_PASSWORD, SessionContext::web())
        .await
        .unwrap();
}

#[tokio::test]
async fn changing_the_password_signs_out_the_other_sessions() {
    let f = fixture();
    let user = f.verified().await;
    let here = f.login(PASSWORD).await.unwrap();
    let elsewhere = f.login(PASSWORD).await.unwrap();
    let pending_reset = f.request_reset().await;
    let session = f.validate(here.token.expose()).await;
    f.recorder.take();

    f.auth
        .change_password(&session, PASSWORD, NEW_PASSWORD, SessionContext::web())
        .await
        .unwrap();
    assert!(
        f.sessions
            .get(here.session.id)
            .unwrap()
            .revoked_at
            .is_none()
    );
    assert!(
        f.sessions
            .get(elsewhere.session.id)
            .unwrap()
            .revoked_at
            .is_some()
    );
    let names = f.event_names();
    assert_eq!(names, ["session_revoked", "password_changed"]);
    let emails = f.mailer.take();
    assert!(matches!(
        &emails[..],
        [AuthEmail::PasswordChanged {
            via: PasswordChangeVia::Change,
            to,
            ..
        }] if to.id == user.id
    ));
    // Outstanding reset links end with the change.
    let reset = f
        .auth
        .reset_password(&pending_reset, PASSWORD, SessionContext::web())
        .await;
    assert!(matches!(reset, Err(LocalError::InvalidToken)));
    assert!(f.login(NEW_PASSWORD).await.is_ok());
    assert_eq!(
        f.attempts.count(AttemptScope::PasswordChange, user.id),
        None,
        "cleared on success"
    );
}

#[tokio::test]
async fn wrong_current_passwords_revoke_the_session_without_locking_the_account() {
    let f = fixture_with(|builder| {
        builder.password_change_policy(
            PasswordChangePolicy::default().limit(3, Duration::from_secs(60)),
        )
    });
    let user = f.verified().await;
    let login = f.login(PASSWORD).await.unwrap();
    let session = f.validate(login.token.expose()).await;
    let change = |current: &'static str| {
        let auth = f.auth.clone();
        let session = session.clone();
        async move {
            auth.change_password(&session, current, NEW_PASSWORD, SessionContext::web())
                .await
        }
    };

    for _ in 0..2 {
        assert!(matches!(
            change("wrong password").await,
            Err(LocalError::InvalidCredentials)
        ));
    }
    assert_eq!(f.users.get(user.id).unwrap().failed_login_count, 0);
    assert!(matches!(
        change("wrong password").await,
        Err(LocalError::TooManyAttempts)
    ));
    assert!(
        f.sessions
            .get(login.session.id)
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(
        LocalError::TooManyAttempts.kind(),
        LocalErrorKind::RateLimited
    );
    // Even the right password is refused until the period ends.
    assert!(matches!(
        change(PASSWORD).await,
        Err(LocalError::TooManyAttempts)
    ));
    assert_eq!(f.users.get(user.id).unwrap().failed_login_count, 0);
    assert!(f.login(PASSWORD).await.is_ok(), "login is not locked");
}

#[tokio::test]
async fn a_new_password_is_checked_before_any_attempt_is_counted() {
    let f = fixture();
    let user = f.verified().await;
    let login = f.login(PASSWORD).await.unwrap();
    let session = f.validate(login.token.expose()).await;
    let result = f
        .auth
        .change_password(&session, "wrong password", "short", SessionContext::web())
        .await;
    assert!(matches!(result, Err(LocalError::PasswordTooShort { .. })));
    assert_eq!(
        f.attempts.count(AttemptScope::PasswordChange, user.id),
        None
    );
    assert_eq!(session.session.state, SessionState::Active);
}

#[tokio::test]
async fn the_owner_is_told_once_when_the_account_locks() {
    let f = fixture_with(|builder| {
        builder.email_policy(EmailPolicy::default().limit(10, Duration::from_secs(60)))
    });
    let user = f.verified().await;
    for _ in 0..4 {
        assert!(matches!(
            f.login("wrong password").await,
            Err(LocalError::InvalidCredentials)
        ));
    }
    assert!(f.mailer.is_empty());
    assert!(matches!(
        f.login("wrong password").await,
        Err(LocalError::InvalidCredentials)
    ));
    let emails = f.mailer.take();
    assert!(matches!(
        &emails[..],
        [AuthEmail::AccountLocked { to, until }]
            if to.id == user.id && *until == f.clock.now() + Duration::from_secs(60)
    ));

    // Longer locks later in the same series send nothing more.
    f.clock.advance(Duration::from_secs(60));
    assert!(f.login("wrong password").await.is_err());
    assert!(f.mailer.is_empty());

    // A successful login ends the series; the next lock is reported again.
    f.clock.advance(Duration::from_secs(15 * 60));
    f.login(PASSWORD).await.unwrap();
    for _ in 0..5 {
        assert!(f.login("wrong password").await.is_err());
    }
    assert_eq!(f.mailer.len(), 1);
}

#[tokio::test]
async fn emails_are_counted_per_receiving_account() {
    let f = fixture();
    let budi = f.verified().await;
    for _ in 0..3 {
        f.request_reset().await;
    }
    // Siti's emails are counted separately.
    let siti = f
        .auth
        .register(registration("siti", "siti@example.com"))
        .await
        .unwrap()
        .created()
        .unwrap()
        .clone();
    f.mailer.take();
    f.auth
        .resend_verification("siti@example.com", SessionContext::web())
        .await
        .unwrap();
    assert_eq!(f.mailer.len(), 1);
    assert_eq!(f.attempts.count(AttemptScope::Email, budi.id), Some(3));
    assert_eq!(f.attempts.count(AttemptScope::Email, siti.id), Some(1));
}
