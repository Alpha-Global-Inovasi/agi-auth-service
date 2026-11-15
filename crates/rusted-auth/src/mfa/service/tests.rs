use super::*;
use crate::encryption::{EncryptionKey, Keyring};
use crate::mfa::{MemoryMfaStore, MfaErrorKind, RecoveryCodes, TotpConfig};
use crate::session::event::testing::Recorder;
use crate::session::{
    IssuedSession, MemorySessionStore, MemoryUserStore, NewUser, SessionContext, SessionError,
    SessionState, UserStore,
};
use std::sync::Mutex;
use std::time::Duration;

const STEP: Duration = Duration::from_secs(30);
const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(86_400);

/// A clock the test moves by hand, starting at the beginning of a time step.
#[derive(Clone)]
struct TestClock(Arc<Mutex<SystemTime>>);

impl TestClock {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(now - now % 30);
        Self(Arc::new(Mutex::new(start)))
    }

    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

fn key(byte: u8) -> EncryptionKey {
    EncryptionKey::from_bytes([byte; 32])
}

type TestMfa = Mfa<MemoryMfaStore, MemorySessionStore>;

struct Fixture {
    mfa: TestMfa,
    store: MemoryMfaStore,
    #[cfg_attr(not(feature = "local"), allow(dead_code))]
    users: MemoryUserStore,
    sessions: SessionManager<MemorySessionStore>,
    clock: TestClock,
    recorder: Recorder,
    user: User,
}

impl Fixture {
    async fn new() -> Self {
        Self::with(MfaConfig::default()).await
    }

    async fn with(config: MfaConfig) -> Self {
        let clock = TestClock::new();
        let recorder = Recorder::default();
        let users = MemoryUserStore::new();
        let user = users
            .insert(NewUser {
                username: "budi".into(),
                email: "budi@example.com".into(),
                name: "Budi".into(),
                password_hash: None,
            })
            .await
            .unwrap();
        let for_sessions = clock.clone();
        let sessions = SessionManager::builder(MemorySessionStore::new(users.clone()))
            .events(recorder.clone())
            .clock(move || for_sessions.now())
            .build();
        let store = MemoryMfaStore::new();
        let mfa = Self::build(
            &store,
            &sessions,
            &clock,
            config,
            Keyring::new("k1", key(1)),
        );
        Self {
            mfa,
            store,
            users,
            sessions,
            clock,
            recorder,
            user,
        }
    }

    fn build(
        store: &MemoryMfaStore,
        sessions: &SessionManager<MemorySessionStore>,
        clock: &TestClock,
        config: MfaConfig,
        keyring: Result<Keyring, crate::encryption::EncryptionError>,
    ) -> TestMfa {
        let clock = clock.clone();
        Mfa::builder(store.clone(), keyring.unwrap(), sessions.clone())
            .issuer("Acme")
            .config(config)
            .clock(move || clock.now())
            .build()
            .unwrap()
    }

    fn id(&self) -> Uuid {
        self.user.id
    }

    /// The stored secret, decrypted with every key the tests use.
    fn secret(&self) -> Zeroizing<Vec<u8>> {
        let record = self.store.totp(self.id()).expect("a TOTP record");
        let keys = Keyring::new("k1", key(1))
            .unwrap()
            .with_key("k2", key(2))
            .unwrap();
        keys.decrypt(&record.secret_enc, &secret_context(self.id()))
            .unwrap()
    }

    /// The code `offset` steps from now.
    fn code(&self, offset: i64) -> String {
        let config = TotpConfig::default();
        let step = config
            .step_at(self.clock.now())
            .checked_add_signed(offset)
            .unwrap();
        config.code(&self.secret(), step).as_str().to_owned()
    }

    /// Set up and confirm TOTP, then move to the next time step so the confirmation
    /// code is not the current one any more.
    async fn enable(&self) -> RecoveryCodes {
        self.mfa
            .start_totp(self.id(), "budi@example.com")
            .await
            .unwrap();
        let codes = self
            .mfa
            .confirm_totp(self.id(), &self.code(0))
            .await
            .unwrap();
        self.clock.advance(STEP);
        self.recorder.take();
        codes
    }

    async fn pending(&self) -> IssuedSession {
        let issued = self
            .sessions
            .create(self.id(), SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        self.recorder.take();
        issued
    }

    /// A code of TOTP length that is neither a TOTP code near now nor an unused recovery
    /// code, so it is always rejected as invalid.
    async fn wrong(&self) -> String {
        let near: Vec<String> = (-2..=2).map(|offset| self.code(offset)).collect();
        for n in 0u32.. {
            let candidate = format!("{n:06}");
            let hashes =
                candidate_hashes(&self.mfa.inner.keyring, self.id(), &candidate, 6).unwrap();
            let unused = self
                .store
                .find_unused_recovery_code(self.id(), &hashes)
                .await
                .unwrap();
            if !near.contains(&candidate) && unused.is_none() {
                return candidate;
            }
        }
        unreachable!()
    }

    /// Failure reasons reported so far, then forgets all events.
    fn failures(&self) -> Vec<MfaFailure> {
        self.recorder
            .take()
            .into_iter()
            .filter_map(|e| match e.kind {
                AuthEventKind::MfaFailed { reason, .. } => Some(reason),
                _ => None,
            })
            .collect()
    }
}

#[tokio::test]
async fn setup_is_shown_once_and_only_a_confirmed_one_counts() {
    let f = Fixture::new().await;
    assert_eq!(f.mfa.status(f.id()).await.unwrap(), MfaStatus::Disabled);

    let setup = f.mfa.start_totp(f.id(), "budi@example.com").await.unwrap();
    assert_eq!(setup.secret().len(), 32);
    assert_eq!(
        setup.uri(),
        format!(
            "otpauth://totp/Acme:budi%40example.com?secret={}&issuer=Acme&algorithm=SHA1&digits=6&period=30",
            setup.secret()
        )
    );
    assert_eq!(format!("{setup:?}"), "TotpSetup(<redacted>)");
    // Stored encrypted, not as the raw secret.
    let record = f.store.totp(f.id()).unwrap();
    let raw = f.secret();
    assert!(!record.secret_enc.windows(raw.len()).any(|w| w == &raw[..]));
    assert_eq!(
        f.mfa.status(f.id()).await.unwrap(),
        MfaStatus::SetupInProgress
    );
    assert!(!f.mfa.is_enabled(f.id()).await.unwrap());

    // A wrong code does not confirm.
    let wrong = f.wrong().await;
    let error = f.mfa.confirm_totp(f.id(), &wrong).await.unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));

    // Starting again replaces the secret; the first one can no longer be confirmed.
    let old_code = f.code(0);
    let again = f.mfa.start_totp(f.id(), "budi@example.com").await.unwrap();
    assert_ne!(again.secret(), setup.secret());
    if old_code != f.code(0) {
        let error = f.mfa.confirm_totp(f.id(), &old_code).await.unwrap_err();
        assert!(matches!(error, MfaError::InvalidCode));
    }

    let codes = f.mfa.confirm_totp(f.id(), &f.code(0)).await.unwrap();
    assert_eq!(codes.len(), 10);
    assert!(f.mfa.is_enabled(f.id()).await.unwrap());
    assert_eq!(
        f.mfa.status(f.id()).await.unwrap(),
        MfaStatus::Enabled {
            since: f.clock.now(),
            recovery_codes_left: 10
        }
    );
    assert_eq!(
        f.recorder.take_names(),
        ["totp_enabled", "recovery_codes_generated"]
    );

    let error = f.mfa.start_totp(f.id(), "budi").await.unwrap_err();
    assert!(matches!(error, MfaError::AlreadyEnabled));
    assert_eq!(error.kind(), MfaErrorKind::Conflict);
    let error = f.mfa.confirm_totp(f.id(), &f.code(0)).await.unwrap_err();
    assert!(matches!(error, MfaError::AlreadyEnabled));
    let error = f
        .mfa
        .confirm_totp(Uuid::new_v4(), "123456")
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::NoSetupInProgress));
}

#[tokio::test]
async fn correct_code_activates_under_a_new_token() {
    let f = Fixture::new().await;
    f.enable().await;
    let pending = f.pending().await;
    f.clock.advance(MINUTE);

    let login = f
        .mfa
        .complete_login(pending.token.expose(), &f.code(0))
        .await
        .unwrap();
    assert_eq!(login.method, MfaMethod::Totp);
    assert_eq!(login.user.id, f.id());
    assert_eq!(login.session.state, SessionState::Active);
    assert_ne!(login.session.id, pending.session.id);
    assert_ne!(login.token.expose(), pending.token.expose());
    // The absolute lifetime counts from the password login.
    assert_eq!(
        login.session.absolute_expires_at,
        pending.session.created_at + 30 * DAY
    );
    assert_eq!(
        f.recorder.take_names(),
        ["session_activated", "mfa_succeeded"]
    );

    let authenticated = f.sessions.validate(login.token.expose()).await.unwrap();
    assert_eq!(authenticated.session.id, login.session.id);
    let error = f
        .sessions
        .validate(pending.token.expose())
        .await
        .unwrap_err();
    assert!(matches!(error, SessionError::Revoked));
    // The old token cannot be used for a second attempt either.
    f.clock.advance(STEP);
    let error = f
        .mfa
        .complete_login(pending.token.expose(), &f.code(0))
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::Session(SessionError::Revoked)));
    assert_eq!(error.kind(), MfaErrorKind::Unauthenticated);
    // Nor can an active session.
    let error = f
        .mfa
        .complete_login(login.token.expose(), &f.code(0))
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::Session(SessionError::Invalid)));
}

#[tokio::test]
async fn a_code_is_accepted_once_and_older_codes_never() {
    let f = Fixture::new().await;
    f.mfa.start_totp(f.id(), "budi").await.unwrap();
    let confirmation = f.code(0);
    f.mfa.confirm_totp(f.id(), &confirmation).await.unwrap();
    f.recorder.take();

    // The code that confirmed the setup cannot also complete a login.
    let first = f.pending().await;
    let error = f
        .mfa
        .complete_login(first.token.expose(), &confirmation)
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert_eq!(f.failures(), [MfaFailure::ReusedCode]);

    // A newer one can, once.
    f.clock.advance(STEP);
    let code = f.code(0);
    f.mfa
        .complete_login(first.token.expose(), &code)
        .await
        .unwrap();
    f.recorder.take();
    let second = f.pending().await;
    let error = f
        .mfa
        .complete_login(second.token.expose(), &code)
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert_eq!(error.public_message(), "Invalid verification code");
    assert_eq!(f.failures(), [MfaFailure::ReusedCode]);

    // The previous step is inside the window but older than the one used.
    let error = f
        .mfa
        .complete_login(second.token.expose(), &f.code(-1))
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert_eq!(f.failures(), [MfaFailure::ReusedCode]);
}

#[tokio::test]
async fn clock_differences_of_one_step_are_tolerated() {
    let f = Fixture::new().await;
    f.enable().await;
    // Two steps after the confirmation, so the previous step is unused.
    f.clock.advance(STEP);

    let pending = f.pending().await;
    for offset in [-2, 2] {
        let error = f
            .mfa
            .complete_login(pending.token.expose(), &f.code(offset))
            .await
            .unwrap_err();
        assert!(matches!(error, MfaError::InvalidCode), "{offset}");
    }
    assert_eq!(f.failures(), [MfaFailure::InvalidCode; 2]);
    // One step behind: the code shown just before the step changed.
    f.mfa
        .complete_login(pending.token.expose(), &f.code(-1))
        .await
        .unwrap();

    // One step ahead: a phone whose clock runs fast. Later steps stay usable.
    f.clock.advance(2 * STEP);
    let pending = f.pending().await;
    f.mfa
        .complete_login(pending.token.expose(), &f.code(1))
        .await
        .unwrap();

    // A wider window is a setting.
    let wide = Fixture::with(MfaConfig::default().totp(TotpConfig::default().skew_steps(2))).await;
    wide.enable().await;
    wide.clock.advance(2 * STEP);
    let pending = wide.pending().await;
    wide.mfa
        .complete_login(pending.token.expose(), &wide.code(-2))
        .await
        .unwrap();
}

#[tokio::test]
async fn too_many_wrong_codes_cancel_the_login() {
    let f = Fixture::new().await;
    f.enable().await;
    let pending = f.pending().await;
    let right = f.code(0);
    let wrong = f.wrong().await;

    for attempt in 1..=4 {
        let error = f
            .mfa
            .complete_login(pending.token.expose(), &wrong)
            .await
            .unwrap_err();
        assert!(matches!(error, MfaError::InvalidCode), "attempt {attempt}");
    }
    // Malformed input and unknown recovery codes count too.
    let error = f
        .mfa
        .complete_login(pending.token.expose(), "not a code")
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::TooManyAttempts));
    assert_eq!(error.kind(), MfaErrorKind::Unauthenticated);
    assert_eq!(error.public_message(), "Too many attempts, sign in again");

    let events = f.recorder.take();
    let names: Vec<_> = events.iter().map(|e| e.kind.name()).collect();
    assert_eq!(
        names,
        [
            "mfa_failed",
            "mfa_failed",
            "mfa_failed",
            "mfa_failed",
            "mfa_failed",
            "mfa_attempts_exceeded",
            "session_revoked"
        ]
    );
    assert!(matches!(
        events[4].kind,
        AuthEventKind::MfaFailed {
            method: None,
            attempts: 5,
            ..
        }
    ));

    // The session is gone, so even the right code needs a new login.
    let error = f
        .mfa
        .complete_login(pending.token.expose(), &right)
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::Session(SessionError::Revoked)));

    // A new login starts with a fresh allowance and succeeds.
    let next = f.pending().await;
    f.mfa
        .complete_login(next.token.expose(), &right)
        .await
        .unwrap();
}

#[tokio::test]
async fn the_attempt_limit_is_configurable() {
    let f = Fixture::with(MfaConfig::default().max_attempts(1)).await;
    f.enable().await;
    let pending = f.pending().await;
    let error = f
        .mfa
        .complete_login(pending.token.expose(), "1234-5678")
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::TooManyAttempts));
    assert!(
        f.sessions
            .validate_pending_mfa(pending.token.expose())
            .await
            .is_err()
    );

    assert!(matches!(
        Mfa::builder(
            MemoryMfaStore::new(),
            Keyring::new("k", key(1)).unwrap(),
            f.sessions.clone()
        )
        .config(MfaConfig::default().max_attempts(0))
        .build(),
        Err(MfaError::Config(_))
    ));
    assert!(matches!(
        Mfa::builder(
            MemoryMfaStore::new(),
            Keyring::new("k", key(1)).unwrap(),
            f.sessions.clone()
        )
        .config(MfaConfig::default().recovery_codes(0))
        .build(),
        Err(MfaError::Config(_))
    ));
    for digits in [5, 13] {
        assert!(matches!(
            Mfa::builder(
                MemoryMfaStore::new(),
                Keyring::new("k", key(1)).unwrap(),
                f.sessions.clone()
            )
            .config(MfaConfig::default().recovery_code_digits(digits))
            .build(),
            Err(MfaError::Config(_))
        ));
    }
}

#[tokio::test]
async fn a_pending_session_expires_after_five_minutes() {
    let f = Fixture::new().await;
    f.enable().await;
    let pending = f.pending().await;
    f.clock.advance(5 * MINUTE);
    let error = f
        .mfa
        .complete_login(pending.token.expose(), &f.code(0))
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::Session(SessionError::Expired)));
}

#[tokio::test]
async fn recovery_codes_are_single_use_and_can_be_replaced() {
    let f = Fixture::new().await;
    let codes = f.enable().await;
    let codes: Vec<String> = codes.iter().map(str::to_owned).collect();
    // Only hashes are stored.
    assert_eq!(f.store.recovery_code_count(f.id()), 10);

    assert!(codes.iter().all(|c| c.len() == 6));

    // Six digits, like a TOTP code: it is checked as one first, then as a recovery code.
    let pending = f.pending().await;
    let login = f
        .mfa
        .complete_login(pending.token.expose(), &codes[0])
        .await
        .unwrap();
    assert_eq!(login.method, MfaMethod::RecoveryCode);
    assert!(matches!(
        f.mfa.status(f.id()).await.unwrap(),
        MfaStatus::Enabled {
            recovery_codes_left: 9,
            ..
        }
    ));

    let pending = f.pending().await;
    let error = f
        .mfa
        .complete_login(pending.token.expose(), &codes[0])
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert!(matches!(
        f.recorder.take()[0].kind,
        AuthEventKind::MfaFailed {
            method: Some(MfaMethod::Totp),
            reason: MfaFailure::InvalidCode,
            attempts: 1,
            ..
        }
    ));

    // A new set replaces every earlier code, used or not. It takes a current code.
    let new_codes = f
        .mfa
        .regenerate_recovery_codes(f.id(), &f.code(0))
        .await
        .unwrap();
    assert_eq!(new_codes.len(), 10);
    assert_eq!(f.recorder.take_names(), ["recovery_codes_generated"]);
    let error = f
        .mfa
        .complete_login(pending.token.expose(), &codes[1])
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    let login = f
        .mfa
        .complete_login(pending.token.expose(), &{
            let code = new_codes.iter().next().unwrap();
            format!(" {}-{} ", &code[..3], &code[3..])
        })
        .await
        .unwrap();
    assert_eq!(login.method, MfaMethod::RecoveryCode);

    let error = f
        .mfa
        .regenerate_recovery_codes(Uuid::new_v4(), "123456")
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::NotEnabled));
}

#[tokio::test]
async fn recovery_code_length_is_a_setting() {
    let f = Fixture::with(MfaConfig::default().recovery_code_digits(10)).await;
    let codes = f.enable().await;
    assert!(codes.iter().all(|c| c.len() == 10));
    let pending = f.pending().await;
    let login = f
        .mfa
        .complete_login(pending.token.expose(), codes.iter().nth(3).unwrap())
        .await
        .unwrap();
    assert_eq!(login.method, MfaMethod::RecoveryCode);
    // A six-digit input is only a TOTP code now.
    let pending = f.pending().await;
    let wrong = f.wrong().await;
    f.mfa
        .complete_login(pending.token.expose(), &wrong)
        .await
        .unwrap_err();
    assert!(matches!(
        f.recorder.take()[0].kind,
        AuthEventKind::MfaFailed {
            method: Some(MfaMethod::Totp),
            ..
        }
    ));
}

#[tokio::test]
async fn changes_to_the_second_factor_need_a_code_and_use_it_up() {
    let f = Fixture::new().await;
    let codes = f.enable().await;

    // Wrong or missing codes change nothing.
    let wrong = f.wrong().await;
    for code in [wrong.as_str(), "", "not a code"] {
        let error = f.mfa.disable_totp(f.id(), code).await.unwrap_err();
        assert!(matches!(error, MfaError::InvalidCode), "{code:?}");
    }
    let error = f
        .mfa
        .regenerate_recovery_codes(f.id(), &wrong)
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert!(f.mfa.is_enabled(f.id()).await.unwrap());
    let events = f.recorder.take();
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|e| matches!(
        e.kind,
        AuthEventKind::MfaFailed {
            session_id: None,
            ..
        }
    )));

    // The TOTP code that replaced the recovery codes cannot also complete a login.
    let code = f.code(0);
    f.mfa
        .regenerate_recovery_codes(f.id(), &code)
        .await
        .unwrap();
    let pending = f.pending().await;
    let error = f
        .mfa
        .complete_login(pending.token.expose(), &code)
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert_eq!(f.failures(), [MfaFailure::ReusedCode]);

    // A recovery code of the replaced set no longer works.
    let error = f
        .mfa
        .disable_totp(f.id(), codes.iter().next().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));

    // A recovery code of the current set works, once.
    f.clock.advance(STEP);
    let codes = f
        .mfa
        .regenerate_recovery_codes(f.id(), &f.code(0))
        .await
        .unwrap();
    let mut codes = codes.iter();
    let replaced = f
        .mfa
        .regenerate_recovery_codes(f.id(), codes.next().unwrap())
        .await
        .unwrap();
    assert_eq!(replaced.len(), 10);
    let first = replaced.iter().next().unwrap();
    assert!(f.mfa.disable_totp(f.id(), first).await.unwrap());
    assert_eq!(f.mfa.status(f.id()).await.unwrap(), MfaStatus::Disabled);

    // An unfinished setup protects nothing, so it is removed without a code.
    f.mfa.start_totp(f.id(), "budi").await.unwrap();
    assert!(f.mfa.disable_totp(f.id(), "").await.unwrap());
    assert!(!f.mfa.disable_totp(f.id(), "").await.unwrap());
}

#[tokio::test]
async fn a_used_recovery_code_cannot_confirm_a_change() {
    let f = Fixture::new().await;
    let codes = f.enable().await;
    let code = codes.iter().next().unwrap();
    let pending = f.pending().await;
    f.mfa
        .complete_login(pending.token.expose(), code)
        .await
        .unwrap();
    let error = f.mfa.disable_totp(f.id(), code).await.unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert!(f.mfa.is_enabled(f.id()).await.unwrap());
}

#[tokio::test]
async fn too_many_wrong_codes_block_changes_for_five_minutes() {
    let f = Fixture::new().await;
    f.enable().await;
    let wrong = f.wrong().await;
    for attempt in 1..=5 {
        let error = f.mfa.disable_totp(f.id(), &wrong).await.unwrap_err();
        let expected = if attempt < 5 {
            matches!(error, MfaError::InvalidCode)
        } else {
            matches!(error, MfaError::TooManyAttempts)
        };
        assert!(expected, "attempt {attempt}: {error}");
    }
    assert_eq!(
        f.recorder.take_names().last().copied(),
        Some("mfa_attempts_exceeded")
    );
    // Even the right code, for either change, until the window ends.
    let error = f
        .mfa
        .regenerate_recovery_codes(f.id(), &f.code(0))
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::TooManyAttempts));
    assert!(f.mfa.is_enabled(f.id()).await.unwrap());
    // Logins are counted separately.
    let pending = f.pending().await;
    f.mfa
        .complete_login(pending.token.expose(), &f.code(0))
        .await
        .unwrap();

    f.clock.advance(5 * MINUTE);
    assert!(f.mfa.disable_totp(f.id(), &f.code(0)).await.unwrap());
}

#[tokio::test]
async fn disabling_deletes_the_secret_and_the_recovery_codes() {
    let f = Fixture::new().await;
    let codes = f.enable().await;
    let pending = f.pending().await;

    assert!(f.mfa.disable_totp(f.id(), &f.code(0)).await.unwrap());
    assert_eq!(f.recorder.take_names(), ["totp_disabled"]);
    assert!(f.store.totp(f.id()).is_none());
    assert_eq!(f.store.recovery_code_count(f.id()), 0);
    assert_eq!(f.mfa.status(f.id()).await.unwrap(), MfaStatus::Disabled);
    assert!(!f.mfa.disable_totp(f.id(), "").await.unwrap());

    // A login that was waiting cannot be completed with what was deleted.
    let error = f
        .mfa
        .complete_login(pending.token.expose(), codes.iter().next().unwrap())
        .await
        .unwrap_err();
    assert!(matches!(error, MfaError::InvalidCode));
    assert_eq!(f.failures(), [MfaFailure::NotEnabled]);

    // Setup can start over.
    f.mfa.start_totp(f.id(), "budi").await.unwrap();
}

#[tokio::test]
async fn secrets_follow_a_key_rotation() {
    let f = Fixture::new().await;
    f.enable().await;
    let keyring = Keyring::new("k1", key(1));
    assert_eq!(
        keyring
            .as_ref()
            .unwrap()
            .key_id_of(&f.store.totp(f.id()).unwrap().secret_enc),
        Ok("k1")
    );

    // New active key, old key kept for decryption.
    let rotated = Keyring::new("k1", key(1))
        .unwrap()
        .with_key("k2", key(2))
        .unwrap()
        .activate("k2");
    let mfa = Fixture::build(
        &f.store,
        &f.sessions,
        &f.clock,
        MfaConfig::default(),
        rotated,
    );
    let code = f.code(0);
    let pending = f.pending().await;
    mfa.complete_login(pending.token.expose(), &code)
        .await
        .unwrap();
    let record = f.store.totp(f.id()).unwrap();
    assert_eq!(keyring.unwrap().key_id_of(&record.secret_enc), Ok("k2"));

    // The old key can now be removed.
    let retired = Fixture::build(
        &f.store,
        &f.sessions,
        &f.clock,
        MfaConfig::default(),
        Keyring::new("k2", key(2)),
    );
    f.clock.advance(STEP);
    let pending = f.pending().await;
    retired
        .complete_login(pending.token.expose(), &f.code(0))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_secret_that_cannot_be_decrypted_fails_closed() {
    let f = Fixture::new().await;
    f.enable().await;
    let code = f.code(0);
    let mut record = f.store.totp(f.id()).unwrap();
    let last = record.secret_enc.len() - 1;
    record.secret_enc[last] ^= 1;
    f.store
        .replace_totp_secret(
            f.id(),
            &f.store.totp(f.id()).unwrap().secret_enc,
            record.secret_enc,
        )
        .await
        .unwrap();

    let pending = f.pending().await;
    for _ in 0..6 {
        let error = f
            .mfa
            .complete_login(pending.token.expose(), &code)
            .await
            .unwrap_err();
        assert!(matches!(error, MfaError::Internal(_)), "{error}");
        assert!(error.is_server_error());
        assert!(!error.public_message().contains("decrypt"));
    }
    // Server failures do not use up attempts or report a failed code.
    assert!(f.failures().is_empty());
    assert!(
        f.sessions
            .validate_pending_mfa(pending.token.expose())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn codes_and_secrets_never_reach_events_or_debug_output() {
    let f = Fixture::new().await;
    let setup = f.mfa.start_totp(f.id(), "budi").await.unwrap();
    let secret = setup.secret().to_owned();
    let confirmation = f.code(0);
    let codes = f.mfa.confirm_totp(f.id(), &confirmation).await.unwrap();
    f.clock.advance(STEP);
    let pending = f.pending().await;
    let wrong = f.wrong().await;
    let _ = f.mfa.complete_login(pending.token.expose(), &wrong).await;
    let code = f.code(0);
    let login = f
        .mfa
        .complete_login(pending.token.expose(), &code)
        .await
        .unwrap();

    let debug = format!(
        "{:?} {:?} {:?} {:?} {:?} {:?}",
        f.recorder.events(),
        f.mfa,
        login,
        codes,
        f.store,
        setup
    );
    // TOTP and recovery codes are short digit strings, which timestamps and identifiers
    // in the output contain by chance, so they are not searched for: no event field can
    // hold text, and the code types print as redacted.
    let _ = (&confirmation, &code);
    assert!(!debug.contains(&secret), "{debug}");
    assert!(debug.contains("RecoveryCodes(<10 redacted>)"), "{debug}");
    assert!(!debug.contains(login.token.expose()));
}

#[cfg(feature = "local")]
mod login {
    use super::*;
    use crate::local::{HashLimits, LocalAuth, PasswordHasher, Registration};

    const PASSWORD: &str = "correct horse battery staple";

    async fn local(f: &Fixture) -> LocalAuth<MemoryUserStore, MemorySessionStore> {
        let auth = LocalAuth::builder(f.users.clone(), f.sessions.clone())
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .mfa(&f.mfa)
            .build()
            .unwrap();
        let outcome = auth
            .register(Registration {
                username: "siti".into(),
                email: "siti@example.com".into(),
                name: "Siti".into(),
                password: PASSWORD.into(),
            })
            .await
            .unwrap();
        let id = outcome.created().unwrap().id;
        f.users
            .update(id, |r| r.user.email_verified_at = Some(SystemTime::now()));
        auth
    }

    /// The fixture, with its user replaced by the account that logs in with a password.
    async fn fixture() -> (Fixture, LocalAuth<MemoryUserStore, MemorySessionStore>) {
        let mut f = Fixture::new().await;
        let auth = local(&f).await;
        f.user = f
            .users
            .find_by_username("siti")
            .await
            .unwrap()
            .unwrap()
            .user;
        (f, auth)
    }

    #[tokio::test]
    async fn password_then_code_then_a_rotated_token() {
        let (f, auth) = fixture().await;
        f.enable().await;

        let login = auth
            .login("siti", PASSWORD, SessionContext::mobile())
            .await
            .unwrap();
        assert!(login.mfa_required());
        assert_eq!(login.session.state, SessionState::PendingMfa);
        assert_eq!(
            login.session.absolute_expires_at,
            f.clock.now() + 5 * MINUTE
        );
        let events = f.recorder.take();
        assert!(events.iter().any(|e| e.kind
            == AuthEventKind::LoginSucceeded {
                session_id: login.session.id,
                mfa_required: true,
            }));

        // The pending token is not a session yet.
        let error = auth
            .sessions()
            .validate(login.token.expose())
            .await
            .unwrap_err();
        assert!(matches!(error, SessionError::MfaRequired));

        f.clock.advance(MINUTE);
        let done = f
            .mfa
            .complete_login(login.token.expose(), &f.code(0))
            .await
            .unwrap();
        assert_eq!(done.user.id, f.id());
        assert_ne!(done.token.expose(), login.token.expose());
        assert_eq!(done.session.kind, crate::session::SessionKind::Mobile);
        assert_eq!(
            done.session.absolute_expires_at,
            login.session.created_at + 90 * DAY
        );
        auth.sessions().validate(done.token.expose()).await.unwrap();
        let error = auth
            .sessions()
            .validate(login.token.expose())
            .await
            .unwrap_err();
        assert!(matches!(error, SessionError::Revoked));
    }

    #[tokio::test]
    async fn accounts_without_a_confirmed_authenticator_log_in_directly() {
        let (f, auth) = fixture().await;
        let login = auth
            .login("siti", PASSWORD, SessionContext::web())
            .await
            .unwrap();
        assert!(!login.mfa_required());
        assert_eq!(login.session.state, SessionState::Active);
        auth.sessions()
            .validate(login.token.expose())
            .await
            .unwrap();

        // An unfinished setup changes nothing.
        f.mfa.start_totp(f.id(), "siti").await.unwrap();
        let login = auth
            .login("siti", PASSWORD, SessionContext::web())
            .await
            .unwrap();
        assert_eq!(login.session.state, SessionState::Active);
        assert!(events_say_no_mfa(&f.recorder, login.session.id));

        // Once confirmed it is required, and once disabled no longer.
        f.mfa.confirm_totp(f.id(), &f.code(0)).await.unwrap();
        let login = auth
            .login("siti", PASSWORD, SessionContext::web())
            .await
            .unwrap();
        assert!(login.mfa_required());
        f.clock.advance(STEP);
        f.mfa.disable_totp(f.id(), &f.code(0)).await.unwrap();
        let login = auth
            .login("siti", PASSWORD, SessionContext::web())
            .await
            .unwrap();
        assert!(!login.mfa_required());
    }

    fn events_say_no_mfa(recorder: &Recorder, session_id: Uuid) -> bool {
        recorder.take().iter().any(|e| {
            e.kind
                == AuthEventKind::LoginSucceeded {
                    session_id,
                    mfa_required: false,
                }
        })
    }

    #[tokio::test]
    async fn without_mfa_configured_every_login_is_active() {
        let (f, _) = fixture().await;
        f.enable().await;
        let plain = LocalAuth::builder(f.users.clone(), f.sessions.clone())
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .build()
            .unwrap();
        let login = plain
            .login("siti", PASSWORD, SessionContext::web())
            .await
            .unwrap();
        assert!(!login.mfa_required());
    }
}

mod activation {
    use super::*;
    use crate::session::{NewSession, SessionRecord, SessionTokenHash, StoreError};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The memory store, except that activation can be made to refuse.
    #[derive(Clone)]
    struct Refusing {
        inner: MemorySessionStore,
        refuse: Arc<AtomicBool>,
    }

    impl SessionStore for Refusing {
        async fn insert(&self, session: NewSession) -> Result<Session, StoreError> {
            self.inner.insert(session).await
        }

        async fn find_by_token_hash(
            &self,
            token_hash: &SessionTokenHash,
        ) -> Result<Option<SessionRecord>, StoreError> {
            self.inner.find_by_token_hash(token_hash).await
        }

        async fn touch(
            &self,
            id: Uuid,
            last_seen_at: SystemTime,
            idle_expires_at: SystemTime,
        ) -> Result<(), StoreError> {
            self.inner.touch(id, last_seen_at, idle_expires_at).await
        }

        async fn activate(
            &self,
            pending_id: Uuid,
            replacement: NewSession,
            now: SystemTime,
        ) -> Result<Option<Session>, StoreError> {
            if self.refuse.load(Ordering::SeqCst) {
                return Ok(None);
            }
            self.inner.activate(pending_id, replacement, now).await
        }

        async fn revoke(
            &self,
            id: Uuid,
            owner: Option<Uuid>,
            at: SystemTime,
        ) -> Result<Option<Session>, StoreError> {
            self.inner.revoke(id, owner, at).await
        }

        async fn revoke_all_for_user(
            &self,
            user_id: Uuid,
            except: Option<Uuid>,
            at: SystemTime,
        ) -> Result<Vec<Uuid>, StoreError> {
            self.inner.revoke_all_for_user(user_id, except, at).await
        }

        async fn list_active_for_user(
            &self,
            user_id: Uuid,
            now: SystemTime,
        ) -> Result<Vec<Session>, StoreError> {
            self.inner.list_active_for_user(user_id, now).await
        }
    }

    #[tokio::test]
    async fn a_failed_activation_leaves_the_code_unused() {
        let users = MemoryUserStore::new();
        let user = users
            .insert(NewUser {
                username: "budi".into(),
                email: "budi@example.com".into(),
                name: "Budi".into(),
                password_hash: None,
            })
            .await
            .unwrap();
        let refuse = Arc::new(AtomicBool::new(false));
        let clock = TestClock::new();
        let for_sessions = clock.clone();
        let sessions = SessionManager::builder(Refusing {
            inner: MemorySessionStore::new(users),
            refuse: Arc::clone(&refuse),
        })
        .clock(move || for_sessions.now())
        .build();
        let store = MemoryMfaStore::new();
        let mfa = Mfa::builder(
            store.clone(),
            Keyring::new("k1", key(1)).unwrap(),
            sessions.clone(),
        )
        .clock({
            let clock = clock.clone();
            move || clock.now()
        })
        .build()
        .unwrap();
        let code_now = || {
            let record = store.totp(user.id).unwrap();
            let secret = Keyring::new("k1", key(1))
                .unwrap()
                .decrypt(&record.secret_enc, &secret_context(user.id))
                .unwrap();
            let config = TotpConfig::default();
            config
                .code(&secret, config.step_at(clock.now()))
                .as_str()
                .to_owned()
        };
        mfa.start_totp(user.id, "budi").await.unwrap();
        let codes = mfa.confirm_totp(user.id, &code_now()).await.unwrap();
        let recovery = codes.iter().next().unwrap();
        // The confirmation used the current step.
        let step = TotpConfig::default().step_at(clock.now());
        clock.advance(STEP);
        let totp = code_now();

        let pending = sessions
            .create(user.id, SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        refuse.store(true, Ordering::SeqCst);
        for code in [recovery, totp.as_str()] {
            let error = mfa
                .complete_login(pending.token.expose(), code)
                .await
                .unwrap_err();
            assert!(matches!(error, MfaError::Session(_)), "{error}");
        }
        assert_eq!(store.recovery_code_count(user.id), 10);
        assert!(matches!(
            mfa.status(user.id).await.unwrap(),
            MfaStatus::Enabled {
                recovery_codes_left: 10,
                ..
            }
        ));
        assert_eq!(store.totp(user.id).unwrap().last_used_step, Some(step));

        // Both codes still work once activation does.
        refuse.store(false, Ordering::SeqCst);
        mfa.complete_login(pending.token.expose(), &totp)
            .await
            .unwrap();
        let pending = sessions
            .create(user.id, SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        let login = mfa
            .complete_login(pending.token.expose(), recovery)
            .await
            .unwrap();
        assert_eq!(login.method, MfaMethod::RecoveryCode);
    }
}

mod shared_attempts {
    use super::*;
    use crate::session::StoreError;
    use crate::session::{AttemptScope, AttemptStore, MemoryAttemptStore};

    fn process(f: &Fixture, attempts: &MemoryAttemptStore) -> TestMfa {
        let clock = f.clock.clone();
        Mfa::builder(
            f.store.clone(),
            Keyring::new("k1", key(1)).unwrap(),
            f.sessions.clone(),
        )
        .attempts(attempts.clone())
        .clock(move || clock.now())
        .build()
        .unwrap()
    }

    #[tokio::test]
    async fn processes_sharing_a_store_share_the_limit() {
        let f = Fixture::new().await;
        f.enable().await;
        let shared = MemoryAttemptStore::new();
        let (a, b) = (process(&f, &shared), process(&f, &shared));
        let pending = f.pending().await;
        let wrong = f.wrong().await;
        for attempt in 1..=4 {
            let mfa = if attempt % 2 == 0 { &a } else { &b };
            let error = mfa
                .complete_login(pending.token.expose(), &wrong)
                .await
                .unwrap_err();
            assert!(matches!(error, MfaError::InvalidCode), "attempt {attempt}");
        }
        assert_eq!(
            shared.count(AttemptScope::Login, pending.session.id),
            Some(4)
        );
        let error = a
            .complete_login(pending.token.expose(), &wrong)
            .await
            .unwrap_err();
        assert!(matches!(error, MfaError::TooManyAttempts));
        // The counter is cleared once the session is revoked.
        assert_eq!(shared.count(AttemptScope::Login, pending.session.id), None);

        // Changes are counted per account across processes as well.
        for mfa in [&a, &b, &a, &b] {
            mfa.disable_totp(f.id(), &wrong).await.unwrap_err();
        }
        let error = b.disable_totp(f.id(), &wrong).await.unwrap_err();
        assert!(matches!(error, MfaError::TooManyAttempts));
        let error = a.disable_totp(f.id(), &f.code(0)).await.unwrap_err();
        assert!(matches!(error, MfaError::TooManyAttempts));

        // A correct code clears the login counter.
        let pending = f.pending().await;
        a.complete_login(pending.token.expose(), &wrong)
            .await
            .unwrap_err();
        b.complete_login(pending.token.expose(), &f.code(0))
            .await
            .unwrap();
        assert_eq!(shared.count(AttemptScope::Login, pending.session.id), None);
    }

    /// A counter store whose backend is down.
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
            Err(StoreError::backend("counter store unavailable"))
        }

        async fn give_back(&self, _: AttemptScope, _: Uuid) -> Result<(), StoreError> {
            Err(StoreError::backend("counter store unavailable"))
        }

        async fn clear(&self, _: AttemptScope, _: Uuid) -> Result<(), StoreError> {
            Err(StoreError::backend("counter store unavailable"))
        }
    }

    #[tokio::test]
    async fn a_failing_counter_store_refuses_codes() {
        let f = Fixture::new().await;
        f.enable().await;
        let clock = f.clock.clone();
        let mfa = Mfa::builder(
            f.store.clone(),
            Keyring::new("k1", key(1)).unwrap(),
            f.sessions.clone(),
        )
        .attempts(Down)
        .clock(move || clock.now())
        .build()
        .unwrap();
        let pending = f.pending().await;
        let error = mfa
            .complete_login(pending.token.expose(), &f.code(0))
            .await
            .unwrap_err();
        assert!(error.is_server_error(), "{error}");
        let error = mfa.disable_totp(f.id(), &f.code(0)).await.unwrap_err();
        assert!(error.is_server_error(), "{error}");
        assert!(f.mfa.is_enabled(f.id()).await.unwrap());
        // Nothing was used up: the same code still completes the login elsewhere.
        f.mfa
            .complete_login(pending.token.expose(), &f.code(0))
            .await
            .unwrap();
    }
}
