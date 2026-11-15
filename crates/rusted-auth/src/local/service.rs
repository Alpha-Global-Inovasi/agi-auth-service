use super::error::LocalError;
use super::password::{HashLimits, PasswordHasher, PasswordPolicy};
use super::user::{NewUser, StoreError, User, UserRecord, UserStore};
use super::validate;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// When and for how long an account is locked after failed logins.
///
/// The lock starts once [`threshold`](Self::threshold) consecutive logins have failed and
/// doubles with every further failure, up to [`max_duration`](Self::max_duration). With
/// the defaults that is 1 minute after the 5th failure, 2 after the 6th, 4 after the 7th,
/// and 15 minutes from the 9th on. A successful login resets the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockoutPolicy {
    /// Consecutive failures that trigger the first lock. Default: 5.
    pub threshold: u32,
    /// Length of the first lock. Default: 1 minute.
    pub base_duration: Duration,
    /// Longest lock. Default: 15 minutes.
    pub max_duration: Duration,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            threshold: 5,
            base_duration: Duration::from_secs(60),
            max_duration: Duration::from_secs(15 * 60),
        }
    }
}

impl LockoutPolicy {
    /// Set [`threshold`](Self::threshold). Values below 1 are raised to 1.
    pub fn threshold(mut self, failures: u32) -> Self {
        self.threshold = failures.max(1);
        self
    }

    /// Set [`base_duration`](Self::base_duration).
    pub fn base_duration(mut self, duration: Duration) -> Self {
        self.base_duration = duration;
        self
    }

    /// Set [`max_duration`](Self::max_duration).
    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = duration;
        self
    }

    /// How long to lock an account whose failure count just reached `failed_logins`, or
    /// `None` below the threshold.
    pub fn lock_duration(&self, failed_logins: u32) -> Option<Duration> {
        let threshold = self.threshold.max(1);
        let doublings = failed_logins.checked_sub(threshold)?;
        let factor = 1u32.checked_shl(doublings).unwrap_or(u32::MAX);
        Some(
            self.base_duration
                .saturating_mul(factor)
                .min(self.max_duration),
        )
    }
}

/// Input to [`LocalAuth::register`].
///
/// The `Debug` output does not include the password.
#[derive(Clone)]
pub struct Registration {
    /// Desired username.
    pub username: String,
    /// Email address.
    pub email: String,
    /// Display name. Required.
    pub name: String,
    /// Plain-text password.
    pub password: String,
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// What [`LocalAuth::register`] did.
///
/// **Both variants must produce the same response to the client.** The difference only
/// decides which email is sent: a verification link to a new account, or a notice to the
/// owner of the existing one. Answering them differently tells anyone who asks whether an
/// email address has an account.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistrationOutcome {
    /// A new account was created.
    Created(User),
    /// An account with this email address already exists; nothing was created.
    EmailAlreadyRegistered {
        /// The address as submitted, trimmed.
        email: String,
    },
}

impl RegistrationOutcome {
    /// The new account, if one was created.
    pub fn created(&self) -> Option<&User> {
        match self {
            Self::Created(user) => Some(user),
            Self::EmailAlreadyRegistered { .. } => None,
        }
    }
}

type Clock = Box<dyn Fn() -> SystemTime + Send + Sync>;

/// Local accounts: registration and login with a username or email address and a
/// password.
///
/// Cheap to clone; clones share the store and the password hasher.
///
/// ```rust
/// use rusted_auth::local::{LocalAuth, MemoryUserStore, Registration};
/// use std::time::SystemTime;
///
/// # async fn run() -> Result<(), rusted_auth::local::LocalError> {
/// let auth = LocalAuth::builder(MemoryUserStore::new()).build()?;
///
/// let outcome = auth
///     .register(Registration {
///         username: "budi".into(),
///         email: "budi@example.com".into(),
///         name: "Budi Santoso".into(),
///         password: "correct horse battery staple".into(),
///     })
///     .await?;
///
/// // Logging in requires a verified email address. The verification flow normally
/// // records this; here the test store is edited directly.
/// let id = outcome.created().expect("a new account").id;
/// auth.store()
///     .update(id, |account| account.user.email_verified_at = Some(SystemTime::now()));
///
/// let user = auth.login("budi@example.com", "correct horse battery staple").await?;
/// assert_eq!(user.username, "budi");
/// # Ok(())
/// # }
/// ```
pub struct LocalAuth<S> {
    inner: Arc<Inner<S>>,
}

struct Inner<S> {
    store: S,
    hasher: PasswordHasher,
    lockout: LockoutPolicy,
    password_policy: PasswordPolicy,
    reveal_existing_email: bool,
    require_verified_email: bool,
    clock: Clock,
}

impl<S> Clone for LocalAuth<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S> fmt::Debug for LocalAuth<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalAuth")
            .field("hasher", &self.inner.hasher)
            .field("lockout", &self.inner.lockout)
            .field("password_policy", &self.inner.password_policy)
            .field("reveal_existing_email", &self.inner.reveal_existing_email)
            .field("require_verified_email", &self.inner.require_verified_email)
            .finish_non_exhaustive()
    }
}

/// Configures a [`LocalAuth`]. Created by [`LocalAuth::builder`].
pub struct LocalAuthBuilder<S> {
    store: S,
    hasher: Option<PasswordHasher>,
    hash_limits: HashLimits,
    lockout: LockoutPolicy,
    password_policy: PasswordPolicy,
    reveal_existing_email: bool,
    require_verified_email: bool,
    clock: Clock,
}

impl<S: UserStore> LocalAuthBuilder<S> {
    /// Limits on concurrent password hashing. Ignored when a
    /// [`hasher`](Self::hasher) is supplied.
    pub fn hash_limits(mut self, limits: HashLimits) -> Self {
        self.hash_limits = limits;
        self
    }

    /// Use an existing hasher, so several components share one concurrency limit.
    pub fn hasher(mut self, hasher: PasswordHasher) -> Self {
        self.hasher = Some(hasher);
        self
    }

    /// Account lockout after failed logins.
    pub fn lockout(mut self, policy: LockoutPolicy) -> Self {
        self.lockout = policy;
        self
    }

    /// Length rule for new passwords. Default: 8 to 128 characters.
    pub fn password_policy(mut self, policy: PasswordPolicy) -> Self {
        self.password_policy = policy;
        self
    }

    /// Whether [`LocalAuth::login`] refuses accounts whose email address has not been
    /// verified. Default: `true`.
    ///
    /// Turn this off only in development, where no verification email can be delivered.
    /// With it off, anyone can register with an address they do not own and use the
    /// account.
    pub fn require_verified_email(mut self, require: bool) -> Self {
        self.require_verified_email = require;
        self
    }

    /// When `true`, registering an email address that already has an account fails with
    /// [`LocalError::EmailTaken`] instead of returning
    /// [`RegistrationOutcome::EmailAlreadyRegistered`], and
    /// [`LocalAuth::username_available`] is switched on.
    ///
    /// This is friendlier, and it lets anyone test whether an address has an account.
    /// Default: `false`.
    pub fn reveal_existing_email(mut self, reveal: bool) -> Self {
        self.reveal_existing_email = reveal;
        self
    }

    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Build the service.
    ///
    /// Unless a [`hasher`](Self::hasher) was supplied this creates one, which computes a
    /// password hash on the calling thread (see [`PasswordHasher::new`]).
    pub fn build(self) -> Result<LocalAuth<S>, LocalError> {
        let hasher = match self.hasher {
            Some(hasher) => hasher,
            None => PasswordHasher::with_limits(self.hash_limits)?,
        };
        Ok(LocalAuth {
            inner: Arc::new(Inner {
                store: self.store,
                hasher,
                lockout: self.lockout,
                password_policy: self.password_policy,
                reveal_existing_email: self.reveal_existing_email,
                require_verified_email: self.require_verified_email,
                clock: self.clock,
            }),
        })
    }
}

impl<S: UserStore> LocalAuth<S> {
    /// Start configuring local accounts backed by `store`.
    pub fn builder(store: S) -> LocalAuthBuilder<S> {
        LocalAuthBuilder {
            store,
            hasher: None,
            hash_limits: HashLimits::default(),
            lockout: LockoutPolicy::default(),
            password_policy: PasswordPolicy::default(),
            reveal_existing_email: false,
            require_verified_email: true,
            clock: Box::new(SystemTime::now),
        }
    }

    /// The user store.
    pub fn store(&self) -> &S {
        &self.inner.store
    }

    /// The password hasher, for sharing its concurrency limit with other components.
    pub fn hasher(&self) -> &PasswordHasher {
        &self.inner.hasher
    }

    /// Whether `username` is well formed and not used by any account.
    ///
    /// Only available with
    /// [`reveal_existing_email(true)`](LocalAuthBuilder::reveal_existing_email);
    /// otherwise it fails with [`LocalError::UsernameCheckDisabled`]. When registration
    /// hides whether an email address has an account, this check would give it away: a
    /// registration that silently created nothing leaves its username available.
    ///
    /// This reveals which usernames exist, so callers must rate limit it. There is
    /// deliberately no equivalent for email addresses.
    ///
    /// Returns [`LocalError::InvalidUsername`] for a malformed username.
    pub async fn username_available(&self, username: &str) -> Result<bool, LocalError> {
        if !self.inner.reveal_existing_email {
            return Err(LocalError::UsernameCheckDisabled);
        }
        let username = validate::username(username)?;
        Ok(self.inner.store.find_by_username(username).await?.is_none())
    }

    /// Create an account.
    ///
    /// The username, email address and name are trimmed; the password is not. The new
    /// account's email address is unverified, so it cannot log in until the application
    /// has verified it (see [`LocalAuthBuilder::require_verified_email`]).
    ///
    /// # Email addresses that are already registered
    ///
    /// By default this returns `Ok(`[`RegistrationOutcome::EmailAlreadyRegistered`]`)`
    /// and does the same amount of password hashing as a successful registration, so the
    /// caller can answer exactly as it would for a new account. See
    /// [`RegistrationOutcome`] and [`LocalAuthBuilder::reveal_existing_email`].
    ///
    /// A username that is taken is always reported as [`LocalError::UsernameTaken`],
    /// whether or not the email address is registered.
    ///
    /// # Errors
    ///
    /// Validation errors ([`LocalError::InvalidUsername`], [`LocalError::InvalidEmail`],
    /// [`LocalError::InvalidName`], [`LocalError::PasswordTooShort`],
    /// [`LocalError::PasswordTooLong`]), [`LocalError::UsernameTaken`],
    /// [`LocalError::Busy`], and storage failures.
    pub async fn register(&self, input: Registration) -> Result<RegistrationOutcome, LocalError> {
        let inner = &self.inner;
        let username = validate::username(&input.username)?;
        let email = validate::email(&input.email)?;
        let name = validate::name(&input.name)?;
        inner.password_policy.validate(&input.password)?;

        if inner.store.find_by_username(username).await?.is_some() {
            return Err(LocalError::UsernameTaken);
        }

        // Hashed before the email address is looked at, so a registered address costs
        // the same as a new one.
        let password_hash = inner.hasher.hash(&input.password).await?;
        let new_user = NewUser {
            username: username.to_owned(),
            email: email.to_owned(),
            name: name.to_owned(),
            password_hash: Some(password_hash),
        };

        match inner.store.insert(new_user).await {
            Ok(user) => {
                tracing::debug!(user_id = %user.id, "local account registered");
                Ok(RegistrationOutcome::Created(user))
            }
            Err(StoreError::EmailTaken) if !inner.reveal_existing_email => {
                tracing::debug!("registration for an email address that already has an account");
                Ok(RegistrationOutcome::EmailAlreadyRegistered {
                    email: email.to_owned(),
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Check a username or email address and a password.
    ///
    /// An identifier containing `@` is looked up as an email address, anything else as a
    /// username. On success the failed login counter is reset and the account is
    /// returned; issuing a session for it is up to the caller.
    ///
    /// Every attempt performs exactly one password hash verification, including attempts
    /// for accounts that do not exist, have no password, are locked or are disabled, so
    /// response time does not tell these cases apart. Attempts against a locked account
    /// are rejected even with the right password and do not extend the lock.
    ///
    /// # Errors
    ///
    /// [`LocalError::InvalidCredentials`], [`LocalError::AccountLocked`] and
    /// [`LocalError::AccountDisabled`] all carry the same
    /// [`public_message`](LocalError::public_message); the variants differ for logging
    /// and metrics only. [`LocalError::EmailNotVerified`] is returned when the password
    /// is right but the email address is unverified. Also [`LocalError::Busy`] and
    /// storage failures.
    pub async fn login(&self, identifier: &str, password: &str) -> Result<User, LocalError> {
        let inner = &self.inner;
        let record = self.find(identifier.trim()).await?;

        let Some((record, hash)) = record.and_then(|r| {
            let hash = r.password_hash.clone()?;
            Some((r, hash))
        }) else {
            inner.hasher.verify_dummy(password).await?;
            tracing::debug!("login rejected: no such account or no password set");
            return Err(LocalError::InvalidCredentials);
        };

        let password_matches = inner.hasher.verify(password, &hash).await?;
        let user = record.user;
        let now = (inner.clock)();

        if user.disabled_at.is_some() {
            tracing::debug!(user_id = %user.id, "login rejected: account is disabled");
            return Err(LocalError::AccountDisabled);
        }
        if let Some(until) = record.locked_until.filter(|until| *until > now) {
            tracing::debug!(user_id = %user.id, "login rejected: account is locked");
            return Err(LocalError::AccountLocked { until });
        }
        if !password_matches {
            let failures = inner.store.record_failed_login(user.id).await?;
            if let Some(duration) = inner.lockout.lock_duration(failures) {
                inner
                    .store
                    .set_locked_until(user.id, Some(now + duration))
                    .await?;
                tracing::warn!(
                    user_id = %user.id,
                    failures,
                    lock_secs = duration.as_secs(),
                    "account locked after repeated failed logins"
                );
            } else {
                tracing::debug!(user_id = %user.id, failures, "login rejected: wrong password");
            }
            return Err(LocalError::InvalidCredentials);
        }

        if inner.require_verified_email && user.email_verified_at.is_none() {
            tracing::debug!(user_id = %user.id, "login rejected: email address is not verified");
            return Err(LocalError::EmailNotVerified);
        }

        inner.store.record_successful_login(user.id).await?;
        tracing::debug!(user_id = %user.id, "login succeeded");
        Ok(user)
    }

    async fn find(&self, identifier: &str) -> Result<Option<UserRecord>, LocalError> {
        let store = &self.inner.store;
        // Nothing this long or empty can be a username or an email address.
        if identifier.is_empty() || identifier.len() > validate::MAX_EMAIL_CHARS {
            return Ok(None);
        }
        let record = if identifier.contains('@') {
            store.find_by_email(identifier).await?
        } else {
            store.find_by_username(identifier).await?
        };
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::MemoryUserStore;
    use std::sync::Mutex;

    const PASSWORD: &str = "correct horse battery staple";

    /// A clock the test moves by hand.
    #[derive(Clone)]
    struct TestClock(Arc<Mutex<SystemTime>>);

    impl TestClock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(SystemTime::now())))
        }

        fn now(&self) -> SystemTime {
            *self.0.lock().unwrap()
        }

        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    fn builder() -> (LocalAuthBuilder<MemoryUserStore>, TestClock) {
        let clock = TestClock::new();
        let for_auth = clock.clone();
        let builder = LocalAuth::builder(MemoryUserStore::new())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .clock(move || for_auth.now());
        (builder, clock)
    }

    fn auth() -> (LocalAuth<MemoryUserStore>, TestClock) {
        let (builder, clock) = builder();
        (builder.build().unwrap(), clock)
    }

    fn registration(username: &str, email: &str) -> Registration {
        Registration {
            username: username.into(),
            email: email.into(),
            name: "Budi Santoso".into(),
            password: PASSWORD.into(),
        }
    }

    async fn register_budi(auth: &LocalAuth<MemoryUserStore>) -> User {
        let outcome = auth
            .register(registration("budi", "budi@example.com"))
            .await
            .unwrap();
        let user = outcome.created().unwrap().clone();
        verify_email(auth, &user)
    }

    /// Mark the account's email address as verified, as the verification flow would.
    fn verify_email(auth: &LocalAuth<MemoryUserStore>, user: &User) -> User {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        auth.store()
            .update(user.id, |r| r.user.email_verified_at = Some(at));
        auth.store().get(user.id).unwrap().user
    }

    async fn fail_login(auth: &LocalAuth<MemoryUserStore>, times: u32) {
        for _ in 0..times {
            let result = auth.login("budi", "wrong password").await;
            assert!(matches!(result, Err(LocalError::InvalidCredentials)));
        }
    }

    #[test]
    fn lockout_grows_and_is_capped() {
        let policy = LockoutPolicy::default();
        assert_eq!(policy.lock_duration(0), None);
        assert_eq!(policy.lock_duration(4), None);
        assert_eq!(policy.lock_duration(5), Some(Duration::from_secs(60)));
        assert_eq!(policy.lock_duration(6), Some(Duration::from_secs(120)));
        assert_eq!(policy.lock_duration(7), Some(Duration::from_secs(240)));
        assert_eq!(policy.lock_duration(8), Some(Duration::from_secs(480)));
        assert_eq!(policy.lock_duration(9), Some(Duration::from_secs(900)));
        assert_eq!(
            policy.lock_duration(u32::MAX),
            Some(Duration::from_secs(900))
        );

        let strict = LockoutPolicy::default().threshold(0);
        assert_eq!(strict.threshold, 1);
        assert_eq!(strict.lock_duration(1), Some(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn register_then_login_with_username_or_email() {
        let (auth, _) = auth();
        let user = auth
            .register(Registration {
                username: "  Budi ".into(),
                email: " Budi@Example.com ".into(),
                name: " Budi Santoso ".into(),
                password: PASSWORD.into(),
            })
            .await
            .unwrap()
            .created()
            .unwrap()
            .clone();

        assert_eq!(user.username, "Budi");
        assert_eq!(user.email, "Budi@Example.com");
        assert_eq!(user.name, "Budi Santoso");
        assert_eq!(user.email_verified_at, None);
        assert_eq!(user.disabled_at, None);

        let record = auth.store().get(user.id).unwrap();
        let hash = record.password_hash.unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(!hash.contains(PASSWORD));

        let user = verify_email(&auth, &user);
        assert_eq!(auth.login("budi", PASSWORD).await.unwrap(), user);
        assert_eq!(auth.login("BUDI", PASSWORD).await.unwrap(), user);
        assert_eq!(
            auth.login(" budi@example.com ", PASSWORD).await.unwrap(),
            user
        );
    }

    #[tokio::test]
    async fn register_validates_input() {
        let (auth, _) = auth();
        let mut input = registration("b!", "budi@example.com");
        assert!(matches!(
            auth.register(input.clone()).await,
            Err(LocalError::InvalidUsername)
        ));

        input = registration("budi", "not-an-email");
        assert!(matches!(
            auth.register(input.clone()).await,
            Err(LocalError::InvalidEmail)
        ));

        input = registration("budi", "budi@example.com");
        input.name = "x".repeat(256);
        assert!(matches!(
            auth.register(input.clone()).await,
            Err(LocalError::InvalidName)
        ));

        input = registration("budi", "budi@example.com");
        input.password = "1234567".into();
        assert!(matches!(
            auth.register(input.clone()).await,
            Err(LocalError::PasswordTooShort { min: 8 })
        ));

        input.password = "a".repeat(129);
        assert!(matches!(
            auth.register(input.clone()).await,
            Err(LocalError::PasswordTooLong { max: 128 })
        ));
        assert!(auth.store().is_empty());

        input.password = "a".repeat(128);
        assert!(auth.register(input.clone()).await.is_ok());
        input = registration("siti", "siti@example.com");
        input.password = "12345678".into();
        assert!(auth.register(input).await.is_ok());
    }

    #[tokio::test]
    async fn duplicate_email_looks_like_success_by_default() {
        let (auth, _) = auth();
        let budi = register_budi(&auth).await;

        let outcome = auth
            .register(registration("someone-else", " BUDI@example.com "))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            RegistrationOutcome::EmailAlreadyRegistered {
                email: "BUDI@example.com".into()
            }
        );
        assert!(outcome.created().is_none());

        // Nothing was created or changed, and the original password still works.
        assert_eq!(auth.store().len(), 1);
        assert!(
            auth.store()
                .find_by_username("someone-else")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(auth.login("budi", PASSWORD).await.unwrap(), budi);
    }

    #[tokio::test]
    async fn duplicate_email_is_an_error_when_revealing_is_enabled() {
        let (builder, _) = builder();
        let auth = builder.reveal_existing_email(true).build().unwrap();
        register_budi(&auth).await;

        let result = auth
            .register(registration("someone-else", "budi@example.com"))
            .await;
        assert!(matches!(result, Err(LocalError::EmailTaken)));
        assert_eq!(auth.store().len(), 1);
    }

    #[tokio::test]
    async fn duplicate_username_is_reported() {
        let (auth, _) = auth();
        register_budi(&auth).await;

        let other_email = auth
            .register(registration("BUDI", "other@example.com"))
            .await;
        assert!(matches!(other_email, Err(LocalError::UsernameTaken)));

        // Also when the email address is registered: the username answer wins and says
        // nothing about the address.
        let same_email = auth
            .register(registration("budi", "budi@example.com"))
            .await;
        assert!(matches!(same_email, Err(LocalError::UsernameTaken)));
        assert_eq!(auth.store().len(), 1);
    }

    #[tokio::test]
    async fn username_availability() {
        let (builder, _) = builder();
        let auth = builder.reveal_existing_email(true).build().unwrap();
        assert!(auth.username_available("budi").await.unwrap());
        register_budi(&auth).await;
        assert!(!auth.username_available("budi").await.unwrap());
        assert!(!auth.username_available(" Budi ").await.unwrap());
        assert!(auth.username_available("siti").await.unwrap());
        assert!(matches!(
            auth.username_available("no spaces allowed").await,
            Err(LocalError::InvalidUsername)
        ));
    }

    #[tokio::test]
    async fn username_check_is_off_while_registration_hides_existing_emails() {
        let (auth, _) = auth();
        register_budi(&auth).await;
        for username in ["budi", "siti", "not a username"] {
            let error = auth.username_available(username).await.unwrap_err();
            assert!(matches!(error, LocalError::UsernameCheckDisabled));
            assert_eq!(error.public_message(), "Not available");
        }
    }

    #[tokio::test]
    async fn name_is_required() {
        let (auth, _) = auth();
        for name in ["", "   "] {
            let mut input = registration("budi", "budi@example.com");
            input.name = name.into();
            assert!(matches!(
                auth.register(input).await,
                Err(LocalError::InvalidName)
            ));
        }
        assert!(auth.store().is_empty());
    }

    #[tokio::test]
    async fn minimum_password_length_is_configurable() {
        let (builder, _) = builder();
        let auth = builder
            .password_policy(PasswordPolicy::default().min_chars(12))
            .build()
            .unwrap();

        let mut input = registration("budi", "budi@example.com");
        input.password = "11 chars...".into();
        assert!(matches!(
            auth.register(input.clone()).await,
            Err(LocalError::PasswordTooShort { min: 12 })
        ));
        input.password = "12 chars....".into();
        assert!(auth.register(input).await.is_ok());
    }

    #[tokio::test]
    async fn unverified_email_cannot_log_in() {
        let (auth, _) = auth();
        let user = auth
            .register(registration("budi", "budi@example.com"))
            .await
            .unwrap()
            .created()
            .unwrap()
            .clone();

        let error = auth.login("budi", PASSWORD).await.unwrap_err();
        assert!(matches!(error, LocalError::EmailNotVerified));
        assert_eq!(error.public_message(), "Email address is not verified");
        assert_eq!(auth.store().get(user.id).unwrap().failed_login_count, 0);

        // Without the password the account looks like any other.
        let error = auth.login("budi", "wrong password").await.unwrap_err();
        assert!(matches!(error, LocalError::InvalidCredentials));
        assert_eq!(auth.store().get(user.id).unwrap().failed_login_count, 1);

        let user = verify_email(&auth, &user);
        assert_eq!(auth.login("budi", PASSWORD).await.unwrap(), user);
    }

    #[tokio::test]
    async fn unverified_email_can_log_in_when_the_requirement_is_off() {
        let (builder, _) = builder();
        let auth = builder.require_verified_email(false).build().unwrap();
        let user = auth
            .register(registration("budi", "budi@example.com"))
            .await
            .unwrap()
            .created()
            .unwrap()
            .clone();

        assert_eq!(user.email_verified_at, None);
        assert_eq!(auth.login("budi", PASSWORD).await.unwrap(), user);
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_user_are_indistinguishable() {
        let (auth, _) = auth();
        let budi = register_budi(&auth).await;

        let wrong_password = auth.login("budi", "wrong password").await.unwrap_err();
        let unknown_user = auth.login("nobody", PASSWORD).await.unwrap_err();
        let unknown_email = auth
            .login("nobody@example.com", PASSWORD)
            .await
            .unwrap_err();
        let empty = auth.login("", "").await.unwrap_err();
        let oversized = auth.login(&"x".repeat(5000), PASSWORD).await.unwrap_err();

        for error in [
            &wrong_password,
            &unknown_user,
            &unknown_email,
            &empty,
            &oversized,
        ] {
            assert!(matches!(error, LocalError::InvalidCredentials));
            assert_eq!(error.public_message(), "Invalid username or password");
            assert_eq!(error.to_string(), "invalid credentials");
        }
        assert_eq!(auth.store().get(budi.id).unwrap().failed_login_count, 1);
    }

    #[tokio::test]
    async fn oversized_password_is_rejected_like_a_wrong_one() {
        let (auth, _) = auth();
        register_budi(&auth).await;
        let result = auth.login("budi", &"a".repeat(100_000)).await;
        assert!(matches!(result, Err(LocalError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn account_without_password_cannot_log_in() {
        let (auth, _) = auth();
        let budi = register_budi(&auth).await;
        auth.store().update(budi.id, |r| r.password_hash = None);

        let result = auth.login("budi", PASSWORD).await;
        assert!(matches!(result, Err(LocalError::InvalidCredentials)));
        assert_eq!(auth.store().get(budi.id).unwrap().failed_login_count, 0);
    }

    #[tokio::test]
    async fn disabled_account_cannot_log_in() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;
        auth.store()
            .update(budi.id, |r| r.user.disabled_at = Some(clock.now()));

        let error = auth.login("budi", PASSWORD).await.unwrap_err();
        assert!(matches!(error, LocalError::AccountDisabled));
        assert_eq!(error.public_message(), "Invalid username or password");

        let error = auth.login("budi", "wrong password").await.unwrap_err();
        assert!(matches!(error, LocalError::AccountDisabled));
        assert_eq!(auth.store().get(budi.id).unwrap().failed_login_count, 0);
    }

    #[tokio::test]
    async fn successful_login_resets_the_failure_count() {
        let (auth, _) = auth();
        let budi = register_budi(&auth).await;

        fail_login(&auth, 4).await;
        let record = auth.store().get(budi.id).unwrap();
        assert_eq!(record.failed_login_count, 4);
        assert_eq!(record.locked_until, None);

        auth.login("budi", PASSWORD).await.unwrap();
        assert_eq!(auth.store().get(budi.id).unwrap().failed_login_count, 0);

        // The count starts over, so four more failures still do not lock.
        fail_login(&auth, 4).await;
        assert!(auth.login("budi", PASSWORD).await.is_ok());
    }

    #[tokio::test]
    async fn account_locks_after_repeated_failures_and_unlocks_later() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;

        fail_login(&auth, 5).await;
        let locked_until = auth.store().get(budi.id).unwrap().locked_until.unwrap();
        assert_eq!(locked_until, clock.now() + Duration::from_secs(60));

        // The right password is refused while locked, with the generic message.
        let error = auth.login("budi", PASSWORD).await.unwrap_err();
        assert!(matches!(error, LocalError::AccountLocked { until } if until == locked_until));
        assert_eq!(error.public_message(), "Invalid username or password");

        // Attempts during the lock neither count nor extend it.
        let error = auth.login("budi", "wrong password").await.unwrap_err();
        assert!(matches!(error, LocalError::AccountLocked { .. }));
        let record = auth.store().get(budi.id).unwrap();
        assert_eq!(record.failed_login_count, 5);
        assert_eq!(record.locked_until, Some(locked_until));

        clock.advance(Duration::from_secs(59));
        assert!(matches!(
            auth.login("budi", PASSWORD).await,
            Err(LocalError::AccountLocked { .. })
        ));

        clock.advance(Duration::from_secs(1));
        assert_eq!(auth.login("budi", PASSWORD).await.unwrap(), budi);
        let record = auth.store().get(budi.id).unwrap();
        assert_eq!(record.failed_login_count, 0);
        assert_eq!(record.locked_until, None);
    }

    #[tokio::test]
    async fn lock_gets_longer_with_each_failure_after_it_expires() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;

        fail_login(&auth, 5).await;
        clock.advance(Duration::from_secs(60));

        // One more failure after the first lock expired: locked again, for longer.
        fail_login(&auth, 1).await;
        let record = auth.store().get(budi.id).unwrap();
        assert_eq!(record.failed_login_count, 6);
        assert_eq!(
            record.locked_until,
            Some(clock.now() + Duration::from_secs(120))
        );

        clock.advance(Duration::from_secs(119));
        assert!(matches!(
            auth.login("budi", PASSWORD).await,
            Err(LocalError::AccountLocked { .. })
        ));
        clock.advance(Duration::from_secs(1));
        assert!(auth.login("budi", PASSWORD).await.is_ok());
    }

    #[tokio::test]
    async fn lockout_policy_is_configurable() {
        let (builder, clock) = builder();
        let policy = LockoutPolicy::default()
            .threshold(2)
            .base_duration(Duration::from_secs(10))
            .max_duration(Duration::from_secs(15));
        let auth = builder.lockout(policy).build().unwrap();
        let budi = register_budi(&auth).await;

        fail_login(&auth, 1).await;
        assert_eq!(auth.store().get(budi.id).unwrap().locked_until, None);
        fail_login(&auth, 1).await;
        assert_eq!(
            auth.store().get(budi.id).unwrap().locked_until,
            Some(clock.now() + Duration::from_secs(10))
        );

        clock.advance(Duration::from_secs(10));
        fail_login(&auth, 1).await;
        assert_eq!(
            auth.store().get(budi.id).unwrap().locked_until,
            Some(clock.now() + Duration::from_secs(15))
        );
    }

    #[tokio::test]
    async fn busy_hasher_is_reported_as_busy() {
        let limits = HashLimits::default().max_concurrent(1).max_queued(1);
        let hasher = PasswordHasher::insecure_for_tests(limits).unwrap();
        let auth = LocalAuth::builder(MemoryUserStore::new())
            .hasher(hasher.clone())
            .build()
            .unwrap();
        let budi = register_budi(&auth).await;

        // One job holds the only worker and one fills the queue.
        let (release, blocked) = hasher.occupy_worker();
        let filler = hasher.queue_noop();

        let login = auth.login("budi", PASSWORD).await.unwrap_err();
        assert!(matches!(login, LocalError::Busy));
        assert_eq!(login.public_message(), "Service is busy, try again shortly");
        let unknown = auth.login("nobody", PASSWORD).await.unwrap_err();
        assert!(matches!(unknown, LocalError::Busy));
        let register = auth
            .register(registration("siti", "siti@example.com"))
            .await
            .unwrap_err();
        assert!(matches!(register, LocalError::Busy));

        // A refused attempt is not a failed login.
        assert_eq!(auth.store().get(budi.id).unwrap().failed_login_count, 0);

        release.send(()).unwrap();
        blocked.await.unwrap().unwrap();
        filler.await.unwrap().unwrap();
        assert!(auth.login("budi", PASSWORD).await.is_ok());
    }

    #[test]
    fn debug_output_omits_the_password() {
        let debug = format!("{:?}", registration("budi", "budi@example.com"));
        assert!(!debug.contains(PASSWORD), "{debug}");
        let (auth, _) = auth();
        assert!(!format!("{auth:?}").contains("argon2"));
    }
}
