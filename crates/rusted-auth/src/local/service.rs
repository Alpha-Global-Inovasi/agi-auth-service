use super::error::LocalError;
use super::mail::{DynMailer, Mailer};
use super::password::{HashLimits, PasswordHasher, PasswordPolicy};
use super::validate;
#[cfg(feature = "mfa")]
use crate::mfa::SecondFactor;
use crate::session::attempts::{AttemptStore, DynAttemptStore, MemoryAttemptStore};
use crate::session::event::{AuthEvent, AuthEventKind, Events, LoginFailure};
use crate::session::manager::{Clock, SessionManager};
use crate::session::model::{Session, SessionContext, SessionState, SessionStore};
use crate::session::one_time::{DynOneTimeTokenStore, OneTimeTokenStore};
use crate::session::token::SessionToken;
use crate::session::user::{NewUser, StoreError, User, UserRecord, UserStore};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

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

/// Lifetimes of email links and how many emails others can cause an account to receive.
///
/// The limit covers the emails that someone other than the owner can trigger: the notice
/// about a registration with the address, a password reset link, a verification link
/// sent again, and the lockout notice. With the defaults an account receives at most 3
/// of them in 15 minutes; further requests succeed as usual but send nothing and create
/// no new link, so earlier links keep working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EmailPolicy {
    /// How long a verification link works. Default: 24 hours.
    pub verify_email_ttl: Duration,
    /// How long a password reset link works. Default: 1 hour, at most
    /// [`MAX_RESET_PASSWORD_TTL`].
    pub reset_password_ttl: Duration,
    /// Emails per account and [`window`](Self::window). Default: 3.
    pub max_emails: u32,
    /// Period over which [`max_emails`](Self::max_emails) counts. Default: 15 minutes.
    pub window: Duration,
}

/// Longest lifetime of a password reset link.
pub const MAX_RESET_PASSWORD_TTL: Duration = Duration::from_secs(24 * 60 * 60);

impl Default for EmailPolicy {
    fn default() -> Self {
        Self {
            verify_email_ttl: Duration::from_secs(24 * 60 * 60),
            reset_password_ttl: Duration::from_secs(60 * 60),
            max_emails: 3,
            window: Duration::from_secs(15 * 60),
        }
    }
}

impl EmailPolicy {
    /// Set [`verify_email_ttl`](Self::verify_email_ttl).
    pub fn verify_email_ttl(mut self, ttl: Duration) -> Self {
        self.verify_email_ttl = ttl;
        self
    }

    /// Set [`reset_password_ttl`](Self::reset_password_ttl). Longer values are cut to
    /// [`MAX_RESET_PASSWORD_TTL`].
    pub fn reset_password_ttl(mut self, ttl: Duration) -> Self {
        self.reset_password_ttl = ttl.min(MAX_RESET_PASSWORD_TTL);
        self
    }

    /// Set [`max_emails`](Self::max_emails) per [`window`](Self::window). Values below
    /// 1 are raised to 1.
    pub fn limit(mut self, max_emails: u32, window: Duration) -> Self {
        self.max_emails = max_emails.max(1);
        self.window = window;
        self
    }
}

/// How many wrong current passwords [`LocalAuth::change_password`] accepts.
///
/// With the defaults, the 5th wrong password within 15 minutes revokes the session that
/// made the attempts, and further changes are refused until the period ends. This count
/// is separate from the failed logins that lock an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PasswordChangePolicy {
    /// Wrong current passwords per account and [`window`](Self::window). Default: 5.
    pub max_attempts: u32,
    /// Period over which they count. Default: 15 minutes.
    pub window: Duration,
}

impl Default for PasswordChangePolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window: Duration::from_secs(15 * 60),
        }
    }
}

impl PasswordChangePolicy {
    /// Set both values. Attempts below 1 are raised to 1.
    pub fn limit(mut self, max_attempts: u32, window: Duration) -> Self {
        self.max_attempts = max_attempts.max(1);
        self.window = window;
        self
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

/// A successful [`LocalAuth::login`]: the account and its new session.
///
/// When the account has a second factor set up, the session waits for it
/// ([`mfa_required`](Self::mfa_required)): its token only works for
/// `Mfa::complete_login` (with the `mfa` feature), which replaces it with the token of an
/// active session.
///
/// This is the only time the session token is available. The `Debug` output does not
/// contain it.
#[derive(Debug)]
#[non_exhaustive]
pub struct Login {
    /// The account that logged in.
    pub user: User,
    /// The session created for this login.
    pub session: Session,
    /// The session token to hand to the client.
    pub token: SessionToken,
}

impl Login {
    /// `true` when the session is in state [`PendingMfa`](SessionState::PendingMfa):
    /// the client has to complete the second authentication step before the session
    /// can be used.
    pub fn mfa_required(&self) -> bool {
        self.session.state == SessionState::PendingMfa
    }
}

/// Local accounts: registration and login with a username or email address and a
/// password.
///
/// Cheap to clone; clones share the stores, the session manager and the password hasher.
///
/// ```rust
/// use rusted_auth::local::{LocalAuth, NoMailer, Registration};
/// use rusted_auth::session::{
///     MemoryOneTimeTokenStore, MemorySessionStore, MemoryUserStore, SessionContext,
///     SessionManager,
/// };
/// use std::time::SystemTime;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let users = MemoryUserStore::new();
/// let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
/// let auth = LocalAuth::builder(users, sessions)
///     // A real application queues the emails for delivery; see `Mailer`.
///     .mailer(NoMailer)
///     .tokens(MemoryOneTimeTokenStore::new())
///     .build()?;
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
/// // Logging in requires a verified email address. Normally the owner opens the link
/// // from the verification email (`LocalAuth::verify_email`); here the test store is
/// // edited directly.
/// let id = outcome.created().expect("a new account").id;
/// auth.store()
///     .update(id, |account| account.user.email_verified_at = Some(SystemTime::now()));
///
/// let login = auth
///     .login(
///         "budi@example.com",
///         "correct horse battery staple",
///         SessionContext::web(),
///     )
///     .await?;
/// assert_eq!(login.user.username, "budi");
///
/// // The token goes to the client; later requests are checked with it.
/// let authenticated = auth.sessions().validate(login.token.expose()).await?;
/// assert_eq!(authenticated.user.id, id);
/// # Ok(())
/// # }
/// ```
pub struct LocalAuth<U, S> {
    inner: Arc<Inner<U, S>>,
}

struct Inner<U, S> {
    store: U,
    sessions: SessionManager<S>,
    mailer: Arc<dyn DynMailer>,
    tokens: Arc<dyn DynOneTimeTokenStore>,
    attempts: Arc<dyn DynAttemptStore>,
    email_policy: EmailPolicy,
    password_change: PasswordChangePolicy,
    events: Events,
    hasher: PasswordHasher,
    lockout: LockoutPolicy,
    password_policy: PasswordPolicy,
    reveal_existing_email: bool,
    require_verified_email: bool,
    #[cfg(feature = "mfa")]
    second_factor: Option<Arc<dyn SecondFactor>>,
    clock: Clock,
}

impl<U, S> Clone for LocalAuth<U, S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<U, S> fmt::Debug for LocalAuth<U, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalAuth")
            .field("hasher", &self.inner.hasher)
            .field("lockout", &self.inner.lockout)
            .field("password_policy", &self.inner.password_policy)
            .field("email_policy", &self.inner.email_policy)
            .field("password_change", &self.inner.password_change)
            .field("reveal_existing_email", &self.inner.reveal_existing_email)
            .field("require_verified_email", &self.inner.require_verified_email)
            .finish_non_exhaustive()
    }
}

/// Configures a [`LocalAuth`]. Created by [`LocalAuth::builder`].
pub struct LocalAuthBuilder<U, S> {
    store: U,
    sessions: SessionManager<S>,
    mailer: Option<Arc<dyn DynMailer>>,
    tokens: Option<Arc<dyn DynOneTimeTokenStore>>,
    attempts: Arc<dyn DynAttemptStore>,
    email_policy: EmailPolicy,
    password_change: PasswordChangePolicy,
    hasher: Option<PasswordHasher>,
    hash_limits: HashLimits,
    lockout: LockoutPolicy,
    password_policy: PasswordPolicy,
    reveal_existing_email: bool,
    require_verified_email: bool,
    #[cfg(feature = "mfa")]
    second_factor: Option<Arc<dyn SecondFactor>>,
    clock: Clock,
}

impl<U: UserStore, S: SessionStore> LocalAuthBuilder<U, S> {
    /// Where the account emails go: verification and reset links, and notices about
    /// registrations, lockouts and password changes. **Required**; pass
    /// [`NoMailer`](super::NoMailer) to send nothing. See [`Mailer`] for the contract,
    /// above all that `send` must not wait for delivery.
    pub fn mailer(mut self, mailer: impl Mailer) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }

    /// Where verification and reset tokens are kept. **Required**. Every process that
    /// serves the links must use the same store, since a link sent by one process may be
    /// opened on another.
    pub fn tokens(mut self, store: impl OneTimeTokenStore) -> Self {
        self.tokens = Some(Arc::new(store));
        self
    }

    /// Where emails per account and wrong current passwords are counted. The default, a
    /// [`MemoryAttemptStore`], counts in each process separately; with several processes,
    /// give them one shared store. It can be the store given to `MfaBuilder::attempts`.
    pub fn attempts(mut self, store: impl AttemptStore) -> Self {
        self.attempts = Arc::new(store);
        self
    }

    /// Link lifetimes and the email limit per account.
    pub fn email_policy(mut self, policy: EmailPolicy) -> Self {
        self.email_policy = policy;
        self
    }

    /// The limit on wrong current passwords in [`LocalAuth::change_password`].
    pub fn password_change_policy(mut self, policy: PasswordChangePolicy) -> Self {
        self.password_change = policy;
        self
    }

    /// Require the second factors of `mfa` at login: an account with a confirmed TOTP
    /// authenticator then gets a session in state
    /// [`PendingMfa`](SessionState::PendingMfa) after a correct password, which
    /// [`Mfa::complete_login`](crate::mfa::Mfa::complete_login) turns into an active
    /// session. Accounts without one log in with the password alone, as before.
    ///
    /// This is opt-in: without this call, password logins never wait for a second
    /// factor, even for accounts that have TOTP enabled. Call it whenever the
    /// application offers TOTP.
    ///
    /// `mfa` must use the same session manager as this service. Available with the `mfa`
    /// feature.
    #[cfg(feature = "mfa")]
    pub fn mfa<M: crate::mfa::MfaStore>(mut self, mfa: &crate::mfa::Mfa<M, S>) -> Self {
        self.second_factor = Some(Arc::new(mfa.clone()));
        self
    }

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
    /// password hash on the calling thread (see [`PasswordHasher::new`]) and reports its
    /// queue waits to the session manager's event sink.
    ///
    /// Fails with [`LocalError::Configuration`] when [`mailer`](Self::mailer) or
    /// [`tokens`](Self::tokens) was not called.
    pub fn build(self) -> Result<LocalAuth<U, S>, LocalError> {
        let mailer = self.mailer.ok_or(LocalError::Configuration(
            "LocalAuthBuilder::mailer was not called; pass NoMailer to send no email",
        ))?;
        let tokens = self.tokens.ok_or(LocalError::Configuration(
            "LocalAuthBuilder::tokens was not called",
        ))?;
        let events = self.sessions.events().clone();
        let hasher = match self.hasher {
            Some(hasher) => hasher,
            None => PasswordHasher::production(self.hash_limits, events.clone())?,
        };
        Ok(LocalAuth {
            inner: Arc::new(Inner {
                store: self.store,
                sessions: self.sessions,
                mailer,
                tokens,
                attempts: self.attempts,
                email_policy: self.email_policy,
                password_change: self.password_change,
                events,
                hasher,
                lockout: self.lockout,
                password_policy: self.password_policy,
                reveal_existing_email: self.reveal_existing_email,
                require_verified_email: self.require_verified_email,
                #[cfg(feature = "mfa")]
                second_factor: self.second_factor,
                clock: self.clock,
            }),
        })
    }
}

impl<U: UserStore, S: SessionStore> LocalAuth<U, S> {
    /// Start configuring local accounts backed by `store`, whose logins create sessions
    /// through `sessions`.
    ///
    /// Login events are reported to the event sink of `sessions`
    /// ([`SessionManagerBuilder::events`](crate::session::SessionManagerBuilder::events)).
    pub fn builder(store: U, sessions: SessionManager<S>) -> LocalAuthBuilder<U, S> {
        LocalAuthBuilder {
            store,
            sessions,
            mailer: None,
            tokens: None,
            attempts: Arc::new(MemoryAttemptStore::new()),
            email_policy: EmailPolicy::default(),
            password_change: PasswordChangePolicy::default(),
            hasher: None,
            hash_limits: HashLimits::default(),
            lockout: LockoutPolicy::default(),
            password_policy: PasswordPolicy::default(),
            reveal_existing_email: false,
            require_verified_email: true,
            #[cfg(feature = "mfa")]
            second_factor: None,
            clock: Box::new(SystemTime::now),
        }
    }

    /// The user store.
    pub fn store(&self) -> &U {
        &self.inner.store
    }

    /// The session manager: validates the tokens that [`login`](Self::login) hands out,
    /// lists and revokes sessions.
    pub fn sessions(&self) -> &SessionManager<S> {
        &self.inner.sessions
    }

    /// Whether registration reports email addresses that already have an account
    /// ([`LocalAuthBuilder::reveal_existing_email`]). When it does not, web adapters
    /// leave out the route of [`username_available`](Self::username_available).
    pub fn reveals_existing_email(&self) -> bool {
        self.inner.reveal_existing_email
    }

    /// Whether password logins wait for a second factor, that is whether
    /// [`LocalAuthBuilder::mfa`] was called. Always `false` without the `mfa` feature.
    ///
    /// Web adapters check this when they are given an `mfa::Mfa` as well, since a
    /// service built without it lets accounts with TOTP log in with the password alone.
    pub fn second_factor_enabled(&self) -> bool {
        #[cfg(feature = "mfa")]
        {
            self.inner.second_factor.is_some()
        }
        #[cfg(not(feature = "mfa"))]
        {
            false
        }
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
                self.send_verification(&user).await;
                Ok(RegistrationOutcome::Created(user))
            }
            Err(StoreError::EmailTaken) if !inner.reveal_existing_email => {
                tracing::debug!("registration for an email address that already has an account");
                self.notify_registration_attempt(email).await;
                Ok(RegistrationOutcome::EmailAlreadyRegistered {
                    email: email.to_owned(),
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Check a username or email address and a password, and create a session.
    ///
    /// An identifier containing `@` is looked up as an email address, anything else as a
    /// username. `context` says what kind of client is logging in and carries its address
    /// and `User-Agent`, which are stored with the session and copied into audit events.
    ///
    /// On success the failed login counter is reset and the result holds the account and
    /// a **new** session in state [`Active`](SessionState::Active) with its token. Every
    /// login creates its own session and no existing session is reused, so a token that
    /// was known before the login never becomes authenticated by it (session fixation).
    /// Earlier sessions of the account stay valid.
    ///
    /// When second factors are configured (`LocalAuthBuilder::mfa`, with the `mfa`
    /// feature) and the account has a confirmed TOTP authenticator, the new session is in
    /// state [`PendingMfa`](SessionState::PendingMfa) instead and lasts 5 minutes
    /// ([`Login::mfa_required`]).
    ///
    /// Every attempt performs exactly one password hash verification, including attempts
    /// for accounts that do not exist, have no password, are locked or are disabled, so
    /// response time does not tell these cases apart. Attempts against a locked account
    /// are rejected even with the right password and do not extend the lock.
    ///
    /// The account is read again after the hash check, and that second read decides:
    /// a lock, a disabled account or a new password stored while the request waited
    /// for the hasher applies to it. Concurrent guesses therefore cannot slip past a
    /// lock that earlier guesses set. Accounts that do not exist are looked up twice
    /// as well.
    ///
    /// # Outdated password hashes
    ///
    /// When the stored hash was made with other parameters than the hasher uses now, a
    /// successful login hashes the password again and replaces the stored hash. This
    /// costs one extra hash, once per account. If it fails, for example because hashing
    /// is at capacity, the login still succeeds and the next one tries again.
    ///
    /// # Errors
    ///
    /// [`LocalError::InvalidCredentials`], [`LocalError::AccountLocked`] and
    /// [`LocalError::AccountDisabled`] all carry the same
    /// [`public_message`](LocalError::public_message); the variants differ for logging
    /// and metrics only. [`LocalError::EmailNotVerified`] is returned when the password
    /// is right but the email address is unverified. Also [`LocalError::Busy`] and
    /// storage failures.
    pub async fn login(
        &self,
        identifier: &str,
        password: &str,
        context: SessionContext,
    ) -> Result<Login, LocalError> {
        let inner = &self.inner;
        let context = context.normalized();
        let identifier = identifier.trim();
        let record = self.find(identifier).await?;

        let Some((record, hash)) = record.and_then(|r| {
            let hash = r.password_hash.clone()?;
            Some((r, hash))
        }) else {
            inner.hasher.verify_dummy(password).await?;
            // The same second lookup as for an existing account, below.
            self.find(identifier).await?;
            tracing::debug!("login rejected: no such account or no password set");
            let now = (inner.clock)();
            self.login_failed(now, None, &context, LoginFailure::UnknownAccount);
            return Err(LocalError::InvalidCredentials);
        };

        let password_matches = inner.hasher.verify(password, &hash).await?;
        // Read the account again: the first read can be up to `HashLimits::max_wait`
        // old by now. Concurrent guesses that queued for the hasher before the account
        // locked would otherwise all be judged against the unlocked state, so a burst
        // of requests could try far more passwords than the lockout allows, and could
        // extend a lock that is already in place.
        let fresh = self
            .find(identifier)
            .await?
            .filter(|fresh| fresh.user.id == record.user.id);
        let Some(record) = fresh else {
            tracing::debug!(user_id = %record.user.id, "login rejected: account changed during login");
            let now = (inner.clock)();
            self.login_failed(
                now,
                Some(record.user.id),
                &context,
                LoginFailure::UnknownAccount,
            );
            return Err(LocalError::InvalidCredentials);
        };
        // A password reset or change while the hash was checked replaced it: the
        // password that matched is no longer the account's.
        let password_matches =
            password_matches && record.password_hash.as_deref() == Some(hash.as_str());
        let user = record.user;
        let now = (inner.clock)();

        if user.disabled_at.is_some() {
            tracing::debug!(user_id = %user.id, "login rejected: account is disabled");
            self.login_failed(now, Some(user.id), &context, LoginFailure::AccountDisabled);
            return Err(LocalError::AccountDisabled);
        }
        if let Some(until) = record.locked_until.filter(|until| *until > now) {
            tracing::debug!(user_id = %user.id, "login rejected: account is locked");
            self.login_failed(now, Some(user.id), &context, LoginFailure::AccountLocked);
            return Err(LocalError::AccountLocked { until });
        }
        if !password_matches {
            let failures = inner.store.record_failed_login(user.id).await?;
            self.login_failed(now, Some(user.id), &context, LoginFailure::WrongPassword);
            if let Some(duration) = inner.lockout.lock_duration(failures) {
                let until = now + duration;
                inner.store.set_locked_until(user.id, Some(until)).await?;
                tracing::warn!(
                    user_id = %user.id,
                    failures,
                    lock_secs = duration.as_secs(),
                    "account locked after repeated failed logins"
                );
                self.emit(now, Some(user.id), &context, || {
                    AuthEventKind::AccountLocked {
                        until,
                        failed_logins: failures,
                    }
                });
                // Only at the first lock of a series of failures, so that someone
                // guessing cannot fill the owner's inbox.
                if failures == inner.lockout.threshold.max(1) {
                    self.notify_lockout(now, &user, until, &context).await;
                }
            } else {
                tracing::debug!(user_id = %user.id, failures, "login rejected: wrong password");
            }
            return Err(LocalError::InvalidCredentials);
        }

        if inner.require_verified_email && user.email_verified_at.is_none() {
            tracing::debug!(user_id = %user.id, "login rejected: email address is not verified");
            self.login_failed(now, Some(user.id), &context, LoginFailure::EmailNotVerified);
            return Err(LocalError::EmailNotVerified);
        }

        inner.store.record_successful_login(user.id).await?;
        self.rehash_if_outdated(now, user.id, password, &hash, &context)
            .await;

        let mfa_required = self.second_factor_required(user.id).await?;
        let state = if mfa_required {
            SessionState::PendingMfa
        } else {
            SessionState::Active
        };
        let issued = inner
            .sessions
            .create(user.id, state, context.clone())
            .await?;
        tracing::debug!(
            user_id = %user.id,
            session_id = %issued.session.id,
            mfa_required,
            "login succeeded"
        );
        self.emit(now, Some(user.id), &context, || {
            AuthEventKind::LoginSucceeded {
                session_id: issued.session.id,
                mfa_required,
            }
        });
        Ok(Login {
            user,
            session: issued.session,
            token: issued.token,
        })
    }

    /// Whether the account has to complete a second authentication step.
    async fn second_factor_required(&self, user_id: Uuid) -> Result<bool, LocalError> {
        #[cfg(feature = "mfa")]
        if let Some(second_factor) = &self.inner.second_factor {
            return Ok(second_factor.required_for(user_id).await?);
        }
        let _ = user_id;
        Ok(false)
    }

    /// Replace a password hash made with outdated parameters. Never fails the login.
    async fn rehash_if_outdated(
        &self,
        now: SystemTime,
        user_id: Uuid,
        password: &str,
        current_hash: &str,
        context: &SessionContext,
    ) {
        let inner = &self.inner;
        if !inner.hasher.needs_rehash(current_hash) {
            return;
        }
        let replaced = async {
            let new_hash = inner.hasher.hash(password).await?;
            let replaced = inner
                .store
                .replace_password_hash(user_id, current_hash, new_hash)
                .await?;
            Ok::<_, LocalError>(replaced)
        }
        .await;
        match replaced {
            Ok(true) => {
                tracing::debug!(%user_id, "password hash upgraded to the current parameters");
                self.emit(now, Some(user_id), context, || {
                    AuthEventKind::PasswordRehashed
                });
            }
            Ok(false) => {
                tracing::debug!(%user_id, "password changed during login; hash left as it is");
            }
            Err(error) => {
                tracing::warn!(%user_id, %error, "could not upgrade password hash");
            }
        }
    }

    fn login_failed(
        &self,
        now: SystemTime,
        user_id: Option<Uuid>,
        context: &SessionContext,
        reason: LoginFailure,
    ) {
        self.emit(now, user_id, context, || AuthEventKind::LoginFailed {
            reason,
        });
    }

    fn emit(
        &self,
        now: SystemTime,
        user_id: Option<Uuid>,
        context: &SessionContext,
        kind: impl FnOnce() -> AuthEventKind,
    ) {
        self.inner.events.emit(|| AuthEvent {
            at: now,
            user_id,
            ip: context.ip,
            user_agent: context.user_agent.clone(),
            kind: kind(),
        });
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

mod account;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::testing::Recorder;
    use crate::session::{MemorySessionStore, MemoryUserStore, SessionError, SessionKind};
    use std::sync::Mutex;

    type TestAuth = LocalAuth<MemoryUserStore, MemorySessionStore>;
    type TestBuilder = LocalAuthBuilder<MemoryUserStore, MemorySessionStore>;

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

    fn sessions(
        users: &MemoryUserStore,
        clock: &TestClock,
        recorder: &Recorder,
    ) -> SessionManager<MemorySessionStore> {
        let clock = clock.clone();
        SessionManager::builder(MemorySessionStore::new(users.clone()))
            .events(recorder.clone())
            .clock(move || clock.now())
            .build()
    }

    fn builder_with_events() -> (TestBuilder, TestClock, Recorder) {
        let clock = TestClock::new();
        let recorder = Recorder::default();
        let users = MemoryUserStore::new();
        let sessions = sessions(&users, &clock, &recorder);
        let for_auth = clock.clone();
        let builder = LocalAuth::builder(users, sessions)
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .clock(move || for_auth.now());
        (builder, clock, recorder)
    }

    fn builder() -> (TestBuilder, TestClock) {
        let (builder, clock, _) = builder_with_events();
        (builder, clock)
    }

    /// Log in from a browser and keep only the account, as most tests need.
    async fn login(auth: &TestAuth, identifier: &str, password: &str) -> Result<User, LocalError> {
        auth.login(identifier, password, SessionContext::web())
            .await
            .map(|login| login.user)
    }

    fn auth() -> (TestAuth, TestClock) {
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

    async fn register_budi(auth: &TestAuth) -> User {
        let outcome = auth
            .register(registration("budi", "budi@example.com"))
            .await
            .unwrap();
        let user = outcome.created().unwrap().clone();
        verify_email(auth, &user)
    }

    /// Mark the account's email address as verified, as the verification flow would.
    fn verify_email(auth: &TestAuth, user: &User) -> User {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        auth.store()
            .update(user.id, |r| r.user.email_verified_at = Some(at));
        auth.store().get(user.id).unwrap().user
    }

    async fn fail_login(auth: &TestAuth, times: u32) {
        for _ in 0..times {
            let result = login(auth, "budi", "wrong password").await;
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
        assert_eq!(login(&auth, "budi", PASSWORD).await.unwrap(), user);
        assert_eq!(login(&auth, "BUDI", PASSWORD).await.unwrap(), user);
        assert_eq!(
            login(&auth, " budi@example.com ", PASSWORD).await.unwrap(),
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
        assert_eq!(login(&auth, "budi", PASSWORD).await.unwrap(), budi);
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

        let error = login(&auth, "budi", PASSWORD).await.unwrap_err();
        assert!(matches!(error, LocalError::EmailNotVerified));
        assert_eq!(error.public_message(), "Email address is not verified");
        assert_eq!(auth.store().get(user.id).unwrap().failed_login_count, 0);

        // Without the password the account looks like any other.
        let error = login(&auth, "budi", "wrong password").await.unwrap_err();
        assert!(matches!(error, LocalError::InvalidCredentials));
        assert_eq!(auth.store().get(user.id).unwrap().failed_login_count, 1);

        let user = verify_email(&auth, &user);
        assert_eq!(login(&auth, "budi", PASSWORD).await.unwrap(), user);
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
        assert_eq!(login(&auth, "budi", PASSWORD).await.unwrap(), user);
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_user_are_indistinguishable() {
        let (auth, _) = auth();
        let budi = register_budi(&auth).await;

        let wrong_password = login(&auth, "budi", "wrong password").await.unwrap_err();
        let unknown_user = login(&auth, "nobody", PASSWORD).await.unwrap_err();
        let unknown_email = login(&auth, "nobody@example.com", PASSWORD)
            .await
            .unwrap_err();
        let empty = login(&auth, "", "").await.unwrap_err();
        let oversized = login(&auth, &"x".repeat(5000), PASSWORD).await.unwrap_err();

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
        let result = login(&auth, "budi", &"a".repeat(100_000)).await;
        assert!(matches!(result, Err(LocalError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn account_without_password_cannot_log_in() {
        let (auth, _) = auth();
        let budi = register_budi(&auth).await;
        auth.store().update(budi.id, |r| r.password_hash = None);

        let result = login(&auth, "budi", PASSWORD).await;
        assert!(matches!(result, Err(LocalError::InvalidCredentials)));
        assert_eq!(auth.store().get(budi.id).unwrap().failed_login_count, 0);
    }

    #[tokio::test]
    async fn disabled_account_cannot_log_in() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;
        auth.store()
            .update(budi.id, |r| r.user.disabled_at = Some(clock.now()));

        let error = login(&auth, "budi", PASSWORD).await.unwrap_err();
        assert!(matches!(error, LocalError::AccountDisabled));
        assert_eq!(error.public_message(), "Invalid username or password");

        let error = login(&auth, "budi", "wrong password").await.unwrap_err();
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

        login(&auth, "budi", PASSWORD).await.unwrap();
        assert_eq!(auth.store().get(budi.id).unwrap().failed_login_count, 0);

        // The count starts over, so four more failures still do not lock.
        fail_login(&auth, 4).await;
        assert!(login(&auth, "budi", PASSWORD).await.is_ok());
    }

    #[tokio::test]
    async fn account_locks_after_repeated_failures_and_unlocks_later() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;

        fail_login(&auth, 5).await;
        let locked_until = auth.store().get(budi.id).unwrap().locked_until.unwrap();
        assert_eq!(locked_until, clock.now() + Duration::from_secs(60));

        // The right password is refused while locked, with the generic message.
        let error = login(&auth, "budi", PASSWORD).await.unwrap_err();
        assert!(matches!(error, LocalError::AccountLocked { until } if until == locked_until));
        assert_eq!(error.public_message(), "Invalid username or password");

        // Attempts during the lock neither count nor extend it.
        let error = login(&auth, "budi", "wrong password").await.unwrap_err();
        assert!(matches!(error, LocalError::AccountLocked { .. }));
        let record = auth.store().get(budi.id).unwrap();
        assert_eq!(record.failed_login_count, 5);
        assert_eq!(record.locked_until, Some(locked_until));

        clock.advance(Duration::from_secs(59));
        assert!(matches!(
            login(&auth, "budi", PASSWORD).await,
            Err(LocalError::AccountLocked { .. })
        ));

        clock.advance(Duration::from_secs(1));
        assert_eq!(login(&auth, "budi", PASSWORD).await.unwrap(), budi);
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
            login(&auth, "budi", PASSWORD).await,
            Err(LocalError::AccountLocked { .. })
        ));
        clock.advance(Duration::from_secs(1));
        assert!(login(&auth, "budi", PASSWORD).await.is_ok());
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
        let users = MemoryUserStore::new();
        let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
        let auth = LocalAuth::builder(users, sessions)
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(hasher.clone())
            .build()
            .unwrap();
        let budi = register_budi(&auth).await;

        // One job holds the only worker and one fills the queue.
        let (release, blocked) = hasher.occupy_worker();
        let filler = hasher.queue_noop();

        let refused = login(&auth, "budi", PASSWORD).await.unwrap_err();
        assert!(matches!(refused, LocalError::Busy));
        assert_eq!(
            refused.public_message(),
            "Service is busy, try again shortly"
        );
        let unknown = login(&auth, "nobody", PASSWORD).await.unwrap_err();
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
        assert!(login(&auth, "budi", PASSWORD).await.is_ok());
    }

    #[test]
    fn debug_output_omits_the_password() {
        let debug = format!("{:?}", registration("budi", "budi@example.com"));
        assert!(!debug.contains(PASSWORD), "{debug}");
        let (auth, _) = auth();
        assert!(!format!("{auth:?}").contains("argon2"));
    }

    #[tokio::test]
    async fn every_login_issues_a_new_active_session() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;
        let ip = "203.0.113.7".parse().unwrap();

        let first = auth
            .login(
                "budi",
                PASSWORD,
                SessionContext::web().ip(ip).user_agent("Mozilla/5.0"),
            )
            .await
            .unwrap();
        let second = auth
            .login("budi", PASSWORD, SessionContext::mobile())
            .await
            .unwrap();

        assert_eq!(first.user, budi);
        assert_eq!(first.session.user_id, budi.id);
        assert_eq!(first.session.state, SessionState::Active);
        assert_eq!(first.session.kind, SessionKind::Web);
        assert_eq!(first.session.ip, Some(ip));
        assert_eq!(first.session.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(first.session.created_at, clock.now());
        assert_eq!(second.session.kind, SessionKind::Mobile);

        // Two logins never share a session or a token.
        assert_ne!(first.session.id, second.session.id);
        assert_ne!(first.token.expose(), second.token.expose());
        assert!(first.token.expose().starts_with("rusted_s_"));

        // Both tokens work, each for its own session; the first login is not replaced.
        let sessions = auth.sessions();
        let validated = sessions.validate(first.token.expose()).await.unwrap();
        assert_eq!(validated.session.id, first.session.id);
        assert_eq!(validated.user, budi);
        let validated = sessions.validate(second.token.expose()).await.unwrap();
        assert_eq!(validated.session.id, second.session.id);
        assert_eq!(sessions.list(budi.id).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn rejected_logins_create_no_session() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;

        assert!(login(&auth, "budi", "wrong password").await.is_err());
        assert!(login(&auth, "nobody", PASSWORD).await.is_err());
        auth.store()
            .update(budi.id, |r| r.user.disabled_at = Some(clock.now()));
        assert!(login(&auth, "budi", PASSWORD).await.is_err());

        assert!(auth.sessions().store().is_empty());
    }

    #[tokio::test]
    async fn session_ends_when_the_account_is_disabled() {
        let (auth, clock) = auth();
        let budi = register_budi(&auth).await;
        let login = auth
            .login("budi", PASSWORD, SessionContext::web())
            .await
            .unwrap();
        let sessions = auth.sessions();
        assert!(sessions.validate(login.token.expose()).await.is_ok());

        auth.store()
            .update(budi.id, |r| r.user.disabled_at = Some(clock.now()));
        sessions.forget_user(budi.id);
        let error = sessions.validate(login.token.expose()).await.unwrap_err();
        assert!(matches!(error, SessionError::UserDisabled));
    }

    /// Give budi a hash made with other parameters than `auth` uses.
    async fn store_outdated_hash(auth: &TestAuth, budi: &User) -> String {
        let older = PasswordHasher::insecure(2, HashLimits::default(), Events::default()).unwrap();
        let outdated = older.hash(PASSWORD).await.unwrap();
        assert!(auth.hasher().needs_rehash(&outdated));
        let stored = outdated.clone();
        auth.store()
            .update(budi.id, |r| r.password_hash = Some(stored));
        outdated
    }

    #[tokio::test]
    async fn outdated_hash_is_replaced_on_successful_login() {
        let (builder, _, recorder) = builder_with_events();
        let auth = builder.build().unwrap();
        let budi = register_budi(&auth).await;
        let outdated = store_outdated_hash(&auth, &budi).await;

        // A failed login leaves the hash alone.
        assert!(login(&auth, "budi", "wrong password").await.is_err());
        let stored = auth.store().get(budi.id).unwrap().password_hash.unwrap();
        assert_eq!(stored, outdated);

        recorder.take();
        login(&auth, "budi", PASSWORD).await.unwrap();
        let upgraded = auth.store().get(budi.id).unwrap().password_hash.unwrap();
        assert_ne!(upgraded, outdated);
        assert!(!auth.hasher().needs_rehash(&upgraded));
        assert!(auth.hasher().verify(PASSWORD, &upgraded).await.unwrap());
        assert_eq!(
            recorder.take_names(),
            ["password_rehashed", "session_created", "login_succeeded"]
        );

        // The password still works and the current hash is not replaced again.
        login(&auth, "budi", PASSWORD).await.unwrap();
        let unchanged = auth.store().get(budi.id).unwrap().password_hash.unwrap();
        assert_eq!(unchanged, upgraded);
        assert_eq!(
            recorder.take_names(),
            ["session_created", "login_succeeded"]
        );
    }

    /// A user store that changes the account right after the first lookup, as a
    /// concurrent request would while this one waits for the hasher.
    #[derive(Clone)]
    struct ChangesAfterFirstRead {
        users: MemoryUserStore,
        reads: Arc<std::sync::atomic::AtomicUsize>,
        change: Arc<dyn Fn(&mut UserRecord) + Send + Sync>,
    }

    impl ChangesAfterFirstRead {
        fn after_first_read(&self, found: &Option<UserRecord>) {
            use std::sync::atomic::Ordering;
            if self.reads.fetch_add(1, Ordering::SeqCst) == 0
                && let Some(record) = found
            {
                let change = Arc::clone(&self.change);
                self.users.update(record.user.id, move |r| change(r));
            }
        }
    }

    impl UserStore for ChangesAfterFirstRead {
        async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, StoreError> {
            let found = self.users.find_by_username(username).await?;
            self.after_first_read(&found);
            Ok(found)
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, StoreError> {
            let found = self.users.find_by_email(email).await?;
            self.after_first_read(&found);
            Ok(found)
        }

        async fn insert(&self, user: NewUser) -> Result<User, StoreError> {
            self.users.insert(user).await
        }

        async fn record_failed_login(&self, id: Uuid) -> Result<u32, StoreError> {
            self.users.record_failed_login(id).await
        }

        async fn set_locked_until(
            &self,
            id: Uuid,
            until: Option<SystemTime>,
        ) -> Result<(), StoreError> {
            self.users.set_locked_until(id, until).await
        }

        async fn record_successful_login(&self, id: Uuid) -> Result<(), StoreError> {
            self.users.record_successful_login(id).await
        }

        async fn mark_email_verified(&self, id: Uuid, at: SystemTime) -> Result<bool, StoreError> {
            self.users.mark_email_verified(id, at).await
        }

        async fn reset_password(&self, id: Uuid, hash: String) -> Result<(), StoreError> {
            self.users.reset_password(id, hash).await
        }

        async fn replace_password_hash(
            &self,
            id: Uuid,
            current: &str,
            new: String,
        ) -> Result<bool, StoreError> {
            self.users.replace_password_hash(id, current, new).await
        }
    }

    /// Log in once against an account that `change` alters while the password is
    /// being checked.
    async fn login_while_account_changes(
        change: impl Fn(&mut UserRecord) + Send + Sync + 'static,
    ) -> (Result<Login, LocalError>, UserRecord) {
        let users = MemoryUserStore::new();
        let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
        let registered = LocalAuth::builder(users.clone(), sessions.clone())
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .require_verified_email(false)
            .build()
            .unwrap()
            .register(registration("budi", "budi@example.com"))
            .await
            .unwrap();
        let id = registered.created().unwrap().id;
        let store = ChangesAfterFirstRead {
            users: users.clone(),
            reads: Arc::default(),
            change: Arc::new(change),
        };
        let auth = LocalAuth::builder(store, sessions)
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .require_verified_email(false)
            .build()
            .unwrap();
        let result = auth.login("budi", PASSWORD, SessionContext::web()).await;
        (result, users.get(id).unwrap())
    }

    #[tokio::test]
    async fn lock_set_while_the_password_is_checked_is_respected() {
        // Concurrent wrong guesses locked the account after this login read it.
        let until = SystemTime::now() + Duration::from_secs(3600);
        let (result, record) = login_while_account_changes(move |r| {
            r.failed_login_count = 5;
            r.locked_until = Some(until);
        })
        .await;
        assert!(matches!(result, Err(LocalError::AccountLocked { .. })));
        assert_eq!(record.failed_login_count, 5, "not counted while locked");
        assert_eq!(record.locked_until, Some(until), "lock not extended");
    }

    #[tokio::test]
    async fn wrong_password_during_a_lock_does_not_extend_it() {
        let users = MemoryUserStore::new();
        let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
        let until = SystemTime::now() + Duration::from_secs(60);
        let store = ChangesAfterFirstRead {
            users: users.clone(),
            reads: Arc::default(),
            change: Arc::new(move |r: &mut UserRecord| {
                r.failed_login_count = 5;
                r.locked_until = Some(until);
            }),
        };
        let auth = LocalAuth::builder(store, sessions)
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .require_verified_email(false)
            .build()
            .unwrap();
        let id = users
            .insert(NewUser {
                username: "budi".into(),
                email: "budi@example.com".into(),
                name: "Budi".into(),
                password_hash: Some(auth.hasher().hash(PASSWORD).await.unwrap()),
            })
            .await
            .unwrap()
            .id;
        let result = auth
            .login("budi", "wrong password", SessionContext::web())
            .await;
        assert!(matches!(result, Err(LocalError::AccountLocked { .. })));
        let record = users.get(id).unwrap();
        assert_eq!(record.failed_login_count, 5);
        assert_eq!(record.locked_until, Some(until));
    }

    #[tokio::test]
    async fn password_replaced_while_it_is_checked_does_not_log_in() {
        // A reset stored a new hash after this login read the old one.
        let (result, _) = login_while_account_changes(|r| {
            r.password_hash = Some("$argon2id$v=19$m=8,t=1,p=1$c29tZXNhbHQ$aGFzaA".into());
        })
        .await;
        assert!(matches!(result, Err(LocalError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn disabled_while_the_password_is_checked_does_not_log_in() {
        let (result, _) =
            login_while_account_changes(|r| r.user.disabled_at = Some(SystemTime::now())).await;
        assert!(matches!(result, Err(LocalError::AccountDisabled)));
    }

    /// A user store whose hash replacement fails or reports a concurrent change.
    #[derive(Clone)]
    struct NoRehash {
        users: MemoryUserStore,
        fail: bool,
    }

    impl UserStore for NoRehash {
        async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, StoreError> {
            self.users.find_by_username(username).await
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, StoreError> {
            self.users.find_by_email(email).await
        }

        async fn insert(&self, user: NewUser) -> Result<User, StoreError> {
            self.users.insert(user).await
        }

        async fn record_failed_login(&self, id: Uuid) -> Result<u32, StoreError> {
            self.users.record_failed_login(id).await
        }

        async fn set_locked_until(
            &self,
            id: Uuid,
            until: Option<SystemTime>,
        ) -> Result<(), StoreError> {
            self.users.set_locked_until(id, until).await
        }

        async fn record_successful_login(&self, id: Uuid) -> Result<(), StoreError> {
            self.users.record_successful_login(id).await
        }

        async fn mark_email_verified(&self, id: Uuid, at: SystemTime) -> Result<bool, StoreError> {
            self.users.mark_email_verified(id, at).await
        }

        async fn reset_password(&self, id: Uuid, hash: String) -> Result<(), StoreError> {
            self.users.reset_password(id, hash).await
        }

        async fn replace_password_hash(
            &self,
            _: Uuid,
            _: &str,
            _: String,
        ) -> Result<bool, StoreError> {
            if self.fail {
                Err(StoreError::backend("database is read-only"))
            } else {
                Ok(false)
            }
        }
    }

    #[tokio::test]
    async fn failed_rehash_does_not_fail_the_login() {
        for fail in [true, false] {
            let users = MemoryUserStore::new();
            let recorder = Recorder::default();
            let sessions = SessionManager::builder(MemorySessionStore::new(users.clone()))
                .events(recorder.clone())
                .build();
            let store = NoRehash {
                users: users.clone(),
                fail,
            };
            let auth = LocalAuth::builder(store, sessions)
                .mailer(crate::local::NoMailer)
                .tokens(crate::session::MemoryOneTimeTokenStore::new())
                .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
                .require_verified_email(false)
                .build()
                .unwrap();
            let budi = auth
                .register(registration("budi", "budi@example.com"))
                .await
                .unwrap()
                .created()
                .unwrap()
                .clone();
            let older =
                PasswordHasher::insecure(2, HashLimits::default(), Events::default()).unwrap();
            let outdated = older.hash(PASSWORD).await.unwrap();
            let stored = outdated.clone();
            users.update(budi.id, |r| r.password_hash = Some(stored));
            recorder.take();

            let login = auth
                .login("budi", PASSWORD, SessionContext::web())
                .await
                .unwrap();
            assert_eq!(login.user.id, budi.id);
            assert!(auth.sessions().validate(login.token.expose()).await.is_ok());
            let unchanged = users.get(budi.id).unwrap().password_hash.unwrap();
            assert_eq!(unchanged, outdated);
            assert_eq!(
                recorder.take_names(),
                ["session_created", "login_succeeded"]
            );
        }
    }

    #[tokio::test]
    async fn busy_hasher_during_rehash_does_not_fail_the_login() {
        // One worker and no queue: the rehash is refused when it is submitted while the
        // only worker is held, which the test arranges through the store.
        #[derive(Clone)]
        struct HoldWorker {
            users: MemoryUserStore,
            hasher: PasswordHasher,
            held: Arc<Mutex<Vec<std::sync::mpsc::Sender<()>>>>,
        }

        impl UserStore for HoldWorker {
            async fn find_by_username(
                &self,
                username: &str,
            ) -> Result<Option<UserRecord>, StoreError> {
                self.users.find_by_username(username).await
            }

            async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, StoreError> {
                self.users.find_by_email(email).await
            }

            async fn insert(&self, user: NewUser) -> Result<User, StoreError> {
                self.users.insert(user).await
            }

            async fn record_failed_login(&self, id: Uuid) -> Result<u32, StoreError> {
                self.users.record_failed_login(id).await
            }

            async fn set_locked_until(
                &self,
                id: Uuid,
                until: Option<SystemTime>,
            ) -> Result<(), StoreError> {
                self.users.set_locked_until(id, until).await
            }

            /// Runs after the password was verified and before the rehash.
            async fn record_successful_login(&self, id: Uuid) -> Result<(), StoreError> {
                let (release, _blocked) = self.hasher.occupy_worker();
                self.held.lock().unwrap().push(release);
                self.users.record_successful_login(id).await
            }

            async fn mark_email_verified(
                &self,
                id: Uuid,
                at: SystemTime,
            ) -> Result<bool, StoreError> {
                self.users.mark_email_verified(id, at).await
            }

            async fn reset_password(&self, id: Uuid, hash: String) -> Result<(), StoreError> {
                self.users.reset_password(id, hash).await
            }

            async fn replace_password_hash(
                &self,
                id: Uuid,
                current: &str,
                new: String,
            ) -> Result<bool, StoreError> {
                self.users.replace_password_hash(id, current, new).await
            }
        }

        let limits = HashLimits::default().max_concurrent(1).max_queued(0);
        let hasher = PasswordHasher::insecure_for_tests(limits).unwrap();
        let users = MemoryUserStore::new();
        let held = Arc::new(Mutex::new(Vec::new()));
        let store = HoldWorker {
            users: users.clone(),
            hasher: hasher.clone(),
            held: Arc::clone(&held),
        };
        let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
        let auth = LocalAuth::builder(store, sessions)
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .hasher(hasher)
            .require_verified_email(false)
            .build()
            .unwrap();
        let budi = auth
            .register(registration("budi", "budi@example.com"))
            .await
            .unwrap()
            .created()
            .unwrap()
            .clone();
        let older = PasswordHasher::insecure(2, HashLimits::default(), Events::default()).unwrap();
        let outdated = older.hash(PASSWORD).await.unwrap();
        let stored = outdated.clone();
        users.update(budi.id, |r| r.password_hash = Some(stored));

        let login = auth
            .login("budi", PASSWORD, SessionContext::web())
            .await
            .unwrap();
        assert_eq!(login.user.id, budi.id);
        assert_eq!(held.lock().unwrap().len(), 1, "the worker was held");
        let unchanged = users.get(budi.id).unwrap().password_hash.unwrap();
        assert_eq!(unchanged, outdated);
    }

    #[tokio::test]
    async fn logins_and_lockouts_are_reported_without_secrets() {
        let (builder, clock, recorder) = builder_with_events();
        let auth = builder.build().unwrap();
        let budi = register_budi(&auth).await;
        let ip = "203.0.113.7".parse().unwrap();
        let context = || SessionContext::web().ip(ip).user_agent("Mozilla/5.0");

        let unknown = "typed-my-password-here";
        assert!(auth.login(unknown, PASSWORD, context()).await.is_err());
        let events = recorder.take();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].user_id, None);
        assert_eq!(events[0].ip, Some(ip));
        assert_eq!(events[0].user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(events[0].at, clock.now());
        assert_eq!(
            events[0].kind,
            AuthEventKind::LoginFailed {
                reason: LoginFailure::UnknownAccount
            }
        );

        for _ in 0..4 {
            assert!(
                auth.login("budi", "wrong password", context())
                    .await
                    .is_err()
            );
        }
        assert_eq!(recorder.take_names(), ["login_failed"; 4]);

        // The fifth failure locks the account.
        assert!(
            auth.login("budi", "wrong password", context())
                .await
                .is_err()
        );
        let events = recorder.take();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].user_id, Some(budi.id));
        assert_eq!(
            events[0].kind,
            AuthEventKind::LoginFailed {
                reason: LoginFailure::WrongPassword
            }
        );
        assert_eq!(
            events[1].kind,
            AuthEventKind::AccountLocked {
                until: clock.now() + Duration::from_secs(60),
                failed_logins: 5
            }
        );

        assert!(auth.login("budi", PASSWORD, context()).await.is_err());
        let events = recorder.take();
        assert_eq!(
            events[0].kind,
            AuthEventKind::LoginFailed {
                reason: LoginFailure::AccountLocked
            }
        );

        clock.advance(Duration::from_secs(60));
        let login = auth.login("budi", PASSWORD, context()).await.unwrap();
        let events = recorder.take();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].kind,
            AuthEventKind::SessionCreated {
                session_id: login.session.id,
                kind: SessionKind::Web,
                state: SessionState::Active
            }
        );
        assert_eq!(
            events[1].kind,
            AuthEventKind::LoginSucceeded {
                session_id: login.session.id,
                mfa_required: false,
            }
        );
        assert_eq!(events[1].user_id, Some(budi.id));

        auth.store()
            .update(budi.id, |r| r.user.disabled_at = Some(clock.now()));
        assert!(auth.login("budi", PASSWORD, context()).await.is_err());
        auth.store().update(budi.id, |r| {
            r.user.disabled_at = None;
            r.user.email_verified_at = None;
        });
        assert!(auth.login("budi", PASSWORD, context()).await.is_err());
        let reasons: Vec<_> = recorder.take().into_iter().map(|e| e.kind).collect();
        assert_eq!(
            reasons,
            [
                AuthEventKind::LoginFailed {
                    reason: LoginFailure::AccountDisabled
                },
                AuthEventKind::LoginFailed {
                    reason: LoginFailure::EmailNotVerified
                },
            ]
        );

        // Nothing that was reported or returned gives away a secret.
        let hash = auth.store().get(budi.id).unwrap().password_hash.unwrap();
        let everything = format!("{:?} {login:?}", recorder.events());
        for secret in [PASSWORD, unknown, hash.as_str(), login.token.expose()] {
            assert!(!everything.contains(secret), "{everything}");
        }
        assert!(!everything.contains("rusted_s_"), "{everything}");
    }

    #[tokio::test]
    async fn hasher_built_by_local_auth_reports_queue_waits() {
        let recorder = Recorder::default();
        let users = MemoryUserStore::new();
        let sessions = SessionManager::builder(MemorySessionStore::new(users.clone()))
            .events(recorder.clone())
            .build();
        let auth = LocalAuth::builder(users, sessions)
            .mailer(crate::local::NoMailer)
            .tokens(crate::session::MemoryOneTimeTokenStore::new())
            .build()
            .unwrap();

        assert!(login(&auth, "nobody", PASSWORD).await.is_err());
        assert_eq!(recorder.waits().len(), 1);
    }
}
