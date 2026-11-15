//! Creating, validating and revoking sessions.

use super::error::SessionError;
use super::event::{AuthEvent, AuthEventKind, EventSink, Events};
use super::model::{
    LAST_SEEN_WRITE_INTERVAL, MAX_SESSION_CACHE_TTL, NewSession, Session, SessionConfig,
    SessionContext, SessionKind, SessionState, SessionStore, after,
};
use super::token::{SessionToken, SessionTokenHash};
use super::user::{StoreError, User};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

pub(crate) type Clock = Box<dyn Fn() -> SystemTime + Send + Sync>;

impl From<StoreError> for SessionError {
    fn from(error: StoreError) -> Self {
        Self::Store(Box::new(error))
    }
}

/// A new session together with its token.
///
/// This is the only time the token is available. The `Debug` output does not contain it.
#[derive(Debug)]
#[non_exhaustive]
pub struct IssuedSession {
    /// The token to hand to the client.
    pub token: SessionToken,
    /// The session that was created.
    pub session: Session,
}

/// A session that passed validation, with the account it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthenticatedSession {
    /// The session.
    pub session: Session,
    /// The account. Like the session, it can be up to the cache lifetime old.
    pub user: User,
}

/// Creates, validates and revokes sessions.
///
/// A session is identified by an opaque token ([`SessionToken`]) of which only the
/// SHA-256 hash is stored. Cheap to clone; clones share the store and the cache.
///
/// # Validation and the cache
///
/// [`validate`](Self::validate) is meant to run on every authenticated request. A session
/// that passed is kept in memory for up to 30 seconds ([`SessionConfig::cache_ttl`]), so
/// most requests do not reach the store. The expiry times are still checked on every
/// call. The cache needs no background task and no particular async runtime.
///
/// The price is that **a change made elsewhere takes up to the cache lifetime to be
/// noticed**: a session revoked by another process, or an account disabled directly in
/// the database, keeps working here for at most 30 seconds. Revocations made through
/// this manager take effect in this process immediately, and
/// [`forget_user`](Self::forget_user) does the same after an account was disabled.
///
/// `last_seen_at` and the idle expiry are written at most once per minute per session
/// ([`LAST_SEEN_WRITE_INTERVAL`]).
///
/// ```rust
/// use rusted_auth::session::{
///     MemorySessionStore, MemoryUserStore, SessionContext, SessionManager, SessionState,
/// };
/// # use rusted_auth::session::Uuid;
///
/// # async fn run(user_id: Uuid) -> Result<(), rusted_auth::session::SessionError> {
/// let users = MemoryUserStore::new();
/// let sessions = SessionManager::new(MemorySessionStore::new(users));
///
/// let issued = sessions
///     .create(user_id, SessionState::Active, SessionContext::web())
///     .await?;
/// let cookie_value = issued.token.expose();
///
/// let authenticated = sessions.validate(cookie_value).await?;
/// assert_eq!(authenticated.user.id, user_id);
///
/// sessions.revoke(authenticated.session.id).await?;
/// assert!(sessions.validate(cookie_value).await.is_err());
/// # Ok(())
/// # }
/// ```
pub struct SessionManager<S> {
    inner: Arc<Inner<S>>,
}

struct Inner<S> {
    store: S,
    config: SessionConfig,
    cache: Mutex<Cache>,
    events: Events,
    clock: Clock,
}

#[derive(Default)]
struct Cache {
    /// Counts revocations, so a lookup that was in flight while one happened is not
    /// cached.
    epoch: u64,
    entries: HashMap<SessionTokenHash, CacheEntry>,
}

struct CacheEntry {
    session: Session,
    user: User,
    cached_at: SystemTime,
}

impl<S> Clone for SessionManager<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S> fmt::Debug for SessionManager<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManager")
            .field("config", &self.inner.config)
            .field("events", &self.inner.events)
            .finish_non_exhaustive()
    }
}

/// Configures a [`SessionManager`]. Created by [`SessionManager::builder`].
pub struct SessionManagerBuilder<S> {
    store: S,
    config: SessionConfig,
    events: Events,
    clock: Clock,
}

impl<S: SessionStore> SessionManagerBuilder<S> {
    /// Session lifetimes and cache settings.
    pub fn config(mut self, config: SessionConfig) -> Self {
        self.config = config;
        self
    }

    /// Where audit events and measurements are reported. Default: nowhere.
    ///
    /// To share one sink with other components, wrap it in an `Arc` and pass a clone.
    pub fn events(mut self, sink: impl EventSink) -> Self {
        self.events = Events::new(sink);
        self
    }

    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Build the manager.
    pub fn build(self) -> SessionManager<S> {
        let mut config = self.config;
        config.cache_ttl = config.cache_ttl.min(MAX_SESSION_CACHE_TTL);
        SessionManager {
            inner: Arc::new(Inner {
                store: self.store,
                config,
                cache: Mutex::new(Cache::default()),
                events: self.events,
                clock: self.clock,
            }),
        }
    }
}

impl<S: SessionStore> SessionManager<S> {
    /// A manager with the default [`SessionConfig`] and no event sink.
    pub fn new(store: S) -> Self {
        Self::builder(store).build()
    }

    /// Start configuring a manager backed by `store`.
    pub fn builder(store: S) -> SessionManagerBuilder<S> {
        SessionManagerBuilder {
            store,
            config: SessionConfig::default(),
            events: Events::default(),
            clock: Box::new(SystemTime::now),
        }
    }

    /// The session store.
    pub fn store(&self) -> &S {
        &self.inner.store
    }

    /// The configuration in effect.
    pub fn config(&self) -> SessionConfig {
        self.inner.config
    }

    #[cfg_attr(not(feature = "local"), allow(dead_code))]
    pub(crate) fn events(&self) -> &Events {
        &self.inner.events
    }

    /// Create a session for an account and return it with its token.
    ///
    /// Every call makes a new session with a new random token; an existing session is
    /// never reused or extended. This does not check that the account may sign in: that
    /// is the caller's job (`local::LocalAuth::login` does it).
    ///
    /// An [`Active`](SessionState::Active) session gets the lifetime of its kind. A
    /// [`PendingMfa`](SessionState::PendingMfa) session lasts
    /// [`SessionConfig::pending_mfa`] and is not extended by use.
    pub async fn create(
        &self,
        user_id: Uuid,
        state: SessionState,
        context: SessionContext,
    ) -> Result<IssuedSession, SessionError> {
        let inner = &self.inner;
        let context = context.normalized();
        let now = (inner.clock)();
        let (idle_expires_at, absolute_expires_at) = match state {
            SessionState::Active => inner.active_expiry(context.kind, now, now),
            SessionState::PendingMfa => {
                let expires = after(now, inner.config.pending_mfa);
                (expires, expires)
            }
        };

        let token = SessionToken::generate()?;
        let session = inner
            .store
            .insert(NewSession {
                token_hash: token.hash(),
                user_id,
                kind: context.kind,
                state,
                created_at: now,
                idle_expires_at,
                absolute_expires_at,
                ip: context.ip,
                user_agent: context.user_agent,
                idp_sid: None,
            })
            .await?;

        tracing::debug!(session_id = %session.id, user_id = %user_id, "session created");
        inner.events.emit(|| AuthEvent {
            at: now,
            user_id: Some(user_id),
            ip: session.ip,
            user_agent: session.user_agent.clone(),
            kind: AuthEventKind::SessionCreated {
                session_id: session.id,
                kind: session.kind,
                state: session.state,
            },
        });
        Ok(IssuedSession { token, session })
    }

    /// Check a token presented by a client and return its session and account.
    ///
    /// Only fully authenticated sessions pass. On success the session's `last_seen_at`
    /// and idle expiry are moved forward, at most once per minute.
    ///
    /// # Errors
    ///
    /// - [`SessionError::Invalid`]: the text is not a session token, or no session exists
    ///   for it. Malformed input is rejected without asking the store.
    /// - [`SessionError::Expired`]: idle for too long, or past its absolute lifetime.
    /// - [`SessionError::Revoked`].
    /// - [`SessionError::UserDisabled`]: the account has been disabled.
    /// - [`SessionError::MfaRequired`]: the second authentication step is still due.
    /// - [`SessionError::Store`]: the store failed.
    ///
    /// All but the last two share one [`public_message`](SessionError::public_message).
    pub async fn validate(&self, token: &str) -> Result<AuthenticatedSession, SessionError> {
        self.check(token, SessionState::Active).await
    }

    /// Like [`validate`](Self::validate), for the endpoint that takes the second
    /// authentication step: only a session in state
    /// [`PendingMfa`](SessionState::PendingMfa) passes, and an active one is refused with
    /// [`SessionError::Invalid`]. Does not extend the session.
    pub async fn validate_pending_mfa(
        &self,
        token: &str,
    ) -> Result<AuthenticatedSession, SessionError> {
        self.check(token, SessionState::PendingMfa).await
    }

    async fn check(
        &self,
        token: &str,
        wanted: SessionState,
    ) -> Result<AuthenticatedSession, SessionError> {
        let inner = &self.inner;
        let hash = SessionTokenHash::of_presented(token).ok_or(SessionError::Invalid)?;
        let now = (inner.clock)();

        // `fetched_at_epoch` is set when the session came from the store.
        let (mut session, user, fetched_at_epoch) = match inner.cached(&hash, now) {
            Some((session, user)) => (session, user, None),
            None => {
                let epoch = inner.cache().epoch;
                let record = inner
                    .store
                    .find_by_token_hash(&hash)
                    .await?
                    .ok_or(SessionError::Invalid)?;
                if record.token_hash != hash {
                    tracing::error!("session store returned a session for a different token hash");
                    return Err(SessionError::Invalid);
                }
                (record.session, record.user, Some(epoch))
            }
        };

        if let Err(error) = judge(&session, &user, now, wanted) {
            if fetched_at_epoch.is_none() {
                inner.cache().entries.remove(&hash);
            }
            tracing::debug!(session_id = %session.id, reason = %error, "session rejected");
            return Err(error);
        }

        let seen_long_ago = |session: &Session| {
            session.state == SessionState::Active
                && now
                    .duration_since(session.last_seen_at)
                    .is_ok_and(|since| since >= LAST_SEEN_WRITE_INTERVAL)
        };
        let mut touch = seen_long_ago(&session);
        let touched = |session: &mut Session| {
            session.last_seen_at = now;
            session.idle_expires_at =
                inner.idle_expiry(session.kind, now, session.absolute_expires_at);
        };

        match fetched_at_epoch {
            Some(epoch) => {
                if touch {
                    touched(&mut session);
                }
                inner.remember(hash, &session, &user, now, epoch);
            }
            None => {
                // Decided again under the lock, so concurrent requests write once.
                let mut cache = inner.cache();
                match cache.entries.get_mut(&hash) {
                    Some(entry) if seen_long_ago(&entry.session) => {
                        touched(&mut entry.session);
                        session = entry.session.clone();
                    }
                    Some(entry) => {
                        session = entry.session.clone();
                        touch = false;
                    }
                    // Evicted meanwhile, most likely revoked: leave the store alone.
                    None => touch = false,
                }
            }
        }

        if touch
            && let Err(error) = inner
                .store
                .touch(session.id, session.last_seen_at, session.idle_expires_at)
                .await
        {
            // The session itself is valid; failing the request would gain nothing.
            tracing::warn!(session_id = %session.id, %error, "could not record session use");
        }

        Ok(AuthenticatedSession { session, user })
    }

    /// Make a session that passed its second authentication step fully authenticated.
    ///
    /// `session` is the one returned by
    /// [`validate_pending_mfa`](Self::validate_pending_mfa). It keeps its token and gets
    /// the lifetime of its kind, with the absolute limit counted from when it was
    /// created. Fails with [`SessionError::Invalid`] when the session is not waiting for
    /// that step any more: already active, revoked or expired.
    pub async fn activate(&self, session: &Session) -> Result<Session, SessionError> {
        let inner = &self.inner;
        let now = (inner.clock)();
        let (idle_expires_at, absolute_expires_at) =
            inner.active_expiry(session.kind, now, session.created_at);
        let activated = inner
            .store
            .activate(session.id, now, idle_expires_at, absolute_expires_at)
            .await?;
        inner.evict(|cached| cached.id == session.id);
        let activated = activated.ok_or(SessionError::Invalid)?;

        tracing::debug!(session_id = %activated.id, "session activated");
        inner.events.emit(|| AuthEvent {
            at: now,
            user_id: Some(activated.user_id),
            ip: None,
            user_agent: None,
            kind: AuthEventKind::SessionActivated {
                session_id: activated.id,
            },
        });
        Ok(activated)
    }

    /// Revoke one session, for example on logout. Returns `false` when there is no such
    /// session or it was already revoked.
    ///
    /// The session stops working in this process immediately, and in other processes
    /// sharing the store within their cache lifetime (30 seconds by default).
    pub async fn revoke(&self, session_id: Uuid) -> Result<bool, SessionError> {
        self.revoke_one(session_id, None).await
    }

    /// Revoke one session only if it belongs to `user_id`. Use this when the identifier
    /// comes from the client, as on a "sessions and devices" page, so that one account
    /// cannot end another's sessions. Otherwise like [`revoke`](Self::revoke).
    pub async fn revoke_for_user(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<bool, SessionError> {
        self.revoke_one(session_id, Some(user_id)).await
    }

    async fn revoke_one(
        &self,
        session_id: Uuid,
        owner: Option<Uuid>,
    ) -> Result<bool, SessionError> {
        let inner = &self.inner;
        let now = (inner.clock)();
        let result = inner.store.revoke(session_id, owner, now).await;
        // Evicted even when the store failed: asking again is the safe direction.
        inner.evict(|cached| cached.id == session_id && owner.is_none_or(|o| o == cached.user_id));
        let Some(session) = result? else {
            return Ok(false);
        };
        inner.revoked(session.user_id, &[session.id], now);
        Ok(true)
    }

    /// Revoke every session of an account. Returns how many were revoked.
    ///
    /// Takes effect like [`revoke`](Self::revoke): immediately here, within the cache
    /// lifetime in other processes.
    pub async fn revoke_all(&self, user_id: Uuid) -> Result<usize, SessionError> {
        self.revoke_many(user_id, None).await
    }

    /// Revoke every session of an account except `current_session_id`: what a password
    /// change does, so the device that made the change stays signed in and every other
    /// one is signed out. Returns how many were revoked.
    pub async fn revoke_others(
        &self,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> Result<usize, SessionError> {
        self.revoke_many(user_id, Some(current_session_id)).await
    }

    async fn revoke_many(
        &self,
        user_id: Uuid,
        except: Option<Uuid>,
    ) -> Result<usize, SessionError> {
        let inner = &self.inner;
        let now = (inner.clock)();
        let result = inner.store.revoke_all_for_user(user_id, except, now).await;
        inner.evict(|cached| cached.user_id == user_id && Some(cached.id) != except);
        let revoked = result?;
        inner.revoked(user_id, &revoked, now);
        Ok(revoked.len())
    }

    /// The account's usable sessions, most recently created first: fully authenticated,
    /// not revoked and not expired. Neither tokens nor their hashes are part of the
    /// result. `last_seen_at` can be up to a minute behind.
    pub async fn list(&self, user_id: Uuid) -> Result<Vec<Session>, SessionError> {
        let now = (self.inner.clock)();
        Ok(self.inner.store.list_active_for_user(user_id, now).await?)
    }

    /// Drop an account's sessions from this process's cache, so their next validation
    /// reads the store. Call it after disabling an account, which otherwise takes up to
    /// the cache lifetime to be noticed. Other processes still need that long.
    pub fn forget_user(&self, user_id: Uuid) {
        self.inner.evict(|cached| cached.user_id == user_id);
    }
}

impl<S> Inner<S> {
    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Idle and absolute expiry of an active session used at `now` that was created at
    /// `created_at`.
    fn active_expiry(
        &self,
        kind: SessionKind,
        now: SystemTime,
        created_at: SystemTime,
    ) -> (SystemTime, SystemTime) {
        let absolute = after(created_at, self.config.lifetime(kind).absolute);
        (self.idle_expiry(kind, now, absolute), absolute)
    }

    /// Idle expiry of an active session used at `now`, never past its absolute expiry.
    fn idle_expiry(&self, kind: SessionKind, now: SystemTime, absolute: SystemTime) -> SystemTime {
        after(now, self.config.lifetime(kind).idle).min(absolute)
    }

    fn cached(&self, hash: &SessionTokenHash, now: SystemTime) -> Option<(Session, User)> {
        let ttl = self.config.cache_ttl;
        let mut cache = self.cache();
        let entry = cache.entries.get(hash)?;
        if is_fresh(entry.cached_at, now, ttl) {
            return Some((entry.session.clone(), entry.user.clone()));
        }
        cache.entries.remove(hash);
        None
    }

    /// Cache a session that was just read from the store, unless something was revoked
    /// since the read began.
    fn remember(
        &self,
        hash: SessionTokenHash,
        session: &Session,
        user: &User,
        now: SystemTime,
        fetched_at_epoch: u64,
    ) {
        let ttl = self.config.cache_ttl;
        if ttl.is_zero() {
            return;
        }
        let mut cache = self.cache();
        if cache.epoch != fetched_at_epoch {
            return;
        }
        if cache.entries.len() >= self.config.cache_capacity {
            cache
                .entries
                .retain(|_, entry| is_fresh(entry.cached_at, now, ttl));
            if cache.entries.len() >= self.config.cache_capacity {
                return;
            }
        }
        cache.entries.insert(
            hash,
            CacheEntry {
                session: session.clone(),
                user: user.clone(),
                cached_at: now,
            },
        );
    }

    fn evict(&self, matches: impl Fn(&Session) -> bool) {
        let mut cache = self.cache();
        cache.epoch = cache.epoch.wrapping_add(1);
        cache.entries.retain(|_, entry| !matches(&entry.session));
    }

    fn revoked(&self, user_id: Uuid, session_ids: &[Uuid], now: SystemTime) {
        for &session_id in session_ids {
            tracing::debug!(%session_id, %user_id, "session revoked");
            self.events.emit(|| AuthEvent {
                at: now,
                user_id: Some(user_id),
                ip: None,
                user_agent: None,
                kind: AuthEventKind::SessionRevoked { session_id },
            });
        }
    }
}

fn is_fresh(cached_at: SystemTime, now: SystemTime, ttl: Duration) -> bool {
    // A clock that moved backwards makes the entry stale.
    now.duration_since(cached_at).is_ok_and(|age| age < ttl)
}

/// Decide whether a session may be used at `now`.
fn judge(
    session: &Session,
    user: &User,
    now: SystemTime,
    wanted: SessionState,
) -> Result<(), SessionError> {
    if session.revoked_at.is_some() {
        return Err(SessionError::Revoked);
    }
    if now >= session.absolute_expires_at || now >= session.idle_expires_at {
        return Err(SessionError::Expired);
    }
    if user.disabled_at.is_some() {
        return Err(SessionError::UserDisabled);
    }
    match (session.state, wanted) {
        (state, wanted) if state == wanted => Ok(()),
        (SessionState::PendingMfa, _) => Err(SessionError::MfaRequired),
        _ => Err(SessionError::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::testing::Recorder;
    use crate::session::model::{SessionLifetime, SessionRecord};
    use crate::session::{MemorySessionStore, MemoryUserStore, NewUser, UserStore};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const MINUTE: Duration = Duration::from_secs(60);
    const DAY: Duration = Duration::from_secs(86_400);

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

        fn rewind(&self, by: Duration) {
            *self.0.lock().unwrap() -= by;
        }
    }

    /// Counts how often the store is read and written, and can be made to fail.
    #[derive(Clone)]
    struct CountingStore {
        inner: MemorySessionStore,
        lookups: Arc<AtomicUsize>,
        touches: Arc<AtomicUsize>,
        fail_touch: Arc<AtomicBool>,
        fail_revoke: Arc<AtomicBool>,
    }

    impl CountingStore {
        fn lookups(&self) -> usize {
            self.lookups.load(Ordering::SeqCst)
        }

        fn touches(&self) -> usize {
            self.touches.load(Ordering::SeqCst)
        }
    }

    impl SessionStore for CountingStore {
        async fn insert(&self, session: NewSession) -> Result<Session, StoreError> {
            self.inner.insert(session).await
        }

        async fn find_by_token_hash(
            &self,
            token_hash: &SessionTokenHash,
        ) -> Result<Option<SessionRecord>, StoreError> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            self.inner.find_by_token_hash(token_hash).await
        }

        async fn touch(
            &self,
            id: Uuid,
            last_seen_at: SystemTime,
            idle_expires_at: SystemTime,
        ) -> Result<(), StoreError> {
            self.touches.fetch_add(1, Ordering::SeqCst);
            if self.fail_touch.load(Ordering::SeqCst) {
                return Err(StoreError::backend("connection reset"));
            }
            self.inner.touch(id, last_seen_at, idle_expires_at).await
        }

        async fn activate(
            &self,
            id: Uuid,
            now: SystemTime,
            idle_expires_at: SystemTime,
            absolute_expires_at: SystemTime,
        ) -> Result<Option<Session>, StoreError> {
            self.inner
                .activate(id, now, idle_expires_at, absolute_expires_at)
                .await
        }

        async fn revoke(
            &self,
            id: Uuid,
            owner: Option<Uuid>,
            at: SystemTime,
        ) -> Result<Option<Session>, StoreError> {
            if self.fail_revoke.load(Ordering::SeqCst) {
                return Err(StoreError::backend("connection reset"));
            }
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

    struct Fixture {
        sessions: SessionManager<CountingStore>,
        store: CountingStore,
        users: MemoryUserStore,
        clock: TestClock,
        recorder: Recorder,
        budi: Uuid,
        siti: Uuid,
    }

    impl Fixture {
        async fn new() -> Self {
            Self::with_config(SessionConfig::default()).await
        }

        async fn with_config(config: SessionConfig) -> Self {
            let users = MemoryUserStore::new();
            let budi = add_user(&users, "budi").await;
            let siti = add_user(&users, "siti").await;
            let store = CountingStore {
                inner: MemorySessionStore::new(users.clone()),
                lookups: Arc::default(),
                touches: Arc::default(),
                fail_touch: Arc::default(),
                fail_revoke: Arc::default(),
            };
            let clock = TestClock::new();
            let recorder = Recorder::default();
            let sessions = Self::manager(&store, &clock, &recorder, config);
            Self {
                sessions,
                store,
                users,
                clock,
                recorder,
                budi,
                siti,
            }
        }

        /// Another manager on the same store, as a second server process would be.
        fn other_process(&self) -> SessionManager<CountingStore> {
            Self::manager(
                &self.store,
                &self.clock,
                &Recorder::default(),
                self.sessions.config(),
            )
        }

        fn manager(
            store: &CountingStore,
            clock: &TestClock,
            recorder: &Recorder,
            config: SessionConfig,
        ) -> SessionManager<CountingStore> {
            let clock = clock.clone();
            SessionManager::builder(store.clone())
                .config(config)
                .events(recorder.clone())
                .clock(move || clock.now())
                .build()
        }

        async fn web(&self, user_id: Uuid) -> IssuedSession {
            self.sessions
                .create(user_id, SessionState::Active, SessionContext::web())
                .await
                .unwrap()
        }

        fn stored(&self, id: Uuid) -> Session {
            self.store.inner.get(id).unwrap()
        }
    }

    async fn add_user(users: &MemoryUserStore, name: &str) -> Uuid {
        let user = NewUser {
            username: name.into(),
            email: format!("{name}@example.com"),
            name: name.into(),
            password_hash: None,
        };
        users.insert(user).await.unwrap().id
    }

    #[tokio::test]
    async fn created_session_validates_and_stores_only_the_hash() {
        let f = Fixture::new().await;
        let ip = "2001:db8::7".parse().unwrap();
        let issued = f
            .sessions
            .create(
                f.budi,
                SessionState::Active,
                SessionContext::web().ip(ip).user_agent("Mozilla/5.0"),
            )
            .await
            .unwrap();

        let session = &issued.session;
        assert_eq!(session.user_id, f.budi);
        assert_eq!(session.kind, SessionKind::Web);
        assert_eq!(session.state, SessionState::Active);
        assert_eq!(session.created_at, f.clock.now());
        assert_eq!(session.last_seen_at, f.clock.now());
        assert_eq!(session.idle_expires_at, f.clock.now() + 7 * DAY);
        assert_eq!(session.absolute_expires_at, f.clock.now() + 30 * DAY);
        assert_eq!(session.ip, Some(ip));
        assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(session.revoked_at, None);
        assert_eq!(session.idp_sid, None);

        let authenticated = f.sessions.validate(issued.token.expose()).await.unwrap();
        assert_eq!(&authenticated.session, session);
        assert_eq!(authenticated.user.id, f.budi);
        assert_eq!(authenticated.user.username, "budi");

        // Neither the store nor any debug output holds the token.
        let token = issued.token.expose();
        let everything = format!(
            "{:?} {issued:?} {authenticated:?} {:?} {:?}",
            f.store.inner,
            f.sessions,
            f.recorder.events()
        );
        assert!(!everything.contains(token), "{everything}");
        assert!(!everything.contains(&token[9..]), "{everything}");
    }

    #[tokio::test]
    async fn mobile_and_pending_sessions_get_their_own_lifetimes() {
        let f = Fixture::new().await;
        let mobile = f
            .sessions
            .create(f.budi, SessionState::Active, SessionContext::mobile())
            .await
            .unwrap()
            .session;
        assert_eq!(mobile.kind, SessionKind::Mobile);
        assert_eq!(mobile.idle_expires_at, f.clock.now() + 30 * DAY);
        assert_eq!(mobile.absolute_expires_at, f.clock.now() + 90 * DAY);

        let pending = f
            .sessions
            .create(f.budi, SessionState::PendingMfa, SessionContext::mobile())
            .await
            .unwrap()
            .session;
        assert_eq!(pending.state, SessionState::PendingMfa);
        assert_eq!(pending.idle_expires_at, f.clock.now() + 5 * MINUTE);
        assert_eq!(pending.absolute_expires_at, f.clock.now() + 5 * MINUTE);
    }

    #[tokio::test]
    async fn lifetimes_are_configurable() {
        let config = SessionConfig::default()
            .web(SessionLifetime::new(10 * MINUTE, 60 * MINUTE))
            // An idle limit beyond the absolute one is capped by it.
            .mobile(SessionLifetime::new(DAY, 60 * MINUTE))
            .pending_mfa(MINUTE);
        let f = Fixture::with_config(config).await;

        let web = f.web(f.budi).await.session;
        assert_eq!(web.idle_expires_at, f.clock.now() + 10 * MINUTE);
        assert_eq!(web.absolute_expires_at, f.clock.now() + 60 * MINUTE);

        let mobile = f
            .sessions
            .create(f.budi, SessionState::Active, SessionContext::mobile())
            .await
            .unwrap()
            .session;
        assert_eq!(mobile.idle_expires_at, f.clock.now() + 60 * MINUTE);

        let pending = f
            .sessions
            .create(f.budi, SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        f.clock.advance(MINUTE);
        let error = f
            .sessions
            .validate_pending_mfa(pending.token.expose())
            .await
            .unwrap_err();
        assert!(matches!(error, SessionError::Expired));
    }

    #[tokio::test]
    async fn session_for_an_unknown_account_is_refused() {
        let f = Fixture::new().await;
        let result = f
            .sessions
            .create(Uuid::new_v4(), SessionState::Active, SessionContext::web())
            .await;
        assert!(matches!(result, Err(SessionError::Store(_))));
        assert!(f.store.inner.is_empty());
        assert!(f.recorder.events().is_empty());
    }

    #[tokio::test]
    async fn malformed_and_unknown_tokens_are_invalid() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();

        let malformed = [
            String::new(),
            "rusted_s_".to_owned(),
            token[9..].to_owned(),
            token[..token.len() - 1].to_owned(),
            format!("{token}A"),
            format!(" {token}"),
            format!("Bearer {token}"),
            token.to_uppercase(),
            "eyJhbGciOiJIUzI1NiJ9.e30.signature".to_owned(),
            "x".repeat(100_000),
        ];
        for presented in &malformed {
            let error = f.sessions.validate(presented).await.unwrap_err();
            assert!(matches!(error, SessionError::Invalid), "{presented:?}");
            assert_eq!(error.public_message(), "Not authenticated");
        }
        assert_eq!(
            f.store.lookups(),
            0,
            "malformed tokens never reach the store"
        );

        // Well formed, but not a token that was ever issued.
        let unknown = SessionToken::generate().unwrap();
        let error = f.sessions.validate(unknown.expose()).await.unwrap_err();
        assert!(matches!(error, SessionError::Invalid));
        assert_eq!(f.store.lookups(), 1);

        // Unknown tokens are not cached, so they cannot fill the cache.
        assert!(f.sessions.validate(unknown.expose()).await.is_err());
        assert_eq!(f.store.lookups(), 2);
        assert!(f.sessions.inner.cache().entries.is_empty());
    }

    #[tokio::test]
    async fn a_store_answering_with_another_sessions_hash_is_not_trusted() {
        /// Answers every lookup with the first session it stored.
        #[derive(Clone)]
        struct WrongHash(MemorySessionStore, Arc<Mutex<Option<SessionTokenHash>>>);

        impl SessionStore for WrongHash {
            async fn insert(&self, session: NewSession) -> Result<Session, StoreError> {
                self.1.lock().unwrap().get_or_insert(session.token_hash);
                self.0.insert(session).await
            }

            async fn find_by_token_hash(
                &self,
                _: &SessionTokenHash,
            ) -> Result<Option<SessionRecord>, StoreError> {
                let first = self.1.lock().unwrap().expect("a session was stored");
                self.0.find_by_token_hash(&first).await
            }

            async fn touch(
                &self,
                id: Uuid,
                a: SystemTime,
                b: SystemTime,
            ) -> Result<(), StoreError> {
                self.0.touch(id, a, b).await
            }

            async fn activate(
                &self,
                id: Uuid,
                now: SystemTime,
                a: SystemTime,
                b: SystemTime,
            ) -> Result<Option<Session>, StoreError> {
                self.0.activate(id, now, a, b).await
            }

            async fn revoke(
                &self,
                id: Uuid,
                owner: Option<Uuid>,
                at: SystemTime,
            ) -> Result<Option<Session>, StoreError> {
                self.0.revoke(id, owner, at).await
            }

            async fn revoke_all_for_user(
                &self,
                user_id: Uuid,
                except: Option<Uuid>,
                at: SystemTime,
            ) -> Result<Vec<Uuid>, StoreError> {
                self.0.revoke_all_for_user(user_id, except, at).await
            }

            async fn list_active_for_user(
                &self,
                user_id: Uuid,
                now: SystemTime,
            ) -> Result<Vec<Session>, StoreError> {
                self.0.list_active_for_user(user_id, now).await
            }
        }

        let users = MemoryUserStore::new();
        let budi = add_user(&users, "budi").await;
        let store = WrongHash(MemorySessionStore::new(users), Arc::default());
        let sessions = SessionManager::new(store);
        let issued = sessions
            .create(budi, SessionState::Active, SessionContext::web())
            .await
            .unwrap();
        assert!(sessions.validate(issued.token.expose()).await.is_ok());

        let other = SessionToken::generate().unwrap();
        let error = sessions.validate(other.expose()).await.unwrap_err();
        assert!(matches!(error, SessionError::Invalid));
    }

    #[tokio::test]
    async fn idle_session_expires() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();

        f.clock.advance(7 * DAY - Duration::from_secs(1));
        // Still inside the idle limit; using it moves the limit forward.
        let seen = f.sessions.validate(token).await.unwrap().session;
        assert_eq!(seen.idle_expires_at, f.clock.now() + 7 * DAY);

        f.clock.advance(7 * DAY);
        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Expired));
        assert_eq!(error.public_message(), "Not authenticated");
        // Expiry is not revocation: the stored row is left as it is.
        assert_eq!(f.stored(issued.session.id).revoked_at, None);
    }

    #[tokio::test]
    async fn session_expires_at_its_absolute_limit_however_much_it_is_used() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();
        let absolute = issued.session.absolute_expires_at;

        // Used every 6 days, so it is never idle for 7.
        for _ in 0..4 {
            f.clock.advance(6 * DAY);
            let seen = f.sessions.validate(token).await.unwrap().session;
            assert_eq!(seen.absolute_expires_at, absolute, "never extended");
            assert!(seen.idle_expires_at <= absolute);
        }
        // Day 24: the idle limit would be day 31 and is capped at day 30.
        assert_eq!(f.stored(issued.session.id).idle_expires_at, absolute);

        f.clock.advance(6 * DAY - Duration::from_secs(1));
        assert!(f.sessions.validate(token).await.is_ok());
        f.clock.advance(Duration::from_secs(1));
        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Expired));
    }

    #[tokio::test]
    async fn cached_session_still_expires_on_time() {
        let config = SessionConfig::default().web(SessionLifetime::new(
            Duration::from_secs(45),
            Duration::from_secs(50),
        ));
        let f = Fixture::with_config(config).await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();

        f.clock.advance(Duration::from_secs(20));
        assert!(f.sessions.validate(token).await.is_ok());
        // 25 seconds later the cache entry is still fresh, the session is not.
        f.clock.advance(Duration::from_secs(25));
        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Expired));
        assert_eq!(f.store.lookups(), 1, "decided from the cache");
    }

    #[tokio::test]
    async fn revoked_session_is_rejected() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();
        assert!(f.sessions.validate(token).await.is_ok());

        assert!(f.sessions.revoke(issued.session.id).await.unwrap());
        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Revoked));
        assert_eq!(error.public_message(), "Not authenticated");
        assert_eq!(f.stored(issued.session.id).revoked_at, Some(f.clock.now()));

        // Revoking again, or something that does not exist, reports `false`.
        assert!(!f.sessions.revoke(issued.session.id).await.unwrap());
        assert!(!f.sessions.revoke(Uuid::new_v4()).await.unwrap());
    }

    #[tokio::test]
    async fn session_of_a_disabled_account_is_rejected() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();

        f.users
            .update(f.budi, |r| r.user.disabled_at = Some(f.clock.now()));
        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::UserDisabled));
        assert_eq!(error.public_message(), "Not authenticated");

        // Enabled again: the session, which was never revoked, works again.
        f.users.update(f.budi, |r| r.user.disabled_at = None);
        assert!(f.sessions.validate(token).await.is_ok());
    }

    #[tokio::test]
    async fn disabling_an_account_is_noticed_within_the_cache_lifetime() {
        let f = Fixture::new().await;
        let first = f.web(f.budi).await;
        let second = f.web(f.budi).await;
        assert!(f.sessions.validate(first.token.expose()).await.is_ok());
        assert!(f.sessions.validate(second.token.expose()).await.is_ok());

        f.users
            .update(f.budi, |r| r.user.disabled_at = Some(f.clock.now()));
        // Still cached.
        f.clock.advance(Duration::from_secs(29));
        assert!(f.sessions.validate(first.token.expose()).await.is_ok());
        f.clock.advance(Duration::from_secs(1));
        let error = f.sessions.validate(first.token.expose()).await.unwrap_err();
        assert!(matches!(error, SessionError::UserDisabled));

        // `forget_user` makes it immediate for sessions that are still cached.
        f.users.update(f.budi, |r| r.user.disabled_at = None);
        assert!(f.sessions.validate(second.token.expose()).await.is_ok());
        f.users
            .update(f.budi, |r| r.user.disabled_at = Some(f.clock.now()));
        f.sessions.forget_user(f.budi);
        let error = f
            .sessions
            .validate(second.token.expose())
            .await
            .unwrap_err();
        assert!(matches!(error, SessionError::UserDisabled));
    }

    #[tokio::test]
    async fn validation_is_cached_for_thirty_seconds() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();

        for _ in 0..5 {
            assert!(f.sessions.validate(token).await.is_ok());
        }
        assert_eq!(f.store.lookups(), 1);

        f.clock.advance(Duration::from_secs(29));
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.lookups(), 1);

        // The lifetime counts from when the store was read, not from the last use.
        f.clock.advance(Duration::from_secs(1));
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.lookups(), 2);

        f.clock.advance(Duration::from_secs(29));
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.lookups(), 2);
    }

    #[tokio::test]
    async fn a_clock_that_moves_backwards_does_not_keep_entries_alive() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();
        f.clock.advance(MINUTE);
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.lookups(), 1);

        f.clock.rewind(Duration::from_secs(10));
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.lookups(), 2, "an entry from the future is not used");
    }

    #[tokio::test]
    async fn cache_can_be_switched_off() {
        let f = Fixture::with_config(SessionConfig::default().cache_ttl(Duration::ZERO)).await;
        let issued = f.web(f.budi).await;
        for _ in 0..3 {
            assert!(f.sessions.validate(issued.token.expose()).await.is_ok());
        }
        assert_eq!(f.store.lookups(), 3);
        assert!(f.sessions.inner.cache().entries.is_empty());
    }

    #[tokio::test]
    async fn cache_lifetime_cannot_exceed_thirty_seconds() {
        // Set through the public field, bypassing the setter.
        let config = SessionConfig {
            cache_ttl: Duration::from_secs(3600),
            ..SessionConfig::default()
        };
        let f = Fixture::with_config(config).await;
        assert_eq!(f.sessions.config().cache_ttl, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn cache_is_bounded() {
        let f = Fixture::with_config(SessionConfig::default().cache_capacity(2)).await;
        let a = f.web(f.budi).await;
        let b = f.web(f.budi).await;
        let c = f.web(f.budi).await;

        assert!(f.sessions.validate(a.token.expose()).await.is_ok());
        assert!(f.sessions.validate(b.token.expose()).await.is_ok());
        // Full: the third session is valid but read from the store every time.
        assert!(f.sessions.validate(c.token.expose()).await.is_ok());
        assert!(f.sessions.validate(c.token.expose()).await.is_ok());
        assert_eq!(f.store.lookups(), 4);
        assert_eq!(f.sessions.inner.cache().entries.len(), 2);

        // Entries past their lifetime make room.
        f.clock.advance(Duration::from_secs(30));
        assert!(f.sessions.validate(c.token.expose()).await.is_ok());
        assert!(f.sessions.validate(c.token.expose()).await.is_ok());
        assert_eq!(f.store.lookups(), 5);
        assert_eq!(f.sessions.inner.cache().entries.len(), 1);
    }

    #[tokio::test]
    async fn last_seen_is_written_at_most_once_per_minute() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();
        let id = issued.session.id;
        let created = f.clock.now();

        // Used every 10 seconds for just under a minute: nothing is written.
        for _ in 0..5 {
            f.clock.advance(Duration::from_secs(10));
            let seen = f.sessions.validate(token).await.unwrap().session;
            assert_eq!(seen.last_seen_at, created);
        }
        f.clock.advance(Duration::from_secs(9));
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.touches(), 0);
        assert_eq!(f.stored(id).last_seen_at, created);

        // One minute after creation: written once, with the idle limit moved.
        f.clock.advance(Duration::from_secs(1));
        let seen = f.sessions.validate(token).await.unwrap().session;
        assert_eq!(f.store.touches(), 1);
        assert_eq!(seen.last_seen_at, f.clock.now());
        assert_eq!(seen.idle_expires_at, f.clock.now() + 7 * DAY);
        assert_eq!(f.stored(id), seen);
        let first_write = f.clock.now();

        // Any number of uses within the next minute write nothing more, whether they
        // are answered from the cache or from the store.
        for _ in 0..59 {
            f.clock.advance(Duration::from_secs(1));
            let seen = f.sessions.validate(token).await.unwrap().session;
            assert_eq!(seen.last_seen_at, first_write);
        }
        assert_eq!(f.store.touches(), 1);
        assert!(f.store.lookups() >= 3, "the cache was refreshed meanwhile");

        f.clock.advance(Duration::from_secs(1));
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.touches(), 2);
        assert_eq!(f.stored(id).last_seen_at, f.clock.now());
    }

    #[tokio::test]
    async fn last_seen_limit_holds_without_the_cache() {
        let f = Fixture::with_config(SessionConfig::default().cache_ttl(Duration::ZERO)).await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();

        for _ in 0..59 {
            f.clock.advance(Duration::from_secs(1));
            assert!(f.sessions.validate(token).await.is_ok());
        }
        assert_eq!(f.store.touches(), 0);
        f.clock.advance(Duration::from_secs(1));
        assert!(f.sessions.validate(token).await.is_ok());
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.touches(), 1);
    }

    #[tokio::test]
    async fn concurrent_requests_write_last_seen_once() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();
        assert!(f.sessions.validate(token).await.is_ok());

        // Refresh the cache entry shortly before the minute is up, so that the session
        // is still cached when it is.
        f.clock.advance(Duration::from_secs(50));
        assert!(f.sessions.validate(token).await.is_ok());
        assert_eq!(f.store.touches(), 0);

        f.clock.advance(Duration::from_secs(15));
        let (a, b, c) = tokio::join!(
            f.sessions.validate(token),
            f.sessions.validate(token),
            f.sessions.validate(token)
        );
        assert!(a.is_ok() && b.is_ok() && c.is_ok());
        assert_eq!(f.store.touches(), 1);
    }

    #[tokio::test]
    async fn failing_to_record_use_does_not_fail_validation() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        f.store.fail_touch.store(true, Ordering::SeqCst);

        f.clock.advance(2 * MINUTE);
        let result = f.sessions.validate(issued.token.expose()).await;
        assert!(result.is_ok());
        assert_eq!(f.store.touches(), 1);
    }

    #[tokio::test]
    async fn revocation_is_immediate_here_and_bounded_by_the_cache_elsewhere() {
        let f = Fixture::new().await;
        let other = f.other_process();
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();

        // Both processes have the session cached.
        assert!(f.sessions.validate(token).await.is_ok());
        assert!(other.validate(token).await.is_ok());

        assert!(f.sessions.revoke(issued.session.id).await.unwrap());
        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Revoked));

        // The other process notices when its cache entry runs out, not later.
        f.clock.advance(Duration::from_secs(29));
        assert!(other.validate(token).await.is_ok());
        f.clock.advance(Duration::from_secs(1));
        let error = other.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Revoked));
    }

    #[tokio::test]
    async fn a_failed_revocation_still_drops_the_cached_session() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let token = issued.token.expose();
        assert!(f.sessions.validate(token).await.is_ok());

        f.store.fail_revoke.store(true, Ordering::SeqCst);
        let result = f.sessions.revoke(issued.session.id).await;
        assert!(matches!(result, Err(SessionError::Store(_))));
        assert!(f.sessions.inner.cache().entries.is_empty());
    }

    #[tokio::test]
    async fn a_lookup_in_flight_during_a_revocation_is_not_cached() {
        let f = Fixture::new().await;
        let issued = f.web(f.budi).await;
        let hash = issued.token.hash();
        let user = f.users.get(f.budi).unwrap().user;

        // A validation read the store, then the revocation happened, then it finishes.
        let epoch = f.sessions.inner.cache().epoch;
        assert!(f.sessions.revoke(issued.session.id).await.unwrap());
        f.sessions
            .inner
            .remember(hash, &issued.session, &user, f.clock.now(), epoch);
        assert!(f.sessions.inner.cache().entries.is_empty());

        let error = f
            .sessions
            .validate(issued.token.expose())
            .await
            .unwrap_err();
        assert!(matches!(error, SessionError::Revoked));
    }

    #[tokio::test]
    async fn revoke_for_user_checks_ownership() {
        let f = Fixture::new().await;
        let budis = f.web(f.budi).await;
        assert!(f.sessions.validate(budis.token.expose()).await.is_ok());

        // Siti cannot end Budi's session, and it stays cached.
        let revoked = f.sessions.revoke_for_user(f.siti, budis.session.id).await;
        assert!(!revoked.unwrap());
        assert!(f.sessions.validate(budis.token.expose()).await.is_ok());
        assert_eq!(f.sessions.inner.cache().entries.len(), 1);
        assert_eq!(f.stored(budis.session.id).revoked_at, None);

        let revoked = f.sessions.revoke_for_user(f.budi, budis.session.id).await;
        assert!(revoked.unwrap());
        let error = f.sessions.validate(budis.token.expose()).await.unwrap_err();
        assert!(matches!(error, SessionError::Revoked));
    }

    #[tokio::test]
    async fn revoke_all_ends_every_session_of_the_account_only() {
        let f = Fixture::new().await;
        let first = f.web(f.budi).await;
        let second = f.web(f.budi).await;
        let pending = f
            .sessions
            .create(f.budi, SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        let sitis = f.web(f.siti).await;
        for issued in [&first, &second, &sitis] {
            assert!(f.sessions.validate(issued.token.expose()).await.is_ok());
        }
        f.recorder.take();

        assert_eq!(f.sessions.revoke_all(f.budi).await.unwrap(), 3);
        for issued in [&first, &second] {
            let error = f
                .sessions
                .validate(issued.token.expose())
                .await
                .unwrap_err();
            assert!(matches!(error, SessionError::Revoked));
        }
        let error = f
            .sessions
            .validate_pending_mfa(pending.token.expose())
            .await
            .unwrap_err();
        assert!(matches!(error, SessionError::Revoked));
        assert!(f.sessions.validate(sitis.token.expose()).await.is_ok());

        let events = f.recorder.take();
        assert_eq!(events.len(), 3);
        for event in &events {
            assert_eq!(event.user_id, Some(f.budi));
            assert_eq!(event.kind.name(), "session_revoked");
        }

        // Nothing left to revoke.
        assert_eq!(f.sessions.revoke_all(f.budi).await.unwrap(), 0);
        assert!(f.sessions.list(f.budi).await.unwrap().is_empty());
        assert_eq!(f.sessions.list(f.siti).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn revoke_others_keeps_the_current_session() {
        let f = Fixture::new().await;
        let current = f.web(f.budi).await;
        let phone = f
            .sessions
            .create(f.budi, SessionState::Active, SessionContext::mobile())
            .await
            .unwrap();
        let laptop = f.web(f.budi).await;
        let sitis = f.web(f.siti).await;
        for issued in [&current, &phone, &laptop, &sitis] {
            assert!(f.sessions.validate(issued.token.expose()).await.is_ok());
        }

        let revoked = f.sessions.revoke_others(f.budi, current.session.id).await;
        assert_eq!(revoked.unwrap(), 2);

        assert!(f.sessions.validate(current.token.expose()).await.is_ok());
        assert!(f.sessions.validate(sitis.token.expose()).await.is_ok());
        for issued in [&phone, &laptop] {
            let error = f
                .sessions
                .validate(issued.token.expose())
                .await
                .unwrap_err();
            assert!(matches!(error, SessionError::Revoked));
        }
        // The current session was not even dropped from the cache.
        let lookups = f.store.lookups();
        assert!(f.sessions.validate(current.token.expose()).await.is_ok());
        assert_eq!(f.store.lookups(), lookups);

        let listed = f.sessions.list(f.budi).await.unwrap();
        assert_eq!(listed, vec![f.stored(current.session.id)]);
    }

    #[tokio::test]
    async fn list_shows_usable_sessions_newest_first_without_secrets() {
        let f = Fixture::new().await;
        let oldest = f.web(f.budi).await;
        f.clock.advance(DAY);
        let revoked = f.web(f.budi).await;
        let phone = f
            .sessions
            .create(
                f.budi,
                SessionState::Active,
                SessionContext::mobile().user_agent("App/1.0"),
            )
            .await
            .unwrap();
        let pending = f
            .sessions
            .create(f.budi, SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        f.web(f.siti).await;
        f.sessions.revoke(revoked.session.id).await.unwrap();

        let listed = f.sessions.list(f.budi).await.unwrap();
        let ids: Vec<Uuid> = listed.iter().map(|s| s.id).collect();
        assert_eq!(ids, [phone.session.id, oldest.session.id]);
        assert_eq!(listed[0].user_agent.as_deref(), Some("App/1.0"));
        assert!(listed.iter().all(|s| s.user_id == f.budi));
        assert!(!ids.contains(&pending.session.id));

        let debug = format!("{listed:?}");
        for issued in [&oldest, &phone] {
            assert!(!debug.contains(issued.token.expose()), "{debug}");
            assert!(!debug.contains("rusted_s_"), "{debug}");
        }

        // The web session runs out of idle time first; the mobile one stays.
        f.clock.advance(6 * DAY);
        let ids: Vec<Uuid> = f
            .sessions
            .list(f.budi)
            .await
            .unwrap()
            .iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(ids, [phone.session.id]);
    }

    #[tokio::test]
    async fn pending_session_is_refused_until_it_is_activated() {
        let f = Fixture::new().await;
        let issued = f
            .sessions
            .create(f.budi, SessionState::PendingMfa, SessionContext::mobile())
            .await
            .unwrap();
        let token = issued.token.expose();

        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::MfaRequired));
        assert_eq!(error.public_message(), "Additional verification required");

        f.clock.advance(MINUTE);
        let pending = f.sessions.validate_pending_mfa(token).await.unwrap();
        assert_eq!(pending.session.state, SessionState::PendingMfa);
        assert_eq!(pending.user.id, f.budi);
        // A pending session is not extended by use.
        f.clock.advance(MINUTE);
        assert!(f.sessions.validate_pending_mfa(token).await.is_ok());
        assert_eq!(f.store.touches(), 0);
        f.recorder.take();

        let activated = f.sessions.activate(&pending.session).await.unwrap();
        assert_eq!(activated.id, issued.session.id);
        assert_eq!(activated.state, SessionState::Active);
        assert_eq!(activated.last_seen_at, f.clock.now());
        assert_eq!(activated.idle_expires_at, f.clock.now() + 30 * DAY);
        assert_eq!(
            activated.absolute_expires_at,
            issued.session.created_at + 90 * DAY
        );
        assert_eq!(f.recorder.take_names(), ["session_activated"]);

        // The same token is now a full session, at once, and no longer a pending one.
        let authenticated = f.sessions.validate(token).await.unwrap();
        assert_eq!(authenticated.session, activated);
        let error = f.sessions.validate_pending_mfa(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Invalid));

        // Activating twice is refused.
        let error = f.sessions.activate(&pending.session).await.unwrap_err();
        assert!(matches!(error, SessionError::Invalid));
    }

    #[tokio::test]
    async fn pending_session_expires_after_five_minutes_and_cannot_be_activated() {
        let f = Fixture::new().await;
        let issued = f
            .sessions
            .create(f.budi, SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        let token = issued.token.expose();

        f.clock.advance(5 * MINUTE - Duration::from_secs(1));
        assert!(f.sessions.validate_pending_mfa(token).await.is_ok());
        f.clock.advance(Duration::from_secs(1));
        let error = f.sessions.validate_pending_mfa(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Expired));
        let error = f.sessions.validate(token).await.unwrap_err();
        assert!(matches!(error, SessionError::Expired));

        let error = f.sessions.activate(&issued.session).await.unwrap_err();
        assert!(matches!(error, SessionError::Invalid));

        // Nor can a revoked one.
        let other = f
            .sessions
            .create(f.budi, SessionState::PendingMfa, SessionContext::web())
            .await
            .unwrap();
        f.sessions.revoke(other.session.id).await.unwrap();
        let error = f.sessions.activate(&other.session).await.unwrap_err();
        assert!(matches!(error, SessionError::Invalid));
    }

    #[tokio::test]
    async fn session_events_carry_no_secrets() {
        let f = Fixture::new().await;
        let ip = "203.0.113.7".parse().unwrap();
        let issued = f
            .sessions
            .create(
                f.budi,
                SessionState::Active,
                SessionContext::web().ip(ip).user_agent("Mozilla/5.0"),
            )
            .await
            .unwrap();
        f.sessions.revoke(issued.session.id).await.unwrap();

        let events = f.recorder.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].user_id, Some(f.budi));
        assert_eq!(events[0].ip, Some(ip));
        assert_eq!(events[0].user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(events[0].at, f.clock.now());
        assert_eq!(
            events[0].kind,
            AuthEventKind::SessionCreated {
                session_id: issued.session.id,
                kind: SessionKind::Web,
                state: SessionState::Active
            }
        );
        assert_eq!(
            events[1].kind,
            AuthEventKind::SessionRevoked {
                session_id: issued.session.id
            }
        );

        let debug = format!("{events:?}");
        assert!(!debug.contains(&issued.token.expose()[9..]), "{debug}");
        assert!(!debug.contains("rusted_s_"), "{debug}");
    }

    #[tokio::test]
    async fn store_failures_are_server_errors() {
        let f = Fixture::new().await;
        f.store.fail_revoke.store(true, Ordering::SeqCst);
        let error = f.sessions.revoke(Uuid::new_v4()).await.unwrap_err();
        assert!(error.is_server_error());
        assert!(error.to_string().contains("connection reset"));
        assert!(!error.public_message().contains("connection"));
    }
}
