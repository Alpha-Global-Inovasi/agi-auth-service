//! Session data, lifetimes and the storage trait.

use super::token::SessionTokenHash;
use super::user::{StoreError, User};
use std::future::Future;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Longest `User-Agent` kept with a session or an event, in characters. Longer values
/// are cut.
pub const MAX_USER_AGENT_CHARS: usize = 512;

/// Longest time a validated session may be served from the in-process cache, and so the
/// longest a revocation made by another process can take to be noticed.
pub const MAX_SESSION_CACHE_TTL: Duration = Duration::from_secs(30);

/// Shortest time between two writes of a session's `last_seen_at`.
pub const LAST_SEEN_WRITE_INTERVAL: Duration = Duration::from_secs(60);

const DAY: u64 = 24 * 60 * 60;

/// The kind of client a session belongs to. It selects the session's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionKind {
    /// A browser, which holds the token in a cookie.
    Web,
    /// A mobile app, which sends the token in a header.
    Mobile,
}

impl SessionKind {
    /// The name to store: `"web"` or `"mobile"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Mobile => "mobile",
        }
    }

    /// The inverse of [`as_str`](Self::as_str).
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "web" => Some(Self::Web),
            "mobile" => Some(Self::Mobile),
            _ => None,
        }
    }
}

/// How far a session has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionState {
    /// The password was accepted but the second authentication step is still due. The
    /// session is short lived and is refused by
    /// [`SessionManager::validate`](super::SessionManager::validate).
    PendingMfa,
    /// Fully authenticated.
    Active,
}

impl SessionState {
    /// The name to store: `"pending_mfa"` or `"active"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingMfa => "pending_mfa",
            Self::Active => "active",
        }
    }

    /// The inverse of [`as_str`](Self::as_str).
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "pending_mfa" => Some(Self::PendingMfa),
            "active" => Some(Self::Active),
            _ => None,
        }
    }
}

/// A session, without its token.
///
/// Neither the token nor its hash is part of this type, so it is safe to show to the
/// account's owner, for example on a "sessions and devices" page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Stable identifier. Not a credential: knowing it does not grant access.
    pub id: Uuid,
    /// The account the session belongs to.
    pub user_id: Uuid,
    /// Web or mobile.
    pub kind: SessionKind,
    /// Whether the session is fully authenticated.
    pub state: SessionState,
    /// When the session was created.
    pub created_at: SystemTime,
    /// When the session was last used. Written at most once per
    /// [`LAST_SEEN_WRITE_INTERVAL`], so it can be up to a minute behind.
    pub last_seen_at: SystemTime,
    /// The session ends at this time unless it is used before; every recorded use moves
    /// it forward, never past [`absolute_expires_at`](Self::absolute_expires_at).
    pub idle_expires_at: SystemTime,
    /// The session ends at this time no matter how much it is used.
    pub absolute_expires_at: SystemTime,
    /// Client address when the session was created.
    pub ip: Option<IpAddr>,
    /// Client `User-Agent` when the session was created.
    pub user_agent: Option<String>,
    /// When the session was revoked, if it has been.
    pub revoked_at: Option<SystemTime>,
    /// Session identifier at an external identity provider. Reserved for sign-in through
    /// such a provider; sessions created by this module leave it `None`.
    pub idp_sid: Option<String>,
}

/// The session a [`SessionStore`] is asked to create.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NewSession {
    /// Hash of the session token. Unique across sessions.
    pub token_hash: SessionTokenHash,
    /// The account the session belongs to.
    pub user_id: Uuid,
    /// Web or mobile.
    pub kind: SessionKind,
    /// Initial state.
    pub state: SessionState,
    /// Creation time, also the initial `last_seen_at`.
    pub created_at: SystemTime,
    /// Initial idle expiry.
    pub idle_expires_at: SystemTime,
    /// Absolute expiry.
    pub absolute_expires_at: SystemTime,
    /// Client address.
    pub ip: Option<IpAddr>,
    /// Client `User-Agent`, at most [`MAX_USER_AGENT_CHARS`] characters.
    pub user_agent: Option<String>,
    /// Session identifier at an external identity provider; see [`Session::idp_sid`].
    pub idp_sid: Option<String>,
}

/// What [`SessionStore::find_by_token_hash`] returns: a session, the hash it is stored
/// under, and the account it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// The session.
    pub session: Session,
    /// The stored token hash, which is compared again with the presented one.
    pub token_hash: SessionTokenHash,
    /// The account the session belongs to, as it is now.
    pub user: User,
}

/// Where a login or a new session comes from: the kind of client and what is known about
/// it. The address and `User-Agent` are stored with the session and copied into audit
/// events.
///
/// ```rust
/// use rusted_auth::session::SessionContext;
///
/// let context = SessionContext::web()
///     .ip("203.0.113.7".parse().unwrap())
///     .user_agent("Mozilla/5.0");
/// # let _ = context;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionContext {
    /// Web or mobile.
    pub kind: SessionKind,
    /// Client address. Behind a reverse proxy, pass the address the proxy reports, not
    /// the proxy's own.
    pub ip: Option<IpAddr>,
    /// Client `User-Agent`. Cut to [`MAX_USER_AGENT_CHARS`] characters.
    pub user_agent: Option<String>,
}

impl SessionContext {
    /// A client of the given kind about which nothing else is known.
    pub fn new(kind: SessionKind) -> Self {
        Self {
            kind,
            ip: None,
            user_agent: None,
        }
    }

    /// A browser.
    pub fn web() -> Self {
        Self::new(SessionKind::Web)
    }

    /// A mobile app.
    pub fn mobile() -> Self {
        Self::new(SessionKind::Mobile)
    }

    /// Set the client address.
    pub fn ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Set the client `User-Agent`.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// The same context with the `User-Agent` cut to its maximum length.
    pub(crate) fn normalized(mut self) -> Self {
        if let Some(user_agent) = &mut self.user_agent
            && let Some((cut, _)) = user_agent.char_indices().nth(MAX_USER_AGENT_CHARS)
        {
            user_agent.truncate(cut);
        }
        self
    }
}

/// How long a session of one kind lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionLifetime {
    /// The session ends after this long without being used.
    pub idle: Duration,
    /// The session ends this long after it was created, however much it is used.
    pub absolute: Duration,
}

impl SessionLifetime {
    /// A lifetime with the given idle and absolute limits.
    pub fn new(idle: Duration, absolute: Duration) -> Self {
        Self { idle, absolute }
    }
}

/// Session lifetimes and cache settings.
///
/// | | Default |
/// |---|---|
/// | Web session | idle 7 days, absolute 30 days |
/// | Mobile session | idle 30 days, absolute 90 days |
/// | Session waiting for its second authentication step | 5 minutes |
/// | Validation cache | 30 seconds, 10 000 sessions |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionConfig {
    /// Lifetime of web sessions.
    pub web: SessionLifetime,
    /// Lifetime of mobile sessions.
    pub mobile: SessionLifetime,
    /// How long a session may wait for its second authentication step.
    pub pending_mfa: Duration,
    /// How long a validated session is served from memory before the store is asked
    /// again. Never more than [`MAX_SESSION_CACHE_TTL`]; zero switches the cache off.
    pub cache_ttl: Duration,
    /// Most sessions kept in the cache. When it is full, further sessions are validated
    /// against the store every time.
    pub cache_capacity: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            web: SessionLifetime::new(Duration::from_secs(7 * DAY), Duration::from_secs(30 * DAY)),
            mobile: SessionLifetime::new(
                Duration::from_secs(30 * DAY),
                Duration::from_secs(90 * DAY),
            ),
            pending_mfa: Duration::from_secs(5 * 60),
            cache_ttl: MAX_SESSION_CACHE_TTL,
            cache_capacity: 10_000,
        }
    }
}

impl SessionConfig {
    /// Set the lifetime of [`web`](Self::web) sessions.
    pub fn web(mut self, lifetime: SessionLifetime) -> Self {
        self.web = lifetime;
        self
    }

    /// Set the lifetime of [`mobile`](Self::mobile) sessions.
    pub fn mobile(mut self, lifetime: SessionLifetime) -> Self {
        self.mobile = lifetime;
        self
    }

    /// Set [`pending_mfa`](Self::pending_mfa).
    pub fn pending_mfa(mut self, duration: Duration) -> Self {
        self.pending_mfa = duration;
        self
    }

    /// Set [`cache_ttl`](Self::cache_ttl). Values above [`MAX_SESSION_CACHE_TTL`] are
    /// lowered to it.
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl.min(MAX_SESSION_CACHE_TTL);
        self
    }

    /// Set [`cache_capacity`](Self::cache_capacity).
    pub fn cache_capacity(mut self, sessions: usize) -> Self {
        self.cache_capacity = sessions;
        self
    }

    /// The lifetime for sessions of `kind`.
    pub fn lifetime(&self, kind: SessionKind) -> SessionLifetime {
        match kind {
            SessionKind::Web => self.web,
            SessionKind::Mobile => self.mobile,
        }
    }
}

/// `time + duration`, or `time` itself if that cannot be represented, so that an absurd
/// configuration yields a session that is already expired rather than a panic.
pub(crate) fn after(time: SystemTime, duration: Duration) -> SystemTime {
    time.checked_add(duration).unwrap_or(time)
}

/// Persistence for sessions.
///
/// Implement this for your database. [`MemorySessionStore`](super::MemorySessionStore) is
/// an in-memory implementation for tests.
///
/// # Contract
///
/// - Only the token hash is stored, in a unique column. The store never sees a token.
/// - [`find_by_token_hash`](Self::find_by_token_hash) returns the session together with
///   its account as it is now, typically with a join.
/// - A revoked session stays revoked: [`touch`](Self::touch) and
///   [`activate`](Self::activate) never clear `revoked_at`.
/// - Each method is atomic. In particular [`activate`](Self::activate) checks and changes
///   the state in one step.
pub trait SessionStore: Send + Sync + 'static {
    /// Create a session and return it with its new identifier. `last_seen_at` starts at
    /// `created_at` and `revoked_at` is empty.
    ///
    /// Returns [`StoreError::NotFound`] when the account does not exist.
    fn insert(
        &self,
        session: NewSession,
    ) -> impl Future<Output = Result<Session, StoreError>> + Send;

    /// Look up a session by the hash of its token, whatever its state: expired and
    /// revoked sessions are returned too.
    fn find_by_token_hash(
        &self,
        token_hash: &SessionTokenHash,
    ) -> impl Future<Output = Result<Option<SessionRecord>, StoreError>> + Send;

    /// Record that the session was used: set `last_seen_at` and `idle_expires_at`.
    fn touch(
        &self,
        id: Uuid,
        last_seen_at: SystemTime,
        idle_expires_at: SystemTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Turn a session that is waiting for its second authentication step into an active
    /// one, with new expiry times and `last_seen_at = now`.
    ///
    /// Only applies when the session is in state `pending_mfa`, is not revoked and its
    /// `absolute_expires_at` is later than `now`. Returns the updated session, or `None`
    /// when it did not apply.
    fn activate(
        &self,
        id: Uuid,
        now: SystemTime,
        idle_expires_at: SystemTime,
        absolute_expires_at: SystemTime,
    ) -> impl Future<Output = Result<Option<Session>, StoreError>> + Send;

    /// Revoke one session by setting `revoked_at`. With `owner`, only when the session
    /// belongs to that account.
    ///
    /// Returns the session, or `None` when there is no such session, it belongs to
    /// someone else, or it was already revoked.
    fn revoke(
        &self,
        id: Uuid,
        owner: Option<Uuid>,
        at: SystemTime,
    ) -> impl Future<Output = Result<Option<Session>, StoreError>> + Send;

    /// Revoke every session of an account that is not yet revoked, except the session
    /// `except` if given. Returns the identifiers of the sessions revoked by this call.
    fn revoke_all_for_user(
        &self,
        user_id: Uuid,
        except: Option<Uuid>,
        at: SystemTime,
    ) -> impl Future<Output = Result<Vec<Uuid>, StoreError>> + Send;

    /// The account's usable sessions: state `active`, not revoked, and both expiry times
    /// later than `now`. Most recently created first.
    fn list_active_for_user(
        &self,
        user_id: Uuid,
        now: SystemTime,
    ) -> impl Future<Output = Result<Vec<Session>, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_lifetimes() {
        let config = SessionConfig::default();
        assert_eq!(config.web.idle, Duration::from_secs(7 * 86_400));
        assert_eq!(config.web.absolute, Duration::from_secs(30 * 86_400));
        assert_eq!(config.mobile.idle, Duration::from_secs(30 * 86_400));
        assert_eq!(config.mobile.absolute, Duration::from_secs(90 * 86_400));
        assert_eq!(config.pending_mfa, Duration::from_secs(300));
        assert_eq!(config.cache_ttl, Duration::from_secs(30));
        assert_eq!(config.lifetime(SessionKind::Web), config.web);
        assert_eq!(config.lifetime(SessionKind::Mobile), config.mobile);
    }

    #[test]
    fn cache_ttl_can_be_lowered_but_not_raised() {
        let config = SessionConfig::default().cache_ttl(Duration::from_secs(600));
        assert_eq!(config.cache_ttl, Duration::from_secs(30));
        let config = config.cache_ttl(Duration::from_secs(5));
        assert_eq!(config.cache_ttl, Duration::from_secs(5));
    }

    #[test]
    fn names_round_trip() {
        for kind in [SessionKind::Web, SessionKind::Mobile] {
            assert_eq!(SessionKind::parse(kind.as_str()), Some(kind));
        }
        for state in [SessionState::PendingMfa, SessionState::Active] {
            assert_eq!(SessionState::parse(state.as_str()), Some(state));
        }
        assert_eq!(SessionState::PendingMfa.as_str(), "pending_mfa");
        assert_eq!(SessionKind::parse("desktop"), None);
        assert_eq!(SessionState::parse(""), None);
    }

    #[test]
    fn user_agent_is_cut_on_a_character_boundary() {
        let long = "é".repeat(MAX_USER_AGENT_CHARS + 10);
        let context = SessionContext::mobile().user_agent(long).normalized();
        let user_agent = context.user_agent.unwrap();
        assert_eq!(user_agent.chars().count(), MAX_USER_AGENT_CHARS);

        let short = SessionContext::web().user_agent("curl/8").normalized();
        assert_eq!(short.user_agent.as_deref(), Some("curl/8"));
        assert_eq!(short.kind, SessionKind::Web);
    }

    #[test]
    fn unrepresentable_expiry_fails_closed() {
        let now = SystemTime::now();
        assert_eq!(after(now, Duration::MAX), now);
        assert_eq!(
            after(now, Duration::from_secs(1)),
            now + Duration::from_secs(1)
        );
    }
}
