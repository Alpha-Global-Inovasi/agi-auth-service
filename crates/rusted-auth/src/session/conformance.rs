//! Checks that a storage implementation behaves like the in-memory stores.
//!
//! Available with the `test-util` cargo feature. Each function runs a fixed series of
//! operations against a store and panics, like `assert!`, at the first result that
//! differs from the contract of the trait. Call them from a test of your own store:
//!
//! ```rust,no_run
//! # async fn run() {
//! use rusted_auth::session::{MemorySessionStore, MemoryUserStore, conformance};
//!
//! let users = MemoryUserStore::new();
//! let sessions = MemorySessionStore::new(users.clone());
//! conformance::user_store(&users).await;
//! conformance::session_store(&users, &sessions).await;
//! # }
//! ```
//!
//! The checks create their own accounts with random names and use random keys, so they
//! can run side by side against one database that holds other data. They only use times
//! in whole seconds, so stores that keep timestamps with less precision than
//! [`SystemTime`] (such as Postgres, with microseconds) compare equal.
//!
//! Besides the behaviour of single calls, they check the operations the traits require
//! to be atomic by starting many of them at once on the same task: of sixteen concurrent
//! attempts to consume one token, exactly one may succeed. A store backed by a
//! connection pool runs them on separate connections, so give the pool several.

use super::attempts::{AttemptScope, AttemptStore};
use super::model::{NewSession, Session, SessionKind, SessionState, SessionStore};
use super::one_time::{
    ConsumedToken, NewOneTimeToken, OneTimeTokenHash, OneTimeTokenStore, TokenPurpose,
};
use super::token::SessionTokenHash;
use super::user::{NewUser, StoreError, User, UserStore};
use std::future::{Future, poll_fn};
use std::net::IpAddr;
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// How many copies of an operation the concurrency checks start at once.
const CONCURRENT: usize = 16;

/// Run `futures` concurrently on the current task and return their outputs in order.
pub(crate) async fn join_all<F: Future>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut futures: Vec<Pin<Box<F>>> = futures.into_iter().map(Box::pin).collect();
    let mut outputs: Vec<Option<F::Output>> = futures.iter().map(|_| None).collect();
    poll_fn(|cx| {
        let mut pending = false;
        for (future, output) in futures.iter_mut().zip(outputs.iter_mut()) {
            if output.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *output = Some(value),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    outputs.into_iter().flatten().collect()
}

/// A time in whole seconds near the present, so that stored times compare equal after
/// a round trip through a store with microsecond precision.
pub(crate) fn base_time() -> SystemTime {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(1_800_000_000, |d| d.as_secs());
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Eight random lowercase hexadecimal characters.
pub(crate) fn suffix() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_owned()
}

/// 32 random bytes.
pub(crate) fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Create an account with a random username and email address.
pub(crate) async fn new_account<U: UserStore>(users: &U, label: &str) -> User {
    let tag = suffix();
    users
        .insert(NewUser {
            username: format!("{label}.{tag}"),
            email: format!("{label}.{tag}@example.com"),
            name: format!("{label} {tag}"),
            password_hash: Some(format!("$test${tag}")),
        })
        .await
        .expect("insert a new account")
}

/// Check a [`UserStore`]: case-insensitive lookups and uniqueness, the login counters,
/// the compare-and-swap of password hashes, email verification and password reset.
pub async fn user_store<U: UserStore>(users: &U) {
    let tag = suffix();
    let username = format!("Budi.{tag}");
    let email = format!("Budi.{tag}@Example.com");
    let created = users
        .insert(NewUser {
            username: username.clone(),
            email: email.clone(),
            name: "Budi Santoso".into(),
            password_hash: Some("$argon2id$first".into()),
        })
        .await
        .expect("insert");
    assert_eq!(
        created.username, username,
        "username keeps its capitalization"
    );
    assert_eq!(created.email, email, "email keeps its capitalization");
    assert_eq!(created.name, "Budi Santoso");
    assert_eq!(created.email_verified_at, None);
    assert_eq!(created.disabled_at, None);
    let id = created.id;

    let by_name = users
        .find_by_username(&username.to_uppercase())
        .await
        .expect("find_by_username")
        .expect("username lookup ignores case");
    assert_eq!(by_name.user, created);
    assert_eq!(by_name.password_hash.as_deref(), Some("$argon2id$first"));
    assert_eq!(by_name.failed_login_count, 0);
    assert_eq!(by_name.locked_until, None);
    let by_email = users
        .find_by_email(&email.to_lowercase())
        .await
        .expect("find_by_email")
        .expect("email lookup ignores case");
    assert_eq!(by_email.user, created);
    let missing = format!("nobody.{tag}");
    assert!(
        users
            .find_by_username(&missing)
            .await
            .expect("find")
            .is_none()
    );
    assert!(
        users
            .find_by_email(&format!("{missing}@example.com"))
            .await
            .expect("find")
            .is_none()
    );

    let other = |username: String, email: String| NewUser {
        username,
        email,
        name: "Siti".into(),
        password_hash: None,
    };
    let same_name = users
        .insert(other(
            username.to_lowercase(),
            format!("siti.{tag}@example.com"),
        ))
        .await;
    assert!(
        matches!(same_name, Err(StoreError::UsernameTaken)),
        "same username in other case: {same_name:?}"
    );
    let same_email = users
        .insert(other(format!("siti.{tag}"), email.to_uppercase()))
        .await;
    assert!(
        matches!(same_email, Err(StoreError::EmailTaken)),
        "same email in other case: {same_email:?}"
    );
    let both = users.insert(other(username.clone(), email.clone())).await;
    assert!(
        matches!(both, Err(StoreError::UsernameTaken)),
        "both taken reports the username: {both:?}"
    );

    // An account without a password.
    let siti = users
        .insert(other(
            format!("siti.{tag}"),
            format!("siti.{tag}@example.com"),
        ))
        .await
        .expect("insert an account without a password");
    let siti_record = users
        .find_by_username(&siti.username)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(siti_record.password_hash, None);

    // Login counters.
    assert_eq!(users.record_failed_login(id).await.expect("count"), 1);
    assert_eq!(users.record_failed_login(id).await.expect("count"), 2);
    let until = base_time() + secs(60);
    users
        .set_locked_until(id, Some(until))
        .await
        .expect("set_locked_until");
    let record = users
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.failed_login_count, 2);
    assert_eq!(record.locked_until, Some(until));
    users.set_locked_until(id, None).await.expect("clear lock");
    let record = users
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.locked_until, None);
    assert_eq!(
        record.failed_login_count, 2,
        "clearing the lock keeps the count"
    );
    users
        .set_locked_until(id, Some(until))
        .await
        .expect("set_locked_until");
    users
        .record_successful_login(id)
        .await
        .expect("record_successful_login");
    let record = users
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.failed_login_count, 0);
    assert_eq!(record.locked_until, None);
    assert_eq!(
        users
            .find_by_username(&siti.username)
            .await
            .expect("find")
            .expect("found")
            .failed_login_count,
        0,
        "counters belong to one account"
    );

    // Compare-and-swap of the password hash.
    assert!(
        !users
            .replace_password_hash(id, "$argon2id$other", "$argon2id$second".into())
            .await
            .expect("replace_password_hash"),
        "replaced although the current hash differs"
    );
    assert!(
        users
            .replace_password_hash(id, "$argon2id$first", "$argon2id$second".into())
            .await
            .expect("replace_password_hash")
    );
    let record = users
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.password_hash.as_deref(), Some("$argon2id$second"));
    assert!(
        !users
            .replace_password_hash(siti.id, "$argon2id$first", "x".into())
            .await
            .expect("replace_password_hash"),
        "replaced the hash of an account without a password"
    );

    // Email verification is recorded once.
    let first = base_time();
    assert!(users.mark_email_verified(id, first).await.expect("verify"));
    assert!(
        !users
            .mark_email_verified(id, first + secs(10))
            .await
            .expect("verify again")
    );
    let record = users
        .find_by_email(&email)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.user.email_verified_at, Some(first));

    // Password reset replaces the hash and clears the lockout state.
    users.record_failed_login(id).await.expect("count");
    users
        .set_locked_until(id, Some(until))
        .await
        .expect("set_locked_until");
    users
        .reset_password(id, "$argon2id$reset".into())
        .await
        .expect("reset_password");
    let record = users
        .find_by_username(&username)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.password_hash.as_deref(), Some("$argon2id$reset"));
    assert_eq!(record.failed_login_count, 0);
    assert_eq!(record.locked_until, None);
    users
        .reset_password(siti.id, "$argon2id$siti".into())
        .await
        .expect("reset_password on an account without a password");
    let record = users
        .find_by_username(&siti.username)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.password_hash.as_deref(), Some("$argon2id$siti"));

    // Unknown accounts.
    let nobody = Uuid::new_v4();
    let not_found = |result: Result<(), StoreError>, what: &str| {
        assert!(
            matches!(result, Err(StoreError::NotFound)),
            "{what}: {result:?}"
        );
    };
    not_found(
        users.record_failed_login(nobody).await.map(drop),
        "record_failed_login",
    );
    not_found(
        users.set_locked_until(nobody, None).await,
        "set_locked_until",
    );
    not_found(
        users.record_successful_login(nobody).await,
        "record_successful_login",
    );
    not_found(
        users
            .replace_password_hash(nobody, "a", "b".into())
            .await
            .map(drop),
        "replace_password_hash",
    );
    not_found(
        users.mark_email_verified(nobody, first).await.map(drop),
        "mark_email_verified",
    );
    not_found(
        users.reset_password(nobody, "x".into()).await,
        "reset_password",
    );

    // Concurrent registrations of one username create one account.
    let tag = suffix();
    let results = join_all((0..CONCURRENT).map(|i| {
        let username = format!("Same.{tag}");
        users.insert(NewUser {
            username: if i % 2 == 0 {
                username.to_uppercase()
            } else {
                username
            },
            email: format!("same{i}.{tag}@example.com"),
            name: "Same".into(),
            password_hash: None,
        })
    }))
    .await;
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "concurrent registrations of one username"
    );
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| matches!(e, StoreError::UsernameTaken)),
        "{results:?}"
    );

    // Concurrent failed logins are all counted.
    let mut counts: Vec<u32> = join_all((0..CONCURRENT).map(|_| users.record_failed_login(id)))
        .await
        .into_iter()
        .map(|count| count.expect("record_failed_login"))
        .collect();
    counts.sort_unstable();
    let expected: Vec<u32> = (1..=CONCURRENT as u32).collect();
    assert_eq!(counts, expected, "concurrent failed logins");
}

fn new_session(
    user_id: Uuid,
    kind: SessionKind,
    state: SessionState,
    created_at: SystemTime,
) -> (NewSession, SessionTokenHash) {
    let token_hash = SessionTokenHash::from_bytes(random_bytes());
    let session = NewSession {
        token_hash,
        user_id,
        kind,
        state,
        created_at,
        idle_expires_at: created_at + secs(3_600),
        absolute_expires_at: created_at + secs(86_400),
        ip: None,
        user_agent: None,
        idp_sid: None,
    };
    (session, token_hash)
}

/// Check a [`SessionStore`] whose sessions belong to the accounts of `users`: insert and
/// lookup with the current account, `touch`, activation of a pending session, revocation
/// and the list of usable sessions.
pub async fn session_store<U: UserStore, S: SessionStore>(users: &U, sessions: &S) {
    let budi = new_account(users, "budi").await;
    let siti = new_account(users, "siti").await;
    let t0 = base_time();

    // Insert and look up, with every optional field set.
    let token_hash = SessionTokenHash::from_bytes(random_bytes());
    let ip: IpAddr = "2001:db8::7".parse().expect("address");
    let inserted = sessions
        .insert(NewSession {
            token_hash,
            user_id: budi.id,
            kind: SessionKind::Mobile,
            state: SessionState::Active,
            created_at: t0,
            idle_expires_at: t0 + secs(600),
            absolute_expires_at: t0 + secs(7_200),
            ip: Some(ip),
            user_agent: Some("Mozilla/5.0 (Linux) é".into()),
            idp_sid: Some("idp-session".into()),
        })
        .await
        .expect("insert");
    let expected = Session {
        id: inserted.id,
        user_id: budi.id,
        kind: SessionKind::Mobile,
        state: SessionState::Active,
        created_at: t0,
        last_seen_at: t0,
        idle_expires_at: t0 + secs(600),
        absolute_expires_at: t0 + secs(7_200),
        ip: Some(ip),
        user_agent: Some("Mozilla/5.0 (Linux) é".into()),
        revoked_at: None,
        idp_sid: Some("idp-session".into()),
    };
    assert_eq!(inserted, expected);
    let record = sessions
        .find_by_token_hash(&token_hash)
        .await
        .expect("find_by_token_hash")
        .expect("found");
    assert_eq!(record.session, expected);
    assert_eq!(record.token_hash, token_hash);
    assert_eq!(record.user, budi);
    assert!(
        sessions
            .find_by_token_hash(&SessionTokenHash::from_bytes(random_bytes()))
            .await
            .expect("find_by_token_hash")
            .is_none()
    );

    // The account is read as it is now.
    users
        .mark_email_verified(budi.id, t0)
        .await
        .expect("mark_email_verified");
    let record = sessions
        .find_by_token_hash(&token_hash)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.user.email_verified_at, Some(t0));

    // An IPv4 address, and no optional fields.
    let (mut web, web_hash) = new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
    web.ip = Some("203.0.113.7".parse().expect("address"));
    let web = sessions.insert(web).await.expect("insert");
    assert_eq!(web.ip, Some("203.0.113.7".parse().expect("address")));
    let record = sessions
        .find_by_token_hash(&web_hash)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.session, web);
    assert_eq!(record.session.user_agent, None);
    assert_eq!(record.session.idp_sid, None);

    // Unknown account, duplicate hash.
    let (orphan, _) = new_session(Uuid::new_v4(), SessionKind::Web, SessionState::Active, t0);
    let result = sessions.insert(orphan).await;
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "unknown account: {result:?}"
    );
    let (mut duplicate, _) = new_session(siti.id, SessionKind::Web, SessionState::Active, t0);
    duplicate.token_hash = token_hash;
    assert!(
        sessions.insert(duplicate).await.is_err(),
        "duplicate token hash accepted"
    );

    // touch.
    sessions
        .touch(inserted.id, t0 + secs(60), t0 + secs(660))
        .await
        .expect("touch");
    let record = sessions
        .find_by_token_hash(&token_hash)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.session.last_seen_at, t0 + secs(60));
    assert_eq!(record.session.idle_expires_at, t0 + secs(660));
    let result = sessions.touch(Uuid::new_v4(), t0, t0).await;
    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "touch unknown: {result:?}"
    );

    activation(sessions, &budi, t0).await;
    revocation(sessions, &budi, &siti, t0).await;
    listing(users, sessions, t0).await;
}

async fn activation<S: SessionStore>(sessions: &S, budi: &User, t0: SystemTime) {
    let (pending, pending_hash) =
        new_session(budi.id, SessionKind::Web, SessionState::PendingMfa, t0);
    let pending = sessions.insert(pending).await.expect("insert pending");
    assert_eq!(pending.state, SessionState::PendingMfa);
    let now = t0 + secs(30);

    // A session that is not pending does not qualify.
    let (active, _) = new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
    let active = sessions.insert(active).await.expect("insert active");
    let (replacement, _) = new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
    assert_eq!(
        sessions
            .activate(active.id, replacement, now)
            .await
            .expect("activate"),
        None,
        "activated a session that was not pending"
    );
    let (replacement, _) = new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
    assert_eq!(
        sessions
            .activate(Uuid::new_v4(), replacement, now)
            .await
            .expect("activate"),
        None,
        "activated an unknown session"
    );

    // An expired pending session does not qualify.
    let (mut expired, _) = new_session(budi.id, SessionKind::Web, SessionState::PendingMfa, t0);
    expired.absolute_expires_at = now;
    let expired = sessions.insert(expired).await.expect("insert");
    let (replacement, replacement_hash) =
        new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
    assert_eq!(
        sessions
            .activate(expired.id, replacement, now)
            .await
            .expect("activate"),
        None,
        "activated an expired session"
    );
    assert!(
        sessions
            .find_by_token_hash(&replacement_hash)
            .await
            .expect("find")
            .is_none(),
        "a failed activation inserted its replacement"
    );

    // The pending session is revoked and its replacement inserted.
    let (mut replacement, replacement_hash) =
        new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
    replacement.absolute_expires_at = pending.absolute_expires_at;
    let activated = sessions
        .activate(pending.id, replacement, now)
        .await
        .expect("activate")
        .expect("the pending session qualifies");
    assert_ne!(activated.id, pending.id);
    assert_eq!(activated.state, SessionState::Active);
    assert_eq!(activated.user_id, budi.id);
    assert_eq!(activated.revoked_at, None);
    assert_eq!(activated.absolute_expires_at, pending.absolute_expires_at);
    let old = sessions
        .find_by_token_hash(&pending_hash)
        .await
        .expect("find")
        .expect("the pending session is kept");
    assert_eq!(old.session.revoked_at, Some(now));
    let new = sessions
        .find_by_token_hash(&replacement_hash)
        .await
        .expect("find")
        .expect("the replacement is stored");
    assert_eq!(new.session, activated);

    // Only once.
    let (replacement, _) = new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
    assert_eq!(
        sessions
            .activate(pending.id, replacement, now)
            .await
            .expect("activate"),
        None,
        "activated the same pending session twice"
    );

    // Of concurrent activations of one pending session, one succeeds.
    let (pending, _) = new_session(budi.id, SessionKind::Web, SessionState::PendingMfa, t0);
    let pending = sessions.insert(pending).await.expect("insert pending");
    let activated = join_all((0..CONCURRENT).map(|_| {
        let (replacement, _) = new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
        sessions.activate(pending.id, replacement, now)
    }))
    .await;
    let activated: Vec<Session> = activated
        .into_iter()
        .filter_map(|result| result.expect("activate"))
        .collect();
    assert_eq!(
        activated.len(),
        1,
        "concurrent activations of one pending session"
    );
}

async fn revocation<S: SessionStore>(sessions: &S, budi: &User, siti: &User, t0: SystemTime) {
    let mut budis = Vec::new();
    for _ in 0..3 {
        let (session, _) = new_session(budi.id, SessionKind::Web, SessionState::Active, t0);
        budis.push(sessions.insert(session).await.expect("insert").id);
    }
    let (session, siti_hash) = new_session(siti.id, SessionKind::Web, SessionState::Active, t0);
    let sitis = sessions.insert(session).await.expect("insert").id;
    let at = t0 + secs(5);

    assert_eq!(
        sessions
            .revoke(budis[0], Some(siti.id), at)
            .await
            .expect("revoke"),
        None,
        "revoked a session of another account"
    );
    let revoked = sessions
        .revoke(budis[0], Some(budi.id), at)
        .await
        .expect("revoke")
        .expect("revoked");
    assert_eq!(revoked.id, budis[0]);
    assert_eq!(revoked.revoked_at, Some(at));
    assert_eq!(
        sessions
            .revoke(budis[0], None, at + secs(1))
            .await
            .expect("revoke"),
        None,
        "revoked a session twice"
    );
    let revoked = sessions
        .revoke(budis[1], None, at)
        .await
        .expect("revoke")
        .expect("revoked without an owner");
    assert_eq!(revoked.revoked_at, Some(at));
    assert_eq!(
        sessions
            .revoke(Uuid::new_v4(), None, at)
            .await
            .expect("revoke"),
        None
    );

    // touch never clears a revocation.
    sessions
        .touch(budis[1], at, at + secs(600))
        .await
        .expect("touch");
    let listed = sessions
        .list_active_for_user(budi.id, at)
        .await
        .expect("list");
    assert!(
        !listed.iter().any(|s| s.id == budis[1]),
        "touch brought back a revoked session"
    );

    // revoke_all_for_user, with and without an exception.
    let keep = budis[2];
    let mut revoked = sessions
        .revoke_all_for_user(budi.id, Some(keep), at)
        .await
        .expect("revoke_all_for_user");
    revoked.sort();
    let still_active: Vec<Uuid> = sessions
        .list_active_for_user(budi.id, at)
        .await
        .expect("list")
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(still_active, vec![keep], "only the exception stays");
    assert!(!revoked.contains(&keep));
    assert!(
        !revoked.contains(&budis[0]),
        "an already revoked session was revoked again"
    );
    assert!(!revoked.is_empty());
    assert_eq!(
        sessions
            .revoke_all_for_user(budi.id, None, at)
            .await
            .expect("revoke_all_for_user"),
        vec![keep]
    );
    assert_eq!(
        sessions
            .revoke_all_for_user(budi.id, None, at)
            .await
            .expect("revoke_all_for_user"),
        Vec::<Uuid>::new()
    );
    let record = sessions
        .find_by_token_hash(&siti_hash)
        .await
        .expect("find")
        .expect("found");
    assert_eq!(record.session.id, sitis);
    assert_eq!(
        record.session.revoked_at, None,
        "another account's session was revoked"
    );
}

async fn listing<U: UserStore, S: SessionStore>(users: &U, sessions: &S, t0: SystemTime) {
    let user = new_account(users, "list").await;
    let now = t0 + secs(100);
    let insert = |created: u64, change: fn(&mut NewSession)| {
        let (mut session, _) = new_session(
            user.id,
            SessionKind::Web,
            SessionState::Active,
            t0 + secs(created),
        );
        change(&mut session);
        async move { sessions.insert(session).await.expect("insert").id }
    };
    let older = insert(1, |_| {}).await;
    let newer = insert(3, |_| {}).await;
    let mobile = insert(2, |s| s.kind = SessionKind::Mobile).await;
    insert(4, |s| s.state = SessionState::PendingMfa).await;
    insert(5, |s| s.idle_expires_at = s.created_at + secs(95)).await;
    insert(6, |s| s.absolute_expires_at = s.created_at + secs(94)).await;
    let revoked = insert(7, |_| {}).await;
    sessions.revoke(revoked, None, now).await.expect("revoke");

    let listed: Vec<Uuid> = sessions
        .list_active_for_user(user.id, now)
        .await
        .expect("list")
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(
        listed,
        vec![newer, mobile, older],
        "usable sessions, newest first"
    );
    assert!(
        sessions
            .list_active_for_user(Uuid::new_v4(), now)
            .await
            .expect("list")
            .is_empty()
    );
}

fn new_token(
    user: &User,
    purpose: TokenPurpose,
    expires_at: SystemTime,
) -> (NewOneTimeToken, OneTimeTokenHash) {
    let token_hash = OneTimeTokenHash::from_bytes(random_bytes());
    let token = NewOneTimeToken {
        token_hash,
        user_id: user.id,
        purpose,
        email: user.email.clone(),
        expires_at,
    };
    (token, token_hash)
}

/// Check a [`OneTimeTokenStore`] for tokens of the accounts of `users`: consumption by
/// hash and purpose, once and only before the token expires, and invalidation.
pub async fn one_time_token_store<U: UserStore, T: OneTimeTokenStore>(users: &U, tokens: &T) {
    let budi = new_account(users, "budi").await;
    let siti = new_account(users, "siti").await;
    let t0 = base_time();
    let end = t0 + secs(3_600);
    let reset = TokenPurpose::ResetPassword;
    let verify = TokenPurpose::VerifyEmail;

    let (token, hash) = new_token(&budi, reset, end);
    tokens.insert(token).await.expect("insert");
    let (mut duplicate, _) = new_token(&siti, verify, end);
    duplicate.token_hash = hash;
    assert!(
        tokens.insert(duplicate).await.is_err(),
        "duplicate token hash accepted"
    );

    assert_eq!(
        tokens.consume(&hash, verify, t0).await.expect("consume"),
        None,
        "consumed a token for another purpose"
    );
    assert_eq!(
        tokens
            .consume(&OneTimeTokenHash::from_bytes(random_bytes()), reset, t0)
            .await
            .expect("consume"),
        None
    );
    assert_eq!(
        tokens.consume(&hash, reset, t0).await.expect("consume"),
        Some(ConsumedToken::new(budi.id, budi.email.clone()))
    );
    assert_eq!(
        tokens.consume(&hash, reset, t0).await.expect("consume"),
        None,
        "consumed a token twice"
    );

    // The address is the one stored with the token, not the account's.
    let (mut token, hash) = new_token(&budi, verify, end);
    token.email = format!("Old.{}@Example.com", suffix());
    let address = token.email.clone();
    tokens.insert(token).await.expect("insert");
    assert_eq!(
        tokens.consume(&hash, verify, t0).await.expect("consume"),
        Some(ConsumedToken::new(budi.id, address))
    );

    // A token stops working at its expiry time.
    let (token, hash) = new_token(&budi, verify, end);
    tokens.insert(token).await.expect("insert");
    assert_eq!(
        tokens.consume(&hash, verify, end).await.expect("consume"),
        None,
        "consumed a token at its expiry time"
    );
    assert!(
        tokens
            .consume(&hash, verify, end - secs(1))
            .await
            .expect("consume")
            .is_some()
    );

    // Invalidation applies to one account and one purpose.
    let (first, first_hash) = new_token(&budi, reset, end);
    let (second, second_hash) = new_token(&budi, reset, end);
    let (other_purpose, other_purpose_hash) = new_token(&budi, verify, end);
    let (other_user, other_user_hash) = new_token(&siti, reset, end);
    for token in [first, second, other_purpose, other_user] {
        tokens.insert(token).await.expect("insert");
    }
    tokens
        .invalidate(budi.id, reset, t0)
        .await
        .expect("invalidate");
    for hash in [first_hash, second_hash] {
        assert_eq!(
            tokens.consume(&hash, reset, t0).await.expect("consume"),
            None,
            "an invalidated token still works"
        );
    }
    assert!(
        tokens
            .consume(&other_purpose_hash, verify, t0)
            .await
            .expect("consume")
            .is_some(),
        "invalidation reached another purpose"
    );
    assert_eq!(
        tokens
            .consume(&other_user_hash, reset, t0)
            .await
            .expect("consume"),
        Some(ConsumedToken::new(siti.id, siti.email.clone())),
        "invalidation reached another account"
    );
    tokens
        .invalidate(Uuid::new_v4(), reset, t0)
        .await
        .expect("invalidate for an unknown account");

    // Of concurrent uses of one token, one succeeds.
    let (token, hash) = new_token(&budi, reset, end);
    tokens.insert(token).await.expect("insert");
    let consumed = join_all((0..CONCURRENT).map(|_| tokens.consume(&hash, reset, t0))).await;
    let consumed = consumed
        .into_iter()
        .filter_map(|result| result.expect("consume"))
        .count();
    assert_eq!(consumed, 1, "concurrent uses of one token");
}

/// Check an [`AttemptStore`]: counting up to the limit, starting over after the end of
/// the window, giving attempts back and clearing.
pub async fn attempt_store<A: AttemptStore>(attempts: &A) {
    let key = Uuid::new_v4();
    let now = base_time();
    let later = now + secs(300);
    let login = AttemptScope::Login;

    for expected in 1..=3 {
        assert_eq!(
            attempts
                .begin(login, key, 3, later, now)
                .await
                .expect("begin"),
            Some(expected)
        );
    }
    assert_eq!(
        attempts
            .begin(login, key, 3, later, now)
            .await
            .expect("begin"),
        None,
        "counted past the limit"
    );
    assert_eq!(
        attempts
            .begin(login, key, 4, later, now)
            .await
            .expect("begin"),
        Some(4),
        "the limit is the caller's, not stored"
    );

    // Scopes and keys are separate.
    for scope in [
        AttemptScope::Change,
        AttemptScope::Email,
        AttemptScope::PasswordChange,
        AttemptScope::ClientAddress,
    ] {
        assert_eq!(
            attempts
                .begin(scope, key, 3, later, now)
                .await
                .expect("begin"),
            Some(1),
            "{scope:?} shares a counter"
        );
    }
    assert_eq!(
        attempts
            .begin(login, Uuid::new_v4(), 3, later, now)
            .await
            .expect("begin"),
        Some(1)
    );

    // give_back lowers by one, not below zero.
    attempts.give_back(login, key).await.expect("give_back");
    assert_eq!(
        attempts
            .begin(login, key, 4, later, now)
            .await
            .expect("begin"),
        Some(4)
    );
    let fresh = Uuid::new_v4();
    attempts
        .begin(login, fresh, 3, later, now)
        .await
        .expect("begin");
    attempts.give_back(login, fresh).await.expect("give_back");
    attempts.give_back(login, fresh).await.expect("give_back");
    assert_eq!(
        attempts
            .begin(login, fresh, 3, later, now)
            .await
            .expect("begin"),
        Some(1),
        "give_back went below zero"
    );
    attempts
        .give_back(login, Uuid::new_v4())
        .await
        .expect("give_back without a counter");

    // clear.
    attempts.clear(login, key).await.expect("clear");
    assert_eq!(
        attempts
            .begin(login, key, 3, later, now)
            .await
            .expect("begin"),
        Some(1)
    );
    attempts
        .clear(login, Uuid::new_v4())
        .await
        .expect("clear without a counter");

    // A counter whose end is not later than `now` starts over with the new end, and a
    // counter that has not ended keeps its end.
    let scope = AttemptScope::Change;
    let key = Uuid::new_v4();
    let end = now + secs(300);
    assert_eq!(
        attempts
            .begin(scope, key, 1, end, now)
            .await
            .expect("begin"),
        Some(1)
    );
    assert_eq!(
        attempts
            .begin(scope, key, 2, end + secs(9), now)
            .await
            .expect("begin"),
        Some(2)
    );
    let next_end = end + secs(300);
    assert_eq!(
        attempts
            .begin(scope, key, 1, next_end, end)
            .await
            .expect("begin"),
        Some(1),
        "an ended counter did not start over"
    );
    assert_eq!(
        attempts
            .begin(scope, key, 1, next_end, end)
            .await
            .expect("begin"),
        None
    );
    assert_eq!(
        attempts
            .begin(scope, key, 1, next_end + secs(300), next_end)
            .await
            .expect("begin"),
        Some(1),
        "an ended counter did not start over"
    );

    // Concurrent attempts never pass the limit.
    let key = Uuid::new_v4();
    let granted =
        join_all((0..CONCURRENT).map(|_| attempts.begin(AttemptScope::Login, key, 5, later, now)))
            .await;
    let mut granted: Vec<u32> = granted
        .into_iter()
        .filter_map(|result| result.expect("begin"))
        .collect();
    granted.sort_unstable();
    assert_eq!(granted, vec![1, 2, 3, 4, 5], "concurrent attempts");
}

#[cfg(test)]
mod tests {
    use super::super::{
        MemoryAttemptStore, MemoryOneTimeTokenStore, MemorySessionStore, MemoryUserStore,
    };

    #[tokio::test]
    async fn memory_stores_conform() {
        let users = MemoryUserStore::new();
        super::user_store(&users).await;
        super::session_store(&users, &MemorySessionStore::new(users.clone())).await;
        super::one_time_token_store(&users, &MemoryOneTimeTokenStore::new()).await;
        super::attempt_store(&MemoryAttemptStore::new()).await;
    }
}
