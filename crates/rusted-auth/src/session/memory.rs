use super::model::{NewSession, Session, SessionRecord, SessionState, SessionStore};
use super::token::SessionTokenHash;
use super::user::{NewUser, StoreError, User, UserRecord, UserStore};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;
use uuid::Uuid;

/// In-memory [`UserStore`] for tests and examples.
///
/// Accounts are lost when the last clone is dropped. Clones share the same accounts.
#[derive(Debug, Clone, Default)]
pub struct MemoryUserStore {
    users: Arc<Mutex<Vec<UserRecord>>>,
}

impl MemoryUserStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The stored record for `id`, including lockout state.
    pub fn get(&self, id: Uuid) -> Option<UserRecord> {
        self.lock().iter().find(|r| r.user.id == id).cloned()
    }

    /// Change a stored record in place, for example to disable an account in a test.
    /// Returns `false` when the account does not exist.
    pub fn update(&self, id: Uuid, change: impl FnOnce(&mut UserRecord)) -> bool {
        match self.lock().iter_mut().find(|r| r.user.id == id) {
            Some(record) => {
                change(record);
                true
            }
            None => false,
        }
    }

    /// Number of accounts.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` when there are no accounts.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<UserRecord>> {
        self.users.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn update_or_not_found(
        &self,
        id: Uuid,
        change: impl FnOnce(&mut UserRecord),
    ) -> Result<(), StoreError> {
        if self.update(id, change) {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }
}

fn same(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

impl UserStore for MemoryUserStore {
    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, StoreError> {
        Ok(self
            .lock()
            .iter()
            .find(|r| same(&r.user.username, username))
            .cloned())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, StoreError> {
        Ok(self
            .lock()
            .iter()
            .find(|r| same(&r.user.email, email))
            .cloned())
    }

    async fn insert(&self, new_user: NewUser) -> Result<User, StoreError> {
        let mut users = self.lock();
        if users
            .iter()
            .any(|r| same(&r.user.username, &new_user.username))
        {
            return Err(StoreError::UsernameTaken);
        }
        if users.iter().any(|r| same(&r.user.email, &new_user.email)) {
            return Err(StoreError::EmailTaken);
        }
        let user = User {
            id: Uuid::new_v4(),
            username: new_user.username,
            email: new_user.email,
            email_verified_at: None,
            name: new_user.name,
            disabled_at: None,
        };
        users.push(UserRecord {
            user: user.clone(),
            password_hash: new_user.password_hash,
            failed_login_count: 0,
            locked_until: None,
        });
        Ok(user)
    }

    async fn record_failed_login(&self, id: Uuid) -> Result<u32, StoreError> {
        let mut count = 0;
        self.update_or_not_found(id, |record| {
            record.failed_login_count = record.failed_login_count.saturating_add(1);
            count = record.failed_login_count;
        })?;
        Ok(count)
    }

    async fn set_locked_until(
        &self,
        id: Uuid,
        until: Option<SystemTime>,
    ) -> Result<(), StoreError> {
        self.update_or_not_found(id, |record| record.locked_until = until)
    }

    async fn record_successful_login(&self, id: Uuid) -> Result<(), StoreError> {
        self.update_or_not_found(id, |record| {
            record.failed_login_count = 0;
            record.locked_until = None;
        })
    }

    async fn replace_password_hash(
        &self,
        id: Uuid,
        current: &str,
        new: String,
    ) -> Result<bool, StoreError> {
        let mut replaced = false;
        self.update_or_not_found(id, |record| {
            if record.password_hash.as_deref() == Some(current) {
                record.password_hash = Some(new);
                replaced = true;
            }
        })?;
        Ok(replaced)
    }

    async fn mark_email_verified(&self, id: Uuid, at: SystemTime) -> Result<bool, StoreError> {
        let mut changed = false;
        self.update_or_not_found(id, |record| {
            if record.user.email_verified_at.is_none() {
                record.user.email_verified_at = Some(at);
                changed = true;
            }
        })?;
        Ok(changed)
    }

    async fn reset_password(&self, id: Uuid, password_hash: String) -> Result<(), StoreError> {
        self.update_or_not_found(id, |record| {
            record.password_hash = Some(password_hash);
            record.failed_login_count = 0;
            record.locked_until = None;
        })
    }
}

/// In-memory [`SessionStore`] for tests and examples.
///
/// It reads accounts from the [`MemoryUserStore`] it was created with, the way a database
/// store joins the sessions table with the users table. Sessions are lost when the last
/// clone is dropped. Clones share the same sessions.
#[derive(Debug, Clone)]
pub struct MemorySessionStore {
    users: MemoryUserStore,
    sessions: Arc<Mutex<Vec<StoredSession>>>,
}

#[derive(Debug, Clone)]
struct StoredSession {
    session: Session,
    token_hash: SessionTokenHash,
}

impl From<NewSession> for StoredSession {
    fn from(new: NewSession) -> Self {
        Self {
            session: Session {
                id: Uuid::new_v4(),
                user_id: new.user_id,
                kind: new.kind,
                state: new.state,
                created_at: new.created_at,
                last_seen_at: new.created_at,
                idle_expires_at: new.idle_expires_at,
                absolute_expires_at: new.absolute_expires_at,
                ip: new.ip,
                user_agent: new.user_agent,
                revoked_at: None,
                idp_sid: new.idp_sid,
            },
            token_hash: new.token_hash,
        }
    }
}

impl MemorySessionStore {
    /// An empty store for the sessions of the accounts in `users`.
    pub fn new(users: MemoryUserStore) -> Self {
        Self {
            users,
            sessions: Arc::default(),
        }
    }

    /// The stored session `id`, whatever its state.
    pub fn get(&self, id: Uuid) -> Option<Session> {
        self.lock()
            .iter()
            .find(|s| s.session.id == id)
            .map(|s| s.session.clone())
    }

    /// Change a stored session in place, for example to age it in a test. Returns `false`
    /// when the session does not exist.
    pub fn update(&self, id: Uuid, change: impl FnOnce(&mut Session)) -> bool {
        match self.lock().iter_mut().find(|s| s.session.id == id) {
            Some(stored) => {
                change(&mut stored.session);
                true
            }
            None => false,
        }
    }

    /// Number of sessions, including expired and revoked ones.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` when there are no sessions.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<StoredSession>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SessionStore for MemorySessionStore {
    async fn insert(&self, new: NewSession) -> Result<Session, StoreError> {
        if self.users.get(new.user_id).is_none() {
            return Err(StoreError::NotFound);
        }
        let mut sessions = self.lock();
        if sessions.iter().any(|s| s.token_hash == new.token_hash) {
            return Err(StoreError::backend("duplicate session token hash"));
        }
        let stored = StoredSession::from(new);
        let session = stored.session.clone();
        sessions.push(stored);
        Ok(session)
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &SessionTokenHash,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let Some(stored) = self
            .lock()
            .iter()
            .find(|s| s.token_hash == *token_hash)
            .cloned()
        else {
            return Ok(None);
        };
        Ok(self
            .users
            .get(stored.session.user_id)
            .map(|account| SessionRecord {
                session: stored.session,
                token_hash: stored.token_hash,
                user: account.user,
            }))
    }

    async fn touch(
        &self,
        id: Uuid,
        last_seen_at: SystemTime,
        idle_expires_at: SystemTime,
    ) -> Result<(), StoreError> {
        let found = self.update(id, |session| {
            session.last_seen_at = last_seen_at;
            session.idle_expires_at = idle_expires_at;
        });
        if found {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn activate(
        &self,
        pending_id: Uuid,
        replacement: NewSession,
        now: SystemTime,
    ) -> Result<Option<Session>, StoreError> {
        if self.users.get(replacement.user_id).is_none() {
            return Err(StoreError::NotFound);
        }
        let mut sessions = self.lock();
        if sessions
            .iter()
            .any(|s| s.token_hash == replacement.token_hash)
        {
            return Err(StoreError::backend("duplicate session token hash"));
        }
        let Some(pending) = sessions
            .iter_mut()
            .map(|s| &mut s.session)
            .find(|s| s.id == pending_id)
        else {
            return Ok(None);
        };
        if pending.state != SessionState::PendingMfa
            || pending.revoked_at.is_some()
            || pending.absolute_expires_at <= now
        {
            return Ok(None);
        }
        pending.revoked_at = Some(now);
        let stored = StoredSession::from(replacement);
        let session = stored.session.clone();
        sessions.push(stored);
        Ok(Some(session))
    }

    async fn revoke(
        &self,
        id: Uuid,
        owner: Option<Uuid>,
        at: SystemTime,
    ) -> Result<Option<Session>, StoreError> {
        let mut sessions = self.lock();
        let session = sessions
            .iter_mut()
            .map(|s| &mut s.session)
            .find(|s| s.id == id && owner.is_none_or(|owner| owner == s.user_id))
            .filter(|s| s.revoked_at.is_none());
        Ok(session.map(|session| {
            session.revoked_at = Some(at);
            session.clone()
        }))
    }

    async fn revoke_all_for_user(
        &self,
        user_id: Uuid,
        except: Option<Uuid>,
        at: SystemTime,
    ) -> Result<Vec<Uuid>, StoreError> {
        let mut revoked = Vec::new();
        for stored in self.lock().iter_mut() {
            let session = &mut stored.session;
            if session.user_id == user_id
                && Some(session.id) != except
                && session.revoked_at.is_none()
            {
                session.revoked_at = Some(at);
                revoked.push(session.id);
            }
        }
        Ok(revoked)
    }

    async fn list_active_for_user(
        &self,
        user_id: Uuid,
        now: SystemTime,
    ) -> Result<Vec<Session>, StoreError> {
        let mut sessions: Vec<Session> = self
            .lock()
            .iter()
            .map(|s| &s.session)
            .filter(|s| {
                s.user_id == user_id
                    && s.state == SessionState::Active
                    && s.revoked_at.is_none()
                    && s.idle_expires_at > now
                    && s.absolute_expires_at > now
            })
            .cloned()
            .collect();
        // Reversed first so that, with a stable sort, the later of two sessions created
        // at the same instant comes first.
        sessions.reverse();
        sessions.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_user(username: &str, email: &str) -> NewUser {
        NewUser {
            username: username.into(),
            email: email.into(),
            name: String::new(),
            password_hash: None,
        }
    }

    #[tokio::test]
    async fn lookups_ignore_case() {
        let store = MemoryUserStore::new();
        let user = store
            .insert(new_user("Budi", "Budi@Example.com"))
            .await
            .unwrap();

        let by_name = store.find_by_username("bUDI").await.unwrap().unwrap();
        let by_email = store
            .find_by_email("budi@example.COM")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_name.user, user);
        assert_eq!(by_email.user, user);
        assert_eq!(user.username, "Budi");
        assert!(store.find_by_username("siti").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_rejects_duplicates_ignoring_case() {
        let store = MemoryUserStore::new();
        store
            .insert(new_user("budi", "budi@example.com"))
            .await
            .unwrap();

        let same_name = store.insert(new_user("BUDI", "other@example.com")).await;
        assert!(matches!(same_name, Err(StoreError::UsernameTaken)));

        let same_email = store.insert(new_user("siti", "BUDI@example.com")).await;
        assert!(matches!(same_email, Err(StoreError::EmailTaken)));

        let both = store.insert(new_user("budi", "budi@example.com")).await;
        assert!(matches!(both, Err(StoreError::UsernameTaken)));
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn login_counters_round_trip() {
        let store = MemoryUserStore::new();
        let id = store
            .insert(new_user("budi", "budi@example.com"))
            .await
            .unwrap()
            .id;

        assert_eq!(store.record_failed_login(id).await.unwrap(), 1);
        assert_eq!(store.record_failed_login(id).await.unwrap(), 2);
        let until = SystemTime::now();
        store.set_locked_until(id, Some(until)).await.unwrap();
        assert_eq!(store.get(id).unwrap().locked_until, Some(until));

        store.record_successful_login(id).await.unwrap();
        let record = store.get(id).unwrap();
        assert_eq!(record.failed_login_count, 0);
        assert_eq!(record.locked_until, None);

        let missing = store.record_failed_login(Uuid::new_v4()).await;
        assert!(matches!(missing, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn email_verification_is_recorded_once() {
        let store = MemoryUserStore::new();
        let id = store
            .insert(new_user("budi", "budi@example.com"))
            .await
            .unwrap()
            .id;
        let first = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10);
        let second = first + std::time::Duration::from_secs(10);

        assert!(store.mark_email_verified(id, first).await.unwrap());
        assert!(!store.mark_email_verified(id, second).await.unwrap());
        assert_eq!(store.get(id).unwrap().user.email_verified_at, Some(first));
        let missing = store.mark_email_verified(Uuid::new_v4(), first).await;
        assert!(matches!(missing, Err(StoreError::NotFound)));
    }

    #[tokio::test]
    async fn password_reset_replaces_the_hash_and_clears_the_lock() {
        let store = MemoryUserStore::new();
        let id = store
            .insert(new_user("budi", "budi@example.com"))
            .await
            .unwrap()
            .id;
        store.record_failed_login(id).await.unwrap();
        store
            .set_locked_until(id, Some(SystemTime::now()))
            .await
            .unwrap();

        store.reset_password(id, "new-hash".into()).await.unwrap();
        let record = store.get(id).unwrap();
        assert_eq!(record.password_hash.as_deref(), Some("new-hash"));
        assert_eq!(record.failed_login_count, 0);
        assert_eq!(record.locked_until, None);
        let missing = store.reset_password(Uuid::new_v4(), "x".into()).await;
        assert!(matches!(missing, Err(StoreError::NotFound)));
    }
}
