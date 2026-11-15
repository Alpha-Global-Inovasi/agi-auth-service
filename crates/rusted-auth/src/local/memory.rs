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
}
