use super::recovery::RecoveryCodeHash;
use super::store::{MfaStore, TotpRecord};
use crate::session::StoreError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;
use uuid::Uuid;

/// An in-memory [`MfaStore`] for tests and examples.
///
/// Everything is lost when the last clone is dropped. Clones share the same data.
#[derive(Debug, Clone, Default)]
pub struct MemoryMfaStore {
    data: Arc<Mutex<Data>>,
}

#[derive(Debug, Default)]
struct Data {
    totp: HashMap<Uuid, TotpRecord>,
    recovery: HashMap<Uuid, Vec<StoredCode>>,
}

#[derive(Debug, Clone)]
struct StoredCode {
    hash: RecoveryCodeHash,
    used_at: Option<SystemTime>,
}

impl MemoryMfaStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The stored TOTP record of an account, if any.
    pub fn totp(&self, user_id: Uuid) -> Option<TotpRecord> {
        self.lock().totp.get(&user_id).cloned()
    }

    /// Number of recovery codes stored for an account, used or not.
    pub fn recovery_code_count(&self, user_id: Uuid) -> usize {
        self.lock().recovery.get(&user_id).map_or(0, Vec::len)
    }

    fn lock(&self) -> MutexGuard<'_, Data> {
        self.data.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn fresh(codes: Vec<RecoveryCodeHash>) -> Vec<StoredCode> {
    codes
        .into_iter()
        .map(|hash| StoredCode {
            hash,
            used_at: None,
        })
        .collect()
}

impl MfaStore for MemoryMfaStore {
    async fn find_totp(&self, user_id: Uuid) -> Result<Option<TotpRecord>, StoreError> {
        Ok(self.totp(user_id))
    }

    async fn save_unconfirmed_totp(
        &self,
        user_id: Uuid,
        secret_enc: Vec<u8>,
    ) -> Result<bool, StoreError> {
        let mut data = self.lock();
        if data
            .totp
            .get(&user_id)
            .is_some_and(TotpRecord::is_confirmed)
        {
            return Ok(false);
        }
        data.totp
            .insert(user_id, TotpRecord::new(user_id, secret_enc, None, None));
        Ok(true)
    }

    async fn confirm_totp(
        &self,
        user_id: Uuid,
        secret_enc: &[u8],
        used_step: u64,
        at: SystemTime,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, StoreError> {
        let mut data = self.lock();
        let Some(record) = data.totp.get_mut(&user_id) else {
            return Ok(false);
        };
        if record.is_confirmed() || record.secret_enc != secret_enc {
            return Ok(false);
        }
        record.confirmed_at = Some(at);
        record.last_used_step = Some(used_step);
        data.recovery.insert(user_id, fresh(recovery_codes));
        Ok(true)
    }

    async fn record_totp_step(&self, user_id: Uuid, step: u64) -> Result<bool, StoreError> {
        let mut data = self.lock();
        match data.totp.get_mut(&user_id) {
            Some(record)
                if record.is_confirmed() && record.last_used_step.is_none_or(|s| s < step) =>
            {
                record.last_used_step = Some(step);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn replace_totp_secret(
        &self,
        user_id: Uuid,
        current: &[u8],
        new: Vec<u8>,
    ) -> Result<bool, StoreError> {
        let mut data = self.lock();
        match data.totp.get_mut(&user_id) {
            Some(record) if record.secret_enc == current => {
                record.secret_enc = new;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn delete_totp(&self, user_id: Uuid) -> Result<bool, StoreError> {
        let mut data = self.lock();
        data.recovery.remove(&user_id);
        Ok(data.totp.remove(&user_id).is_some())
    }

    async fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        recovery_codes: Vec<RecoveryCodeHash>,
    ) -> Result<bool, StoreError> {
        let mut data = self.lock();
        if !data
            .totp
            .get(&user_id)
            .is_some_and(TotpRecord::is_confirmed)
        {
            return Ok(false);
        }
        data.recovery.insert(user_id, fresh(recovery_codes));
        Ok(true)
    }

    async fn find_unused_recovery_code(
        &self,
        user_id: Uuid,
        candidates: &[RecoveryCodeHash],
    ) -> Result<Option<RecoveryCodeHash>, StoreError> {
        let data = self.lock();
        let Some(codes) = data.recovery.get(&user_id) else {
            return Ok(None);
        };
        Ok(candidates.iter().copied().find(|candidate| {
            codes
                .iter()
                .any(|c| c.used_at.is_none() && c.hash == *candidate)
        }))
    }

    async fn use_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &RecoveryCodeHash,
        at: SystemTime,
    ) -> Result<bool, StoreError> {
        let mut data = self.lock();
        let Some(code) = data.recovery.get_mut(&user_id).and_then(|codes| {
            codes
                .iter_mut()
                .find(|c| c.used_at.is_none() && c.hash == *code_hash)
        }) else {
            return Ok(false);
        };
        code.used_at = Some(at);
        Ok(true)
    }

    async fn count_unused_recovery_codes(&self, user_id: Uuid) -> Result<usize, StoreError> {
        Ok(self.lock().recovery.get(&user_id).map_or(0, |codes| {
            codes.iter().filter(|c| c.used_at.is_none()).count()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> RecoveryCodeHash {
        RecoveryCodeHash::from_bytes([byte; 32])
    }

    #[tokio::test]
    async fn confirmed_records_are_not_replaced_by_a_new_setup() {
        let store = MemoryMfaStore::new();
        let id = Uuid::new_v4();
        assert!(store.save_unconfirmed_totp(id, vec![1]).await.unwrap());
        assert!(store.save_unconfirmed_totp(id, vec![2]).await.unwrap());
        // The setup was restarted, so confirming the first secret fails.
        let now = SystemTime::now();
        assert!(!store.confirm_totp(id, &[1], 5, now, vec![]).await.unwrap());
        assert!(
            store
                .confirm_totp(id, &[2], 5, now, vec![hash(1)])
                .await
                .unwrap()
        );
        assert!(!store.confirm_totp(id, &[2], 6, now, vec![]).await.unwrap());
        assert!(!store.save_unconfirmed_totp(id, vec![3]).await.unwrap());
        let record = store.totp(id).unwrap();
        assert_eq!(record.secret_enc, [2]);
        assert_eq!(record.last_used_step, Some(5));
    }

    #[tokio::test]
    async fn steps_only_move_forward_and_codes_are_used_once() {
        let store = MemoryMfaStore::new();
        let id = Uuid::new_v4();
        store.save_unconfirmed_totp(id, vec![1]).await.unwrap();
        assert!(!store.record_totp_step(id, 9).await.unwrap(), "unconfirmed");
        let now = SystemTime::now();
        store
            .confirm_totp(id, &[1], 5, now, vec![hash(1), hash(2)])
            .await
            .unwrap();
        assert!(!store.record_totp_step(id, 5).await.unwrap());
        assert!(!store.record_totp_step(id, 4).await.unwrap());
        assert!(store.record_totp_step(id, 6).await.unwrap());

        assert_eq!(store.count_unused_recovery_codes(id).await.unwrap(), 2);
        let found = store
            .find_unused_recovery_code(id, &[hash(9), hash(1)])
            .await
            .unwrap();
        assert_eq!(found, Some(hash(1)));
        assert_eq!(
            store.count_unused_recovery_codes(id).await.unwrap(),
            2,
            "only looked up"
        );
        assert!(store.use_recovery_code(id, &hash(1), now).await.unwrap());
        assert_eq!(
            store
                .find_unused_recovery_code(id, &[hash(1)])
                .await
                .unwrap(),
            None
        );
        assert!(!store.use_recovery_code(id, &hash(1), now).await.unwrap());
        assert!(!store.use_recovery_code(id, &hash(3), now).await.unwrap());
        assert!(
            !store
                .use_recovery_code(Uuid::new_v4(), &hash(2), now)
                .await
                .unwrap()
        );
        assert_eq!(store.count_unused_recovery_codes(id).await.unwrap(), 1);

        assert!(
            store
                .replace_recovery_codes(id, vec![hash(7)])
                .await
                .unwrap()
        );
        assert!(!store.use_recovery_code(id, &hash(2), now).await.unwrap());
        assert_eq!(store.recovery_code_count(id), 1);

        assert!(store.delete_totp(id).await.unwrap());
        assert!(!store.delete_totp(id).await.unwrap());
        assert_eq!(store.recovery_code_count(id), 0);
        assert!(
            !store
                .replace_recovery_codes(id, vec![hash(8)])
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn secrets_are_replaced_only_when_unchanged() {
        let store = MemoryMfaStore::new();
        let id = Uuid::new_v4();
        store.save_unconfirmed_totp(id, vec![1]).await.unwrap();
        assert!(!store.replace_totp_secret(id, &[9], vec![2]).await.unwrap());
        assert!(store.replace_totp_secret(id, &[1], vec![2]).await.unwrap());
        assert_eq!(store.totp(id).unwrap().secret_enc, [2]);
    }
}
