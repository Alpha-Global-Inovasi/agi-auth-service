//! Checks that an [`MfaStore`] behaves like [`MemoryMfaStore`](super::MemoryMfaStore).
//!
//! Available with the `test-util` and `mfa` cargo features; see
//! [`session::conformance`](crate::session::conformance) for how the checks work.

use super::recovery::RecoveryCodeHash;
use super::store::MfaStore;
use crate::session::UserStore;
use crate::session::conformance::{base_time, join_all, new_account, random_bytes};
use std::time::Duration;

fn codes(n: usize) -> Vec<RecoveryCodeHash> {
    (0..n)
        .map(|_| RecoveryCodeHash::from_bytes(random_bytes()))
        .collect()
}

/// Check an [`MfaStore`] for the accounts of `users`: TOTP setup and confirmation, the
/// last used time step, re-encryption, recovery codes and deletion.
pub async fn mfa_store<U: UserStore, M: MfaStore>(users: &U, mfa: &M) {
    let budi = new_account(users, "budi").await.id;
    let siti = new_account(users, "siti").await.id;
    let at = base_time();

    // Setup, restarted once.
    assert_eq!(mfa.find_totp(budi).await.expect("find_totp"), None);
    assert!(
        mfa.save_unconfirmed_totp(budi, vec![1; 40])
            .await
            .expect("save_unconfirmed_totp")
    );
    assert!(
        mfa.save_unconfirmed_totp(budi, vec![2; 40])
            .await
            .expect("save_unconfirmed_totp replaces an unconfirmed record")
    );
    let record = mfa.find_totp(budi).await.expect("find").expect("found");
    assert_eq!(record.user_id, budi);
    assert_eq!(record.secret_enc, vec![2; 40]);
    assert_eq!(record.confirmed_at, None);
    assert_eq!(record.last_used_step, None);
    assert!(
        !mfa.record_totp_step(budi, 5)
            .await
            .expect("record_totp_step"),
        "recorded a step on an unconfirmed record"
    );
    assert!(
        !mfa.replace_recovery_codes(budi, codes(2))
            .await
            .expect("replace_recovery_codes"),
        "recovery codes without a confirmed record"
    );

    // Confirmation needs the secret that is stored now.
    let first_set = codes(3);
    assert!(
        !mfa.confirm_totp(budi, &[1; 40], 10, at, first_set.clone())
            .await
            .expect("confirm_totp"),
        "confirmed with a replaced secret"
    );
    assert_eq!(
        mfa.count_unused_recovery_codes(budi).await.expect("count"),
        0
    );
    // A step beyond the range of a signed 64-bit integer would not fit; this one does.
    let step = 1_u64 << 40;
    assert!(
        mfa.confirm_totp(budi, &[2; 40], step, at, first_set.clone())
            .await
            .expect("confirm_totp")
    );
    let record = mfa.find_totp(budi).await.expect("find").expect("found");
    assert!(record.is_confirmed());
    assert_eq!(record.confirmed_at, Some(at));
    assert_eq!(record.last_used_step, Some(step));
    assert_eq!(
        mfa.count_unused_recovery_codes(budi).await.expect("count"),
        3
    );
    assert!(
        !mfa.confirm_totp(budi, &[2; 40], step, at, codes(3))
            .await
            .expect("confirm_totp"),
        "confirmed twice"
    );
    assert!(
        !mfa.save_unconfirmed_totp(budi, vec![3; 40])
            .await
            .expect("save_unconfirmed_totp"),
        "replaced a confirmed record"
    );
    let record = mfa.find_totp(budi).await.expect("find").expect("found");
    assert_eq!(record.secret_enc, vec![2; 40]);
    assert!(record.is_confirmed());

    // Time steps only move forward.
    assert!(
        !mfa.record_totp_step(budi, step)
            .await
            .expect("record_totp_step")
    );
    assert!(
        !mfa.record_totp_step(budi, step - 1)
            .await
            .expect("record_totp_step")
    );
    assert!(
        mfa.record_totp_step(budi, step + 1)
            .await
            .expect("record_totp_step")
    );
    assert_eq!(
        mfa.find_totp(budi)
            .await
            .expect("find")
            .expect("found")
            .last_used_step,
        Some(step + 1)
    );
    assert!(
        !mfa.record_totp_step(siti, step + 2)
            .await
            .expect("record_totp_step")
    );

    // Re-encryption compares the current secret.
    assert!(
        !mfa.replace_totp_secret(budi, &[9; 40], vec![4; 41])
            .await
            .expect("replace_totp_secret")
    );
    assert!(
        mfa.replace_totp_secret(budi, &[2; 40], vec![4; 41])
            .await
            .expect("replace_totp_secret")
    );
    let record = mfa.find_totp(budi).await.expect("find").expect("found");
    assert_eq!(record.secret_enc, vec![4; 41]);
    assert_eq!(
        record.last_used_step,
        Some(step + 1),
        "re-encryption kept the step"
    );
    assert!(record.is_confirmed());

    // Recovery codes: found without being used, then used once.
    let unknown = RecoveryCodeHash::from_bytes(random_bytes());
    assert_eq!(
        mfa.find_unused_recovery_code(budi, &[unknown, first_set[1]])
            .await
            .expect("find_unused_recovery_code"),
        Some(first_set[1])
    );
    assert_eq!(
        mfa.find_unused_recovery_code(budi, &[unknown])
            .await
            .expect("find_unused_recovery_code"),
        None
    );
    assert_eq!(
        mfa.find_unused_recovery_code(budi, &[])
            .await
            .expect("find_unused_recovery_code without candidates"),
        None
    );
    assert_eq!(
        mfa.count_unused_recovery_codes(budi).await.expect("count"),
        3
    );
    let used_at = at + Duration::from_secs(5);
    assert!(
        mfa.use_recovery_code(budi, &first_set[1], used_at)
            .await
            .expect("use_recovery_code")
    );
    assert!(
        !mfa.use_recovery_code(budi, &first_set[1], used_at)
            .await
            .expect("use_recovery_code"),
        "used a recovery code twice"
    );
    assert_eq!(
        mfa.find_unused_recovery_code(budi, &[first_set[1]])
            .await
            .expect("find_unused_recovery_code"),
        None,
        "found a used recovery code"
    );
    assert_eq!(
        mfa.count_unused_recovery_codes(budi).await.expect("count"),
        2
    );
    assert!(
        !mfa.use_recovery_code(siti, &first_set[0], used_at)
            .await
            .expect("use_recovery_code"),
        "used another account's recovery code"
    );
    assert_eq!(
        mfa.find_unused_recovery_code(siti, &[first_set[0]])
            .await
            .expect("find_unused_recovery_code"),
        None,
        "found another account's recovery code"
    );

    // A new set replaces every earlier code, used or not.
    let second_set = codes(4);
    assert!(
        mfa.replace_recovery_codes(budi, second_set.clone())
            .await
            .expect("replace_recovery_codes")
    );
    assert_eq!(
        mfa.count_unused_recovery_codes(budi).await.expect("count"),
        4
    );
    assert_eq!(
        mfa.find_unused_recovery_code(budi, &[first_set[0], first_set[2]])
            .await
            .expect("find_unused_recovery_code"),
        None,
        "an old recovery code survived the replacement"
    );
    assert_eq!(
        mfa.find_unused_recovery_code(budi, &[second_set[3]])
            .await
            .expect("find_unused_recovery_code"),
        Some(second_set[3])
    );

    // Siti's setup is independent.
    assert!(
        mfa.save_unconfirmed_totp(siti, vec![7; 40])
            .await
            .expect("save_unconfirmed_totp")
    );
    assert!(
        mfa.confirm_totp(siti, &[7; 40], 1, at, codes(2))
            .await
            .expect("confirm_totp")
    );
    assert_eq!(
        mfa.count_unused_recovery_codes(siti).await.expect("count"),
        2
    );

    // Deletion removes the record and the codes.
    assert!(mfa.delete_totp(budi).await.expect("delete_totp"));
    assert_eq!(mfa.find_totp(budi).await.expect("find_totp"), None);
    assert_eq!(
        mfa.count_unused_recovery_codes(budi).await.expect("count"),
        0
    );
    assert!(!mfa.delete_totp(budi).await.expect("delete_totp"));
    assert_eq!(
        mfa.count_unused_recovery_codes(siti).await.expect("count"),
        2
    );
    assert!(mfa.find_totp(siti).await.expect("find_totp").is_some());

    // Setup can start again after deletion.
    assert!(
        mfa.save_unconfirmed_totp(budi, vec![8; 40])
            .await
            .expect("save_unconfirmed_totp")
    );
    assert_eq!(
        mfa.find_totp(budi)
            .await
            .expect("find")
            .expect("found")
            .confirmed_at,
        None
    );

    // Of concurrent uses of one time step or one recovery code, one succeeds.
    let code = RecoveryCodeHash::from_bytes(random_bytes());
    assert!(
        mfa.confirm_totp(budi, &[8; 40], 100, at, vec![code])
            .await
            .expect("confirm_totp")
    );
    let steps = join_all((0..16).map(|_| mfa.record_totp_step(budi, 101))).await;
    let accepted = steps
        .into_iter()
        .filter(|result| *result.as_ref().expect("record_totp_step"))
        .count();
    assert_eq!(accepted, 1, "concurrent uses of one time step");
    let uses = join_all((0..16).map(|_| mfa.use_recovery_code(budi, &code, at))).await;
    let accepted = uses
        .into_iter()
        .filter(|result| *result.as_ref().expect("use_recovery_code"))
        .count();
    assert_eq!(accepted, 1, "concurrent uses of one recovery code");
}

#[cfg(test)]
mod tests {
    use crate::mfa::MemoryMfaStore;
    use crate::session::MemoryUserStore;

    #[tokio::test]
    async fn memory_store_conforms() {
        super::mfa_store(&MemoryUserStore::new(), &MemoryMfaStore::new()).await;
    }
}
