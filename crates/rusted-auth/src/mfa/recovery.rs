//! Single-use recovery codes.

use crate::encryption::Keyring;
use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Most recovery codes per set.
pub const MAX_RECOVERY_CODES: usize = 32;
/// Fewest digits per recovery code.
pub const MIN_RECOVERY_CODE_DIGITS: u32 = 6;
/// Most digits per recovery code.
pub const MAX_RECOVERY_CODE_DIGITS: u32 = 12;

/// Associated data of a recovery code's keyed hash: the purpose and the account.
fn context(user_id: Uuid) -> Vec<u8> {
    let mut context = b"mfa_recovery_codes.code_hash\0".to_vec();
    context.extend_from_slice(user_id.as_bytes());
    context
}

/// One recovery code, as shown to the user: a string of digits, such as `482019` with
/// the default length.
///
/// When a code is entered, spaces and hyphens are ignored. The `Debug` output never
/// contains the code, and the memory is wiped when the value is dropped.
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    /// The code, to show to the user once.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

/// A new set of recovery codes, shown to the user once.
///
/// Only keyed hashes of the codes are stored, so they cannot be shown again; generating
/// a new set replaces all earlier codes. The codes of one set are all different. The
/// `Debug` output shows how many codes there are, never the codes.
pub struct RecoveryCodes(Vec<RecoveryCode>);

impl RecoveryCodes {
    /// `count` distinct, uniformly random codes of `digits` digits.
    pub(crate) fn generate(count: usize, digits: u32) -> Result<Self, getrandom::Error> {
        let modulus = 10u64.pow(digits);
        // The largest multiple of `modulus` that fits, so that the remainder is uniform.
        let limit = u64::MAX - u64::MAX % modulus;
        let mut seen = HashSet::with_capacity(count);
        let mut codes = Vec::with_capacity(count);
        while codes.len() < count {
            let mut bytes = Zeroizing::new([0u8; 8]);
            getrandom::fill(bytes.as_mut_slice())?;
            let value = u64::from_le_bytes(*bytes);
            if value >= limit {
                continue;
            }
            let number = value % modulus;
            if !seen.insert(number) {
                continue;
            }
            codes.push(RecoveryCode(Zeroizing::new(format!(
                "{number:0width$}",
                width = digits as usize
            ))));
        }
        Ok(Self(codes))
    }

    /// The codes.
    pub fn codes(&self) -> &[RecoveryCode] {
        &self.0
    }

    /// The codes as text, in order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(RecoveryCode::expose)
    }

    /// Number of codes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The hashes to store, made with the keyring's active key.
    pub(crate) fn hashes(&self, keyring: &Keyring, user_id: Uuid) -> Vec<RecoveryCodeHash> {
        let context = context(user_id);
        self.0
            .iter()
            .map(|code| RecoveryCodeHash(keyring.keyed_hash(&context, code.0.as_bytes())))
            .collect()
    }
}

impl fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryCodes(<{} redacted>)", self.0.len())
    }
}

/// `input` without spaces and hyphens, when what remains is exactly `digits` ASCII
/// digits.
pub(crate) fn normalize(input: &str, digits: u32) -> Option<Zeroizing<String>> {
    let digits = digits as usize;
    let mut normalized = Zeroizing::new(String::with_capacity(digits));
    for c in input.chars().filter(|c| !matches!(c, ' ' | '-')) {
        if !c.is_ascii_digit() || normalized.len() == digits {
            return None;
        }
        normalized.push(c);
    }
    (normalized.len() == digits).then_some(normalized)
}

/// The hashes an entered code may be stored under: one per key of the keyring, the
/// active key first. `None` when the input does not have the shape of a recovery code,
/// so no lookup is needed.
pub(crate) fn candidate_hashes(
    keyring: &Keyring,
    user_id: Uuid,
    input: &str,
    digits: u32,
) -> Option<Vec<RecoveryCodeHash>> {
    let normalized = normalize(input, digits)?;
    Some(
        keyring
            .keyed_hashes(&context(user_id), normalized.as_bytes())
            .into_iter()
            .map(RecoveryCodeHash)
            .collect(),
    )
}

/// Keyed hash of a recovery code: the only form in which a code is stored.
///
/// HMAC-SHA-256 under a key derived from a [`Keyring`] key, bound to the account.
/// Recovery codes are short, so a plain hash could be reversed by trying every code;
/// without the key, a copy of the database does not reveal them. Removing a key from
/// the keyring therefore voids the recovery codes hashed under it.
///
/// Comparison takes the same time whether or not the values match, and the `Debug`
/// output does not contain the hash.
#[derive(Clone, Copy)]
pub struct RecoveryCodeHash([u8; 32]);

impl RecoveryCodeHash {
    /// Rebuild a hash from the bytes a store saved.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 hash bytes, for a store to save.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for RecoveryCodeHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for RecoveryCodeHash {}

impl Hash for RecoveryCodeHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for RecoveryCodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryCodeHash(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::EncryptionKey;

    fn keyring() -> Keyring {
        Keyring::new("k1", EncryptionKey::from_bytes([1; 32])).unwrap()
    }

    #[test]
    fn codes_are_distinct_digit_strings() {
        let codes = RecoveryCodes::generate(32, 6).unwrap();
        assert_eq!(codes.len(), 32);
        let unique: HashSet<&str> = codes.iter().collect();
        assert_eq!(unique.len(), 32);
        for code in codes.iter() {
            assert_eq!(code.len(), 6, "{code}");
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "{code}");
        }
        let long = RecoveryCodes::generate(3, MAX_RECOVERY_CODE_DIGITS).unwrap();
        assert!(long.iter().all(|c| c.len() == 12));
    }

    #[test]
    fn entered_codes_are_normalized() {
        let norm = |s: &str| normalize(s, 6).map(|n| n.as_str().to_owned());
        assert_eq!(norm("482019").as_deref(), Some("482019"));
        assert_eq!(norm(" 482-019 ").as_deref(), Some("482019"));
        assert_eq!(norm("482 019").as_deref(), Some("482019"));
        for bad in ["", "48201", "4820190", "48201a", "\u{0664}82019", "482_019"] {
            assert!(norm(bad).is_none(), "{bad:?}");
        }
        assert!(norm(&"1".repeat(10_000)).is_none());
    }

    #[test]
    fn hashes_are_keyed_bound_to_the_account_and_follow_rotation() {
        let user = Uuid::new_v4();
        let codes = RecoveryCodes::generate(1, 6).unwrap();
        let code = codes.iter().next().unwrap();
        let stored = codes.hashes(&keyring(), user)[0];

        assert_eq!(
            candidate_hashes(&keyring(), user, code, 6).unwrap(),
            [stored]
        );
        assert!(candidate_hashes(&keyring(), user, "12345", 6).is_none());
        // Another account or another key gives another hash.
        let other_user = candidate_hashes(&keyring(), Uuid::new_v4(), code, 6).unwrap();
        assert_ne!(other_user[0], stored);
        let other_key = Keyring::new("k1", EncryptionKey::from_bytes([2; 32])).unwrap();
        assert_ne!(
            candidate_hashes(&other_key, user, code, 6).unwrap()[0],
            stored
        );
        // Not a plain hash of the code.
        use sha2::{Digest as _, Sha256};
        let plain: [u8; 32] = Sha256::digest(code.as_bytes()).into();
        assert_ne!(stored.as_bytes(), &plain);

        // After a rotation the old key's hash is still a candidate, after the active one.
        let rotated = keyring()
            .with_key("k2", EncryptionKey::from_bytes([2; 32]))
            .unwrap()
            .activate("k2")
            .unwrap();
        let candidates = candidate_hashes(&rotated, user, code, 6).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_ne!(candidates[0], stored);
        assert_eq!(candidates[1], stored);
        assert_eq!(RecoveryCodeHash::from_bytes(*stored.as_bytes()), stored);
    }

    #[test]
    fn debug_output_never_shows_codes_or_hashes() {
        let codes = RecoveryCodes::generate(2, 8).unwrap();
        let hashes = codes.hashes(&keyring(), Uuid::nil());
        let debug = format!("{codes:?} {:?} {hashes:?}", codes.codes()[0]);
        assert_eq!(
            debug,
            "RecoveryCodes(<2 redacted>) RecoveryCode(<redacted>) \
             [RecoveryCodeHash(<redacted>), RecoveryCodeHash(<redacted>)]"
        );
    }
}
