//! The keyring and the stored ciphertext format.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Length of an [`EncryptionKey`] in bytes (256 bits).
pub const KEY_BYTES: usize = 32;

/// Longest key identifier, in characters.
pub const MAX_KEY_ID_CHARS: usize = 32;

/// First byte of every ciphertext. Changes if the format ever does.
const FORMAT_VERSION: u8 = 1;
/// XChaCha20-Poly1305 nonce length.
const NONCE_BYTES: usize = 24;
/// Poly1305 tag length.
const TAG_BYTES: usize = 16;
/// Separates the associated data of this crate from any other use of the same key.
const AAD_DOMAIN: &[u8] = b"rusted-auth encryption v1\0";
/// Input from which each key's hashing key is derived, so that hashing and encryption
/// never use the same key.
const HASH_KEY_LABEL: &[u8] = b"rusted-auth keyed hash v1";

/// Errors from building a [`Keyring`], encrypting or decrypting.
///
/// None of them contain key material or plaintext.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncryptionError {
    /// A key identifier is empty, longer than [`MAX_KEY_ID_CHARS`], or contains other
    /// characters than ASCII letters, digits, `.`, `_` and `-`.
    #[error("invalid encryption key identifier")]
    InvalidKeyId,

    /// A key is not [`KEY_BYTES`] bytes, or not valid base64.
    #[error("invalid encryption key")]
    InvalidKey,

    /// Two keys in the keyring have the same identifier.
    #[error("duplicate encryption key identifier")]
    DuplicateKeyId,

    /// The ciphertext names a key that is not in the keyring, or the key to activate is
    /// not in it.
    #[error("encryption key {0:?} is not in the keyring")]
    UnknownKeyId(String),

    /// The input is not a ciphertext made by [`Keyring::encrypt`].
    #[error("malformed ciphertext")]
    Malformed,

    /// The ciphertext was changed, belongs to another context, or was made with another
    /// key of the same identifier.
    #[error("ciphertext failed authentication")]
    Decryption,

    /// The system random number generator failed.
    #[error("system random number generator failed: {0}")]
    Random(String),
}

/// A 256-bit key for [`Keyring`].
///
/// The `Debug` output never contains the key, and the memory is wiped when the value is
/// dropped.
#[derive(Clone)]
pub struct EncryptionKey(Zeroizing<[u8; KEY_BYTES]>);

impl EncryptionKey {
    /// A key from its raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A key from standard base64 with padding, as printed by `openssl rand -base64 32`.
    /// Surrounding whitespace is ignored.
    pub fn from_base64(text: &str) -> Result<Self, EncryptionError> {
        let decoded = Zeroizing::new(
            STANDARD
                .decode(text.trim())
                .map_err(|_| EncryptionError::InvalidKey)?,
        );
        let bytes: [u8; KEY_BYTES] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| EncryptionError::InvalidKey)?;
        Ok(Self::from_bytes(bytes))
    }

    /// A new key from the operating system's random number generator, for example for a
    /// command that prints a fresh key with [`to_base64`](Self::to_base64).
    pub fn generate() -> Result<Self, EncryptionError> {
        let mut bytes = Zeroizing::new([0u8; KEY_BYTES]);
        getrandom::fill(bytes.as_mut_slice())
            .map_err(|e| EncryptionError::Random(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// The key in standard base64, the form [`from_base64`](Self::from_base64) reads.
    /// Treat the result as a secret.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0.as_slice()))
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptionKey(<redacted>)")
    }
}

/// `true` when `id` can name a key: 1 to [`MAX_KEY_ID_CHARS`] ASCII letters, digits,
/// `.`, `_` or `-`.
pub fn is_valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_KEY_ID_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Encryption keys with identifiers: one active key encrypts, every key decrypts.
///
/// Built once at startup and cheap to share by reference or in an `Arc`. The `Debug`
/// output lists the key identifiers, never the keys. See the
/// [module documentation](crate::encryption) for rotation.
///
/// # Ciphertext format
///
/// `[1] [n] [key id: n bytes] [nonce: 24 bytes] [ciphertext and 16-byte tag]`, where the
/// first byte is the format version. The header and the caller's `context` are
/// authenticated as associated data, so neither can be changed without decryption
/// failing.
///
/// # Keyed hashes
///
/// Each key also yields a separate hashing key (HMAC-SHA-256 of a fixed label), used
/// inside this crate for values that are short enough to guess from a plain hash, such
/// as recovery codes. A value hashed under a key can no longer be matched once that key
/// is removed from the keyring.
pub struct Keyring {
    active: usize,
    keys: Vec<(String, XChaCha20Poly1305)>,
    /// Hashing key of each entry of `keys`, at the same index.
    hash_keys: Vec<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("active", &self.active_key_id())
            .field("keys", &self.key_ids().collect::<Vec<_>>())
            .finish()
    }
}

impl Keyring {
    /// A keyring with one key, which is active.
    pub fn new(id: &str, key: EncryptionKey) -> Result<Self, EncryptionError> {
        let mut keyring = Self {
            active: 0,
            keys: Vec::with_capacity(2),
            hash_keys: Vec::with_capacity(2),
        };
        keyring.push(id, key)?;
        Ok(keyring)
    }

    /// Add a key that decrypts but does not encrypt, typically the previous key during a
    /// rotation. [`activate`](Self::activate) makes it the one that encrypts.
    pub fn with_key(mut self, id: &str, key: EncryptionKey) -> Result<Self, EncryptionError> {
        self.push(id, key)?;
        Ok(self)
    }

    /// Make the key `id` the one that encrypts.
    pub fn activate(mut self, id: &str) -> Result<Self, EncryptionError> {
        self.active = self
            .position(id)
            .ok_or_else(|| EncryptionError::UnknownKeyId(id.to_owned()))?;
        Ok(self)
    }

    /// Read keys from `id:base64key` pairs separated by commas. The first pair is the
    /// active key. Whitespace around pairs and parts is ignored.
    ///
    /// This parses a string the application read itself, for example from an
    /// `AUTH_ENCRYPTION_KEYS` environment variable; the library does not read the
    /// environment.
    ///
    /// ```rust
    /// use rusted_auth::encryption::Keyring;
    ///
    /// let keys = "2026-06:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=, \
    ///             2026-01:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=";
    /// let keyring = Keyring::parse(keys).unwrap();
    /// assert_eq!(keyring.active_key_id(), "2026-06");
    /// ```
    pub fn parse(spec: &str) -> Result<Self, EncryptionError> {
        let mut keyring: Option<Self> = None;
        for pair in spec.split(',').map(str::trim) {
            let (id, key) = pair.split_once(':').ok_or(EncryptionError::InvalidKey)?;
            let key = EncryptionKey::from_base64(key)?;
            keyring = Some(match keyring {
                None => Self::new(id.trim(), key)?,
                Some(keyring) => keyring.with_key(id.trim(), key)?,
            });
        }
        keyring.ok_or(EncryptionError::InvalidKey)
    }

    /// Identifier of the key that encrypts.
    pub fn active_key_id(&self) -> &str {
        &self.keys[self.active].0
    }

    /// Identifiers of all keys, active or not, in the order they were added.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|(id, _)| id.as_str())
    }

    /// Encrypt `plaintext` with the active key.
    ///
    /// `context` is authenticated but not stored: decryption needs the same value. Pass
    /// what the ciphertext belongs to, such as the purpose and the record's identifier,
    /// so that a ciphertext copied to another record does not decrypt there.
    pub fn encrypt(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let (id, cipher) = &self.keys[self.active];
        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|e| EncryptionError::Random(e.to_string()))?;

        let mut out = header(id);
        let aad = associated_data(&out, context);
        let sealed = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| EncryptionError::Malformed)?;
        out.reserve(NONCE_BYTES + sealed.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Decrypt a ciphertext made by [`encrypt`](Self::encrypt) with any key of the
    /// keyring and the same `context`.
    ///
    /// Fails with [`EncryptionError::UnknownKeyId`] when the key is not in the keyring,
    /// and with [`EncryptionError::Decryption`] when the ciphertext, its header or the
    /// context differ from what was encrypted.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EncryptionError> {
        let parsed = Parsed::from(ciphertext)?;
        let index = self
            .position(parsed.key_id)
            .ok_or_else(|| EncryptionError::UnknownKeyId(parsed.key_id.to_owned()))?;
        let aad = associated_data(parsed.header, context);
        let nonce: [u8; NONCE_BYTES] = parsed
            .nonce
            .try_into()
            .map_err(|_| EncryptionError::Malformed)?;
        self.keys[index]
            .1
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: parsed.sealed,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| EncryptionError::Decryption)
    }

    /// Identifier of the key a ciphertext was made with. Checks only the header, not
    /// that the ciphertext decrypts.
    pub fn key_id_of<'a>(&self, ciphertext: &'a [u8]) -> Result<&'a str, EncryptionError> {
        Ok(Parsed::from(ciphertext)?.key_id)
    }

    /// `true` when a ciphertext was made with another key than the active one, so it
    /// should be encrypted again before that key is retired. `false` for input that is
    /// not a ciphertext.
    pub fn needs_reencryption(&self, ciphertext: &[u8]) -> bool {
        self.key_id_of(ciphertext)
            .is_ok_and(|id| id != self.active_key_id())
    }

    /// Keyed hash of `data` with the active key's hashing key. `context` separates
    /// purposes and records, as for [`encrypt`](Self::encrypt).
    #[cfg_attr(not(feature = "mfa"), allow(dead_code))]
    pub(crate) fn keyed_hash(&self, context: &[u8], data: &[u8]) -> [u8; 32] {
        keyed_hash(&self.hash_keys[self.active], context, data)
    }

    /// Keyed hashes of `data` under every key, the active key first, then the others in
    /// the order they were added: what to look a stored hash up by.
    #[cfg_attr(not(feature = "mfa"), allow(dead_code))]
    pub(crate) fn keyed_hashes(&self, context: &[u8], data: &[u8]) -> Vec<[u8; 32]> {
        std::iter::once(self.active)
            .chain((0..self.keys.len()).filter(|&index| index != self.active))
            .map(|index| keyed_hash(&self.hash_keys[index], context, data))
            .collect()
    }

    fn push(&mut self, id: &str, key: EncryptionKey) -> Result<(), EncryptionError> {
        if !is_valid_key_id(id) {
            return Err(EncryptionError::InvalidKeyId);
        }
        if self.position(id).is_some() {
            return Err(EncryptionError::DuplicateKeyId);
        }
        let cipher = XChaCha20Poly1305::new(&Key::from(*key.0));
        let mut derive = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.0.as_slice())
            .map_err(|_| EncryptionError::InvalidKey)?;
        derive.update(HASH_KEY_LABEL);
        let hash_key = Zeroizing::new(<[u8; 32]>::from(derive.finalize().into_bytes()));
        self.keys.push((id.to_owned(), cipher));
        self.hash_keys.push(hash_key);
        Ok(())
    }

    fn position(&self, id: &str) -> Option<usize> {
        self.keys.iter().position(|(known, _)| known == id)
    }
}

fn keyed_hash(hash_key: &[u8; 32], context: &[u8], data: &[u8]) -> [u8; 32] {
    // A 32-byte key is always accepted.
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(hash_key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    // The length prefix keeps `context` and `data` from running into each other.
    mac.update(&(context.len() as u64).to_be_bytes());
    mac.update(context);
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn header(key_id: &str) -> Vec<u8> {
    let mut header = Vec::with_capacity(2 + key_id.len() + NONCE_BYTES + TAG_BYTES + 64);
    header.push(FORMAT_VERSION);
    // At most MAX_KEY_ID_CHARS ASCII bytes, checked when the key was added.
    header.push(key_id.len() as u8);
    header.extend_from_slice(key_id.as_bytes());
    header
}

fn associated_data(header: &[u8], context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + header.len() + context.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(header);
    aad.extend_from_slice(context);
    aad
}

/// The parts of a ciphertext.
struct Parsed<'a> {
    header: &'a [u8],
    key_id: &'a str,
    nonce: &'a [u8],
    sealed: &'a [u8],
}

impl<'a> Parsed<'a> {
    fn from(ciphertext: &'a [u8]) -> Result<Self, EncryptionError> {
        let [version, id_len, rest @ ..] = ciphertext else {
            return Err(EncryptionError::Malformed);
        };
        if *version != FORMAT_VERSION {
            return Err(EncryptionError::Malformed);
        }
        let id_len = usize::from(*id_len);
        if rest.len() < id_len + NONCE_BYTES + TAG_BYTES {
            return Err(EncryptionError::Malformed);
        }
        let (id, rest) = rest.split_at(id_len);
        let key_id = std::str::from_utf8(id).map_err(|_| EncryptionError::Malformed)?;
        if !is_valid_key_id(key_id) {
            return Err(EncryptionError::Malformed);
        }
        let (nonce, sealed) = rest.split_at(NONCE_BYTES);
        Ok(Self {
            header: &ciphertext[..2 + id_len],
            key_id,
            nonce,
            sealed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> EncryptionKey {
        EncryptionKey::from_bytes([byte; KEY_BYTES])
    }

    #[test]
    fn keyed_hashes_depend_on_key_context_and_data_and_list_the_active_key_first() {
        let one = Keyring::new("k1", key(1)).unwrap();
        let h = one.keyed_hash(b"ctx", b"482019");
        assert_eq!(h, one.keyed_hash(b"ctx", b"482019"));
        assert_ne!(h, one.keyed_hash(b"ctx", b"482018"));
        assert_ne!(h, one.keyed_hash(b"ctx2", b"482019"));
        // The length prefix keeps context and data apart.
        assert_ne!(one.keyed_hash(b"ab", b"c"), one.keyed_hash(b"a", b"bc"));
        assert_ne!(
            h,
            Keyring::new("k1", key(2))
                .unwrap()
                .keyed_hash(b"ctx", b"482019")
        );
        assert_eq!(one.keyed_hashes(b"ctx", b"482019"), [h]);

        let rotated = Keyring::new("k1", key(1))
            .unwrap()
            .with_key("k2", key(2))
            .unwrap()
            .activate("k2")
            .unwrap();
        let all = rotated.keyed_hashes(b"ctx", b"482019");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], rotated.keyed_hash(b"ctx", b"482019"));
        assert_eq!(all[1], h);
    }

    #[test]
    fn round_trip_with_a_fresh_nonce_each_time() {
        let keyring = Keyring::new("k1", key(1)).unwrap();
        let a = keyring.encrypt(b"totp secret", b"ctx").unwrap();
        let b = keyring.encrypt(b"totp secret", b"ctx").unwrap();
        assert_ne!(a, b, "the nonce must be random per encryption");
        assert_eq!(a.len(), 2 + 2 + NONCE_BYTES + 11 + TAG_BYTES);
        assert_eq!(&keyring.decrypt(&a, b"ctx").unwrap()[..], b"totp secret");
        assert_eq!(&keyring.decrypt(&b, b"ctx").unwrap()[..], b"totp secret");
        assert!(!a.windows(11).any(|w| w == b"totp secret"));
    }

    #[test]
    fn old_keys_decrypt_after_rotation_and_new_data_uses_the_active_key() {
        let before = Keyring::new("old", key(1)).unwrap();
        let stored = before.encrypt(b"secret", b"ctx").unwrap();
        assert!(!before.needs_reencryption(&stored));

        let after = Keyring::new("old", key(1))
            .unwrap()
            .with_key("new", key(2))
            .unwrap()
            .activate("new")
            .unwrap();
        assert_eq!(after.active_key_id(), "new");
        assert_eq!(after.key_ids().collect::<Vec<_>>(), ["old", "new"]);
        assert_eq!(&after.decrypt(&stored, b"ctx").unwrap()[..], b"secret");
        assert!(after.needs_reencryption(&stored));

        let fresh = after.encrypt(b"secret", b"ctx").unwrap();
        assert_eq!(after.key_id_of(&fresh).unwrap(), "new");
        assert!(!after.needs_reencryption(&fresh));

        // Once the old key is removed, its ciphertexts cannot be read.
        let retired = Keyring::new("new", key(2)).unwrap();
        assert_eq!(
            retired.decrypt(&stored, b"ctx").unwrap_err(),
            EncryptionError::UnknownKeyId("old".into())
        );
        assert_eq!(&retired.decrypt(&fresh, b"ctx").unwrap()[..], b"secret");
    }

    #[test]
    fn tampered_ciphertexts_are_rejected() {
        let keyring = Keyring::new("k1", key(1)).unwrap();
        let stored = keyring.encrypt(b"secret", b"ctx").unwrap();

        // Every single bit flip after the header fails authentication.
        for index in 4..stored.len() {
            let mut changed = stored.clone();
            changed[index] ^= 0x01;
            assert_eq!(
                keyring.decrypt(&changed, b"ctx").unwrap_err(),
                EncryptionError::Decryption,
                "byte {index}"
            );
        }
        // Other context, truncated, extended.
        assert_eq!(
            keyring.decrypt(&stored, b"other").unwrap_err(),
            EncryptionError::Decryption
        );
        let mut longer = stored.clone();
        longer.push(0);
        assert_eq!(
            keyring.decrypt(&longer, b"ctx").unwrap_err(),
            EncryptionError::Decryption
        );
        assert_eq!(
            keyring
                .decrypt(&stored[..stored.len() - 1], b"ctx")
                .unwrap_err(),
            EncryptionError::Decryption
        );
        // A key with the same identifier but other bytes.
        let impostor = Keyring::new("k1", key(9)).unwrap();
        assert_eq!(
            impostor.decrypt(&stored, b"ctx").unwrap_err(),
            EncryptionError::Decryption
        );
        // A header pointing at another key of the keyring.
        let both = Keyring::new("k1", key(1))
            .unwrap()
            .with_key("k2", key(2))
            .unwrap();
        let mut relabelled = stored.clone();
        relabelled[3] = b'2';
        assert_eq!(
            both.decrypt(&relabelled, b"ctx").unwrap_err(),
            EncryptionError::Decryption
        );
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        let keyring = Keyring::new("k1", key(1)).unwrap();
        let stored = keyring.encrypt(b"", b"").unwrap();
        for bad in [
            &[][..],
            &[1],
            &[2, 2, b'k', b'1'],
            &stored[..stored.len() - TAG_BYTES - 1],
            &[1, 0, 0, 0],
            &[1, 2, 0xff, 0xfe],
        ] {
            assert!(keyring.decrypt(bad, b"").is_err(), "{bad:?}");
        }
        let mut wrong_version = stored.clone();
        wrong_version[0] = 2;
        assert_eq!(
            keyring.decrypt(&wrong_version, b"").unwrap_err(),
            EncryptionError::Malformed
        );
        assert!(!keyring.needs_reencryption(b"junk"));
    }

    #[test]
    fn key_identifiers_and_keys_are_validated() {
        assert_eq!(
            Keyring::new("", key(1)).unwrap_err(),
            EncryptionError::InvalidKeyId
        );
        assert_eq!(
            Keyring::new("has space", key(1)).unwrap_err(),
            EncryptionError::InvalidKeyId
        );
        assert_eq!(
            Keyring::new(&"x".repeat(MAX_KEY_ID_CHARS + 1), key(1)).unwrap_err(),
            EncryptionError::InvalidKeyId
        );
        assert!(Keyring::new(&"x".repeat(MAX_KEY_ID_CHARS), key(1)).is_ok());
        assert_eq!(
            Keyring::new("a", key(1))
                .unwrap()
                .with_key("a", key(2))
                .unwrap_err(),
            EncryptionError::DuplicateKeyId
        );
        assert_eq!(
            Keyring::new("a", key(1))
                .unwrap()
                .activate("b")
                .unwrap_err(),
            EncryptionError::UnknownKeyId("b".into())
        );
        assert_eq!(
            EncryptionKey::from_base64("c2hvcnQ=").unwrap_err(),
            EncryptionError::InvalidKey
        );
        assert_eq!(
            EncryptionKey::from_base64("not base64!").unwrap_err(),
            EncryptionError::InvalidKey
        );
    }

    #[test]
    fn parse_reads_pairs_with_the_first_active() {
        let k1 = key(1).to_base64();
        let k2 = key(2).to_base64();
        let keyring = Keyring::parse(&format!(" new : {} , old:{} ", *k2, *k1)).unwrap();
        assert_eq!(keyring.active_key_id(), "new");
        assert_eq!(keyring.key_ids().collect::<Vec<_>>(), ["new", "old"]);

        let old = Keyring::new("old", key(1)).unwrap();
        let stored = old.encrypt(b"x", b"").unwrap();
        assert_eq!(&keyring.decrypt(&stored, b"").unwrap()[..], b"x");

        assert!(Keyring::parse("").is_err());
        assert!(Keyring::parse("no-colon").is_err());
        assert!(Keyring::parse("a:").is_err());
        assert!(Keyring::parse(&format!("a:{},a:{}", *k1, *k2)).is_err());
        assert!(Keyring::parse(&format!("a:{},", *k1)).is_err());
    }

    #[test]
    fn debug_output_never_shows_keys() {
        let key = EncryptionKey::generate().unwrap();
        let encoded = key.to_base64();
        let keyring = Keyring::new("k1", key.clone()).unwrap();
        let debug = format!("{key:?} {keyring:?}");
        assert!(!debug.contains(encoded.as_str()), "{debug}");
        assert_eq!(
            debug,
            "EncryptionKey(<redacted>) Keyring { active: \"k1\", keys: [\"k1\"] }"
        );
    }
}
