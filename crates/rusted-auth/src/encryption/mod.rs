//! Encryption of secrets kept at rest, with keys that can be rotated.
//!
//! Enabled by the `encryption` cargo feature (turned on by `mfa`). Secrets that the
//! server must be able to read back, such as TOTP secrets, are stored encrypted with
//! XChaCha20-Poly1305: an authenticated cipher, so a ciphertext that was changed, cut or
//! moved to another record fails to decrypt instead of yielding garbage. Every
//! encryption draws a fresh 192-bit random nonce, which is large enough that random
//! nonces never repeat in practice.
//!
//! # Keys and rotation
//!
//! A [`Keyring`] holds one or more 256-bit keys, each with a short identifier. One of
//! them is *active* and encrypts everything new; all of them decrypt. The identifier of
//! the key is stored in front of each ciphertext, so the right key is found without
//! trying them all. To rotate:
//!
//! 1. Add a new key and make it active, keeping the old one in the keyring.
//! 2. Records are re-encrypted with the new key as they are used (the
//!    `mfa` module does this after a successful TOTP check), or by a job of yours that
//!    calls [`Keyring::decrypt`] and [`Keyring::encrypt`].
//! 3. Once no record uses the old key ([`Keyring::key_id_of`] tells which key a record
//!    uses), remove it.
//!
//! **Recovery codes of the `mfa` module are hashed, not encrypted**, under a key derived
//! from the keyring key that was active when they were made. They cannot be moved to a
//! new key: they keep working while their key is in the keyring, and stop matching,
//! without an error, once it is removed. Remove an old key only after every user whose
//! recovery codes were made under it has generated a new set
//! (`Mfa::regenerate_recovery_codes`).
//!
//! The library never reads environment variables or files: the application loads the
//! keys from wherever it keeps secrets and builds the keyring.
//! [`Keyring::parse`] reads the common `id:base64key,id:base64key` form, for example
//! from an `AUTH_ENCRYPTION_KEYS` variable the application reads itself.
//!
//! ```rust
//! use rusted_auth::encryption::{EncryptionKey, Keyring};
//!
//! # fn run() -> Result<(), rusted_auth::encryption::EncryptionError> {
//! // Normally the keys come from a secret store, for example via `Keyring::parse`.
//! let old = EncryptionKey::generate()?;
//! let new = EncryptionKey::generate()?;
//! let keyring = Keyring::new("2026-01", old)?;
//!
//! let stored = keyring.encrypt(b"secret", b"user 42")?;
//!
//! // Rotation: the new key encrypts, the old one still decrypts.
//! let keyring = keyring.with_key("2026-06", new)?.activate("2026-06")?;
//! assert_eq!(keyring.key_id_of(&stored)?, "2026-01");
//! assert_eq!(&keyring.decrypt(&stored, b"user 42")?[..], b"secret");
//! assert!(keyring.decrypt(&stored, b"user 43").is_err());
//! # Ok(())
//! # }
//! # run().unwrap();
//! ```

mod keyring;

pub use keyring::{
    EncryptionError, EncryptionKey, KEY_BYTES, Keyring, MAX_KEY_ID_CHARS, is_valid_key_id,
};
