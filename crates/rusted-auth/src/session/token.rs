//! Session tokens and their stored hashes.

use super::error::SessionError;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::hash::{Hash, Hasher};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// Prefix of every session token.
///
/// It is fixed so that one secret-scanner pattern covers every deployment:
/// `rusted_s_[A-Za-z0-9_-]{43}`.
pub const SESSION_TOKEN_PREFIX: &str = "rusted_s_";

/// Random bytes in a token (256 bits).
const TOKEN_BYTES: usize = 32;
/// Length of [`TOKEN_BYTES`] bytes in base64url without padding.
const ENCODED_LEN: usize = 43;

/// A session token: [`SESSION_TOKEN_PREFIX`] followed by 256 random bits in base64url
/// without padding.
///
/// The token is the client's only credential for the session. It is handed out once, by
/// [`SessionManager::create`](super::SessionManager::create) or by a login such as
/// `local::LocalAuth::login`, and cannot be recovered afterwards:
/// only its SHA-256 hash is stored.
///
/// The `Debug` output never contains the token, there is no `Display`, and the memory is
/// wiped when the value is dropped. Call [`expose`](Self::expose) to send it to the
/// client, and never log it.
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    /// A new token from the operating system's random number generator.
    pub(crate) fn generate() -> Result<Self, SessionError> {
        random_token(SESSION_TOKEN_PREFIX)
            .map(Self)
            .map_err(SessionError::Internal)
    }

    /// The token text, to put in a cookie or a response body.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The hash under which this token is stored.
    pub(crate) fn hash(&self) -> SessionTokenHash {
        SessionTokenHash::of(&self.0)
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// `prefix` followed by 256 bits from the operating system's random number generator, in
/// base64url without padding.
pub(crate) fn random_token(prefix: &str) -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
    getrandom::fill(bytes.as_mut_slice())
        .map_err(|e| format!("system random number generator failed: {e}"))?;
    let mut token = Zeroizing::new(String::with_capacity(prefix.len() + ENCODED_LEN));
    token.push_str(prefix);
    URL_SAFE_NO_PAD.encode_string(bytes.as_slice(), &mut token);
    Ok(token)
}

/// `true` when `token` is `prefix` followed by [`ENCODED_LEN`] base64url characters.
pub(crate) fn has_token_shape(token: &str, prefix: &str) -> bool {
    token.strip_prefix(prefix).is_some_and(|random| {
        random.len() == ENCODED_LEN
            && random
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

/// `true` when `token` has the shape of a session token. Says nothing about whether a
/// session exists for it.
fn is_well_formed(token: &str) -> bool {
    has_token_shape(token, SESSION_TOKEN_PREFIX)
}

/// SHA-256 hash of a session token: the only form in which a token is stored.
///
/// A [`SessionStore`](super::SessionStore) keeps it in a unique column and looks sessions
/// up by it. Comparison takes the same time whether or not the values match, and the
/// `Debug` output does not contain the hash.
#[derive(Clone, Copy)]
pub struct SessionTokenHash([u8; 32]);

impl SessionTokenHash {
    /// The hash of a token presented by a client, or `None` when the text does not have
    /// the shape of a session token (so no lookup is needed).
    pub fn of_presented(token: &str) -> Option<Self> {
        is_well_formed(token).then(|| Self::of(token))
    }

    fn of(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }

    /// Rebuild a hash from the bytes a store saved.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 hash bytes, for a store to save.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for SessionTokenHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SessionTokenHash {}

impl Hash for SessionTokenHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for SessionTokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionTokenHash(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn token_has_the_documented_format() {
        let token = SessionToken::generate().unwrap();
        let text = token.expose();
        assert_eq!(text.len(), 9 + 43);
        let random = text.strip_prefix("rusted_s_").unwrap();
        assert!(
            random
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "not base64url without padding"
        );
        // 43 characters of base64url carry exactly 256 bits.
        assert_eq!(URL_SAFE_NO_PAD.decode(random).unwrap().len(), 32);
        assert!(is_well_formed(text));
    }

    #[test]
    fn tokens_are_unique() {
        let tokens: HashSet<String> = (0..1000)
            .map(|_| SessionToken::generate().unwrap().expose().to_owned())
            .collect();
        assert_eq!(tokens.len(), 1000);

        let hashes: HashSet<SessionTokenHash> = tokens
            .iter()
            .map(|t| SessionTokenHash::of_presented(t).unwrap())
            .collect();
        assert_eq!(hashes.len(), 1000);
    }

    #[test]
    fn malformed_tokens_are_not_hashed() {
        let valid = SessionToken::generate().unwrap();
        let valid = valid.expose();
        let random = &valid[9..];

        let malformed = [
            String::new(),
            "rusted_s_".to_owned(),
            random.to_owned(),
            format!("agis_{random}"),
            format!("RUSTED_S_{random}"),
            format!("rusted_s_{}", &random[1..]),
            format!("rusted_s_{random}A"),
            format!("rusted_s_{}=", &random[1..]),
            format!("rusted_s_{}+", &random[1..]),
            format!("rusted_s_{}/", &random[1..]),
            format!(" {valid}"),
            format!("{valid}\n"),
            format!("Bearer {valid}"),
            format!("rusted_s_{}é", &random[2..]),
            "x".repeat(100_000),
        ];
        for token in &malformed {
            assert!(
                SessionTokenHash::of_presented(token).is_none(),
                "accepted {token:?}"
            );
        }
        assert!(SessionTokenHash::of_presented(valid).is_some());
    }

    #[test]
    fn hash_is_sha256_of_the_token_text() {
        let token = SessionToken::generate().unwrap();
        let expected: [u8; 32] = Sha256::digest(token.expose().as_bytes()).into();
        assert_eq!(token.hash().as_bytes(), &expected);
        assert_eq!(
            SessionTokenHash::of_presented(token.expose()).unwrap(),
            token.hash()
        );
        assert_eq!(SessionTokenHash::from_bytes(expected), token.hash());
        assert_ne!(SessionTokenHash::from_bytes([0; 32]), token.hash());
    }

    #[test]
    fn debug_output_never_shows_the_token_or_its_hash() {
        let token = SessionToken::generate().unwrap();
        let random = &token.expose()[9..];
        let debug = format!("{token:?} {:?}", token.hash());
        assert!(!debug.contains(random), "{debug}");
        assert!(!debug.contains("rusted_s_"), "{debug}");
        assert_eq!(
            debug,
            "SessionToken(<redacted>) SessionTokenHash(<redacted>)"
        );
    }
}
