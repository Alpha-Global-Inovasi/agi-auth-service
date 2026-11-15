//! Single-use tokens sent in email links: email verification and password reset.

use super::attempts::BoxFuture;
use super::token::{has_token_shape, random_token};
use super::user::StoreError;
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Prefix of every single-use token.
///
/// Tokens travel in links, which end up in access logs and `Referer` headers, so they
/// carry a fixed prefix that one secret-scanner pattern covers:
/// `rusted_t_[A-Za-z0-9_-]{43}`.
pub const ONE_TIME_TOKEN_PREFIX: &str = "rusted_t_";

/// What a single-use token is for. A token only works for its own purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenPurpose {
    /// Proves control of the account's email address.
    VerifyEmail,
    /// Lets the owner of the email address set a new password.
    ResetPassword,
}

impl TokenPurpose {
    /// The name to store: `verify_email` or `reset_password`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::ResetPassword => "reset_password",
        }
    }

    /// The purpose stored as `name`, or `None` for an unknown name.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "verify_email" => Some(Self::VerifyEmail),
            "reset_password" => Some(Self::ResetPassword),
            _ => None,
        }
    }
}

/// A single-use token: [`ONE_TIME_TOKEN_PREFIX`] followed by 256 random bits in
/// base64url without padding.
///
/// It is handed out once, inside an email, and only its SHA-256 hash is stored. The
/// `Debug` output never contains the token, there is no `Display`, and the memory is
/// wiped when the value is dropped. Call [`expose`](Self::expose) to put it in a link,
/// and never log it.
pub struct OneTimeToken(Zeroizing<String>);

#[cfg_attr(not(feature = "local"), allow(dead_code))]
impl OneTimeToken {
    pub(crate) fn generate() -> Result<Self, String> {
        random_token(ONE_TIME_TOKEN_PREFIX).map(Self)
    }

    /// The token text, to put in a link.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The hash under which this token is stored.
    pub(crate) fn hash(&self) -> OneTimeTokenHash {
        OneTimeTokenHash::of(&self.0)
    }
}

impl fmt::Debug for OneTimeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneTimeToken(<redacted>)")
    }
}

/// SHA-256 hash of a single-use token: the only form in which a token is stored.
///
/// Comparison takes the same time whether or not the values match, and the `Debug`
/// output does not contain the hash.
#[derive(Clone, Copy)]
pub struct OneTimeTokenHash([u8; 32]);

impl OneTimeTokenHash {
    /// The hash of a token presented by a client, or `None` when the text does not have
    /// the shape of a single-use token (so no lookup is needed).
    pub fn of_presented(token: &str) -> Option<Self> {
        has_token_shape(token, ONE_TIME_TOKEN_PREFIX).then(|| Self::of(token))
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

impl PartialEq for OneTimeTokenHash {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for OneTimeTokenHash {}

impl Hash for OneTimeTokenHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for OneTimeTokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneTimeTokenHash(<redacted>)")
    }
}

/// A token a [`OneTimeTokenStore`] is asked to save.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NewOneTimeToken {
    /// Hash of the token; unique.
    pub token_hash: OneTimeTokenHash,
    /// The account the token belongs to.
    pub user_id: Uuid,
    /// What the token is for.
    pub purpose: TokenPurpose,
    /// The email address the token was sent to. The token stops working once the
    /// account has another address.
    pub email: String,
    /// The token does not work from this time on.
    pub expires_at: SystemTime,
}

/// A token that [`OneTimeTokenStore::consume`] just used up.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConsumedToken {
    /// The account the token belongs to.
    pub user_id: Uuid,
    /// The email address the token was sent to.
    pub email: String,
}

impl ConsumedToken {
    /// A consumed token, for stores outside this crate.
    pub fn new(user_id: Uuid, email: impl Into<String>) -> Self {
        Self {
            user_id,
            email: email.into(),
        }
    }
}

/// Persistence for single-use tokens, for example a `one_time_tokens` table
/// (`token_hash` unique, `user_id`, `purpose`, `email`, `expires_at`, `used_at`).
///
/// Implement this for your database. [`MemoryOneTimeTokenStore`] is an in-memory
/// implementation for tests. Tokens must be readable from every process that serves
/// the links, so give all of them the same store.
///
/// # Contract
///
/// [`consume`](Self::consume) is one atomic step, so that a token cannot be used twice
/// by concurrent requests. In Postgres:
///
/// ```sql
/// UPDATE one_time_tokens SET used_at = $3
/// WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3
/// RETURNING user_id, email
/// ```
///
/// Used and expired rows are no longer needed; delete them from time to time.
pub trait OneTimeTokenStore: Send + Sync + 'static {
    /// Save a new token.
    fn insert(&self, token: NewOneTimeToken)
    -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Mark the token with this hash and purpose as used at `now`, if it is unused and
    /// its `expires_at` is later than `now`, and return its account and address.
    /// Returns `None`, changing nothing, otherwise.
    fn consume(
        &self,
        token_hash: &OneTimeTokenHash,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> impl Future<Output = Result<Option<ConsumedToken>, StoreError>> + Send;

    /// Mark every unused token of the account for `purpose` as used at `now`, so that
    /// none of them works any more.
    fn invalidate(
        &self,
        user_id: Uuid,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// A stored token as [`MemoryOneTimeTokenStore`] keeps it, without its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OneTimeTokenRecord {
    /// The account the token belongs to.
    pub user_id: Uuid,
    /// What the token is for.
    pub purpose: TokenPurpose,
    /// The address the token was sent to.
    pub email: String,
    /// End of validity.
    pub expires_at: SystemTime,
    /// When it was used or invalidated, if it was.
    pub used_at: Option<SystemTime>,
}

/// In-memory [`OneTimeTokenStore`] for tests and examples.
///
/// Tokens are lost when the last clone is dropped. Clones share the same tokens.
#[derive(Debug, Clone, Default)]
pub struct MemoryOneTimeTokenStore {
    tokens: Arc<Mutex<Vec<(OneTimeTokenHash, OneTimeTokenRecord)>>>,
}

impl MemoryOneTimeTokenStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The account's tokens, used or not, oldest first.
    pub fn tokens_for(&self, user_id: Uuid) -> Vec<OneTimeTokenRecord> {
        self.lock()
            .iter()
            .filter(|(_, record)| record.user_id == user_id)
            .map(|(_, record)| record.clone())
            .collect()
    }

    /// Number of tokens, including used and expired ones.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` when there are no tokens.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<(OneTimeTokenHash, OneTimeTokenRecord)>> {
        self.tokens.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl OneTimeTokenStore for MemoryOneTimeTokenStore {
    async fn insert(&self, token: NewOneTimeToken) -> Result<(), StoreError> {
        let mut tokens = self.lock();
        if tokens.iter().any(|(hash, _)| *hash == token.token_hash) {
            return Err(StoreError::backend("duplicate one-time token hash"));
        }
        tokens.push((
            token.token_hash,
            OneTimeTokenRecord {
                user_id: token.user_id,
                purpose: token.purpose,
                email: token.email,
                expires_at: token.expires_at,
                used_at: None,
            },
        ));
        Ok(())
    }

    async fn consume(
        &self,
        token_hash: &OneTimeTokenHash,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> Result<Option<ConsumedToken>, StoreError> {
        let mut tokens = self.lock();
        let Some((_, record)) = tokens.iter_mut().find(|(hash, record)| {
            hash == token_hash
                && record.purpose == purpose
                && record.used_at.is_none()
                && record.expires_at > now
        }) else {
            return Ok(None);
        };
        record.used_at = Some(now);
        Ok(Some(ConsumedToken::new(
            record.user_id,
            record.email.clone(),
        )))
    }

    async fn invalidate(
        &self,
        user_id: Uuid,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        for (_, record) in self.lock().iter_mut() {
            if record.user_id == user_id && record.purpose == purpose && record.used_at.is_none() {
                record.used_at = Some(now);
            }
        }
        Ok(())
    }
}

/// [`OneTimeTokenStore`] without its type, so that the services using it keep their
/// type parameters.
#[cfg_attr(not(feature = "local"), allow(dead_code))]
pub(crate) trait DynOneTimeTokenStore: Send + Sync {
    fn dyn_insert(&self, token: NewOneTimeToken) -> BoxFuture<'_, Result<(), StoreError>>;
    fn dyn_consume<'a>(
        &'a self,
        token_hash: &'a OneTimeTokenHash,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> BoxFuture<'a, Result<Option<ConsumedToken>, StoreError>>;
    fn dyn_invalidate(
        &self,
        user_id: Uuid,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> BoxFuture<'_, Result<(), StoreError>>;
}

impl<T: OneTimeTokenStore> DynOneTimeTokenStore for T {
    fn dyn_insert(&self, token: NewOneTimeToken) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(OneTimeTokenStore::insert(self, token))
    }

    fn dyn_consume<'a>(
        &'a self,
        token_hash: &'a OneTimeTokenHash,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> BoxFuture<'a, Result<Option<ConsumedToken>, StoreError>> {
        Box::pin(OneTimeTokenStore::consume(self, token_hash, purpose, now))
    }

    fn dyn_invalidate(
        &self,
        user_id: Uuid,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> BoxFuture<'_, Result<(), StoreError>> {
        Box::pin(OneTimeTokenStore::invalidate(self, user_id, purpose, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn new_token(
        user_id: Uuid,
        purpose: TokenPurpose,
        expires_at: SystemTime,
    ) -> (OneTimeToken, NewOneTimeToken) {
        let token = OneTimeToken::generate().unwrap();
        let new = NewOneTimeToken {
            token_hash: token.hash(),
            user_id,
            purpose,
            email: "budi@example.com".into(),
            expires_at,
        };
        (token, new)
    }

    #[test]
    fn token_has_the_documented_format_and_is_redacted() {
        let token = OneTimeToken::generate().unwrap();
        let text = token.expose();
        assert_eq!(text.len(), 9 + 43);
        assert!(text.starts_with("rusted_t_"));
        assert!(OneTimeTokenHash::of_presented(text) == Some(token.hash()));
        assert!(!format!("{token:?}").contains(&text[9..]));
        assert!(!format!("{:?}", token.hash()).contains("rusted"));
        assert!(OneTimeTokenHash::of_presented("rusted_s_abc").is_none());
        let session = crate::session::SessionToken::generate().unwrap();
        assert!(OneTimeTokenHash::of_presented(session.expose()).is_none());
        assert_eq!(
            TokenPurpose::parse("verify_email"),
            Some(TokenPurpose::VerifyEmail)
        );
        assert_eq!(TokenPurpose::ResetPassword.as_str(), "reset_password");
        assert_eq!(TokenPurpose::parse("mobile_handoff"), None);
    }

    #[tokio::test]
    async fn a_token_is_used_once_for_its_purpose_before_it_expires() {
        let store = MemoryOneTimeTokenStore::new();
        let user = Uuid::new_v4();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let end = now + Duration::from_secs(60);
        let (token, new) = new_token(user, TokenPurpose::ResetPassword, end);
        store.insert(new.clone()).await.unwrap();
        assert!(store.insert(new).await.is_err(), "duplicate hash");

        let hash = token.hash();
        let other_purpose = store.consume(&hash, TokenPurpose::VerifyEmail, now).await;
        assert_eq!(other_purpose.unwrap(), None);
        let expired = store.consume(&hash, TokenPurpose::ResetPassword, end).await;
        assert_eq!(expired.unwrap(), None);

        let used = store
            .consume(&hash, TokenPurpose::ResetPassword, now)
            .await
            .unwrap();
        assert_eq!(used, Some(ConsumedToken::new(user, "budi@example.com")));
        let again = store.consume(&hash, TokenPurpose::ResetPassword, now).await;
        assert_eq!(again.unwrap(), None);
        assert_eq!(store.tokens_for(user)[0].used_at, Some(now));
    }

    #[tokio::test]
    async fn invalidate_ends_unused_tokens_of_one_purpose() {
        let store = MemoryOneTimeTokenStore::new();
        let user = Uuid::new_v4();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let end = now + Duration::from_secs(60);
        let (reset, new_reset) = new_token(user, TokenPurpose::ResetPassword, end);
        let (verify, new_verify) = new_token(user, TokenPurpose::VerifyEmail, end);
        let (other, new_other) = new_token(Uuid::new_v4(), TokenPurpose::ResetPassword, end);
        for new in [new_reset, new_verify, new_other] {
            store.insert(new).await.unwrap();
        }

        store
            .invalidate(user, TokenPurpose::ResetPassword, now)
            .await
            .unwrap();
        let reset_purpose = TokenPurpose::ResetPassword;
        assert_eq!(
            store
                .consume(&reset.hash(), reset_purpose, now)
                .await
                .unwrap(),
            None
        );
        assert!(
            store
                .consume(&verify.hash(), TokenPurpose::VerifyEmail, now)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .consume(&other.hash(), reset_purpose, now)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(store.len(), 3);
    }
}
