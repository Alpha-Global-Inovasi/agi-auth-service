//! Token verification against a set of trusted issuers.

use crate::algorithm::Algorithm;
use crate::bearer::extract_bearer_token;
use crate::error::{AuthError, AuthResult};
use crate::http;
use crate::issuer::{Issuer, KeySource};
use crate::jwks::{Jwks, Timings};
use crate::principal::Principal;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Tokens are a few kilobytes; reject anything far beyond that before parsing.
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_KID_BYTES: usize = 256;

struct TrustedIssuer {
    config: Issuer,
    keys: Jwks,
}

/// Verifies bearer tokens from one or more trusted issuers.
///
/// Cheap to clone (it is an `Arc` inside) and safe to share across threads. Build one at
/// startup and hand clones to your web framework.
#[derive(Clone)]
pub struct Verifier {
    issuers: Arc<HashMap<String, TrustedIssuer>>,
}

/// Builder for [`Verifier`]. Obtain it from [`Verifier::builder`].
#[derive(Debug, Default)]
#[must_use = "call build() to obtain a Verifier"]
pub struct VerifierBuilder {
    issuers: Vec<Issuer>,
    timings: Timings,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut issuers: Vec<_> = self.issuers.keys().collect();
        issuers.sort();
        f.debug_struct("Verifier")
            .field("issuers", &issuers)
            .finish()
    }
}

impl VerifierBuilder {
    /// Trust tokens from this issuer.
    pub fn issuer(mut self, issuer: Issuer) -> Self {
        self.issuers.push(issuer);
        self
    }

    #[cfg(test)]
    pub(crate) fn timings(mut self, timings: Timings) -> Self {
        self.timings = timings;
        self
    }

    /// Validate the configuration and build the verifier.
    ///
    /// Does not contact any issuer; keys are fetched on first use. Call
    /// [`Verifier::refresh_keys`] afterwards to fail fast at startup instead.
    ///
    /// # Errors
    ///
    /// [`AuthError::Config`] when there is no issuer, an issuer is listed twice, an issuer
    /// has no audience, algorithm or key source, a JWKS URL is not HTTPS, or a static JWKS
    /// document has no usable key.
    pub fn build(self) -> AuthResult<Verifier> {
        if self.issuers.is_empty() {
            return Err(AuthError::Config("at least one issuer is required".into()));
        }

        let mut client = None;
        let mut issuers = HashMap::with_capacity(self.issuers.len());
        for config in self.issuers {
            config.validate()?;
            let keys = match &config.keys {
                Some(KeySource::Static(json)) => Jwks::from_static(json)?,
                Some(KeySource::Remote(url)) => {
                    let client = match &client {
                        Some(client) => client,
                        None => client.insert(http::client()?),
                    };
                    Jwks::remote(url.clone(), client.clone(), self.timings)
                }
                None => return Err(AuthError::Config("issuer has no key source".into())),
            };

            let name = config.issuer.clone();
            if issuers
                .insert(name.clone(), TrustedIssuer { config, keys })
                .is_some()
            {
                return Err(AuthError::Config(format!(
                    "issuer '{name}' is configured twice"
                )));
            }
        }

        Ok(Verifier {
            issuers: Arc::new(issuers),
        })
    }
}

impl Verifier {
    /// Start configuring a verifier.
    pub fn builder() -> VerifierBuilder {
        VerifierBuilder::default()
    }

    /// Verify a token and return who it identifies.
    ///
    /// Checks, in order: size, header shape, that `iss` is a configured issuer, that the
    /// algorithm is allowed for that issuer, the `typ` requirement, the signature against
    /// that issuer's keys only, then `iss`, `aud`, `exp`, `nbf`, a non-empty `sub`, and
    /// that `auth_time` (if present) is not in the future.
    pub async fn verify(&self, token: &str) -> AuthResult<Principal> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::MalformedToken("token is too large".into()));
        }
        let header = decode_header(token).map_err(|e| AuthError::MalformedToken(e.to_string()))?;

        // `iss` is read before the signature is checked, but only to choose which
        // configured issuer's keys and rules apply. Nothing else is trusted from it.
        let trusted = self
            .issuers
            .get(&peek_issuer(token)?)
            .ok_or(AuthError::UntrustedIssuer)?;
        let config = &trusted.config;

        let alg = Algorithm::from_jwt(header.alg)
            .filter(|alg| config.algorithms.contains(alg))
            .ok_or(AuthError::DisallowedAlgorithm)?;
        if !config.typ_matches(header.typ.as_deref()) {
            return Err(AuthError::InvalidTokenType);
        }

        let kid = header.kid.ok_or(AuthError::MissingKeyId)?;
        if kid.len() > MAX_KID_BYTES {
            return Err(AuthError::MalformedToken("kid is too large".into()));
        }
        let signing_key = trusted.keys.get(&kid).await?;
        if signing_key.alg.is_some_and(|key_alg| key_alg != alg) {
            return Err(AuthError::DisallowedAlgorithm);
        }

        let mut validation = Validation::new(alg.to_jwt());
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&config.audiences);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = config.leeway.as_secs();

        let claims = decode::<Map<String, Value>>(token, &signing_key.key, &validation)
            .map_err(map_jwt_error)?
            .claims;

        if claims
            .get("sub")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(AuthError::InvalidClaims("'sub' is empty".into()));
        }
        if let Some(auth_time) = claims.get("auth_time").and_then(Value::as_u64)
            && auth_time > unix_now().saturating_add(config.leeway.as_secs())
        {
            return Err(AuthError::InvalidClaims(
                "'auth_time' is in the future".into(),
            ));
        }

        Ok(Principal::from_claims(claims))
    }

    /// Verify the value of an `Authorization: Bearer <token>` header.
    pub async fn verify_bearer(&self, authorization: &str) -> AuthResult<Principal> {
        self.verify(extract_bearer_token(authorization)?).await
    }

    /// Fetch the signing keys of every issuer now.
    ///
    /// Optional. Useful at startup to surface a wrong JWKS URL or missing network access
    /// before the first request does. Returns the first error; issuers with static keys
    /// are skipped.
    pub async fn refresh_keys(&self) -> AuthResult<()> {
        for trusted in self.issuers.values() {
            trusted.keys.refresh().await?;
        }
        Ok(())
    }
}

/// Read `iss` from the (unverified) payload segment.
fn peek_issuer(token: &str) -> AuthResult<String> {
    #[derive(Deserialize)]
    struct Peek {
        iss: Option<String>,
    }

    let malformed = |what: &str| AuthError::MalformedToken(what.to_string());

    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| malformed("not a JWT"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| malformed("payload is not base64url"))?;
    let peek: Peek =
        serde_json::from_slice(&bytes).map_err(|_| malformed("payload is not a JSON object"))?;

    peek.iss
        .ok_or_else(|| AuthError::InvalidClaims("missing 'iss'".into()))
}

fn map_jwt_error(e: jsonwebtoken::errors::Error) -> AuthError {
    use jsonwebtoken::errors::ErrorKind as K;
    match e.kind() {
        K::ExpiredSignature => AuthError::TokenExpired,
        K::ImmatureSignature => AuthError::TokenNotYetValid,
        K::InvalidSignature => AuthError::InvalidSignature,
        K::InvalidIssuer => AuthError::InvalidIssuer,
        K::InvalidAudience => AuthError::InvalidAudience,
        K::InvalidAlgorithm => AuthError::DisallowedAlgorithm,
        K::MissingRequiredClaim(claim) => AuthError::InvalidClaims(format!("missing '{claim}'")),
        _ => AuthError::MalformedToken(e.to_string()),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::support::{
        JWKS_JSON, OTHER_ISSUER, TEST_AUDIENCE, TEST_ISSUER, TEST_KID, now, sign, sign_hs256,
        sign_with_other_key, test_verifier, valid_claims,
    };
    use jsonwebtoken::Header;

    async fn verify(claims: &Value) -> AuthResult<Principal> {
        test_verifier().verify(&sign(claims, Some(TEST_KID))).await
    }

    #[tokio::test]
    async fn valid_token_yields_principal() {
        let p = verify(&valid_claims()).await.unwrap();
        assert_eq!(p.issuer, TEST_ISSUER);
        assert_eq!(p.subject, "user-123");
        assert_eq!(p.email.as_deref(), Some("user@example.com"));
        assert!(p.email_verified);
        assert_eq!(crate::firebase::sign_in_provider(&p), Some("password"));
    }

    #[tokio::test]
    async fn audience_may_be_an_array() {
        let mut c = valid_claims();
        c["aud"] = serde_json::json!(["something-else", TEST_AUDIENCE]);
        assert!(verify(&c).await.is_ok());
    }

    #[tokio::test]
    async fn auth_time_is_optional() {
        let mut c = valid_claims();
        c.as_object_mut().unwrap().remove("auth_time");
        assert!(verify(&c).await.is_ok());
    }

    #[tokio::test]
    async fn time_claims() {
        let mut c = valid_claims();
        c["exp"] = (now() - 3600).into();
        assert!(matches!(verify(&c).await, Err(AuthError::TokenExpired)));

        let mut c = valid_claims();
        c["nbf"] = (now() + 3600).into();
        assert!(matches!(verify(&c).await, Err(AuthError::TokenNotYetValid)));

        let mut c = valid_claims();
        c["auth_time"] = (now() + 3600).into();
        assert!(matches!(verify(&c).await, Err(AuthError::InvalidClaims(_))));
    }

    #[tokio::test]
    async fn wrong_audience() {
        let mut c = valid_claims();
        c["aud"] = "other-audience".into();
        assert!(matches!(verify(&c).await, Err(AuthError::InvalidAudience)));
    }

    #[tokio::test]
    async fn unknown_issuer_is_untrusted() {
        let mut c = valid_claims();
        c["iss"] = "https://evil.example".into();
        assert!(matches!(verify(&c).await, Err(AuthError::UntrustedIssuer)));
    }

    #[tokio::test]
    async fn missing_or_empty_sub() {
        let mut c = valid_claims();
        c["sub"] = "".into();
        assert!(matches!(verify(&c).await, Err(AuthError::InvalidClaims(_))));

        let mut c = valid_claims();
        c.as_object_mut().unwrap().remove("sub");
        assert!(matches!(verify(&c).await, Err(AuthError::InvalidClaims(_))));
    }

    #[tokio::test]
    async fn signature_from_another_key() {
        let token = sign_with_other_key(&valid_claims(), TEST_KID);
        assert!(matches!(
            test_verifier().verify(&token).await,
            Err(AuthError::InvalidSignature)
        ));
    }

    #[tokio::test]
    async fn kid_problems() {
        let v = test_verifier();
        assert!(matches!(
            v.verify(&sign(&valid_claims(), None)).await,
            Err(AuthError::MissingKeyId)
        ));
        assert!(matches!(
            v.verify(&sign(&valid_claims(), Some("no-such-kid"))).await,
            Err(AuthError::KeyNotFound { .. })
        ));
        let long_kid = "k".repeat(MAX_KID_BYTES + 1);
        assert!(matches!(
            v.verify(&sign(&valid_claims(), Some(&long_kid))).await,
            Err(AuthError::MalformedToken(_))
        ));
    }

    /// Algorithm confusion: an HS256 token "signed" with the issuer's public key.
    #[tokio::test]
    async fn hmac_token_is_rejected() {
        let token = sign_hs256(&valid_claims(), TEST_KID);
        assert!(matches!(
            test_verifier().verify(&token).await,
            Err(AuthError::DisallowedAlgorithm)
        ));
    }

    #[tokio::test]
    async fn unsigned_token_is_rejected() {
        let encode = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
        let header = serde_json::json!({"alg": "none", "typ": "JWT", "kid": TEST_KID});
        let token = format!("{}.{}.", encode(&header), encode(&valid_claims()));
        assert!(matches!(
            test_verifier().verify(&token).await,
            Err(AuthError::MalformedToken(_))
        ));
    }

    #[tokio::test]
    async fn algorithm_outside_the_allowlist() {
        let verifier = Verifier::builder()
            .issuer(
                Issuer::new(TEST_ISSUER)
                    .audience(TEST_AUDIENCE)
                    .algorithms(&[Algorithm::ES256])
                    .jwks_json(JWKS_JSON),
            )
            .build()
            .unwrap();
        let token = sign(&valid_claims(), Some(TEST_KID));
        assert!(matches!(
            verifier.verify(&token).await,
            Err(AuthError::DisallowedAlgorithm)
        ));
    }

    #[tokio::test]
    async fn required_token_type() {
        let verifier = Verifier::builder()
            .issuer(
                Issuer::new(TEST_ISSUER)
                    .audience(TEST_AUDIENCE)
                    .require_type("at+jwt")
                    .jwks_json(JWKS_JSON),
            )
            .build()
            .unwrap();

        let id_token = sign(&valid_claims(), Some(TEST_KID));
        assert!(matches!(
            verifier.verify(&id_token).await,
            Err(AuthError::InvalidTokenType)
        ));

        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some(TEST_KID.into());
        let access_token = crate::tests::support::sign_with_header(&valid_claims(), &header);
        assert!(verifier.verify(&access_token).await.is_ok());
    }

    /// A token naming issuer B must be checked against B's keys, even when issuer A
    /// publishes a key with the same `kid`.
    #[tokio::test]
    async fn keys_are_not_shared_between_issuers() {
        let verifier = Verifier::builder()
            .issuer(
                Issuer::new(TEST_ISSUER)
                    .audience(TEST_AUDIENCE)
                    .jwks_json(JWKS_JSON),
            )
            .issuer(
                Issuer::new(OTHER_ISSUER)
                    .audience(TEST_AUDIENCE)
                    .jwks_json(crate::tests::support::OTHER_JWKS_JSON),
            )
            .build()
            .unwrap();

        // Signed by TEST_ISSUER's key but claiming to come from OTHER_ISSUER
        let mut forged = valid_claims();
        forged["iss"] = OTHER_ISSUER.into();
        assert!(matches!(
            verifier.verify(&sign(&forged, Some(TEST_KID))).await,
            Err(AuthError::InvalidSignature)
        ));

        // The same claims signed by OTHER_ISSUER's own key are accepted
        let genuine = sign_with_other_key(&forged, TEST_KID);
        assert_eq!(
            verifier.verify(&genuine).await.unwrap().issuer,
            OTHER_ISSUER
        );
    }

    #[tokio::test]
    async fn garbage_input() {
        let v = test_verifier();
        for token in ["", "abc", "a.b.c", "....", "é.é.é"] {
            assert!(
                matches!(v.verify(token).await, Err(AuthError::MalformedToken(_))),
                "{token:?}"
            );
        }
        let huge = "a".repeat(MAX_TOKEN_BYTES + 1);
        assert!(matches!(
            v.verify(&huge).await,
            Err(AuthError::MalformedToken(_))
        ));
    }

    #[tokio::test]
    async fn bearer_header() {
        let v = test_verifier();
        let token = sign(&valid_claims(), Some(TEST_KID));
        assert!(v.verify_bearer(&format!("Bearer {token}")).await.is_ok());
        let _ = crate::tests::support::test_issuer();
        assert!(matches!(
            v.verify_bearer(&token).await,
            Err(AuthError::InvalidAuthHeaderFormat)
        ));
    }

    #[test]
    fn builder_rejects_bad_configuration() {
        assert!(Verifier::builder().build().is_err(), "no issuer");

        let issuer = || {
            Issuer::new(TEST_ISSUER)
                .audience(TEST_AUDIENCE)
                .jwks_json(JWKS_JSON)
        };
        assert!(
            Verifier::builder()
                .issuer(issuer())
                .issuer(issuer())
                .build()
                .is_err(),
            "duplicate issuer"
        );
        assert!(
            Verifier::builder()
                .issuer(
                    Issuer::new(TEST_ISSUER)
                        .audience(TEST_AUDIENCE)
                        .jwks_json("{}")
                )
                .build()
                .is_err(),
            "unusable static JWKS"
        );
    }

    #[test]
    fn verifier_is_shareable_and_its_future_is_send() {
        fn assert_send_sync<T: Send + Sync + Clone>() {}
        fn assert_send<T: Send>(_: T) {}
        assert_send_sync::<Verifier>();
        assert_send(test_verifier().verify("token"));
        assert_send(test_verifier().refresh_keys());
    }
}
