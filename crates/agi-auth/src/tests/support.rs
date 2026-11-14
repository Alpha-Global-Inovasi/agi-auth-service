//! Helpers for signing fake tokens with the local test keys in `testdata/`.

use crate::{Issuer, Verifier};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

pub(crate) const TEST_ISSUER: &str = "https://issuer.test";
pub(crate) const OTHER_ISSUER: &str = "https://other-issuer.test";
pub(crate) const TEST_AUDIENCE: &str = "test-audience";
pub(crate) const TEST_KID: &str = "test-kid";

/// Public half of `rsa_private.pem`, published under [`TEST_KID`].
pub(crate) const JWKS_JSON: &str = include_str!("../../../../testdata/jwks.json");
/// Public half of `rsa_other_private.pem`, also under [`TEST_KID`].
pub(crate) const OTHER_JWKS_JSON: &str = include_str!("../../../../testdata/other_jwks.json");

const PRIVATE_KEY: &str = include_str!("../../../../testdata/rsa_private.pem");
const PUBLIC_KEY: &str = include_str!("../../../../testdata/rsa_public.pem");
const OTHER_PRIVATE_KEY: &str = include_str!("../../../../testdata/rsa_other_private.pem");

/// A verifier trusting [`TEST_ISSUER`] with the static test key.
pub(crate) fn test_verifier() -> Verifier {
    Verifier::builder().issuer(test_issuer()).build().unwrap()
}

pub(crate) fn test_issuer() -> Issuer {
    Issuer::new(TEST_ISSUER)
        .audience(TEST_AUDIENCE)
        .jwks_json(JWKS_JSON)
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Claims of a token that [`test_verifier`] accepts.
pub(crate) fn valid_claims() -> Value {
    let now = now();
    json!({
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
        "sub": "user-123",
        "iat": now - 60,
        "exp": now + 3600,
        "auth_time": now - 60,
        "email": "user@example.com",
        "email_verified": true,
        "firebase": { "sign_in_provider": "password" },
    })
}

fn rs256_header(kid: Option<&str>) -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_string);
    header
}

fn sign_rsa(claims: &Value, header: &Header, private_pem: &str) -> String {
    let key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
    encode(header, claims, &key).unwrap()
}

/// Sign with the test key; verifies when `kid` is [`TEST_KID`].
pub(crate) fn sign(claims: &Value, kid: Option<&str>) -> String {
    sign_rsa(claims, &rs256_header(kid), PRIVATE_KEY)
}

/// Sign with the test key and a custom header (e.g. a specific `typ`).
pub(crate) fn sign_with_header(claims: &Value, header: &Header) -> String {
    sign_rsa(claims, header, PRIVATE_KEY)
}

/// Sign with the unrelated key (the one behind [`OTHER_JWKS_JSON`]).
pub(crate) fn sign_with_other_key(claims: &Value, kid: &str) -> String {
    sign_rsa(claims, &rs256_header(Some(kid)), OTHER_PRIVATE_KEY)
}

/// An HS256 token whose HMAC secret is the issuer's public key (algorithm confusion).
pub(crate) fn sign_hs256(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        claims,
        &EncodingKey::from_secret(PUBLIC_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}
