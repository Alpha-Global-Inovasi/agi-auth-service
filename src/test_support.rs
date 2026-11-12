//! Helpers for signing fake Firebase ID tokens with the local test keys in `testdata/`.

use crate::auth::insert_test_key;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use serde_json::{Value, json};

pub(crate) const TEST_KID: &str = "test-kid";
pub(crate) const TEST_PROJECT: &str = "test-project";

const PRIVATE_KEY: &str = include_str!("../testdata/rsa_private.pem");
const PUBLIC_KEY: &str = include_str!("../testdata/rsa_public.pem");
const OTHER_PRIVATE_KEY: &str = include_str!("../testdata/rsa_other_private.pem");

/// Put the test public key into the JWK cache under [`TEST_KID`]
pub(crate) fn install_test_key() {
    insert_test_key(
        TEST_KID,
        DecodingKey::from_rsa_pem(PUBLIC_KEY.as_bytes()).unwrap(),
    );
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Claims of a valid token for [`TEST_PROJECT`]
pub(crate) fn valid_claims() -> Value {
    let now = now();
    json!({
        "iss": format!("https://securetoken.google.com/{TEST_PROJECT}"),
        "aud": TEST_PROJECT,
        "sub": "user-123",
        "iat": now - 60,
        "exp": now + 3600,
        "auth_time": now - 60,
        "email": "user@example.com",
        "email_verified": true,
        "firebase": { "sign_in_provider": "password" },
    })
}

fn sign_with(claims: &Value, kid: Option<&str>, private_pem: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(str::to_string);
    let key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
    encode(&header, claims, &key).unwrap()
}

/// Sign with the test key; the token verifies when `kid` is [`TEST_KID`]
pub(crate) fn sign(claims: &Value, kid: Option<&str>) -> String {
    sign_with(claims, kid, PRIVATE_KEY)
}

/// Sign with an unrelated key, so the signature does not match the key under `kid`
pub(crate) fn sign_with_other_key(claims: &Value, kid: &str) -> String {
    sign_with(claims, Some(kid), OTHER_PRIVATE_KEY)
}
