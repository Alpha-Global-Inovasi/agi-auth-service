//! Token verification logic for Firebase ID tokens

use crate::auth::claims::Claims;
use crate::auth::jwk::get_decoding_key;
use crate::errors::{AuthError, AuthResult};
use jsonwebtoken::{Algorithm, Header, Validation, decode, decode_header};

/// Firebase project ID (loaded from environment)
fn get_project_id() -> AuthResult<String> {
    std::env::var("FIREBASE_PROJECT_ID").map_err(|_| {
        AuthError::ConfigError("Missing FIREBASE_PROJECT_ID environment variable".into())
    })
}

/// Verify a Firebase ID token and return the decoded claims
///
/// # Arguments
/// * `token` - The Firebase ID token string (without "Bearer " prefix)
///
/// # Returns
/// * `Ok(Claims)` - The decoded and verified claims
/// * `Err(AuthError)` - If verification fails
pub async fn verify_token(token: &str) -> AuthResult<Claims> {
    // Reject malformed tokens before reading config or touching the network
    let header = decode_header(token).map_err(|e| AuthError::DecodeError(e.to_string()))?;
    let project_id = get_project_id()?;
    verify_with_header(token, header, &project_id).await
}

async fn verify_with_header(token: &str, header: Header, project_id: &str) -> AuthResult<Claims> {
    let kid = header.kid.ok_or(AuthError::MissingKeyId)?;

    // Get decoding key (with caching)
    let decoding_key = get_decoding_key(&kid).await?;

    // Build validation
    let issuer = format!("https://securetoken.google.com/{}", project_id);

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&issuer]);
    validation.set_audience(&[project_id]);
    validation.validate_exp = true;

    // Decode and verify
    let token_data =
        decode::<Claims>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::InvalidSignature,
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => AuthError::IssuerMismatch {
                expected: issuer.clone(),
                actual: "unknown".into(),
            },
            jsonwebtoken::errors::ErrorKind::InvalidAudience => AuthError::AudienceMismatch {
                expected: project_id.to_string(),
                actual: "unknown".into(),
            },
            _ => AuthError::DecodeError(e.to_string()),
        })?;

    let claims = token_data.claims;

    // Additional validations
    if claims.sub.is_empty() {
        return Err(AuthError::DecodeError("'sub' claim is empty".into()));
    }

    // auth_time should be in the past
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if claims.auth_time > now {
        return Err(AuthError::DecodeError(
            "'auth_time' is in the future".into(),
        ));
    }

    Ok(claims)
}

/// Extract bearer token from Authorization header value
///
/// # Arguments
/// * `auth_header` - The full Authorization header value (e.g., "Bearer eyJ...")
///
/// # Returns
/// * `Ok(&str)` - The token without the "Bearer " prefix
/// * `Err(AuthError)` - If the header format is invalid
pub fn extract_bearer_token(auth_header: &str) -> AuthResult<&str> {
    const BEARER_PREFIX: &str = "Bearer ";

    if auth_header.len() < BEARER_PREFIX.len() {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    let prefix = &auth_header[..BEARER_PREFIX.len()];
    if !prefix.eq_ignore_ascii_case(BEARER_PREFIX) {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    let token = auth_header[BEARER_PREFIX.len()..].trim();
    if token.is_empty() {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        TEST_KID, TEST_PROJECT, install_test_key, now, sign, sign_with_other_key, valid_claims,
    };

    async fn verify(token: &str) -> AuthResult<Claims> {
        install_test_key();
        let header = decode_header(token).map_err(|e| AuthError::DecodeError(e.to_string()))?;
        verify_with_header(token, header, TEST_PROJECT).await
    }

    #[tokio::test]
    async fn valid_token_is_accepted() {
        let claims = verify(&sign(&valid_claims(), Some(TEST_KID)))
            .await
            .unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "user@example.com");
    }

    #[tokio::test]
    async fn expired_token() {
        let mut c = valid_claims();
        c["exp"] = (now() - 3600).into();
        let err = verify(&sign(&c, Some(TEST_KID))).await.unwrap_err();
        assert!(matches!(err, AuthError::TokenExpired), "{err:?}");
    }

    #[tokio::test]
    async fn wrong_audience() {
        let mut c = valid_claims();
        c["aud"] = "other-project".into();
        let err = verify(&sign(&c, Some(TEST_KID))).await.unwrap_err();
        assert!(matches!(err, AuthError::AudienceMismatch { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn wrong_issuer() {
        let mut c = valid_claims();
        c["iss"] = "https://securetoken.google.com/other-project".into();
        let err = verify(&sign(&c, Some(TEST_KID))).await.unwrap_err();
        assert!(matches!(err, AuthError::IssuerMismatch { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn signed_by_unknown_key() {
        let token = sign_with_other_key(&valid_claims(), TEST_KID);
        let err = verify(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidSignature), "{err:?}");
    }

    #[tokio::test]
    async fn missing_kid() {
        let err = verify(&sign(&valid_claims(), None)).await.unwrap_err();
        assert!(matches!(err, AuthError::MissingKeyId), "{err:?}");
    }

    #[tokio::test]
    async fn unknown_kid_is_key_not_found() {
        let err = verify(&sign(&valid_claims(), Some("no-such-kid")))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::KeyNotFound { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn empty_sub() {
        let mut c = valid_claims();
        c["sub"] = "".into();
        let err = verify(&sign(&c, Some(TEST_KID))).await.unwrap_err();
        assert!(matches!(err, AuthError::DecodeError(_)), "{err:?}");
    }

    #[tokio::test]
    async fn auth_time_in_future() {
        let mut c = valid_claims();
        c["auth_time"] = (now() + 3600).into();
        let err = verify(&sign(&c, Some(TEST_KID))).await.unwrap_err();
        assert!(matches!(err, AuthError::DecodeError(_)), "{err:?}");
    }

    #[test]
    fn test_extract_bearer_token_valid() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("bearer xyz789").unwrap(), "xyz789");
    }

    #[test]
    fn test_extract_bearer_token_invalid() {
        assert!(extract_bearer_token("Basic abc123").is_err());
        assert!(extract_bearer_token("").is_err());
        assert!(extract_bearer_token("Bearer ").is_err());
        assert!(extract_bearer_token("Bearer").is_err());
    }
}
