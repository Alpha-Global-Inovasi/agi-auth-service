use crate::error::{AuthError, AuthResult};

/// Extract the token from an `Authorization: Bearer <token>` header value.
///
/// The scheme is matched case-insensitively.
pub fn extract_bearer_token(auth_header: &str) -> AuthResult<&str> {
    const PREFIX: &str = "Bearer ";

    let (scheme, token) = auth_header
        .split_at_checked(PREFIX.len())
        .ok_or(AuthError::InvalidAuthHeaderFormat)?;
    if !scheme.eq_ignore_ascii_case(PREFIX) {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    let token = token.trim();
    if token.is_empty() {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("bearer xyz789").unwrap(), "xyz789");
    }

    #[test]
    fn invalid() {
        assert!(extract_bearer_token("Basic abc123").is_err());
        assert!(extract_bearer_token("").is_err());
        assert!(extract_bearer_token("Bearer ").is_err());
        assert!(extract_bearer_token("Bearer").is_err());
        // Multi-byte input must not panic on a char boundary
        assert!(extract_bearer_token("Beärer xyz").is_err());
    }
}
