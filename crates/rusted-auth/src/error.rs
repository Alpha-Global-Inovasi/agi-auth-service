use thiserror::Error;

/// Errors returned by token verification and configuration.
///
/// The `Display` output is meant for logs and may contain details such as a key ID.
/// Use [`AuthError::public_message`] for anything sent to a client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// No credentials were supplied.
    #[error("missing credentials")]
    MissingCredentials,

    /// The `Authorization` header is not `Bearer <token>`.
    #[error("invalid Authorization header format: expected 'Bearer <token>'")]
    InvalidAuthHeaderFormat,

    /// The token is not a well-formed JWT.
    #[error("malformed token: {0}")]
    MalformedToken(String),

    /// The token's `iss` is not one of the configured issuers.
    #[error("token issuer is not trusted")]
    UntrustedIssuer,

    /// The token's `alg` is not allowed for its issuer, or does not match the key.
    #[error("token algorithm is not allowed")]
    DisallowedAlgorithm,

    /// The token's `typ` header does not match what the issuer requires.
    #[error("token type is not accepted")]
    InvalidTokenType,

    /// The token header has no `kid`.
    #[error("missing 'kid' in token header")]
    MissingKeyId,

    /// The issuer does not publish a key with this `kid`.
    #[error("signing key '{kid}' not found")]
    KeyNotFound {
        /// Key ID taken from the token header.
        kid: String,
    },

    /// The signature does not verify.
    #[error("invalid token signature")]
    InvalidSignature,

    /// `exp` is in the past.
    #[error("token has expired")]
    TokenExpired,

    /// `nbf` is in the future.
    #[error("token is not valid yet")]
    TokenNotYetValid,

    /// `aud` does not contain any configured audience.
    #[error("token audience is not accepted")]
    InvalidAudience,

    /// `iss` does not match the issuer the token was routed to.
    #[error("token issuer does not match")]
    InvalidIssuer,

    /// A required claim is missing or has an invalid value.
    #[error("invalid claims: {0}")]
    InvalidClaims(String),

    /// The issuer's signing keys could not be obtained.
    #[error("signing keys unavailable: {0}")]
    KeysUnavailable(String),

    /// The verifier or an issuer is misconfigured.
    #[error("configuration error: {0}")]
    Config(String),
}

impl AuthError {
    /// `true` when the failure is on the server side (keys unavailable, misconfiguration)
    /// rather than a problem with the client's credentials.
    ///
    /// Adapters map this to HTTP 500 and everything else to 401.
    pub fn is_server_error(&self) -> bool {
        matches!(self, Self::KeysUnavailable(_) | Self::Config(_))
    }

    /// A short message that is safe to return to clients.
    ///
    /// It never contains token contents, key IDs, issuer URLs or upstream errors.
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::MissingCredentials => "Authentication required",
            Self::InvalidAuthHeaderFormat => "Invalid Authorization header",
            Self::TokenExpired => "Token expired",
            e if e.is_server_error() => "Authentication service unavailable",
            _ => "Invalid token",
        }
    }
}

/// Result alias for this crate.
pub type AuthResult<T> = Result<T, AuthError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_message_hides_details() {
        let e = AuthError::KeyNotFound {
            kid: "secret-kid".into(),
        };
        assert_eq!(e.public_message(), "Invalid token");
        assert!(!e.is_server_error());

        let e = AuthError::KeysUnavailable("connect error to 10.0.0.1".into());
        assert_eq!(e.public_message(), "Authentication service unavailable");
        assert!(e.is_server_error());
    }
}
