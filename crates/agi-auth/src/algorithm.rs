/// Asymmetric signing algorithms an [`Issuer`](crate::Issuer) may allow.
///
/// HMAC algorithms (`HS256` etc.) are deliberately absent: tokens from an external issuer
/// are always verified with the issuer's public keys, so a shared-secret algorithm can only
/// appear in an algorithm-confusion attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// Edwards-curve signatures (Ed25519)
    EdDSA,
}

impl Algorithm {
    pub(crate) fn to_jwt(self) -> jsonwebtoken::Algorithm {
        use jsonwebtoken::Algorithm as J;
        match self {
            Self::RS256 => J::RS256,
            Self::RS384 => J::RS384,
            Self::RS512 => J::RS512,
            Self::PS256 => J::PS256,
            Self::PS384 => J::PS384,
            Self::PS512 => J::PS512,
            Self::ES256 => J::ES256,
            Self::ES384 => J::ES384,
            Self::EdDSA => J::EdDSA,
        }
    }

    /// `None` for HMAC algorithms, which are never accepted.
    pub(crate) fn from_jwt(alg: jsonwebtoken::Algorithm) -> Option<Self> {
        use jsonwebtoken::Algorithm as J;
        Some(match alg {
            J::RS256 => Self::RS256,
            J::RS384 => Self::RS384,
            J::RS512 => Self::RS512,
            J::PS256 => Self::PS256,
            J::PS384 => Self::PS384,
            J::PS512 => Self::PS512,
            J::ES256 => Self::ES256,
            J::ES384 => Self::ES384,
            J::EdDSA => Self::EdDSA,
            // HMAC, and any algorithm a future jsonwebtoken release adds, is rejected.
            _ => return None,
        })
    }
}

/// Makes sure jsonwebtoken has a process-wide crypto backend before any key is used.
///
/// jsonwebtoken picks its backend from crate features only when exactly one of
/// `aws_lc_rs` and `rust_crypto` is enabled. Another crate in the application may enable
/// `rust_crypto` as well, in which case jsonwebtoken would panic on the first signature
/// check. Installing aws-lc-rs here (the backend agi-auth depends on) avoids that; a
/// provider the application installed itself is left alone.
pub(crate) fn ensure_crypto_provider() {
    use jsonwebtoken::crypto::{CryptoProvider, aws_lc};
    if CryptoProvider::try_get_default().is_none() {
        // Losing a race with another installer is fine: either way a provider is set.
        let _ = aws_lc::DEFAULT_PROVIDER.install_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_is_never_mapped() {
        for alg in [
            jsonwebtoken::Algorithm::HS256,
            jsonwebtoken::Algorithm::HS384,
            jsonwebtoken::Algorithm::HS512,
        ] {
            assert_eq!(Algorithm::from_jwt(alg), None);
        }
        assert_eq!(
            Algorithm::from_jwt(jsonwebtoken::Algorithm::RS256),
            Some(Algorithm::RS256)
        );
    }
}
