use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// The authenticated caller, normalized across issuers.
///
/// `(issuer, subject)` is the stable identity of a user. Do not key accounts by `email`:
/// emails change, and an issuer that does not verify them can be used to claim someone
/// else's address.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Principal {
    /// The `iss` claim.
    pub issuer: String,
    /// The `sub` claim. Unique within `issuer`.
    pub subject: String,
    /// The `email` claim, if present and non-empty.
    pub email: Option<String>,
    /// The `email_verified` claim; `false` when absent.
    pub email_verified: bool,
    /// The `name` claim.
    pub name: Option<String>,
    /// The `picture` claim.
    pub picture: Option<String>,
    /// Every claim of the token, for issuer-specific data such as roles.
    pub claims: Map<String, Value>,
}

impl Principal {
    /// Build a principal from a set of claims **without verifying anything**.
    ///
    /// [`Verifier::verify`](crate::Verifier::verify) calls this after validation. Call it
    /// yourself only to construct a principal in tests of your own handlers.
    pub fn from_claims(claims: Map<String, Value>) -> Self {
        let string = |key: &str| {
            claims
                .get(key)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };

        Self {
            issuer: string("iss").unwrap_or_default(),
            subject: string("sub").unwrap_or_default(),
            email: string("email"),
            email_verified: claims
                .get("email_verified")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            name: string("name"),
            picture: string("picture"),
            claims,
        }
    }

    /// Deserialize a single claim, e.g. `principal.claim::<Vec<String>>("roles")`.
    ///
    /// Returns `None` when the claim is absent or has a different shape.
    pub fn claim<T: DeserializeOwned>(&self, name: &str) -> Option<T> {
        self.claims
            .get(name)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_standard_claims() {
        let Value::Object(claims) = json!({
            "iss": "https://issuer.test",
            "sub": "u1",
            "email": "",
            "email_verified": true,
            "name": "Ani",
            "roles": ["admin"],
        }) else {
            unreachable!()
        };
        let p = Principal::from_claims(claims);
        assert_eq!(p.issuer, "https://issuer.test");
        assert_eq!(p.subject, "u1");
        assert_eq!(p.email, None, "empty email is treated as absent");
        assert!(p.email_verified);
        assert_eq!(p.name.as_deref(), Some("Ani"));
        assert_eq!(p.claim::<Vec<String>>("roles"), Some(vec!["admin".into()]));
        assert_eq!(p.claim::<u64>("roles"), None);
    }
}
