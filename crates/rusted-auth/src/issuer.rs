use crate::algorithm::Algorithm;
use crate::error::{AuthError, AuthResult};
use crate::http;
use serde::Deserialize;
use std::time::Duration;

/// Default clock-skew allowance for `exp`, `nbf` and `auth_time`.
const DEFAULT_LEEWAY: Duration = Duration::from_secs(60);

/// Where an issuer's signing keys come from.
#[derive(Debug, Clone)]
pub(crate) enum KeySource {
    /// A JWKS document fetched (and cached) from this URL.
    Remote(String),
    /// A JWKS document supplied up front; never refreshed.
    Static(String),
}

/// Configuration for one trusted token issuer.
///
/// Built with [`Issuer::new`], [`Issuer::discover`] or a preset such as
/// [`Issuer::firebase`], then passed to [`VerifierBuilder::issuer`](crate::VerifierBuilder::issuer).
///
/// Defaults: algorithm `RS256` only, 60 seconds leeway, no `typ` requirement.
/// At least one audience is required.
#[derive(Debug, Clone)]
#[must_use = "an Issuer does nothing until it is added to a VerifierBuilder"]
pub struct Issuer {
    pub(crate) issuer: String,
    pub(crate) audiences: Vec<String>,
    pub(crate) algorithms: Vec<Algorithm>,
    pub(crate) keys: Option<KeySource>,
    pub(crate) required_typ: Option<String>,
    pub(crate) leeway: Duration,
    pub(crate) allow_http: bool,
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
}

impl Issuer {
    /// An issuer identified by its `iss` value. Set its keys with [`Issuer::jwks_uri`] or
    /// [`Issuer::jwks_json`] and at least one [`Issuer::audience`].
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audiences: Vec::new(),
            algorithms: vec![Algorithm::RS256],
            keys: None,
            required_typ: None,
            leeway: DEFAULT_LEEWAY,
            allow_http: false,
        }
    }

    /// Configure from the issuer's OpenID Connect discovery document
    /// (`{issuer}/.well-known/openid-configuration`).
    ///
    /// Takes `jwks_uri` and the advertised signing algorithms (asymmetric ones only).
    /// Fails if the document's `issuer` is not exactly `issuer`, as the OpenID Connect
    /// Discovery spec requires. Audiences still have to be added.
    pub async fn discover(issuer: impl Into<String>) -> AuthResult<Self> {
        let issuer = issuer.into();
        require_https(&issuer, false)?;

        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let fetched = http::get(&http::client()?, &url)
            .await
            .map_err(|e| AuthError::KeysUnavailable(format!("discovery request failed: {e}")))?;
        let doc: DiscoveryDocument = serde_json::from_slice(&fetched.body)
            .map_err(|e| AuthError::KeysUnavailable(format!("invalid discovery document: {e}")))?;

        if doc.issuer != issuer {
            return Err(AuthError::Config(format!(
                "discovery issuer mismatch: configured '{issuer}', document says '{}'",
                doc.issuer
            )));
        }

        let mut config = Self::new(issuer).jwks_uri(doc.jwks_uri);
        let advertised: Vec<Algorithm> = doc
            .id_token_signing_alg_values_supported
            .iter()
            .filter_map(|name| name.parse::<jsonwebtoken::Algorithm>().ok())
            .filter_map(Algorithm::from_jwt)
            .collect();
        if !advertised.is_empty() {
            config.algorithms = advertised;
        }
        Ok(config)
    }

    /// Firebase Authentication preset: issuer `https://securetoken.google.com/{project_id}`,
    /// audience `project_id`, RS256, keys from Google's JWKS endpoint.
    ///
    /// Firebase ID tokens are ID tokens, not RFC 9068 access tokens, so no `typ` is required.
    pub fn firebase(project_id: &str) -> Self {
        Self::new(format!("https://securetoken.google.com/{project_id}"))
            .audience(project_id)
            .jwks_uri(crate::firebase::JWKS_URL)
    }

    /// Fetch keys from this JWKS URL (HTTPS required unless [`Issuer::allow_insecure_http`]).
    pub fn jwks_uri(mut self, url: impl Into<String>) -> Self {
        self.keys = Some(KeySource::Remote(url.into()));
        self
    }

    /// Use this JWKS document (`{"keys": [...]}`) and never fetch.
    ///
    /// Useful for pinned keys and for tests.
    pub fn jwks_json(mut self, json: impl Into<String>) -> Self {
        self.keys = Some(KeySource::Static(json.into()));
        self
    }

    /// Accept tokens whose `aud` contains this value. Call repeatedly for several.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audiences.push(audience.into());
        self
    }

    /// Replace the allowed signing algorithms.
    pub fn algorithms(mut self, algorithms: &[Algorithm]) -> Self {
        self.algorithms = algorithms.to_vec();
        self
    }

    /// Require this `typ` header, e.g. `"at+jwt"` to accept only RFC 9068 access tokens.
    ///
    /// Compared case-insensitively; an `application/` prefix in the token is ignored.
    pub fn require_type(mut self, typ: impl Into<String>) -> Self {
        self.required_typ = Some(typ.into());
        self
    }

    /// Clock-skew allowance for time-based claims.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Allow an `http://` JWKS URL. For local development against an IdP on localhost only.
    pub fn allow_insecure_http(mut self) -> Self {
        self.allow_http = true;
        self
    }

    /// The configured `iss` value.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The accepted audiences.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    pub(crate) fn validate(&self) -> AuthResult<()> {
        let fail = |msg: &str| {
            Err(AuthError::Config(format!(
                "issuer '{}': {msg}",
                self.issuer
            )))
        };

        if self.issuer.is_empty() {
            return Err(AuthError::Config("issuer must not be empty".into()));
        }
        if self.audiences.is_empty() || self.audiences.iter().any(String::is_empty) {
            return fail("at least one non-empty audience is required");
        }
        if self.algorithms.is_empty() {
            return fail("at least one algorithm is required");
        }
        match &self.keys {
            None => return fail("no key source; call jwks_uri() or jwks_json()"),
            Some(KeySource::Remote(url)) => require_https(url, self.allow_http)?,
            Some(KeySource::Static(_)) => {}
        }
        Ok(())
    }

    pub(crate) fn typ_matches(&self, typ: Option<&str>) -> bool {
        let Some(required) = &self.required_typ else {
            return true;
        };
        let Some(typ) = typ else {
            return false;
        };
        let typ = typ
            .get(..12)
            .filter(|p| p.eq_ignore_ascii_case("application/"))
            .map_or(typ, |_| &typ[12..]);
        typ.eq_ignore_ascii_case(required)
    }
}

fn require_https(url: &str, allow_http: bool) -> AuthResult<()> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") || (allow_http && lower.starts_with("http://")) {
        Ok(())
    } else {
        Err(AuthError::Config(format!("'{url}' must use https")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firebase_preset() {
        let i = Issuer::firebase("proj");
        assert_eq!(i.issuer(), "https://securetoken.google.com/proj");
        assert_eq!(i.audiences(), ["proj"]);
        assert_eq!(i.algorithms, [Algorithm::RS256]);
        assert!(matches!(&i.keys, Some(KeySource::Remote(u)) if u.starts_with("https://")));
        i.validate().unwrap();
    }

    #[test]
    fn validation_rules() {
        let base = Issuer::new("https://issuer.test").jwks_uri("https://issuer.test/jwks");
        assert!(base.clone().validate().is_err(), "audience required");
        assert!(base.clone().audience("a").validate().is_ok());
        assert!(
            base.clone()
                .audience("a")
                .algorithms(&[])
                .validate()
                .is_err(),
            "algorithm required"
        );
        assert!(
            Issuer::new("x").audience("a").validate().is_err(),
            "key source required"
        );

        let http = Issuer::new("x")
            .audience("a")
            .jwks_uri("http://localhost/jwks");
        assert!(http.clone().validate().is_err(), "http rejected by default");
        assert!(http.allow_insecure_http().validate().is_ok());
    }

    #[test]
    fn typ_matching() {
        let none = Issuer::new("x");
        assert!(none.typ_matches(None));
        assert!(none.typ_matches(Some("JWT")));

        let at = Issuer::new("x").require_type("at+jwt");
        assert!(at.typ_matches(Some("at+jwt")));
        assert!(at.typ_matches(Some("AT+JWT")));
        assert!(at.typ_matches(Some("application/at+jwt")));
        assert!(!at.typ_matches(Some("JWT")));
        assert!(!at.typ_matches(None));
    }
}
