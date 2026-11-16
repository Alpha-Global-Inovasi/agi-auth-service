//! Cookies, the `Origin` check and the double-submit CSRF token.

// Helpers for the routes of the `local` feature.
#![cfg_attr(not(feature = "local"), allow(dead_code))]

use crate::client::TrustedProxies;
use crate::failure::AuthFailure;
use actix_web::cookie::{Cookie, SameSite, time};
use actix_web::http::Method;
use actix_web::http::header::{AUTHORIZATION, COOKIE, ORIGIN, REFERER};
use actix_web::{HttpRequest, HttpResponseBuilder};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq as _;

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "__Host-session";
/// Name of the cookie holding the CSRF token. Not `HttpOnly`: the client reads it.
pub const CSRF_COOKIE: &str = "__Host-csrf";
/// Header in which the client sends the CSRF token back.
pub const CSRF_HEADER: &str = "X-CSRF-Token";
/// Form field that may carry the CSRF token instead of the header, for the plain HTML
/// pages behind email links.
pub(crate) const CSRF_FIELD: &str = "csrf_token";

/// How a request is protected when it uses cookies, and who its client is.
///
/// Shared by [`SessionAuth`](crate::SessionAuth) and the routes.
///
/// # The rule
///
/// A request that changes data (any method but `GET`, `HEAD` and `OPTIONS`) and comes
/// from a browser must
///
/// 1. carry an `Origin` header, or else a `Referer`, naming one of the
///    [allowed origins](Self::new), and
/// 2. send the value of the [`CSRF_COOKIE`] cookie back in the [`CSRF_HEADER`] header
///    (double submit), compared in constant time.
///
/// Failing either is 403 `csrf_failed`. Which requests count as coming from a browser:
///
/// - A route whose answer sets or replaces the session cookie (the web login, and the
///   second-factor step of a cookie session) always does, whatever its headers.
/// - A request with `Authorization: Bearer` does when it also has a `Cookie` header.
///   Without cookies it does not: a page on another site cannot add that header
///   without the server's CORS consent.
/// - Any other request does when it has a `Cookie`, `Origin` or `Referer` header. An
///   `Origin` header counts even when its value is `null` (sandboxed frames, some
///   redirects), so such a request is checked and then refused, since `null` is never
///   an allowed origin.
///
/// So a native app that sends neither cookies nor `Origin` nor `Referer` is not
/// checked: without cookies the request carries no ambient authority to abuse, and a
/// browser sends `Origin` with every cross-site request that changes data.
///
/// The cookies are prefixed `__Host-`, so another subdomain cannot set or overwrite
/// them; the CSRF token is 256 random bits.
#[derive(Debug, Clone)]
pub struct WebConfig {
    origins: Vec<String>,
    proxies: TrustedProxies,
}

/// [`WebConfig::new`] was given no usable origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOrigin(String);

impl fmt::Display for InvalidOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("at least one allowed origin is required")
        } else {
            write!(
                f,
                "`{}` is not an origin such as https://app.example.com",
                self.0
            )
        }
    }
}

impl std::error::Error for InvalidOrigin {}

impl WebConfig {
    /// The origins (`scheme://host[:port]`, such as `https://app.example.com`) whose
    /// pages may send requests with the session cookie. Required, and there is no
    /// default such as "the request's own `Host`", because the `Host` header is chosen
    /// by the client.
    pub fn new<I, O>(allowed_origins: I) -> Result<Self, InvalidOrigin>
    where
        I: IntoIterator<Item = O>,
        O: AsRef<str>,
    {
        let origins = allowed_origins
            .into_iter()
            .map(|origin| {
                let origin = origin.as_ref().trim().trim_end_matches('/');
                normalize_origin(origin)
                    .filter(|normalized| normalized.len() == origin.len())
                    .ok_or_else(|| InvalidOrigin(origin.to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if origins.is_empty() {
            return Err(InvalidOrigin(String::new()));
        }
        Ok(Self {
            origins,
            proxies: TrustedProxies::none(),
        })
    }

    /// Reverse proxies whose `X-Forwarded-For` is believed. Default: none.
    #[must_use]
    pub fn trusted_proxies(mut self, proxies: TrustedProxies) -> Self {
        self.proxies = proxies;
        self
    }

    /// The client address of `req`, as rate limits and sessions see it.
    pub fn client_ip(&self, req: &HttpRequest) -> Option<IpAddr> {
        self.proxies.client_ip_of(req)
    }

    /// Apply the rule above. `always_browser` is set by routes whose answer sets the
    /// session cookie: the request is checked whatever its headers. `form_token` is a
    /// CSRF token from a form field.
    pub(crate) fn check(
        &self,
        req: &HttpRequest,
        always_browser: bool,
        form_token: Option<&str>,
    ) -> Result<(), AuthFailure> {
        if is_safe(req.method()) {
            return Ok(());
        }
        let headers = req.headers();
        let has_cookie = headers.contains_key(COOKIE);
        let browser = if always_browser {
            true
        } else if bearer_token(req).is_some() {
            has_cookie
        } else {
            has_cookie || headers.contains_key(ORIGIN) || headers.contains_key(REFERER)
        };
        if !browser {
            return Ok(());
        }

        let origin = match headers.get(ORIGIN) {
            Some(origin) => origin.to_str().ok().and_then(normalize_origin),
            None => headers
                .get(REFERER)
                .and_then(|referer| referer.to_str().ok())
                .and_then(normalize_origin),
        };
        let Some(origin) = origin else {
            return Err(AuthFailure::csrf("no usable Origin or Referer header"));
        };
        if !self.origins.contains(&origin) {
            return Err(AuthFailure::csrf("origin is not allowed"));
        }

        let cookie = req.cookie(CSRF_COOKIE);
        let sent = headers
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .or(form_token);
        match (cookie, sent) {
            (Some(cookie), Some(sent))
                if !sent.is_empty()
                    && bool::from(cookie.value().as_bytes().ct_eq(sent.as_bytes())) =>
            {
                Ok(())
            }
            (None, _) => Err(AuthFailure::csrf("no CSRF cookie")),
            _ => Err(AuthFailure::csrf("CSRF token does not match")),
        }
    }
}

fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// `scheme://host[:port]` of an origin or URL, lowercased, without a default port.
fn normalize_origin(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    let authority = match (scheme.as_str(), authority.rsplit_once(':')) {
        ("https", Some((host, "443"))) | ("http", Some((host, "80"))) => host.to_owned(),
        _ => authority,
    };
    Some(format!("{scheme}://{authority}"))
}

/// How the client presented its session token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The [`SESSION_COOKIE`] cookie, from a browser.
    Cookie,
    /// `Authorization: Bearer`, from a mobile app or another non-browser client.
    Bearer,
}

/// The bearer token of `req`, if it has an `Authorization: Bearer` header.
pub(crate) fn bearer_token(req: &HttpRequest) -> Option<String> {
    let value = req.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_owned())
}

/// The session token of `req` and how it came: the `Authorization` header wins over
/// the cookie.
pub(crate) fn presented_token(req: &HttpRequest) -> Option<(String, Transport)> {
    if let Some(token) = bearer_token(req) {
        return Some((token, Transport::Bearer));
    }
    req.cookie(SESSION_COOKIE)
        .map(|cookie| (cookie.value().to_owned(), Transport::Cookie))
}

fn base_cookie(name: &'static str, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Lax);
    cookie
}

/// The session cookie for `token`, kept until `expires_at`.
pub(crate) fn session_cookie(token: &str, expires_at: SystemTime) -> Cookie<'static> {
    let mut cookie = base_cookie(SESSION_COOKIE, token.to_owned());
    cookie.set_http_only(true);
    let left = expires_at
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO);
    cookie.set_max_age(time::Duration::seconds(
        i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
    ));
    cookie
}

/// A fresh random CSRF token.
pub(crate) fn new_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    if let Err(error) = getrandom::fill(&mut bytes) {
        // A predictable token would defeat the check; refuse to make one. The empty
        // value never matches, since an empty header is rejected.
        tracing::error!(%error, "no randomness for a CSRF token");
        return String::new();
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The CSRF cookie for `token`. Lives as long as the browser session or the session
/// cookie, whichever the browser keeps.
pub(crate) fn csrf_cookie(token: String) -> Cookie<'static> {
    base_cookie(CSRF_COOKIE, token)
}

/// Set a new session cookie and a new CSRF token on `response`.
pub(crate) fn set_session(response: &mut HttpResponseBuilder, token: &str, expires_at: SystemTime) {
    response.cookie(session_cookie(token, expires_at));
    response.cookie(csrf_cookie(new_csrf_token()));
}

/// Remove both cookies.
pub(crate) fn clear_session(response: &mut HttpResponseBuilder) {
    for name in [SESSION_COOKIE, CSRF_COOKIE] {
        let mut cookie = base_cookie(name, String::new());
        cookie.make_removal();
        response.cookie(cookie);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn config() -> WebConfig {
        WebConfig::new(["https://app.example.com", "http://localhost:5173"]).unwrap()
    }

    #[test]
    fn origins_are_normalized_and_required() {
        assert_eq!(
            normalize_origin("HTTPS://App.Example.com:443/path?x").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(
            normalize_origin("http://localhost:5173/").as_deref(),
            Some("http://localhost:5173")
        );
        assert_eq!(normalize_origin("null"), None);
        assert_eq!(normalize_origin("https://user@evil.example"), None);
        assert!(WebConfig::new(Vec::<String>::new()).is_err());
        assert!(WebConfig::new(["app.example.com"]).is_err());
        assert!(WebConfig::new(["https://app.example.com/login"]).is_err());
        assert!(WebConfig::new(["https://app.example.com/"]).is_ok());
    }

    #[test]
    fn browser_requests_need_origin_and_token() {
        let config = config();
        let token = "abc";
        let ok = TestRequest::post()
            .insert_header((ORIGIN, "https://app.example.com"))
            .insert_header((CSRF_HEADER, token))
            .cookie(Cookie::new(CSRF_COOKIE, token))
            .to_http_request();
        assert!(config.check(&ok, false, None).is_ok());

        let wrong_origin = TestRequest::post()
            .insert_header((ORIGIN, "https://evil.example"))
            .insert_header((CSRF_HEADER, token))
            .cookie(Cookie::new(CSRF_COOKIE, token))
            .to_http_request();
        assert_eq!(
            config.check(&wrong_origin, false, None).unwrap_err().code(),
            "csrf_failed"
        );

        let referer = TestRequest::post()
            .insert_header((REFERER, "http://localhost:5173/login?next=/"))
            .insert_header((CSRF_HEADER, token))
            .cookie(Cookie::new(CSRF_COOKIE, token))
            .to_http_request();
        assert!(config.check(&referer, false, None).is_ok());

        let no_token = TestRequest::post()
            .insert_header((ORIGIN, "https://app.example.com"))
            .cookie(Cookie::new(CSRF_COOKIE, token))
            .to_http_request();
        assert!(config.check(&no_token, false, None).is_err());

        let cookie_without_origin = TestRequest::post()
            .insert_header((CSRF_HEADER, token))
            .cookie(Cookie::new(CSRF_COOKIE, token))
            .to_http_request();
        assert!(config.check(&cookie_without_origin, false, None).is_err());

        let native = TestRequest::post().to_http_request();
        assert!(config.check(&native, false, None).is_ok());
        assert!(config.check(&native, true, None).is_err(), "web login");

        let bearer = TestRequest::post()
            .insert_header((AUTHORIZATION, "Bearer rusted_s_x"))
            .insert_header((ORIGIN, "https://evil.example"))
            .to_http_request();
        assert!(config.check(&bearer, false, None).is_ok());
        assert!(
            config.check(&bearer, true, None).is_err(),
            "a route that sets the session cookie is always checked"
        );

        let bearer_with_cookie = TestRequest::post()
            .insert_header((AUTHORIZATION, "Bearer rusted_s_x"))
            .cookie(Cookie::new(SESSION_COOKIE, "rusted_s_y"))
            .to_http_request();
        assert!(config.check(&bearer_with_cookie, false, None).is_err());

        let null_origin = TestRequest::post()
            .insert_header((ORIGIN, "null"))
            .insert_header((REFERER, "https://app.example.com/"))
            .insert_header((CSRF_HEADER, token))
            .cookie(Cookie::new(CSRF_COOKIE, token))
            .to_http_request();
        assert!(config.check(&null_origin, false, None).is_err());
        let null_origin_only = TestRequest::post()
            .insert_header((ORIGIN, "null"))
            .to_http_request();
        assert!(config.check(&null_origin_only, false, None).is_err());

        let get = TestRequest::get()
            .insert_header((ORIGIN, "https://evil.example"))
            .to_http_request();
        assert!(config.check(&get, true, None).is_ok());

        let form = TestRequest::post()
            .insert_header((ORIGIN, "https://app.example.com"))
            .cookie(Cookie::new(CSRF_COOKIE, token))
            .to_http_request();
        assert!(config.check(&form, false, Some(token)).is_ok());
    }
}
