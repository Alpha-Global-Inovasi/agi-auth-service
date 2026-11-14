//! Outbound HTTP for discovery and JWKS documents.
//!
//! Every request has a timeout, a response size cap, and only follows redirects that stay
//! on HTTPS.

use crate::error::{AuthError, AuthResult};
use reqwest::header::{CACHE_CONTROL, HeaderMap};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 3;

/// Discovery and JWKS documents are a few kilobytes; anything near this is not one.
const MAX_BODY_BYTES: usize = 1024 * 1024;

pub(crate) struct Fetched {
    pub body: Vec<u8>,
    /// `max-age` from the response's `Cache-Control`, if any.
    pub max_age: Option<Duration>,
}

pub(crate) fn client() -> AuthResult<reqwest::Client> {
    let redirects = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            attempt.error("too many redirects")
        } else if attempt.url().scheme() != "https" {
            attempt.error("redirect to a non-https URL")
        } else {
            attempt.follow()
        }
    });

    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(redirects)
        .user_agent(concat!("rusted-auth/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AuthError::Config(format!("cannot build HTTP client: {e}")))
}

/// GET `url` and return the body, failing on a non-2xx status or an oversized response.
///
/// The error is a plain description for logs; callers wrap it in the right [`AuthError`].
pub(crate) async fn get(client: &reqwest::Client, url: &str) -> Result<Fetched, String> {
    let mut response = client.get(url).send().await.map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
    {
        return Err("response too large".into());
    }

    let max_age = parse_max_age(response.headers());

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err("response too large".into());
        }
        body.extend_from_slice(&chunk);
    }

    Ok(Fetched { body, max_age })
}

fn parse_max_age(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(CACHE_CONTROL)?
        .to_str()
        .ok()?
        .split(',')
        .find_map(|directive| directive.trim().strip_prefix("max-age="))
        .and_then(|secs| secs.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_age_from_cache_control() {
        let mut headers = HeaderMap::new();
        let mut set = |value: &'static str| {
            headers.insert(CACHE_CONTROL, value.parse().unwrap());
            parse_max_age(&headers)
        };

        assert_eq!(
            set("public, max-age=19302, must-revalidate, no-transform"),
            Some(Duration::from_secs(19302))
        );
        assert_eq!(set("no-cache"), None);
        assert_eq!(set("max-age=0"), None);
        assert_eq!(parse_max_age(&HeaderMap::new()), None);
    }
}
