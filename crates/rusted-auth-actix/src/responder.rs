use crate::failure::AuthFailure;
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::http::header::{CONTENT_TYPE, HeaderValue, RETRY_AFTER, WWW_AUTHENTICATE};
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// Turns a failed request into an HTTP response.
///
/// Implement this to keep error bodies in your application's own format, for example
/// to add a request id. Use [`AuthFailure::status`], [`AuthFailure::code`],
/// [`AuthFailure::public_message`] and [`AuthFailure::field_errors`]; the `Display`
/// output of the failure is for logs only. The crate adds `WWW-Authenticate` to 401
/// answers of bearer-token requests and `Retry-After` to 429 and 503 answers, unless
/// the response already has them.
///
/// ```rust
/// use actix_web::HttpResponse;
/// use rusted_auth_actix::{AuthFailure, AuthResponder};
///
/// struct PlainText;
///
/// impl AuthResponder for PlainText {
///     fn respond(&self, failure: &AuthFailure) -> HttpResponse {
///         HttpResponse::build(failure.status()).body(failure.public_message())
///     }
/// }
/// ```
pub trait AuthResponder: Send + Sync + 'static {
    /// Build the response for `failure`.
    fn respond(&self, failure: &AuthFailure) -> HttpResponse;
}

/// Default responder: RFC 9457 problem details (`application/problem+json`).
///
/// ```json
/// {
///   "type": "about:blank",
///   "title": "Validation failed",
///   "status": 422,
///   "code": "validation_failed",
///   "errors": {
///     "password": [{ "code": "too_short", "message": "Password is too short", "params": { "min": 8 } }]
///   }
/// }
/// ```
///
/// `errors` appears only on 422. `title` is [`AuthFailure::public_message`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ProblemResponder;

impl ProblemResponder {
    /// The problem details body for `failure`, for responders that add members of
    /// their own (such as a request id) to it.
    pub fn body(failure: &AuthFailure) -> Value {
        let mut body = json!({
            "type": "about:blank",
            "title": failure.public_message(),
            "status": failure.status().as_u16(),
            "code": failure.code(),
        });
        if !failure.field_errors().is_empty() {
            let mut errors = Map::new();
            for error in failure.field_errors() {
                let entry = errors
                    .entry(error.field)
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let (Value::Array(list), Ok(value)) = (entry, serde_json::to_value(error)) {
                    list.push(value);
                }
            }
            body["errors"] = Value::Object(errors);
        }
        body
    }
}

impl AuthResponder for ProblemResponder {
    fn respond(&self, failure: &AuthFailure) -> HttpResponse {
        HttpResponse::build(failure.status())
            .insert_header((CONTENT_TYPE, "application/problem+json"))
            .body(Self::body(failure).to_string())
    }
}

/// Shared handle to the configured responder; also stored in request extensions so the
/// extractors answer in the same format as the middleware.
#[derive(Clone)]
pub(crate) struct SharedResponder(pub Arc<dyn AuthResponder>);

impl SharedResponder {
    /// Log the failure, build the response, and add `WWW-Authenticate` (RFC 6750
    /// section 3) and `Retry-After` unless the responder already set them.
    pub fn respond(&self, failure: &AuthFailure) -> HttpResponse {
        if failure.is_server_error() {
            tracing::error!(%failure, "authentication unavailable");
        } else {
            tracing::debug!(%failure, "authentication request rejected");
        }

        let mut response = self.0.respond(failure);
        let headers = response.headers_mut();
        if let Some(challenge) = failure.challenge()
            && failure.status() == StatusCode::UNAUTHORIZED
            && !headers.contains_key(WWW_AUTHENTICATE)
        {
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }
        if let Some(after) = failure.retry_after()
            && !headers.contains_key(RETRY_AFTER)
        {
            let seconds = after.as_secs().max(1);
            headers.insert(RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

impl Default for SharedResponder {
    fn default() -> Self {
        Self(Arc::new(ProblemResponder))
    }
}
