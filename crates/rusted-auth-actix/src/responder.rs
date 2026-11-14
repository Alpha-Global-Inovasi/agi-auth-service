use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::http::header::{HeaderValue, WWW_AUTHENTICATE};
use rusted_auth::AuthError;
use std::sync::Arc;

/// Turns an authentication failure into an HTTP response.
///
/// Implement this to keep error bodies in your application's own format. Use
/// [`AuthError::public_message`] for anything sent to the client and
/// [`status_for`](AuthResponder::status_for) for the status code. The `Display` output of
/// the error is for logs only.
///
/// ```rust
/// use actix_web::HttpResponse;
/// use rusted_auth::AuthError;
/// use rusted_auth_actix::AuthResponder;
///
/// struct PlainText;
///
/// impl AuthResponder for PlainText {
///     fn respond(&self, error: &AuthError) -> HttpResponse {
///         HttpResponse::build(Self::status_for(error)).body(error.public_message())
///     }
/// }
/// ```
pub trait AuthResponder: Send + Sync + 'static {
    /// Build the response for `error`.
    fn respond(&self, error: &AuthError) -> HttpResponse;

    /// The status code this crate recommends for `error`:
    /// 503 when the issuer's keys are unavailable, 500 for misconfiguration, 401 otherwise.
    fn status_for(error: &AuthError) -> StatusCode
    where
        Self: Sized,
    {
        status_for(error)
    }
}

pub(crate) fn status_for(error: &AuthError) -> StatusCode {
    match error {
        AuthError::KeysUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        e if e.is_server_error() => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::UNAUTHORIZED,
    }
}

/// Default responder: `{"status": false, "message": "...", "data": null}`.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonResponder;

impl AuthResponder for JsonResponder {
    fn respond(&self, error: &AuthError) -> HttpResponse {
        HttpResponse::build(status_for(error)).json(serde_json::json!({
            "status": false,
            "message": error.public_message(),
            "data": null,
        }))
    }
}

/// Shared handle to the configured responder; also stored in request extensions so the
/// extractors answer in the same format as the middleware.
#[derive(Clone)]
pub(crate) struct SharedResponder(pub Arc<dyn AuthResponder>);

impl SharedResponder {
    /// Log the failure, build the response, and add `WWW-Authenticate` to 401s
    /// (RFC 6750 section 3) unless the responder already set one.
    pub fn respond(&self, error: &AuthError) -> HttpResponse {
        if error.is_server_error() {
            tracing::error!(%error, "authentication unavailable");
        } else {
            tracing::debug!(%error, "authentication rejected");
        }

        let mut response = self.0.respond(error);
        if response.status() == StatusCode::UNAUTHORIZED
            && !response.headers().contains_key(WWW_AUTHENTICATE)
        {
            let challenge = match error {
                AuthError::MissingCredentials => "Bearer",
                _ => "Bearer error=\"invalid_token\"",
            };
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        }
        response
    }
}

impl Default for SharedResponder {
    fn default() -> Self {
        Self(Arc::new(JsonResponder))
    }
}
