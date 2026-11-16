use crate::failure::AuthFailure;
use crate::responder::SharedResponder;
use actix_web::dev::Payload;
use actix_web::error::InternalError;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest};
use rusted_auth::{AuthError, Principal};
use std::future::{Ready, ready};
use std::ops::Deref;

/// Extractor for the authenticated caller.
///
/// Requires [`Authenticate`](crate::Authenticate) on the route. Answers 401 when the
/// request is anonymous, which happens under [`Authenticate::optional`](crate::Authenticate::optional)
/// or when the middleware is missing.
///
/// ```rust
/// use rusted_auth_actix::Authenticated;
///
/// async fn me(user: Authenticated) -> String {
///     format!("Hello, {}", user.subject)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Authenticated(pub Principal);

impl Authenticated {
    /// Take the inner [`Principal`].
    pub fn into_inner(self) -> Principal {
        self.0
    }
}

impl Deref for Authenticated {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for Authenticated {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let extensions = req.extensions();
        ready(match extensions.get::<Principal>() {
            Some(principal) => Ok(Self(principal.clone())),
            None => {
                let error = AuthError::MissingCredentials;
                let response = extensions
                    .get::<SharedResponder>()
                    .cloned()
                    .unwrap_or_default()
                    .respond(&AuthFailure::from(AuthError::MissingCredentials));
                Err(InternalError::from_response(error, response).into())
            }
        })
    }
}

/// Extractor for routes where authentication is optional.
///
/// Holds `Some` when [`Authenticate`](crate::Authenticate) authenticated the request,
/// `None` otherwise. Never fails.
#[derive(Debug, Clone)]
pub struct MaybeAuthenticated(pub Option<Principal>);

impl MaybeAuthenticated {
    /// Take the inner `Option<Principal>`.
    pub fn into_inner(self) -> Option<Principal> {
        self.0
    }
}

impl Deref for MaybeAuthenticated {
    type Target = Option<Principal>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for MaybeAuthenticated {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Ok(Self(req.extensions().get::<Principal>().cloned())))
    }
}
