use crate::responder::{AuthResponder, SharedResponder};
use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::header::AUTHORIZATION;
use actix_web::{Error, HttpMessage};
use rusted_auth::{AuthError, AuthResult, Principal, Verifier};
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

/// Middleware that authenticates requests from their `Authorization: Bearer` header.
///
/// On success the [`Principal`] is stored in the request extensions, where the
/// [`Authenticated`](crate::Authenticated) and
/// [`MaybeAuthenticated`](crate::MaybeAuthenticated) extractors find it.
///
/// - [`Authenticate::required`]: requests without valid credentials are rejected.
/// - [`Authenticate::optional`]: requests without an `Authorization` header continue
///   anonymously. A header that is present but invalid is still rejected, so a client
///   with an expired token learns about it instead of silently becoming anonymous.
#[derive(Clone)]
pub struct Authenticate {
    verifier: Verifier,
    responder: SharedResponder,
    required: bool,
}

impl Authenticate {
    /// Reject requests that are not authenticated.
    pub fn required(verifier: Verifier) -> Self {
        Self {
            verifier,
            responder: SharedResponder::default(),
            required: true,
        }
    }

    /// Let requests without credentials through as anonymous.
    pub fn optional(verifier: Verifier) -> Self {
        Self {
            required: false,
            ..Self::required(verifier)
        }
    }

    /// Use a custom [`AuthResponder`] for error responses.
    #[must_use]
    pub fn responder(mut self, responder: impl AuthResponder) -> Self {
        self.responder = SharedResponder(Arc::new(responder));
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for Authenticate
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthenticateMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticateMiddleware {
            service: Rc::new(service),
            config: self.clone(),
        }))
    }
}

/// The service created by [`Authenticate`]. Not used directly.
pub struct AuthenticateMiddleware<S> {
    service: Rc<S>,
    config: Authenticate,
}

impl<S, B> Service<ServiceRequest> for AuthenticateMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let config = self.config.clone();

        Box::pin(async move {
            // Extractors on this request answer in the same format as the middleware
            req.extensions_mut().insert(config.responder.clone());

            match authenticate(&config, &req).await {
                Ok(principal) => {
                    if let Some(principal) = principal {
                        req.extensions_mut().insert(principal);
                    }
                    service
                        .call(req)
                        .await
                        .map(ServiceResponse::map_into_left_body)
                }
                Err(error) => {
                    let response = config.responder.respond(&error);
                    Ok(req.into_response(response).map_into_right_body())
                }
            }
        })
    }
}

/// `Ok(None)` means "anonymous, and that is allowed".
async fn authenticate(
    config: &Authenticate,
    req: &ServiceRequest,
) -> AuthResult<Option<Principal>> {
    let Some(header) = req.headers().get(AUTHORIZATION) else {
        return if config.required {
            Err(AuthError::MissingCredentials)
        } else {
            Ok(None)
        };
    };
    let header = header
        .to_str()
        .map_err(|_| AuthError::InvalidAuthHeaderFormat)?;

    config.verifier.verify_bearer(header).await.map(Some)
}
