//! [`SessionAuth`]: sessions from a cookie or a bearer token, with CSRF protection.

// Helpers for the routes of the `local` feature.
#![cfg_attr(not(feature = "local"), allow(dead_code))]

use crate::failure::AuthFailure;
use crate::responder::{AuthResponder, SharedResponder};
use crate::web::{Transport, WebConfig, presented_token};
use actix_web::body::EitherBody;
use actix_web::dev::{Payload, Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::error::InternalError;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest};
use rusted_auth::session::{
    AuthenticatedSession, Session, SessionError, SessionErrorKind, SessionManager, SessionStore,
    User,
};
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

/// Middleware that finds the caller's session and protects cookie requests from CSRF.
///
/// Wrap the whole API with it, not only the authentication routes:
///
/// 1. Requests that change data are checked as [`WebConfig`] describes (`Origin` and the
///    double-submit CSRF token). A failure is answered with 403 at once.
/// 2. The session token is read from `Authorization: Bearer` or else from the
///    `__Host-session` cookie, and validated with the [`SessionManager`]. The result is
///    kept for the [`CurrentSession`] and [`MaybeSession`] extractors.
///
/// The middleware itself never refuses a request for a missing or invalid session, so
/// public routes keep working with a stale cookie; [`CurrentSession`] does, with 401
/// `unauthenticated`, or 401 `mfa_required` for a session that still waits for its
/// second factor.
///
/// ```rust,no_run
/// use actix_web::{App, web};
/// use rusted_auth::session::{MemorySessionStore, MemoryUserStore, SessionManager};
/// use rusted_auth_actix::{CurrentSession, SessionAuth, WebConfig};
///
/// async fn me(current: CurrentSession) -> String {
///     current.user.username.clone()
/// }
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let users = MemoryUserStore::new();
/// let sessions = SessionManager::new(MemorySessionStore::new(users));
/// let web_config = WebConfig::new(["https://app.example.com"])?;
/// let app = App::new()
///     .wrap(SessionAuth::new(sessions, web_config))
///     .route("/api/me", web::get().to(me));
/// # let _ = app;
/// # Ok(())
/// # }
/// ```
pub struct SessionAuth<S> {
    sessions: SessionManager<S>,
    web: WebConfig,
    responder: SharedResponder,
}

impl<S> Clone for SessionAuth<S> {
    fn clone(&self) -> Self {
        Self {
            sessions: self.sessions.clone(),
            web: self.web.clone(),
            responder: self.responder.clone(),
        }
    }
}

impl<S: SessionStore> SessionAuth<S> {
    /// Sessions from `sessions`, protected as `web` says.
    pub fn new(sessions: SessionManager<S>, web: WebConfig) -> Self {
        Self {
            sessions,
            web,
            responder: SharedResponder::default(),
        }
    }

    /// Use a custom [`AuthResponder`] for error responses, here and in the extractors.
    #[must_use]
    pub fn responder(mut self, responder: impl AuthResponder) -> Self {
        self.responder = SharedResponder(Arc::new(responder));
        self
    }
}

impl<S, B, Svc> Transform<Svc, ServiceRequest> for SessionAuth<S>
where
    S: SessionStore,
    Svc: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = SessionAuthMiddleware<S, Svc>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: Svc) -> Self::Future {
        ready(Ok(SessionAuthMiddleware {
            service: Rc::new(service),
            config: self.clone(),
        }))
    }
}

/// The service created by [`SessionAuth`]. Not used directly.
pub struct SessionAuthMiddleware<S, Svc> {
    service: Rc<Svc>,
    config: SessionAuth<S>,
}

impl<S, B, Svc> Service<ServiceRequest> for SessionAuthMiddleware<S, Svc>
where
    S: SessionStore,
    Svc: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
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
            req.extensions_mut().insert(config.responder.clone());
            if let Err(failure) = config.web.check(req.request(), false, None) {
                let response = config.responder.respond(&failure);
                return Ok(req.into_response(response).map_into_right_body());
            }
            let resolved = resolve(&config.sessions, req.request()).await;
            req.extensions_mut().insert(resolved);
            service
                .call(req)
                .await
                .map(ServiceResponse::map_into_left_body)
        })
    }
}

/// What the middleware found, kept in the request extensions.
#[derive(Debug, Clone)]
pub(crate) enum Resolved {
    Anonymous,
    Session(Box<AuthenticatedSession>, Transport),
    Rejected(SessionErrorKind),
}

impl Resolved {
    fn failure(kind: SessionErrorKind) -> AuthFailure {
        match kind {
            SessionErrorKind::MfaRequired => SessionError::MfaRequired.into(),
            SessionErrorKind::Server => {
                SessionError::Internal("the session store failed; see the earlier log".into())
                    .into()
            }
            _ => AuthFailure::unauthenticated(),
        }
    }
}

/// Validate the token `req` presents, if any.
pub(crate) async fn resolve<S: SessionStore>(
    sessions: &SessionManager<S>,
    req: &HttpRequest,
) -> Resolved {
    let Some((token, transport)) = presented_token(req) else {
        return Resolved::Anonymous;
    };
    match sessions.validate(&token).await {
        Ok(session) => Resolved::Session(Box::new(session), transport),
        Err(error) => {
            if error.is_server_error() {
                tracing::error!(%error, "session validation failed");
            } else {
                tracing::debug!(%error, "session rejected");
            }
            Resolved::Rejected(error.kind())
        }
    }
}

/// The active session of `req`: the one [`SessionAuth`] found, or else validated now.
pub(crate) async fn current<S: SessionStore>(
    sessions: &SessionManager<S>,
    req: &HttpRequest,
) -> Result<CurrentSession, AuthFailure> {
    let found = req.extensions().get::<Resolved>().cloned();
    let resolved = match found {
        Some(resolved) => resolved,
        None => resolve(sessions, req).await,
    };
    match resolved {
        Resolved::Session(session, transport) => Ok(CurrentSession::new(*session, transport)),
        Resolved::Anonymous => Err(AuthFailure::unauthenticated()),
        Resolved::Rejected(kind) => Err(Resolved::failure(kind)),
    }
}

/// Extractor for the caller's active session. Requires [`SessionAuth`].
///
/// Answers 401 `unauthenticated` when there is no usable session (also without the
/// middleware), and 401 `mfa_required` for a session that still waits for its second
/// factor. Dereferences to the [`AuthenticatedSession`], so `current.user` and
/// `current.session` work directly.
#[derive(Debug, Clone)]
pub struct CurrentSession {
    authenticated: AuthenticatedSession,
    transport: Transport,
}

impl CurrentSession {
    fn new(authenticated: AuthenticatedSession, transport: Transport) -> Self {
        Self {
            authenticated,
            transport,
        }
    }

    /// Whether the token came in the cookie or the `Authorization` header.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// The session and account, as `rusted-auth` operations take them.
    pub fn authenticated(&self) -> &AuthenticatedSession {
        &self.authenticated
    }

    /// The account.
    pub fn user(&self) -> &User {
        &self.authenticated.user
    }

    /// The session.
    pub fn session(&self) -> &Session {
        &self.authenticated.session
    }
}

impl std::ops::Deref for CurrentSession {
    type Target = AuthenticatedSession;

    fn deref(&self) -> &Self::Target {
        &self.authenticated
    }
}

fn reject(req: &HttpRequest, failure: &AuthFailure) -> Error {
    let response = req
        .extensions()
        .get::<SharedResponder>()
        .cloned()
        .unwrap_or_default()
        .respond(failure);
    InternalError::from_response(failure.to_string(), response).into()
}

impl FromRequest for CurrentSession {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let resolved = req.extensions().get::<Resolved>().cloned();
        ready(match resolved {
            Some(Resolved::Session(session, transport)) => Ok(Self::new(*session, transport)),
            Some(Resolved::Rejected(kind)) => Err(reject(req, &Resolved::failure(kind))),
            Some(Resolved::Anonymous) | None => Err(reject(req, &AuthFailure::unauthenticated())),
        })
    }
}

/// Extractor for routes where a session is optional: `Some` with a usable session,
/// `None` without one. Fails only when the session store failed (500).
#[derive(Debug, Clone)]
pub struct MaybeSession(pub Option<CurrentSession>);

impl FromRequest for MaybeSession {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let resolved = req.extensions().get::<Resolved>().cloned();
        ready(match resolved {
            Some(Resolved::Session(session, transport)) => {
                Ok(Self(Some(CurrentSession::new(*session, transport))))
            }
            Some(Resolved::Rejected(SessionErrorKind::Server)) => {
                Err(reject(req, &Resolved::failure(SessionErrorKind::Server)))
            }
            _ => Ok(Self(None)),
        })
    }
}
