//! [`AuthRoutes`]: HTTP routes for local accounts and their second factor.

pub mod dto;
mod handlers;
mod links;
#[cfg(feature = "mfa")]
mod second_factor;

use crate::failure::AuthFailure;
use crate::rate_limit::{Bucket, RateLimiter};
use crate::responder::{AuthResponder, SharedResponder};
use crate::web::WebConfig;
use actix_web::http::header::USER_AGENT;
use actix_web::web::{self, Data, ServiceConfig};
use actix_web::{HttpRequest, HttpResponse};
use rusted_auth::local::LocalAuth;
use rusted_auth::session::{SessionContext, SessionKind, SessionStore, UserStore};
use std::fmt;
use std::sync::Arc;

pub use links::LinkTargets;

/// HTTP routes for local accounts: registration, login and logout, email verification,
/// password reset and change, and (with the `mfa` feature) TOTP and recovery codes.
///
/// Mount them under a scope of your choice; the paths below are relative to it:
///
/// ```rust,no_run
/// use actix_web::{App, HttpServer, web};
/// use rusted_auth::local::{LocalAuth, NoMailer};
/// use rusted_auth::session::{
///     MemoryOneTimeTokenStore, MemorySessionStore, MemoryUserStore, SessionManager,
/// };
/// use rusted_auth_actix::{AuthRoutes, SessionAuth, WebConfig};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let users = MemoryUserStore::new();
/// let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
/// let local = LocalAuth::builder(users, sessions.clone())
///     .mailer(NoMailer)
///     .tokens(MemoryOneTimeTokenStore::new())
///     .build()?;
/// let web_config = WebConfig::new(["https://app.example.com"])?;
/// let routes = AuthRoutes::builder(local, web_config.clone()).build()?;
///
/// HttpServer::new(move || {
///     App::new()
///         .wrap(SessionAuth::new(sessions.clone(), web_config.clone()))
///         .service(web::scope("/api/auth").configure(|cfg| routes.configure(cfg)))
/// })
/// .bind(("127.0.0.1", 8080))?
/// .run()
/// .await?;
/// # Ok(())
/// # }
/// ```
///
/// | Route | Answer |
/// |---|---|
/// | `GET /csrf` | 204, sets the CSRF cookie if there is none |
/// | `POST /register` | 202 without a body, the same whether or not the address has an account |
/// | `POST /login` | 200 [`LoginResponse`](dto::LoginResponse), sets the session cookie |
/// | `POST /mobile/login` | 200 [`MobileLoginResponse`](dto::MobileLoginResponse) with the token, no cookie |
/// | `POST /logout` | 204, clears the cookies |
/// | `POST /email/verify` | 204; does not sign in |
/// | `POST /email/verify/resend` | 202 |
/// | `POST /password/forgot` | 202 |
/// | `POST /password/reset` | 204; signs out every session |
/// | `POST /password/change` | 204; signs out the other sessions |
/// | `GET /username-available?username=` | 200 [`UsernameAvailableResponse`](dto::UsernameAvailableResponse); only with `reveal_existing_email` |
/// | `GET /email/verify`, `GET /password/reset` | the page behind an email link; see [`LinkTargets`] |
///
/// With the `mfa` feature and [`AuthRoutesBuilder::mfa`]:
///
/// | Route | Answer |
/// |---|---|
/// | `POST /mfa/verify` | 200 [`MfaVerifyResponse`](dto::MfaVerifyResponse); replaces the session cookie, or returns the new token to bearer clients |
/// | `GET /mfa` | 200 [`MfaStatusResponse`](dto::MfaStatusResponse) |
/// | `POST /mfa/totp/start` | 200 [`TotpSetupResponse`](dto::TotpSetupResponse) |
/// | `POST /mfa/totp/confirm` | 200 [`RecoveryCodesResponse`](dto::RecoveryCodesResponse) |
/// | `POST /mfa/totp/disable` | 204; needs a current code |
/// | `POST /mfa/recovery-codes` | 200 [`RecoveryCodesResponse`](dto::RecoveryCodesResponse); needs a current code |
///
/// Failures go through the [`AuthResponder`]; see [`AuthFailure`] for the codes.
///
/// # Browsers and mobile apps
///
/// Browsers log in with `POST /login` and get the `__Host-session` cookie; mobile apps
/// use `POST /mobile/login`, keep the token, and send `Authorization: Bearer` on every
/// later request, including to these routes. Requests that change data from a browser
/// must pass the `Origin` and CSRF checks of [`WebConfig`]: fetch `GET /csrf` once and
/// send the `__Host-csrf` cookie's value in the `X-CSRF-Token` header.
///
/// # Second factor
///
/// Pass the `Mfa` to both `LocalAuthBuilder::mfa` and [`AuthRoutesBuilder::mfa`].
/// **Without `LocalAuthBuilder::mfa`, logins never ask for the second factor, even for
/// accounts with TOTP**; [`build`](AuthRoutesBuilder::build) therefore fails when only
/// one of the two was given.
///
/// # Rate limits
///
/// Login, registration, the email-sending routes and the link-token routes are
/// counted per client address ([`RateLimiter`]). Behind a reverse proxy, configure
/// [`WebConfig::trusted_proxies`], or every client counts as the proxy.
pub struct AuthRoutes<U, S> {
    state: Data<State<U, S>>,
}

impl<U, S> Clone for AuthRoutes<U, S> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

impl<U, S> fmt::Debug for AuthRoutes<U, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthRoutes").finish_non_exhaustive()
    }
}

pub(crate) struct State<U, S> {
    pub local: LocalAuth<U, S>,
    #[cfg(feature = "mfa")]
    pub mfa: Option<Arc<dyn second_factor::DynMfa>>,
    pub web: WebConfig,
    pub limiter: RateLimiter,
    pub responder: SharedResponder,
    pub links: LinkTargets,
}

impl<U: UserStore, S: SessionStore> State<U, S> {
    pub fn answer(&self, result: Result<HttpResponse, AuthFailure>) -> HttpResponse {
        result.unwrap_or_else(|failure| self.responder.respond(&failure))
    }

    pub fn context(&self, req: &HttpRequest, kind: SessionKind) -> SessionContext {
        let mut context = SessionContext::new(kind);
        if let Some(ip) = self.web.client_ip(req) {
            context = context.ip(ip);
        }
        if let Some(agent) = req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()) {
            context = context.user_agent(agent);
        }
        context
    }

    pub async fn limit(&self, bucket: Bucket, req: &HttpRequest) -> Result<(), AuthFailure> {
        self.limiter.check(bucket, self.web.client_ip(req)).await
    }
}

/// [`AuthRoutesBuilder::build`] found the second factor connected on one side only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// The routes were given an `Mfa`, but `LocalAuth` was built without
    /// `LocalAuthBuilder::mfa`, so logins would skip the second factor.
    MfaNotInLocalAuth,
    /// `LocalAuth` asks for a second factor, but the routes were given no `Mfa`, so
    /// nobody could complete such a login.
    MfaNotInRoutes,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MfaNotInLocalAuth => {
                "AuthRoutesBuilder::mfa was called, but LocalAuthBuilder::mfa was not: \
                 logins would not ask for the second factor"
            }
            Self::MfaNotInRoutes => {
                "LocalAuthBuilder::mfa was called, but AuthRoutesBuilder::mfa was not: \
                 logins could not complete the second factor"
            }
        })
    }
}

impl std::error::Error for ConfigError {}

/// Configures [`AuthRoutes`]. Created by [`AuthRoutes::builder`].
pub struct AuthRoutesBuilder<U, S> {
    local: LocalAuth<U, S>,
    #[cfg(feature = "mfa")]
    mfa: Option<Arc<dyn second_factor::DynMfa>>,
    web: WebConfig,
    limiter: Option<RateLimiter>,
    responder: SharedResponder,
    links: LinkTargets,
}

impl<U: UserStore, S: SessionStore> AuthRoutes<U, S> {
    /// Routes for `local`, protected as `web` says.
    pub fn builder(local: LocalAuth<U, S>, web: WebConfig) -> AuthRoutesBuilder<U, S> {
        AuthRoutesBuilder {
            local,
            #[cfg(feature = "mfa")]
            mfa: None,
            web,
            limiter: None,
            responder: SharedResponder::default(),
            links: LinkTargets::default(),
        }
    }

    /// Register the routes on `cfg`, typically a scope such as `/api/auth`.
    pub fn configure(&self, cfg: &mut ServiceConfig) {
        use handlers as h;
        cfg.app_data(self.state.clone());
        cfg.route("/csrf", web::get().to(h::csrf))
            .route("/register", web::post().to(h::register::<U, S>))
            .route("/login", web::post().to(h::login::<U, S>))
            .route("/mobile/login", web::post().to(h::mobile_login::<U, S>))
            .route("/logout", web::post().to(h::logout::<U, S>))
            .route(
                "/email/verify/resend",
                web::post().to(h::resend_verification::<U, S>),
            )
            .route(
                "/password/forgot",
                web::post().to(h::forgot_password::<U, S>),
            )
            .route(
                "/password/change",
                web::post().to(h::change_password::<U, S>),
            )
            .service(
                web::resource("/email/verify")
                    .route(web::get().to(links::verify_email_page::<U, S>))
                    .route(web::post().to(h::verify_email::<U, S>)),
            )
            .service(
                web::resource("/password/reset")
                    .route(web::get().to(links::reset_password_page::<U, S>))
                    .route(web::post().to(h::reset_password::<U, S>)),
            );
        if self.state.local.reveals_existing_email() {
            cfg.route(
                "/username-available",
                web::get().to(h::username_available::<U, S>),
            );
        }
        #[cfg(feature = "mfa")]
        if self.state.mfa.is_some() {
            use handlers::mfa as m;
            cfg.route("/mfa", web::get().to(m::status::<U, S>))
                .route("/mfa/verify", web::post().to(m::verify::<U, S>))
                .route("/mfa/totp/start", web::post().to(m::start_totp::<U, S>))
                .route("/mfa/totp/confirm", web::post().to(m::confirm_totp::<U, S>))
                .route("/mfa/totp/disable", web::post().to(m::disable_totp::<U, S>))
                .route(
                    "/mfa/recovery-codes",
                    web::post().to(m::regenerate_recovery_codes::<U, S>),
                );
        }
    }
}

impl<U: UserStore, S: SessionStore> AuthRoutesBuilder<U, S> {
    /// Serve the second factor of `mfa`: `POST /mfa/verify` and the TOTP routes. The
    /// same `Mfa` must be given to `LocalAuthBuilder::mfa`.
    #[cfg(feature = "mfa")]
    #[must_use]
    pub fn mfa<M: rusted_auth::mfa::MfaStore>(mut self, mfa: &rusted_auth::mfa::Mfa<M, S>) -> Self {
        self.mfa = Some(Arc::new(mfa.clone()));
        self
    }

    /// Where request counts per client address are kept. Default:
    /// [`RateLimiter::memory`], which counts in each process separately.
    #[must_use]
    pub fn rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.limiter = Some(limiter);
        self
    }

    /// Use a custom [`AuthResponder`] for error responses.
    #[must_use]
    pub fn responder(mut self, responder: impl AuthResponder) -> Self {
        self.responder = SharedResponder(Arc::new(responder));
        self
    }

    /// Where the pages behind email links send the browser.
    #[must_use]
    pub fn link_targets(mut self, links: LinkTargets) -> Self {
        self.links = links;
        self
    }

    /// Build the routes. Fails when the second factor is connected on one side only;
    /// see [`ConfigError`].
    pub fn build(self) -> Result<AuthRoutes<U, S>, ConfigError> {
        #[cfg(feature = "mfa")]
        let routes_have_mfa = self.mfa.is_some();
        #[cfg(not(feature = "mfa"))]
        let routes_have_mfa = false;
        match (routes_have_mfa, self.local.second_factor_enabled()) {
            (true, false) => return Err(ConfigError::MfaNotInLocalAuth),
            (false, true) => return Err(ConfigError::MfaNotInRoutes),
            _ => {}
        }
        Ok(AuthRoutes {
            state: Data::new(State {
                local: self.local,
                #[cfg(feature = "mfa")]
                mfa: self.mfa,
                web: self.web,
                limiter: self.limiter.unwrap_or_else(RateLimiter::memory),
                responder: self.responder,
                links: self.links,
            }),
        })
    }
}
