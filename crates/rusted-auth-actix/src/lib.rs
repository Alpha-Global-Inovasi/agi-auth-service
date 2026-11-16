//! # rusted-auth-actix
//!
//! Actix-web adapter for [`rusted-auth`](rusted_auth).
//!
//! - [`Authenticate`] verifies JWTs from any OpenID Connect issuer (such as Firebase) in
//!   the `Authorization: Bearer` header; [`Authenticated`] and [`MaybeAuthenticated`]
//!   hand the [`Principal`](rusted_auth::Principal) to handlers.
//! - With the `session` feature, `SessionAuth` finds the caller's `rusted-auth`
//!   session in the `__Host-session` cookie or a bearer token, protects cookie
//!   requests against CSRF (`WebConfig`), and gives handlers a `CurrentSession`.
//! - With the `local` feature, `AuthRoutes` serves registration, login, logout,
//!   email verification and password reset for local accounts, rate limited per
//!   client address (`RateLimiter`). With `mfa`, also TOTP and recovery codes.
//! - With `utoipa`, `openapi::AuthApi` describes those routes for an OpenAPI document.
//!
//! ## Token verification
//!
//! ```rust,no_run
//! use actix_web::{App, HttpServer, web};
//! use rusted_auth::{Issuer, Verifier};
//! use rusted_auth_actix::{Authenticate, Authenticated};
//!
//! async fn me(user: Authenticated) -> String {
//!     format!("Hello, {}", user.subject)
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let verifier = Verifier::builder()
//!         .issuer(Issuer::firebase("my-firebase-project"))
//!         .build()
//!         .expect("valid auth configuration");
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .wrap(Authenticate::required(verifier.clone()))
//!             .route("/me", web::get().to(me))
//!     })
//!     .bind(("127.0.0.1", 8080))?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ## Responses
//!
//! Every failure becomes an [`AuthFailure`] with a status, a stable `code` and a
//! public message; bodies never contain internal details, which go to the log. The
//! body format is yours to choose: implement [`AuthResponder`]. The default,
//! [`ProblemResponder`], writes RFC 9457 problem details
//! (`application/problem+json`). 401 answers to bearer requests carry
//! `WWW-Authenticate: Bearer`, and 429 and 503 answers `Retry-After`.

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod client;
mod extract;
mod failure;
mod middleware;
mod responder;

#[cfg(feature = "local")]
mod mail;
#[cfg(feature = "utoipa")]
pub mod openapi;
#[cfg(feature = "session")]
mod rate_limit;
#[cfg(feature = "local")]
mod routes;
#[cfg(feature = "session")]
mod session;
#[cfg(feature = "session")]
mod web;

pub use client::{InvalidProxy, TrustedProxies};
pub use extract::{Authenticated, MaybeAuthenticated};
pub use failure::{AuthFailure, FieldError};
pub use middleware::{Authenticate, AuthenticateMiddleware};
pub use responder::{AuthResponder, ProblemResponder};

#[cfg(feature = "local")]
pub use mail::SpawnMailer;
#[cfg(feature = "session")]
pub use rate_limit::{Bucket, Limit, RateLimiter, RateLimits};
#[cfg(feature = "local")]
pub use routes::{AuthRoutes, AuthRoutesBuilder, ConfigError, LinkTargets, dto};
#[cfg(feature = "session")]
pub use session::{CurrentSession, MaybeSession, SessionAuth, SessionAuthMiddleware};
#[cfg(feature = "session")]
pub use web::{CSRF_COOKIE, CSRF_HEADER, InvalidOrigin, SESSION_COOKIE, Transport, WebConfig};

#[cfg(test)]
mod tests;

/// Compiles the code blocks in the crate README as doc tests. They use the routes, so
/// they need the `local` feature.
#[cfg(all(doctest, feature = "local"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
