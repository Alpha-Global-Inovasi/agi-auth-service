//! # agi-auth-actix
//!
//! Actix-web middleware and extractors for [`agi-auth`](agi_auth).
//!
//! ```rust,no_run
//! use actix_web::{App, HttpServer, web};
//! use agi_auth::{Issuer, Verifier};
//! use agi_auth_actix::{Authenticate, Authenticated};
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
//! Failures are answered with 401 (bad or missing credentials), 503 (the issuer's keys
//! cannot be fetched) or 500 (misconfiguration). 401 responses carry a
//! `WWW-Authenticate: Bearer` header. Bodies never contain internal details; the full
//! error goes to the log.
//!
//! The body format is yours to choose: implement [`AuthResponder`] and pass it to
//! [`Authenticate::responder`]. The default, [`JsonResponder`], writes
//! `{"status": false, "message": "...", "data": null}`.

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod extract;
mod middleware;
mod responder;

pub use extract::{Authenticated, MaybeAuthenticated};
pub use middleware::{Authenticate, AuthenticateMiddleware};
pub use responder::{AuthResponder, JsonResponder};

#[cfg(test)]
mod tests;

/// Compiles the code blocks in the crate README as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
