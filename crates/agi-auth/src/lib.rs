//! # agi-auth
//!
//! Framework-agnostic authentication core for AGI services.
//!
//! This release (0.4) provides token verification for any OpenID Connect / JWT issuer:
//!
//! - Several trusted issuers at once, each with its own audience, algorithm allowlist and
//!   JWKS cache. A key from one issuer never validates a token from another.
//! - JWKS caching that honors `Cache-Control: max-age`, refreshes once for concurrent
//!   misses, rate limits fetches, and keeps serving keys for a while if the issuer is down.
//! - A [`Issuer::firebase`] preset, so Firebase Authentication is one configuration among
//!   others instead of being built in.
//! - A normalized [`Principal`] for handlers, and errors that can be shown to clients
//!   without leaking internals ([`AuthError::public_message`]).
//!
//! Web framework adapters live in separate crates (`agi-auth-actix`).
//!
//! ## Example
//!
//! ```rust,no_run
//! use agi_auth::{Issuer, Verifier};
//!
//! # async fn run() -> Result<(), agi_auth::AuthError> {
//! let verifier = Verifier::builder()
//!     .issuer(Issuer::firebase("my-firebase-project"))
//!     .issuer(
//!         Issuer::discover("https://auth.example.com")
//!             .await?
//!             .audience("my-api"),
//!     )
//!     .build()?;
//!
//! let principal = verifier.verify_bearer("Bearer eyJ...").await?;
//! println!("user {} from {}", principal.subject, principal.issuer);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(test, allow(clippy::unwrap_used))]

#[cfg(not(any(feature = "rustls-tls", feature = "native-tls")))]
compile_error!(
    "agi-auth needs a TLS backend: enable the `rustls-tls` (default) or `native-tls` feature"
);

mod algorithm;
mod bearer;
mod error;
pub mod firebase;
mod http;
mod issuer;
mod jwks;
mod principal;
mod verifier;

#[cfg(test)]
mod tests;

pub use algorithm::Algorithm;
pub use bearer::extract_bearer_token;
pub use error::{AuthError, AuthResult};
pub use issuer::Issuer;
pub use principal::Principal;
pub use verifier::{Verifier, VerifierBuilder};

/// Compiles the code blocks in the crate README as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
