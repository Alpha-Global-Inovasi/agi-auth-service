//! Firebase Authentication helpers.
//!
//! Configure Firebase with [`Issuer::firebase`](crate::Issuer::firebase); this module holds
//! the parts that only make sense for Firebase tokens.

use crate::Principal;
use serde_json::Value;

/// Google's JWKS endpoint for Firebase ID tokens.
pub const JWKS_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

/// The sign-in method Firebase recorded (`"password"`, `"google.com"`, `"phone"`, ...).
pub fn sign_in_provider(principal: &Principal) -> Option<&str> {
    principal
        .claims
        .get("firebase")?
        .get("sign_in_provider")
        .and_then(Value::as_str)
}
