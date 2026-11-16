//! OpenAPI description of [`AuthRoutes`](crate::AuthRoutes), for utoipa 6.
//!
//! [`AuthApi`] holds the paths of the local-account routes and their schemas;
//! [`UsernameAvailableApi`] the username check, which is only mounted when
//! registration reveals existing addresses; [`MfaApi`] (with the `mfa` feature) the
//! second factor. [`AuthRoutes::openapi`](crate::AuthRoutes::openapi) merges exactly
//! the ones a set of routes mounts. Paths are relative to the scope the routes are
//! mounted under, so nest the documents at the same place:
//!
//! ```rust
//! use utoipa::OpenApi;
//! use rusted_auth_actix::openapi::AuthApi;
//!
//! #[derive(OpenApi)]
//! #[openapi(nest((path = "/api/auth", api = AuthApi)))]
//! struct ApiDoc;
//!
//! let spec = ApiDoc::openapi();
//! assert!(spec.paths.paths.contains_key("/api/auth/login"));
//! ```
//!
//! Every operation is tagged `auth`, and its `operationId` follows the route
//! (`login`, `mobile_login`, `forgot_password`, ...). Failures are RFC 9457 problem
//! details ([`Problem`]); the `code` member is listed at
//! [`AuthFailure::code`](crate::AuthFailure::code). Requests from a browser that
//! change data need the `X-CSRF-Token` header ([`WebConfig`](crate::WebConfig)).

#![allow(dead_code, missing_docs)]

use crate::routes::dto::*;
use serde::Serialize;
use std::collections::BTreeMap;
use utoipa::{OpenApi, ToSchema};

/// An RFC 9457 problem details body, as written by the default
/// [`ProblemResponder`](crate::ProblemResponder).
#[derive(Debug, Serialize, ToSchema)]
pub struct Problem {
    /// Always `about:blank`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Short English text that is safe to show.
    pub title: String,
    /// The HTTP status.
    pub status: u16,
    /// Stable identifier, such as `invalid_credentials`.
    pub code: String,
    /// Only for `validation_failed`: what is wrong with which field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<BTreeMap<String, Vec<ProblemFieldError>>>,
}

/// One entry of [`Problem::errors`].
#[derive(Debug, Serialize, ToSchema)]
pub struct ProblemFieldError {
    /// `invalid`, `too_short`, `too_long`, `taken` or `incorrect`.
    pub code: String,
    /// English fallback text.
    pub message: String,
    /// Values for building a message, such as `{ "min": 8 }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub params: Option<serde_json::Value>,
}

const TAG: &str = "auth";

#[utoipa::path(get, path = "/csrf", tag = TAG, operation_id = "get_csrf_token",
    description = "Set the `__Host-csrf` cookie if there is none. Send its value in the `X-CSRF-Token` header of requests that change data.",
    responses((status = 204, description = "The cookie is set")))]
fn csrf() {}

#[utoipa::path(post, path = "/register", tag = TAG, operation_id = "register",
    description = "Create an account. The answer is the same whether or not the address already has one; its owner gets an email either way.",
    request_body = RegisterRequest,
    responses(
        (status = 202, description = "Accepted"),
        (status = 422, description = "`validation_failed`", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn register() {}

#[utoipa::path(post, path = "/login", tag = TAG, operation_id = "login",
    description = "Log in from a browser. Sets the `__Host-session` cookie and a new CSRF cookie.",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Logged in, or waiting for the second factor when `mfa_required` is true", body = LoginResponse),
        (status = 401, description = "`invalid_credentials`", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "`email_not_verified` or `csrf_failed`", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn login() {}

#[utoipa::path(post, path = "/mobile/login", tag = TAG, operation_id = "mobile_login",
    description = "Log in from a mobile app. The token goes in `Authorization: Bearer` from then on.",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Logged in, or waiting for the second factor when `mfa_required` is true", body = MobileLoginResponse),
        (status = 401, description = "`invalid_credentials`", body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "`email_not_verified`", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn mobile_login() {}

#[utoipa::path(post, path = "/logout", tag = TAG, operation_id = "logout",
    description = "End the session, also one that waits for its second factor, and clear the cookies.",
    responses((status = 204, description = "Logged out")))]
fn logout() {}

#[utoipa::path(post, path = "/email/verify", tag = TAG, operation_id = "verify_email",
    description = "Use the token from a verification link. Does not sign in.",
    request_body = TokenRequest,
    responses(
        (status = 204, description = "Verified"),
        (status = 400, description = "`invalid_token`", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn verify_email() {}

#[utoipa::path(post, path = "/email/verify/resend", tag = TAG, operation_id = "resend_verification",
    description = "Send a new verification link. The answer does not tell whether the address has an account.",
    request_body = EmailRequest,
    responses(
        (status = 202, description = "Accepted"),
        (status = 422, description = "`validation_failed`", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn resend_verification() {}

#[utoipa::path(post, path = "/password/forgot", tag = TAG, operation_id = "forgot_password",
    description = "Send a password reset link. The answer does not tell whether the address has an account.",
    request_body = EmailRequest,
    responses(
        (status = 202, description = "Accepted"),
        (status = 422, description = "`validation_failed`", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn forgot_password() {}

#[utoipa::path(post, path = "/password/reset", tag = TAG, operation_id = "reset_password",
    description = "Set a new password with the token from a reset link. Signs out every session.",
    request_body = ResetPasswordRequest,
    responses(
        (status = 204, description = "Changed"),
        (status = 400, description = "`invalid_token`", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "`validation_failed`", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn reset_password() {}

#[utoipa::path(post, path = "/password/change", tag = TAG, operation_id = "change_password",
    description = "Change the password of the signed-in account. Signs out its other sessions.",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Changed"),
        (status = 401, description = "`unauthenticated`", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "`validation_failed`, also for a wrong current password", body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "`too_many_attempts`; the session is signed out", body = Problem, content_type = "application/problem+json"),
    ))]
fn change_password() {}

#[utoipa::path(get, path = "/username-available", tag = TAG, operation_id = "username_available",
    description = "Whether a username is free. Only served when registration reveals existing email addresses.",
    params(UsernameQuery),
    responses(
        (status = 200, description = "Whether the username is free", body = UsernameAvailableResponse),
        (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
    ))]
fn username_available() {}

/// Paths and schemas of the local-account routes, without `GET /username-available`
/// (see [`UsernameAvailableApi`]).
#[derive(OpenApi)]
#[openapi(
    paths(
        csrf, register, login, mobile_login, logout, verify_email, resend_verification,
        forgot_password, reset_password, change_password
    ),
    components(schemas(Problem, ProblemFieldError)),
    tags((name = "auth", description = "Accounts, sessions and the second factor"))
)]
pub struct AuthApi;

/// `GET /username-available`. The route is mounted only when `LocalAuth` reveals
/// existing email addresses (`LocalAuthBuilder::reveal_existing_email`), so add this
/// document only then, or use [`AuthRoutes::openapi`](crate::AuthRoutes::openapi).
#[derive(OpenApi)]
#[openapi(
    paths(username_available),
    components(schemas(Problem, ProblemFieldError))
)]
pub struct UsernameAvailableApi;

#[cfg(feature = "mfa")]
mod mfa {
    use super::*;

    #[utoipa::path(post, path = "/mfa/verify", tag = TAG, operation_id = "verify_mfa",
        description = "Complete a login that waits for its second factor. Replaces the session cookie, or returns the new token to bearer clients.",
        request_body = CodeRequest,
        responses(
            (status = 200, description = "Signed in under a new session token", body = MfaVerifyResponse),
            (status = 401, description = "`invalid_code`, `mfa_attempts_exceeded` or `unauthenticated`", body = Problem, content_type = "application/problem+json"),
            (status = 429, description = "`rate_limited`", body = Problem, content_type = "application/problem+json"),
        ))]
    pub(super) fn verify() {}

    #[utoipa::path(get, path = "/mfa", tag = TAG, operation_id = "get_mfa_status",
        responses(
            (status = 200, description = "The second factor of the signed-in account", body = MfaStatusResponse),
            (status = 401, description = "`unauthenticated`", body = Problem, content_type = "application/problem+json"),
        ))]
    pub(super) fn status() {}

    #[utoipa::path(post, path = "/mfa/totp/start", tag = TAG, operation_id = "start_totp",
        description = "Create a TOTP secret. Shown once.",
        responses(
            (status = 200, description = "The new secret and its `otpauth://` URI", body = TotpSetupResponse),
            (status = 409, description = "`mfa_already_enabled`", body = Problem, content_type = "application/problem+json"),
        ))]
    pub(super) fn start() {}

    #[utoipa::path(post, path = "/mfa/totp/confirm", tag = TAG, operation_id = "confirm_totp",
        description = "Switch TOTP on with a code from the app. The recovery codes are shown once.",
        request_body = CodeRequest,
        responses(
            (status = 200, description = "TOTP is on; the recovery codes, shown once", body = RecoveryCodesResponse),
            (status = 409, description = "`mfa_already_enabled` or `mfa_setup_not_started`", body = Problem, content_type = "application/problem+json"),
            (status = 422, description = "`validation_failed` on `code`", body = Problem, content_type = "application/problem+json"),
        ))]
    pub(super) fn confirm() {}

    #[utoipa::path(post, path = "/mfa/totp/disable", tag = TAG, operation_id = "disable_totp",
        description = "Switch TOTP off. Needs a current code or an unused recovery code.",
        request_body = CodeRequest,
        responses(
            (status = 204, description = "Switched off"),
            (status = 422, description = "`validation_failed` on `code`", body = Problem, content_type = "application/problem+json"),
            (status = 429, description = "`too_many_attempts`", body = Problem, content_type = "application/problem+json"),
        ))]
    pub(super) fn disable() {}

    #[utoipa::path(post, path = "/mfa/recovery-codes", tag = TAG, operation_id = "regenerate_recovery_codes",
        description = "Replace all recovery codes. Needs a current code or an unused recovery code.",
        request_body = CodeRequest,
        responses(
            (status = 200, description = "The new recovery codes, shown once", body = RecoveryCodesResponse),
            (status = 409, description = "`mfa_not_enabled`", body = Problem, content_type = "application/problem+json"),
            (status = 422, description = "`validation_failed` on `code`", body = Problem, content_type = "application/problem+json"),
            (status = 429, description = "`too_many_attempts`", body = Problem, content_type = "application/problem+json"),
        ))]
    pub(super) fn regenerate() {}

    /// Paths and schemas of the second-factor routes.
    #[derive(OpenApi)]
    #[openapi(paths(verify, status, start, confirm, disable, regenerate))]
    pub struct MfaApi;
}

#[cfg(feature = "mfa")]
pub use mfa::MfaApi;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Every document a client generator may be given, as JSON.
    fn documents() -> Vec<(&'static str, Value)> {
        let mut documents = vec![
            ("AuthApi", AuthApi::openapi()),
            ("UsernameAvailableApi", UsernameAvailableApi::openapi()),
        ];
        #[cfg(feature = "mfa")]
        documents.push(("MfaApi", MfaApi::openapi()));
        documents
            .into_iter()
            .map(|(name, doc)| (name, serde_json::to_value(doc).unwrap()))
            .collect()
    }

    fn operations(doc: &Value) -> impl Iterator<Item = (String, &Value)> {
        doc["paths"]
            .as_object()
            .into_iter()
            .flatten()
            .flat_map(|(path, item)| {
                item.as_object()
                    .into_iter()
                    .flatten()
                    .map(move |(method, op)| (format!("{method} {path}"), op))
            })
    }

    #[test]
    fn every_response_has_a_description() {
        for (name, doc) in documents() {
            for (operation, op) in operations(&doc) {
                let responses = op["responses"].as_object().expect("responses");
                assert!(
                    !responses.is_empty(),
                    "{name}: {operation} has no responses"
                );
                for (status, response) in responses {
                    let description = response["description"].as_str().unwrap_or("");
                    assert!(
                        !description.trim().is_empty(),
                        "{name}: {operation} {status} has no description"
                    );
                }
            }
        }
    }

    #[test]
    fn every_parameter_says_where_it_goes() {
        for (name, doc) in documents() {
            for (operation, op) in operations(&doc) {
                let path = operation.split_once(' ').unwrap().1;
                for parameter in op["parameters"].as_array().into_iter().flatten() {
                    let pname = parameter["name"].as_str().expect("parameter name");
                    let place = parameter["in"].as_str().unwrap_or("");
                    assert!(
                        ["query", "path", "header", "cookie"].contains(&place),
                        "{name}: {operation} parameter {pname} has `in: {place}`"
                    );
                    assert_eq!(
                        place == "path",
                        path.contains(&format!("{{{pname}}}")),
                        "{name}: {operation} parameter {pname} is `in: {place}`"
                    );
                }
            }
        }
    }

    #[test]
    fn username_check_takes_a_query_parameter() {
        let doc = serde_json::to_value(UsernameAvailableApi::openapi()).unwrap();
        let parameters = &doc["paths"]["/username-available"]["get"]["parameters"];
        assert_eq!(parameters[0]["name"], "username");
        assert_eq!(parameters[0]["in"], "query");
        assert_eq!(parameters[0]["required"], true);
        let auth = serde_json::to_value(AuthApi::openapi()).unwrap();
        assert!(
            auth["paths"].get("/username-available").is_none(),
            "only listed where the route is mounted"
        );
    }
}
