//! The pages behind email links: `GET /email/verify` and `GET /password/reset`.
//!
//! Mail scanners open links with GET, so GET never uses the token: it forwards the
//! browser to the application's page, or shows a form that sends the token back
//! with POST.

use super::State;
use crate::failure::AuthFailure;
use crate::web::{CSRF_COOKIE, CSRF_FIELD, csrf_cookie, new_csrf_token};
use actix_web::http::StatusCode;
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder};
use rusted_auth::session::{ONE_TIME_TOKEN_PREFIX, SessionStore, UserStore};
use serde::Deserialize;

/// Where the pages behind email links send the browser.
///
/// The emails are built by the application, which can point their links straight at
/// its own front-end page; that page then sends the token with `POST /email/verify`
/// or `POST /password/reset`. These settings are for links that point at the routes'
/// own `GET /email/verify?token=...` and `GET /password/reset?token=...`:
///
/// - With a URL set, the route answers 303 to that URL with the token moved into the
///   fragment (`#token=...`). Browsers send neither the fragment to the server nor it
///   in a `Referer`.
/// - Without one, the route shows a minimal HTML page with a form (and no JavaScript,
///   so a link scanner does not submit it) that sends the token back with POST.
///
/// Both answers carry `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkTargets {
    verify_email: Option<String>,
    reset_password: Option<String>,
}

impl LinkTargets {
    /// No forwarding: both routes show their own page.
    pub fn new() -> Self {
        Self::default()
    }

    /// Forward `GET /email/verify` to `url`, such as
    /// `https://app.example.com/verify-email`.
    #[must_use]
    pub fn verify_email(mut self, url: impl Into<String>) -> Self {
        self.verify_email = Some(url.into());
        self
    }

    /// Forward `GET /password/reset` to `url`, such as
    /// `https://app.example.com/reset-password`.
    #[must_use]
    pub fn reset_password(mut self, url: impl Into<String>) -> Self {
        self.reset_password = Some(url.into());
        self
    }
}

#[derive(Debug, Deserialize)]
struct TokenQuery {
    #[serde(default)]
    token: String,
}

#[derive(Deserialize)]
pub(super) struct TokenForm {
    pub token: String,
    pub csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ResetForm {
    pub token: String,
    pub password: String,
    pub csrf_token: Option<String>,
}

/// The token if it looks like one; only such text goes into a URL or a page.
fn well_formed(token: &str) -> Option<&str> {
    let body = token.strip_prefix(ONE_TIME_TOKEN_PREFIX)?;
    (body.len() == 43
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then_some(token)
}

fn link_headers(mut response: HttpResponseBuilder) -> HttpResponseBuilder {
    response
        .insert_header(("Referrer-Policy", "no-referrer"))
        .insert_header((CACHE_CONTROL, "no-store"));
    response
}

fn html(status: StatusCode) -> HttpResponseBuilder {
    let mut response = link_headers(HttpResponse::build(status));
    response
        .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"));
    response
}

fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            c => c.to_string(),
        })
        .collect()
}

fn document(title: &str, content: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title></head><body><main><h1>{title}</h1>{content}</main></body></html>",
        title = escape(title),
    )
}

fn page(
    req: &HttpRequest,
    target: Option<&String>,
    title: &str,
    extra_fields: &str,
    button: &str,
) -> HttpResponse {
    let query = Query::<TokenQuery>::from_query(req.query_string()).ok();
    let token = query.as_ref().and_then(|q| well_formed(&q.token));

    if let Some(target) = target {
        let location = match token {
            Some(token) => format!("{target}#token={token}"),
            None => target.clone(),
        };
        return link_headers(HttpResponse::SeeOther())
            .insert_header((LOCATION, location))
            .finish();
    }

    let Some(token) = token else {
        let body = document(title, "<p>This link is invalid or has expired.</p>");
        return html(StatusCode::BAD_REQUEST).body(body);
    };
    let existing = req.cookie(CSRF_COOKIE).map(|c| c.value().to_owned());
    let csrf = existing
        .clone()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(new_csrf_token);
    let form = format!(
        "<form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"token\" value=\"{token}\">\
         <input type=\"hidden\" name=\"{CSRF_FIELD}\" value=\"{csrf}\">\
         {extra_fields}<button type=\"submit\">{button}</button></form>",
        action = escape(req.path()),
        csrf = escape(&csrf),
        button = escape(button),
    );
    let mut response = html(StatusCode::OK);
    if existing.as_deref() != Some(csrf.as_str()) {
        response.cookie(csrf_cookie(csrf));
    }
    response.body(document(title, &form))
}

pub(super) async fn verify_email_page<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
) -> HttpResponse {
    page(
        &req,
        state.links.verify_email.as_ref(),
        "Verify your email address",
        "",
        "Verify",
    )
}

pub(super) async fn reset_password_page<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
) -> HttpResponse {
    page(
        &req,
        state.links.reset_password.as_ref(),
        "Choose a new password",
        "<p><label>New password <input type=\"password\" name=\"password\" \
         autocomplete=\"new-password\" required minlength=\"8\" maxlength=\"128\"></label></p>",
        "Set password",
    )
}

/// The answer to a form sent from one of these pages: a short HTML page.
pub(super) fn result_page(
    answer: Result<HttpResponse, AuthFailure>,
    success: &str,
) -> HttpResponse {
    match answer {
        Ok(_) => {
            html(StatusCode::OK).body(document("Done", &format!("<p>{}</p>", escape(success))))
        }
        Err(failure) => {
            tracing::debug!(%failure, "email link form rejected");
            let message = if failure.field_errors().is_empty() {
                failure.public_message()
            } else {
                failure.field_errors()[0].message
            };
            html(failure.status()).body(document(
                "Something went wrong",
                &format!("<p>{}</p>", escape(message)),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_well_formed_tokens_are_echoed() {
        let token = format!("{ONE_TIME_TOKEN_PREFIX}{}", "a".repeat(43));
        assert_eq!(well_formed(&token), Some(token.as_str()));
        assert_eq!(well_formed("rusted_t_short"), None);
        let evil = format!("{ONE_TIME_TOKEN_PREFIX}{}\"><script>", "a".repeat(34));
        assert_eq!(well_formed(&evil), None);
        assert_eq!(
            escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
