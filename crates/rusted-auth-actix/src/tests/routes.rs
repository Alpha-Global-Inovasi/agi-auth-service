//! End-to-end tests of `AuthRoutes` and `SessionAuth` with in-memory stores.

use crate::{
    AuthRoutes, Bucket, CSRF_COOKIE, CSRF_HEADER, CurrentSession, Limit, LinkTargets, RateLimiter,
    RateLimits, SESSION_COOKIE, SessionAuth, TrustedProxies, WebConfig,
};
use actix_web::cookie::Cookie;
use actix_web::http::StatusCode;
use actix_web::http::header::{
    AUTHORIZATION, CONTENT_TYPE, COOKIE, HeaderMap, LOCATION, ORIGIN, REFERER, SET_COOKIE,
};
use actix_web::web::Bytes;
use actix_web::{App, HttpResponse, test, web};
use rusted_auth::local::{AuthEmail, HashLimits, LocalAuth, PasswordHasher, RecordingMailer};
use rusted_auth::session::{
    MemoryOneTimeTokenStore, MemorySessionStore, MemoryUserStore, SessionManager,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;

const ORIGIN_URL: &str = "https://app.example.com";
const PASSWORD: &str = "correct horse battery staple";

type Local = LocalAuth<MemoryUserStore, MemorySessionStore>;

struct Fixture {
    sessions: SessionManager<MemorySessionStore>,
    local: Local,
    mailer: RecordingMailer,
    web: WebConfig,
    #[cfg(feature = "mfa")]
    mfa: Option<rusted_auth::mfa::Mfa<rusted_auth::mfa::MemoryMfaStore, MemorySessionStore>>,
}

impl Fixture {
    fn new() -> Self {
        Self::build(false, false)
    }

    fn build(with_mfa: bool, reveal: bool) -> Self {
        let users = MemoryUserStore::new();
        let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
        let mailer = RecordingMailer::new();
        #[allow(unused_mut)]
        let mut builder = LocalAuth::builder(users, sessions.clone())
            .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
            .mailer(mailer.clone())
            .tokens(MemoryOneTimeTokenStore::new())
            .reveal_existing_email(reveal);
        #[cfg(feature = "mfa")]
        let mfa = with_mfa.then(|| {
            use rusted_auth::encryption::{EncryptionKey, Keyring};
            let keyring = Keyring::new("k1", EncryptionKey::from_bytes([1; 32])).unwrap();
            rusted_auth::mfa::Mfa::builder(
                rusted_auth::mfa::MemoryMfaStore::new(),
                keyring,
                sessions.clone(),
            )
            .issuer("Test")
            .build()
            .unwrap()
        });
        #[cfg(feature = "mfa")]
        if let Some(mfa) = &mfa {
            builder = builder.mfa(mfa);
        }
        #[cfg(not(feature = "mfa"))]
        let _ = with_mfa;
        Self {
            sessions,
            local: builder.build().unwrap(),
            mailer,
            web: WebConfig::new([ORIGIN_URL]).unwrap(),
            #[cfg(feature = "mfa")]
            mfa,
        }
    }

    fn routes(&self) -> AuthRoutes<MemoryUserStore, MemorySessionStore> {
        self.routes_with(RateLimiter::memory(), LinkTargets::new())
    }

    fn routes_with(
        &self,
        limiter: RateLimiter,
        links: LinkTargets,
    ) -> AuthRoutes<MemoryUserStore, MemorySessionStore> {
        #[allow(unused_mut)]
        let mut builder = AuthRoutes::builder(self.local.clone(), self.web.clone())
            .rate_limiter(limiter)
            .link_targets(links);
        #[cfg(feature = "mfa")]
        if let Some(mfa) = &self.mfa {
            builder = builder.mfa(mfa);
        }
        builder.build().unwrap()
    }

    /// The link token of the newest email.
    fn last_token(&self) -> String {
        let emails = self.mailer.take();
        let email: &AuthEmail = emails.last().expect("an email was sent");
        email.token().expect("a link email").expose().to_owned()
    }

    /// Register `name` and verify the address, through the library.
    async fn account(&self, name: &str) {
        self.local
            .register(rusted_auth::local::Registration {
                username: name.into(),
                email: format!("{name}@example.com"),
                name: name.into(),
                password: PASSWORD.into(),
            })
            .await
            .unwrap();
        let token = self.last_token();
        self.local
            .verify_email(&token, rusted_auth::session::SessionContext::web())
            .await
            .unwrap();
    }
}

async fn me(current: CurrentSession) -> HttpResponse {
    HttpResponse::Ok().body(current.user.username.clone())
}

async fn note(_current: CurrentSession) -> HttpResponse {
    HttpResponse::Created().finish()
}

macro_rules! app {
    ($fixture:expr, $routes:expr) => {{
        let routes = $routes;
        test::init_service(
            App::new()
                .wrap(SessionAuth::new(
                    $fixture.sessions.clone(),
                    $fixture.web.clone(),
                ))
                .service(web::scope("/auth").configure(|cfg| routes.configure(cfg)))
                .route("/api/me", web::get().to(me))
                .route("/api/notes", web::post().to(note)),
        )
        .await
    }};
    ($fixture:expr) => {
        app!($fixture, $fixture.routes())
    };
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn code(&self) -> Value {
        self.json()["code"].clone()
    }

    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .map_or("", |value| value.to_str().unwrap())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

macro_rules! send {
    ($app:expr, $req:expr) => {{
        let resp = test::call_service(&$app, $req.to_request()).await;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = test::read_body(resp).await;
        Reply {
            status,
            headers,
            body,
        }
    }};
    ($app:expr, $jar:expr, $req:expr) => {{
        let reply = send!($app, $jar.dress($req));
        $jar.absorb(&reply.headers);
        reply
    }};
}

/// A browser: keeps cookies, sends `Origin` and the CSRF header like a SPA would.
#[derive(Debug, Default, Clone)]
struct Browser {
    cookies: BTreeMap<String, String>,
}

impl Browser {
    fn absorb(&mut self, headers: &HeaderMap) {
        for value in headers.get_all(SET_COOKIE) {
            let cookie = Cookie::parse(value.to_str().unwrap().to_owned()).unwrap();
            assert!(
                cookie.secure().unwrap_or(false),
                "{} is Secure",
                cookie.name()
            );
            assert_eq!(cookie.path(), Some("/"));
            let removed = cookie.max_age().is_some_and(|age| age.whole_seconds() <= 0);
            if removed {
                self.cookies.remove(cookie.name());
            } else {
                self.cookies
                    .insert(cookie.name().to_owned(), cookie.value().to_owned());
            }
        }
    }

    fn dress(&self, mut req: test::TestRequest) -> test::TestRequest {
        if !self.cookies.is_empty() {
            let header = self
                .cookies
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            req = req.insert_header((COOKIE, header));
        }
        if let Some(token) = self.cookies.get(CSRF_COOKIE) {
            req = req.insert_header((CSRF_HEADER, token.as_str()));
        }
        req.insert_header((ORIGIN, ORIGIN_URL))
    }

    fn session(&self) -> Option<&String> {
        self.cookies.get(SESSION_COOKIE)
    }
}

fn post(path: &str, body: Value) -> test::TestRequest {
    test::TestRequest::post()
        .uri(path)
        .insert_header((CONTENT_TYPE, "application/json"))
        .set_payload(body.to_string())
}

fn get(path: &str) -> test::TestRequest {
    test::TestRequest::get().uri(path)
}

fn login_body(name: &str, password: &str) -> Value {
    json!({ "identifier": name, "password": password })
}

fn registration(username: &str, email: &str) -> Value {
    json!({ "username": username, "email": email, "name": "Someone", "password": PASSWORD })
}

/// A browser with a CSRF cookie, logged in as `name`.
macro_rules! logged_in {
    ($app:expr, $name:expr) => {{
        let mut browser = Browser::default();
        let reply = send!($app, browser, get("/auth/csrf"));
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        let reply = send!(
            $app,
            browser,
            post("/auth/login", login_body($name, PASSWORD))
        );
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        browser
    }};
}

#[actix_web::test]
async fn web_login_sets_cookies_and_logout_clears_them() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);
    let mut browser = Browser::default();

    let reply = send!(app, browser, get("/auth/csrf"));
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let csrf = browser
        .cookies
        .get(CSRF_COOKIE)
        .cloned()
        .expect("csrf cookie");
    assert_eq!(csrf.len(), 43);

    let reply = send!(
        app,
        browser,
        post("/auth/login", login_body("budi", PASSWORD))
    );
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.header("cache-control"), "no-store");
    let body = reply.json();
    assert_eq!(body["data"]["user"]["username"], "budi");
    assert_eq!(body["data"]["mfa_required"], false);
    assert!(
        body["data"]["user"]["email_verified_at"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert!(body["data"].get("token").is_none(), "no token in the body");
    let session = browser.session().cloned().expect("session cookie");
    assert!(session.starts_with("rusted_s_"));
    assert_ne!(
        browser.cookies[CSRF_COOKIE], csrf,
        "CSRF token rotated at login"
    );

    let set_cookie: Vec<_> = reply.headers.get_all(SET_COOKIE).collect();
    let session_header = set_cookie
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|v| v.starts_with(SESSION_COOKIE))
        .unwrap();
    assert!(session_header.contains("HttpOnly"));
    assert!(session_header.contains("SameSite=Lax"));
    assert!(session_header.contains("Max-Age="));
    let csrf_header = set_cookie
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|v| v.starts_with(CSRF_COOKIE))
        .unwrap();
    assert!(!csrf_header.contains("HttpOnly"), "the client reads it");

    let reply = send!(app, browser, get("/api/me"));
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.text(), "budi");
    let reply = send!(app, browser, post("/api/notes", json!({})));
    assert_eq!(reply.status, StatusCode::CREATED);

    let reply = send!(app, browser, post("/auth/logout", json!({})));
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(browser.session().is_none(), "cookie removed");
    assert!(!browser.cookies.contains_key(CSRF_COOKIE));

    // The old token no longer works, even when sent again.
    let reply = send!(
        app,
        get("/api/me").insert_header((COOKIE, format!("{SESSION_COOKIE}={session}")))
    );
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "unauthenticated");
    assert_eq!(reply.header("content-type"), "application/problem+json");
}

#[actix_web::test]
async fn browser_requests_without_csrf_or_with_a_foreign_origin_are_refused() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);

    // Login without a CSRF cookie: refused even though no session exists yet.
    let reply = send!(
        app,
        post("/auth/login", login_body("budi", PASSWORD)).insert_header((ORIGIN, ORIGIN_URL))
    );
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "csrf_failed");

    // Login without Origin from a client that sends nothing a browser would: still a
    // web login, so refused.
    let reply = send!(app, post("/auth/login", login_body("budi", PASSWORD)));
    assert_eq!(reply.code(), "csrf_failed");

    let mut browser = logged_in!(app, "budi");

    // Another site posting with the victim's cookies.
    let mut foreign = browser.dress(post("/api/notes", json!({})));
    foreign = foreign.insert_header((ORIGIN, "https://evil.example"));
    let reply = send!(app, foreign);
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.code(), "csrf_failed");

    // The cookie alone, without the header.
    let token = browser.cookies.remove(CSRF_COOKIE).unwrap();
    let reply = send!(app, browser.dress(post("/api/notes", json!({}))));
    assert_eq!(reply.code(), "csrf_failed");
    let reply = send!(
        app,
        browser
            .dress(post("/api/notes", json!({})))
            .insert_header((CSRF_HEADER, "not-the-token"))
    );
    assert_eq!(reply.code(), "csrf_failed");
    browser.cookies.insert(CSRF_COOKIE.into(), token);

    // Reading is not checked.
    let reply = send!(
        app,
        browser
            .dress(get("/api/me"))
            .insert_header((ORIGIN, "https://evil.example"))
    );
    assert_eq!(reply.status, StatusCode::OK);

    let reply = send!(app, browser, post("/api/notes", json!({})));
    assert_eq!(reply.status, StatusCode::CREATED);
}

#[actix_web::test]
async fn which_requests_count_as_coming_from_a_browser() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);
    let browser = logged_in!(app, "budi");
    let session = browser.session().cloned().unwrap();

    // `Origin: null` counts as an Origin header, and is never allowed, even with a
    // matching Referer and CSRF token.
    let reply = send!(
        app,
        browser
            .dress(post("/api/notes", json!({})))
            .insert_header((ORIGIN, "null"))
            .insert_header((REFERER, format!("{ORIGIN_URL}/notes")))
    );
    assert_eq!(reply.code(), "csrf_failed");
    let reply = send!(
        app,
        post(
            "/auth/password/forgot",
            json!({ "email": "budi@example.com" })
        )
        .insert_header((ORIGIN, "null"))
    );
    assert_eq!(reply.code(), "csrf_failed", "also before login");

    // A bearer token together with cookies is a browser request.
    let mobile = send!(
        app,
        post("/auth/mobile/login", login_body("budi", PASSWORD))
    );
    let bearer = format!(
        "Bearer {}",
        mobile.json()["data"]["token"].as_str().unwrap()
    );
    let reply = send!(
        app,
        post("/api/notes", json!({}))
            .insert_header((AUTHORIZATION, bearer.as_str()))
            .insert_header((COOKIE, format!("{SESSION_COOKIE}={session}")))
    );
    assert_eq!(reply.code(), "csrf_failed");
    let reply = send!(
        app,
        post("/auth/logout", json!({}))
            .insert_header((AUTHORIZATION, bearer.as_str()))
            .insert_header((COOKIE, format!("{SESSION_COOKIE}={session}")))
    );
    assert_eq!(reply.code(), "csrf_failed");

    // Routes that write the session cookie are checked whatever the headers say.
    let reply = send!(
        app,
        post("/auth/login", login_body("budi", PASSWORD))
            .insert_header((AUTHORIZATION, bearer.as_str()))
    );
    assert_eq!(
        reply.code(),
        "csrf_failed",
        "web login with a bearer header"
    );
    assert!(reply.headers.get(SET_COOKIE).is_none());
    let reply = send!(app, post("/auth/logout", json!({})));
    assert_eq!(
        reply.code(),
        "csrf_failed",
        "logout without a bearer token clears the cookie"
    );

    // Both sessions still work.
    let reply = send!(app, browser.dress(get("/api/me")));
    assert_eq!(reply.text(), "budi");
    let reply = send!(
        app,
        get("/api/me").insert_header((AUTHORIZATION, bearer.as_str()))
    );
    assert_eq!(reply.text(), "budi");
}

#[actix_web::test]
async fn native_clients_use_the_routes_before_login_without_csrf() {
    let fixture = Fixture::new();
    let app = app!(fixture);

    // No Cookie, Origin or Referer: nothing a browser would send.
    let reply = send!(
        app,
        post("/auth/register", registration("budi", "budi@example.com"))
    );
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.text());
    let reply = send!(
        app,
        post(
            "/auth/email/verify/resend",
            json!({ "email": "budi@example.com" })
        )
    );
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.text());
    let token = fixture.last_token();
    let reply = send!(app, post("/auth/email/verify", json!({ "token": token })));
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.text());

    let reply = send!(
        app,
        post(
            "/auth/password/forgot",
            json!({ "email": "budi@example.com" })
        )
    );
    assert_eq!(reply.status, StatusCode::ACCEPTED, "{}", reply.text());
    let token = fixture.last_token();
    let reply = send!(
        app,
        post(
            "/auth/password/reset",
            json!({ "token": token, "password": "another long passphrase" })
        )
    );
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.text());

    let reply = send!(
        app,
        post(
            "/auth/mobile/login",
            login_body("budi", "another long passphrase")
        )
    );
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert!(reply.headers.get(SET_COOKIE).is_none());
}

#[actix_web::test]
async fn registration_answers_the_same_for_new_and_registered_addresses() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);

    let mut browser = Browser::default();
    send!(app, browser, get("/auth/csrf"));
    let new = send!(
        app,
        browser,
        post("/auth/register", registration("siti", "siti@example.com"))
    );
    let registered = send!(
        app,
        browser,
        post("/auth/register", registration("other", "budi@example.com"))
    );
    assert_eq!(new.status, StatusCode::ACCEPTED);
    assert_eq!(registered.status, new.status);
    assert_eq!(registered.body, new.body);
    assert!(new.body.is_empty());
    assert_eq!(
        registered.headers.get(CONTENT_TYPE),
        new.headers.get(CONTENT_TYPE)
    );
    assert!(registered.headers.get(SET_COOKIE).is_none());

    // One verification link to the new account, one notice to the existing owner.
    let kinds: Vec<_> = fixture
        .mailer
        .take()
        .iter()
        .map(|email| email.kind().name())
        .collect();
    assert_eq!(kinds, ["verify_email", "registration_attempt"]);
}

#[actix_web::test]
async fn registration_reports_field_errors() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);
    let mut browser = Browser::default();
    send!(app, browser, get("/auth/csrf"));

    let mut short = registration("siti", "siti@example.com");
    short["password"] = json!("short");
    let reply = send!(app, browser, post("/auth/register", short));
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    let body = reply.json();
    assert_eq!(body["code"], "validation_failed");
    assert_eq!(body["status"], 422);
    assert_eq!(body["errors"]["password"][0]["code"], "too_short");
    assert_eq!(body["errors"]["password"][0]["params"]["min"], 8);

    let reply = send!(
        app,
        browser,
        post("/auth/register", registration("budi", "new@example.com"))
    );
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(reply.json()["errors"]["username"][0]["code"], "taken");

    let reply = send!(
        app,
        browser,
        post("/auth/register", registration("x", "new@example.com"))
    );
    assert_eq!(reply.json()["errors"]["username"][0]["code"], "invalid");

    let reply = send!(
        app,
        browser,
        post("/auth/register", json!({ "username": "siti" }))
    );
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.code(), "bad_request");

    // The username check is not served while registration hides addresses.
    let reply = send!(app, get("/auth/username-available?username=budi"));
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn revealing_registration_reports_taken_addresses_and_serves_the_username_check() {
    let fixture = Fixture::build(false, true);
    fixture.account("budi").await;
    let app = app!(fixture);
    let mut browser = Browser::default();
    send!(app, browser, get("/auth/csrf"));

    let reply = send!(
        app,
        browser,
        post("/auth/register", registration("other", "budi@example.com"))
    );
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(reply.json()["errors"]["email"][0]["code"], "taken");

    let reply = send!(app, get("/auth/username-available?username=budi"));
    assert_eq!(reply.json()["data"]["available"], false);
    let reply = send!(app, get("/auth/username-available?username=siti"));
    assert_eq!(reply.json()["data"]["available"], true);
}

#[actix_web::test]
async fn login_failures_share_one_answer() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    fixture
        .local
        .register(rusted_auth::local::Registration {
            username: "siti".into(),
            email: "siti@example.com".into(),
            name: "Siti".into(),
            password: PASSWORD.into(),
        })
        .await
        .unwrap();
    let app = app!(fixture);
    let mut browser = Browser::default();
    send!(app, browser, get("/auth/csrf"));

    let wrong = send!(
        app,
        browser,
        post("/auth/login", login_body("budi", "wrong password"))
    );
    let unknown = send!(
        app,
        browser,
        post("/auth/login", login_body("nobody", PASSWORD))
    );
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body, unknown.body);
    assert_eq!(wrong.code(), "invalid_credentials");
    assert!(
        wrong.headers.get("www-authenticate").is_none(),
        "not a bearer request"
    );

    let unverified = send!(
        app,
        browser,
        post("/auth/login", login_body("siti", PASSWORD))
    );
    assert_eq!(unverified.status, StatusCode::FORBIDDEN);
    assert_eq!(unverified.code(), "email_not_verified");
}

#[actix_web::test]
async fn mobile_apps_use_bearer_tokens_without_csrf() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);

    let reply = send!(
        app,
        post("/auth/mobile/login", login_body("budi", PASSWORD))
    );
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert!(reply.headers.get(SET_COOKIE).is_none());
    let body = reply.json();
    let token = body["data"]["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("rusted_s_"));
    assert!(body["data"]["expires_at"].as_str().unwrap().ends_with('Z'));
    let session = fixture.sessions.validate(&token).await.unwrap();
    assert_eq!(
        session.session.kind,
        rusted_auth::session::SessionKind::Mobile
    );

    let bearer = format!("Bearer {token}");
    let reply = send!(
        app,
        get("/api/me").insert_header((AUTHORIZATION, bearer.as_str()))
    );
    assert_eq!(reply.text(), "budi");
    let reply = send!(
        app,
        post("/api/notes", json!({}))
            .insert_header((AUTHORIZATION, bearer.as_str()))
            .insert_header((ORIGIN, "https://evil.example"))
    );
    assert_eq!(
        reply.status,
        StatusCode::CREATED,
        "bearer requests skip CSRF"
    );

    // Other native requests need no CSRF either.
    let reply = send!(
        app,
        post(
            "/auth/password/forgot",
            json!({ "email": "budi@example.com" })
        )
    );
    assert_eq!(reply.status, StatusCode::ACCEPTED);

    let reply = send!(
        app,
        post("/auth/logout", json!({})).insert_header((AUTHORIZATION, bearer.as_str()))
    );
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.headers.get(SET_COOKIE).is_none());
    let reply = send!(
        app,
        get("/api/me").insert_header((AUTHORIZATION, bearer.as_str()))
    );
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn email_verification_and_password_reset_go_through_post() {
    let fixture = Fixture::new();
    let app = app!(fixture);
    let mut browser = Browser::default();
    send!(app, browser, get("/auth/csrf"));
    send!(
        app,
        browser,
        post("/auth/register", registration("budi", "budi@example.com"))
    );
    let token = fixture.last_token();

    let reply = send!(
        app,
        browser,
        post("/auth/email/verify", json!({ "token": "rusted_t_nope" }))
    );
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.code(), "invalid_token");
    let reply = send!(
        app,
        browser,
        post("/auth/email/verify", json!({ "token": token }))
    );
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(browser.session().is_none(), "verification does not sign in");

    // Unknown and known addresses get the same answer.
    let unknown = send!(
        app,
        browser,
        post(
            "/auth/password/forgot",
            json!({ "email": "nobody@example.com" })
        )
    );
    let known = send!(
        app,
        browser,
        post(
            "/auth/password/forgot",
            json!({ "email": "budi@example.com" })
        )
    );
    assert_eq!(unknown.status, StatusCode::ACCEPTED);
    assert_eq!(known.status, unknown.status);
    assert_eq!(known.body, unknown.body);
    let reset = fixture.last_token();

    let mut other = logged_in!(app, "budi");
    let reply = send!(
        app,
        browser,
        post(
            "/auth/password/reset",
            json!({ "token": reset, "password": "short" })
        )
    );
    assert_eq!(reply.json()["errors"]["password"][0]["code"], "too_short");
    let reply = send!(
        app,
        browser,
        post(
            "/auth/password/reset",
            json!({ "token": reset, "password": "a brand new password" })
        )
    );
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let reply = send!(app, other, get("/api/me"));
    assert_eq!(
        reply.status,
        StatusCode::UNAUTHORIZED,
        "reset signs out every session"
    );

    let reply = send!(
        app,
        browser,
        post("/auth/login", login_body("budi", "a brand new password"))
    );
    assert_eq!(reply.status, StatusCode::OK);

    let reply = send!(
        app,
        browser,
        post(
            "/auth/email/verify/resend",
            json!({ "email": "budi@example.com" })
        )
    );
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

#[actix_web::test]
async fn password_change_reports_a_wrong_current_password_as_a_field_error() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);
    let mut browser = logged_in!(app, "budi");
    let mut other = logged_in!(app, "budi");

    let reply = send!(
        app,
        browser,
        post(
            "/auth/password/change",
            json!({ "current_password": "wrong", "new_password": "a brand new password" })
        )
    );
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        reply.json()["errors"]["current_password"][0]["code"],
        "incorrect"
    );

    let reply = send!(
        app,
        browser,
        post(
            "/auth/password/change",
            json!({ "current_password": PASSWORD, "new_password": "a brand new password" })
        )
    );
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(send!(app, browser, get("/api/me")).status, StatusCode::OK);
    assert_eq!(
        send!(app, other, get("/api/me")).status,
        StatusCode::UNAUTHORIZED,
        "other sessions are signed out"
    );

    let reply = send!(
        app,
        post(
            "/auth/password/change",
            json!({ "current_password": PASSWORD, "new_password": "x" })
        )
    );
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn too_many_wrong_current_passwords_sign_the_session_out() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let app = app!(fixture);
    let mut browser = logged_in!(app, "budi");
    let wrong = json!({ "current_password": "wrong", "new_password": "a brand new password" });
    for _ in 0..4 {
        let reply = send!(app, browser, post("/auth/password/change", wrong.clone()));
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let last = send!(app, browser, post("/auth/password/change", wrong.clone()));
    assert_eq!(last.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(last.code(), "too_many_attempts");
    assert!(
        browser.session().is_none(),
        "cookies cleared with the session"
    );
}

#[actix_web::test]
async fn requests_over_the_rate_limit_get_429() {
    let fixture = Fixture::new();
    fixture.account("budi").await;
    let limits = RateLimits::default().set(Bucket::Email, Limit::new(2, Duration::from_secs(600)));
    let proxies: TrustedProxies = "10.0.0.0/8".parse().unwrap();
    let web_config = fixture.web.clone().trusted_proxies(proxies);
    let routes = AuthRoutes::builder(fixture.local.clone(), web_config)
        .rate_limiter(RateLimiter::memory().limits(limits))
        .build()
        .unwrap();
    let app = app!(fixture, routes);
    let forgot = |peer: &str, forwarded: Option<&str>| {
        let mut req = post(
            "/auth/password/forgot",
            json!({ "email": "budi@example.com" }),
        )
        .peer_addr(peer.parse().unwrap());
        if let Some(forwarded) = forwarded {
            req = req.insert_header(("X-Forwarded-For", forwarded));
        }
        req
    };

    for _ in 0..2 {
        let reply = send!(app, forgot("198.51.100.1:5000", Some("203.0.113.50")));
        assert_eq!(reply.status, StatusCode::ACCEPTED);
    }
    // The header of an untrusted peer is ignored: still the same client.
    let reply = send!(app, forgot("198.51.100.1:5000", Some("203.0.113.51")));
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reply.code(), "rate_limited");
    assert_eq!(reply.header("retry-after"), "600");

    // Behind a trusted proxy, each forwarded client counts on its own.
    for client in ["203.0.113.1", "203.0.113.1", "203.0.113.2"] {
        let reply = send!(app, forgot("10.0.0.5:5000", Some(client)));
        assert_eq!(reply.status, StatusCode::ACCEPTED, "{client}");
    }
    let reply = send!(app, forgot("10.0.0.5:5000", Some("203.0.113.1")));
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
}

#[actix_web::test]
async fn email_link_pages_never_use_the_token_on_get() {
    let fixture = Fixture::new();
    let app = app!(fixture);
    send!(
        app,
        post("/auth/register", registration("budi", "budi@example.com"))
    );
    let token = fixture.last_token();

    let reply = send!(app, get(&format!("/auth/email/verify?token={token}")));
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.header("referrer-policy"), "no-referrer");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert!(
        reply
            .header("content-security-policy")
            .contains("default-src 'none'")
    );
    assert!(reply.header("content-type").starts_with("text/html"));
    let page = reply.text();
    assert!(page.contains(&token), "the form carries the token");
    assert!(!page.contains("<script"));
    assert!(
        fixture
            .local
            .login(
                "budi",
                PASSWORD,
                rusted_auth::session::SessionContext::web()
            )
            .await
            .is_err(),
        "opening the link did not verify the address"
    );

    // Submitting the form verifies it.
    let mut browser = Browser::default();
    browser.absorb(&reply.headers);
    let csrf = browser.cookies[CSRF_COOKIE].clone();
    assert!(page.contains(&csrf));
    let form = browser
        .dress(test::TestRequest::post().uri("/auth/email/verify"))
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(format!("token={token}&csrf_token={csrf}"));
    let reply = send!(app, form);
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert!(reply.text().contains("verified"));
    assert!(
        fixture
            .local
            .login(
                "budi",
                PASSWORD,
                rusted_auth::session::SessionContext::web()
            )
            .await
            .is_ok()
    );

    let reply = send!(app, get("/auth/password/reset?token=garbage"));
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.text().contains("invalid"));
}

#[actix_web::test]
async fn email_link_pages_forward_to_the_front_end_in_the_fragment() {
    let fixture = Fixture::new();
    let links = LinkTargets::new()
        .verify_email("https://app.example.com/verify")
        .reset_password("https://app.example.com/reset");
    let app = app!(fixture, fixture.routes_with(RateLimiter::memory(), links));
    let token = format!("rusted_t_{}", "A".repeat(43));

    let reply = send!(app, get(&format!("/auth/password/reset?token={token}")));
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.header(LOCATION.as_str()),
        format!("https://app.example.com/reset#token={token}")
    );
    assert_eq!(reply.header("referrer-policy"), "no-referrer");
    let reply = send!(app, get("/auth/email/verify?token=%22%3E"));
    assert_eq!(
        reply.header(LOCATION.as_str()),
        "https://app.example.com/verify"
    );
}

#[cfg(feature = "mfa")]
mod mfa {
    use super::*;
    use crate::ConfigError;
    use hmac::{Hmac, Mac as _};
    use sha1::Sha1;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn base32(text: &str) -> Vec<u8> {
        let mut bits = 0u32;
        let mut count = 0;
        let mut out = Vec::new();
        for c in text.bytes() {
            let value = match c {
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => continue,
            };
            bits = (bits << 5) | u32::from(value);
            count += 5;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
            }
        }
        out
    }

    /// The TOTP code `steps` periods from now.
    fn code(secret: &str, steps: i64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let counter = (now / 30 + steps) as u64;
        let mut mac = <Hmac<Sha1> as hmac::KeyInit>::new_from_slice(&base32(secret)).unwrap();
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[19] & 0xf);
        let value = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        format!("{:06}", value % 1_000_000)
    }

    #[::core::prelude::v1::test]
    fn routes_refuse_a_second_factor_connected_on_one_side() {
        let with = Fixture::build(true, false);
        let without = Fixture::new();
        let error = AuthRoutes::builder(without.local.clone(), without.web.clone())
            .mfa(with.mfa.as_ref().unwrap())
            .build()
            .unwrap_err();
        assert_eq!(error, ConfigError::MfaNotInLocalAuth);
        let error = AuthRoutes::builder(with.local.clone(), with.web.clone())
            .build()
            .unwrap_err();
        assert_eq!(error, ConfigError::MfaNotInRoutes);
    }

    #[actix_web::test]
    async fn totp_setup_login_and_changes() {
        let fixture = Fixture::build(true, false);
        fixture.account("budi").await;
        let app = app!(fixture);
        let mut browser = logged_in!(app, "budi");

        let reply = send!(app, browser, get("/auth/mfa"));
        assert_eq!(reply.json()["data"]["status"], "disabled");
        let reply = send!(app, browser, post("/auth/mfa/totp/start", json!({})));
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.header("cache-control"), "no-store");
        let secret = reply.json()["data"]["secret"].as_str().unwrap().to_owned();
        assert!(
            reply.json()["data"]["uri"]
                .as_str()
                .unwrap()
                .starts_with("otpauth://totp/")
        );

        let reply = send!(
            app,
            browser,
            post("/auth/mfa/totp/confirm", json!({ "code": "000000" }))
        );
        assert_eq!(
            reply.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "signed in, so not 401"
        );
        assert_eq!(reply.json()["errors"]["code"][0]["code"], "invalid");
        let reply = send!(
            app,
            browser,
            post(
                "/auth/mfa/totp/confirm",
                json!({ "code": code(&secret, 0) })
            )
        );
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let recovery: Vec<String> = reply.json()["data"]["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(recovery.len(), 10);
        let reply = send!(app, browser, post("/auth/mfa/totp/start", json!({})));
        assert_eq!(reply.status, StatusCode::CONFLICT);
        assert_eq!(reply.code(), "mfa_already_enabled");
        send!(app, browser, post("/auth/logout", json!({})));

        // Logging in now waits for the second factor.
        let reply = send!(app, browser, get("/auth/csrf"));
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        let reply = send!(
            app,
            browser,
            post("/auth/login", login_body("budi", PASSWORD))
        );
        assert_eq!(reply.json()["data"]["mfa_required"], true);
        let pending = browser.session().cloned().unwrap();
        let reply = send!(app, browser, get("/api/me"));
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.code(), "mfa_required");

        // The web step replaces the cookie, so it is always checked for CSRF, also
        // when the pending token comes in a bearer header next to the cookie.
        let reply = send!(
            app,
            post("/auth/mfa/verify", json!({ "code": code(&secret, 1) }))
                .insert_header((COOKIE, format!("{SESSION_COOKIE}={pending}")))
        );
        assert_eq!(reply.code(), "csrf_failed");
        let reply = send!(
            app,
            post("/auth/mfa/verify", json!({ "code": code(&secret, 1) }))
                .insert_header((AUTHORIZATION, format!("Bearer {pending}")))
                .insert_header((COOKIE, format!("{SESSION_COOKIE}={pending}")))
        );
        assert_eq!(reply.code(), "csrf_failed");

        let reply = send!(
            app,
            browser,
            post("/auth/mfa/verify", json!({ "code": "000000" }))
        );
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.code(), "invalid_code");
        let reply = send!(
            app,
            browser,
            post("/auth/mfa/verify", json!({ "code": code(&secret, 1) }))
        );
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        assert_eq!(reply.json()["data"]["method"], "totp");
        assert!(reply.json()["data"].get("token").is_none());
        let active = browser.session().cloned().unwrap();
        assert_ne!(active, pending, "the cookie holds a new token");
        assert_eq!(send!(app, browser, get("/api/me")).text(), "budi");
        let reply = send!(
            app,
            get("/api/me").insert_header((COOKIE, format!("{SESSION_COOKIE}={pending}")))
        );
        assert_eq!(
            reply.status,
            StatusCode::UNAUTHORIZED,
            "the pending token is gone"
        );

        // Changes need a code; a wrong one is a field error.
        let reply = send!(
            app,
            browser,
            post("/auth/mfa/recovery-codes", json!({ "code": "123" }))
        );
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
        let reply = send!(
            app,
            browser,
            post("/auth/mfa/recovery-codes", json!({ "code": recovery[0] }))
        );
        assert_eq!(reply.status, StatusCode::OK);
        let fresh = reply.json()["data"]["recovery_codes"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let reply = send!(app, browser, get("/auth/mfa"));
        assert_eq!(reply.json()["data"]["status"], "enabled");
        assert_eq!(reply.json()["data"]["recovery_codes_left"], 10);

        let reply = send!(
            app,
            browser,
            post("/auth/mfa/totp/disable", json!({ "code": fresh }))
        );
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        let reply = send!(app, browser, get("/auth/mfa"));
        assert_eq!(reply.json()["data"]["status"], "disabled");
    }

    #[actix_web::test]
    async fn bearer_clients_get_the_new_token_in_the_body() {
        let fixture = Fixture::build(true, false);
        fixture.account("budi").await;
        let mfa = fixture.mfa.clone().unwrap();
        let user = fixture
            .local
            .store()
            .find_by_username("budi")
            .await
            .unwrap()
            .unwrap()
            .user;
        use rusted_auth::session::UserStore as _;
        let setup = mfa.start_totp(user.id, "budi").await.unwrap();
        let recovery = mfa
            .confirm_totp(user.id, &code(setup.secret(), 0))
            .await
            .unwrap();
        let app = app!(fixture);

        let reply = send!(
            app,
            post("/auth/mobile/login", login_body("budi", PASSWORD))
        );
        assert_eq!(reply.json()["data"]["mfa_required"], true);
        let pending = reply.json()["data"]["token"].as_str().unwrap().to_owned();
        let bearer = format!("Bearer {pending}");

        let reply = send!(
            app,
            post(
                "/auth/mfa/verify",
                json!({ "code": recovery.iter().next().unwrap() })
            )
            .insert_header((AUTHORIZATION, bearer.as_str()))
        );
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        assert!(reply.headers.get(SET_COOKIE).is_none());
        let body = reply.json();
        assert_eq!(body["data"]["method"], "recovery_code");
        let token = body["data"]["token"].as_str().unwrap();
        assert_ne!(token, pending);
        let reply = send!(
            app,
            get("/api/me").insert_header((AUTHORIZATION, format!("Bearer {token}")))
        );
        assert_eq!(reply.text(), "budi");
    }

    #[actix_web::test]
    async fn too_many_wrong_codes_end_the_login() {
        let fixture = Fixture::build(true, false);
        fixture.account("budi").await;
        let mfa = fixture.mfa.clone().unwrap();
        use rusted_auth::session::UserStore as _;
        let user = fixture
            .local
            .store()
            .find_by_username("budi")
            .await
            .unwrap()
            .unwrap()
            .user;
        let setup = mfa.start_totp(user.id, "budi").await.unwrap();
        mfa.confirm_totp(user.id, &code(setup.secret(), 0))
            .await
            .unwrap();
        let app = app!(fixture);
        let mut browser = logged_in!(app, "budi");

        let mut last = None;
        for _ in 0..5 {
            last = Some(send!(
                app,
                browser,
                post("/auth/mfa/verify", json!({ "code": "000000" }))
            ));
        }
        assert_eq!(last.unwrap().code(), "mfa_attempts_exceeded");
        let reply = send!(
            app,
            browser,
            post(
                "/auth/mfa/verify",
                json!({ "code": code(setup.secret(), 1) })
            )
        );
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.code(), "unauthenticated");
    }
}

#[cfg(feature = "utoipa")]
#[::core::prelude::v1::test]
fn openapi_lists_exactly_the_mounted_routes() {
    let paths = |fixture: &Fixture| -> Vec<String> {
        fixture
            .routes()
            .openapi()
            .paths
            .paths
            .keys()
            .cloned()
            .collect()
    };
    let default = paths(&Fixture::new());
    assert!(default.contains(&"/login".to_owned()));
    assert!(!default.contains(&"/username-available".to_owned()));
    assert!(!default.iter().any(|path| path.starts_with("/mfa")));

    let revealing = paths(&Fixture::build(false, true));
    assert!(revealing.contains(&"/username-available".to_owned()));

    #[cfg(feature = "mfa")]
    {
        let with_mfa = paths(&Fixture::build(true, false));
        assert!(with_mfa.contains(&"/mfa/verify".to_owned()));
        assert!(!with_mfa.contains(&"/username-available".to_owned()));
    }
}
