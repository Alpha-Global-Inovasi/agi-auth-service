# rusted-auth-actix

Actix-web middleware, extractors and routes for [`rusted-auth`](https://crates.io/crates/rusted-auth).

```toml
[dependencies]
rusted-auth = { version = "0.5", features = ["local"] }
rusted-auth-actix = { version = "0.5", features = ["local"] }
```

```rust,no_run
use actix_web::{App, HttpServer, web};
use rusted_auth::{Issuer, Verifier};
use rusted_auth_actix::{Authenticate, Authenticated, MaybeAuthenticated};

async fn me(user: Authenticated) -> String {
    format!("Hello, {}", user.subject)
}

async fn feed(user: MaybeAuthenticated) -> &'static str {
    if user.is_some() { "your feed" } else { "public feed" }
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = Verifier::builder()
        .issuer(Issuer::firebase("my-firebase-project"))
        .build()?;

    HttpServer::new(move || {
        App::new()
            .service(
                web::scope("/account")
                    .wrap(Authenticate::required(verifier.clone()))
                    .route("/me", web::get().to(me)),
            )
            .service(
                web::scope("/public")
                    .wrap(Authenticate::optional(verifier.clone()))
                    .route("/feed", web::get().to(feed)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}
```

## Middleware

| | No `Authorization` header | Invalid token | Valid token |
|---|---|---|---|
| `Authenticate::required` | 401 | 401 | handler runs |
| `Authenticate::optional` | handler runs, anonymous | 401 | handler runs |

Optional mode rejects an invalid token on purpose: a client with an expired token should find out, not silently become anonymous.

## Extractors

| Extractor | Gives you | When anonymous |
|---|---|---|
| `Authenticated` | `Principal` (via `Deref`) | 401 |
| `MaybeAuthenticated` | `Option<Principal>` | `None` |

## Sessions and routes for local accounts

With the `local` feature (and `mfa` for TOTP), `AuthRoutes` serves registration, login, logout, email verification, password reset and change, and the second factor. `SessionAuth` finds the caller's session in the `__Host-session` cookie or an `Authorization: Bearer` token, protects cookie requests against CSRF, and hands handlers a `CurrentSession`.

```rust,no_run
use actix_web::{App, HttpServer, web};
use rusted_auth::local::{LocalAuth, NoMailer};
use rusted_auth::session::{
    MemoryOneTimeTokenStore, MemorySessionStore, MemoryUserStore, SessionManager,
};
use rusted_auth_actix::{AuthRoutes, CurrentSession, SessionAuth, WebConfig};

async fn me(current: CurrentSession) -> String {
    current.user.username.clone()
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Memory stores for the example; use rusted-auth-sea-orm in production.
    let users = MemoryUserStore::new();
    let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
    let local = LocalAuth::builder(users, sessions.clone())
        .mailer(NoMailer)
        .tokens(MemoryOneTimeTokenStore::new())
        .build()?;
    let web_config = WebConfig::new(["https://app.example.com"])?;
    let routes = AuthRoutes::builder(local, web_config.clone()).build()?;

    HttpServer::new(move || {
        App::new()
            .wrap(SessionAuth::new(sessions.clone(), web_config.clone()))
            .service(web::scope("/api/auth").configure(|cfg| routes.configure(cfg)))
            .route("/api/me", web::get().to(me))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}
```

- **Browsers** call `POST /login` and get the `__Host-session` cookie (`HttpOnly; Secure; SameSite=Lax`). Requests that change data must carry an `Origin` (or `Referer`) from the allowed origins and send the `__Host-csrf` cookie back in `X-CSRF-Token`; call `GET /csrf` once before the first form.
- **Mobile apps** call `POST /mobile/login`, keep the token, and send `Authorization: Bearer` from then on. Bearer requests are not checked for CSRF.
- **Second factor**: give the same `Mfa` to `LocalAuthBuilder::mfa` and `AuthRoutesBuilder::mfa`. Without `LocalAuthBuilder::mfa`, logins never ask for the second factor, so `build` fails when only one side has it. `POST /mfa/verify` replaces the cookie, or returns the new token to bearer clients.
- **Email links** should point at your front end, which posts the token. The routes' own `GET /email/verify` and `GET /password/reset` never use the token: they forward to `LinkTargets` with the token in the URL fragment, or show a plain form.
- **Rate limits** per client address (`RateLimiter`) cover login, registration, the email-sending routes and the link-token routes. Give every process the same shared store and key. Behind a reverse proxy, set `WebConfig::trusted_proxies`.
- **Email delivery** must not wait for SMTP. Without a job queue, wrap your mailer in `SpawnMailer`.
- **OpenAPI**: the `utoipa` feature adds `openapi::AuthApi` and `openapi::MfaApi` (utoipa 6).

## Responses

Every failure is an `AuthFailure` with an HTTP status, a stable `code` (such as `invalid_credentials`, `validation_failed` or `rate_limited`) and a public message. Bodies never contain internal details. The default `ProblemResponder` writes RFC 9457 problem details:

```json
{ "type": "about:blank", "title": "Validation failed", "status": 422, "code": "validation_failed",
  "errors": { "password": [{ "code": "too_short", "message": "Password is too short", "params": { "min": 8 } }] } }
```

401 answers to bearer requests carry `WWW-Authenticate: Bearer`, and 429 and 503 answers carry `Retry-After`. To use your application's own format, implement `AuthResponder`:

```rust
use actix_web::HttpResponse;
use rusted_auth_actix::{AuthFailure, AuthResponder};

struct MyResponder;

impl AuthResponder for MyResponder {
    fn respond(&self, failure: &AuthFailure) -> HttpResponse {
        HttpResponse::build(failure.status())
            .json(serde_json::json!({ "error": failure.code(), "message": failure.public_message() }))
    }
}

// Authenticate::required(verifier).responder(MyResponder)
```

## License

MIT or Apache-2.0, at your option.
