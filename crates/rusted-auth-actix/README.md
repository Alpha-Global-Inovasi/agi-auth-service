# rusted-auth-actix

Actix-web middleware and extractors for [`rusted-auth`](https://crates.io/crates/rusted-auth).

```toml
[dependencies]
rusted-auth = "0.4"
rusted-auth-actix = "0.4"
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

## Responses

| Situation | Status |
|---|---|
| Missing or invalid credentials | 401 with `WWW-Authenticate: Bearer` |
| The issuer's keys cannot be fetched | 503 |
| Misconfiguration | 500 |

Bodies never contain internal details. The default body is `{"status": false, "message": "...", "data": null}`. To use your application's own format, implement `AuthResponder`:

```rust
use actix_web::HttpResponse;
use rusted_auth::AuthError;
use rusted_auth_actix::AuthResponder;

struct MyResponder;

impl AuthResponder for MyResponder {
    fn respond(&self, error: &AuthError) -> HttpResponse {
        HttpResponse::build(Self::status_for(error))
            .json(serde_json::json!({ "error": error.public_message() }))
    }
}

// Authenticate::required(verifier).responder(MyResponder)
```

## License

MIT or Apache-2.0, at your option.
