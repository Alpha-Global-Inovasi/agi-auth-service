# cf-auth

A shared Rust library for Firebase Authentication, designed for use by multiple microservices.

## Features

- 🔐 **JWT Verification** - Verify Firebase ID tokens against Google's public keys
- 🗄️ **JWK Caching** - Caches Google's keys for the `max-age` Google sends, with a single shared refresh and stale-key fallback when Google is unreachable
- 🌐 **Actix-web Middleware** - Optional feature flag for Actix integration
- ⚡ **Framework Agnostic** - Core auth logic works with any Rust framework

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
# Without Actix middleware
cf-auth = { git = "https://github.com/Crypto-Foundation-Dev/cf-auth.git" }

# With Actix middleware
cf-auth = { git = "https://github.com/Crypto-Foundation-Dev/cf-auth.git", features = ["actix"] }
```

## Environment Variables

| Variable              | Required | Description              |
| --------------------- | -------- | ------------------------ |
| `FIREBASE_PROJECT_ID` | Yes      | Your Firebase project ID |
| `FIREBASE_SIGNATURE`  | Only for `firebase_signature_middleware` | Expected `X-Firebase-Signature` value |

## Usage

### Basic Token Verification

```rust
use cf_auth::{verify_token, CurrentUser, AuthError};

async fn authenticate(token: &str) -> Result<CurrentUser, AuthError> {
    let claims = verify_token(token).await?;
    Ok(CurrentUser::from(claims))
}
```

### Actix-web Middleware

```rust
use actix_web::{web, App, HttpServer, middleware::from_fn};
use cf_auth::{firebase_auth_middleware, AuthenticatedUser};

async fn protected_handler(user: AuthenticatedUser) -> String {
    format!("Hello, {}!", user.uid)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .wrap(from_fn(firebase_auth_middleware))
            .route("/me", web::get().to(protected_handler))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

### Optional Authentication

For endpoints that work with or without auth:

```rust
use cf_auth::middleware::{optional_firebase_auth_middleware, OptionalUser};

async fn mixed_handler(user: OptionalUser) -> String {
    match user.0 {
        Some(u) => format!("Hello, {}!", u.uid),
        None => "Hello, anonymous!".to_string(),
    }
}
```

## API Reference

### Structs

| Struct              | Description                                   |
| ------------------- | --------------------------------------------- |
| `Claims`            | Full Firebase JWT payload                     |
| `CurrentUser`       | Lightweight user data extracted from claims   |
| `AuthenticatedUser` | Actix `FromRequest` extractor (requires auth) |
| `OptionalUser`      | Actix `FromRequest` extractor (optional auth) |

### Functions

| Function                       | Description                               |
| ------------------------------ | ----------------------------------------- |
| `verify_token(token)`          | Verify a Firebase ID token                |
| `extract_bearer_token(header)` | Extract token from `Authorization` header |
| `force_refresh_jwks()`         | Force refresh Google's public keys        |

### Middleware (Actix feature)

| Middleware                          | Description                        |
| ----------------------------------- | ---------------------------------- |
| `firebase_auth_middleware`          | Returns 401 if auth fails          |
| `optional_firebase_auth_middleware` | Continues without error if no auth; 401 if a header is present but invalid |
| `firebase_signature_middleware`     | Returns 401 if signature fails     |

## Key Caching

Google's public keys are fetched from the `securetoken` x509 endpoint and cached:

- **TTL** follows Google's `Cache-Control: max-age` (1 hour if absent).
- **One refresh at a time.** Concurrent requests that miss the cache wait for a single fetch.
- **Stale fallback.** If a refresh fails, expired keys are still used for up to 24 hours, so a Google outage does not take auth down.
- **Rate limit.** At most one fetch attempt per 60 seconds. A token with an unknown `kid` cannot force repeated fetches.
- **Timeout.** The fetch times out after 10 seconds.

## HTTP Status Mapping

How the Actix middleware maps verification errors:

| Error                                                            | Status |
| ---------------------------------------------------------------- | ------ |
| `TokenExpired`, `InvalidSignature`, `KeyNotFound`, other token errors | 401    |
| `JwkFetchError`, `ConfigError`                                   | 500    |

`KeyNotFound` means the token's `kid` is not among Google's current keys, so it is treated as a bad token.

## Error Types

```rust
pub enum AuthError {
    MissingAuthHeader,
    InvalidAuthHeaderFormat,
    TokenExpired,
    InvalidSignature,
    InvalidSignatureHeader,
    IssuerMismatch { expected, actual },
    AudienceMismatch { expected, actual },
    MissingKeyId,
    KeyNotFound { kid },
    JwkFetchError(String),
    DecodeError(String),
    ConfigError(String),
}
```

## Testing

```bash
cargo test --all-features             # offline; signs tokens with the keys in testdata/
cargo test --all-features -- --ignored # also fetches Google's real keys (needs network)
```

The keys in `testdata/` are test fixtures, not secrets.

## License

MIT
