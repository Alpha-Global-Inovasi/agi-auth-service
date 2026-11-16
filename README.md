# rusted-auth

Authentication for Rust services, built by PT Alpha Global Inovasi.

This repository is a Cargo workspace:

| Crate | What it is |
|---|---|
| [`rusted-auth`](crates/rusted-auth) | Framework-agnostic core: token verification for any OpenID Connect / JWT issuer, and (behind features) local accounts, sessions and a second factor |
| [`rusted-auth-actix`](crates/rusted-auth-actix) | Actix-web middleware, extractors, session cookies with CSRF protection, and the HTTP routes |
| [`rusted-auth-sea-orm`](crates/rusted-auth-sea-orm) | Postgres storage with SeaORM for accounts, sessions, second factors and the audit log |

Formerly published as `agi-auth` (0.4.0) and, before that, `cf-auth` (Firebase only). See the [changelog](CHANGELOG.md) for how to migrate.

## Status

Version 0.5 covers:

- **Token verification**: the application receives a bearer token issued by an identity provider (Firebase, Keycloak, Zitadel, Auth0, Microsoft Entra ID, ...) and gets back a normalized `Principal`.
- **Local accounts** (`local` feature): registration, password login with argon2id, lockout, email verification, password reset and change.
- **Sessions** (`session` feature): opaque `rusted_s_` tokens in a `__Host-` cookie for browsers or a bearer header for mobile apps, revocable at any time.
- **Second factor** (`mfa` feature): TOTP authenticators and recovery codes, with secrets encrypted under a rotatable keyring.
- **HTTP routes** for Actix-web with CSRF protection and per-address rate limits, and **Postgres storage** with migrations.

Single sign-on modes are planned for later releases.

Upgrading from 0.4: see [Migrating to 0.5](docs/migrating-to-0.5.md). Before going to production with local accounts, read the [security notes](docs/security.md), [key rotation](docs/key-rotation.md) and [secret scanning](docs/secret-scanning.md).

## Quick start

```toml
[dependencies]
rusted-auth = "0.5"
rusted-auth-actix = "0.5"
```

```rust
use actix_web::{App, HttpServer, web};
use rusted_auth::{Issuer, Verifier};
use rusted_auth_actix::{Authenticate, Authenticated};

async fn me(user: Authenticated) -> String {
    format!("Hello, {}", user.subject)
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = Verifier::builder()
        .issuer(Issuer::firebase("my-firebase-project"))
        .build()?;

    HttpServer::new(move || {
        App::new()
            .wrap(Authenticate::required(verifier.clone()))
            .route("/me", web::get().to(me))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}
```

## Security properties

- **Issuers are configured, never taken from the token.** The token's `iss` only selects which configured issuer's rules apply.
- **Keys are not shared between issuers.** Each issuer has its own key cache.
- **Algorithms are allowlisted per issuer.** HMAC algorithms and `alg: none` are never accepted, which rules out algorithm-confusion attacks.
- **Standard claim checks:** `iss`, `aud`, `exp`, `nbf`, a non-empty `sub`, and `auth_time` not in the future.
- **Key fetching is bounded:** HTTPS only, 10 second timeout, 1 MiB response cap, redirects only to HTTPS, and at most one fetch per minute per issuer no matter what tokens arrive.
- **Error responses carry no internal details.** The full error goes to the log.
- **Local accounts** do not reveal which addresses are registered, lock after repeated failures, keep only hashes of tokens, and rotate the session token after the second factor. See the [security notes](docs/security.md) for the details and the known limits.
- `#![forbid(unsafe_code)]` across the workspace.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development

```bash
cargo test --workspace                  # offline; tokens are signed with the keys in testdata/
cargo test --workspace -- --ignored     # also contacts Google's real key endpoint
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check                        # licenses and advisories (needs cargo-deny)
# Postgres storage tests run when a database is given:
RUSTED_AUTH_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test -p rusted-auth-sea-orm --all-features
```

Minimum supported Rust version: 1.89 (1.94 for `rusted-auth-sea-orm`, which SeaORM 2.0 requires). Raising it is a minor-version change.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
