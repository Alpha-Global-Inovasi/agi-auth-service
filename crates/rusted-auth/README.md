# rusted-auth

Framework-agnostic authentication core for Rust services.

Verifies bearer tokens from any OpenID Connect / JWT issuer and returns a normalized `Principal`. Firebase Authentication is available as a preset, not a requirement.

```toml
[dependencies]
rusted-auth = "0.4"
```

```rust,no_run
use rusted_auth::{AuthError, Issuer, Principal, Verifier};

async fn build_verifier() -> Result<Verifier, AuthError> {
    Verifier::builder()
        // Firebase: issuer, audience, algorithm and key URL are filled in
        .issuer(Issuer::firebase("my-firebase-project"))
        // Any OIDC provider, configured from its discovery document
        .issuer(
            Issuer::discover("https://auth.example.com")
                .await?
                .audience("my-api"),
        )
        .build()
}

async fn who_is_calling(verifier: &Verifier, authorization: &str) -> Result<Principal, AuthError> {
    verifier.verify_bearer(authorization).await
}
```

For Actix-web, use [`rusted-auth-actix`](https://crates.io/crates/rusted-auth-actix).

## Configuring an issuer

| Method | Purpose |
|---|---|
| `Issuer::firebase(project_id)` | Firebase Authentication preset |
| `Issuer::discover(issuer).await` | Read `jwks_uri` and algorithms from `/.well-known/openid-configuration` |
| `Issuer::new(issuer).jwks_uri(url)` | Set the key URL yourself |
| `.jwks_json(json)` | Pin keys from a JWKS document; nothing is fetched |
| `.audience(aud)` | Accepted `aud`; at least one is required |
| `.algorithms(&[...])` | Allowed signing algorithms (default: `RS256`) |
| `.require_type("at+jwt")` | Accept only RFC 9068 access tokens, not ID tokens |
| `.leeway(duration)` | Clock-skew allowance (default: 60 seconds) |

`(principal.issuer, principal.subject)` is the stable identity of a user. Do not key accounts by email.

## Key caching

- Keys are cached for the `max-age` the issuer sends, or 1 hour.
- Concurrent requests that miss the cache share a single fetch.
- At most one fetch attempt per minute per issuer, so tokens with a made-up `kid` cannot be used to flood the issuer.
- If the issuer is unreachable, expired keys are served for up to 24 hours.
- `Verifier::refresh_keys()` fetches immediately; call it at startup to fail fast.

## Errors

`AuthError` implements `Display` for logs. For anything sent to a client use `AuthError::public_message()`, which never contains token contents, key IDs or upstream errors. `AuthError::is_server_error()` separates "the caller's credentials are bad" from "we could not check them".

## Features

| Feature | Default | Effect |
|---|---|---|
| `rustls-tls` | yes | Fetch keys over TLS using rustls, verifying certificates against the operating system's trust store |
| `native-tls` | no | Use the platform TLS library instead |
| `local` | no | Local accounts: registration and login with argon2id password hashing (`rusted_auth::local`). Unreleased; see the module documentation |
| `test-util` | no | Test helpers for `local`, such as a password hasher with cheap parameters. Never enable it in a production build |

The library never reads environment variables and keeps no global state. It needs a Tokio runtime.

## License

MIT or Apache-2.0, at your option.
