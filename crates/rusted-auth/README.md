# rusted-auth

Framework-agnostic authentication core for Rust services.

- Verifies bearer tokens from any OpenID Connect / JWT issuer and returns a normalized `Principal`. Firebase Authentication is available as a preset, not a requirement.
- With cargo features: local accounts with password login, opaque sessions, TOTP and recovery codes, independent of any web framework or database. [`rusted-auth-actix`](https://crates.io/crates/rusted-auth-actix) serves them over HTTP and [`rusted-auth-sea-orm`](https://crates.io/crates/rusted-auth-sea-orm) stores them in Postgres.

```toml
[dependencies]
rusted-auth = "0.5"
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

## Local accounts, sessions and a second factor

```toml
[dependencies]
rusted-auth = { version = "0.5", features = ["local", "mfa"] }
```

```rust
# #[cfg(feature = "local")]
# async fn run() -> Result<(), Box<dyn std::error::Error>> {
use rusted_auth::local::{LocalAuth, NoMailer, Registration};
use rusted_auth::session::{
    MemoryOneTimeTokenStore, MemorySessionStore, MemoryUserStore, SessionContext,
    SessionManager,
};

// Memory stores for the example; use rusted-auth-sea-orm in production.
let users = MemoryUserStore::new();
let sessions = SessionManager::new(MemorySessionStore::new(users.clone()));
let auth = LocalAuth::builder(users, sessions.clone())
    .mailer(NoMailer) // required: queue the emails in a real application
    .tokens(MemoryOneTimeTokenStore::new()) // required: shared by every process
    .require_verified_email(false) // development only
    .build()?;

auth.register(Registration {
    username: "budi".into(),
    email: "budi@example.com".into(),
    name: "Budi Santoso".into(),
    password: "correct horse battery staple".into(),
})
.await?;

let login = auth
    .login("budi", "correct horse battery staple", SessionContext::web())
    .await?;
let token = login.token.expose(); // rusted_s_..., for a cookie or a bearer header
let current = sessions.validate(token).await?;
assert_eq!(current.user.username, "budi");
# Ok(())
# }
```

| Module | Feature | What it does |
|---|---|---|
| `session` | `session` | Opaque session tokens (`rusted_s_` + 256 bits, stored as SHA-256), web and mobile lifetimes, revocation, single-use link tokens (`rusted_t_`), shared attempt counters, audit events |
| `local` | `local` | Registration that does not reveal registered addresses, argon2id password login with lockout, email verification, password reset and change, the `Mailer` trait |
| `mfa` | `mfa` | TOTP (RFC 6238), recovery codes, and the second step of login under a new session token |
| `encryption` | `encryption` | `Keyring`: XChaCha20-Poly1305 with rotatable keys |

Every storage trait has an in-memory implementation for tests and a set of conformance
checks (`session::conformance`, `mfa::conformance`, with `test-util`) for your own.

Read before production:

- [Security notes](https://github.com/Alpha-Global-Inovasi/rusted-auth/blob/main/docs/security.md): what is guaranteed and the known limits, including that a password reset signs other processes out within 30 seconds and that using the link and storing the new password are not one transaction.
- [Key rotation](https://github.com/Alpha-Global-Inovasi/rusted-auth/blob/main/docs/key-rotation.md): an old key may only be removed after the recovery codes made under it are replaced.
- [Secret scanning](https://github.com/Alpha-Global-Inovasi/rusted-auth/blob/main/docs/secret-scanning.md): patterns for `rusted_s_` and `rusted_t_` tokens.
- [Migrating to 0.5](https://github.com/Alpha-Global-Inovasi/rusted-auth/blob/main/docs/migrating-to-0.5.md).

## Features

| Feature | Default | Effect |
|---|---|---|
| `rustls-tls` | yes | Fetch keys over TLS using rustls, verifying certificates against the operating system's trust store |
| `native-tls` | no | Use the platform TLS library instead |
| `session` | no | Sessions, accounts and the audit hook shared by every way of signing in (`rusted_auth::session`), without password hashing. See the module documentation |
| `local` | no | Local accounts: registration and login with argon2id password hashing (`rusted_auth::local`). Turns on `session`. See the module documentation |
| `mfa` | no | Second factor: TOTP authenticators and recovery codes (`rusted_auth::mfa`). Turns on `session` and `encryption`. See the module documentation |
| `encryption` | no | Encryption of secrets at rest with XChaCha20-Poly1305 and a keyring that supports key rotation (`rusted_auth::encryption`) |
| `test-util` | no | Test helpers for `local`, such as a password hasher with cheap parameters. Never enable it in a production build |

The library never reads environment variables and keeps no global state. It needs a Tokio runtime.

## License

MIT or Apache-2.0, at your option.
