# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version
may contain breaking changes.

## [Unreleased]

### Added

- `local` cargo feature (off by default) with the `rusted_auth::local` module: accounts
  with a username, an email address and a password, independent of any web framework or
  database.
  - `LocalAuth::register` and `LocalAuth::login`. Login accepts a username or an email
    address.
  - `UserStore` trait for persistence, and `MemoryUserStore` for tests.
  - `PasswordHasher`: argon2id with the OWASP parameters (m = 19 MiB, t = 2, p = 1).
    At most 8 hashes run at once on dedicated threads, and a request that waits more
    than 2 seconds fails with `LocalError::Busy`; both limits are set with `HashLimits`.
    It does not depend on a particular async runtime.
  - Passwords are 8 to 128 characters with no composition rules, and are normalized to
    Unicode NFKC before hashing. `PasswordPolicy` raises the minimum length.
  - Registration answers the same way whether or not the email address already has an
    account (`RegistrationOutcome`). `LocalAuthBuilder::reveal_existing_email` opts out.
  - `LocalAuth::username_available`, which only works together with
    `reveal_existing_email(true)`: while registration hides existing email addresses,
    a public username check would reveal them.
  - A login for an unknown account costs the same hashing work as one for a known
    account, and a wrong password, an unknown account, a locked account and a disabled
    account all have the same public message.
  - Accounts lock after 5 consecutive failed logins, for 1 minute doubling up to
    15 minutes (`LockoutPolicy`).
  - Login requires a verified email address (`LocalError::EmailNotVerified`).
    `LocalAuthBuilder::require_verified_email(false)` turns this off for development.
  - `LocalError` with `public_message()` and `kind()`.
- `test-util` cargo feature: `PasswordHasher::insecure_for_tests`, a hasher with the
  weakest argon2 parameters so that test suites stay fast. Never enable it in a
  production build.

## [0.4.1] - 2026-11-15

### Changed

- Renamed to match the Rusted brand: `agi-auth` is now `rusted-auth` and `agi-auth-actix`
  is now `rusted-auth-actix`. The repository moved to
  `Alpha-Global-Inovasi/rusted-auth`. The code is the same as 0.4.0.
- `agi-auth` and `agi-auth-actix` 0.4.1 are final releases that re-export the new crates,
  so existing code keeps building. No further releases will be made under the old names.

### Migrating from agi-auth 0.4

```toml
[dependencies]
rusted-auth = "0.4"
rusted-auth-actix = "0.4"
```

Then replace `agi_auth` with `rusted_auth` and `agi_auth_actix` with `rusted_auth_actix`
in `use` statements. Nothing else changes.

## [0.4.0] - 2026-11-14

The library is renamed from `cf-auth` to `agi-auth` and is no longer tied to Firebase.
This release is a breaking redesign.

### Added

- `Verifier`: verifies tokens from several trusted issuers, each with its own audience,
  algorithm allowlist and key cache.
- `Issuer`: configure an issuer by hand, from its OpenID Connect discovery document
  (`Issuer::discover`), from a static JWKS (`jwks_json`), or with the `Issuer::firebase`
  preset.
- `Principal`: normalized identity with access to all raw claims.
- `Issuer::require_type` to accept only RFC 9068 access tokens.
- `Verifier::refresh_keys` to fetch keys at startup.
- `AuthError::public_message` and `AuthError::is_server_error`.
- `agi-auth-actix`: `Authenticate` middleware, `Authenticated` and `MaybeAuthenticated`
  extractors, and the `AuthResponder` trait for custom error bodies.
- `native-tls` feature as an alternative to the default `rustls-tls`.
- JWKS cache: stale-key fallback, single shared refresh, fetch rate limiting, 10 second
  timeout, response size cap, `Cache-Control: max-age` support.

### Changed

- The repository is a workspace: `agi-auth` (core) and `agi-auth-actix`.
- Keys are read from standard JWKS documents instead of Google's X.509 endpoint.
- `aud` may be a string or an array; `auth_time` is optional.
- An unknown `kid` is answered with 401, unreachable issuer keys with 503 (previously 500).
- Error responses no longer include internal details.
- 401 responses carry a `WWW-Authenticate: Bearer` header.
- License is now `MIT OR Apache-2.0`, copyright PT Alpha Global Inovasi.
- Minimum supported Rust version is 1.89, required by the patched releases of
  `actix-web` and `actix-http`.
- Dependencies are on their latest stable releases: `jsonwebtoken` 12, `reqwest` 0.13,
  `base64` 0.23, `actix-web` 4.19. Minimum versions are raised so applications cannot
  resolve releases with known advisories.
- Signatures are checked with aws-lc-rs. agi-auth installs it as jsonwebtoken's crypto
  provider when the application has not chosen one, so enabling jsonwebtoken's
  `rust_crypto` feature elsewhere in the dependency graph no longer causes a panic.
- With `rustls-tls`, certificates are verified against the operating system's trust store
  instead of a bundled copy of the Mozilla roots.

### Removed

- Global state and the `FIREBASE_PROJECT_ID` / `FIREBASE_SIGNATURE` environment variables.
  The application passes configuration to the builder.
- `verify_token`, `force_refresh_jwks`, `Claims`, `CurrentUser`, `FirebaseClaims`.
- `firebase_signature_middleware` and `ApiResponse` / `EmptyResponse`.

### Fixed

- `extract_bearer_token` panicked on an `Authorization` header with a multi-byte
  character in its first seven bytes.

### Migrating from cf-auth 0.3

| cf-auth 0.3 | agi-auth 0.4 |
|---|---|
| `FIREBASE_PROJECT_ID` env var | `Issuer::firebase(project_id)` |
| `verify_token(token)` | `verifier.verify(token)` |
| `CurrentUser { uid, .. }` | `Principal { subject, .. }` |
| `user.sign_in_provider` | `agi_auth::firebase::sign_in_provider(&principal)` |
| `.wrap(from_fn(firebase_auth_middleware))` | `.wrap(Authenticate::required(verifier))` |
| `.wrap(from_fn(optional_firebase_auth_middleware))` | `.wrap(Authenticate::optional(verifier))` |
| `AuthenticatedUser`, `OptionalUser` | `Authenticated`, `MaybeAuthenticated` |
| `force_refresh_jwks()` | `verifier.refresh_keys()` |
