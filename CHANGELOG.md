# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version
may contain breaking changes.

## [Unreleased]

### Added

- `local` cargo feature (off by default) with the `rusted_auth::local` module: accounts
  with a username, an email address and a password, independent of any web framework or
  database. It turns on the `session` feature below.
  - `LocalAuth::register` and `LocalAuth::login`. Login accepts a username or an email
    address, and a successful login creates a new session and returns its token
    (`Login`).
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
  - A password hash made with other parameters than the current ones is replaced at the
    next successful login (`PasswordHasher::needs_rehash`,
    `UserStore::replace_password_hash`). A failed replacement does not fail the login.
  - Email verification, password reset and password change:
    `LocalAuth::verify_email`, `resend_verification`, `request_password_reset`,
    `reset_password` and `change_password`. A reset revokes every session of the
    account, clears its lockout and counts the address as verified; a change revokes
    the other sessions. Neither link signs the user in. Requests for addresses without
    an account succeed and send nothing.
  - `Mailer` trait, which the application implements by queueing emails (it must not
    wait for delivery), and `AuthEmail`, the typed emails it receives: verification and
    reset links, and notices about a registration with a known address, a lockout and
    a password change. `LocalAuthBuilder::mailer` is required; `NoMailer` sends
    nothing. Mailer errors are logged and reported, never returned, so that responses
    do not reveal registered addresses. With `test-util`, `RecordingMailer` keeps the
    emails for tests.
  - Registration sends the verification link to a new account, and a notice to the
    owner when the address already has one. The owner is also told when the account
    locks, once per series of failed logins.
  - The emails others can cause an account to receive are limited to 3 per 15 minutes
    (`EmailPolicy`); requests over the limit succeed, send nothing and create no new
    link. Wrong current passwords in `change_password` are counted separately from
    failed logins (`PasswordChangePolicy`, 5 per 15 minutes); at the limit the calling
    session is revoked (`LocalError::TooManyAttempts`).
  - `LocalAuthBuilder::tokens` (required) and `LocalAuthBuilder::attempts`.
    `LocalError::InvalidToken`, `TooManyAttempts` and `Configuration`.
- `session` cargo feature (off by default) with the `rusted_auth::session` module: the
  parts every way of signing in shares, without any password code (it does not pull in
  argon2).
  - `User` and the `UserStore` trait for persistence, with `MemoryUserStore` for tests,
    and `StoreError`. `UserStore::mark_email_verified` and `UserStore::reset_password`
    (a new hash and a cleared lockout in one step).
  - Single-use tokens for email links (`OneTimeToken`, purposes `verify_email` and
    `reset_password`): `rusted_t_` plus 43 base64url characters (secret-scanner pattern
    `rusted_t_[A-Za-z0-9_-]{43}`), stored as a SHA-256 hash together with the address
    they were sent to. `OneTimeTokenStore` uses a token up in one atomic step;
    `MemoryOneTimeTokenStore` is for tests.
  - `AttemptStore`, shared counters of failed attempts with one atomic "count unless at
    the limit" step, and `MemoryAttemptStore`.
  - Sessions, through `SessionManager` (also reachable as `LocalAuth::sessions`):
    - Opaque tokens of 256 random bits, formatted `rusted_s_` plus 43 base64url
      characters (secret-scanner pattern `rusted_s_[A-Za-z0-9_-]{43}`). Only the SHA-256
      hash is stored; the token is returned once and never logged or shown by `Debug`.
    - `SessionStore` trait for persistence, and `MemorySessionStore` for tests.
    - Default lifetimes: web sessions end after 7 days without use or 30 days in total,
      mobile sessions after 30 and 90 days, and sessions waiting for a second
      authentication step after 5 minutes. All are set with `SessionConfig`.
    - `validate` rejects malformed, unknown, expired and revoked tokens and sessions of
      disabled accounts. Validated sessions are cached in memory for 30 seconds without
      depending on an async runtime, and `last_seen_at` is written at most once per
      minute.
    - `revoke`, `revoke_for_user`, `revoke_all` and `revoke_others`. A revocation takes
      effect at once in the process that made it and within the cache lifetime
      (30 seconds) in other processes.
    - `list` returns an account's usable sessions without tokens or hashes.
    - The `PendingMfa` state for logins waiting for a second factor, with
      `validate_pending_mfa` and `activate`. `activate` revokes the pending session and
      returns a new active session with a new token (`IssuedSession`); its absolute
      lifetime still counts from the creation of the pending session.
      `SessionStore::activate` does this in one atomic step.
  - `EventSink`, a hook for an audit log and metrics: successful and failed logins,
    lockouts, sessions created, activated and revoked, replaced password hashes,
    password resets and changes, verified addresses, refused and throttled emails, and
    how long hashing requests wait in the queue. There is no built-in implementation
    and no dependency on a metrics library; events never contain passwords, tokens or
    hashes.
- `encryption` cargo feature (off by default) with the `rusted_auth::encryption` module:
  `Keyring` encrypts secrets at rest with XChaCha20-Poly1305 and a random 192-bit nonce
  per encryption. It holds several keys with identifiers; the active one encrypts and
  all of them decrypt, and the key identifier is stored in front of each ciphertext, so
  keys can be rotated. A caller-supplied context is authenticated with the ciphertext.
  `Keyring::parse` reads `id:base64key,...` strings; the library reads no environment
  variables.
- `mfa` cargo feature (off by default) with the `rusted_auth::mfa` module: TOTP
  (RFC 6238) and recovery codes, independent of any web framework or database.
  - `Mfa::start_totp` creates a secret and returns it once with its `otpauth://` URI;
    `Mfa::confirm_totp` switches TOTP on after one correct code and returns the recovery
    codes once. An unconfirmed setup does not affect login.
  - `Mfa::complete_login` takes the token of a pending session and a TOTP code or a
    recovery code, and returns a new active session under a new token (`MfaLogin`).
    After 5 wrong codes the pending session is revoked and the user must log in again
    (`MfaConfig::max_attempts`).
  - TOTP codes are compared in constant time, accepted for one step either way by
    default, and accepted once: codes for the last used step or older ones are refused.
    Defaults are HMAC-SHA-1, 6 digits, 30 seconds and 160-bit secrets (`TotpConfig`).
  - 10 distinct six-digit recovery codes per set (`MfaConfig::recovery_codes` and
    `MfaConfig::recovery_code_digits`, 6 to 12 digits), single use. They are stored as
    HMAC-SHA-256 under a key derived from the `Keyring`, bound to the account. Input of
    TOTP length is checked as a TOTP code first, then as a recovery code.
  - A code is used up only after the new session exists, so a login that fails for
    another reason leaves the code valid.
  - `Mfa::regenerate_recovery_codes` replaces all recovery codes and `Mfa::disable_totp`
    deletes the secret and every code. Both take a current TOTP code or an unused
    recovery code and use it up; after 5 wrong codes per account they are refused for
    5 minutes. An unfinished setup is removed without a code.
  - TOTP secrets are stored encrypted with the application's `Keyring`, bound to their
    account, and re-encrypted with the active key after a rotation when they are next
    used.
  - Wrong codes are counted in a `session::AttemptStore` (`MfaBuilder::attempts`), one atomic
    "count unless at the limit" step that a single SQL statement can implement. The
    default `MemoryAttemptStore` counts per process; several processes share a store
    so that the limits hold across all of them. A failing counter store refuses codes.
  - `MfaStore` trait for persistence, and `MemoryMfaStore` for tests. `MfaError` with
    `public_message()` and `kind()`.
  - With the `local` feature, `LocalAuthBuilder::mfa` makes password logins of accounts
    with confirmed TOTP return a session in state `PendingMfa` (5 minutes) instead of
    an active one (`Login::mfa_required`).
  - New audit events: `MfaSucceeded`, `MfaFailed`, `MfaAttemptsExceeded`,
    `TotpEnabled`, `TotpDisabled` and `RecoveryCodesGenerated`. `MfaFailed` and
    `MfaAttemptsExceeded` carry no session for codes that confirm a change.
    `LoginSucceeded` tells
    whether the second step is required, and `SessionActivated` names the replaced
    session. Secrets and codes never appear in events, errors, logs or `Debug` output.
- `test-util` cargo feature: `PasswordHasher::insecure_for_tests`, a hasher with the
  weakest argon2 parameters so that test suites stay fast. Never enable it in a
  production build.
  - `session::conformance` (and `mfa::conformance` with the `mfa` feature): checks that
    a storage implementation behaves like the in-memory stores, including the
    operations the traits require to be atomic under concurrent calls. The in-memory
    stores pass them.
- New crate `rusted-auth-sea-orm`: Postgres storage with SeaORM 2.0. `SeaOrmStore`
  implements `UserStore`, `SessionStore`, `OneTimeTokenStore`, `AttemptStore` and,
  with its `mfa` feature, `MfaStore`; `SeaOrmStore::event_sink` records audit events in
  `auth_events` through a bounded queue and a writer task. The `migration` module
  creates `users`, `sessions`, `one_time_tokens`, `mfa_totp`, `mfa_recovery_codes`,
  `auth_attempts` and `auth_events`, either through `Migrator` or merged into the
  application's migrator. `SeaOrmStore::cleanup` deletes ended sessions, used and
  expired tokens, ended attempt counters, and audit events older than a year
  (`Retention`), for a periodic job of the application. The crate needs Rust 1.94.
- `rusted-auth-actix`: `session` feature with `SessionAuth`, which finds the session in
  the `__Host-session` cookie or an `Authorization: Bearer` token and hands handlers a
  `CurrentSession` or `MaybeSession`. Browser requests that change data need an allowed
  `Origin` (or `Referer`) and the `__Host-csrf` cookie echoed in `X-CSRF-Token`
  (`WebConfig`).
- `rusted-auth-actix`: `local` feature with `AuthRoutes`, the HTTP routes for local
  accounts: register, web and mobile login, logout, email verification, resending it,
  forgot, reset and change password, and with `mfa` the second factor (verify, status,
  TOTP start, confirm and disable, new recovery codes). A successful second factor
  replaces the cookie or returns a new token. Email links open a page that posts the
  token, or forward to the application (`LinkTargets`), with
  `Referrer-Policy: no-referrer`. Registration answers the same for a new and a
  registered address unless `reveal_existing_email` is on.
- `rusted-auth-actix`: `RateLimiter`, per-client-address limits for login,
  registration, emails and tokens, in memory or shared through an `AttemptStore`. The
  address is stored as a keyed HMAC, IPv6 grouped by /64. `TrustedProxies` reads
  `X-Forwarded-For` from the right, past the listed proxies.
- `rusted-auth-actix`: `SpawnMailer` sends emails on a tokio task, with a bounded queue.
- `rusted-auth-actix`: `utoipa` feature with `openapi::AuthApi` and `openapi::MfaApi`,
  the OpenAPI paths and schemas of the routes for utoipa 6.
- `AttemptScope::ClientAddress`, and `LocalAuth::second_factor_enabled` and
  `LocalAuth::reveals_existing_email`.

### Changed

- `rusted-auth-actix`: `AuthResponder::respond` takes an `AuthFailure` (status, stable
  `code`, public message, field errors) instead of an `AuthError`. The default
  `ProblemResponder` writes RFC 9457 problem details (`application/problem+json`);
  `JsonResponder` is removed.

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
