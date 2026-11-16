# Migrating to 0.5

0.5 adds local accounts, sessions, a second factor (TOTP and recovery codes), Postgres
storage and HTTP routes. Token verification (`Verifier`, `Issuer`, `Principal`) is
unchanged. This guide covers what breaks for code written against 0.4.1, and, at the
end, against pre-releases of 0.5 taken from git.

## Dependencies

```toml
[dependencies]
rusted-auth = "0.5"
rusted-auth-actix = "0.5"
```

The new parts sit behind cargo features that are off by default:

| Crate | Feature | What it adds |
|---|---|---|
| `rusted-auth` | `session` | Sessions, accounts, single-use tokens, attempt counters, audit events |
| `rusted-auth` | `local` | Registration and password login (turns on `session`) |
| `rusted-auth` | `mfa` | TOTP and recovery codes (turns on `session` and `encryption`) |
| `rusted-auth` | `encryption` | `Keyring` for secrets at rest |
| `rusted-auth-actix` | `session`, `local`, `mfa`, `utoipa` | Session middleware and CSRF, the routes, the second-factor routes, the OpenAPI description |
| `rusted-auth-sea-orm` | (new crate) | Postgres storage and migrations, Rust 1.94 or newer |

An application that only verifies tokens needs no feature and no code change in
`rusted-auth`.

## `rusted-auth-actix`: responses

### `AuthResponder` takes an `AuthFailure`

`AuthResponder::respond` now receives an `AuthFailure` instead of an `AuthError`. An
`AuthFailure` covers every failure the crate answers, not only token verification:
session and CSRF failures, rate limits, and the errors of the new routes. It carries
the HTTP status, a stable `code`, a public message and, for 422, errors per field.

```rust
// 0.4
impl AuthResponder for MyResponder {
    fn respond(&self, error: &AuthError) -> HttpResponse {
        HttpResponse::build(Self::status_for(error))
            .json(json!({ "message": error.public_message() }))
    }
}

// 0.5
impl AuthResponder for MyResponder {
    fn respond(&self, failure: &AuthFailure) -> HttpResponse {
        HttpResponse::build(failure.status())
            .json(json!({ "code": failure.code(), "message": failure.public_message() }))
    }
}
```

`AuthResponder::status_for` is removed: use `AuthFailure::status`. The crate still adds
`WWW-Authenticate` to 401 answers of bearer requests, and now also `Retry-After` to 429
and 503 answers, unless your responder set them.

### `JsonResponder` is removed; the default body is RFC 9457

The default responder is now `ProblemResponder`, which writes problem details with
`Content-Type: application/problem+json`:

```json
{ "type": "about:blank", "title": "Invalid token", "status": 401, "code": "unauthenticated" }
```

0.4 wrote `{"status": false, "message": "...", "data": null}`. Clients that parse
that body must either switch to the new one or keep the old shape with a responder of
their own:

```rust
struct LegacyResponder;

impl AuthResponder for LegacyResponder {
    fn respond(&self, failure: &AuthFailure) -> HttpResponse {
        HttpResponse::build(failure.status()).json(serde_json::json!({
            "status": false,
            "message": failure.public_message(),
            "data": null,
        }))
    }
}

// Authenticate::required(verifier).responder(LegacyResponder)
```

`ProblemResponder::body` returns the problem details as JSON, for a responder that only
adds a member such as a request id.

## Adding sessions and the routes

Nothing here is required by an upgrade; it is what the new features expect once they
are turned on. The crate READMEs have complete examples.

- **Cookies and headers.** Browsers get the session in `__Host-session`
  (`HttpOnly; Secure; SameSite=Lax; Path=/`) and a CSRF token in `__Host-csrf`
  (readable by JavaScript). Requests that change data send the CSRF token back in
  `X-CSRF-Token`. The `__Host-` prefix means the cookies are only accepted over HTTPS
  and without a `Domain`, so the API and the pages must share one origin or the API
  must be reached through the pages' origin. Local development over plain HTTP needs a
  browser that treats `localhost` as secure (current browsers do).
- **`WebConfig` needs the allowed origins.** `WebConfig::new(["https://app.example.com"])`
  fails without at least one origin. There is no default such as "the request's own
  `Host`".
- **Which requests are checked for CSRF.** A request that changes data is checked
  (allowed `Origin`, or `Referer` without `Origin`, and the double-submit token) when
  it comes from a browser:
  - the route sets or clears the session cookie (`/login`, `/mfa/verify` with a
    cookie session, `/logout` without a bearer token), whatever its headers;
  - it has `Authorization: Bearer` **and** a `Cookie` header;
  - it has no bearer token and has any of `Cookie`, `Origin` or `Referer`.
    `Origin: null` counts as present and is refused.

  Bearer requests without cookies, and native clients that send none of `Cookie`,
  `Origin` and `Referer`, are not checked. A single-page app calls `GET /csrf` once
  before its first form.
- **Mobile apps** log in with `POST /mobile/login` and send `Authorization: Bearer`
  from then on.
- **Second factor.** Pass the same `Mfa` to `LocalAuthBuilder::mfa` and
  `AuthRoutesBuilder::mfa`; `AuthRoutesBuilder::build` fails when only one side has it,
  because without `LocalAuthBuilder::mfa` logins never ask for the second factor.
- **Several processes.** Give every process the same `rusted-auth-sea-orm` store for
  sessions, tokens and attempt counters, and the same 32-byte key to
  `RateLimiter::shared`. With the in-memory defaults each process counts on its own.
- **Behind a reverse proxy**, set `WebConfig::trusted_proxies`, or every client counts
  as the proxy for rate limits.
- **Email** must not wait for SMTP (response times would reveal registered
  addresses). Queue it, or wrap your mailer in `SpawnMailer`.
- **Cleanup.** Run `SeaOrmStore::cleanup` from a periodic job.

Read [password reset](security.md#password-reset) and [key rotation](key-rotation.md)
before going to production.

## From pre-releases of 0.5 (git dependencies)

Applications that used `rusted-auth` from git before 0.5.0 was published:

- **Modules.** `User`, `UserStore`, `MemoryUserStore`, `StoreError`, sessions
  (`SessionManager`, `SessionStore`, tokens, `SessionConfig`) and `EventSink` live in
  `rusted_auth::session`, not `rusted_auth::local`. `AttemptStore`,
  `MemoryAttemptStore` and `AttemptScope` moved from `rusted_auth::mfa` to
  `rusted_auth::session`.
- **`LocalAuthBuilder::mailer` and `LocalAuthBuilder::tokens` are required.** `build()`
  fails without them. An application that sends no email passes `NoMailer` explicitly;
  the token store must be shared by every process (`SeaOrmStore`), since a link made in
  one process is used in another.
- **Table names.** The attempt counter table is `auth_attempts` (it was `mfa_attempts`
  in early drafts). Its `scope` column takes `login`, `login_account`, `change`,
  `email`, `password_change` and `client_address`.
- **`JsonResponder`** is gone, as described above.
- **`MfaConfig::max_account_attempts`** is new: by default an account accepts 20 wrong
  second-step codes per hour across all its logins; see the changelog.
- **OpenAPI.** `openapi::AuthApi` no longer lists `GET /username-available`, which is
  only mounted when registration reveals existing addresses. Add
  `openapi::UsernameAvailableApi` in that case, or use `AuthRoutes::openapi`, which
  lists exactly the mounted routes. The `username` parameter is now described as a
  query parameter.
