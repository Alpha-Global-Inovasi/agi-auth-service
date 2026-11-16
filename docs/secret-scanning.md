# Secret scanning

Tokens issued by `rusted-auth` have fixed prefixes, the same in every deployment, so
one pattern finds them in logs, repositories, tickets and chat exports:

| Token | Pattern | Where it lives |
|---|---|---|
| Session | `rusted_s_[A-Za-z0-9_-]{43}` | `__Host-session` cookie, `Authorization: Bearer` header, mobile app storage |
| Single-use link (email verification, password reset) | `rusted_t_[A-Za-z0-9_-]{43}` | URLs in emails, and therefore access logs and `Referer` headers |

Both are the prefix followed by 256 random bits in base64url without padding. Only
their SHA-256 hashes are stored, so a match in a log or a file is a live credential
until the session ends or the link expires (1 hour for password reset, 24 hours for
email verification, by default).

A leaked session token is revoked with `SessionManager::revoke` (or every session of
the account with `revoke_all`). A leaked reset link stops working once the user asks
for a new one or changes the password.

## GitHub secret scanning

On GitHub Advanced Security or GitHub Secret Protection, add custom patterns under
**Settings → Code security → Secret scanning → Custom patterns** (repository or
organization):

| Name | Secret format | Before secret | After secret |
|---|---|---|---|
| rusted-auth session token | `rusted_s_[A-Za-z0-9_-]{43}` | `\A\|[^A-Za-z0-9_-]` | `\z\|[^A-Za-z0-9_-]` |
| rusted-auth link token | `rusted_t_[A-Za-z0-9_-]{43}` | `\A\|[^A-Za-z0-9_-]` | `\z\|[^A-Za-z0-9_-]` |

Enable push protection for both, so a token pasted into a test fixture or a log
excerpt is caught before it is pushed.

## gitleaks

Add the rules to the `.gitleaks.toml` of the repositories you scan (they extend the
default rules):

```toml
[extend]
useDefault = true

[[rules]]
id = "rusted-auth-session-token"
description = "rusted-auth session token"
regex = '''\brusted_s_[A-Za-z0-9_-]{43}(?:[^A-Za-z0-9_-]|$)'''
keywords = ["rusted_s_"]

[[rules]]
id = "rusted-auth-link-token"
description = "rusted-auth single-use link token (email verification, password reset)"
regex = '''\brusted_t_[A-Za-z0-9_-]{43}(?:[^A-Za-z0-9_-]|$)'''
keywords = ["rusted_t_"]
```

The same file is in this repository as [`gitleaks.toml`](gitleaks.toml).

## Other scanners

The patterns are plain regular expressions; tools such as TruffleHog (custom
detectors), detect-secrets (a regex plugin) or a log pipeline filter take them as
they are. To redact rather than detect, replace the 43 characters after the prefix and
keep the prefix, so the log still shows which kind of token was there.

## Logs

The library never logs tokens, and `Debug` output of `SessionToken` and
`OneTimeToken` is redacted. Link tokens still reach access logs through URLs when the
email link points at `GET /email/verify?token=...` or `GET /password/reset?token=...`
of `rusted-auth-actix`. Point email links at your front end instead, with the token in
the URL fragment (`#token=...`), which browsers never send to a server; or redact the
`token` query parameter in your proxy's access log.
