# Security notes for local accounts

What the `session`, `local` and `mfa` features guarantee, and the limits an
application has to know about. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Passwords and login

- argon2id with m = 19 MiB, t = 2, p = 1, run on the library's own threads: at most 8
  at once per process, and a request that waits more than 2 seconds fails as busy
  (503). Passwords are 8 to 128 characters, normalized to Unicode NFKC, without
  composition rules.
- A wrong password, an unknown account, a locked account and a disabled account get
  the same answer, and every attempt runs exactly one password hash check (a dummy
  one for accounts that do not exist). "Email address not verified" is only answered
  after the right password.
- An account locks after 5 consecutive failed logins, for 1 minute, doubling with each
  further failure up to 15 minutes. The account is read again after the hash check, so
  guesses sent in parallel are judged against the lock that earlier guesses set, and a
  lock in place is neither extended nor counted against.
- Every login creates a new session; a token known before the login never becomes
  authenticated by it.

### Known limits

- **Timing.** An existing account costs a few more database writes than an unknown
  one: a failed login records the failure, and the email routes store a token and
  count the email. The difference is small next to the password hash, but it is not
  zero; per-address rate limits (`RateLimiter`) keep it from being measured at scale.
- **Registration** can tell whether an address has an account at the cost of one
  registration per guess (register with the address and a username, then try the same
  username again). Username availability checks are off by default for that reason.

## Sessions

- Tokens are `rusted_s_` plus 256 random bits; only the SHA-256 hash is stored, and
  lookups compare in constant time.
- Validated sessions are cached in each process for up to **30 seconds**. A
  revocation (logout, password reset, password change, too many wrong codes) applies at
  once in the process that made it, and **within 30 seconds in other processes**.
  `SessionConfig::cache_ttl` can lower this, or switch the cache off.
- After the second factor, the pending session is revoked and replaced by a new one
  under a new token, so a token that leaked during the login is useless afterwards.

## Password reset

- A reset link holds a `rusted_t_` token, valid for 1 hour by default, stored as a
  SHA-256 hash together with the address it was sent to. Only the newest link of an
  account works, and it is used up in one atomic update.
- A successful reset stores the new hash, clears the lockout, ends the other reset
  links and **revokes every session of the account**. Those sessions stop working at
  once in the process that handled the reset and **within 30 seconds in the other
  processes** (the session cache above). Resets are often done because an account was
  taken over: if 30 seconds is too long for you, lower `SessionConfig::cache_ttl`.
- **Using the token and storing the new password are two separate store calls, not one
  transaction.** The new password is hashed first, then the token is used up, then the
  hash is stored. If storing fails after the token was used, the old password stays in
  place and the user has to request a new link. The opposite order would let two
  requests use the same token at once, so this one was chosen.
- A reset neither signs the user in nor skips the second factor.

## Second factor

- TOTP codes are compared in constant time and accepted once: the last used time step
  and older ones are refused, atomically in the store.
- Recovery codes are 10 codes of 6 digits by default, single use, stored as
  HMAC-SHA-256 under a key derived from the keyring and bound to the account.
- Wrong codes are limited three ways: 5 per login (the pending session is then
  revoked), **20 per account per hour across all its logins**
  (`MfaConfig::max_account_attempts`), and 5 per account in 5 minutes for disabling
  TOTP or replacing the recovery codes. The per-account limit matters because whoever
  knows the password can start a new login after every 5 wrong codes.
- Disabling TOTP and replacing recovery codes need a current code, so a stolen session
  alone cannot remove the second factor.
- Keys: see [key rotation](key-rotation.md). An old key may only be removed after the
  recovery codes made under it have been replaced.

## Web adapter

- Cookies `__Host-session` (`HttpOnly`) and `__Host-csrf`, both `Secure`,
  `SameSite=Lax`, `Path=/`. Browser requests that change data need an allowed `Origin`
  (or `Referer`) and the double-submit CSRF token; see `WebConfig` for which requests
  count as coming from a browser.
- Per-address rate limits on login, registration, the email routes and the link-token
  routes. Addresses are stored as a keyed HMAC, IPv6 grouped by /64.
  `X-Forwarded-For` is only read from configured proxies.
- Responses never contain internal errors; the full error goes to the log at `error`
  level for server failures and `debug` for rejected requests.

## Tokens in logs and repositories

See [secret scanning](secret-scanning.md) for the patterns of both token kinds.
