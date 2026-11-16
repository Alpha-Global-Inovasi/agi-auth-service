# Rotating encryption keys

The `mfa` feature keeps two kinds of secret data under the application's `Keyring`:

- **TOTP secrets**, encrypted with XChaCha20-Poly1305 under a key of the keyring. The
  identifier of that key is stored in front of each ciphertext.
- **Recovery codes**, stored as HMAC-SHA-256 under a hashing key derived from a key of
  the keyring. A hash cannot be decrypted or re-hashed: the code itself is never
  stored, so only the user's next set of codes can move to a new key.

The library reads no environment variables. The application loads the keys (for
example `AUTH_ENCRYPTION_KEYS=2026-06:base64key,2026-01:base64key`, parsed with
`Keyring::parse`) and decides which one is active.

## Steps

1. **Add a new key and make it active**, keeping every old key in the keyring:

   ```rust
   let keyring = Keyring::parse(&keys_from_your_secret_store)?.activate("2026-06")?;
   ```

   Deploy this to every process before anything else. A process that does not know the
   new key cannot read what the others write with it.

2. **TOTP secrets move by themselves.** After each successful TOTP login the secret is
   encrypted again with the active key. Secrets of users who do not log in stay on the
   old key; a job of yours can move them with `Keyring::decrypt` and
   `Keyring::encrypt` and `MfaStore::replace_totp_secret`. The context the library
   authenticates with each secret is the bytes `mfa_totp.secret_enc`, a zero byte, and
   the 16 bytes of the account's UUID; a secret encrypted under another context does not
   decrypt. `Keyring::key_id_of` tells which key a stored secret uses.

3. **Recovery codes do not move.** A code is still accepted while the key it was
   hashed under is in the keyring, because lookups try every key, the active one
   first. Each user's codes move to the new key only when that user generates a new
   set (`Mfa::regenerate_recovery_codes`, or confirming TOTP again). Ask users to do
   so, for example with a notice after login, and track who has not.

4. **Remove the old key only after both have moved**: no TOTP secret uses it and every
   user with recovery codes hashed under it has generated a new set.

   **Removing a key earlier makes those recovery codes stop working without any
   error**: they simply no longer match. A user who then loses their authenticator is
   locked out of the account. TOTP secrets under a removed key fail to decrypt, and
   those logins fail as a server error.

## Backups

Keep every key that is still in the keyring in your secret store's backup. A database
backup is useless for second factors without the keys that were in use when it was
taken.

## If a key leaks

Treat a leaked key as a leaked copy of every TOTP secret it encrypts, given access to
the database. Rotate as above, then reset the second factor of the affected accounts
(`MfaStore::delete_totp` from an administrative path, then a new setup by each
user) rather than waiting for logins to re-encrypt the secrets: re-encryption does not
change the secret itself.
