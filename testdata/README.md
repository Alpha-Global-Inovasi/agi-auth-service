# Test fixtures

RSA keypairs used only by the test suites to sign fake tokens. They are **not secrets**,
are excluded from the published crates, and must never be used outside tests.

| File | Purpose |
|---|---|
| `rsa_private.pem`, `rsa_public.pem` | Key of the test issuer |
| `jwks.json` | Public half of `rsa_private.pem` as a JWKS document, `kid` = `test-kid` |
| `rsa_other_private.pem` | A second, unrelated key (wrong-signature and second-issuer tests) |
| `other_jwks.json` | Public half of `rsa_other_private.pem`, also `kid` = `test-kid` |

Regenerate a JWKS file from a PEM with `openssl rsa -noout -modulus` and base64url-encode
the modulus as `n` (`e` is `AQAB`).
