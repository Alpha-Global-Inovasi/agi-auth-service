# Test fixtures

RSA keypairs used only by the unit tests to sign fake Firebase ID tokens.
They are not secrets and must never be used outside tests.

- `rsa_private.pem` / `rsa_public.pem`: the "Google" key the tests install in the JWK cache
- `rsa_other_private.pem`: an unrelated key, for invalid-signature tests
