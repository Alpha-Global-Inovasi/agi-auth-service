# Security Policy

`rusted-auth` is authentication code. We treat every vulnerability report as a priority.

## Supported versions

Until 1.0, only the latest minor release receives security fixes.

| Version | Supported |
|---|---|
| 0.5.x | yes |
| 0.4.x | no |
| < 0.4 (`agi-auth`, `cf-auth`) | no |

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:

1. Go to the repository's **Security** tab.
2. Choose **Report a vulnerability**.

Include the affected version, a description of the issue and its impact, and steps or a
proof of concept if you have one.

What to expect:

- Acknowledgement within 3 working days.
- An assessment and a planned fix date within 10 working days.
- A fixed release and a published advisory, with credit to you unless you prefer otherwise.

Please give us reasonable time to release a fix before disclosing publicly.

## Scope

In scope: token verification bypass, key confusion between issuers, algorithm confusion,
information leaks in error responses or logs, denial of service through crafted tokens or
JWKS documents, and anything that weakens the guarantees described in the README and in
[docs/security.md](docs/security.md): for local accounts, among others, ways to tell
registered addresses apart beyond the known limits listed there, lockout or rate limit
bypasses, session fixation, CSRF bypasses, and second-factor bypasses.

Out of scope: vulnerabilities in an identity provider itself, and misconfiguration by the
application (for example trusting an issuer you do not control).
