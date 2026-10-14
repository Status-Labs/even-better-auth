# Threat model

This document says what even better auth defends against, what it assumes about the
deployment, and where review is most needed. It is a working document for contributors and
reviewers. It is not a claim that the defenses are free of bugs; the project has not been
independently audited (see [SECURITY.md](SECURITY.md)).

## What the library is

A server-side authentication library. It runs inside the application's process, exposes HTTP
endpoints under a base path (default `/api/auth`), and stores users, sessions, accounts and
verification values through an `Adapter` (in-memory or sqlx) and, optionally, a
`SecondaryStorage` (in-memory or Redis). It is wire-compatible with the TypeScript
better-auth, so browsers and the official JS client talk to it directly.

## Assets

- **Credentials:** password hashes, OAuth access/refresh/ID tokens, TOTP secrets, backup
  codes, passkey public keys and counters, API key hashes.
- **Session state:** session tokens, signed session cookies, cookie caches (compact, JWT,
  JWE), the `account_data` cookie in stateless mode.
- **One-time values:** email verification, password reset, magic link, OTP, OAuth `state`,
  PKCE verifiers, WebAuthn challenges, device codes, one-time tokens.
- **Secrets held by the deployer:** `secret`/`secrets` (cookie signing, encryption, HKDF
  purpose keys), JWKS private keys, OAuth client secrets.
- **Authorization data:** roles, organization memberships, permissions, API key quotas.

## Trust boundaries

1. **Client → server HTTP.** Everything in a request (body, query, headers, cookies) is
   attacker-controlled.
2. **Server → identity providers.** OAuth/OIDC token and userinfo responses, discovery
   documents and JWKS are trusted only after the checks listed below.
3. **Server → database and Redis.** Treated as trusted storage. An attacker with write access
   there is out of scope.
4. **Library → application callbacks.** Hooks, email/SMS senders, `verify_message` (SIWE),
   custom session data. These run with full trust; their correctness is the application's
   responsibility.

## Attacker model

In scope:

- A remote, unauthenticated attacker sending arbitrary HTTP requests.
- An authenticated user trying to reach other users' data or escalate roles (admin,
  organization, API key permissions).
- A malicious website the victim visits (CSRF, open redirects, login CSRF, OAuth
  mix-up through crafted callback URLs).
- A network attacker without TLS termination access (cookie theft over plain HTTP, when
  `Secure` cookies are in use).
- Concurrency attacks: racing requests to reuse one-time tokens, exceed quotas, or double
  spend verification values.

Out of scope:

- Compromise of the host, the database, Redis, or the deployer's secrets.
- Malicious application callbacks or plugins.
- Denial of service beyond the built-in rate limiter (volumetric attacks belong to the
  infrastructure in front of the server).
- Side channels other than response timing of secret comparisons.

## Defenses and where they live

| Threat | Defense | Code |
|---|---|---|
| Cookie tampering | HMAC-SHA256 signed cookies, constant-time verification | `api/mod.rs`, `crypto/mod.rs` |
| Cookie cache disclosure | `dir`/`A256CBC-HS512` JWE with HKDF-derived keys; compact and JWT strategies are signed, not encrypted | `crypto/jwe.rs`, `cookies/session.rs` |
| Password cracking after a leak | scrypt (N=16384, r=16, p=1, 64-byte key), parameters fixed by TS compatibility | `crypto/password.rs` |
| Guessable tokens and ids | CSPRNG (`rand::rng`, ChaCha seeded from the OS) | `crypto/random.rs` |
| Timing leaks on secrets | `subtle` constant-time comparison for signatures, password hashes, OTPs, JWE tags | `crypto/mod.rs` |
| CSRF | Origin/Referer validation against trusted origins for state-changing requests; Fetch Metadata checks on form posts | `api/middleware.rs` |
| Open redirects | callback/redirect URLs validated against trusted origins (wildcards, custom schemes) | `api/middleware.rs`, `utils/url.rs` |
| Brute force | rate limiting per IP and path, stricter defaults on sign-in, sign-up, change-password/email, password-reset and verification-email paths; two-factor attempt budgets and lockout | `api/rate_limit.rs`, `plugins/two_factor` |
| User enumeration | uniform responses on sign-up/sign-in/reset paths where TS provides them | `api/routes` |
| OAuth CSRF / code injection | `state` bound to DB or cookie, PKCE, ID-token nonce and audience checks; issuer checks where the provider has a fixed issuer | `oauth2/state.rs`, `oauth2/id_token.rs` |
| One-time token reuse | consumption is atomic (guarded updates, transactions) on SQLite, Postgres and MySQL | `db`, `even-better-auth-sqlx` |
| Quota races (API keys) | guarded conditional updates; covered by a deterministic race test | `plugins/api_key/store.rs` |
| WebAuthn | challenge, origin, RP ID hash, flags, signature and counter checks following `@simplewebauthn/server` | `plugins/passkey/webauthn.rs` |
| SQL injection | values are always bound parameters; identifiers are quoted and come from the configured schema, never from request input | `even-better-auth-sqlx/src/query.rs` |
| Memory safety | no `unsafe` code (`unsafe_code = "forbid"` across the workspace) | `Cargo.toml` |
| Vulnerable dependencies | `cargo deny` (RustSec advisories, licenses, sources) in CI; Dependabot | `deny.toml` |

## Deployment assumptions

The defenses above hold only if the deployer:

- Sets a high-entropy `secret` of at least 32 characters (release builds refuse to start
  without one; debug builds fall back to a public default and log a warning).
- Serves over HTTPS so `Secure` cookies apply, and sets `base_url` correctly.
- Configures `trusted_origins` narrowly.
- Configures `ip.trusted_proxies` (or a single-hop `x-forwarded-for`) to match the real proxy
  chain. Otherwise clients can spoof their IP and evade rate limits.
- Uses Redis or database-backed rate limiting when running more than one process; the
  in-memory limiter is per process.

## Known gaps

- Passkey attestation: `none` and `packed` self-attestation are verified; certificate
  attestation chains are **not** validated. Do not rely on attestation to restrict
  authenticator models.
- SIWE: the library checks the message, nonce, domain and time, but signature verification is
  the application's callback.
- The compact and JWT cookie-cache strategies are signed, not encrypted: their contents are
  readable by the client.
- The `rsa` crate has no fix for the Marvin timing attack (RUSTSEC-2023-0071). We only sign
  with RSA, and every signature is blinded. EdDSA, the JWT plugin's default, avoids the issue
  entirely; prefer it or ES256 if you can.
- Providers with tenant-dependent issuers (multi-tenant Microsoft Entra ID: `common`,
  `organizations`, `consumers`) replace the fixed issuer check with a tenant-claim check,
  matching TS.
- No fuzzing yet of the parsers listed below.

## Where review helps most

Ordered by expected impact:

1. Session and cookie handling: signing, cookie cache strategies, chunking, refresh, stateless
   mode (`cookies/`, `api/routes/session*`).
2. OAuth2/OIDC: state, PKCE, ID-token validation, account linking rules (`oauth2/`,
   `plugins/generic_oauth`).
3. WebAuthn and the CBOR/authData parser (`plugins/passkey/`).
4. CSRF/origin checks and trusted-origin matching (`api/middleware.rs`, `utils/url.rs`).
5. Two-factor flows and trusted devices (`plugins/two_factor`).
6. Authorization in admin, organization and api-key (`plugins/access.rs`,
   `plugins/organization`, `plugins/api_key`).
7. The SQL builder and guarded updates (`even-better-auth-sqlx`).
8. JOSE: JWK import, JWS verification, JWE (`crypto/`).

Paths are relative to `crates/even-better-auth/src` unless they name another crate.
