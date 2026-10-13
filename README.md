# even better auth

> [!WARNING]
> Pre-1.0 and not yet security-reviewed. APIs will change, and it should not protect production
> data yet. Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

A Rust port of [better-auth](https://better-auth.com) (MIT; see [LICENSE](LICENSE)): a framework-agnostic authentication
library. The server speaks the same HTTP protocol as the TypeScript version: the same paths
under `/api/auth`, the same JSON shapes and error codes, and the same cookie names and formats.
The official JavaScript client (`better-auth/client`, React/Vue/Svelte bindings) therefore
works against a Rust backend unchanged.

## Crates

| Crate | Purpose |
|---|---|
| `even-better-auth` | Core: options, router, endpoints, cookies, crypto, adapter trait, in-memory adapter, OAuth2 |
| `even-better-auth-axum` | axum integration: mount the handler, `AuthSession` / `MaybeAuthSession` extractors |
| `even-better-auth-sqlx` | SQL adapter (SQLite / Postgres / MySQL) with schema migration |
| `even-better-auth-redis` | Redis secondary storage (sessions, verification values, rate limits) |

## Quick start (axum)

```rust
use std::sync::Arc;
use axum::{extract::FromRef, routing::get, Router};
use even_better_auth::{BetterAuth, BetterAuthOptions, EmailAndPasswordOptions, MemoryAdapter};
use even_better_auth_axum::{AuthSession, BetterAuthExt};

#[derive(Clone)]
struct AppState { auth: BetterAuth }
impl FromRef<AppState> for BetterAuth {
    fn from_ref(s: &AppState) -> Self { s.auth.clone() }
}

async fn me(AuthSession(s): AuthSession) -> String { s.user.email }

#[tokio::main]
async fn main() -> even_better_auth::Result<()> {
    let mut options = BetterAuthOptions::new(Arc::new(MemoryAdapter::new()));
    options.base_url = Some("http://localhost:3000".into());
    options.secret = Some(std::env::var("BETTER_AUTH_SECRET").unwrap());
    options.email_and_password = EmailAndPasswordOptions::enabled();
    let auth = BetterAuth::new(options).await?;
    auth.migrate().await?;

    let app = Router::new()
        .route("/me", get(me))
        .with_state(AppState { auth: auth.clone() })
        .mount_better_auth(auth);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
```

You can use other frameworks too: convert the request into `http::Request<Bytes>` and call
`auth.handler(req).await`. For server-side calls (TS `auth.api.*`), use
`auth.api(ApiCall::new("getSession").headers(h))` or helpers such as `auth.get_session(&headers)`.

See `examples/axum-server` for a runnable server.

## Design notes

How the TypeScript concepts map onto this crate:

| TypeScript | Rust |
|---|---|
| `betterAuth(options)` | `BetterAuth::new(BetterAuthOptions)` |
| `createAuthEndpoint` / better-call router | `Endpoint` + `handler(async fn(Ctx) -> EndpointResult)`; `api::dispatch` |
| `ctx.context` (`AuthContext`) | `ctx.auth: Arc<AuthContext>` |
| `AsyncLocalStorage` endpoint context | `tokio::task_local!` (`api::current_request()`) |
| `use: [sessionMiddleware]` | explicit guard calls: `require_session(&ctx).await?` |
| `hooks.before/after`, plugin hooks with matchers | `Hooks`, `PluginHooks` / `MatchedHook` |
| `databaseHooks` | `db::hooks::DatabaseHooks` |
| `runWithTransaction` / `getCurrentAdapter` | `auth.transaction(fut)` / `Db::transaction` (task-local scope); adapters implement `Adapter::begin` |
| `queueAfterTransactionHook` | `db::after_commit` |
| `createAdapterFactory` + `CustomAdapter` | `db::Db` (name mapping, ids, defaults) over the `Adapter` trait |
| `BetterAuthPlugin` | `trait Plugin` |
| `APIError` + `BASE_ERROR_CODES` | `ApiError` + `error::codes` |

Records cross the adapter boundary as `serde_json::Map`s; dates are RFC 3339 strings with
millisecond precision, the same as JavaScript's `toISOString`. Core models (`User`,
`Session`, `Account`, `Verification`) are typed structs. Plugin and additional fields live in a
flattened `extra` map.

## Compatibility

These are verified by tests:

- **Crypto** (`crates/better-auth/tests/js_compat.rs`). Vectors produced by `node:crypto`,
  `@noble/ciphers` and `jose` are checked against the Rust implementation:
  - scrypt password hashes (N=16384, r=16, p=1, dkLen=64)
  - signed-cookie HMAC
  - XChaCha20-Poly1305 symmetric encryption
  - `dir`/`A256CBC-HS512` JWE
  - HKDF purpose keys
- **Official JS client** (`e2e/js-client`). `better-auth@1.7.7`'s `createAuthClient` drives
  the Rust example server: sign-up, sign-in, sign-out, sessions and errors. `getCookieCache`
  decodes Rust-issued session caches for the `compact`, `jwt` and `jwe` strategies.

```sh
cargo test --workspace
./e2e/js-client/run.sh        # requires Node 20+
```

Postgres, MySQL and Redis tests run when their URLs are set (CI runs everything; see
`.github/workflows/ci.yml`):

```sh
DATABASE_URL_POSTGRES=postgres://postgres:pw@127.0.0.1:5432/postgres \
DATABASE_URL_MYSQL=mysql://root:pw@127.0.0.1:3306/ba \
REDIS_URL=redis://127.0.0.1:6379/ \
cargo test --workspace --all-features
```

## Status

The core library and all built-in TypeScript plugins are ported. The separately published packages are next.

- [x] Email & password: sign-up, sign-in, enumeration protection, password length rules
- [x] Sessions: get/list/revoke, refresh (`updateAge`), deferred refresh, `dontRememberMe`, freshness
- [x] Cookie cache: compact, JWT and JWE strategies, with chunking
- [x] Email verification (including change-email flows), auto sign-in after verification
- [x] Origin/CSRF protection, trusted origins (wildcards, custom schemes), rate limiting
- [x] Database hooks, request hooks, plugin trait, `validate_user_info` gate
- [x] Stateless mode (`BetterAuthOptions::stateless()`): JWE cookie-cache sessions with self-refresh, OAuth accounts in the `account_data` cookie (`store_account_cookie`)
- [x] In-memory adapter
- [x] Password reset, update user, change password/email, delete user, update session
- [x] OAuth2 social sign-in (PKCE, DB/cookie state, ID-token sign-in), account linking, account routes, `private_key_jwt` client authentication
- [x] JOSE: JWK import/export and JWS for EdDSA, ES256/384/512, RS*/PS* (interop-tested against `jose`)
- [x] Social providers: Apple, Atlassian, Cloudflare, Cognito, Discord, Dropbox, Facebook, Figma, GitHub, GitLab, Google, Hugging Face, Kakao, Kick, LINE, Linear, LinkedIn, Microsoft Entra ID, Naver, Notion, Paybin, PayPal, Polar, Railway, Reddit, Roblox, Salesforce, Slack, Spotify, TikTok, Twitch, Twitter/X, Vercel, VK, WeChat, Zoom
- [x] SQL adapter (sqlx): SQLite, Postgres, MySQL, with migrations (tested against Postgres 16 and MySQL 8.4)
- [x] Transactions: sign-up, OAuth user creation, password reset/change, user deletion and token consumption are atomic; database `after` hooks run after commit
- [x] Secondary storage (`secondary_storage`): in-memory and Redis; `store_session_in_database`, `preserve_session_in_database`, `verification.store_in_database`, rate limiting; same key layout as TS so servers can share a store
- [x] All TS social providers ported (36, `even_better_auth::social_providers`)
- [ ] Plugins (`even_better_auth::plugins`), ported one at a time:
  - [x] bearer
  - [x] username
  - [x] jwt (JWKS, rotation, `/token`, `set-auth-jwt`, server-side sign/verify, cookie-cache signing)
  - [x] magic-link
  - [x] email-otp
  - [x] two-factor (TOTP, OTP, backup codes, trusted devices, attempt budgets, account lockout)
  - [x] admin (with `plugins::access` role-based access control)
  - [x] organization (members, invitations, teams, dynamic roles, lifecycle hooks)
  - [x] anonymous
  - [x] multi-session
  - [x] phone-number
  - [x] one-time-token
  - [x] custom-session
  - [x] last-login-method
  - [x] haveibeenpwned (`oauth` feature, for the HTTP client)
  - [x] captcha (Turnstile, reCAPTCHA v2/v3, hCaptcha, CaptchaFox, BotID-style callback; `oauth` feature)
  - [x] generic-oauth (discovery, PKCE, nonce-bound ID tokens, presets: Auth0, Okta, Keycloak, Microsoft Entra ID, Slack, LINE, Yandex, HubSpot, Patreon, Gumroad; `oauth` feature)
  - [x] open-api (document built from routes and the DB schema; no per-endpoint body/response schemas)
  - [x] one-tap (`oauth` feature)
  - [x] siwe (message/nonce/domain/time checks and EIP-55 built in; signature verification is your callback)
  - [x] device-authorization (RFC 8628; the `grant` extension hook used by oauth-provider is not ported yet)
  - [x] oauth-proxy (`oauth` feature)
  - [x] oauth-popup (experimental in TS; `oauth` feature)
  - [x] api-key (`@better-auth/api-key`: hashing, prefixes, expiry, quotas with refills, per-key rate limits, permissions, metadata, user- or organization-owned keys, database / secondary-storage / both, sessions from `x-api-key`)
  - [x] passkey (`@better-auth/passkey`: registration and sign-in with WebAuthn, verified in pure Rust following `@simplewebauthn/server`; EdDSA, ES256/384/512, RS256/384, PS256/384/512; `none` and `packed` self-attestation verified, certificate attestation chains not validated)
  - [ ] separate packages: sso, oauth-provider, scim, ...
