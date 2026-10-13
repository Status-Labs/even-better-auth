//! Configuration (`BetterAuthOptions`).

use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;
use http::HeaderMap;

use crate::api::{AfterHook, BeforeHook};
use crate::db::hooks::DatabaseHooks;
use crate::db::{Adapter, IdGenerator, TableOptions};
use crate::error::Result;
use crate::plugin::Plugin;
use crate::types::User;

#[cfg(feature = "oauth")]
use crate::oauth2::OAuthProvider;

/// An async callback taking `A`.
pub struct Callback<A>(Arc<dyn Fn(A) -> BoxFuture<'static, Result<()>> + Send + Sync>);

impl<A> Clone for Callback<A> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<A: Send + 'static> Callback<A> {
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        Self(Arc::new(move |a| Box::pin(f(a))))
    }

    pub async fn call(&self, a: A) -> Result<()> {
        (self.0)(a).await
    }
}

/// Wrap an async closure as a [`Callback`].
pub fn callback<A: Send + 'static, F, Fut>(f: F) -> Option<Callback<A>>
where
    F: Fn(A) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    Some(Callback::new(f))
}

/// Arguments for email callbacks carrying a link/token for a user.
#[derive(Debug, Clone)]
pub struct UserTokenEmail {
    pub user: User,
    pub url: String,
    pub token: String,
    /// Headers of the request that triggered the email, if any.
    pub request_headers: Option<HeaderMap>,
}

/// Custom password hashing.
#[derive(Clone)]
pub struct PasswordHasher {
    pub hash: Arc<dyn Fn(String) -> BoxFuture<'static, Result<String>> + Send + Sync>,
    pub verify: Arc<dyn Fn(String, String) -> BoxFuture<'static, Result<bool>> + Send + Sync>,
}

#[derive(Clone)]
pub struct EmailAndPasswordOptions {
    pub enabled: bool,
    pub disable_sign_up: bool,
    pub require_email_verification: bool,
    pub min_password_length: usize,
    pub max_password_length: usize,
    /// Sign the user in after sign-up (default `true`).
    pub auto_sign_in: bool,
    pub send_reset_password: Option<Callback<UserTokenEmail>>,
    /// Seconds until a reset-password token expires (default 1 hour).
    pub reset_password_token_expires_in: i64,
    pub on_password_reset: Option<Callback<User>>,
    pub revoke_sessions_on_password_reset: bool,
    pub password: Option<PasswordHasher>,
    /// Called when someone signs up with an existing email in generic-duplicate mode.
    pub on_existing_user_sign_up: Option<Callback<User>>,
}

impl Default for EmailAndPasswordOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            disable_sign_up: false,
            require_email_verification: false,
            min_password_length: 8,
            max_password_length: 128,
            auto_sign_in: true,
            send_reset_password: None,
            reset_password_token_expires_in: 60 * 60,
            on_password_reset: None,
            revoke_sessions_on_password_reset: false,
            password: None,
            on_existing_user_sign_up: None,
        }
    }
}

impl EmailAndPasswordOptions {
    pub fn enabled() -> Self {
        Self { enabled: true, ..Default::default() }
    }
}

#[derive(Clone)]
pub struct EmailVerificationOptions {
    pub send_verification_email: Option<Callback<UserTokenEmail>>,
    /// Send on sign-up. Defaults to `require_email_verification` when unset.
    pub send_on_sign_up: Option<bool>,
    pub send_on_sign_in: bool,
    pub auto_sign_in_after_verification: bool,
    /// Seconds until the verification token expires (default 1 hour).
    pub expires_in: i64,
    pub before_email_verification: Option<Callback<User>>,
    pub after_email_verification: Option<Callback<User>>,
}

impl Default for EmailVerificationOptions {
    fn default() -> Self {
        Self {
            send_verification_email: None,
            send_on_sign_up: None,
            send_on_sign_in: false,
            auto_sign_in_after_verification: false,
            expires_in: 3600,
            before_email_verification: None,
            after_email_verification: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CookieCacheStrategy {
    #[default]
    Compact,
    Jwt,
    Jwe,
}

#[derive(Debug, Clone)]
pub struct CookieCacheOptions {
    pub enabled: bool,
    /// Seconds (default 5 minutes).
    pub max_age: i64,
    pub strategy: CookieCacheStrategy,
    pub version: String,
    /// Refresh the cache cookie when within `update_age` seconds of expiry, without a DB hit.
    /// `None` disables refreshing (the TS default is `false`).
    pub refresh_cache_update_age: Option<i64>,
}

impl Default for CookieCacheOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: 300,
            strategy: CookieCacheStrategy::Compact,
            version: "1".into(),
            refresh_cache_update_age: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub table: TableOptions,
    /// Seconds (default 7 days).
    pub expires_in: i64,
    /// Seconds between session expiry extensions (default 1 day).
    pub update_age: i64,
    /// Seconds a session counts as "fresh" for sensitive operations (default 1 day, 0 disables).
    pub fresh_age: i64,
    pub disable_session_refresh: bool,
    pub defer_session_refresh: bool,
    pub cookie_cache: CookieCacheOptions,
    /// With secondary storage, also write sessions to the database (default false).
    pub store_session_in_database: bool,
    /// With secondary storage and `store_session_in_database`, keep revoked session rows
    /// (ended by setting `expiresAt` to now) instead of deleting them.
    pub preserve_session_in_database: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            table: TableOptions::default(),
            expires_in: 60 * 60 * 24 * 7,
            update_age: 60 * 60 * 24,
            fresh_age: 60 * 60 * 24,
            disable_session_refresh: false,
            defer_session_refresh: false,
            cookie_cache: CookieCacheOptions::default(),
            store_session_in_database: false,
            preserve_session_in_database: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccountLinkingOptions {
    pub enabled: bool,
    /// Providers whose emails are trusted for implicit linking even if unverified.
    pub trusted_providers: Vec<String>,
    pub allow_different_emails: bool,
    pub allow_unlinking_all: bool,
    pub update_user_info_on_link: bool,
    /// Require the existing local user's email to be verified before implicit linking.
    pub require_local_email_verified: bool,
    /// Never link a new provider account to an existing user by email.
    pub disable_implicit_linking: bool,
}

impl Default for AccountLinkingOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            trusted_providers: vec![],
            allow_different_emails: false,
            allow_unlinking_all: false,
            update_user_info_on_link: false,
            require_local_email_verified: true,
            disable_implicit_linking: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AccountOptions {
    pub table: TableOptions,
    pub account_linking: AccountLinkingOptions,
    pub encrypt_oauth_tokens: bool,
    pub skip_state_cookie_check: bool,
    /// Store OAuth state in a cookie instead of the verification table.
    pub store_state_in_cookie: bool,
    pub update_account_on_sign_in: Option<bool>,
    /// Keep the OAuth account (with its tokens) in an encrypted `account_data` cookie, so
    /// token routes work without a database lookup. On by default in stateless mode.
    pub store_account_cookie: bool,
}

#[derive(Clone, Default)]
pub enum StoreIdentifier {
    #[default]
    Plain,
    Hashed,
    /// Hash identifiers that start with any of these prefixes; store the rest plainly.
    HashedPrefixes(Vec<String>),
}

impl StoreIdentifier {
    pub fn should_hash(&self, identifier: &str) -> bool {
        match self {
            StoreIdentifier::Plain => false,
            StoreIdentifier::Hashed => true,
            StoreIdentifier::HashedPrefixes(p) => p.iter().any(|p| identifier.starts_with(p.as_str())),
        }
    }
}

#[derive(Clone, Default)]
pub struct VerificationOptions {
    pub table: TableOptions,
    pub disable_cleanup: bool,
    pub store_identifier: StoreIdentifier,
    /// With secondary storage, also write verification values to the database (default false).
    pub store_in_database: bool,
}

#[derive(Clone, Default)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    /// Send a confirmation to the *current* email before changing it.
    pub send_change_email_confirmation: Option<Callback<ChangeEmailArgs>>,
    /// Allow changing the email immediately when the current email is unverified.
    pub update_email_without_verification: bool,
}

#[derive(Debug, Clone)]
pub struct ChangeEmailArgs {
    pub user: User,
    pub new_email: String,
    pub url: String,
    pub token: String,
    /// Headers of the request that triggered the email, if any.
    pub request_headers: Option<HeaderMap>,
}

#[derive(Clone, Default)]
pub struct DeleteUserOptions {
    pub enabled: bool,
    pub send_delete_account_verification: Option<Callback<UserTokenEmail>>,
    pub before_delete: Option<Callback<User>>,
    pub after_delete: Option<Callback<User>>,
    /// Seconds (default 1 day).
    pub delete_token_expires_in: Option<i64>,
}

#[derive(Clone, Default)]
pub struct UserOptions {
    pub table: TableOptions,
    pub change_email: ChangeEmailOptions,
    pub delete_user: DeleteUserOptions,
    /// Gate on user creation, account linking and provider sign-in (`validateUserInfo`).
    pub validate_user_info: Option<crate::utils::validate_user_info::ValidateUserInfoFn>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitStorage {
    Memory,
    Database,
    /// Counters in [`BetterAuthOptions::secondary_storage`] via `increment`.
    SecondaryStorage,
}

/// A rate limit rule: at most `max` requests per `window` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitRule {
    pub window: u64,
    pub max: u64,
}

#[derive(Debug, Clone)]
pub struct RateLimitOptions {
    /// Defaults to enabled in release builds only (TS: enabled in production).
    pub enabled: Option<bool>,
    pub window: u64,
    pub max: u64,
    /// Custom rules keyed by path pattern (wildcards allowed); `None` disables limiting for the path.
    pub custom_rules: Vec<(String, Option<RateLimitRule>)>,
    /// Defaults to secondary storage when configured, otherwise memory.
    pub storage: Option<RateLimitStorage>,
}

impl Default for RateLimitOptions {
    fn default() -> Self {
        Self { enabled: None, window: 10, max: 100, custom_rules: vec![], storage: None }
    }
}

impl BetterAuthOptions {
    /// The rate-limit storage in effect.
    pub fn rate_limit_storage(&self) -> RateLimitStorage {
        self.rate_limit.storage.unwrap_or(if self.secondary_storage.is_some() {
            RateLimitStorage::SecondaryStorage
        } else {
            RateLimitStorage::Memory
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct CookieAttributes {
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<crate::cookies::SameSite>,
    pub partitioned: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct CookieOverride {
    pub name: Option<String>,
    pub attributes: CookieAttributes,
}

#[derive(Debug, Clone, Default)]
pub struct CrossSubDomainCookies {
    pub enabled: bool,
    pub domain: Option<String>,
}

#[derive(Clone, Default)]
pub struct AdvancedOptions {
    pub ip_address: crate::utils::ip::IpConfig,
    pub use_secure_cookies: Option<bool>,
    pub disable_csrf_check: bool,
    pub disable_origin_check: bool,
    pub cross_sub_domain_cookies: CrossSubDomainCookies,
    /// Per-cookie overrides keyed by cookie name without prefix (e.g. `"session_token"`).
    pub cookies: Vec<(String, CookieOverride)>,
    pub default_cookie_attributes: CookieAttributes,
    /// Defaults to `"better-auth"`.
    pub cookie_prefix: Option<String>,
    pub generate_id: IdGenerator,
    /// Trust `x-forwarded-host`/`x-forwarded-proto` when inferring the base URL.
    pub trusted_proxy_headers: bool,
}

#[derive(Clone, Default)]
pub struct Hooks {
    pub before: Option<BeforeHook>,
    pub after: Option<AfterHook>,
}

/// Top-level configuration. Construct with [`BetterAuthOptions::new`] and adjust fields.
#[derive(Clone)]
pub struct BetterAuthOptions {
    pub app_name: String,
    /// Public base URL of the server, e.g. `https://example.com`. When unset it is inferred
    /// per request from the `Host` header.
    pub base_url: Option<String>,
    pub base_path: String,
    /// Secret for signing and encryption. Falls back to `BETTER_AUTH_SECRET` / `AUTH_SECRET`.
    pub secret: Option<String>,
    /// Versioned secrets for rotation; the highest version is current.
    pub secrets: Vec<(u32, String)>,
    pub database: Arc<dyn Adapter>,
    /// No persistent database ([`BetterAuthOptions::stateless`]): `database` is a process-local
    /// memory adapter and sessions live in the cookie cache.
    pub stateless: bool,
    /// Key-value store (e.g. Redis) for sessions, verification values and rate limits.
    pub secondary_storage: Option<Arc<dyn crate::storage::SecondaryStorage>>,
    pub email_and_password: EmailAndPasswordOptions,
    pub email_verification: EmailVerificationOptions,
    #[cfg(feature = "oauth")]
    pub social_providers: Vec<Arc<dyn OAuthProvider>>,
    pub plugins: Vec<Arc<dyn Plugin>>,
    pub user: UserOptions,
    pub session: SessionOptions,
    pub account: AccountOptions,
    pub verification: VerificationOptions,
    pub trusted_origins: Vec<String>,
    pub rate_limit: RateLimitOptions,
    pub advanced: AdvancedOptions,
    pub database_hooks: DatabaseHooks,
    pub hooks: Hooks,
    /// Paths (relative to `base_path`) that respond 404.
    pub disabled_paths: Vec<String>,
    /// URL to redirect to for errors in browser flows; defaults to `{baseURL}/error`.
    pub on_api_error_url: Option<String>,
}

impl BetterAuthOptions {
    /// Options for a deployment without a database (TS: omitting `database`). Data lives in
    /// a process-local memory adapter, so durable state is carried in cookies: sessions in a
    /// JWE cookie cache that refreshes itself (lasting `session.expires_in`), and OAuth
    /// accounts in the account cookie. Suited to social sign-in; adjust fields as needed.
    pub fn stateless() -> Self {
        let mut options = Self::new(Arc::new(crate::db::MemoryAdapter::new()));
        options.stateless = true;
        let cache = &mut options.session.cookie_cache;
        cache.enabled = true;
        cache.strategy = CookieCacheStrategy::Jwe;
        cache.max_age = options.session.expires_in;
        cache.refresh_cache_update_age = Some(cache.max_age / 5);
        options.account.store_account_cookie = true;
        options
    }

    pub fn new(database: Arc<dyn Adapter>) -> Self {
        Self {
            app_name: "Better Auth".into(),
            base_url: None,
            base_path: "/api/auth".into(),
            secret: None,
            secrets: vec![],
            database,
            stateless: false,
            secondary_storage: None,
            email_and_password: Default::default(),
            email_verification: Default::default(),
            #[cfg(feature = "oauth")]
            social_providers: vec![],
            plugins: vec![],
            user: Default::default(),
            session: Default::default(),
            account: Default::default(),
            verification: Default::default(),
            trusted_origins: vec![],
            rate_limit: Default::default(),
            advanced: Default::default(),
            database_hooks: Default::default(),
            hooks: Default::default(),
            disabled_paths: vec![],
            on_api_error_url: None,
        }
    }
}
