//! Shared auth state (`AuthContext`), built once from [`BetterAuthOptions`].

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::api::rate_limit::RateLimiter;
use crate::cookies::{AuthCookies, CookieFactory};
use crate::crypto::{self, SecretConfig};
use crate::db::hooks::DatabaseHooks;
use crate::db::internal::InternalConfig;
use crate::db::{Db, InternalAdapter, Schema, filter_output, get_auth_tables};
use crate::error::{Error, Result};
use crate::options::BetterAuthOptions;
use crate::plugin::Plugin;
use crate::types::{Model, Session, User};
use crate::utils::url::{get_origin, matches_origin_pattern, with_base_path};

const DEFAULT_SECRET: &str = "better-auth-secret-12345678901234567890";

pub struct AuthContext {
    pub options: BetterAuthOptions,
    /// Configured base URL including the base path, if any.
    pub base_url: Option<String>,
    pub secret: String,
    pub secret_config: SecretConfig,
    pub schema: Arc<Schema>,
    pub db: Db,
    pub internal_adapter: InternalAdapter,
    pub cookie_factory: CookieFactory,
    pub cookies: AuthCookies,
    pub trusted_origins: Vec<String>,
    pub rate_limiter: RateLimiter,
}

fn resolve_secrets(options: &BetterAuthOptions) -> Result<(String, SecretConfig)> {
    let env = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    let legacy = options.secret.clone().or_else(|| env("BETTER_AUTH_SECRET")).or_else(|| env("AUTH_SECRET"));
    if !options.secrets.is_empty() {
        let keys: BTreeMap<u32, String> = options.secrets.iter().cloned().collect();
        let current_version = *keys.keys().next_back().expect("non-empty");
        let current = keys[&current_version].clone();
        let config = SecretConfig { keys, current_version, legacy_secret: legacy, versioned: true };
        return Ok((current, config));
    }
    let secret = match legacy {
        Some(s) => s,
        None if cfg!(debug_assertions) => {
            tracing::warn!("no secret configured; using the insecure default secret (development only)");
            DEFAULT_SECRET.to_owned()
        }
        None => {
            return Err(Error::Config("a secret is required in production: set `secret` or BETTER_AUTH_SECRET".into()));
        }
    };
    if secret.len() < 32 {
        tracing::warn!("the configured secret is shorter than 32 characters");
    }
    Ok((secret.clone(), SecretConfig::single(secret)))
}

impl AuthContext {
    pub(crate) fn new(mut options: BetterAuthOptions) -> Result<Self> {
        if !options.base_path.starts_with('/') {
            options.base_path = format!("/{}", options.base_path);
        }
        options.base_path = options.base_path.trim_end_matches('/').to_owned();
        if options.base_url.is_none() {
            options.base_url =
                std::env::var("BETTER_AUTH_URL").ok().or_else(|| std::env::var("NEXT_PUBLIC_BETTER_AUTH_URL").ok());
        }
        let base_url = match &options.base_url {
            Some(u) => Some(
                with_base_path(u, &options.base_path).ok_or_else(|| Error::Config(format!("invalid baseURL: {u}")))?,
            ),
            None => None,
        };
        let (secret, secret_config) = resolve_secrets(&options)?;
        let stateful = !options.stateless || options.secondary_storage.is_some();
        if stateful && options.session.cookie_cache.refresh_cache_update_age.is_some() {
            tracing::warn!(
                "`session.cookie_cache.refresh_cache_update_age` is set while a database or secondary storage holds sessions. Refreshing the cache without the store is meant for stateless setups; disabling it."
            );
            options.session.cookie_cache.refresh_cache_update_age = None;
        }

        let schema = Arc::new(get_auth_tables(&options));
        let db = Db::new(options.database.clone(), schema.clone(), options.advanced.generate_id.clone());

        let mut hooks = DatabaseHooks::new();
        hooks.extend(options.database_hooks.clone());
        for plugin in &options.plugins {
            hooks.extend(plugin.database_hooks());
        }
        let mut ip = options.advanced.ip_address.clone();
        ip.localhost_fallback = cfg!(debug_assertions);
        let internal_adapter = InternalAdapter::new(
            db.clone(),
            Arc::new(hooks),
            InternalConfig {
                session_expires_in: options.session.expires_in,
                store_identifier: options.verification.store_identifier.clone(),
                disable_verification_cleanup: options.verification.disable_cleanup,
                ip,
                storage: options.secondary_storage.clone(),
                store_session_in_db: options.session.store_session_in_database,
                preserve_session_in_db: options.session.preserve_session_in_database,
                verification_in_db: options.verification.store_in_database,
                validate_user_info: options.user.validate_user_info.clone(),
            },
        );

        let cookie_factory = CookieFactory::new(&options);
        let cookies = AuthCookies::new(&cookie_factory, &options);

        let mut trusted_origins = vec![];
        if let Some(origin) = base_url.as_deref().and_then(get_origin) {
            trusted_origins.push(origin);
        }
        trusted_origins.extend(options.trusted_origins.iter().cloned());
        if let Ok(env) = std::env::var("BETTER_AUTH_TRUSTED_ORIGINS") {
            trusted_origins.extend(env.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()));
        }
        for plugin in &options.plugins {
            trusted_origins.extend(plugin.trusted_origins());
        }

        let rate_limiter = RateLimiter::new(&options);

        Ok(Self {
            options,
            base_url,
            secret,
            secret_config,
            schema,
            db,
            internal_adapter,
            cookie_factory,
            cookies,
            trusted_origins,
            rate_limiter,
        })
    }

    pub fn plugins(&self) -> &[Arc<dyn Plugin>] {
        &self.options.plugins
    }

    /// Find a plugin by id.
    pub fn plugin(&self, id: &str) -> Option<&Arc<dyn Plugin>> {
        self.options.plugins.iter().find(|p| p.id() == id)
    }

    pub fn has_plugin(&self, id: &str) -> bool {
        self.plugin(id).is_some()
    }

    /// Whether `url` matches a trusted origin. `request_origin` (the origin of the
    /// request's base URL) is also trusted.
    pub fn is_trusted_origin(&self, url: &str, allow_relative_paths: bool, request_origin: Option<&str>) -> bool {
        self.trusted_origins
            .iter()
            .map(String::as_str)
            .chain(request_origin)
            .any(|o| matches_origin_pattern(url, o, allow_relative_paths))
    }

    /// Hash a password with the configured hasher.
    /// Whether sessions have a server-side store (a database or secondary storage). In
    /// stateless mode the signed cookie cache is the session record.
    pub fn is_stateful(&self) -> bool {
        !self.options.stateless || self.options.secondary_storage.is_some()
    }

    /// Run `work` in a database transaction (`runWithTransaction`); see [`Db::transaction`].
    pub async fn transaction<T, E: From<crate::error::Error>>(
        &self,
        work: impl std::future::Future<Output = std::result::Result<T, E>>,
    ) -> std::result::Result<T, E> {
        self.db.transaction(work).await
    }

    pub async fn hash_password(&self, password: &str) -> Result<String> {
        match &self.options.email_and_password.password {
            Some(h) => (h.hash)(password.to_owned()).await,
            None => crypto::hash_password(password).await,
        }
    }

    pub async fn verify_password(&self, hash: &str, password: &str) -> Result<bool> {
        match &self.options.email_and_password.password {
            Some(h) => (h.verify)(hash.to_owned(), password.to_owned()).await,
            None => crypto::verify_password(hash, password).await,
        }
    }

    /// User as returned by the API (`parseUserOutput`): hidden fields removed.
    pub fn user_output(&self, user: &User) -> Map<String, Value> {
        let record = user.to_record();
        match self.schema.table("user") {
            Some(t) => filter_output(t, record),
            None => record,
        }
    }

    pub fn session_output(&self, session: &Session) -> Map<String, Value> {
        let record = session.to_record();
        match self.schema.table("session") {
            Some(t) => filter_output(t, record),
            None => record,
        }
    }

    pub fn account_output(&self, account: &crate::types::Account) -> Map<String, Value> {
        let record = account.to_record();
        match self.schema.table("account") {
            Some(t) => filter_output(t, record),
            None => record,
        }
    }
}
