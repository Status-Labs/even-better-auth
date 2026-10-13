//! Plugin interface (`BetterAuthPlugin`).

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::api::{AfterHook, BeforeHook, Endpoint, Matcher};
use crate::context::AuthContext;
use crate::db::TableExtension;
use crate::db::hooks::DatabaseHooks;
use crate::error::ErrorCode;
use crate::options::RateLimitRule;

/// A hook with a matcher deciding which endpoint calls it applies to.
#[derive(Clone)]
pub struct MatchedHook {
    pub matcher: Matcher,
    pub handler: BeforeHook,
}

impl MatchedHook {
    pub fn new(
        matcher: impl Fn(&crate::api::EndpointContext) -> bool + Send + Sync + 'static,
        handler: BeforeHook,
    ) -> Self {
        Self { matcher: Arc::new(matcher), handler }
    }
}

#[derive(Clone, Default)]
pub struct PluginHooks {
    pub before: Vec<MatchedHook>,
    pub after: Vec<MatchedHook>,
}

/// A rate-limit rule for paths matched by `path_matcher`.
#[derive(Clone)]
pub struct PluginRateLimit {
    pub path_matcher: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    pub rule: RateLimitRule,
}

/// Extends the auth server with endpoints, schema, hooks and request interception.
#[async_trait]
pub trait Plugin: Send + Sync + 'static {
    fn id(&self) -> &str;

    /// Tables to create, or fields to add to existing tables.
    fn schema(&self) -> Vec<TableExtension> {
        vec![]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![]
    }

    fn hooks(&self) -> PluginHooks {
        PluginHooks::default()
    }

    fn database_hooks(&self) -> DatabaseHooks {
        DatabaseHooks::default()
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![]
    }

    fn trusted_origins(&self) -> Vec<String> {
        vec![]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![]
    }

    /// Adjust the options before the auth context is built (TS `init` returning `options`).
    fn configure(&self, _options: &mut crate::options::BetterAuthOptions) {}

    /// Async counterpart of [`configure`](Self::configure), run after it (e.g. to fetch an
    /// OIDC discovery document). An error aborts `BetterAuth::new`.
    async fn prepare(&self, _options: &mut crate::options::BetterAuthOptions) -> crate::error::Result<()> {
        Ok(())
    }

    /// Validate the plugin against the final configuration; runs once in `BetterAuth::new`.
    fn init(&self, _ctx: &AuthContext) -> crate::error::Result<()> {
        Ok(())
    }

    /// Sign and verify JWT-strategy session cookie caches (`sessionConfig.cookieCacheSigner`).
    fn cookie_cache_signer(&self) -> Option<Arc<dyn crate::cookies::CookieCacheSigner>> {
        None
    }

    /// Inspect or rewrite an incoming request. Returning a response short-circuits routing.
    async fn on_request(
        &self,
        _request: &mut http::Request<Bytes>,
        _ctx: &AuthContext,
    ) -> Option<http::Response<Bytes>> {
        None
    }

    /// Inspect or modify the outgoing response.
    async fn on_response(&self, _response: &mut http::Response<Bytes>, _ctx: &AuthContext) {}

    /// For downcasting via [`AuthContext::plugin`].
    fn as_any(&self) -> &dyn Any;
}

/// Convenience to build an after-hook (same shape as a before-hook).
pub fn after_hook(h: AfterHook) -> AfterHook {
    h
}
