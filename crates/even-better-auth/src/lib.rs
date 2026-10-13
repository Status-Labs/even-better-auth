//! # better-auth
//!
//! A framework-agnostic authentication library for Rust, ported from the TypeScript
//! [better-auth](https://better-auth.com). The HTTP API (paths, JSON shapes, cookies) is
//! compatible with the official JavaScript client.
//!
//! ```no_run
//! use std::sync::Arc;
//! use even_better_auth::{BetterAuth, BetterAuthOptions, EmailAndPasswordOptions, MemoryAdapter};
//!
//! # async fn run() -> even_better_auth::Result<()> {
//! let mut options = BetterAuthOptions::new(Arc::new(MemoryAdapter::new()));
//! options.base_url = Some("http://localhost:3000".into());
//! options.secret = Some("a-long-random-secret-at-least-32-chars".into());
//! options.email_and_password = EmailAndPasswordOptions::enabled();
//! let auth = BetterAuth::new(options).await?;
//! // Pass `http::Request<Bytes>` to `auth.handler(req).await` from your framework.
//! # Ok(()) }
//! ```

pub mod api;
pub mod context;
pub mod cookies;
pub mod crypto;
pub mod db;
pub mod error;
#[cfg(feature = "oauth")]
pub mod oauth2;
pub mod options;
pub mod plugin;
pub mod plugins;
#[cfg(feature = "oauth")]
pub mod social_providers;
pub mod storage;
pub mod types;
pub mod utils;

use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;

pub use api::{ApiCall, ApiResponse, Ctx, Endpoint, EndpointContext, EndpointOutput, EndpointResult};
pub use context::AuthContext;
pub use db::{Adapter, MemoryAdapter};
pub use error::{ApiError, Error, Result};
pub use options::*;
pub use plugin::Plugin;
pub use storage::{MemoryStorage, SecondaryStorage};
pub use types::{Account, Session, SessionWithUser, User, Verification};
pub use utils::validate_user_info::{
    ProviderInfo, UserInfoRejection, UserSource, ValidateUserInfo, ValidateUserInfoAction, ValidateUserInfoFn,
};

use api::Router;

/// The auth server. Cheap to clone.
#[derive(Clone)]
pub struct BetterAuth {
    ctx: Arc<AuthContext>,
    router: Arc<Router>,
}

impl BetterAuth {
    /// Build the auth server from options. Does not touch the database; call
    /// [`migrate`](Self::migrate) to create tables when using a SQL adapter.
    pub async fn new(mut options: BetterAuthOptions) -> Result<Self> {
        for plugin in options.plugins.clone() {
            plugin.configure(&mut options);
        }
        for plugin in options.plugins.clone() {
            plugin.prepare(&mut options).await?;
        }
        let ctx = Arc::new(AuthContext::new(options)?);
        for plugin in ctx.plugins() {
            plugin.init(&ctx)?;
        }
        let mut endpoints = api::routes::core_endpoints();
        for plugin in ctx.plugins() {
            for e in plugin.endpoints() {
                endpoints.retain(|existing| existing.key != e.key);
                endpoints.push(e);
            }
        }
        Ok(Self { ctx, router: Arc::new(Router::new(endpoints)) })
    }

    pub fn context(&self) -> &Arc<AuthContext> {
        &self.ctx
    }

    pub fn options(&self) -> &BetterAuthOptions {
        &self.ctx.options
    }

    /// The registered endpoints.
    pub fn endpoints(&self) -> &[Endpoint] {
        self.router.endpoints()
    }

    /// Create or update database tables for the configured schema.
    pub async fn migrate(&self) -> Result<()> {
        self.ctx.db.migrate().await
    }

    /// Handle an HTTP request addressed to the auth base path.
    pub async fn handler(&self, request: http::Request<Bytes>) -> http::Response<Bytes> {
        api::dispatch::handle(self.ctx.clone(), &self.router, request).await
    }

    /// Call an endpoint directly from server code (`auth.api.*`).
    pub async fn api(&self, call: ApiCall) -> std::result::Result<ApiResponse, ApiError> {
        api::dispatch::call(self.ctx.clone(), &self.router, call).await
    }

    /// Resolve the session for a set of request headers (`auth.api.getSession`).
    pub async fn get_session(&self, headers: &HeaderMap) -> Result<Option<SessionWithUser>> {
        let res = self.api(ApiCall::new("getSession").headers(headers.clone())).await?;
        let value = res.json();
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(value)?))
    }
}
