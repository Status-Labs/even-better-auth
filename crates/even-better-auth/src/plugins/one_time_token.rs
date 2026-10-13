//! One-time tokens (`plugins/one-time-token`): exchange a signed-in session for a short-lived,
//! single-use token that another client (e.g. a different domain or a native app) redeems for
//! the same session.

use std::any::Any;
use std::sync::Arc;

use chrono::{Duration, Utc};
use futures::future::BoxFuture;
use http::StatusCode;
use serde::Deserialize;
use serde_json::json;

use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler, hook};
use crate::cookies::set_session_cookie;
use crate::error::{ApiError, Result};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::types::SessionWithUser;

pub type TokenFn = Arc<dyn Fn(SessionWithUser) -> BoxFuture<'static, Result<String>> + Send + Sync>;
pub type HashFn = Arc<dyn Fn(String) -> BoxFuture<'static, Result<String>> + Send + Sync>;

/// How tokens are stored (`storeToken`).
#[derive(Clone, Default)]
pub enum StoreToken {
    #[default]
    Plain,
    /// SHA-256, base64url without padding.
    Hashed,
    CustomHasher(HashFn),
}

#[derive(Clone)]
pub struct OneTimeTokenOptions {
    /// Token lifetime in minutes. Default 3.
    pub expires_in: i64,
    /// Only allow generating tokens through the server API, not over HTTP.
    pub disable_client_request: bool,
    /// Default: 32 random alphanumeric characters.
    pub generate_token: Option<TokenFn>,
    /// Redeem without setting the session cookie on the response.
    pub disable_set_session_cookie: bool,
    pub store_token: StoreToken,
    /// Send a fresh token in a `set-ott` header whenever a session is created.
    pub set_ott_header_on_new_session: bool,
}

impl Default for OneTimeTokenOptions {
    fn default() -> Self {
        Self {
            expires_in: 3,
            disable_client_request: false,
            generate_token: None,
            disable_set_session_cookie: false,
            store_token: StoreToken::Plain,
            set_ott_header_on_new_session: false,
        }
    }
}

struct Inner {
    options: OneTimeTokenOptions,
}

fn bad(message: &str) -> ApiError {
    ApiError::message(StatusCode::BAD_REQUEST, message)
}

impl Inner {
    async fn stored(&self, token: &str) -> Result<String> {
        Ok(match &self.options.store_token {
            StoreToken::Plain => token.to_owned(),
            StoreToken::Hashed => crate::crypto::sha256_base64url(token),
            StoreToken::CustomHasher(hash) => hash(token.to_owned()).await?,
        })
    }

    async fn generate(&self, ctx: &EndpointContext, session: &SessionWithUser) -> Result<String> {
        let token = match &self.options.generate_token {
            Some(f) => f(session.clone()).await?,
            None => crate::crypto::generate_random_string(32),
        };
        let expires_at = Utc::now() + Duration::minutes(self.options.expires_in);
        let id = format!("one-time-token:{}", self.stored(&token).await?);
        ctx.auth.internal_adapter.create_verification_value(&id, &session.session.token, expires_at).await?;
        Ok(token)
    }
}

async fn generate_one_time_token(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    if inner.options.disable_client_request && ctx.is_request {
        return Err(bad("Client requests are disabled"));
    }
    let token = inner.generate(&ctx, &session).await?;
    ctx.json(json!({ "token": token }))
}

#[derive(Deserialize)]
struct VerifyBody {
    token: String,
}

async fn verify_one_time_token(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: VerifyBody = ctx.parse_body()?;
    let id = format!("one-time-token:{}", inner.stored(&body.token).await?);
    // Burn the single-use record before issuing a session, so concurrent redemptions of the
    // same token resolve to one success.
    let ia = &ctx.auth.internal_adapter;
    let Some(verification) = ia.consume_verification_value(&id).await? else {
        return Err(bad("Invalid token"));
    };
    let Some(session) = ia.find_session(&verification.value).await? else {
        return Err(bad("Session not found"));
    };
    if !inner.options.disable_set_session_cookie {
        set_session_cookie(&ctx, &session, None, None).await;
    }
    if session.session.expires_at < Utc::now() {
        return Err(bad("Session expired"));
    }
    ctx.json(json!({
        "session": ctx.auth.session_output(&session.session),
        "user": ctx.auth.user_output(&session.user),
    }))
}

/// `setOttHeaderOnNewSession`: hand a token for every new session to the client.
async fn after_new_session(inner: &Inner, ctx: &EndpointContext) -> Result<()> {
    let Some(session) = ctx.new_session() else { return Ok(()) };
    let exposed = ctx.response_header("access-control-expose-headers").unwrap_or_default();
    let mut headers: Vec<&str> = exposed.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
    if !headers.contains(&"set-ott") {
        headers.push("set-ott");
    }
    let token = inner.generate(ctx, &session).await?;
    ctx.set_header("set-ott", &token);
    ctx.set_header("access-control-expose-headers", &headers.join(", "));
    Ok(())
}

pub struct OneTimeToken {
    inner: Arc<Inner>,
}

pub fn one_time_token(options: OneTimeTokenOptions) -> Arc<dyn Plugin> {
    Arc::new(OneTimeToken { inner: Arc::new(Inner { options }) })
}

impl Plugin for OneTimeToken {
    fn id(&self) -> &str {
        "one-time-token"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b) = (self.inner.clone(), self.inner.clone());
        vec![
            Endpoint::get(
                "generateOneTimeToken",
                "/one-time-token/generate",
                handler(move |ctx| generate_one_time_token(a.clone(), ctx)),
            ),
            Endpoint::post(
                "verifyOneTimeToken",
                "/one-time-token/verify",
                handler(move |ctx| verify_one_time_token(b.clone(), ctx)),
            ),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        if !self.inner.options.set_ott_header_on_new_session {
            return PluginHooks::default();
        }
        let inner = self.inner.clone();
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |_| true,
                hook(move |ctx| {
                    let inner = inner.clone();
                    async move {
                        after_new_session(&inner, &ctx).await?;
                        Ok(None)
                    }
                }),
            )],
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
