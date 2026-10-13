//! Multiple sessions per device (`plugins/multi-session`): every session created in a
//! browser is remembered in a signed `{session_token}_multi-{token}` cookie, so the user can
//! list the accounts signed in on this device, switch between them, and revoke them.

use std::any::Any;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;

use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler, hook};
use crate::cookies::{CookieOptions, SECURE_COOKIE_PREFIX, delete_session_cookie, set_session_cookie};
use crate::error::{ApiError, ErrorCode};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::types::SessionWithUser;

/// Error codes (`MULTI_SESSION_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    pub const INVALID_SESSION_TOKEN: ErrorCode =
        ErrorCode { code: "INVALID_SESSION_TOKEN", message: "Invalid session token" };
    pub const ALL: &[ErrorCode] = &[INVALID_SESSION_TOKEN];
}

use error_codes as e;

#[derive(Debug, Clone)]
pub struct MultiSessionOptions {
    /// The maximum number of sessions remembered on one device. Default 5.
    pub maximum_sessions: usize,
}

impl Default for MultiSessionOptions {
    fn default() -> Self {
        Self { maximum_sessions: 5 }
    }
}

fn is_multi_session_cookie(name: &str) -> bool {
    name.contains("_multi-")
}

fn multi_cookie_name(ctx: &EndpointContext, token: &str) -> String {
    format!("{}_multi-{}", ctx.auth.cookies.session_token.name, token.to_lowercase())
}

/// Tokens from every validly signed multi-session cookie on the request.
fn multi_session_tokens(ctx: &EndpointContext) -> Vec<String> {
    let secret = &ctx.auth.secret;
    ctx.cookies_matching(is_multi_session_cookie)
        .into_iter()
        .filter_map(|(name, _)| ctx.get_signed_cookie(&name, secret))
        .collect()
}

fn expire(ctx: &EndpointContext, name: &str) {
    let attributes = &ctx.auth.cookies.session_token.attributes;
    ctx.set_cookie(name, "", &CookieOptions { max_age: Some(0), ..attributes.clone() });
}

fn output(ctx: &EndpointContext, s: &SessionWithUser) -> serde_json::Value {
    json!({ "session": ctx.auth.session_output(&s.session), "user": ctx.auth.user_output(&s.user) })
}

async fn list_device_sessions(ctx: Ctx) -> EndpointResult {
    let tokens = multi_session_tokens(&ctx);
    if tokens.is_empty() {
        return ctx.json(json!([]));
    }
    let now = chrono::Utc::now();
    let mut unique: Vec<SessionWithUser> = vec![];
    for s in ctx.auth.internal_adapter.find_sessions(&tokens).await? {
        if s.session.expires_at > now && !unique.iter().any(|u| u.user.id == s.user.id) {
            unique.push(s);
        }
    }
    ctx.json(unique.iter().map(|s| output(&ctx, s)).collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenBody {
    session_token: String,
}

/// The token held in the signed multi-session cookie for `body.sessionToken`. The cookie
/// value is authoritative: the signature covers the value, not the cookie's name.
fn signed_token(ctx: &EndpointContext) -> Result<(String, String), ApiError> {
    let body: TokenBody = ctx.parse_body()?;
    let name = multi_cookie_name(ctx, &body.session_token);
    let token = ctx
        .get_signed_cookie(&name, &ctx.auth.secret)
        .ok_or_else(|| ApiError::unauthorized(e::INVALID_SESSION_TOKEN))?;
    Ok((name, token))
}

async fn set_active_session(ctx: Ctx) -> EndpointResult {
    let (name, token) = signed_token(&ctx)?;
    let session = ctx.auth.internal_adapter.find_session(&token).await?;
    let Some(session) = session.filter(|s| s.session.expires_at >= chrono::Utc::now()) else {
        expire(&ctx, &name);
        return Err(ApiError::unauthorized(e::INVALID_SESSION_TOKEN));
    };
    set_session_cookie(&ctx, &session, None, None).await;
    ctx.json(output(&ctx, &session))
}

async fn revoke_device_session(ctx: Ctx) -> EndpointResult {
    let current = require_session(&ctx).await?;
    let (name, token) = signed_token(&ctx)?;
    ctx.auth.internal_adapter.delete_session(&token).await?;
    expire(&ctx, &name);
    if current.session.token != token {
        return ctx.json(json!({ "status": true }));
    }
    let tokens = multi_session_tokens(&ctx);
    let now = chrono::Utc::now();
    let next = ctx.auth.internal_adapter.find_sessions(&tokens).await?.into_iter().find(|s| s.session.expires_at > now);
    match next {
        Some(next) => set_session_cookie(&ctx, &next, None, None).await,
        None => delete_session_cookie(&ctx, false),
    }
    ctx.json(json!({ "status": true }))
}

/// Remember a newly created session in its own multi-session cookie, replacing any other
/// remembered session of the same user.
async fn after_new_session(options: &MultiSessionOptions, ctx: &EndpointContext) -> Result<(), ApiError> {
    let Some(new_session) = ctx.new_session() else { return Ok(()) };
    let config = &ctx.auth.cookies.session_token;
    let sets_session_cookie = ctx.response_cookie(&config.name).is_some();
    let token = &new_session.session.token;
    let cookie_name = multi_cookie_name(ctx, token);
    if ctx.response_cookie(&cookie_name).is_some() || ctx.get_cookie(&cookie_name).is_some() {
        return Ok(());
    }
    let keys: Vec<String> = ctx.cookies_matching(is_multi_session_cookie).into_iter().map(|(n, _)| n).collect();
    let mut to_delete = vec![];
    for key in &keys {
        let Some(t) = ctx.get_signed_cookie(key, &ctx.auth.secret) else { continue };
        let session = ctx.auth.internal_adapter.find_session(&t).await?;
        if session.is_some_and(|s| s.user.id == new_session.user.id) {
            to_delete.push(t);
            expire(ctx, key);
        }
    }
    if !to_delete.is_empty() {
        ctx.auth.internal_adapter.delete_sessions(&to_delete).await?;
    }
    let count = keys.len() - to_delete.len() + usize::from(sets_session_cookie);
    if count > options.maximum_sessions {
        return Ok(());
    }
    ctx.set_signed_cookie(&cookie_name, token, &ctx.auth.secret, &config.attributes);
    Ok(())
}

/// Signing out signs out of every session remembered on this device.
async fn after_sign_out(ctx: &EndpointContext) -> Result<(), ApiError> {
    let mut tokens = vec![];
    for (key, _) in ctx.cookies_matching(is_multi_session_cookie) {
        if let Some(token) = ctx.get_signed_cookie(&key, &ctx.auth.secret) {
            let name = key.to_lowercase().replace(&SECURE_COOKIE_PREFIX.to_lowercase(), SECURE_COOKIE_PREFIX);
            expire(ctx, &name);
            tokens.push(token);
        }
    }
    if !tokens.is_empty() {
        ctx.auth.internal_adapter.delete_sessions(&tokens).await?;
    }
    Ok(())
}

pub struct MultiSession {
    options: Arc<MultiSessionOptions>,
}

pub fn multi_session(options: MultiSessionOptions) -> Arc<dyn Plugin> {
    Arc::new(MultiSession { options: Arc::new(options) })
}

impl Plugin for MultiSession {
    fn id(&self) -> &str {
        "multi-session"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![
            Endpoint::get("listDeviceSessions", "/multi-session/list-device-sessions", handler(list_device_sessions)),
            Endpoint::post("setActiveSession", "/multi-session/set-active", handler(set_active_session)),
            Endpoint::post("revokeDeviceSession", "/multi-session/revoke", handler(revoke_device_session)),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        let options = self.options.clone();
        PluginHooks {
            before: vec![],
            after: vec![
                MatchedHook::new(
                    |_| true,
                    hook(move |ctx| {
                        let options = options.clone();
                        async move {
                            after_new_session(&options, &ctx).await?;
                            Ok(None)
                        }
                    }),
                ),
                MatchedHook::new(
                    |ctx| ctx.path == "/sign-out",
                    hook(|ctx| async move {
                        after_sign_out(&ctx).await?;
                        Ok(None)
                    }),
                ),
            ],
        }
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
