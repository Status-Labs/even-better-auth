//! Session endpoints (`api/routes/session.ts`).

use http::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::middleware::{require_fresh_session, require_sensitive_session};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::{
    decode_cookie_cache, delete_session_cookie, get_chunked_cookie, set_cookie_cache, set_session_cookie,
};
use crate::db::Record;
use crate::error::{ApiError, codes};
use crate::types::SessionWithUser;
use crate::utils::date;

#[derive(Debug, Clone, Copy, Default)]
pub struct GetSessionOptions {
    pub disable_cookie_cache: bool,
    pub disable_refresh: bool,
}

/// Output of a resolved session: `{ session, user }` with hidden fields removed.
pub fn session_json(ctx: &EndpointContext, s: &SessionWithUser) -> Value {
    json!({
        "session": ctx.auth.session_output(&s.session),
        "user": ctx.auth.user_output(&s.user),
    })
}

/// Result of [`get_session_impl`] with the `needsRefresh` flag used by deferred refresh.
struct Resolved {
    session: Option<SessionWithUser>,
    needs_refresh: Option<bool>,
}

async fn resolve(ctx: &EndpointContext, opts: GetSessionOptions, is_post: bool) -> Result<Resolved, ApiError> {
    let auth = &ctx.auth;
    let options = &auth.options.session;
    let none = Ok(Resolved { session: None, needs_refresh: None });
    let cache_enabled = options.cookie_cache.enabled;
    let token = ctx.get_signed_cookie(&auth.cookies.session_token.name, &auth.secret);
    if token.is_none() && cache_enabled {
        return none;
    }
    let data_cookie = get_chunked_cookie(ctx, &auth.cookies.session_data.name);
    if data_cookie.is_some() && !cache_enabled {
        delete_stale_cache(ctx);
    }
    let Some(token) = token else { return none };

    let use_cache = cache_enabled && !opts.disable_cookie_cache;
    let cached = match (&data_cookie, use_cache) {
        (Some(v), true) => {
            let decoded = decode_cookie_cache(ctx, v).await;
            if decoded.is_none() {
                ctx.expire_cookie(&auth.cookies.session_data);
            }
            decoded
        }
        _ => None,
    };
    let dont_remember = ctx.get_signed_cookie(&auth.cookies.dont_remember.name, &auth.secret).is_some();

    if let Some(payload) = cached {
        let now = chrono::Utc::now();
        let expired = payload.session.session.token != token
            || payload.version != options.cookie_cache.version
            || payload.expires_at < now.timestamp_millis()
            || payload.session.session.expires_at < now;
        if expired {
            ctx.expire_cookie(&auth.cookies.session_data);
        } else {
            if let Some(update_age) = options.cookie_cache.refresh_cache_update_age {
                let time_until_expiry = payload.expires_at - now.timestamp_millis();
                if time_until_expiry < update_age * 1000 && !options.disable_session_refresh {
                    set_cookie_cache(ctx, &payload.session, false).await;
                    let mut attrs = auth.cookies.session_token.attributes.clone();
                    attrs.max_age = if dont_remember { None } else { Some(options.expires_in) };
                    ctx.set_signed_cookie(&auth.cookies.session_token.name, &token, &auth.secret, &attrs);
                }
            }
            return Ok(Resolved { session: Some(payload.session), needs_refresh: None });
        }
    }

    let found = auth.internal_adapter.find_session(&token).await?;
    let Some(found) = found.filter(|s| s.session.expires_at >= chrono::Utc::now()) else {
        delete_session_cookie(ctx, false);
        if let Some(expired) = auth.internal_adapter.find_session(&token).await.ok().flatten()
            && (!options.defer_session_refresh || is_post)
        {
            auth.internal_adapter.delete_session(&expired.session.token).await?;
        }
        return none;
    };

    if dont_remember || opts.disable_refresh {
        return Ok(Resolved { session: Some(found), needs_refresh: None });
    }

    let due = found.session.expires_at.timestamp_millis() - options.expires_in * 1000 + options.update_age * 1000;
    let should_update = due <= chrono::Utc::now().timestamp_millis();
    let needs_refresh = should_update && !options.disable_session_refresh;

    if options.defer_session_refresh && !is_post {
        set_cookie_cache(ctx, &found, dont_remember).await;
        return Ok(Resolved { session: Some(found), needs_refresh: Some(needs_refresh) });
    }

    if needs_refresh {
        let mut update = Record::new();
        update.insert("expiresAt".into(), date::to_value(date::in_secs(options.expires_in)));
        update.insert("updatedAt".into(), date::now_value());
        let Some(updated) = auth.internal_adapter.update_session(&found.session.token, update).await? else {
            delete_session_cookie(ctx, false);
            return Err(ApiError::unauthorized(codes::FAILED_TO_GET_SESSION));
        };
        let refreshed = SessionWithUser { session: updated, user: found.user };
        set_session_cookie(ctx, &refreshed, Some(false), Some(options.expires_in)).await;
        return Ok(Resolved { session: Some(refreshed), needs_refresh: None });
    }

    set_cookie_cache(ctx, &found, dont_remember).await;
    Ok(Resolved { session: Some(found), needs_refresh: None })
}

fn delete_stale_cache(ctx: &EndpointContext) {
    let cookie = &ctx.auth.cookies.session_data;
    let prefix = format!("{}.", cookie.name);
    for (n, _) in ctx.cookies_matching(|n| n == cookie.name || n.starts_with(&prefix)) {
        ctx.set_cookie(&n, "", &crate::cookies::CookieOptions { max_age: Some(0), ..cookie.attributes.clone() });
    }
}

/// Resolve the session for the request, refreshing it and its cookies as needed.
pub async fn get_session_impl(
    ctx: &EndpointContext,
    opts: GetSessionOptions,
) -> Result<Option<SessionWithUser>, ApiError> {
    Ok(resolve(ctx, opts, false).await?.session)
}

pub(crate) async fn get_session(ctx: Ctx) -> EndpointResult {
    ctx.set_header("cache-control", "no-store");
    ctx.set_header("pragma", "no-cache");
    let is_post = ctx.method == Method::POST;
    if is_post && !ctx.auth.options.session.defer_session_refresh {
        return Err(ApiError::from_code(
            StatusCode::METHOD_NOT_ALLOWED,
            codes::METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED,
        ));
    }
    let opts = GetSessionOptions {
        disable_cookie_cache: ctx.query_flag("disableCookieCache"),
        disable_refresh: ctx.query_flag("disableRefresh"),
    };
    let resolved = match resolve(&ctx, opts, is_post).await {
        Ok(r) => r,
        Err(e) if e.status == StatusCode::INTERNAL_SERVER_ERROR => {
            return Err(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, codes::FAILED_TO_GET_SESSION));
        }
        Err(e) => return Err(e),
    };
    ctx.set_session(resolved.session.clone());
    match resolved.session {
        None => ctx.json(Value::Null),
        Some(s) => {
            let mut out = session_json(&ctx, &s);
            if let Some(n) = resolved.needs_refresh {
                out["needsRefresh"] = n.into();
            }
            ctx.json(out)
        }
    }
}

async fn list_sessions(ctx: Ctx) -> EndpointResult {
    let session = require_fresh_session(&ctx).await?;
    let now = chrono::Utc::now();
    let sessions = ctx.auth.internal_adapter.list_sessions(&session.user.id).await?;
    let active: Vec<Value> =
        sessions.iter().filter(|s| s.expires_at > now).map(|s| Value::Object(ctx.auth.session_output(s))).collect();
    ctx.json(Value::Array(active))
}

#[derive(Deserialize)]
struct RevokeSessionBody {
    token: String,
}

async fn revoke_session(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let body: RevokeSessionBody = ctx.parse_body()?;
    let target = ctx.auth.internal_adapter.find_session(&body.token).await?;
    if target.is_some_and(|t| t.session.user_id == session.user.id) {
        ctx.auth.internal_adapter.delete_session(&body.token).await?;
    }
    ctx.json(json!({ "status": true }))
}

async fn revoke_sessions(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    ctx.auth.internal_adapter.delete_user_sessions(&session.user.id).await?;
    ctx.json(json!({ "status": true }))
}

async fn revoke_other_sessions(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let now = chrono::Utc::now();
    let others: Vec<String> = ctx
        .auth
        .internal_adapter
        .list_sessions(&session.user.id)
        .await?
        .into_iter()
        .filter(|s| s.expires_at > now && s.token != session.session.token)
        .map(|s| s.token)
        .collect();
    ctx.auth.internal_adapter.delete_sessions(&others).await?;
    ctx.json(json!({ "status": true }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::get("getSession", "/get-session", handler(get_session)).methods(&[Method::GET, Method::POST]),
        Endpoint::get("listSessions", "/list-sessions", handler(list_sessions)),
        Endpoint::post("revokeSession", "/revoke-session", handler(revoke_session)),
        Endpoint::post("revokeSessions", "/revoke-sessions", handler(revoke_sessions)),
        Endpoint::post("revokeOtherSessions", "/revoke-other-sessions", handler(revoke_other_sessions)),
    ]
}
