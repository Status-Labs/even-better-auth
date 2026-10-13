//! Origin/CSRF checks and session guards (`api/middlewares`, `sessionMiddleware`, ...).

use serde_json::Value;

use super::EndpointContext;
use super::routes::session::{GetSessionOptions, get_session_impl};
use crate::error::{ApiError, codes};
use crate::types::SessionWithUser;
use crate::utils::url::get_origin;

fn skip_origin_check(ctx: &EndpointContext) -> bool {
    ctx.auth.options.advanced.disable_origin_check
}

fn skip_csrf_check(ctx: &EndpointContext) -> bool {
    // `disableOriginCheck` also disables CSRF checks, for backwards compatibility.
    ctx.auth.options.advanced.disable_csrf_check || ctx.auth.options.advanced.disable_origin_check
}

/// The origin of this request's base URL, which is always trusted.
fn request_origin(ctx: &EndpointContext) -> Option<String> {
    get_origin(&ctx.base_url)
}

pub fn is_trusted(ctx: &EndpointContext, url: &str, allow_relative_paths: bool) -> bool {
    ctx.auth.is_trusted_origin(url, allow_relative_paths, request_origin(ctx).as_deref())
}

fn validate_origin(ctx: &EndpointContext, force: bool) -> Result<(), ApiError> {
    if !ctx.is_request || skip_csrf_check(ctx) || skip_origin_check(ctx) {
        return Ok(());
    }
    let uses_cookies = ctx.has_header(http::header::COOKIE.as_str());
    if !(force || uses_cookies) {
        return Ok(());
    }
    let origin = ctx.header("origin");
    let header = origin.clone().or_else(|| ctx.header("referer")).unwrap_or_default();
    let inferred = (origin.as_deref() == Some("null")
        && ctx.header("sec-fetch-site").as_deref() == Some("same-origin"))
    .then(|| request_origin(ctx))
    .flatten();
    let to_validate = inferred.as_deref().unwrap_or(&header);
    if to_validate.is_empty() || to_validate == "null" {
        return Err(ApiError::forbidden(codes::MISSING_OR_NULL_ORIGIN));
    }
    if !is_trusted(ctx, to_validate, false) {
        tracing::error!(origin = to_validate, "invalid origin; add it to trusted_origins if it is valid");
        return Err(ApiError::forbidden(codes::INVALID_ORIGIN));
    }
    Ok(())
}

fn validate_url(ctx: &EndpointContext, value: Option<&Value>, label: &str) -> Result<(), ApiError> {
    let Some(value) = value.filter(|v| !v.is_null() && v.as_str() != Some("")) else {
        return Ok(());
    };
    let Some(url) = value.as_str() else {
        return Err(ApiError::message(http::StatusCode::BAD_REQUEST, format!("Invalid {label}: expected a string")));
    };
    if is_trusted(ctx, url, true) {
        return Ok(());
    }
    tracing::error!("Invalid {label}: {url}");
    Err(ApiError::forbidden(match label {
        "callbackURL" => codes::INVALID_CALLBACK_URL,
        "redirectURL" => codes::INVALID_REDIRECT_URL,
        "errorCallbackURL" => codes::INVALID_ERROR_CALLBACK_URL,
        "newUserCallbackURL" => codes::INVALID_NEW_USER_CALLBACK_URL,
        _ => codes::INVALID_ORIGIN,
    }))
}

/// Applied to every request (`originCheckMiddleware`): for state-changing methods, verify
/// the `Origin` of cookie-bearing requests and validate redirect URLs in the body/query.
pub fn origin_check(ctx: &EndpointContext) -> Result<(), ApiError> {
    if !ctx.is_request || matches!(ctx.method, http::Method::GET | http::Method::OPTIONS | http::Method::HEAD) {
        return Ok(());
    }
    validate_origin(ctx, false)?;
    if skip_origin_check(ctx) {
        return Ok(());
    }
    let body = ctx.body();
    let query = ctx.query();
    let callback = body.get("callbackURL").or_else(|| query.get("callbackURL"));
    validate_url(ctx, callback, "callbackURL")?;
    validate_url(ctx, body.get("redirectTo"), "redirectURL")?;
    validate_url(ctx, body.get("errorCallbackURL"), "errorCallbackURL")?;
    validate_url(ctx, body.get("newUserCallbackURL"), "newUserCallbackURL")?;
    Ok(())
}

/// Validate a callback URL for GET endpoints (`originCheck(getValue)`).
pub fn check_callback_urls(ctx: &EndpointContext, urls: &[Option<String>]) -> Result<(), ApiError> {
    if !ctx.is_request || skip_origin_check(ctx) {
        return Ok(());
    }
    for url in urls.iter().flatten() {
        validate_url(ctx, Some(&Value::String(url.clone())), "callbackURL")?;
    }
    Ok(())
}

/// CSRF protection for endpoints that accept form posts (`formCsrfMiddleware`).
pub fn form_csrf(ctx: &EndpointContext) -> Result<(), ApiError> {
    if !ctx.is_request || skip_csrf_check(ctx) {
        return Ok(());
    }
    if ctx.has_header(http::header::COOKIE.as_str()) {
        return validate_origin(ctx, false);
    }
    let fetch_header = |name: &str| ctx.header(name).map(|v| v.trim().to_owned()).filter(|s| !s.is_empty());
    let (site, mode, dest) =
        (fetch_header("sec-fetch-site"), fetch_header("sec-fetch-mode"), fetch_header("sec-fetch-dest"));
    let (site, mode) = (site.as_deref(), mode.as_deref());
    if site.is_some() || mode.is_some() || dest.is_some() {
        if site == Some("cross-site") && mode == Some("navigate") {
            tracing::error!("blocked cross-site navigation login attempt (CSRF protection)");
            return Err(ApiError::forbidden(codes::CROSS_SITE_NAVIGATION_LOGIN_BLOCKED));
        }
        return validate_origin(ctx, true);
    }
    if ctx.header("origin").is_some() || ctx.header("referer").is_some() {
        return validate_origin(ctx, true);
    }
    Ok(())
}

/// Resolve the current session (`getSessionFromCtx`), caching it on the context.
pub async fn get_session_from_ctx(
    ctx: &EndpointContext,
    opts: GetSessionOptions,
) -> Result<Option<SessionWithUser>, ApiError> {
    if let Some(s) = ctx.session() {
        return Ok(Some(s));
    }
    let session = get_session_impl(ctx, opts).await.unwrap_or(None);
    ctx.set_session(session.clone());
    Ok(session)
}

/// Require a valid session (`sessionMiddleware`).
pub async fn require_session(ctx: &EndpointContext) -> Result<SessionWithUser, ApiError> {
    get_session_from_ctx(ctx, GetSessionOptions::default()).await?.ok_or_else(ApiError::unauthenticated)
}

/// The session from the store that can authorize sensitive work
/// (`getAuthoritativeSessionFromCtx`): bypasses the cookie cache when a server-side session
/// store exists; in stateless mode the signed cookie is the session record.
pub async fn authoritative_session(ctx: &EndpointContext) -> Result<Option<SessionWithUser>, ApiError> {
    ctx.set_session(None);
    get_session_from_ctx(ctx, GetSessionOptions { disable_cookie_cache: ctx.auth.is_stateful(), ..Default::default() })
        .await
}

/// Require a session read from the database, bypassing the cookie cache
/// (`sensitiveSessionMiddleware`).
pub async fn require_sensitive_session(ctx: &EndpointContext) -> Result<SessionWithUser, ApiError> {
    authoritative_session(ctx).await?.ok_or_else(ApiError::unauthenticated)
}

/// Require a session when called over HTTP; allow server calls without one
/// (`requestOnlySessionMiddleware`).
pub async fn request_only_session(ctx: &EndpointContext) -> Result<Option<SessionWithUser>, ApiError> {
    let session = get_session_from_ctx(ctx, GetSessionOptions::default()).await?;
    if session.is_none() && (ctx.is_request || !ctx.headers().is_empty()) {
        return Err(ApiError::unauthenticated());
    }
    Ok(session)
}

/// Require a session created within `freshAge` (`freshSessionMiddleware`).
pub async fn require_fresh_session(ctx: &EndpointContext) -> Result<SessionWithUser, ApiError> {
    let session = require_session(ctx).await?;
    let fresh_age = ctx.auth.options.session.fresh_age;
    if fresh_age != 0 {
        let age = chrono::Utc::now() - session.session.created_at;
        if age.num_seconds() >= fresh_age {
            return Err(ApiError::forbidden(codes::SESSION_NOT_FRESH));
        }
    }
    Ok(session)
}
