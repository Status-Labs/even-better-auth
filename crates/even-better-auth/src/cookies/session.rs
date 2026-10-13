//! Session cookies and the session-data cookie cache.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use super::{AuthCookie, CookieOptions, serialize_cookie};
use crate::api::EndpointContext;
use crate::crypto;
use crate::options::CookieCacheStrategy;
use crate::types::{Session, SessionWithUser, User};

const MAX_COOKIE_SIZE: usize = 4050;
const MAX_COOKIE_CHUNKS: usize = 100;
const SESSION_SALT: &str = "better-auth-session";

/// Signs and verifies JWT-strategy session cookie caches in place of the secret-keyed
/// HS256 JWT (provided by the JWT plugin's `session_cookie_cache`).
#[async_trait::async_trait]
pub trait CookieCacheSigner: Send + Sync {
    /// Sign the cache `payload` (`session`, `user`, `updatedAt`, `version`).
    async fn sign(&self, ctx: &EndpointContext, payload: &Map<String, Value>, expires_in: i64)
    -> crate::Result<String>;
    /// Verify a token, returning its claims and expiry in milliseconds.
    async fn verify(&self, ctx: &EndpointContext, token: &str) -> Option<(Map<String, Value>, i64)>;
}

fn cookie_cache_signer(ctx: &EndpointContext) -> Option<std::sync::Arc<dyn CookieCacheSigner>> {
    ctx.auth.plugins().iter().find_map(|p| p.cookie_cache_signer())
}

/// Decoded cookie-cache contents.
#[derive(Debug, Clone)]
pub struct CookieCachePayload {
    pub session: SessionWithUser,
    /// Milliseconds since epoch when the cache was written.
    pub updated_at: i64,
    pub version: String,
    /// Milliseconds since epoch when the cache expires.
    pub expires_at: i64,
}

fn chunk_index(cookie_name: &str, name: &str) -> Option<usize> {
    let suffix = name.strip_prefix(cookie_name)?.strip_prefix('.')?;
    let idx: usize = suffix.parse().ok()?;
    (idx.to_string() == suffix).then_some(idx)
}

/// Read a possibly-chunked cookie (`name`, or `name.0`, `name.1`, ...).
pub fn get_chunked_cookie(ctx: &EndpointContext, name: &str) -> Option<String> {
    if let Some(v) = ctx.get_cookie(name).filter(|v| !v.is_empty()) {
        return Some(v);
    }
    let mut chunks: Vec<(usize, String)> = ctx
        .cookies_matching(|n| chunk_index(name, n).is_some())
        .into_iter()
        .filter_map(|(n, v)| chunk_index(name, &n).map(|i| (i, v)))
        .collect();
    if chunks.is_empty() {
        return None;
    }
    chunks.sort_by_key(|(i, _)| *i);
    Some(chunks.into_iter().map(|(_, v)| v).collect())
}

/// Expire every existing chunk of `name` present on the request.
pub(super) fn clean_chunks(ctx: &EndpointContext, name: &str, attrs: &CookieOptions) {
    for (n, _) in ctx.cookies_matching(|n| n == name || chunk_index(name, n).is_some()) {
        ctx.set_cookie(&n, "", &CookieOptions { max_age: Some(0), ..attrs.clone() });
    }
}

/// Write `value` to cookie `name`, splitting into chunks if it exceeds the size limit.
pub(super) fn set_chunked(ctx: &EndpointContext, name: &str, value: &str, attrs: &CookieOptions) {
    clean_chunks(ctx, name, attrs);
    let overhead = serialize_cookie(&format!("{name}.{}", MAX_COOKIE_CHUNKS - 1), "", attrs).len();
    let chunk_size = MAX_COOKIE_SIZE.saturating_sub(overhead);
    if chunk_size == 0 {
        return;
    }
    let count = value.len().div_ceil(chunk_size);
    if count <= 1 {
        ctx.set_cookie(name, value, attrs);
        return;
    }
    if count > MAX_COOKIE_CHUNKS {
        tracing::warn!("session cookie is too large to store even after chunking; cookie cache skipped");
        return;
    }
    // The value is ASCII (base64url / JWT), so byte slicing is safe.
    for i in 0..count {
        let start = i * chunk_size;
        let end = (start + chunk_size).min(value.len());
        ctx.set_cookie(&format!("{name}.{i}"), &value[start..end], attrs);
    }
}

fn to_map(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// Write the session-data cookie cache (no-op unless enabled).
pub async fn set_cookie_cache(ctx: &EndpointContext, session: &SessionWithUser, dont_remember: bool) {
    let auth = &ctx.auth;
    let cache = &auth.options.session.cookie_cache;
    if !cache.enabled {
        return;
    }
    let mut payload = Map::new();
    payload.insert("session".into(), Value::Object(auth.session_output(&session.session)));
    payload.insert("user".into(), Value::Object(auth.user_output(&session.user)));
    payload.insert("updatedAt".into(), chrono::Utc::now().timestamp_millis().into());
    payload.insert("version".into(), cache.version.clone().into());

    let cookie = &auth.cookies.session_data;
    let mut attrs = cookie.attributes.clone();
    if dont_remember {
        attrs.max_age = None;
    }
    let max_age = attrs.max_age.unwrap_or(60);
    let expires_at = chrono::Utc::now().timestamp_millis() + max_age * 1000;
    let jwt_max_age = attrs.max_age.unwrap_or(300);

    let data = match cache.strategy {
        CookieCacheStrategy::Jwe => {
            match crypto::symmetric_encode_jwt(&payload, &auth.secret_config, SESSION_SALT, jwt_max_age) {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "failed to encode cookie cache");
                    return;
                }
            }
        }
        CookieCacheStrategy::Jwt => {
            let signed = match cookie_cache_signer(ctx) {
                Some(signer) => signer.sign(ctx, &payload, jwt_max_age).await,
                None => crypto::sign_jwt(&payload, &auth.secret, jwt_max_age),
            };
            match signed {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(error = %e, "failed to sign cookie cache");
                    return;
                }
            }
        }
        CookieCacheStrategy::Compact => {
            let mut signed = payload.clone();
            signed.insert("expiresAt".into(), expires_at.into());
            let signature = crypto::hmac_sign_base64url(&auth.secret, &Value::Object(signed).to_string());
            let mut outer = Map::new();
            outer.insert("session".into(), Value::Object(payload));
            outer.insert("expiresAt".into(), expires_at.into());
            outer.insert("signature".into(), signature.into());
            URL_SAFE_NO_PAD.encode(Value::Object(outer).to_string())
        }
    };
    set_chunked(ctx, &cookie.name, &data, &attrs);
}

fn parse_payload(v: Map<String, Value>, expires_at: i64) -> Option<CookieCachePayload> {
    let session: Session = serde_json::from_value(v.get("session")?.clone()).ok()?;
    let user: User = serde_json::from_value(v.get("user")?.clone()).ok()?;
    Some(CookieCachePayload {
        session: SessionWithUser { session, user },
        updated_at: v.get("updatedAt")?.as_i64()?,
        version: v.get("version").and_then(Value::as_str).unwrap_or("1").to_owned(),
        expires_at,
    })
}

/// Decode and verify a cookie-cache value.
pub async fn decode_cookie_cache(ctx: &EndpointContext, value: &str) -> Option<CookieCachePayload> {
    let auth = &ctx.auth;
    let now_ms = chrono::Utc::now().timestamp_millis();
    match auth.options.session.cookie_cache.strategy {
        CookieCacheStrategy::Jwe => {
            let claims = crypto::symmetric_decode_jwt(value, &auth.secret_config, SESSION_SALT)?;
            let exp = claims.get("exp").and_then(Value::as_i64).map(|e| e * 1000).unwrap_or(now_ms);
            parse_payload(claims, exp)
        }
        CookieCacheStrategy::Jwt => {
            if let Some(signer) = cookie_cache_signer(ctx) {
                let (claims, exp) = signer.verify(ctx, value).await?;
                return parse_payload(claims, exp);
            }
            let claims = crypto::verify_jwt(value, &auth.secret)?;
            let exp = claims.get("exp").and_then(Value::as_i64).map(|e| e * 1000).unwrap_or(now_ms);
            parse_payload(claims, exp)
        }
        CookieCacheStrategy::Compact => {
            let raw = URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()?;
            let outer: Map<String, Value> = serde_json::from_slice(&raw).ok()?;
            let session = to_map(outer.get("session")?.clone());
            let expires_at = outer.get("expiresAt")?.as_i64()?;
            let signature = outer.get("signature")?.as_str()?;
            let mut signed = session.clone();
            signed.insert("expiresAt".into(), expires_at.into());
            if !crypto::hmac_verify_base64url(&auth.secret, &Value::Object(signed).to_string(), signature) {
                return None;
            }
            parse_payload(session, expires_at)
        }
    }
}

/// Set the session token cookie (and cookie cache) for `session`.
///
/// `dont_remember`: `None` reads the existing `dont_remember` cookie.
/// `max_age_override`: replaces the computed token cookie max-age.
pub async fn set_session_cookie(
    ctx: &EndpointContext,
    session: &SessionWithUser,
    dont_remember: Option<bool>,
    max_age_override: Option<i64>,
) {
    let auth = &ctx.auth;
    let dont_remember = dont_remember
        .unwrap_or_else(|| ctx.get_signed_cookie(&auth.cookies.dont_remember.name, &auth.secret).is_some());
    let mut attrs = auth.cookies.session_token.attributes.clone();
    attrs.max_age = if dont_remember { None } else { Some(auth.options.session.expires_in) };
    if let Some(m) = max_age_override {
        attrs.max_age = Some(m);
    }
    ctx.set_signed_cookie(&auth.cookies.session_token.name, &session.session.token, &auth.secret, &attrs);
    if dont_remember {
        ctx.set_signed_cookie(
            &auth.cookies.dont_remember.name,
            "true",
            &auth.secret,
            &auth.cookies.dont_remember.attributes,
        );
    }
    set_cookie_cache(ctx, session, dont_remember).await;
    super::account::sync_account_cookie(ctx, &session.user.id);
    ctx.set_new_session(session.clone());
}

/// Expire all session cookies.
pub fn delete_session_cookie(ctx: &EndpointContext, skip_dont_remember: bool) {
    let auth = &ctx.auth;
    ctx.expire_cookie(&auth.cookies.session_token);
    ctx.expire_cookie(&auth.cookies.session_data);
    if auth.options.account.store_state_in_cookie {
        ctx.expire_cookie(&auth.cookie_factory.create("oauth_state", None));
    }
    let data: &AuthCookie = &auth.cookies.session_data;
    for (n, _) in ctx.cookies_matching(|n| chunk_index(&data.name, n).is_some()) {
        ctx.set_cookie(&n, "", &CookieOptions { max_age: Some(0), ..data.attributes.clone() });
    }
    if auth.options.account.store_account_cookie {
        let account = &auth.cookies.account_data;
        clean_chunks(ctx, &account.name, &account.attributes);
    }
    if !skip_dont_remember {
        ctx.expire_cookie(&auth.cookies.dont_remember);
    }
}
