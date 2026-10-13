//! Popup OAuth sign-in (`plugins/oauth-popup`, experimental in TS): `GET /oauth-popup/start`
//! runs the provider flow in a popup, and the callback answers with a small page that
//! `postMessage`s the session token to the (trusted) opener, so apps embedded in cross-site
//! iframes can sign in. Pair with the bearer plugin.

use std::any::Any;
use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use serde_json::{Map, Value, json};
use url::Url;

use crate::api::{Ctx, Endpoint, EndpointContext, EndpointOutput, EndpointResult, handler, hook};
use crate::error::{ApiError, ErrorCode, codes};
use crate::oauth2::state::{
    INTERNAL_STATE_KEYS, StateData, generate_generic_state, generate_id_token_nonce, set_oauth_state,
};
use crate::oauth2::{AuthorizationUrlParams, find_provider};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};

/// Error codes (`OAUTH_POPUP_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    pub const POPUP_SIGN_IN_FAILED: ErrorCode =
        ErrorCode { code: "POPUP_SIGN_IN_FAILED", message: "Popup sign-in failed" };
    pub const POPUP_BLOCKED: ErrorCode =
        ErrorCode { code: "POPUP_BLOCKED", message: "Sign-in popup was blocked by the browser" };
    pub const POPUP_CLOSED: ErrorCode =
        ErrorCode { code: "POPUP_CLOSED", message: "Sign-in popup was closed before completing" };
    pub const POPUP_TIMEOUT: ErrorCode = ErrorCode { code: "POPUP_TIMEOUT", message: "Sign-in popup timed out" };
    pub const ALL: &[ErrorCode] = &[POPUP_SIGN_IN_FAILED, POPUP_BLOCKED, POPUP_CLOSED, POPUP_TIMEOUT];
}

pub const OAUTH_POPUP_MESSAGE_TYPE: &str = "better-auth:oauth-popup";
pub const OAUTH_POPUP_DATA_ELEMENT_ID: &str = "better-auth-oauth-popup";
pub const POPUP_MARKER_COOKIE: &str = "oauth_popup";
/// The completion script, byte-identical to TS so the CSP hash below matches.
pub const OAUTH_POPUP_COMPLETE_SCRIPT: &str = include_str!("complete.js");
pub const OAUTH_POPUP_SCRIPT_CSP_HASH: &str = "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=";

/// JSON safe to inline in a `<script>` element.
fn inline_json(value: &Value) -> String {
    let mut out = String::new();
    for c in value.to_string().chars() {
        match c {
            '<' | '\u{2028}' | '\u{2029}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn render_completion(ctx: &EndpointContext, popup_origin: &str, message: Map<String, Value>) -> EndpointOutput {
    if message.contains_key("token") && !ctx.auth.has_plugin("bearer") {
        tracing::warn!(
            "OAuth popup hands the session token back via postMessage, but the `bearer` plugin is not registered, so an embedded (cross-site iframe) app cannot authenticate with it. Add bearer() to your auth `plugins`."
        );
    }
    let mut data = Map::new();
    data.insert("type".into(), OAUTH_POPUP_MESSAGE_TYPE.into());
    data.insert("targetOrigin".into(), popup_origin.into());
    data.extend(message);
    let html = format!(
        "<!doctype html>\n<html>\n<head><meta charset=\"utf-8\"><title>Completing sign-in</title></head>\n<body>\n<script type=\"application/json\" id=\"{OAUTH_POPUP_DATA_ELEMENT_ID}\">{}</script>\n<script>{OAUTH_POPUP_COMPLETE_SCRIPT}</script>\n</body>\n</html>",
        inline_json(&Value::Object(data))
    );
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header(
            "content-security-policy",
            format!("default-src 'none'; script-src '{OAUTH_POPUP_SCRIPT_CSP_HASH}'; base-uri 'none'"),
        )
        // The page carries the session token, so keep it out of any cache.
        .header("cache-control", "no-store")
        .header("pragma", "no-cache")
        .body(Bytes::from(html))
        .expect("valid response");
    EndpointOutput::Response(response)
}

fn error_message(nonce: &str, code: &str, description: Option<String>) -> Map<String, Value> {
    let mut error = json!({ "code": code });
    if let Some(d) = description {
        error["description"] = d.into();
    }
    let mut m = Map::new();
    m.insert("nonce".into(), nonce.into());
    m.insert("error".into(), error);
    m
}

async fn start(ctx: Ctx) -> EndpointResult {
    let q = |k: &str| ctx.query_str(k);
    let (Some(provider_id), Some(popup_origin)) = (q("provider"), q("popupOrigin")) else {
        return Err(ApiError::bad_request(codes::VALIDATION_ERROR));
    };
    // The opener must be trusted before anything is posted to it.
    if !ctx.auth.is_trusted_origin(&popup_origin, false, None) {
        tracing::error!("OAuth popup origin is not a trusted origin. Add {popup_origin} to trustedOrigins.");
        return Err(ApiError::forbidden(codes::INVALID_ORIGIN));
    }
    let nonce = q("popupNonce").unwrap_or_default();
    // Once the opener is trusted, start-stage failures are relayed to it.
    let fail = |code: &str, description: Option<String>| {
        Ok(render_completion(&ctx, &popup_origin, error_message(&nonce, code, description)))
    };
    for (key, code) in [
        ("callbackURL", "invalid_callback_url"),
        ("errorCallbackURL", "invalid_error_callback_url"),
        ("newUserCallbackURL", "invalid_new_user_callback_url"),
    ] {
        if let Some(url) = q(key)
            && !ctx.auth.is_trusted_origin(&url, true, None)
        {
            tracing::error!("Invalid redirect URL: {url}");
            return fail(code, Some(format!("Untrusted URL: {url}")));
        }
    }
    let Some(provider) = find_provider(&ctx, &provider_id) else {
        return fail("provider_not_found", Some(format!("Unknown provider: {provider_id}")));
    };
    let additional: Map<String, Value> = q("additionalData")
        .and_then(|d| serde_json::from_str::<Map<String, Value>>(&d).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|(k, _)| !INTERNAL_STATE_KEYS.contains(&k.as_str()))
        .collect();
    let code_verifier = crate::crypto::generate_random_string(128);
    let id_token_nonce = generate_id_token_nonce(provider.as_ref());
    let data = StateData {
        additional,
        callback_url: q("callbackURL").unwrap_or_else(|| ctx.base_url.clone()),
        code_verifier: code_verifier.clone(),
        id_token_nonce: id_token_nonce.clone(),
        error_url: q("errorCallbackURL"),
        new_user_url: q("newUserCallbackURL"),
        request_sign_up: (q("requestSignUp").as_deref() == Some("true")).then_some(true),
        expires_at: chrono::Utc::now().timestamp_millis() + 10 * 60 * 1000,
        ..Default::default()
    };
    set_oauth_state(&ctx, &data);
    let started = async {
        let state = generate_generic_state(&ctx, data).await.map_err(|e| e.message)?;
        // Remember the opener so the callback's completion page can post to it.
        let marker = ctx.auth.cookie_factory.create(POPUP_MARKER_COOKIE, Some(10 * 60));
        let value = json!({ "popupOrigin": popup_origin, "popupNonce": nonce }).to_string();
        ctx.set_signed_cookie(&marker.name, &value, &ctx.auth.secret, &marker.attributes);
        provider
            .create_authorization_url(AuthorizationUrlParams {
                state: state.state,
                code_verifier,
                scopes: q("scopes").map(|s| s.split(',').map(str::to_owned).collect()).unwrap_or_default(),
                redirect_uri: format!("{}/callback/{}", ctx.base_url, provider.id()),
                id_token_nonce,
                ..Default::default()
            })
            .await
            .map_err(|e| e.to_string())
    };
    match started.await {
        Ok(url) => ctx.redirect(url.to_string()),
        Err(err) => {
            tracing::error!(error = err, "OAuth popup failed to start");
            fail("popup_sign_in_failed", Some("Failed to start the OAuth flow.".into()))
        }
    }
}

/// Swap the callback's redirect for the completion page when the flow started in a popup.
fn after_callback(ctx: &EndpointContext) -> Option<EndpointOutput> {
    let redirect_to = match ctx.returned()? {
        Ok(EndpointOutput::Redirect(url)) => url,
        Err(e) if e.status.is_redirection() => e.headers.get(http::header::LOCATION)?.to_str().ok()?.to_owned(),
        _ => return None,
    };
    let cookie = ctx.auth.cookie_factory.create(POPUP_MARKER_COOKIE, None);
    let marker = ctx.get_signed_cookie(&cookie.name, &ctx.auth.secret)?;
    ctx.expire_cookie(&cookie);
    let marker: Value = serde_json::from_str(&marker).ok()?;
    let popup_origin = marker.get("popupOrigin")?.as_str()?.to_owned();
    let nonce = marker.get("popupNonce").and_then(Value::as_str).unwrap_or_default().to_owned();
    let session_cookie = ctx.response_cookie(&ctx.auth.cookies.session_token.name);
    let token = session_cookie
        .as_deref()
        .and_then(|c| c.split(';').next())
        .and_then(|p| p.split_once('='))
        .map(|(_, v)| v.to_owned())
        .filter(|v| !v.is_empty());
    let message = match token {
        Some(token) => {
            let mut m = Map::new();
            m.insert("nonce".into(), nonce.into());
            m.insert("token".into(), token.into());
            m.insert("redirectTo".into(), redirect_to.into());
            m
        }
        None => {
            let url = Url::parse(&redirect_to)
                .or_else(|_| Url::parse(&ctx.base_url).and_then(|b| b.join(&redirect_to)))
                .ok()?;
            let param = |k: &str| url.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());
            // An unrecognized outcome keeps the redirect.
            let code = param("error")?;
            error_message(&nonce, &code, param("error_description"))
        }
    };
    Some(render_completion(ctx, &popup_origin, message))
}

pub struct OAuthPopup;

pub fn oauth_popup() -> Arc<dyn Plugin> {
    Arc::new(OAuthPopup)
}

impl Plugin for OAuthPopup {
    fn id(&self) -> &str {
        "oauth-popup"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        vec![Endpoint::get("oauthPopupStart", "/oauth-popup/start", handler(start))]
    }

    fn hooks(&self) -> PluginHooks {
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |ctx| ctx.path.starts_with("/callback/") || ctx.path.starts_with("/oauth2/callback/"),
                hook(|ctx| async move { Ok(after_callback(&ctx)) }),
            )],
        }
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        error_codes::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    #[test]
    fn csp_hash_matches_script() {
        let digest = crate::crypto::sha256(OAUTH_POPUP_COMPLETE_SCRIPT.as_bytes());
        let hash = format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(digest));
        assert_eq!(hash, OAUTH_POPUP_SCRIPT_CSP_HASH);
        assert_eq!(inline_json(&json!("</script>\u{2028}")), "\"\\u003c/script>\\u2028\"");
    }
}
