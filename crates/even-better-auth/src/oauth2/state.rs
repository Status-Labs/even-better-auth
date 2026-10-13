//! OAuth state handling (`oauth2/state.ts`, `state.ts`): a verification row plus a signed
//! `state` cookie by default, or an encrypted `oauth_state` cookie when
//! `account.store_state_in_cookie` is set.

use http::StatusCode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::api::EndpointContext;
use crate::api::routes::util::append_query_params;
use crate::crypto::{
    EncryptionPurpose, derive_purpose_key, generate_random_string, symmetric_decrypt, symmetric_encrypt,
};
use crate::error::{ApiError, codes};

const STATE_TTL_MS: i64 = 10 * 60 * 1000;

fn coerce_string<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    match Value::deserialize(d)? {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        other => Err(serde::de::Error::custom(format!("expected a string, got {other}"))),
    }
}

/// The user an OAuth flow links a provider account to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkData {
    pub email: String,
    #[serde(deserialize_with = "coerce_string")]
    pub user_id: String,
}

/// Data carried across the provider redirect (`StateData`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StateData {
    /// `additionalData` from the request, round-tripped verbatim.
    #[serde(flatten)]
    pub additional: Map<String, Value>,
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
    #[serde(rename = "codeVerifier")]
    pub code_verifier: String,
    #[serde(rename = "errorURL", default, skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,
    #[serde(rename = "newUserURL", default, skip_serializing_if = "Option::is_none")]
    pub new_user_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<LinkData>,
    #[serde(rename = "serverContext", default, skip_serializing_if = "Option::is_none")]
    pub server_context: Option<Map<String, Value>>,
    /// Milliseconds since the epoch.
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    #[serde(rename = "requestSignUp", default, skip_serializing_if = "Option::is_none")]
    pub request_sign_up: Option<bool>,
    #[serde(rename = "idTokenNonce", default, skip_serializing_if = "Option::is_none")]
    pub id_token_nonce: Option<String>,
    /// The `state` parameter sent to the provider.
    #[serde(rename = "oauthState", default, skip_serializing_if = "Option::is_none")]
    pub oauth_state: Option<String>,
}

/// Keys owned by [`StateData`]; never taken from `additionalData`.
pub const INTERNAL_STATE_KEYS: &[&str] = &[
    "callbackURL",
    "codeVerifier",
    "errorURL",
    "newUserURL",
    "expiresAt",
    "oauthState",
    "link",
    "requestSignUp",
    "idTokenNonce",
    "serverContext",
];

const SERVER_CONTEXT_KEY: &str = "oauthServerContext";
const OAUTH_STATE_KEY: &str = "oauthState";

/// Attach server-trusted data to the current OAuth flow so it survives the provider redirect
/// (`addOAuthServerContext`). Call from a `before` hook on an OAuth sign-in path; read it back
/// on the callback from [`get_oauth_state`]`.server_context`. Calls merge.
pub fn add_oauth_server_context(ctx: &EndpointContext, values: Map<String, Value>) {
    let mut current = ctx.local(SERVER_CONTEXT_KEY).and_then(|v| v.as_object().cloned()).unwrap_or_default();
    current.extend(values);
    ctx.set_local(SERVER_CONTEXT_KEY, Value::Object(current));
}

/// The OAuth state of this request: freshly generated during sign-in, or parsed during the
/// callback (`getOAuthState`). Top-level `additional` keys are client-supplied.
pub fn get_oauth_state(ctx: &EndpointContext) -> Option<StateData> {
    serde_json::from_value(ctx.local(OAUTH_STATE_KEY)?).ok()
}

/// Make `data` the current OAuth state for later hooks (`setOAuthState`).
pub fn set_oauth_state(ctx: &EndpointContext, data: &StateData) {
    remember_state(ctx, data);
}

fn remember_state(ctx: &EndpointContext, data: &StateData) {
    if let Ok(v) = serde_json::to_value(data) {
        ctx.set_local(OAUTH_STATE_KEY, v);
    }
}

const BASE_URL_OVERRIDE_KEY: &str = "oauthBaseURL";

/// The base URL OAuth redirect URIs are built from: normally the request's, but a plugin
/// (oauth-proxy) may point it at another deployment for this request.
pub fn oauth_base_url(ctx: &EndpointContext) -> String {
    ctx.local(BASE_URL_OVERRIDE_KEY).and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_else(|| ctx.base_url.clone())
}

/// Override [`oauth_base_url`] for the current request.
pub fn set_oauth_base_url(ctx: &EndpointContext, base_url: &str) {
    ctx.set_local(BASE_URL_OVERRIDE_KEY, base_url.into());
}

/// Verification identifier for database-backed state.
pub fn auth_state_identifier(state: &str) -> String {
    format!("auth-state:{state}")
}

/// A state parsing failure (`StateError`).
#[derive(Debug, Clone)]
pub struct StateError {
    pub code: &'static str,
    pub message: String,
    /// The flow's `errorCallbackURL`, when the state itself could be parsed.
    pub error_url: Option<String>,
}

impl StateError {
    fn new(code: &'static str, message: &str, error_url: Option<String>) -> Self {
        Self { code, message: message.into(), error_url }
    }
}

/// `options.on_api_error_url` or `{baseURL}/error`.
pub fn default_error_url(ctx: &EndpointContext) -> String {
    ctx.auth.options.on_api_error_url.clone().unwrap_or_else(|| format!("{}/error", ctx.base_url))
}

/// A `302 Found` to `url`, as an error (`throw ctx.redirect(url)`).
pub fn redirect_error(url: &str) -> ApiError {
    let mut err = ApiError { status: StatusCode::FOUND, body: Map::new(), headers: Default::default() };
    if let Ok(v) = http::HeaderValue::from_str(url) {
        err.headers.insert(http::header::LOCATION, v);
    }
    err
}

/// Redirect to `error_url?error=<code>[&error_description=...]` (`redirectOnError`).
pub fn redirect_on_error(error_url: &str, error: &str, description: Option<&str>) -> ApiError {
    let mut params = vec![("error", error)];
    if let Some(d) = description.filter(|d| !d.is_empty()) {
        params.push(("error_description", d));
    }
    redirect_error(&append_query_params(error_url, &params))
}

/// Inputs for [`generate_state`].
#[derive(Debug, Clone, Default)]
pub struct GenerateStateOptions {
    pub link: Option<LinkData>,
    pub additional_data: Option<Map<String, Value>>,
    pub id_token_nonce: Option<String>,
}

/// The `state` parameter and PKCE verifier for an authorization URL.
#[derive(Debug, Clone)]
pub struct GeneratedState {
    pub state: String,
    pub code_verifier: String,
}

/// A random OIDC nonce when the provider requires ID-token nonce binding.
pub fn generate_id_token_nonce(provider: &dyn super::OAuthProvider) -> Option<String> {
    provider.requires_id_token_nonce().then(|| generate_random_string(32))
}

/// Create and persist OAuth state for a redirect flow (`generateState`).
pub async fn generate_state(ctx: &EndpointContext, options: GenerateStateOptions) -> Result<GeneratedState, ApiError> {
    let body = ctx.body();
    let body_str = |k: &str| body.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
    let callback_url = body_str("callbackURL")
        .or_else(|| ctx.auth.options.base_url.clone().filter(|s| !s.is_empty()))
        .ok_or_else(|| ApiError::bad_request(codes::CALLBACK_URL_REQUIRED))?;
    let mut additional = options.additional_data.unwrap_or_default();
    additional.retain(|k, _| !INTERNAL_STATE_KEYS.contains(&k.as_str()));
    let data = StateData {
        additional,
        callback_url,
        code_verifier: generate_random_string(128),
        error_url: body_str("errorCallbackURL"),
        new_user_url: body_str("newUserCallbackURL"),
        link: options.link,
        // Server-trusted values, set after the client's `additionalData` so they can't be spoofed.
        server_context: ctx.local(SERVER_CONTEXT_KEY).and_then(|v| v.as_object().cloned()).filter(|m| !m.is_empty()),
        expires_at: chrono::Utc::now().timestamp_millis() + STATE_TTL_MS,
        request_sign_up: body.get("requestSignUp").and_then(Value::as_bool),
        id_token_nonce: options.id_token_nonce,
        oauth_state: None,
    };
    generate_generic_state(ctx, data).await.map_err(|e| {
        tracing::error!(error = %e.message, "failed to create verification");
        ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, "Unable to create verification")
    })
}

/// Persist `data` and return a fresh `state` (`generateGenericState`).
pub async fn generate_generic_state(ctx: &EndpointContext, mut data: StateData) -> Result<GeneratedState, StateError> {
    let auth = &ctx.auth;
    let state = generate_random_string(32);
    data.oauth_state = Some(state.clone());
    remember_state(ctx, &data);
    let json =
        serde_json::to_string(&data).map_err(|e| StateError::new("state_generation_error", &e.to_string(), None))?;
    if auth.options.account.store_state_in_cookie {
        let key = derive_purpose_key(&auth.secret_config, EncryptionPurpose::OAuthStateCookie);
        let encrypted = symmetric_encrypt(&key, &json)
            .map_err(|e| StateError::new("state_generation_error", &e.to_string(), None))?;
        let cookie = auth.cookie_factory.create("oauth_state", Some(10 * 60));
        ctx.set_cookie(&cookie.name, &encrypted, &cookie.attributes);
        return Ok(GeneratedState { state, code_verifier: data.code_verifier });
    }
    let cookie = auth.cookie_factory.create("state", Some(5 * 60));
    ctx.set_signed_cookie(&cookie.name, &state, &auth.secret, &cookie.attributes);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    auth.internal_adapter
        .create_verification_value(&auth_state_identifier(&state), &json, expires_at)
        .await
        .map_err(|_| {
            StateError::new(
                "state_generation_error",
                "Unable to create verification. Make sure the database adapter is properly working and there is a verification table in the database",
                None,
            )
        })?;
    Ok(GeneratedState { state, code_verifier: data.code_verifier })
}

/// Load and validate the state for a callback (`parseGenericState`).
pub async fn parse_generic_state(ctx: &EndpointContext, state: Option<&str>) -> Result<StateData, StateError> {
    parse_generic_state_with(ctx, state, None).await
}

/// [`parse_generic_state`], optionally overriding `account.skip_state_cookie_check` (the
/// oauth-proxy plugin restores state on a server that never set the state cookie).
pub async fn parse_generic_state_with(
    ctx: &EndpointContext,
    state: Option<&str>,
    skip_state_cookie_check: Option<bool>,
) -> Result<StateData, StateError> {
    let Some(state) = state.filter(|s| !s.is_empty()) else {
        return Err(StateError::new("state_not_found", "State not found in OAuth callback", None));
    };
    let auth = &ctx.auth;
    let data: StateData = if auth.options.account.store_state_in_cookie {
        let cookie = auth.cookie_factory.create("oauth_state", None);
        let Some(encrypted) = ctx.get_cookie(&cookie.name).filter(|v| !v.is_empty()) else {
            return Err(StateError::new("state_mismatch", "State mismatch: auth state cookie not found", None));
        };
        let key = derive_purpose_key(&auth.secret_config, EncryptionPurpose::OAuthStateCookie);
        let data: StateData =
            symmetric_decrypt(&key, &encrypted).ok().and_then(|json| serde_json::from_str(&json).ok()).ok_or_else(
                || StateError::new("state_invalid", "State invalid: Failed to decrypt or parse auth state", None),
            )?;
        if data.oauth_state.as_deref() != Some(state) {
            return Err(StateError::new(
                "state_security_mismatch",
                "State mismatch: OAuth state parameter does not match stored state",
                data.error_url,
            ));
        }
        ctx.expire_cookie(&cookie);
        data
    } else {
        let identifier = auth_state_identifier(state);
        let found = auth.internal_adapter.find_verification_value(&identifier).await.ok().flatten();
        let Some(found) = found else {
            return Err(StateError::new("state_mismatch", "State mismatch: verification not found", None));
        };
        let data: StateData = serde_json::from_str(&found.value)
            .map_err(|_| StateError::new("state_invalid", "State invalid: failed to parse auth state", None))?;
        if data.oauth_state.as_deref().is_some_and(|s| s != state) {
            return Err(StateError::new(
                "state_security_mismatch",
                "State mismatch: OAuth state parameter does not match stored state",
                data.error_url,
            ));
        }
        let cookie = auth.cookie_factory.create("state", None);
        let cookie_value = ctx.get_signed_cookie(&cookie.name, &auth.secret);
        let skip = skip_state_cookie_check.unwrap_or(auth.options.account.skip_state_cookie_check);
        if !skip && cookie_value.as_deref() != Some(state) {
            return Err(StateError::new(
                "state_security_mismatch",
                "State mismatch: State not persisted correctly",
                data.error_url,
            ));
        }
        ctx.expire_cookie(&cookie);
        if let Err(e) = auth.internal_adapter.delete_verification_by_identifier(&identifier).await {
            tracing::error!(error = %e, "failed to delete state verification");
        }
        data
    };
    if data.expires_at < chrono::Utc::now().timestamp_millis() {
        return Err(StateError::new("state_mismatch", "Invalid state: request expired", data.error_url));
    }
    Ok(data)
}

/// Parse the callback state, redirecting to the error URL on failure (`parseState`).
pub async fn parse_state(ctx: &EndpointContext) -> Result<StateData, ApiError> {
    let state = ctx.query_str("state").or_else(|| ctx.body_str("state"));
    let error_url = default_error_url(ctx);
    let mut data = match parse_generic_state(ctx, state.as_deref()).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(code = e.code, "Failed to parse state: {}", e.message);
            let code = if e.code == "state_security_mismatch" { "state_mismatch" } else { e.code };
            return Err(redirect_on_error(e.error_url.as_deref().unwrap_or(&error_url), code, None));
        }
    };
    if data.error_url.is_none() {
        data.error_url = Some(error_url);
    }
    remember_state(ctx, &data);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn state_data_json_shape() {
        let mut additional = Map::new();
        additional.insert("foo".into(), "bar".into());
        let data = StateData {
            additional,
            callback_url: "/cb".into(),
            code_verifier: "v".into(),
            link: Some(LinkData { email: "a@b.com".into(), user_id: "u1".into() }),
            expires_at: 1,
            oauth_state: Some("s".into()),
            ..Default::default()
        };
        let v = serde_json::to_value(&data).unwrap();
        assert_eq!(
            v,
            json!({"foo": "bar", "callbackURL": "/cb", "codeVerifier": "v", "link": {"email": "a@b.com", "userId": "u1"}, "expiresAt": 1, "oauthState": "s"})
        );
        let back: StateData = serde_json::from_value(v).unwrap();
        assert_eq!(back, data);
        let numeric: StateData = serde_json::from_value(
            json!({"callbackURL": "/", "codeVerifier": "v", "expiresAt": 2, "link": {"email": "e", "userId": 5}}),
        )
        .unwrap();
        assert_eq!(numeric.link.unwrap().user_id, "5");
    }
}
