//! OAuth proxy (`plugins/oauth-proxy`): lets preview/development deployments use the OAuth
//! apps registered for production. The preview sends the provider's redirect to production
//! with an encrypted state package; production exchanges the code and redirects back to the
//! preview with an encrypted, short-lived profile payload that the preview turns into a
//! session. All environments must share `secret` (or the auth secret).

use std::any::Any;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use url::Url;

use crate::api::middleware::check_callback_urls;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointOutput, EndpointResult, handler, hook};
use crate::cookies::set_session_cookie;
use crate::crypto::{EncryptionPurpose, SecretConfig, derive_purpose_key, symmetric_decrypt, symmetric_encrypt};
use crate::error::ApiError;
use crate::oauth2::link_account::{HandleOAuthUserInfo, OAuthAccountData, handle_oauth_user_info, link_oauth_account};
use crate::oauth2::state::{
    StateData, auth_state_identifier, parse_generic_state_with, redirect_error, redirect_on_error, set_oauth_base_url,
    set_oauth_state,
};
use crate::oauth2::{
    OAuth2UserInfo, UserInfoRequest, ValidateCodeParams, find_provider, oauth_callback_path, resolve_account_id,
};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::utils::url::{encode_uri_component, get_origin};

#[derive(Clone, Default)]
pub struct OAuthProxyOptions {
    /// This deployment's URL; defaults to the request URL (when trusted), a platform URL
    /// (`VERCEL_URL`, `NETLIFY_URL`, `RENDER_URL`, ...) or the base URL.
    pub current_url: Option<String>,
    /// The production deployment that owns the OAuth app's redirect URI.
    pub production_url: Option<String>,
    /// Seconds a profile payload stays valid. Default 60.
    pub max_age: Option<i64>,
    /// Shared encryption secret; defaults to the auth secret.
    pub secret: Option<SecretConfig>,
}

struct Inner {
    options: OAuthProxyOptions,
}

const PACKAGE_STATE_FIELD: &str = "isOAuthProxy";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn vendor_base_url() -> Option<String> {
    env("VERCEL_URL")
        .map(|v| format!("https://{v}"))
        .or_else(|| env("NETLIFY_URL"))
        .or_else(|| env("RENDER_URL"))
        .or_else(|| env("AWS_LAMBDA_FUNCTION_NAME"))
        .or_else(|| env("GOOGLE_CLOUD_FUNCTION_NAME"))
        .or_else(|| env("AZURE_FUNCTION_NAME"))
}

fn strip_trailing_slash(url: &str) -> &str {
    url.trim_end_matches('/')
}

impl Inner {
    fn key(&self, ctx: &EndpointContext, purpose: EncryptionPurpose) -> SecretConfig {
        derive_purpose_key(self.options.secret.as_ref().unwrap_or(&ctx.auth.secret_config), purpose)
    }

    fn encrypt(&self, ctx: &EndpointContext, purpose: EncryptionPurpose, data: &str) -> Option<String> {
        symmetric_encrypt(&self.key(ctx, purpose), data).ok()
    }

    fn decrypt(&self, ctx: &EndpointContext, purpose: EncryptionPurpose, data: &str) -> Option<String> {
        symmetric_decrypt(&self.key(ctx, purpose), data).ok()
    }

    /// Whether this request is already on production (`checkSkipProxy`).
    fn skip_proxy(&self, ctx: &EndpointContext) -> bool {
        if ctx.has_header("x-skip-oauth-proxy") {
            return true;
        }
        let production = self
            .options
            .production_url
            .clone()
            .or_else(|| env("BETTER_AUTH_URL"))
            .unwrap_or_else(|| ctx.base_url.clone());
        let Some(current) = self.options.current_url.clone().or_else(|| ctx.request_url()).or_else(vendor_base_url)
        else {
            return false;
        };
        get_origin(&production).is_some() && get_origin(&production) == get_origin(&current)
    }

    /// This deployment's URL (`resolveCurrentURL`).
    fn current_url(&self, ctx: &EndpointContext) -> Option<Url> {
        if let Some(u) = &self.options.current_url {
            return Url::parse(u).ok();
        }
        if let Some(request) = ctx.request_url()
            && let Some(origin) = get_origin(&request)
            && ctx.auth.is_trusted_origin(&origin, false, None)
        {
            return Url::parse(&request).ok();
        }
        let base = vendor_base_url().filter(|v| get_origin(v).is_some()).unwrap_or_else(|| ctx.base_url.clone());
        Url::parse(&base).ok()
    }

    fn base_path<'a>(&self, ctx: &'a EndpointContext) -> &'a str {
        let p = ctx.auth.options.base_path.as_str();
        if p.is_empty() { "/api/auth" } else { p }
    }
}

// ---- preview: sign-in --------------------------------------------------------------------

/// Point the provider redirect at production and the final callback at this deployment's
/// completion endpoint.
async fn before_sign_in(inner: &Inner, ctx: &EndpointContext) -> Result<(), ApiError> {
    if inner.skip_proxy(ctx) {
        return Ok(());
    }
    let Value::Object(mut body) = ctx.body() else { return Ok(()) };
    let Some(provider) = body.get("provider").and_then(Value::as_str).map(str::to_owned) else { return Ok(()) };
    let Some(current) = inner.current_url(ctx) else { return Ok(()) };
    let original = body.get("callbackURL").and_then(Value::as_str).map_or_else(|| ctx.base_url.clone(), str::to_owned);
    let base_path = inner.base_path(ctx);
    if let Some(production) = &inner.options.production_url {
        set_oauth_base_url(ctx, &format!("{}{base_path}", strip_trailing_slash(production)));
    }
    let origin = current.origin().ascii_serialization();
    let callback = format!(
        "{}{base_path}/callback/{provider}/oauth-proxy?callbackURL={}",
        strip_trailing_slash(&origin),
        encode_uri_component(&original)
    );
    body.insert("callbackURL".into(), callback.into());
    ctx.set_body(Value::Object(body));
    Ok(())
}

/// Wrap the provider `state` in a package production can decrypt with the shared secret.
async fn after_sign_in(inner: &Inner, ctx: &EndpointContext) -> Option<EndpointOutput> {
    if inner.skip_proxy(ctx) {
        return None;
    }
    let Some(Ok(EndpointOutput::Json(Value::Object(mut returned)))) = ctx.returned() else { return None };
    let provider_url = returned.get("url").and_then(Value::as_str).filter(|u| !u.is_empty())?.to_owned();
    let mut url = Url::parse(&provider_url).ok()?;
    let state = url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned())?;
    let auth = &ctx.auth;
    let plaintext = if auth.options.account.store_state_in_cookie {
        let cookie = auth.cookie_factory.create("oauth_state", None);
        let set_cookie = ctx.response_cookie(&cookie.name)?;
        let value = set_cookie.split(';').next()?.split_once('=')?.1.to_owned();
        let key = derive_purpose_key(&auth.secret_config, EncryptionPurpose::OAuthStateCookie);
        symmetric_decrypt(&key, &value).ok()
    } else {
        auth.internal_adapter
            .find_verification_value(&auth_state_identifier(&state))
            .await
            .ok()
            .flatten()
            .map(|v| v.value)
    };
    let Some(plaintext) = plaintext else {
        tracing::warn!("No OAuth state found for proxy");
        return None;
    };
    let state_cookie = inner.encrypt(ctx, EncryptionPurpose::OAuthProxyState, &plaintext)?;
    let package = json!({ "state": state, "stateCookie": state_cookie, PACKAGE_STATE_FIELD: true });
    let Some(encrypted) = inner.encrypt(ctx, EncryptionPurpose::OAuthProxyPackage, &package.to_string()) else {
        tracing::error!("Failed to prepare OAuth proxy state");
        return None;
    };
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            let v = if k == "state" { encrypted.clone() } else { v.into_owned() };
            (k.into_owned(), v)
        })
        .collect();
    url.query_pairs_mut().clear().extend_pairs(pairs);
    let new_url = url.to_string();
    if ctx.response_header("location").is_some() {
        ctx.set_header("location", &new_url);
    }
    returned.insert("url".into(), new_url.into());
    Some(EndpointOutput::Json(Value::Object(returned)))
}

// ---- production: provider callback -------------------------------------------------------

fn callback_param(ctx: &EndpointContext, key: &str) -> Option<String> {
    ctx.query_str(key).or_else(|| ctx.body_str(key))
}

/// On production: exchange the code for a proxied flow and redirect to the preview with
/// the encrypted profile. Returns `None` for ordinary (non-proxy) callbacks.
async fn before_callback(inner: &Inner, ctx: &EndpointContext) -> Result<Option<EndpointOutput>, ApiError> {
    let Some(state) = callback_param(ctx, "state") else { return Ok(None) };
    let Some(package) = inner
        .decrypt(ctx, EncryptionPurpose::OAuthProxyPackage, &state)
        .and_then(|p| serde_json::from_str::<Map<String, Value>>(&p).ok())
    else {
        tracing::debug!("OAuth proxy: could not decrypt state package, falling back to regular callback");
        return Ok(None);
    };
    let s = |k: &str| package.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_owned);
    let (Some(package_state), Some(state_cookie), true) =
        (s("state"), s("stateCookie"), package.get(PACKAGE_STATE_FIELD) == Some(&Value::Bool(true)))
    else {
        tracing::warn!("Invalid OAuth proxy state package");
        return Ok(None);
    };
    let Some(state_data) = inner
        .decrypt(ctx, EncryptionPurpose::OAuthProxyState, &state_cookie)
        .and_then(|d| serde_json::from_str::<StateData>(&d).ok())
    else {
        tracing::error!("Failed to decrypt OAuth proxy state cookie");
        return Ok(None);
    };
    let error_url = state_data
        .error_url
        .clone()
        .or_else(|| ctx.auth.options.on_api_error_url.clone())
        .unwrap_or_else(|| format!("{}/error", ctx.base_url));
    let fail = |code: &str| Err(redirect_on_error(&error_url, code, None));
    if state_data.oauth_state.as_deref().is_some_and(|s| s != package_state) {
        tracing::error!("OAuth proxy state binding mismatch");
        return fail("state_mismatch");
    }
    if let Some(error) = callback_param(ctx, "error") {
        return fail(&error);
    }
    let Some(code) = callback_param(ctx, "code") else {
        tracing::warn!("OAuth callback missing authorization code");
        return fail("no_code");
    };
    let provider_id = ctx.param("id").unwrap_or_default().to_owned();
    let Some(provider) = find_provider(ctx, &provider_id) else {
        tracing::warn!(provider_id, "OAuth provider not found");
        return fail("oauth_provider_not_found");
    };
    let tokens = provider
        .validate_authorization_code(ValidateCodeParams {
            code,
            redirect_uri: format!("{}{}", ctx.base_url, oauth_callback_path(provider.as_ref())),
            code_verifier: Some(state_data.code_verifier.clone()),
            device_id: None,
        })
        .await;
    let Ok(tokens) = tokens else {
        tracing::error!("Failed to validate authorization code");
        return fail("invalid_code");
    };
    let user = callback_param(ctx, "user").and_then(|u| serde_json::from_str::<Value>(&u).ok());
    let request =
        UserInfoRequest { tokens: tokens.clone(), expected_id_token_nonce: state_data.id_token_nonce.clone(), user };
    let Ok(Some(info)) = provider.get_user_info(&request).await else {
        tracing::error!("Unable to get user info from provider");
        return fail("unable_to_get_user_info");
    };
    let Some(email) = info.user.email.clone().filter(|e| !e.is_empty()) else {
        tracing::error!("Provider did not return email");
        return fail("email_not_found");
    };
    let Ok(account_id) = resolve_account_id(provider.as_ref(), &tokens, &info.data) else {
        tracing::error!(provider_id, "Unable to derive provider account identity");
        return fail("unable_to_get_user_info");
    };
    let Ok(mut proxy_callback) = Url::parse(&state_data.callback_url) else { return fail("invalid_callback_url") };
    let final_callback = proxy_callback
        .query_pairs()
        .find(|(k, _)| k == "callbackURL")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| state_data.callback_url.clone());
    let date = |d: Option<DateTime<Utc>>| d.map(|d| Value::from(crate::utils::date::format(d))).unwrap_or(Value::Null);
    let options = provider.options();
    let payload = json!({
        "userInfo": {
            "id": account_id,
            "email": email,
            "name": info.user.name.clone().unwrap_or_default(),
            "image": info.user.image,
            "emailVerified": info.user.email_verified,
        },
        "profile": info.data,
        "scopes": tokens.scopes,
        "account": {
            "providerId": provider.id(),
            "accountId": account_id,
            "accessToken": tokens.access_token,
            "refreshToken": tokens.refresh_token,
            "idToken": tokens.id_token,
            "accessTokenExpiresAt": date(tokens.access_token_expires_at),
            "refreshTokenExpiresAt": date(tokens.refresh_token_expires_at),
            "scope": (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
        },
        "state": package_state,
        "callbackURL": final_callback,
        "newUserURL": state_data.new_user_url,
        "errorURL": state_data.error_url,
        "disableSignUp": (options.disable_implicit_sign_up && state_data.request_sign_up != Some(true)) || options.disable_sign_up,
        "timestamp": Utc::now().timestamp_millis(),
    });
    let Some(encrypted) = inner.encrypt(ctx, EncryptionPurpose::OAuthProxyProfile, &payload.to_string()) else {
        return Err(ApiError::internal("Failed to encrypt OAuth proxy payload"));
    };
    let pairs: Vec<(String, String)> = proxy_callback
        .query_pairs()
        .filter(|(k, _)| k != "profile")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    proxy_callback.query_pairs_mut().clear().extend_pairs(pairs).append_pair("profile", &encrypted);
    Ok(Some(EndpointOutput::Redirect(proxy_callback.to_string())))
}

/// Same-origin proxy redirects (production signing itself in) go straight to the target.
fn after_callback(inner: &Inner, ctx: &EndpointContext) -> Option<EndpointOutput> {
    let Some(Ok(EndpointOutput::Redirect(location))) = ctx.returned() else { return None };
    let proxied =
        location.contains("/oauth-proxy?callbackURL") || location.contains("/oauth-proxy-callback?callbackURL");
    if !proxied || !location.starts_with("http") {
        return None;
    }
    let production = inner
        .options
        .production_url
        .clone()
        .or_else(|| ctx.auth.options.base_url.clone())
        .unwrap_or_else(|| ctx.base_url.clone());
    let url = Url::parse(&location).ok()?;
    if get_origin(&production).as_deref() != Some(url.origin().ascii_serialization().as_str()) {
        tracing::warn!("OAuth proxy: cross-origin callback reached after hook unexpectedly");
        return None;
    }
    let target = url.query_pairs().find(|(k, _)| k == "callbackURL").map(|(_, v)| v.into_owned())?;
    Some(EndpointOutput::Redirect(target))
}

// ---- preview: completion -----------------------------------------------------------------

fn parse_date(v: &Value) -> Option<DateTime<Utc>> {
    crate::utils::date::parse_value(v)
}

async fn completion(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let callback_url = ctx.query_str("callbackURL");
    if callback_url.is_none() {
        return Err(ApiError::bad_request(crate::error::codes::VALIDATION_ERROR)
            .with_field("message", "[query.callbackURL] Invalid input: expected string, received undefined"));
    }
    check_callback_urls(&ctx, &[callback_url])?;
    let base = ctx.auth.options.base_url.clone().or_else(|| get_origin(&ctx.base_url)).unwrap_or_default();
    let default_error_url = ctx
        .auth
        .options
        .on_api_error_url
        .clone()
        .unwrap_or_else(|| format!("{}/api/auth/error", strip_trailing_slash(&base)));
    let Some(encrypted) = ctx.query_str("profile") else {
        tracing::error!("OAuth proxy callback missing profile data");
        return Err(redirect_on_error(&default_error_url, "missing_profile", None));
    };
    let Some(decrypted) = inner.decrypt(&ctx, EncryptionPurpose::OAuthProxyProfile, &encrypted) else {
        tracing::error!("Failed to decrypt OAuth proxy profile");
        return Err(redirect_on_error(&default_error_url, "invalid_profile", None));
    };
    let payload = serde_json::from_str::<Map<String, Value>>(&decrypted).ok().filter(|p| {
        p.get("userInfo").is_some_and(Value::is_object)
            && p.get("account").is_some_and(Value::is_object)
            && p.get("state").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && p.get("callbackURL").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && p.get("timestamp").is_some_and(Value::is_number)
    });
    let Some(payload) = payload else {
        tracing::error!("Failed to parse OAuth proxy payload");
        return Err(redirect_on_error(&default_error_url, "invalid_payload", None));
    };
    let s = |k: &str| payload.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_owned);
    let error_url = s("errorURL").unwrap_or(default_error_url);
    let (user, account) = (&payload["userInfo"], &payload["account"]);
    let provider_id = account["providerId"].as_str().unwrap_or_default().to_owned();
    if ctx.path.starts_with("/callback/") && ctx.param("id") != Some(provider_id.as_str()) {
        tracing::warn!("OAuth proxy callback provider mismatch");
        return Err(redirect_on_error(&error_url, "provider_mismatch", None));
    }
    let age = (Utc::now().timestamp_millis() as f64 - payload["timestamp"].as_f64().unwrap_or(0.0)) / 1000.0;
    let max_age = inner.options.max_age.unwrap_or(60) as f64;
    if age > max_age || age < -10.0 {
        tracing::error!("OAuth proxy payload expired or invalid (age: {age}s, maxAge: {max_age}s)");
        return Err(redirect_on_error(&error_url, "payload_expired", None));
    }
    let state = s("state").unwrap_or_default();
    let state_data = match parse_generic_state_with(&ctx, Some(&state), Some(true)).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(code = e.code, "OAuth proxy state missing or invalid: {}", e.message);
            return Err(redirect_on_error(&error_url, "state_mismatch", None));
        }
    };
    set_oauth_state(&ctx, &state_data);

    let str_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let user_info = OAuth2UserInfo {
        name: str_of(user, "name"),
        email: str_of(user, "email"),
        image: str_of(user, "image"),
        email_verified: user.get("emailVerified").and_then(Value::as_bool).unwrap_or(false),
        extra: Map::new(),
    };
    let account_data = OAuthAccountData {
        provider_id: provider_id.clone(),
        account_id: str_of(account, "accountId").unwrap_or_default(),
        access_token: str_of(account, "accessToken"),
        refresh_token: str_of(account, "refreshToken"),
        id_token: str_of(account, "idToken"),
        access_token_expires_at: account.get("accessTokenExpiresAt").and_then(parse_date),
        refresh_token_expires_at: account.get("refreshTokenExpiresAt").and_then(parse_date),
        scope: str_of(account, "scope"),
    };
    let profile = payload.get("profile").cloned().filter(Value::is_object);
    let callback = s("callbackURL").unwrap_or_default();

    if let Some(link) = &state_data.link {
        let scopes: Vec<String> = match payload.get("scopes").and_then(Value::as_array) {
            Some(a) => a.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            None => {
                account_data.scope.as_deref().map(|s| s.split(',').map(str::to_owned).collect()).unwrap_or_default()
            }
        };
        return match link_oauth_account(
            &ctx,
            link,
            &user_info,
            &account_data,
            &scopes,
            Some(profile.unwrap_or_default()),
        )
        .await?
        {
            Ok(()) => Err(redirect_error(&callback)),
            Err(f) => Err(redirect_on_error(&error_url, &f.code, f.message.as_deref())),
        };
    }

    let outcome = handle_oauth_user_info(
        &ctx,
        HandleOAuthUserInfo {
            user_info,
            account: account_data,
            callback_url: Some(callback.clone()),
            disable_sign_up: payload.get("disableSignUp").and_then(Value::as_bool).unwrap_or(false),
            override_user_info: false,
            is_trusted_provider: false,
            profile,
        },
    )
    .await;
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => match e.code().map(str::to_owned) {
            Some(code) => {
                let message = e.body.get("message").and_then(Value::as_str).map(str::to_owned);
                return Err(redirect_on_error(&error_url, &code, message.as_deref()));
            }
            None => return Err(e),
        },
    };
    if let Some(error) = outcome.error {
        tracing::error!(error, "OAuth proxy callback error");
        return Err(redirect_on_error(&error_url, &error.split(' ').collect::<Vec<_>>().join("_"), None));
    }
    let Some(data) = outcome.data else {
        tracing::error!("OAuth proxy callback missing session data");
        return Err(redirect_on_error(&error_url, "user_creation_failed", None));
    };
    set_session_cookie(&ctx, &data, None, None).await;
    let target = if outcome.is_register { s("newUserURL").unwrap_or(callback) } else { callback };
    Err(redirect_error(&target))
}

pub struct OAuthProxy {
    inner: Arc<Inner>,
}

pub fn oauth_proxy(options: OAuthProxyOptions) -> Arc<dyn Plugin> {
    Arc::new(OAuthProxy { inner: Arc::new(Inner { options }) })
}

fn is_sign_in(ctx: &EndpointContext) -> bool {
    ctx.path.starts_with("/sign-in/social") || ctx.path == "/link-social"
}

impl Plugin for OAuthProxy {
    fn id(&self) -> &str {
        "oauth-proxy"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b) = (self.inner.clone(), self.inner.clone());
        vec![
            Endpoint::get("oAuthProxy", "/oauth-proxy-callback", handler(move |ctx| completion(a.clone(), ctx))),
            Endpoint::get(
                "oAuthProxyCompletion",
                "/callback/:id/oauth-proxy",
                handler(move |ctx| completion(b.clone(), ctx)),
            ),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        let (a, b, c, d) = (self.inner.clone(), self.inner.clone(), self.inner.clone(), self.inner.clone());
        PluginHooks {
            before: vec![
                MatchedHook::new(
                    is_sign_in,
                    hook(move |ctx| {
                        let inner = a.clone();
                        async move {
                            before_sign_in(&inner, &ctx).await?;
                            Ok(None)
                        }
                    }),
                ),
                MatchedHook::new(
                    |ctx| ctx.path == "/callback/:id",
                    hook(move |ctx| {
                        let inner = b.clone();
                        async move { before_callback(&inner, &ctx).await }
                    }),
                ),
            ],
            after: vec![
                MatchedHook::new(
                    is_sign_in,
                    hook(move |ctx| {
                        let inner = c.clone();
                        async move { Ok(after_sign_in(&inner, &ctx).await) }
                    }),
                ),
                MatchedHook::new(
                    |ctx| ctx.path == "/callback/:id",
                    hook(move |ctx| {
                        let inner = d.clone();
                        async move { Ok(after_callback(&inner, &ctx)) }
                    }),
                ),
            ],
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
