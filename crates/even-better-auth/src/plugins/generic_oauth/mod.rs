//! Generic OAuth 2.0 / OIDC providers (`plugins/generic-oauth`): any authorization server,
//! configured by endpoints or an OIDC discovery document, joins the social providers and
//! signs in through `/sign-in/social` and `/callback/{providerId}`.

mod providers;

pub use providers::*;

use std::any::Any;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use futures::future::BoxFuture;
use serde_json::{Map, Value};
use url::Url;

use crate::error::{ApiError, Error, ErrorCode, Result};
use crate::oauth2::{
    self, AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, EndSessionParams, IdTokenConfig,
    JwksIdTokenConfig, JwksSource, OAuth2Tokens, OAuthProvider, ProviderOptions, UserInfoRequest, UserInfoResult,
    ValidateCodeParams,
};
use crate::options::BetterAuthOptions;
use crate::plugin::Plugin;

/// Error codes (`GENERIC_OAUTH_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    pub const INVALID_OAUTH_CONFIGURATION: ErrorCode =
        ErrorCode { code: "INVALID_OAUTH_CONFIGURATION", message: "Invalid OAuth configuration" };
    pub const TOKEN_URL_NOT_FOUND: ErrorCode =
        ErrorCode { code: "TOKEN_URL_NOT_FOUND", message: "Invalid OAuth configuration. Token URL not found." };
    pub const ALL: &[ErrorCode] = &[INVALID_OAUTH_CONFIGURATION, TOKEN_URL_NOT_FOUND];
}

use error_codes as e;

pub type GetTokenFn = Arc<dyn Fn(ValidateCodeParams) -> BoxFuture<'static, Result<OAuth2Tokens>> + Send + Sync>;
/// Returns the raw profile (`GenericOAuthUserInfo`): `email`, `name`, `image`,
/// `emailVerified`, and `id`/`sub` plus anything else.
pub type GetUserInfoFn = Arc<dyn Fn(OAuth2Tokens) -> BoxFuture<'static, Result<Option<Value>>> + Send + Sync>;
pub type AccountSubjectFn = Arc<dyn Fn(&Value, &OAuth2Tokens) -> Option<String> + Send + Sync>;

/// One provider (`GenericOAuthConfig`).
#[derive(Clone, Default)]
pub struct GenericOAuthConfig {
    pub provider_id: String,
    /// Display name; defaults to the provider id.
    pub name: Option<String>,
    /// The account subject; defaults to `sub` for OIDC providers and `id` otherwise.
    pub account_subject: Option<AccountSubjectFn>,
    /// OIDC discovery document; explicit endpoints take precedence over discovered ones.
    pub discovery_url: Option<String>,
    /// Fail unless discovery yields an issuer and JWKS to verify ID tokens with.
    pub require_id_token_verification: bool,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub user_info_url: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub disable_provider_logout: bool,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// `client_secret_basic`, `client_secret_post` or `private_key_jwt` (TS `tokenEndpointAuth`
    /// and `authentication`). Without one: post when a secret is set, else `none`.
    pub token_endpoint_auth: Option<ClientAuthentication>,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    /// `query` or `form_post`.
    pub response_mode: Option<String>,
    pub prompt: Option<String>,
    /// PKCE (default on).
    pub pkce: Option<bool>,
    pub access_type: Option<String>,
    /// Seconds; applied when the token response has no `expires_in`.
    pub access_token_expires_in: Option<i64>,
    pub get_token: Option<GetTokenFn>,
    pub get_user_info: Option<GetUserInfoFn>,
    pub map_profile_to_user: Option<oauth2::ProfileMapper>,
    pub authorization_url_params: Vec<(String, String)>,
    pub token_url_params: Vec<(String, String)>,
    pub refresh_token_params: Vec<(String, String)>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub discovery_headers: Vec<(String, String)>,
    /// Extra headers on the token request.
    pub authorization_headers: Vec<(String, String)>,
    pub override_user_info: bool,
    pub require_email_verification: bool,
    pub allow_idp_initiated: bool,
    pub disable_id_token_nonce_binding: bool,
}

impl GenericOAuthConfig {
    pub fn new(provider_id: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self { provider_id: provider_id.into(), client_id: client_id.into(), ..Default::default() }
    }

    fn validate(&self) -> Result<()> {
        let id = &self.provider_id;
        let has_secret = self.client_secret.as_deref().is_some_and(|s| !s.is_empty());
        match (&self.token_endpoint_auth, has_secret) {
            (Some(ClientAuthentication::PrivateKeyJwt(_)), true) => Err(Error::Config(format!(
                "Provider \"{id}\": tokenEndpointAuth.method \"private_key_jwt\" cannot be combined with clientSecret"
            ))),
            (Some(ClientAuthentication::Basic), false) => Err(Error::Config(format!(
                "Provider \"{id}\": tokenEndpointAuth.method \"client_secret_basic\" requires clientSecret"
            ))),
            (Some(ClientAuthentication::Post), false) => Err(Error::Config(format!(
                "Provider \"{id}\": tokenEndpointAuth.method \"client_secret_post\" requires clientSecret"
            ))),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Default)]
pub struct GenericOAuthOptions {
    pub config: Vec<GenericOAuthConfig>,
}

// ---- discovery ------------------------------------------------------------------------

#[derive(Default)]
struct Discovered {
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    issuer: Option<String>,
    jwks_uri: Option<String>,
    end_session_endpoint: Option<String>,
    signing_algs: Vec<String>,
}

async fn fetch_discovery(url: &str, headers: &[(String, String)]) -> Result<Option<Discovered>> {
    let headers: Vec<(&str, String)> = headers.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    let doc = match oauth2::get_json(url, &headers).await {
        Ok(Value::Object(doc)) => doc,
        Ok(_) | Err(Error::Http(_)) => return Ok(None),
        Err(err) => return Err(err),
    };
    let s = |k: &str| doc.get(k).and_then(Value::as_str).map(str::to_owned);
    let issuer = s("issuer");
    if issuer.as_deref().is_some_and(|i| Url::parse(i).is_err()) {
        return Ok(None);
    }
    Ok(Some(Discovered {
        authorization_endpoint: s("authorization_endpoint"),
        token_endpoint: s("token_endpoint"),
        userinfo_endpoint: s("userinfo_endpoint"),
        issuer,
        jwks_uri: s("jwks_uri"),
        end_session_endpoint: s("end_session_endpoint"),
        signing_algs: doc
            .get("id_token_signing_alg_values_supported")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default(),
    }))
}

/// The raw profile from the ID token (unverified decode, OIDC Core §3.1.3.7) or the
/// user-info endpoint (`fetchUserInfo`).
async fn fetch_user_info(tokens: &OAuth2Tokens, user_info_url: Option<&str>) -> Result<Option<Value>> {
    if let Some(claims) = tokens.id_token.as_deref().and_then(oauth2::decode_jwt_payload)
        && claims.get("sub").is_some_and(|v| !v.is_null())
        && claims.get("email").is_some_and(|v| !v.is_null())
    {
        let mut profile = Map::new();
        profile.insert("id".into(), claims["sub"].clone());
        profile.insert("emailVerified".into(), claims.get("email_verified").cloned().unwrap_or(Value::Null));
        profile.insert("image".into(), claims.get("picture").cloned().unwrap_or(Value::Null));
        profile.extend(claims);
        return Ok(Some(Value::Object(profile)));
    }
    let Some(url) = user_info_url else { return Ok(None) };
    let data = match oauth2::get_json(url, &[oauth2::bearer(tokens.access_token.as_deref())]).await {
        Ok(Value::Object(data)) => data,
        _ => return Ok(None),
    };
    let mut profile = data.clone();
    profile.insert("email".into(), data.get("email").cloned().unwrap_or(Value::Null));
    profile.insert("emailVerified".into(), data.get("email_verified").cloned().unwrap_or(false.into()));
    profile.insert("image".into(), data.get("picture").cloned().unwrap_or(Value::Null));
    profile.insert("name".into(), data.get("name").cloned().unwrap_or(Value::Null));
    Ok(Some(Value::Object(profile)))
}

fn default_expiry(mut tokens: OAuth2Tokens, expires_in: Option<i64>) -> OAuth2Tokens {
    if tokens.access_token_expires_at.is_none()
        && let Some(secs) = expires_in.filter(|s| *s > 0)
    {
        tokens.access_token_expires_at = Some(Utc::now() + Duration::seconds(secs));
    }
    tokens
}

// ---- provider -------------------------------------------------------------------------

/// A configured generic provider, after discovery.
pub struct GenericOAuthProvider {
    config: GenericOAuthConfig,
    options: ProviderOptions,
    name: String,
    authorization_url: Option<String>,
    token_url: Option<String>,
    user_info_url: Option<String>,
    end_session_endpoint: Option<String>,
    issuer: Option<String>,
    is_oidc: bool,
    id_token: Option<IdTokenConfig>,
    base_url: Option<String>,
}

impl GenericOAuthProvider {
    /// Resolve endpoints (running discovery if configured). `Ok(None)` means the provider is
    /// skipped, as TS does when discovery leaves it unusable.
    async fn build(c: GenericOAuthConfig, base_url: Option<String>) -> Result<Option<Self>> {
        let id = c.provider_id.clone();
        let mut authorization_url = c.authorization_url.clone();
        let mut token_url = c.token_url.clone();
        let mut user_info_url = c.user_info_url.clone();
        let mut end_session_endpoint = c.end_session_endpoint.clone();
        let (mut issuer, mut is_oidc, mut id_token) = (None, false, None);
        if let Some(discovery_url) = &c.discovery_url {
            let discovered = fetch_discovery(discovery_url, &c.discovery_headers).await.unwrap_or_else(|err| {
                tracing::error!("Discovery fetch failed for \"{id}\": {err}");
                None
            });
            if let Some(d) = discovered {
                authorization_url = authorization_url.or(d.authorization_endpoint);
                token_url = token_url.or(d.token_endpoint);
                user_info_url = user_info_url.or(d.userinfo_endpoint);
                end_session_endpoint = end_session_endpoint.or(d.end_session_endpoint);
                issuer = d.issuer.clone();
                is_oidc = !d.signing_algs.is_empty();
                if let (Some(jwks_uri), Some(iss)) = (&d.jwks_uri, &d.issuer) {
                    let Ok(jwks_url) = Url::parse(discovery_url).and_then(|base| base.join(jwks_uri)) else {
                        tracing::error!(
                            "Provider \"{id}\": invalid jwks_uri \"{jwks_uri}\" in discovery document. Provider skipped."
                        );
                        return Ok(None);
                    };
                    let mut config =
                        JwksIdTokenConfig::new(JwksSource::Url(jwks_url.into()), vec![c.client_id.clone()]);
                    config.issuer = vec![iss.clone()];
                    if is_oidc {
                        config.algorithms =
                            d.signing_algs.iter().filter_map(|a| jsonwebtoken::Algorithm::from_str(a).ok()).collect();
                    }
                    id_token = Some(IdTokenConfig::Jwks(config));
                }
            }
            if authorization_url.is_none() || (token_url.is_none() && c.get_token.is_none()) {
                tracing::error!(
                    "Provider \"{id}\": discovery left no usable authorization endpoint or token exchange. Provider skipped."
                );
                return Ok(None);
            }
        }
        if c.require_id_token_verification && id_token.is_none() {
            let message = format!(
                "Provider \"{id}\": requires verified ID tokens, but discovery did not provide a usable issuer and jwks_uri."
            );
            if c.discovery_url.is_some() {
                tracing::error!("{message} Provider skipped.");
                return Ok(None);
            }
            return Err(Error::Config(message));
        }
        let mut options = ProviderOptions::new(c.client_id.clone(), c.client_secret.clone().unwrap_or_default());
        options.redirect_uri = c.redirect_uri.clone();
        options.map_profile_to_user = c.map_profile_to_user.clone();
        options.disable_implicit_sign_up = c.disable_implicit_sign_up;
        options.disable_sign_up = c.disable_sign_up;
        options.prompt = c.prompt.clone();
        options.override_user_info_on_sign_in = c.override_user_info;
        options.require_email_verification = c.require_email_verification;
        if let Some(ClientAuthentication::PrivateKeyJwt(assertion)) = &c.token_endpoint_auth {
            options.client_assertion = Some(assertion.clone());
        }
        Ok(Some(Self {
            name: c.name.clone().unwrap_or_else(|| id.clone()),
            options,
            authorization_url,
            token_url,
            user_info_url,
            end_session_endpoint,
            issuer,
            is_oidc,
            id_token,
            base_url,
            config: c,
        }))
    }

    fn pkce(&self) -> bool {
        self.config.pkce.unwrap_or(true)
    }

    fn token_url(&self) -> Result<&str> {
        self.token_url.as_deref().ok_or_else(|| ApiError::bad_request(e::TOKEN_URL_NOT_FOUND).into())
    }
}

#[async_trait]
impl OAuthProvider for GenericOAuthProvider {
    fn id(&self) -> &str {
        &self.config.provider_id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, tokens: &OAuth2Tokens) -> Option<String> {
        if let Some(f) = &self.config.account_subject {
            return f(profile, tokens);
        }
        oauth2::subject_from(profile.get(if self.is_oidc { "sub" } else { "id" }))
    }

    async fn create_authorization_url(&self, params: AuthorizationUrlParams) -> Result<Url> {
        let Some(endpoint) = &self.authorization_url else {
            return Err(ApiError::bad_request(e::INVALID_OAUTH_CONFIGURATION).into());
        };
        let mut scopes = params.scopes.clone();
        scopes.extend(self.config.scopes.iter().cloned());
        if self.is_oidc && !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".into());
        }
        let mut additional = self.config.authorization_url_params.clone();
        additional.extend(params.additional_params);
        oauth2::create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: endpoint.clone(),
                redirect_uri: params.redirect_uri,
                state: params.state,
                code_verifier: self.pkce().then_some(params.code_verifier),
                scopes,
                prompt: self.config.prompt.clone(),
                access_type: self.config.access_type.clone(),
                response_type: self.config.response_type.clone(),
                response_mode: self.config.response_mode.clone(),
                nonce: params.id_token_nonce,
                login_hint: params.login_hint,
                additional_params: additional,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, mut params: ValidateCodeParams) -> Result<OAuth2Tokens> {
        if !self.pkce() {
            params.code_verifier = None;
        }
        if let Some(get_token) = &self.config.get_token {
            return Ok(default_expiry(get_token(params).await?, self.config.access_token_expires_in));
        }
        let token_url = self.token_url()?;
        let mut req = oauth2::authorization_code_request(
            &self.options,
            &params,
            token_url,
            self.config.token_endpoint_auth.clone(),
            &self.config.token_url_params,
        )?;
        for (k, v) in &self.config.authorization_headers {
            if req.header(k).is_none() {
                req.headers.push((k.clone(), v.clone()));
            }
        }
        let data = oauth2::post_form(token_url, &req).await?;
        let tokens = oauth2::get_oauth2_tokens(&oauth2::as_object(data));
        Ok(default_expiry(tokens, self.config.access_token_expires_in))
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        let tokens = &request.tokens;
        // Fail closed: with a discovered JWKS, an ID token that cannot be verified must not
        // become an identity source.
        if let Some(id_token) = &tokens.id_token
            && self.id_token.is_some()
            && !oauth2::verify_provider_id_token(self, id_token, request.expected_id_token_nonce.as_deref()).await
        {
            tracing::error!(
                "Provider \"{}\": id_token failed verification against the discovery JWKS or expected nonce",
                self.id()
            );
            return Ok(None);
        }
        let raw = match &self.config.get_user_info {
            Some(f) => f(tokens.clone()).await?,
            None => fetch_user_info(tokens, self.user_info_url.as_deref()).await?,
        };
        let Some(raw) = raw else { return Ok(None) };
        let s = |k: &str| raw.get(k).and_then(Value::as_str).map(str::to_owned);
        let user = oauth2::OAuth2UserInfo {
            name: s("name"),
            email: s("email"),
            image: s("image"),
            email_verified: raw.get("emailVerified").and_then(Value::as_bool).unwrap_or(false),
            extra: Map::new(),
        };
        Ok(Some(UserInfoResult { user: self.options.map_profile(&raw, user), data: raw }))
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        let token_url = self.token_url()?;
        let tokens = oauth2::refresh_access_token(
            &self.options,
            refresh_token,
            token_url,
            self.config.token_endpoint_auth.clone(),
            &self.config.refresh_token_params,
        )
        .await?;
        Ok(default_expiry(tokens, self.config.access_token_expires_in))
    }

    fn id_token(&self) -> Option<IdTokenConfig> {
        self.id_token.clone()
    }

    fn issuer(&self) -> Option<String> {
        self.issuer.clone()
    }

    fn requires_id_token_nonce(&self) -> bool {
        self.id_token.is_some() && !self.config.disable_id_token_nonce_binding
    }

    fn allow_idp_initiated(&self) -> bool {
        self.config.allow_idp_initiated
    }

    fn create_end_session_url(&self, params: EndSessionParams) -> Option<Url> {
        if self.config.disable_provider_logout {
            return None;
        }
        let mut url = Url::parse(self.end_session_endpoint.as_deref()?).ok()?;
        let configured = params.post_logout_redirect_uri.or_else(|| self.config.post_logout_redirect_uri.clone());
        let post_logout = configured.and_then(|uri| match Url::parse(&uri) {
            Ok(u) => Some(u.to_string()),
            Err(_) => Url::parse(self.base_url.as_deref()?).ok()?.join(&uri).ok().map(String::from),
        });
        {
            let mut q = url.query_pairs_mut();
            if let Some(id_token) = &params.id_token {
                q.append_pair("id_token_hint", id_token);
            }
            if let Some(redirect) = &post_logout {
                q.append_pair("post_logout_redirect_uri", redirect);
                q.append_pair("client_id", &self.config.client_id);
                if let Some(state) = &params.state {
                    q.append_pair("state", state);
                }
            } else if params.id_token.is_none() {
                q.append_pair("client_id", &self.config.client_id);
            }
        }
        if url.query() == Some("") {
            url.set_query(None);
        }
        Some(url)
    }
}

// ---- plugin ---------------------------------------------------------------------------

pub struct GenericOAuth {
    options: GenericOAuthOptions,
}

/// Validates the static configuration (token endpoint authentication vs. client secret).
pub fn generic_oauth(options: GenericOAuthOptions) -> Result<Arc<dyn Plugin>> {
    let mut seen = std::collections::HashSet::new();
    let duplicates: Vec<&str> =
        options.config.iter().map(|c| c.provider_id.as_str()).filter(|id| !seen.insert(*id)).collect();
    if !duplicates.is_empty() {
        tracing::warn!("Duplicate provider IDs found: {}", duplicates.join(", "));
    }
    for c in &options.config {
        c.validate()?;
    }
    Ok(Arc::new(GenericOAuth { options }))
}

#[async_trait]
impl Plugin for GenericOAuth {
    fn id(&self) -> &str {
        "generic-oauth"
    }

    async fn prepare(&self, options: &mut BetterAuthOptions) -> Result<()> {
        let mut providers: Vec<Arc<dyn OAuthProvider>> = vec![];
        for c in &self.options.config {
            if let Some(p) = GenericOAuthProvider::build(c.clone(), options.base_url.clone()).await? {
                providers.push(Arc::new(p));
            }
        }
        for p in &providers {
            if options.social_providers.iter().any(|s| s.id() == p.id()) {
                tracing::warn!(
                    "Generic OAuth provider \"{}\" shadows a built-in social provider with the same ID",
                    p.id()
                );
            }
        }
        providers.append(&mut options.social_providers);
        options.social_providers = providers;
        Ok(())
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
