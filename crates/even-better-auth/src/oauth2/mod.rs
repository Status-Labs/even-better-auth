//! OAuth 2.0 / OIDC client support (`core/src/oauth2`) and social sign-in flows.

mod client;
mod client_assertion;
mod id_token;
pub mod link_account;
pub mod routes;
pub mod state;

pub use client::*;
pub use client_assertion::*;
pub use id_token::*;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde_json::{Map, Value};
use url::Url;

use crate::api::EndpointContext;
use crate::error::{Error, Result};
use crate::types::SessionWithUser;

/// Tokens returned by a token endpoint.
#[derive(Debug, Clone, Default)]
pub struct OAuth2Tokens {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    /// The raw token response.
    pub raw: Map<String, Value>,
}

/// Normalized local-user attributes from a provider profile. Provider identity is
/// resolved separately through [`OAuthProvider::account_subject`].
#[derive(Debug, Clone, Default)]
pub struct OAuth2UserInfo {
    pub name: Option<String>,
    pub email: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
    /// Extra user fields from `map_profile_to_user`.
    pub extra: Map<String, Value>,
}

impl OAuth2UserInfo {
    /// Merge `map_profile_to_user` output: known keys override, the rest become extra fields.
    pub fn apply_mapping(&mut self, mapped: Map<String, Value>) {
        for (k, v) in mapped {
            match k.as_str() {
                "id" => {}
                "name" => self.name = v.as_str().map(str::to_owned),
                "email" => self.email = v.as_str().map(str::to_owned),
                "image" => self.image = v.as_str().map(str::to_owned),
                "emailVerified" => self.email_verified = v.as_bool().unwrap_or(false),
                _ => {
                    self.extra.insert(k, v);
                }
            }
        }
    }

    /// The JSON shape TS returns (`{ name, email, image, emailVerified, ...mapped }`).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if let Some(n) = &self.name {
            m.insert("name".into(), n.clone().into());
        }
        m.insert("email".into(), self.email.clone().map(Value::from).unwrap_or(Value::Null));
        if let Some(i) = &self.image {
            m.insert("image".into(), i.clone().into());
        }
        m.insert("emailVerified".into(), self.email_verified.into());
        m.extend(self.extra.clone());
        Value::Object(m)
    }
}

/// User info plus the raw provider profile.
#[derive(Debug, Clone)]
pub struct UserInfoResult {
    pub user: OAuth2UserInfo,
    pub data: Value,
}

/// Input to [`OAuthProvider::get_user_info`].
#[derive(Debug, Clone, Default)]
pub struct UserInfoRequest {
    pub tokens: OAuth2Tokens,
    /// OIDC nonce recovered from state, for providers that require nonce binding.
    pub expected_id_token_nonce: Option<String>,
    /// The `user` object some providers (Apple) post to the callback.
    pub user: Option<Value>,
}

impl From<OAuth2Tokens> for UserInfoRequest {
    fn from(tokens: OAuth2Tokens) -> Self {
        Self { tokens, ..Default::default() }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizationUrlParams {
    pub state: String,
    pub code_verifier: String,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub display: Option<String>,
    pub login_hint: Option<String>,
    pub id_token_nonce: Option<String>,
    pub additional_params: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct ValidateCodeParams {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EndSessionParams {
    pub id_token: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

pub type ProfileMapper = Arc<dyn Fn(&Value) -> Map<String, Value> + Send + Sync>;
pub type IdTokenVerifier = Arc<dyn Fn(String, Option<String>) -> BoxFuture<'static, bool> + Send + Sync>;
pub type UserInfoOverride =
    Arc<dyn Fn(OAuth2Tokens) -> BoxFuture<'static, Result<Option<UserInfoResult>>> + Send + Sync>;
pub type RefreshOverride = Arc<dyn Fn(String) -> BoxFuture<'static, Result<OAuth2Tokens>> + Send + Sync>;

/// Common provider configuration (`ProviderOptions`).
#[derive(Clone, Default)]
pub struct ProviderOptions {
    /// The primary client id, used for the authorization and token requests.
    pub client_id: String,
    /// Further client ids accepted as ID-token audiences (the array form of `clientId`).
    pub additional_client_ids: Vec<String>,
    pub client_secret: String,
    /// Sent as `client_key` in the code exchange (TikTok).
    pub client_key: Option<String>,
    /// Extra scopes, added to the provider defaults.
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub redirect_uri: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub disable_id_token_sign_in: bool,
    /// Custom ID token verification.
    pub verify_id_token: Option<IdTokenVerifier>,
    /// Replace the provider's user-info lookup.
    pub get_user_info: Option<UserInfoOverride>,
    /// Replace the provider's token refresh.
    pub refresh_access_token: Option<RefreshOverride>,
    /// Map the raw profile to extra user fields (may override name/email/image/emailVerified).
    pub map_profile_to_user: Option<ProfileMapper>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub prompt: Option<String>,
    pub override_user_info_on_sign_in: bool,
    /// Withhold sessions until the user's email is verified.
    pub require_email_verification: bool,
    /// Authenticate token requests with `private_key_jwt` instead of the client secret.
    pub client_assertion: Option<ClientAssertion>,
}

impl ProviderOptions {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self { client_id: client_id.into(), client_secret: client_secret.into(), ..Default::default() }
    }

    /// All configured client ids, primary first.
    pub fn client_ids(&self) -> Vec<String> {
        let mut ids = vec![self.client_id.clone()];
        ids.extend(self.additional_client_ids.iter().cloned());
        ids.retain(|s| !s.is_empty());
        ids
    }

    /// Default scopes (unless disabled) followed by the configured extra scopes.
    pub fn scopes_with_defaults(&self, defaults: &[&str]) -> Vec<String> {
        let mut scopes: Vec<String> =
            if self.disable_default_scope { vec![] } else { defaults.iter().map(|s| s.to_string()).collect() };
        scopes.extend(self.scope.iter().cloned());
        scopes
    }

    /// Apply `map_profile_to_user` to `user`.
    pub fn map_profile(&self, profile: &Value, mut user: OAuth2UserInfo) -> OAuth2UserInfo {
        if let Some(map) = &self.map_profile_to_user {
            user.apply_mapping(map(profile));
        }
        user
    }
}

/// An OAuth/OIDC identity provider (`OAuthProvider`).
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn options(&self) -> &ProviderOptions;

    /// Callback path relative to the base URL; defaults to `/callback/{id}`.
    fn callback_path(&self) -> String {
        format!("/callback/{}", self.id())
    }

    /// The stable provider subject for the account, read from the raw provider profile
    /// (`accountSubject`). Never derived from `map_profile_to_user`.
    fn account_subject(&self, profile: &Value, tokens: &OAuth2Tokens) -> Option<String>;

    async fn create_authorization_url(&self, params: AuthorizationUrlParams) -> Result<Url>;

    async fn validate_authorization_code(&self, params: ValidateCodeParams) -> Result<OAuth2Tokens>;

    /// Fetch user info. Returns `None` if the provider gave no usable profile.
    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>>;

    /// Whether [`refresh_access_token`](Self::refresh_access_token) is available.
    fn supports_refresh(&self) -> bool {
        self.options().refresh_access_token.is_some()
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        match &self.options().refresh_access_token {
            Some(f) => f(refresh_token.to_owned()).await,
            None => Err(Error::Other(format!("provider {} does not support refreshing tokens", self.id()))),
        }
    }

    async fn revoke_token(&self, _token: &str) -> Result<()> {
        Ok(())
    }

    /// Declarative ID token verification config (`idToken`).
    fn id_token(&self) -> Option<IdTokenConfig> {
        None
    }

    /// Expected authorization server issuer (RFC 9207), checked against the callback `iss`.
    fn issuer(&self) -> Option<String> {
        None
    }

    /// Bind ID tokens to a nonce generated for each redirect flow.
    fn requires_id_token_nonce(&self) -> bool {
        false
    }

    /// Accept callbacks without `state` by restarting the flow (IdP-initiated sign-in).
    fn allow_idp_initiated(&self) -> bool {
        false
    }

    fn create_end_session_url(&self, _params: EndSessionParams) -> Option<Url> {
        None
    }

    /// For downcasting to a concrete provider (e.g. reading Google's `hd` in one-tap).
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
}

/// Stringify a profile id (`String(subject)`); numbers are allowed.
pub fn subject_from(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Resolve and validate the account id for a provider profile (`resolveOAuthAccountKey`).
pub fn resolve_account_id(provider: &dyn OAuthProvider, tokens: &OAuth2Tokens, profile: &Value) -> Result<String> {
    match provider.account_subject(profile, tokens) {
        Some(id) if !id.trim().is_empty() && id != "undefined" && id != "null" => Ok(id),
        _ => Err(Error::Other("OAUTH_ACCOUNT_SUBJECT_INVALID".into())),
    }
}

/// Callback path with a leading slash (`getOAuthCallbackPath`).
pub fn oauth_callback_path(provider: &dyn OAuthProvider) -> String {
    let path = provider.callback_path();
    if path.starts_with('/') { path } else { format!("/{path}") }
}

/// Find a configured social provider by id.
pub fn find_provider(ctx: &EndpointContext, id: &str) -> Option<Arc<dyn OAuthProvider>> {
    ctx.auth.options.social_providers.iter().find(|p| p.id() == id).cloned()
}

/// RP-initiated logout URL for the most recently used provider account that supports it.
pub async fn provider_logout_url(ctx: &EndpointContext, session: &SessionWithUser) -> Option<String> {
    let mut accounts = ctx.auth.internal_adapter.find_accounts(&session.user.id).await.ok()?;
    accounts.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
    let callback = ctx.body_str("callbackURL").and_then(|cb| Url::parse(&ctx.base_url).ok()?.join(&cb).ok());
    for account in accounts {
        let Some(provider) = find_provider(ctx, &account.provider_id) else { continue };
        let url = provider.create_end_session_url(EndSessionParams {
            id_token: account.id_token.clone(),
            post_logout_redirect_uri: callback.as_ref().map(|u| u.to_string()),
            state: ctx.body_str("state"),
        });
        if let Some(url) = url {
            return Some(url.to_string());
        }
    }
    None
}
