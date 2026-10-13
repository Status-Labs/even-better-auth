//! Facebook (`social-providers/facebook.ts`).

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, require_client_credentials, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, IdTokenConfig, JwksIdTokenConfig, JwksSource, OAuth2Tokens,
    OAuth2UserInfo, OAuthProvider, ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer,
    create_authorization_url, decode_jwt_payload, get_json, refresh_access_token, subject_from,
    validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://graph.facebook.com/v24.0/oauth/access_token";

pub struct Facebook {
    pub options: ProviderOptions,
    /// Extra profile fields beyond `id,name,email,picture`.
    pub fields: Vec<String>,
    /// Facebook Login for Business configuration id.
    pub config_id: Option<String>,
}

impl Facebook {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, fields: vec![], config_id: None }
    }

    /// Validate an opaque access token against this app via `debug_token`; returns its user id.
    async fn verify_access_token(&self, access_token: &str) -> Option<String> {
        if self.options.client_id.is_empty() || self.options.client_secret.is_empty() {
            return None;
        }
        let app_token = format!("{}|{}", self.options.client_id, self.options.client_secret);
        let mut url = Url::parse("https://graph.facebook.com/debug_token").ok()?;
        url.query_pairs_mut().append_pair("input_token", access_token).append_pair("access_token", &app_token);
        let data = get_json(url.as_str(), &[]).await.ok()?;
        let data = data.get("data")?;
        let app_id = str_of(data, "app_id")?;
        let user_id = str_of(data, "user_id")?;
        let valid = data.get("is_valid").and_then(Value::as_bool) == Some(true);
        (valid && self.options.client_ids().contains(&app_id)).then_some(user_id)
    }
}

#[async_trait]
impl OAuthProvider for Facebook {
    fn id(&self) -> &str {
        "facebook"
    }
    fn name(&self) -> &str {
        "Facebook"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        match profile.get("sub") {
            Some(sub) => subject_from(Some(sub)),
            None => subject_from(profile.get("id")),
        }
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Facebook", &self.options, true)?;
        let mut scopes = self.options.scopes_with_defaults(&["email", "public_profile"]);
        scopes.extend(p.scopes);
        let mut additional = vec![];
        if let Some(id) = &self.config_id {
            additional.push(("config_id".to_owned(), id.clone()));
        }
        additional.extend(p.additional_params);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://www.facebook.com/v24.0/dialog/oauth".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                login_hint: p.login_hint,
                additional_params: additional,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { code_verifier: None, device_id: None, ..p };
        validate_authorization_code(&self.options, &params, TOKEN_ENDPOINT, None).await
    }

    fn id_token(&self) -> Option<IdTokenConfig> {
        let jwks = JwksSource::Url("https://limited.facebook.com/.well-known/oauth/openid/jwks/".into());
        let mut config = JwksIdTokenConfig::new(jwks, self.options.client_ids());
        config.issuer = vec!["https://www.facebook.com".into()];
        config.algorithms = vec![Algorithm::RS256];
        config.allow_opaque_token = true;
        Some(IdTokenConfig::Jwks(config))
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        refresh_access_token(&self.options, refresh_token, TOKEN_ENDPOINT, None, &[]).await
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        if let Some(claims) = request.tokens.id_token.as_deref().and_then(decode_jwt_payload) {
            // Limited Login tokens carry no email_verified claim.
            let profile = Value::Object(claims);
            let user = OAuth2UserInfo {
                name: str_of(&profile, "name"),
                email: str_of(&profile, "email"),
                image: str_of(&profile, "picture"),
                email_verified: false,
                extra: Default::default(),
            };
            return Ok(finish(&self.options, profile, user));
        }
        let Some(access_token) = request.tokens.access_token.as_deref() else { return Ok(None) };
        let Some(token_user_id) = self.verify_access_token(access_token).await else { return Ok(None) };
        let mut fields = vec!["id".to_owned(), "name".into(), "email".into(), "picture".into()];
        fields.extend(self.fields.iter().cloned());
        let url = format!("https://graph.facebook.com/me?fields={}", fields.join(","));
        let Ok(profile) = get_json(&url, &[bearer(Some(access_token))]).await else { return Ok(None) };
        if str_of(&profile, "id").as_deref() != Some(token_user_id.as_str()) {
            return Ok(None);
        }
        let user = OAuth2UserInfo {
            name: str_of(&profile, "name"),
            email: str_of(&profile, "email"),
            image: profile.pointer("/picture/data/url").and_then(Value::as_str).map(str::to_owned),
            email_verified: profile.get("email_verified").and_then(Value::as_bool).unwrap_or(false),
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }
}
