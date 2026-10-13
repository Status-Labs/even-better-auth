//! Paybin (`social-providers/paybin.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{
    bool_of, finish, refresh_override, require_client_credentials, require_code_verifier, str_of, truthy_str,
    user_info_override,
};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, create_authorization_url, decode_jwt_payload,
    refresh_access_token, subject_from, validate_authorization_code,
};

const DEFAULT_ISSUER: &str = "https://idp.paybin.io";

pub struct Paybin {
    pub options: ProviderOptions,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Paybin {
    pub fn new(options: ProviderOptions) -> Self {
        Self::with_issuer(options, None)
    }

    /// A Paybin OAuth server at `issuer` (default `https://idp.paybin.io`).
    pub fn with_issuer(options: ProviderOptions, issuer: Option<&str>) -> Self {
        let issuer = issuer.filter(|i| !i.is_empty()).unwrap_or(DEFAULT_ISSUER);
        Self {
            options,
            authorization_endpoint: format!("{issuer}/oauth2/authorize"),
            token_endpoint: format!("{issuer}/oauth2/token"),
        }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: Some(
            truthy_str(profile, "name").or_else(|| truthy_str(profile, "preferred_username")).unwrap_or_default(),
        ),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Paybin {
    fn id(&self) -> &str {
        "paybin"
    }
    fn name(&self) -> &str {
        "Paybin"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Paybin", &self.options, true)?;
        require_code_verifier("Paybin", &p.code_verifier)?;
        let mut scopes = self.options.scopes_with_defaults(&["openid", "email", "profile"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: self.authorization_endpoint.clone(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                prompt: self.options.prompt.clone(),
                login_hint: p.login_hint,
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        validate_authorization_code(&self.options, &params, &self.token_endpoint, None).await
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        refresh_access_token(&self.options, refresh_token, &self.token_endpoint, None, &[]).await
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let Some(claims) = request.tokens.id_token.as_deref().and_then(decode_jwt_payload) else {
            return Ok(None);
        };
        let profile = Value::Object(claims);
        let user = to_user(&profile);
        Ok(finish(&self.options, profile, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::social_providers::test_support::*;
    use serde_json::json;

    #[tokio::test]
    async fn authorization_url() {
        let mut o = ProviderOptions::new("client-123", "secret-abc");
        o.prompt = Some("login".into());
        let url = Paybin::new(o).create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://idp.paybin.io/oauth2/authorize");
        assert_eq!(q["scope"], "openid email profile");
        assert_eq!(q["prompt"], "login");
        assert_eq!(q["code_challenge_method"], "S256");

        let custom = Paybin::with_issuer(ProviderOptions::new("c", "s"), Some("https://idp.example.com"));
        assert_eq!(custom.token_endpoint, "https://idp.example.com/oauth2/token");
        assert!(Paybin::new(ProviderOptions::new("c", "")).create_authorization_url(params()).await.is_err());
    }

    #[test]
    fn maps_profile() {
        let profile =
            json!({"sub": "pb-1", "email": "ada@example.com", "preferred_username": "ada", "email_verified": true});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert!(user.email_verified);
        let p = Paybin::new(ProviderOptions::new("a", "b"));
        assert_eq!(p.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("pb-1"));
    }
}
