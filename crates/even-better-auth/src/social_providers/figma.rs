//! Figma (`social-providers/figma.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, require_client_credentials, require_code_verifier, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://api.figma.com/v1/oauth/token";

pub struct Figma {
    pub options: ProviderOptions,
}

impl Figma {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: str_of(profile, "handle"),
        email: str_of(profile, "email"),
        image: str_of(profile, "img_url"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Figma {
    fn id(&self) -> &str {
        "figma"
    }
    fn name(&self) -> &str {
        "Figma"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Figma", &self.options, true)?;
        require_code_verifier("Figma", &p.code_verifier)?;
        let mut scopes = self.options.scopes_with_defaults(&["current_user:read"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://www.figma.com/oauth".into(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        validate_authorization_code(&self.options, &params, TOKEN_ENDPOINT, Some(ClientAuthentication::Basic)).await
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        refresh_access_token(&self.options, refresh_token, TOKEN_ENDPOINT, Some(ClientAuthentication::Basic), &[]).await
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let headers = [bearer(request.tokens.access_token.as_deref())];
        let profile = match get_json("https://api.figma.com/v1/me", &headers).await {
            Ok(profile) => profile,
            Err(e) => {
                tracing::error!(error = %e, "Failed to fetch user info from Figma");
                return Ok(None);
            }
        };
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
        let f = Figma::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = f.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://www.figma.com/oauth");
        assert_eq!(q["scope"], "current_user:read");
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(Figma::new(ProviderOptions::new("client-123", "")).create_authorization_url(params()).await.is_err());
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"id": "f1", "email": "ada@example.com", "handle": "ada", "img_url": "https://i"});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://i"));
        assert!(!user.email_verified);
        let f = Figma::new(ProviderOptions::new("a", "b"));
        assert_eq!(f.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("f1"));
    }
}
