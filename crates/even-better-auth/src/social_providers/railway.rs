//! Railway (`social-providers/railway.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const AUTHORIZATION_ENDPOINT: &str = "https://backboard.railway.com/oauth/auth";
const TOKEN_ENDPOINT: &str = "https://backboard.railway.com/oauth/token";
const USERINFO_ENDPOINT: &str = "https://backboard.railway.com/oauth/me";

pub struct Railway {
    pub options: ProviderOptions,
}

impl Railway {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    // Railway does not provide an email_verified claim.
    OAuth2UserInfo {
        name: str_of(profile, "name"),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Railway {
    fn id(&self) -> &str {
        "railway"
    }
    fn name(&self) -> &str {
        "Railway"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["openid", "email", "profile"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: AUTHORIZATION_ENDPOINT.into(),
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
        let Ok(profile) = get_json(USERINFO_ENDPOINT, &headers).await else {
            return Ok(None);
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
        let r = Railway::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = r.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), AUTHORIZATION_ENDPOINT);
        assert_eq!(q["scope"], "openid email profile");
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"sub": "rw-1", "email": "ada@example.com", "name": "Ada", "picture": "https://p"});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(!user.email_verified);
        let r = Railway::new(ProviderOptions::new("a", "b"));
        assert_eq!(r.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("rw-1"));
    }
}
