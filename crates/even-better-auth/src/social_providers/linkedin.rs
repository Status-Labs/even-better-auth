//! LinkedIn (`social-providers/linkedin.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{bool_of, finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://www.linkedin.com/oauth/v2/accessToken";

pub struct LinkedIn {
    pub options: ProviderOptions,
}

impl LinkedIn {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: str_of(profile, "name"),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for LinkedIn {
    fn id(&self) -> &str {
        "linkedin"
    }
    fn name(&self) -> &str {
        "Linkedin"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["profile", "email", "openid"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://www.linkedin.com/oauth/v2/authorization".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                login_hint: p.login_hint,
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { code_verifier: None, device_id: None, ..p };
        validate_authorization_code(&self.options, &params, TOKEN_ENDPOINT, None).await
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
        let headers = [bearer(request.tokens.access_token.as_deref())];
        let Ok(profile) = get_json("https://api.linkedin.com/v2/userinfo", &headers).await else {
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
        let l = LinkedIn::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = l.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://www.linkedin.com/oauth/v2/authorization");
        assert_eq!(q["scope"], "profile email openid");
        assert!(!q.contains_key("code_challenge"));
    }

    #[test]
    fn maps_profile() {
        let profile = json!({
            "sub": "li-1", "name": "Ada Lovelace", "given_name": "Ada", "family_name": "Lovelace",
            "picture": "https://p", "email": "ada@example.com", "email_verified": true
        });
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(user.email_verified);
        let l = LinkedIn::new(ProviderOptions::new("a", "b"));
        assert_eq!(l.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("li-1"));
    }
}
