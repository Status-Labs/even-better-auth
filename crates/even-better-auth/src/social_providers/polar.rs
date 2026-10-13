//! Polar (`social-providers/polar.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{bool_of, finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://api.polar.sh/v1/oauth2/token";

pub struct Polar {
    pub options: ProviderOptions,
}

impl Polar {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    // Polar may provide email_verified, but it is not guaranteed.
    OAuth2UserInfo {
        name: Some(truthy_str(profile, "public_name").or_else(|| truthy_str(profile, "username")).unwrap_or_default()),
        email: str_of(profile, "email"),
        image: str_of(profile, "avatar_url"),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Polar {
    fn id(&self) -> &str {
        "polar"
    }
    fn name(&self) -> &str {
        "Polar"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["openid", "profile", "email"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://polar.sh/oauth2/authorize".into(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                prompt: self.options.prompt.clone(),
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
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
        let Ok(profile) = get_json("https://api.polar.sh/v1/oauth2/userinfo", &headers).await else {
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
        let p = Polar::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = p.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://polar.sh/oauth2/authorize");
        assert_eq!(q["scope"], "openid profile email");
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"id": "pl-1", "email": "ada@example.com", "username": "ada", "avatar_url": "https://a"});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://a"));
        assert!(!user.email_verified);
        let p = Polar::new(ProviderOptions::new("a", "b"));
        assert_eq!(p.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("pl-1"));
        let named = to_user(&json!({"id": "x", "public_name": "Ada L", "username": "ada", "email_verified": true}));
        assert_eq!(named.name.as_deref(), Some("Ada L"));
        assert!(named.email_verified);
    }
}
