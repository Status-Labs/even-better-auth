//! Roblox (`social-providers/roblox.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{create_placeholder_email, finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/token";

/// Roblox. `options.prompt` may be `none`, `consent`, `login`, `select_account` or
/// `select_account consent` (the default).
pub struct Roblox {
    pub options: ProviderOptions,
}

impl Roblox {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    // Roblox exposes no email: use a stable, non-routable placeholder keyed to the user id.
    let sub = subject_from(profile.get("sub")).unwrap_or_default();
    OAuth2UserInfo {
        name: Some(
            truthy_str(profile, "nickname").or_else(|| truthy_str(profile, "preferred_username")).unwrap_or_default(),
        ),
        email: Some(create_placeholder_email(&sub, "roblox")),
        image: str_of(profile, "picture"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Roblox {
    fn id(&self) -> &str {
        "roblox"
    }
    fn name(&self) -> &str {
        "Roblox"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["openid", "profile"]);
        scopes.extend(p.scopes);
        let prompt = self.options.prompt.clone().filter(|s| !s.is_empty());
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://apis.roblox.com/oauth/v1/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                prompt: Some(prompt.unwrap_or_else(|| "select_account consent".into())),
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { code_verifier: None, device_id: None, ..p };
        validate_authorization_code(&self.options, &params, TOKEN_ENDPOINT, Some(ClientAuthentication::Post)).await
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
        let Ok(profile) = get_json("https://apis.roblox.com/oauth/v1/userinfo", &headers).await else {
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
        let r = Roblox::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = r.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://apis.roblox.com/oauth/v1/authorize");
        assert_eq!(q["client_id"], "client-123");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["scope"], "openid profile");
        assert_eq!(q["prompt"], "select_account consent");
        assert!(!q.contains_key("code_challenge"));

        let url =
            r.create_authorization_url(with_additional(&[("custom", "value"), ("scope", "admin")])).await.unwrap();
        let q = query(&url);
        assert_eq!(q["custom"], "value");
        assert_eq!(q["scope"], "openid profile");
    }

    #[test]
    fn maps_profile() {
        let profile = json!({
            "sub": "roblox-user-1", "preferred_username": "builderman", "nickname": "Builderman",
            "name": "Builderman", "created_at": 0, "profile": "https://www.roblox.com/users/1/profile",
            "picture": "https://example.com/avatar.png"
        });
        let user = to_user(&profile);
        assert_eq!(user.email.as_deref(), Some("roblox-user-1@roblox.placeholder.invalid"));
        assert_eq!(user.name.as_deref(), Some("Builderman"));
        assert_eq!(user.image.as_deref(), Some("https://example.com/avatar.png"));
        assert!(!user.email_verified);
        let r = Roblox::new(ProviderOptions::new("a", "b"));
        assert_eq!(r.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("roblox-user-1"));
    }
}
