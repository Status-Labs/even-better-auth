//! Spotify (`social-providers/spotify.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://accounts.spotify.com/api/token";

pub struct Spotify {
    pub options: ProviderOptions,
}

impl Spotify {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: str_of(profile, "display_name"),
        email: str_of(profile, "email"),
        image: profile.pointer("/images/0/url").and_then(Value::as_str).map(str::to_owned),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Spotify {
    fn id(&self) -> &str {
        "spotify"
    }
    fn name(&self) -> &str {
        "Spotify"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["user-read-email"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://accounts.spotify.com/authorize".into(),
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
        let Ok(profile) = get_json("https://api.spotify.com/v1/me", &headers).await else {
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
        let s = Spotify::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = s.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://accounts.spotify.com/authorize");
        assert_eq!(q["scope"], "user-read-email");
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"id": "sp-1", "display_name": "Ada", "email": "ada@example.com",
            "images": [{"url": "https://i/1"}, {"url": "https://i/2"}]});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://i/1"));
        assert!(!user.email_verified);
        let s = Spotify::new(ProviderOptions::new("a", "b"));
        assert_eq!(s.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("sp-1"));
        assert!(to_user(&json!({"id": "x", "images": []})).image.is_none());
    }
}
