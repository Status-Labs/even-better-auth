//! Kakao (`social-providers/kakao.ts`).

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

const TOKEN_ENDPOINT: &str = "https://kauth.kakao.com/oauth/token";

pub struct Kakao {
    pub options: ProviderOptions,
}

impl Kakao {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    let account = profile.get("kakao_account").cloned().unwrap_or(Value::Null);
    let kakao_profile = account.get("profile").cloned().unwrap_or(Value::Null);
    OAuth2UserInfo {
        name: Some(truthy_str(&kakao_profile, "nickname").or_else(|| truthy_str(&account, "name")).unwrap_or_default()),
        email: str_of(&account, "email"),
        image: truthy_str(&kakao_profile, "profile_image_url")
            .or_else(|| str_of(&kakao_profile, "thumbnail_image_url")),
        email_verified: bool_of(&account, "is_email_valid") && bool_of(&account, "is_email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Kakao {
    fn id(&self) -> &str {
        "kakao"
    }
    fn name(&self) -> &str {
        "Kakao"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["account_email", "profile_image", "profile_nickname"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://kauth.kakao.com/oauth/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
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
        let Ok(profile) = get_json("https://kapi.kakao.com/v2/user/me", &headers).await else {
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
    async fn authorization_url_without_pkce() {
        let k = Kakao::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = k.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://kauth.kakao.com/oauth/authorize");
        assert_eq!(q["scope"], "account_email profile_image profile_nickname");
        assert!(!q.contains_key("code_challenge"));
    }

    #[test]
    fn maps_profile() {
        let profile = json!({
            "id": 123456789,
            "kakao_account": {
                "profile": {"nickname": "", "thumbnail_image_url": "https://t"},
                "name": "Kim", "email": "kim@example.com", "is_email_valid": true, "is_email_verified": true
            }
        });
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Kim"));
        assert_eq!(user.email.as_deref(), Some("kim@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://t"));
        assert!(user.email_verified);
        let k = Kakao::new(ProviderOptions::new("a", "b"));
        assert_eq!(k.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("123456789"));

        let unverified = to_user(&json!({"id": 1, "kakao_account": {"is_email_valid": true}}));
        assert!(!unverified.email_verified);
        assert_eq!(unverified.name.as_deref(), Some(""));
        assert_eq!(to_user(&json!({"id": 1})).email, None);
    }
}
