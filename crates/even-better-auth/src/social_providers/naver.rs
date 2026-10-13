//! Naver (`social-providers/naver.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://nid.naver.com/oauth2.0/token";

pub struct Naver {
    pub options: ProviderOptions,
}

impl Naver {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

/// Whether the `/v1/nid/me` envelope reports success (`resultcode == "00"`).
fn is_success(profile: &Value) -> bool {
    profile.get("resultcode").and_then(Value::as_str) == Some("00")
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    let res = profile.get("response").cloned().unwrap_or(Value::Null);
    OAuth2UserInfo {
        name: Some(truthy_str(&res, "name").or_else(|| truthy_str(&res, "nickname")).unwrap_or_default()),
        email: str_of(&res, "email"),
        image: str_of(&res, "profile_image"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Naver {
    fn id(&self) -> &str {
        "naver"
    }
    fn name(&self) -> &str {
        "Naver"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.pointer("/response/id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["profile", "email"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://nid.naver.com/oauth2.0/authorize".into(),
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
        let Ok(profile) = get_json("https://openapi.naver.com/v1/nid/me", &headers).await else {
            return Ok(None);
        };
        if !is_success(&profile) {
            return Ok(None);
        }
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
        let n = Naver::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = n.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://nid.naver.com/oauth2.0/authorize");
        assert_eq!(q["scope"], "profile email");
        assert!(!q.contains_key("code_challenge"));
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"resultcode": "00", "message": "success", "response": {
            "id": "nv-1", "nickname": "ada", "name": "", "email": "ada@example.com", "profile_image": "https://p"
        }});
        assert!(is_success(&profile));
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(!user.email_verified);
        let n = Naver::new(ProviderOptions::new("a", "b"));
        assert_eq!(n.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("nv-1"));
        assert!(!is_success(&json!({"resultcode": "024"})));
    }
}
