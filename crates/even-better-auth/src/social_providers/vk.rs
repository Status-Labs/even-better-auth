//! VK ID (`social-providers/vk.ts`). The callback's `device_id` is forwarded to the code
//! exchange. (The TS `scheme` option is declared but unused there, so it is not ported.)

use async_trait::async_trait;
use serde_json::{Map, Value};
use url::Url;

use super::{refresh_override, str_of, truthy_str, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    TokenRequest, UserInfoRequest, UserInfoResult, ValidateCodeParams, create_authorization_url, post_form,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://id.vk.com/oauth2/auth";

pub struct Vk {
    pub options: ProviderOptions,
}

impl Vk {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }

    /// Map the profile; `None` when neither VK nor `map_profile_to_user` supplies an email.
    fn to_user(&self, profile: &Value) -> Option<OAuth2UserInfo> {
        let user = profile.get("user").cloned().unwrap_or(Value::Null);
        let mapped = self.options.map_profile_to_user.as_ref().map(|f| f(profile));
        let mapped_email = mapped.as_ref().and_then(|m| m.get("email")).and_then(Value::as_str);
        if truthy_str(&user, "email").is_none() && mapped_email.is_none_or(str::is_empty) {
            return None;
        }
        let first = str_of(&user, "first_name").unwrap_or_default();
        let last = str_of(&user, "last_name").unwrap_or_default();
        let mut extra = Map::new();
        for key in ["first_name", "last_name", "birthday", "sex"] {
            if let Some(v) = user.get(key).filter(|v| !v.is_null()) {
                extra.insert(key.into(), v.clone());
            }
        }
        let mut info = OAuth2UserInfo {
            name: Some(format!("{first} {last}")),
            email: str_of(&user, "email"),
            image: str_of(&user, "avatar"),
            email_verified: false,
            extra,
        };
        if let Some(mapped) = mapped {
            info.apply_mapping(mapped);
        }
        Some(info)
    }
}

#[async_trait]
impl OAuthProvider for Vk {
    fn id(&self) -> &str {
        "vk"
    }
    fn name(&self) -> &str {
        "VK"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.pointer("/user/user_id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["email", "phone"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://id.vk.com/authorize".into(),
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
        validate_authorization_code(&self.options, &p, TOKEN_ENDPOINT, None).await
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
        let Some(token) = request.tokens.access_token.as_deref() else { return Ok(None) };
        let req = TokenRequest {
            body: vec![("access_token".into(), token.to_owned()), ("client_id".into(), self.options.client_id.clone())],
            headers: vec![("content-type".into(), "application/x-www-form-urlencoded".into())],
        };
        let Ok(profile) = post_form("https://id.vk.com/oauth2/user_info", &req).await else {
            return Ok(None);
        };
        let Some(user) = self.to_user(&profile) else { return Ok(None) };
        Ok(Some(UserInfoResult { user, data: profile }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::oauth2::authorization_code_request;
    use crate::social_providers::test_support::*;
    use serde_json::json;

    #[tokio::test]
    async fn authorization_url() {
        let v = Vk::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = v.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://id.vk.com/authorize");
        assert_eq!(q["scope"], "email phone");
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn code_exchange_forwards_device_id() {
        let params = ValidateCodeParams {
            code: "c".into(),
            redirect_uri: CALLBACK.into(),
            code_verifier: Some("v".into()),
            device_id: Some("dev-1".into()),
        };
        let o = ProviderOptions::new("client-123", "secret-abc");
        let req = authorization_code_request(&o, &params, TOKEN_ENDPOINT, None, &[]).unwrap();
        assert_eq!(req.get("device_id"), Some("dev-1"));
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"user": {"user_id": "vk-1", "first_name": "Ivan", "last_name": "Petrov",
            "email": "ivan@example.com", "avatar": "https://a", "sex": 2, "birthday": "01.01.1990"}});
        let v = Vk::new(ProviderOptions::new("a", "b"));
        let user = v.to_user(&profile).unwrap();
        assert_eq!(user.name.as_deref(), Some("Ivan Petrov"));
        assert_eq!(user.email.as_deref(), Some("ivan@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://a"));
        assert!(!user.email_verified);
        assert_eq!(user.extra["first_name"], "Ivan");
        assert_eq!(user.extra["sex"], 2);
        assert_eq!(user.extra["birthday"], "01.01.1990");
        assert_eq!(v.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("vk-1"));

        let no_email = json!({"user": {"user_id": "vk-2", "first_name": "A", "last_name": "B"}});
        assert!(v.to_user(&no_email).is_none());
        let mut mapped = Vk::new(ProviderOptions::new("a", "b"));
        mapped.options.map_profile_to_user =
            Some(Arc::new(|_| json!({"email": "real@example.com"}).as_object().unwrap().clone()));
        assert_eq!(mapped.to_user(&no_email).unwrap().email.as_deref(), Some("real@example.com"));
    }
}
