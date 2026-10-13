//! Twitter / X (`social-providers/twitter.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{create_placeholder_email, finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://api.x.com/2/oauth2/token";

pub struct Twitter {
    pub options: ProviderOptions,
}

impl Twitter {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl OAuthProvider for Twitter {
    fn id(&self) -> &str {
        "twitter"
    }
    fn name(&self) -> &str {
        "Twitter"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.pointer("/data/id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes =
            self.options.scopes_with_defaults(&["users.read", "tweet.read", "offline.access", "users.email"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://x.com/i/oauth2/authorize".into(),
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
        let Ok(mut profile) = get_json("https://api.x.com/2/users/me?user.fields=profile_image_url", &headers).await
        else {
            return Ok(None);
        };
        let confirmed = get_json("https://api.x.com/2/users/me?user.fields=confirmed_email", &headers)
            .await
            .ok()
            .and_then(|d| d.pointer("/data/confirmed_email").and_then(Value::as_str).map(str::to_owned))
            .filter(|e| !e.is_empty());
        let email_verified = confirmed.is_some();
        if let (Some(email), Some(data)) = (&confirmed, profile.get_mut("data").and_then(Value::as_object_mut)) {
            data.insert("email".into(), email.clone().into());
        }
        let data = profile.get("data").cloned().unwrap_or(Value::Null);
        let id = str_of(&data, "id").unwrap_or_default();
        let user = OAuth2UserInfo {
            name: str_of(&data, "name"),
            email: Some(
                str_of(&data, "email")
                    .filter(|e| !e.is_empty())
                    .unwrap_or_else(|| create_placeholder_email(&id, "twitter")),
            ),
            image: str_of(&data, "profile_image_url"),
            email_verified,
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }
}
