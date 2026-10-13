//! Dropbox (`social-providers/dropbox.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{bool_of, finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, post_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://api.dropboxapi.com/oauth2/token";

pub struct Dropbox {
    pub options: ProviderOptions,
    /// `offline`, `online` or `legacy`; sent as `token_access_type`.
    pub access_type: Option<String>,
}

impl Dropbox {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, access_type: None }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: profile.pointer("/name/display_name").and_then(Value::as_str).map(str::to_owned),
        email: str_of(profile, "email"),
        image: str_of(profile, "profile_photo_url"),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Dropbox {
    fn id(&self) -> &str {
        "dropbox"
    }
    fn name(&self) -> &str {
        "Dropbox"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("account_id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["account_info.read"]);
        scopes.extend(p.scopes);
        let mut additional = vec![];
        if let Some(access_type) = self.access_type.as_ref().filter(|a| !a.is_empty()) {
            additional.push(("token_access_type".to_owned(), access_type.clone()));
        }
        additional.extend(p.additional_params);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://www.dropbox.com/oauth2/authorize".into(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                additional_params: additional,
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
        let Ok(profile) = post_json("https://api.dropboxapi.com/2/users/get_current_account", &headers, None).await
        else {
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
        let mut d = Dropbox::new(ProviderOptions::new("client-123", "secret-abc"));
        d.access_type = Some("offline".into());
        let url = d.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://www.dropbox.com/oauth2/authorize");
        assert_eq!(q["scope"], "account_info.read");
        assert_eq!(q["token_access_type"], "offline");
        assert_eq!(q["code_challenge_method"], "S256");
        let url = d.create_authorization_url(with_additional(&[("token_access_type", "online")])).await.unwrap();
        assert_eq!(query(&url)["token_access_type"], "online");
    }

    #[test]
    fn maps_profile() {
        let profile = json!({
            "account_id": "dbid:1", "name": {"display_name": "Ada L"}, "email": "ada@example.com",
            "email_verified": true, "profile_photo_url": "https://p"
        });
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada L"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(user.email_verified);
        let d = Dropbox::new(ProviderOptions::new("a", "b"));
        assert_eq!(d.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("dbid:1"));
    }
}
