//! Notion (`social-providers/notion.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://api.notion.com/v1/oauth/token";

pub struct Notion {
    pub options: ProviderOptions,
}

impl Notion {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

/// The bot owner's user object; it is also the profile passed to `map_profile_to_user`.
fn profile_from_response(data: &Value) -> Option<Value> {
    data.pointer("/bot/owner/user").filter(|u| u.is_object()).cloned()
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: Some(truthy_str(profile, "name").unwrap_or_default()),
        email: profile.get("person").and_then(|p| truthy_str(p, "email")),
        image: str_of(profile, "avatar_url"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Notion {
    fn id(&self) -> &str {
        "notion"
    }
    fn name(&self) -> &str {
        "Notion"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        // Notion has no default scopes.
        let mut scopes = self.options.scopes_with_defaults(&[]);
        scopes.extend(p.scopes);
        let mut additional = p.additional_params;
        additional.push(("owner".to_owned(), "user".to_owned()));
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://api.notion.com/v1/oauth/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                login_hint: p.login_hint,
                additional_params: additional,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { code_verifier: None, device_id: None, ..p };
        validate_authorization_code(&self.options, &params, TOKEN_ENDPOINT, Some(ClientAuthentication::Basic)).await
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
        let headers = [bearer(request.tokens.access_token.as_deref()), ("notion-version", "2022-06-28".to_owned())];
        let Ok(data) = get_json("https://api.notion.com/v1/users/me", &headers).await else {
            return Ok(None);
        };
        let Some(profile) = profile_from_response(&data) else { return Ok(None) };
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
        let n = Notion::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = n.create_authorization_url(with_additional(&[("owner", "workspace")])).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://api.notion.com/v1/oauth/authorize");
        assert_eq!(q["owner"], "user");
        assert!(!q.contains_key("scope"));
        assert!(!q.contains_key("code_challenge"));
    }

    #[test]
    fn maps_profile() {
        let data = json!({"object": "user", "type": "bot", "bot": {"owner": {"type": "user", "user": {
            "object": "user", "id": "n-1", "type": "person", "name": "Ada", "avatar_url": "https://a",
            "person": {"email": "ada@example.com"}
        }}}});
        let profile = profile_from_response(&data).unwrap();
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://a"));
        assert!(!user.email_verified);
        let n = Notion::new(ProviderOptions::new("a", "b"));
        assert_eq!(n.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("n-1"));
        assert_eq!(to_user(&json!({"id": "x", "person": {"email": ""}})).email, None);
        assert!(profile_from_response(&json!({"bot": {}})).is_none());
    }
}
