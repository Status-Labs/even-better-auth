//! Slack (Sign in with Slack, OpenID Connect) (`social-providers/slack.ts`).

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

const TOKEN_ENDPOINT: &str = "https://slack.com/api/openid.connect.token";

pub struct Slack {
    pub options: ProviderOptions,
}

impl Slack {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: Some(truthy_str(profile, "name").unwrap_or_default()),
        email: str_of(profile, "email"),
        image: truthy_str(profile, "picture").or_else(|| str_of(profile, "https://slack.com/user_image_512")),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Slack {
    fn id(&self) -> &str {
        "slack"
    }
    fn name(&self) -> &str {
        "Slack"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("https://slack.com/user_id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        // Slack appends call-time scopes before the configured ones.
        let mut scopes: Vec<String> = if self.options.disable_default_scope {
            vec![]
        } else {
            vec!["openid".into(), "profile".into(), "email".into()]
        };
        scopes.extend(p.scopes);
        scopes.extend(self.options.scope.iter().cloned());
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://slack.com/openid/connect/authorize".into(),
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
        let Ok(profile) = get_json("https://slack.com/api/openid.connect.userInfo", &headers).await else {
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
        let s = Slack::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = s.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://slack.com/openid/connect/authorize");
        assert_eq!(q["client_id"], "client-123");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["scope"], "openid profile email");
        assert_eq!(q["state"], STATE);
        assert!(!q.contains_key("code_challenge"));

        let url = s
            .create_authorization_url(with_additional(&[("team", "T01ABC"), ("client_id", "attacker")]))
            .await
            .unwrap();
        let q = query(&url);
        assert_eq!(q["team"], "T01ABC");
        assert_eq!(q["client_id"], "client-123");
    }

    #[test]
    fn maps_profile() {
        let profile = json!({
            "ok": true, "sub": "U1", "https://slack.com/user_id": "U1", "https://slack.com/team_id": "T1",
            "email": "ada@example.com", "email_verified": true, "name": "Ada", "picture": "",
            "https://slack.com/user_image_512": "https://512"
        });
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://512"));
        assert!(user.email_verified);
        let s = Slack::new(ProviderOptions::new("a", "b"));
        assert_eq!(s.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("U1"));
    }
}
