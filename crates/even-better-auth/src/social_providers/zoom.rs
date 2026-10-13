//! Zoom (`social-providers/zoom.ts`). Scopes are configured on the Zoom app, so none are sent.

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://zoom.us/oauth/token";

pub struct Zoom {
    pub options: ProviderOptions,
    /// Send a PKCE challenge (default `true`).
    pub pkce: bool,
}

impl Zoom {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, pkce: true }
    }
}

/// JS `Boolean(value)` for the numeric `verified` field.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
        _ => false,
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: str_of(profile, "display_name"),
        email: str_of(profile, "email"),
        image: str_of(profile, "pic_url"),
        email_verified: truthy(profile.get("verified")),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Zoom {
    fn id(&self) -> &str {
        "zoom"
    }
    fn name(&self) -> &str {
        "Zoom"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://zoom.us/oauth/authorize".into(),
                state: p.state,
                code_verifier: self.pkce.then_some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
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
        let Ok(profile) = get_json("https://api.zoom.us/v2/users/me", &headers).await else {
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
        let mut z = Zoom::new(ProviderOptions::new("client-123", "secret-abc"));
        z.pkce = false;
        let url = z.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://zoom.us/oauth/authorize");
        assert_eq!(q["client_id"], "client-123");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["redirect_uri"], CALLBACK);
        assert!(!q.contains_key("scope"));
        assert!(!q.contains_key("code_challenge"));

        let url = z
            .create_authorization_url(with_additional(&[("custom", "value"), ("redirect_uri", "https://attacker")]))
            .await
            .unwrap();
        let q = query(&url);
        assert_eq!(q["custom"], "value");
        assert_eq!(q["redirect_uri"], CALLBACK);

        let url = Zoom::new(ProviderOptions::new("client-123", "s")).create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(q.contains_key("code_challenge"));
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"id": "zJKyaiAyTNC-MWjiWC18KQ", "display_name": "Jill Chill", "email": "jchill@example.com",
            "pic_url": "https://example.com/pic", "verified": 1});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Jill Chill"));
        assert_eq!(user.email.as_deref(), Some("jchill@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://example.com/pic"));
        assert!(user.email_verified);
        assert!(!to_user(&json!({"id": "x", "verified": 0})).email_verified);
        let z = Zoom::new(ProviderOptions::new("a", "b"));
        assert_eq!(z.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("zJKyaiAyTNC-MWjiWC18KQ"));
    }
}
