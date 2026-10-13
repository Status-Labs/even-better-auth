//! Twitch (`social-providers/twitch.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{bool_of, finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, create_authorization_url, decode_jwt_payload,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://id.twitch.tv/oauth2/token";
const DEFAULT_CLAIMS: &[&str] = &["email", "email_verified", "preferred_username", "picture"];

pub struct Twitch {
    pub options: ProviderOptions,
    /// ID-token claims to request; defaults to email, email_verified, preferred_username and picture.
    pub claims: Option<Vec<String>>,
}

impl Twitch {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, claims: None }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: str_of(profile, "preferred_username"),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Twitch {
    fn id(&self) -> &str {
        "twitch"
    }
    fn name(&self) -> &str {
        "Twitch"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["user:read:email", "openid"]);
        scopes.extend(p.scopes);
        let claims = self.claims.clone().unwrap_or_else(|| DEFAULT_CLAIMS.iter().map(|c| c.to_string()).collect());
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://id.twitch.tv/oauth2/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                claims: Some(claims),
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
        let Some(id_token) = request.tokens.id_token.as_deref() else {
            tracing::error!("No idToken found in token");
            return Ok(None);
        };
        let Some(claims) = decode_jwt_payload(id_token) else { return Ok(None) };
        let profile = Value::Object(claims);
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
    async fn authorization_url_requests_claims() {
        let t = Twitch::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = t.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://id.twitch.tv/oauth2/authorize");
        assert_eq!(q["scope"], "user:read:email openid");
        assert!(!q.contains_key("code_challenge"));
        let claims: Value = serde_json::from_str(&q["claims"]).unwrap();
        assert_eq!(
            claims,
            json!({"id_token": {"email": null, "email_verified": null, "preferred_username": null, "picture": null}})
        );
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"sub": "tw-1", "preferred_username": "ada", "email": "ada@example.com",
            "email_verified": true, "picture": "https://p"});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(user.email_verified);
        let t = Twitch::new(ProviderOptions::new("a", "b"));
        assert_eq!(t.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("tw-1"));
    }
}
