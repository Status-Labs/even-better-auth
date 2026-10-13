//! Atlassian (`social-providers/atlassian.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, require_client_credentials, require_code_verifier, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://auth.atlassian.com/oauth/token";

pub struct Atlassian {
    pub options: ProviderOptions,
}

impl Atlassian {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: str_of(profile, "name"),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Atlassian {
    fn id(&self) -> &str {
        "atlassian"
    }
    fn name(&self) -> &str {
        "Atlassian"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("account_id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Atlassian", &self.options, true)?;
        require_code_verifier("Atlassian", &p.code_verifier)?;
        let mut scopes = self.options.scopes_with_defaults(&["read:jira-user", "offline_access"]);
        scopes.extend(p.scopes);
        let mut additional = p.additional_params;
        additional.push(("audience".to_owned(), "api.atlassian.com".to_owned()));
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://auth.atlassian.com/authorize".into(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                prompt: self.options.prompt.clone(),
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
        let Some(token) = request.tokens.access_token.as_deref() else { return Ok(None) };
        let profile = match get_json("https://api.atlassian.com/me", &[bearer(Some(token))]).await {
            Ok(profile) => profile,
            Err(e) => {
                tracing::error!(error = %e, "Failed to fetch user info from Atlassian");
                return Ok(None);
            }
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
        let p = Atlassian::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = p.create_authorization_url(with_additional(&[("audience", "evil"), ("x", "y")])).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://auth.atlassian.com/authorize");
        assert_eq!(q["scope"], "read:jira-user offline_access");
        assert_eq!(q["audience"], "api.atlassian.com");
        assert_eq!(q["x"], "y");
        assert_eq!(q["code_challenge_method"], "S256");
        let mut missing = params();
        missing.code_verifier.clear();
        assert!(p.create_authorization_url(missing).await.is_err());
        let no_secret = Atlassian::new(ProviderOptions::new("client-123", ""));
        assert!(no_secret.create_authorization_url(params()).await.is_err());
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"account_id": "acc-1", "name": "Ada", "email": "ada@example.com", "picture": "https://p"});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(!user.email_verified);
        let p = Atlassian::new(ProviderOptions::new("a", "b"));
        assert_eq!(p.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("acc-1"));
    }
}
