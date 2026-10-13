//! Salesforce (`social-providers/salesforce.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{
    bool_of, finish, refresh_override, require_client_credentials, require_code_verifier, str_of, truthy_str,
    user_info_override,
};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

/// The Salesforce login environment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SalesforceEnvironment {
    #[default]
    Production,
    Sandbox,
}

/// Salesforce. Set `options.redirect_uri` when the callback URL auto-detection does not
/// match the Connected App's configured callback.
pub struct Salesforce {
    pub options: ProviderOptions,
    /// Default [`SalesforceEnvironment::Production`].
    pub environment: SalesforceEnvironment,
    /// A custom (My Domain) login host, e.g. `acme.my.salesforce.com`; overrides `environment`.
    pub login_url: Option<String>,
}

impl Salesforce {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, environment: SalesforceEnvironment::Production, login_url: None }
    }

    fn endpoint(&self, path: &str) -> String {
        let host = match self.login_url.as_deref().filter(|l| !l.is_empty()) {
            Some(login_url) => login_url,
            None if self.environment == SalesforceEnvironment::Sandbox => "test.salesforce.com",
            None => "login.salesforce.com",
        };
        format!("https://{host}/services/oauth2/{path}")
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    let photos = profile.get("photos").cloned().unwrap_or(Value::Null);
    OAuth2UserInfo {
        name: str_of(profile, "name"),
        email: str_of(profile, "email"),
        image: truthy_str(&photos, "picture").or_else(|| str_of(&photos, "thumbnail")),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Salesforce {
    fn id(&self) -> &str {
        "salesforce"
    }
    fn name(&self) -> &str {
        "Salesforce"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("user_id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Salesforce", &self.options, true)?;
        require_code_verifier("Salesforce", &p.code_verifier)?;
        let mut scopes = self.options.scopes_with_defaults(&["openid", "email", "profile"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: self.endpoint("authorize"),
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
        validate_authorization_code(&self.options, &params, &self.endpoint("token"), None).await
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        refresh_access_token(&self.options, refresh_token, &self.endpoint("token"), None, &[]).await
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let headers = [bearer(request.tokens.access_token.as_deref())];
        let profile = match get_json(&self.endpoint("userinfo"), &headers).await {
            Ok(profile) => profile,
            Err(e) => {
                tracing::error!(error = %e, "Failed to fetch user info from Salesforce");
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
    async fn authorization_url_and_environments() {
        let s = Salesforce::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = s.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://login.salesforce.com/services/oauth2/authorize");
        assert_eq!(q["scope"], "openid email profile");
        assert_eq!(q["code_challenge_method"], "S256");

        let mut sandbox = Salesforce::new(ProviderOptions::new("c", "s"));
        sandbox.environment = SalesforceEnvironment::Sandbox;
        assert_eq!(sandbox.endpoint("token"), "https://test.salesforce.com/services/oauth2/token");
        sandbox.login_url = Some("acme.my.salesforce.com".into());
        assert_eq!(sandbox.endpoint("userinfo"), "https://acme.my.salesforce.com/services/oauth2/userinfo");

        let mut o = ProviderOptions::new("c", "s");
        o.redirect_uri = Some("http://localhost:3000/api/auth/callback/salesforce".into());
        let url = Salesforce::new(o).create_authorization_url(params()).await.unwrap();
        assert_eq!(query(&url)["redirect_uri"], "http://localhost:3000/api/auth/callback/salesforce");
    }

    #[test]
    fn maps_profile() {
        let profile = json!({
            "sub": "https://login.salesforce.com/id/00D/005", "user_id": "005", "organization_id": "00D",
            "email": "ada@example.com", "email_verified": true, "name": "Ada",
            "photos": {"picture": "", "thumbnail": "https://t"}
        });
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://t"));
        assert!(user.email_verified);
        let s = Salesforce::new(ProviderOptions::new("a", "b"));
        assert_eq!(s.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("005"));
    }
}
