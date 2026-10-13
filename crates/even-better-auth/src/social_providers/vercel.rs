//! Vercel (`social-providers/vercel.ts`). Vercel has no default scopes and issues no
//! refresh tokens.

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{bool_of, finish, require_code_verifier, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json, subject_from,
    validate_authorization_code,
};

pub struct Vercel {
    pub options: ProviderOptions,
}

impl Vercel {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: Some(str_of(profile, "name").or_else(|| str_of(profile, "preferred_username")).unwrap_or_default()),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Vercel {
    fn id(&self) -> &str {
        "vercel"
    }
    fn name(&self) -> &str {
        "Vercel"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_code_verifier("Vercel", &p.code_verifier)?;
        let mut scopes = self.options.scope.clone();
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://vercel.com/oauth/authorize".into(),
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
        validate_authorization_code(&self.options, &params, "https://api.vercel.com/login/oauth/token", None).await
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let headers = [bearer(request.tokens.access_token.as_deref())];
        let Ok(profile) = get_json("https://api.vercel.com/login/oauth/userinfo", &headers).await else {
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
        let v = Vercel::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = v.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://vercel.com/oauth/authorize");
        assert!(!q.contains_key("scope"));
        assert_eq!(q["code_challenge_method"], "S256");
        let mut p = params();
        p.scopes = vec!["openid".into(), "email".into()];
        assert_eq!(query(&v.create_authorization_url(p).await.unwrap())["scope"], "openid email");
        let mut missing = params();
        missing.code_verifier.clear();
        assert!(v.create_authorization_url(missing).await.is_err());
        assert!(!v.supports_refresh());
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"sub": "vc-1", "preferred_username": "ada", "email": "ada@example.com",
            "email_verified": true, "picture": "https://p"});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(user.email_verified);
        let v = Vercel::new(ProviderOptions::new("a", "b"));
        assert_eq!(v.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("vc-1"));
    }
}
