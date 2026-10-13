//! Linear (`social-providers/linear.ts`).

use async_trait::async_trait;
use serde_json::{Value, json};
use url::Url;

use super::{finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, post_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://api.linear.app/oauth/token";
const VIEWER_QUERY: &str = "query { viewer { id name email avatarUrl active createdAt updatedAt } }";

pub struct Linear {
    pub options: ProviderOptions,
}

impl Linear {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

/// The `viewer` of the GraphQL response; it is also the profile passed to `map_profile_to_user`.
fn profile_from_response(data: &Value) -> Option<Value> {
    data.pointer("/data/viewer").filter(|v| v.is_object()).cloned()
}

fn to_user(viewer: &Value) -> OAuth2UserInfo {
    // Linear does not provide an email_verified claim.
    OAuth2UserInfo {
        name: str_of(viewer, "name"),
        email: str_of(viewer, "email"),
        image: str_of(viewer, "avatarUrl"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Linear {
    fn id(&self) -> &str {
        "linear"
    }
    fn name(&self) -> &str {
        "Linear"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["read"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://linear.app/oauth/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                login_hint: p.login_hint,
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
        let body = json!({ "query": VIEWER_QUERY });
        let Ok(data) = post_json("https://api.linear.app/graphql", &headers, Some(&body)).await else {
            return Ok(None);
        };
        let Some(viewer) = profile_from_response(&data) else { return Ok(None) };
        let user = to_user(&viewer);
        Ok(finish(&self.options, viewer, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::social_providers::test_support::*;

    #[tokio::test]
    async fn authorization_url() {
        let l = Linear::new(ProviderOptions::new("client-123", "secret-abc"));
        let mut p = params();
        p.login_hint = Some("ada@example.com".into());
        let url = l.create_authorization_url(p).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://linear.app/oauth/authorize");
        assert_eq!(q["scope"], "read");
        assert_eq!(q["login_hint"], "ada@example.com");
        assert!(!q.contains_key("code_challenge"));
    }

    #[test]
    fn maps_profile() {
        let data = json!({"data": {"viewer": {
            "id": "lin-1", "name": "Ada", "email": "ada@example.com", "avatarUrl": "https://a", "active": true
        }}});
        let viewer = profile_from_response(&data).unwrap();
        let user = to_user(&viewer);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://a"));
        assert!(!user.email_verified);
        let l = Linear::new(ProviderOptions::new("a", "b"));
        assert_eq!(l.account_subject(&viewer, &OAuth2Tokens::default()).as_deref(), Some("lin-1"));
        assert!(profile_from_response(&json!({"data": null})).is_none());
    }
}
