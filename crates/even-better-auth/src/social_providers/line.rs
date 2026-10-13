//! LINE Login v2.1 (`social-providers/line.ts`).
//!
//! Docs: <https://developers.line.biz/en/reference/line-login/#issue-access-token>

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, IdTokenConfig, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, TokenRequest, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer,
    create_authorization_url, decode_jwt_payload, get_json, post_form, refresh_access_token, subject_from,
    validate_authorization_code,
};

const AUTHORIZATION_ENDPOINT: &str = "https://access.line.me/oauth2/v2.1/authorize";
const TOKEN_ENDPOINT: &str = "https://api.line.me/oauth2/v2.1/token";
const USERINFO_ENDPOINT: &str = "https://api.line.me/oauth2/v2.1/userinfo";
const VERIFY_ID_TOKEN_ENDPOINT: &str = "https://api.line.me/oauth2/v2.1/verify";

pub struct Line {
    pub options: ProviderOptions,
}

impl Line {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

/// Check a `/verify` response: `aud` must be the client id and a returned `nonce` must match.
fn verify_response_ok(data: &Value, client_id: &str, nonce: Option<&str>) -> bool {
    if data.get("aud").and_then(Value::as_str) != Some(client_id) {
        return false;
    }
    match truthy_str(data, "nonce") {
        Some(n) => Some(n.as_str()) == nonce,
        None => true,
    }
}

/// Verify an ID token with LINE's remote verification endpoint.
async fn verify_id_token(client_id: &str, token: &str, nonce: Option<&str>) -> bool {
    let mut body = vec![("id_token".to_owned(), token.to_owned()), ("client_id".to_owned(), client_id.to_owned())];
    if let Some(n) = nonce.filter(|n| !n.is_empty()) {
        body.push(("nonce".to_owned(), n.to_owned()));
    }
    let req = TokenRequest { body, headers: vec![("content-type".into(), "application/x-www-form-urlencoded".into())] };
    match post_form(VERIFY_ID_TOKEN_ENDPOINT, &req).await {
        Ok(data) => verify_response_ok(&data, client_id, nonce),
        Err(_) => false,
    }
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    // LINE does not expose email verification status.
    OAuth2UserInfo {
        name: Some(truthy_str(profile, "name").unwrap_or_default()),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Line {
    fn id(&self) -> &str {
        "line"
    }
    fn name(&self) -> &str {
        "LINE"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["openid", "profile", "email"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: AUTHORIZATION_ENDPOINT.into(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                login_hint: p.login_hint,
                additional_params: p.additional_params,
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

    fn id_token(&self) -> Option<IdTokenConfig> {
        let client_id = self.options.client_id.clone();
        Some(IdTokenConfig::Custom(Arc::new(move |token, nonce| {
            let client_id = client_id.clone();
            Box::pin(async move { verify_id_token(&client_id, &token, nonce.as_deref()).await })
        })))
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        // Prefer the ID token; fall back to the UserInfo endpoint.
        let mut profile = request.tokens.id_token.as_deref().and_then(decode_jwt_payload).map(Value::Object);
        if profile.is_none() {
            let headers = [bearer(request.tokens.access_token.as_deref())];
            profile = get_json(USERINFO_ENDPOINT, &headers).await.ok().filter(|p| p.is_object());
        }
        let Some(profile) = profile else { return Ok(None) };
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
        let l = Line::new(ProviderOptions::new("client-123", "secret-abc"));
        let url = l.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), AUTHORIZATION_ENDPOINT);
        assert_eq!(q["scope"], "openid profile email");
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn verify_response() {
        assert!(verify_response_ok(&json!({"aud": "cid"}), "cid", None));
        assert!(verify_response_ok(&json!({"aud": "cid", "nonce": "n"}), "cid", Some("n")));
        assert!(!verify_response_ok(&json!({"aud": "cid", "nonce": "n"}), "cid", Some("x")));
        assert!(!verify_response_ok(&json!({"aud": "cid", "nonce": "n"}), "cid", None));
        assert!(!verify_response_ok(&json!({"aud": "other"}), "cid", None));
    }

    #[test]
    fn maps_profile() {
        let profile = json!({"sub": "U123", "name": "Ada", "picture": "https://p", "email": "ada@example.com"});
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://p"));
        assert!(!user.email_verified);
        let l = Line::new(ProviderOptions::new("a", "b"));
        assert_eq!(l.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("U123"));
        assert_eq!(to_user(&json!({"sub": "U1"})).name.as_deref(), Some(""));
    }
}
