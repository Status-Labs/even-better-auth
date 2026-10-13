//! PayPal (`social-providers/paypal.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{bool_of, finish, refresh_override, require_client_credentials, str_of, user_info_override};
use crate::error::{Error, Result};
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url,
    decode_jwt_payload, get_json, refresh_access_token, subject_from, validate_authorization_code,
};

/// The PayPal environment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PayPalEnvironment {
    #[default]
    Sandbox,
    Live,
}

/// Log in with PayPal. Permissions are configured in the PayPal Developer Dashboard rather
/// than through OAuth scopes, so no `scope` is sent. (The TS `requestShippingAddress` option
/// is accepted there but unused, so it is not ported.)
pub struct PayPal {
    pub options: ProviderOptions,
    /// Default [`PayPalEnvironment::Sandbox`].
    pub environment: PayPalEnvironment,
}

impl PayPal {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, environment: PayPalEnvironment::Sandbox }
    }

    fn sandbox(&self) -> bool {
        self.environment == PayPalEnvironment::Sandbox
    }

    fn authorization_endpoint(&self) -> &'static str {
        if self.sandbox() {
            "https://www.sandbox.paypal.com/signin/authorize"
        } else {
            "https://www.paypal.com/signin/authorize"
        }
    }

    fn token_endpoint(&self) -> &'static str {
        if self.sandbox() {
            "https://api-m.sandbox.paypal.com/v1/oauth2/token"
        } else {
            "https://api-m.paypal.com/v1/oauth2/token"
        }
    }

    fn userinfo_endpoint(&self) -> &'static str {
        if self.sandbox() {
            "https://api-m.sandbox.paypal.com/v1/identity/oauth2/userinfo"
        } else {
            "https://api-m.paypal.com/v1/identity/oauth2/userinfo"
        }
    }

    /// Token requests carry only the client credentials (and redirect URI override).
    fn token_options(&self) -> ProviderOptions {
        let mut o = ProviderOptions::new(self.options.client_id.clone(), self.options.client_secret.clone());
        o.redirect_uri = self.options.redirect_uri.clone();
        o
    }
}

/// OIDC binds UserInfo to the ID token by `sub`: the profile's `sub` (else `user_id`) must
/// equal the ID token subject. Without an ID token there is nothing to bind.
fn subject_matches_id_token(user_info: &Value, id_token: Option<&str>) -> bool {
    let Some(id_token) = id_token else { return true };
    let Some(claims) = decode_jwt_payload(id_token) else {
        tracing::error!("Failed to decode PayPal ID token");
        return false;
    };
    let id_subject = claims.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty());
    let subject = match user_info.get("sub").filter(|s| !s.is_null()) {
        Some(sub) => sub.as_str(),
        None => user_info.get("user_id").and_then(Value::as_str),
    };
    id_subject.is_some() && subject == id_subject
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: str_of(profile, "name"),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: bool_of(profile, "email_verified"),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for PayPal {
    fn id(&self) -> &str {
        "paypal"
    }
    fn name(&self) -> &str {
        "PayPal"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("user_id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("PayPal", &self.options, true)?;
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: self.authorization_endpoint().into(),
                scopes: vec![],
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                prompt: self.options.prompt.clone(),
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        validate_authorization_code(
            &self.token_options(),
            &params,
            self.token_endpoint(),
            Some(ClientAuthentication::Basic),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "PayPal token exchange failed");
            Error::Other("FAILED_TO_GET_ACCESS_TOKEN".into())
        })
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        let auth = Some(ClientAuthentication::Basic);
        refresh_access_token(&self.token_options(), refresh_token, self.token_endpoint(), auth, &[]).await.map_err(
            |e| {
                tracing::error!(error = %e, "PayPal token refresh failed");
                Error::Other("FAILED_TO_REFRESH_ACCESS_TOKEN".into())
            },
        )
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let Some(token) = request.tokens.access_token.as_deref() else {
            tracing::error!("Access token is required to fetch PayPal user info");
            return Ok(None);
        };
        let url = format!("{}?schema=paypalv1.1", self.userinfo_endpoint());
        let profile = match get_json(&url, &[bearer(Some(token))]).await {
            Ok(profile) => profile,
            Err(e) => {
                tracing::error!(error = %e, "Failed to fetch user info from PayPal");
                return Ok(None);
            }
        };
        if !subject_matches_id_token(&profile, request.tokens.id_token.as_deref()) {
            tracing::error!("PayPal user info subject does not match ID token subject");
            return Ok(None);
        }
        let user = to_user(&profile);
        Ok(finish(&self.options, profile, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::{authorization_code_request, encode_basic_credentials, refresh_access_token_request};
    use crate::social_providers::test_support::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    fn live() -> PayPal {
        let mut p = PayPal::new(ProviderOptions::new("paypal-client-id", "paypal-client-secret"));
        p.environment = PayPalEnvironment::Live;
        p
    }

    fn id_token(sub: &str) -> String {
        encode(&Header::default(), &json!({ "sub": sub }), &EncodingKey::from_secret(b"test-secret")).unwrap()
    }

    #[tokio::test]
    async fn authorization_url_has_no_scope() {
        let url = PayPal::new(ProviderOptions::new("c", "s")).create_authorization_url(params()).await.unwrap();
        assert_eq!(endpoint(&url), "https://www.sandbox.paypal.com/signin/authorize");
        assert!(!query(&url).contains_key("scope"));
        let url = live().create_authorization_url(params()).await.unwrap();
        assert_eq!(endpoint(&url), "https://www.paypal.com/signin/authorize");
        assert!(PayPal::new(ProviderOptions::new("c", "")).create_authorization_url(params()).await.is_err());
    }

    #[test]
    fn token_requests_use_basic_auth() {
        let p = live();
        assert_eq!(p.token_endpoint(), "https://api-m.paypal.com/v1/oauth2/token");
        let params = ValidateCodeParams {
            code: "authorization-code".into(),
            code_verifier: Some("code-verifier".into()),
            redirect_uri: "https://app.example.com/api/auth/callback/paypal".into(),
            device_id: None,
        };
        let auth = Some(ClientAuthentication::Basic);
        let req =
            authorization_code_request(&p.token_options(), &params, p.token_endpoint(), auth.clone(), &[]).unwrap();
        let basic = encode_basic_credentials("paypal-client-id", "paypal-client-secret");
        assert_eq!(req.header("authorization"), Some(basic.as_str()));
        assert_eq!(req.header("accept"), Some("application/json"));
        let mut body = req.body.clone();
        body.sort();
        assert_eq!(
            body,
            vec![
                ("code".to_owned(), "authorization-code".to_owned()),
                ("code_verifier".into(), "code-verifier".into()),
                ("grant_type".into(), "authorization_code".into()),
                ("redirect_uri".into(), "https://app.example.com/api/auth/callback/paypal".into()),
            ]
        );
        let req =
            refresh_access_token_request(&p.token_options(), "refresh-token", p.token_endpoint(), auth, &[]).unwrap();
        assert_eq!(req.header("authorization"), Some(basic.as_str()));
        assert_eq!(req.body.len(), 2);
    }

    #[test]
    fn binds_user_info_to_id_token_subject() {
        let profile = json!({"user_id": "paypal-user-123", "name": "PayPal User", "email": "paypal-user@example.com",
            "email_verified": true, "picture": "https://example.com/avatar.png"});
        assert!(subject_matches_id_token(&profile, None));
        assert!(subject_matches_id_token(&profile, Some(&id_token("paypal-user-123"))));
        assert!(!subject_matches_id_token(&profile, Some(&id_token("paypal-user-456"))));
        assert!(!subject_matches_id_token(&profile, Some("not-a-jwt")));

        let mut with_sub = profile.clone();
        with_sub["sub"] = "paypal-subject-123".into();
        assert!(subject_matches_id_token(&with_sub, Some(&id_token("paypal-subject-123"))));
        assert!(!subject_matches_id_token(&with_sub, Some(&id_token("paypal-user-123"))));
        assert_eq!(live().account_subject(&with_sub, &OAuth2Tokens::default()).as_deref(), Some("paypal-user-123"));

        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("PayPal User"));
        assert_eq!(user.email.as_deref(), Some("paypal-user@example.com"));
        assert_eq!(user.image.as_deref(), Some("https://example.com/avatar.png"));
        assert!(user.email_verified);
    }
}
