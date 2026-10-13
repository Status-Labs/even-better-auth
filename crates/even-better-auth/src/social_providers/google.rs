//! Google (`social-providers/google.ts`).

use std::sync::Arc;

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, require_client_credentials, str_of, user_info_override};
use crate::error::{Error, Result};
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, IdTokenConfig, JwksIdTokenConfig, JwksSource, OAuth2Tokens,
    OAuth2UserInfo, OAuthProvider, ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams,
    create_authorization_url, decode_jwt_payload, refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub struct Google {
    pub options: ProviderOptions,
    /// `offline` to receive a refresh token.
    pub access_type: Option<String>,
    /// `page`, `popup`, `touch` or `wap`.
    pub display: Option<String>,
    /// Required Workspace hosted domain (`"*"` for any); enforced on the `hd` claim.
    pub hd: Option<String>,
    /// Send `include_granted_scopes=true` (default `true`).
    pub include_granted_scopes: bool,
}

impl Google {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, access_type: None, display: None, hd: None, include_granted_scopes: true }
    }
}

/// Whether the token's `hd` claim satisfies the configured hosted domain.
pub fn is_hosted_domain_allowed(configured: Option<&str>, claim: Option<&Value>) -> bool {
    let Some(configured) = configured.filter(|c| !c.is_empty()) else { return true };
    match claim.and_then(Value::as_str).filter(|c| !c.is_empty()) {
        None => false,
        Some(hd) => configured == "*" || hd == configured,
    }
}

#[async_trait]
impl OAuthProvider for Google {
    fn id(&self) -> &str {
        "google"
    }
    fn name(&self) -> &str {
        "Google"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Google", &self.options, true)?;
        if p.code_verifier.is_empty() {
            return Err(Error::Config("codeVerifier is required for Google".into()));
        }
        let mut scopes = self.options.scopes_with_defaults(&["email", "profile", "openid"]);
        scopes.extend(p.scopes);
        let mut additional = vec![];
        if self.include_granted_scopes {
            additional.push(("include_granted_scopes".to_owned(), "true".to_owned()));
        }
        additional.extend(p.additional_params);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                prompt: self.options.prompt.clone(),
                access_type: self.access_type.clone(),
                display: p.display.or_else(|| self.display.clone()),
                login_hint: p.login_hint,
                hd: self.hd.clone(),
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

    fn id_token(&self) -> Option<IdTokenConfig> {
        let mut config = JwksIdTokenConfig::new(JwksSource::Url(JWKS_URL.into()), self.options.client_ids());
        config.issuer = vec!["https://accounts.google.com".into(), "accounts.google.com".into()];
        config.algorithms = vec![Algorithm::RS256];
        config.max_token_age = Some(3600);
        if let Some(hd) = self.hd.clone() {
            config.verify_claims = Some(Arc::new(move |claims| is_hosted_domain_allowed(Some(&hd), claims.get("hd"))));
        }
        Some(IdTokenConfig::Jwks(config))
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let Some(claims) = request.tokens.id_token.as_deref().and_then(decode_jwt_payload) else {
            return Ok(None);
        };
        let profile = Value::Object(claims);
        if !is_hosted_domain_allowed(self.hd.as_deref(), profile.get("hd")) {
            tracing::error!(
                "Google sign-in rejected: id token hosted domain (hd) {:?} does not satisfy the configured \"hd\" option {:?}.",
                profile.get("hd"),
                self.hd
            );
            return Ok(None);
        }
        let user = OAuth2UserInfo {
            name: str_of(&profile, "name"),
            email: str_of(&profile, "email"),
            image: str_of(&profile, "picture"),
            email_verified: profile.get("email_verified").and_then(Value::as_bool).unwrap_or(false),
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn authorization_url_defaults() {
        let mut g = Google::new(ProviderOptions::new("cid", "secret"));
        g.access_type = Some("offline".into());
        let url = g
            .create_authorization_url(AuthorizationUrlParams {
                state: "s".into(),
                code_verifier: "v".into(),
                redirect_uri: "http://localhost/cb".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(q["scope"], "email profile openid");
        assert_eq!(q["access_type"], "offline");
        assert_eq!(q["include_granted_scopes"], "true");
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn hosted_domain() {
        assert!(is_hosted_domain_allowed(None, None));
        assert!(!is_hosted_domain_allowed(Some("a.com"), None));
        assert!(is_hosted_domain_allowed(Some("*"), Some(&json!("b.com"))));
        assert!(!is_hosted_domain_allowed(Some("a.com"), Some(&json!("b.com"))));
    }
}
