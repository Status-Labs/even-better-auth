//! Amazon Cognito (`social-providers/cognito.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::{Error, Result};
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, IdTokenConfig, JwksIdTokenConfig, JwksSource, OAuth2Tokens,
    OAuth2UserInfo, OAuthProvider, ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer,
    create_authorization_url, decode_jwt_payload, get_json, refresh_access_token, subject_from,
    validate_authorization_code,
};
use crate::utils::url::encode_uri_component;

pub struct Cognito {
    pub options: ProviderOptions,
    /// AWS region of the user pool (e.g. `us-east-1`).
    pub region: String,
    pub user_pool_id: String,
    /// Reject authorization requests when no client secret is configured.
    pub require_client_secret: bool,
    /// Preselect a hosted-UI identity provider (`identity_provider`): `COGNITO`, a SAML/OIDC
    /// provider name, or `Google` / `Facebook` / `LoginWithAmazon` / `SignInWithApple`.
    /// Call-time `additional_params` take precedence.
    pub identity_provider: Option<String>,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

impl Cognito {
    /// `domain` is the hosted-UI domain (e.g. `your-app.auth.us-east-1.amazoncognito.com`),
    /// with or without a scheme. Domain, region and user pool id are required.
    pub fn new(
        options: ProviderOptions,
        domain: impl Into<String>,
        region: impl Into<String>,
        user_pool_id: impl Into<String>,
    ) -> Result<Self> {
        let (domain, region, user_pool_id) = (domain.into(), region.into(), user_pool_id.into());
        if domain.is_empty() || region.is_empty() || user_pool_id.is_empty() {
            tracing::error!(
                "Domain, region and userPoolId are required for Amazon Cognito. Make sure to provide them in the options."
            );
            return Err(Error::Config("DOMAIN_AND_REGION_REQUIRED".into()));
        }
        let clean = domain.strip_prefix("https://").or_else(|| domain.strip_prefix("http://")).unwrap_or(&domain);
        Ok(Self {
            options,
            region,
            user_pool_id,
            require_client_secret: false,
            identity_provider: None,
            authorization_endpoint: format!("https://{clean}/oauth2/authorize"),
            token_endpoint: format!("https://{clean}/oauth2/token"),
            userinfo_endpoint: format!("https://{clean}/oauth2/userinfo"),
        })
    }

    fn issuer_url(&self) -> String {
        format!("https://cognito-idp.{}.amazonaws.com/{}", self.region, self.user_pool_id)
    }
}

/// Cognito requires the scope to be encoded with `%20` rather than `+`; move it to the end
/// of the query, encoded like `encodeURIComponent`.
fn reencode_scope(mut url: Url) -> Url {
    let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let Some(scope) = pairs.iter().find(|(k, _)| k == "scope").map(|(_, v)| v.clone()) else { return url };
    let rest = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().filter(|(k, _)| k != "scope"))
        .finish();
    let scope = format!("scope={}", encode_uri_component(&scope));
    let query = if rest.is_empty() { scope } else { format!("{rest}&{scope}") };
    url.set_query(Some(&query));
    url
}

fn email_verified(profile: &Value) -> bool {
    match profile.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

fn display_name(profile: &Value) -> String {
    truthy_str(profile, "name")
        .or_else(|| truthy_str(profile, "given_name"))
        .or_else(|| truthy_str(profile, "username"))
        .unwrap_or_default()
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    OAuth2UserInfo {
        name: Some(display_name(profile)),
        email: str_of(profile, "email"),
        image: str_of(profile, "picture"),
        email_verified: email_verified(profile),
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for Cognito {
    fn id(&self) -> &str {
        "cognito"
    }
    fn name(&self) -> &str {
        "Cognito"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        if self.options.client_id.is_empty() {
            tracing::error!("ClientId is required for Amazon Cognito. Make sure to provide them in the options.");
            return Err(Error::Config("CLIENT_ID_AND_SECRET_REQUIRED".into()));
        }
        if self.require_client_secret && self.options.client_secret.is_empty() {
            tracing::error!(
                "Client Secret is required when requireClientSecret is true. Make sure to provide it in the options."
            );
            return Err(Error::Config("CLIENT_SECRET_REQUIRED".into()));
        }
        let mut scopes = self.options.scopes_with_defaults(&["openid", "profile", "email"]);
        scopes.extend(p.scopes);
        let mut additional = vec![];
        if let Some(idp) = self.identity_provider.as_ref().filter(|i| !i.is_empty()) {
            additional.push(("identity_provider".to_owned(), idp.clone()));
        }
        additional.extend(p.additional_params);
        let url = create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: self.authorization_endpoint.clone(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                prompt: self.options.prompt.clone(),
                additional_params: additional,
                ..Default::default()
            },
        )?;
        Ok(reencode_scope(url))
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        validate_authorization_code(&self.options, &params, &self.token_endpoint, None).await
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        refresh_access_token(&self.options, refresh_token, &self.token_endpoint, None, &[]).await
    }

    fn id_token(&self) -> Option<IdTokenConfig> {
        let issuer = self.issuer_url();
        let jwks = JwksSource::Url(format!("{issuer}/.well-known/jwks.json"));
        let mut config = JwksIdTokenConfig::new(jwks, self.options.client_ids());
        config.issuer = vec![issuer];
        config.max_token_age = Some(3600);
        Some(IdTokenConfig::Jwks(config))
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        if let Some(id_token) = request.tokens.id_token.as_deref() {
            match decode_jwt_payload(id_token) {
                Some(claims) => {
                    let mut profile = Value::Object(claims);
                    profile["name"] = display_name(&profile).into();
                    let user = to_user(&profile);
                    return Ok(finish(&self.options, profile, user));
                }
                None => tracing::error!("Failed to decode ID token"),
            }
        }
        if let Some(token) = request.tokens.access_token.as_deref() {
            match get_json(&self.userinfo_endpoint, &[bearer(Some(token))]).await {
                Ok(profile) => {
                    let user = to_user(&profile);
                    return Ok(finish(&self.options, profile, user));
                }
                Err(e) => tracing::error!(error = %e, "Failed to fetch user info from Cognito"),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::social_providers::test_support::*;
    use serde_json::json;

    fn cognito() -> Cognito {
        Cognito::new(
            ProviderOptions::new("client-123", "secret-abc"),
            "https://test.auth.us-east-1.amazoncognito.com",
            "us-east-1",
            "us-east-1_pool",
        )
        .unwrap()
    }

    #[test]
    fn requires_domain_region_and_pool() {
        assert!(Cognito::new(ProviderOptions::new("a", "b"), "", "us-east-1", "pool").is_err());
        assert!(Cognito::new(ProviderOptions::new("a", "b"), "d", "", "pool").is_err());
        assert!(Cognito::new(ProviderOptions::new("a", "b"), "d", "r", "").is_err());
    }

    #[tokio::test]
    async fn authorization_url_encodes_scope_with_percent_20() {
        let url = cognito().create_authorization_url(params()).await.unwrap();
        assert_eq!(endpoint(&url), "https://test.auth.us-east-1.amazoncognito.com/oauth2/authorize");
        assert!(url.as_str().ends_with("&scope=openid%20profile%20email"));
        let q = query(&url);
        assert_eq!(q["scope"], "openid profile email");
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(!q.contains_key("identity_provider"));
    }

    #[tokio::test]
    async fn identity_provider() {
        let mut c = cognito();
        c.identity_provider = Some("Google".into());
        let url = c.create_authorization_url(params()).await.unwrap();
        assert_eq!(query(&url)["identity_provider"], "Google");
        let url = c.create_authorization_url(with_additional(&[("identity_provider", "Okta")])).await.unwrap();
        assert_eq!(query(&url)["identity_provider"], "Okta");
    }

    #[tokio::test]
    async fn require_client_secret() {
        let mut c = cognito();
        c.options.client_secret.clear();
        assert!(c.create_authorization_url(params()).await.is_ok());
        c.require_client_secret = true;
        assert!(c.create_authorization_url(params()).await.is_err());
    }

    #[test]
    fn id_token_config() {
        let Some(IdTokenConfig::Jwks(config)) = cognito().id_token() else { panic!("expected jwks config") };
        assert_eq!(config.issuer, vec!["https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool".to_owned()]);
        assert_eq!(config.audience, vec!["client-123".to_owned()]);
        assert!(matches!(config.jwks, JwksSource::Url(u) if u.ends_with("/us-east-1_pool/.well-known/jwks.json")));
    }

    #[test]
    fn maps_profile() {
        let user = to_user(
            &json!({"sub": "s", "email": "a@b.c", "email_verified": true, "given_name": "Ada", "picture": "p"}),
        );
        assert_eq!(user.name.as_deref(), Some("Ada"));
        assert_eq!(user.email.as_deref(), Some("a@b.c"));
        assert_eq!(user.image.as_deref(), Some("p"));
        assert!(user.email_verified);
        let user = to_user(&json!({"sub": "s", "username": "ada", "email_verified": "true"}));
        assert_eq!(user.name.as_deref(), Some("ada"));
        assert!(user.email_verified);
        assert_eq!(to_user(&json!({"sub": "s"})).name.as_deref(), Some(""));
    }
}
