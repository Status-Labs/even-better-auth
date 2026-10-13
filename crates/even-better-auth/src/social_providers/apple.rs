//! Sign in with Apple (`social-providers/apple.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, require_client_credentials, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, IdTokenConfig, JwksIdTokenConfig, JwksSource, NonceComparison,
    OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams,
    create_authorization_url, decode_jwt_payload, refresh_access_token, subject_from, validate_authorization_code,
};

const TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";

pub struct Apple {
    pub options: ProviderOptions,
    /// The iOS app bundle id, accepted as ID-token audience for native sign-in.
    pub app_bundle_identifier: Option<String>,
    /// Explicit ID-token audiences; overrides the bundle id and client ids.
    pub audience: Vec<String>,
}

impl Apple {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, app_bundle_identifier: None, audience: vec![] }
    }
}

#[async_trait]
impl OAuthProvider for Apple {
    fn id(&self) -> &str {
        "apple"
    }
    fn name(&self) -> &str {
        "Apple"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("sub"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Apple", &self.options, true)?;
        let mut scopes = self.options.scopes_with_defaults(&["email", "name"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://appleid.apple.com/auth/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                code_verifier: Some(p.code_verifier),
                response_mode: Some("form_post".into()),
                response_type: Some("code id_token".into()),
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        validate_authorization_code(&self.options, &params, TOKEN_ENDPOINT, None).await
    }

    fn id_token(&self) -> Option<IdTokenConfig> {
        let audience = if !self.audience.is_empty() {
            self.audience.clone()
        } else if let Some(bundle) = &self.app_bundle_identifier {
            vec![bundle.clone()]
        } else {
            self.options.client_ids()
        };
        let mut config =
            JwksIdTokenConfig::new(JwksSource::Url("https://appleid.apple.com/auth/keys".into()), audience);
        config.issuer = vec!["https://appleid.apple.com".into()];
        config.max_token_age = Some(3600);
        config.nonce_comparison = NonceComparison::ExactOrSha256;
        Some(IdTokenConfig::Jwks(config))
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
        let Some(claims) = request.tokens.id_token.as_deref().and_then(decode_jwt_payload) else {
            return Ok(None);
        };
        let mut profile = Value::Object(claims);
        let name = match request.user.as_ref().and_then(|u| u.get("name")).filter(|n| n.is_object()) {
            Some(n) => {
                let first = str_of(n, "firstName").unwrap_or_default();
                let last = str_of(n, "lastName").unwrap_or_default();
                format!("{first} {last}").trim().to_owned()
            }
            None => str_of(&profile, "name").unwrap_or_default(),
        };
        let email_verified = match profile.get("email_verified") {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s == "true",
            _ => false,
        };
        profile["name"] = name.clone().into();
        let user = OAuth2UserInfo {
            name: Some(name),
            email: str_of(&profile, "email"),
            image: None,
            email_verified,
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }
}
