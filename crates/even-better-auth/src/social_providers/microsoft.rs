//! Microsoft Entra ID (`social-providers/microsoft-entra-id.ts`).

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, require_client_credentials, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, IdTokenConfig, JwksIdTokenConfig, JwksSource, OAuth2Tokens,
    OAuth2UserInfo, OAuthProvider, ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer,
    create_authorization_url, decode_jwt_payload, get_bytes, refresh_access_token, subject_from,
    validate_authorization_code,
};

/// The fixed tenant id of personal Microsoft accounts.
const CONSUMER_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email", "User.Read", "offline_access"];

pub struct Microsoft {
    pub options: ProviderOptions,
    /// Tenant id, or `common` / `organizations` / `consumers` (default `common`).
    pub tenant_id: String,
    /// Authority URL (default `https://login.microsoftonline.com`).
    pub authority: String,
    /// Profile photo size in pixels (default 48).
    pub profile_photo_size: u32,
    pub disable_profile_photo: bool,
}

impl Microsoft {
    pub fn new(options: ProviderOptions) -> Self {
        Self {
            options,
            tenant_id: "common".into(),
            authority: "https://login.microsoftonline.com".into(),
            profile_photo_size: 48,
            disable_profile_photo: false,
        }
    }

    fn authority(&self) -> String {
        self.authority.trim_end_matches('/').to_owned()
    }

    fn tenant(&self) -> &str {
        if self.tenant_id.is_empty() { "common" } else { &self.tenant_id }
    }

    fn token_endpoint(&self) -> String {
        format!("{}/{}/oauth2/v2.0/token", self.authority(), self.tenant())
    }
}

/// Tenant binding for multi-tenant endpoints: `iss` must name the token's own tenant and
/// the account class must match the configured tenant.
pub fn tenant_claims_allowed(authority: &str, tenant: &str, claims: &serde_json::Map<String, Value>) -> bool {
    let Some(tid) = claims.get("tid").and_then(Value::as_str) else { return false };
    if claims.get("iss").and_then(Value::as_str) != Some(&format!("{authority}/{tid}/v2.0")) {
        return false;
    }
    match tenant {
        "organizations" => tid != CONSUMER_TENANT_ID,
        "consumers" => tid == CONSUMER_TENANT_ID,
        _ => true,
    }
}

#[async_trait]
impl OAuthProvider for Microsoft {
    fn id(&self) -> &str {
        "microsoft"
    }
    fn name(&self) -> &str {
        "Microsoft EntraID"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("oid"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        require_client_credentials("Microsoft Entra ID", &self.options, false)?;
        let mut scopes = self.options.scopes_with_defaults(DEFAULT_SCOPES);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: format!("{}/{}/oauth2/v2.0/authorize", self.authority(), self.tenant()),
                state: p.state,
                code_verifier: Some(p.code_verifier),
                scopes,
                redirect_uri: p.redirect_uri,
                prompt: self.options.prompt.clone(),
                login_hint: p.login_hint,
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        validate_authorization_code(&self.options, &params, &self.token_endpoint(), None).await
    }

    fn id_token(&self) -> Option<IdTokenConfig> {
        let authority = self.authority();
        let tenant = self.tenant().to_owned();
        let jwks = JwksSource::Url(format!("{authority}/{tenant}/discovery/v2.0/keys"));
        let mut config = JwksIdTokenConfig::new(jwks, self.options.client_ids());
        config.max_token_age = Some(3600);
        if !matches!(tenant.as_str(), "common" | "organizations" | "consumers") {
            config.issuer = vec![format!("{authority}/{tenant}/v2.0")];
        }
        config.verify_claims = Some(Arc::new(move |claims| tenant_claims_allowed(&authority, &tenant, claims)));
        Some(IdTokenConfig::Jwks(config))
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let Some(claims) = request.tokens.id_token.as_deref().and_then(decode_jwt_payload) else {
            return Ok(None);
        };
        let mut profile = Value::Object(claims);
        if str_of(&profile, "oid").is_none_or(|o| o.trim().is_empty()) {
            tracing::error!(
                "Microsoft Entra ID token did not include a valid oid claim; unable to resolve a stable account identifier."
            );
            return Ok(None);
        }
        if let (false, Some(token)) = (self.disable_profile_photo, request.tokens.access_token.as_deref()) {
            let size = self.profile_photo_size;
            let url = format!("https://graph.microsoft.com/v1.0/me/photos/{size}x{size}/$value");
            if let Ok(bytes) = get_bytes(&url, &[bearer(Some(token))]).await {
                profile["picture"] = format!("data:image/jpeg;base64, {}", STANDARD.encode(bytes)).into();
            }
        }
        let email = str_of(&profile, "email");
        let in_list = |key: &str| {
            profile
                .get(key)
                .and_then(Value::as_array)
                .is_some_and(|l| l.iter().any(|e| e.as_str().is_some_and(|e| Some(e) == email.as_deref())))
        };
        let email_verified = match profile.get("email_verified").and_then(Value::as_bool) {
            Some(v) => v,
            None => email.is_some() && (in_list("verified_primary_email") || in_list("verified_secondary_email")),
        };
        let user = OAuth2UserInfo {
            name: str_of(&profile, "name"),
            email,
            image: str_of(&profile, "picture"),
            email_verified,
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        let scopes = self.options.scopes_with_defaults(DEFAULT_SCOPES);
        let extra = [("scope".to_owned(), scopes.join(" "))];
        refresh_access_token(&self.options, refresh_token, &self.token_endpoint(), None, &extra).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tenant_binding() {
        let a = "https://login.microsoftonline.com";
        let claims = |tid: &str| json!({"tid": tid, "iss": format!("{a}/{tid}/v2.0")}).as_object().unwrap().clone();
        assert!(tenant_claims_allowed(a, "common", &claims("t1")));
        assert!(tenant_claims_allowed(a, "organizations", &claims("t1")));
        assert!(!tenant_claims_allowed(a, "organizations", &claims(CONSUMER_TENANT_ID)));
        assert!(tenant_claims_allowed(a, "consumers", &claims(CONSUMER_TENANT_ID)));
        assert!(!tenant_claims_allowed(a, "consumers", &claims("t1")));
        let mut wrong = claims("t1");
        wrong.insert("iss".into(), json!(format!("{a}/t2/v2.0")));
        assert!(!tenant_claims_allowed(a, "common", &wrong));
    }
}
