//! Cloudflare (`social-providers/cloudflare.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

const AUTHORIZATION_ENDPOINT: &str = "https://dash.cloudflare.com/oauth2/auth";
const TOKEN_ENDPOINT: &str = "https://dash.cloudflare.com/oauth2/token";
/// Cloudflare's OIDC `userinfo` endpoint only returns `sub`, so the profile is read from
/// the API `/user` endpoint (requires the `user-details.read` scope).
const USER_ENDPOINT: &str = "https://api.cloudflare.com/client/v4/user";

/// Token endpoint authentication supported by Cloudflare OAuth clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflareTokenAuth {
    /// `client_secret_basic` (the default for confidential clients).
    ClientSecretBasic,
    /// `client_secret_post`.
    ClientSecretPost,
    /// Public PKCE clients without a secret (the default when no secret is configured).
    None,
}

pub struct Cloudflare {
    pub options: ProviderOptions,
    /// Token endpoint authentication; defaults to `client_secret_basic` with a secret, else `none`.
    pub token_endpoint_auth_method: Option<CloudflareTokenAuth>,
}

impl Cloudflare {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, token_endpoint_auth_method: None }
    }

    fn token_endpoint_auth(&self) -> Option<ClientAuthentication> {
        let default = if self.options.client_secret.is_empty() {
            CloudflareTokenAuth::None
        } else {
            CloudflareTokenAuth::ClientSecretBasic
        };
        match self.token_endpoint_auth_method.unwrap_or(default) {
            CloudflareTokenAuth::ClientSecretBasic => Some(ClientAuthentication::Basic),
            CloudflareTokenAuth::ClientSecretPost => Some(ClientAuthentication::Post),
            CloudflareTokenAuth::None => None,
        }
    }
}

/// Unwrap the `/user` response envelope (`{ success, errors, result }`).
fn profile_from_response(data: &Value) -> Option<Value> {
    if data.get("success").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    data.get("result").filter(|r| r.is_object()).cloned()
}

fn to_user(profile: &Value) -> OAuth2UserInfo {
    let full: Vec<String> = ["first_name", "last_name"].iter().filter_map(|k| truthy_str(profile, k)).collect();
    let email = str_of(profile, "email");
    let name = Some(full.join(" ")).filter(|n| !n.is_empty()).or_else(|| email.clone());
    // Cloudflare does not expose email verification status.
    OAuth2UserInfo { name, email, image: None, email_verified: false, extra: Default::default() }
}

#[async_trait]
impl OAuthProvider for Cloudflare {
    fn id(&self) -> &str {
        "cloudflare"
    }
    fn name(&self) -> &str {
        "Cloudflare"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["user-details.read"]);
        scopes.extend(p.scopes);
        let mut unique: Vec<String> = vec![];
        for s in scopes {
            if !unique.contains(&s) {
                unique.push(s);
            }
        }
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: AUTHORIZATION_ENDPOINT.into(),
                scopes: unique,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        validate_authorization_code(&self.options, &params, TOKEN_ENDPOINT, self.token_endpoint_auth()).await
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        refresh_access_token(&self.options, refresh_token, TOKEN_ENDPOINT, self.token_endpoint_auth(), &[]).await
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let headers = [bearer(request.tokens.access_token.as_deref())];
        let data = get_json(USER_ENDPOINT, &headers).await;
        let Some(profile) = data.as_ref().ok().and_then(profile_from_response) else {
            match data {
                Err(e) => tracing::error!(error = %e, "Failed to fetch user info from Cloudflare"),
                Ok(d) => {
                    let errors = d.get("errors").cloned().unwrap_or(Value::Null);
                    tracing::error!(%errors, "Failed to fetch user info from Cloudflare");
                }
            }
            return Ok(None);
        };
        let user = to_user(&profile);
        Ok(finish(&self.options, profile, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::{authorization_code_request, encode_basic_credentials};
    use crate::social_providers::test_support::*;
    use serde_json::json;

    #[tokio::test]
    async fn authorization_url_dedupes_scopes() {
        let mut o = ProviderOptions::new("cf-client", "");
        o.scope = vec!["user-details.read".into(), "account.read".into()];
        let url = Cloudflare::new(o).create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), AUTHORIZATION_ENDPOINT);
        assert_eq!(q["scope"], "user-details.read account.read");
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn token_endpoint_auth_defaults() {
        let params = ValidateCodeParams { code: "c".into(), redirect_uri: CALLBACK.into(), ..Default::default() };
        let confidential = Cloudflare::new(ProviderOptions::new("id", "secret"));
        let req = authorization_code_request(
            &confidential.options,
            &params,
            TOKEN_ENDPOINT,
            confidential.token_endpoint_auth(),
            &[],
        )
        .unwrap();
        assert_eq!(req.header("authorization"), Some(encode_basic_credentials("id", "secret").as_str()));
        assert!(!req.has("client_secret"));

        let mut post = Cloudflare::new(ProviderOptions::new("id", "secret"));
        post.token_endpoint_auth_method = Some(CloudflareTokenAuth::ClientSecretPost);
        let req = authorization_code_request(&post.options, &params, TOKEN_ENDPOINT, post.token_endpoint_auth(), &[])
            .unwrap();
        assert_eq!(req.get("client_secret"), Some("secret"));

        let public = Cloudflare::new(ProviderOptions::new("id", ""));
        let req =
            authorization_code_request(&public.options, &params, TOKEN_ENDPOINT, public.token_endpoint_auth(), &[])
                .unwrap();
        assert_eq!(req.get("client_id"), Some("id"));
        assert!(req.header("authorization").is_none());
    }

    #[test]
    fn maps_profile() {
        let data = json!({"success": true, "errors": [], "result": {
            "id": "cloudflare-user-1", "email": "user@example.com", "first_name": "Cloudflare", "last_name": "User"
        }});
        let profile = profile_from_response(&data).unwrap();
        let user = to_user(&profile);
        assert_eq!(user.name.as_deref(), Some("Cloudflare User"));
        assert_eq!(user.email.as_deref(), Some("user@example.com"));
        assert!(!user.email_verified);
        assert!(user.image.is_none());
        let p = Cloudflare::new(ProviderOptions::new("a", "b"));
        assert_eq!(p.account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("cloudflare-user-1"));

        let nameless = to_user(&json!({"id": "2", "email": "nameless@example.com"}));
        assert_eq!(nameless.name.as_deref(), Some("nameless@example.com"));

        assert!(
            profile_from_response(&json!({"success": false, "errors": [{"code": 1000}], "result": null})).is_none()
        );
        assert!(profile_from_response(&json!({"success": true, "errors": [], "result": null})).is_none());
    }
}
