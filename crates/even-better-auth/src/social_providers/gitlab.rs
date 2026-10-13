//! GitLab (`social-providers/gitlab.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, bearer, create_authorization_url, get_json,
    refresh_access_token, subject_from, validate_authorization_code,
};

pub struct GitLab {
    pub options: ProviderOptions,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

fn clean_double_slashes(input: &str) -> String {
    input
        .split("://")
        .map(|part| {
            let mut out = String::with_capacity(part.len());
            for c in part.chars() {
                if !(c == '/' && out.ends_with('/')) {
                    out.push(c);
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("://")
}

impl GitLab {
    pub fn new(options: ProviderOptions) -> Self {
        Self::with_issuer(options, None)
    }

    /// A self-hosted GitLab at `issuer` (default `https://gitlab.com`).
    pub fn with_issuer(options: ProviderOptions, issuer: Option<&str>) -> Self {
        let base = issuer.filter(|i| !i.is_empty()).unwrap_or("https://gitlab.com");
        Self {
            options,
            authorization_endpoint: clean_double_slashes(&format!("{base}/oauth/authorize")),
            token_endpoint: clean_double_slashes(&format!("{base}/oauth/token")),
            userinfo_endpoint: clean_double_slashes(&format!("{base}/api/v4/user")),
        }
    }
}

#[async_trait]
impl OAuthProvider for GitLab {
    fn id(&self) -> &str {
        "gitlab"
    }
    fn name(&self) -> &str {
        "Gitlab"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["read_user"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: self.authorization_endpoint.clone(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                code_verifier: Some(p.code_verifier),
                login_hint: p.login_hint,
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
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

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let headers = [bearer(request.tokens.access_token.as_deref())];
        let Ok(profile) = get_json(&self.userinfo_endpoint, &headers).await else {
            return Ok(None);
        };
        let locked = profile.get("locked").is_some_and(|l| l.as_bool().unwrap_or(!l.is_null()));
        if str_of(&profile, "state").as_deref() != Some("active") || locked {
            return Ok(None);
        }
        let user = OAuth2UserInfo {
            name: str_of(&profile, "name").or_else(|| str_of(&profile, "username")).or_else(|| Some(String::new())),
            email: str_of(&profile, "email"),
            image: str_of(&profile, "avatar_url"),
            email_verified: profile.get("email_verified").and_then(Value::as_bool).unwrap_or(false),
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let g = GitLab::with_issuer(ProviderOptions::new("a", "b"), Some("https://git.example.com/"));
        assert_eq!(g.authorization_endpoint, "https://git.example.com/oauth/authorize");
        assert_eq!(g.userinfo_endpoint, "https://git.example.com/api/v4/user");
    }
}
