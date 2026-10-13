//! GitHub (`social-providers/github.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{finish, refresh_override, str_of, user_info_override};
use crate::error::{Error, Result};
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    UserInfoRequest, UserInfoResult, ValidateCodeParams, as_object, authorization_code_request, bearer,
    create_authorization_url, get_json, get_oauth2_tokens, post_form, refresh_access_token, subject_from,
};

const TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";

pub struct GitHub {
    pub options: ProviderOptions,
}

impl GitHub {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }
}

#[async_trait]
impl OAuthProvider for GitHub {
    fn id(&self) -> &str {
        "github"
    }
    fn name(&self) -> &str {
        "GitHub"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["read:user", "user:email"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://github.com/login/oauth/authorize".into(),
                scopes,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                redirect_uri: p.redirect_uri,
                login_hint: p.login_hint,
                prompt: self.options.prompt.clone(),
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { device_id: None, ..p };
        let req = authorization_code_request(&self.options, &params, TOKEN_ENDPOINT, None, &[])?;
        let data = post_form(TOKEN_ENDPOINT, &req).await.inspect_err(|e| {
            tracing::error!(error = %e, "GitHub OAuth token exchange failed");
        })?;
        if data.get("error").is_some() {
            tracing::error!(response = %data, "GitHub OAuth token exchange failed");
            return Err(Error::Http(format!("GitHub OAuth token exchange failed: {data}")));
        }
        Ok(get_oauth2_tokens(&as_object(data)))
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
        let auth = bearer(request.tokens.access_token.as_deref());
        let headers = [("user-agent", "better-auth".to_owned()), auth];
        let Ok(mut profile) = get_json("https://api.github.com/user", &headers).await else {
            return Ok(None);
        };
        let emails = get_json("https://api.github.com/user/emails", &headers).await.ok();
        let emails = emails.as_ref().and_then(Value::as_array);
        if str_of(&profile, "email").is_none()
            && let Some(list) = emails
        {
            let chosen = list.iter().find(|e| e["primary"] == true).or_else(|| list.first());
            if let Some(email) = chosen.and_then(|e| e.get("email")).cloned() {
                profile["email"] = email;
            }
        }
        let email = str_of(&profile, "email");
        let email_verified = emails
            .and_then(|list| {
                list.iter().find(|e| email.is_some() && e.get("email").and_then(Value::as_str) == email.as_deref())
            })
            .and_then(|e| e.get("verified").and_then(Value::as_bool))
            .unwrap_or(false);
        let name = str_of(&profile, "name")
            .filter(|n| !n.is_empty())
            .or_else(|| str_of(&profile, "login"))
            .unwrap_or_default();
        let user = OAuth2UserInfo {
            name: Some(name),
            email,
            image: str_of(&profile, "avatar_url"),
            email_verified,
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }
}
