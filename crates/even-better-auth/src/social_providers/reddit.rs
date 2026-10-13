//! Reddit (`social-providers/reddit.ts`).

use async_trait::async_trait;
use serde_json::Value;
use url::Url;

use super::{create_placeholder_email, refresh_override, str_of, user_info_override};
use crate::error::Result;
use crate::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, ClientAuthentication, OAuth2Tokens, OAuth2UserInfo, OAuthProvider,
    ProviderOptions, TokenRequest, UserInfoRequest, UserInfoResult, ValidateCodeParams, as_object,
    authorization_code_request, bearer, create_authorization_url, get_json, get_oauth2_tokens, post_form,
    refresh_access_token, subject_from,
};

const TOKEN_ENDPOINT: &str = "https://www.reddit.com/api/v1/access_token";

pub struct Reddit {
    pub options: ProviderOptions,
    /// `temporary` or `permanent` (for a refresh token).
    pub duration: Option<String>,
}

impl Reddit {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, duration: None }
    }

    /// Token requests carry only the client credentials (and redirect URI override).
    fn token_options(&self) -> ProviderOptions {
        let mut o = ProviderOptions::new(self.options.client_id.clone(), self.options.client_secret.clone());
        o.redirect_uri = self.options.redirect_uri.clone();
        o
    }

    fn code_request(&self, params: &ValidateCodeParams) -> Result<TokenRequest> {
        let mut req = authorization_code_request(
            &self.token_options(),
            params,
            TOKEN_ENDPOINT,
            Some(ClientAuthentication::Basic),
            &[],
        )?;
        req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("accept"));
        req.headers.push(("accept".into(), "text/plain".into()));
        req.headers.push(("user-agent".into(), "better-auth".into()));
        Ok(req)
    }

    /// Reddit's `identity` scope returns no email: use a stable, non-routable placeholder
    /// keyed to the Reddit id, left unverified unless `map_profile_to_user` supplies one.
    fn to_user(&self, profile: &Value) -> OAuth2UserInfo {
        let base = OAuth2UserInfo {
            name: str_of(profile, "name"),
            email: None,
            image: str_of(profile, "icon_img").map(|i| i.split('?').next().unwrap_or_default().to_owned()),
            email_verified: false,
            extra: Default::default(),
        };
        let mut user = self.options.map_profile(profile, base);
        if user.email.as_deref().is_none_or(str::is_empty) {
            let id = subject_from(profile.get("id")).unwrap_or_default();
            user.email = Some(create_placeholder_email(&id, "reddit"));
        }
        user
    }
}

#[async_trait]
impl OAuthProvider for Reddit {
    fn id(&self) -> &str {
        "reddit"
    }
    fn name(&self) -> &str {
        "Reddit"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["identity"]);
        scopes.extend(p.scopes);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://www.reddit.com/api/v1/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                duration: self.duration.clone(),
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { code_verifier: None, device_id: None, ..p };
        let req = self.code_request(&params)?;
        let data = post_form(TOKEN_ENDPOINT, &req).await?;
        Ok(get_oauth2_tokens(&as_object(data)))
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        let auth = Some(ClientAuthentication::Basic);
        refresh_access_token(&self.token_options(), refresh_token, TOKEN_ENDPOINT, auth, &[]).await
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let headers = [bearer(request.tokens.access_token.as_deref()), ("user-agent", "better-auth".to_owned())];
        let Ok(profile) = get_json("https://oauth.reddit.com/api/v1/me", &headers).await else {
            return Ok(None);
        };
        let user = self.to_user(&profile);
        Ok(Some(UserInfoResult { user, data: profile }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::oauth2::encode_basic_credentials;
    use crate::social_providers::test_support::*;
    use serde_json::json;

    fn reddit() -> Reddit {
        Reddit::new(ProviderOptions::new("reddit-app", "reddit-secret"))
    }

    #[tokio::test]
    async fn authorization_url() {
        let mut r = reddit();
        r.duration = Some("permanent".into());
        let url = r.create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://www.reddit.com/api/v1/authorize");
        assert_eq!(q["scope"], "identity");
        assert_eq!(q["duration"], "permanent");
        assert!(!q.contains_key("code_challenge"));
    }

    #[test]
    fn code_exchange_uses_basic_auth_and_plain_accept() {
        let params = ValidateCodeParams {
            code: "authorization-code".into(),
            redirect_uri: "https://app.example.com/api/auth/callback/reddit".into(),
            ..Default::default()
        };
        let req = reddit().code_request(&params).unwrap();
        assert_eq!(req.header("accept"), Some("text/plain"));
        assert!(req.header("user-agent").is_some());
        let basic = encode_basic_credentials("reddit-app", "reddit-secret");
        assert_eq!(req.header("authorization"), Some(basic.as_str()));
        let mut body = req.body.clone();
        body.sort();
        assert_eq!(
            body,
            vec![
                ("code".to_owned(), "authorization-code".to_owned()),
                ("grant_type".into(), "authorization_code".into()),
                ("redirect_uri".into(), "https://app.example.com/api/auth/callback/reddit".into()),
            ]
        );
    }

    #[test]
    fn placeholder_email() {
        let profile = json!({"id": "reddit-user-1", "name": "spez", "icon_img": "https://example.com/avatar.png?s=1",
            "has_verified_email": true, "oauth_client_id": "shared-app-client-id", "verified": true});
        let user = reddit().to_user(&profile);
        assert_eq!(user.email.as_deref(), Some("reddit-user-1@reddit.placeholder.invalid"));
        assert!(!user.email_verified);
        assert_eq!(user.name.as_deref(), Some("spez"));
        assert_eq!(user.image.as_deref(), Some("https://example.com/avatar.png"));
        assert_eq!(reddit().account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("reddit-user-1"));

        let b = reddit().to_user(&json!({"id": "user-b", "name": "b", "icon_img": null}));
        assert_eq!(b.email.as_deref(), Some("user-b@reddit.placeholder.invalid"));
        assert!(b.image.is_none());

        let mut mapped = reddit();
        mapped.options.map_profile_to_user =
            Some(Arc::new(|_| json!({"email": "real@example.com"}).as_object().unwrap().clone()));
        assert_eq!(mapped.to_user(&profile).email.as_deref(), Some("real@example.com"));
    }
}
