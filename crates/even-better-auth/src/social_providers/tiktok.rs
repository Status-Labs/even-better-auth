//! TikTok (`social-providers/tiktok.ts`).
//!
//! TikTok identifies the app by `client_key` (set [`ProviderOptions::client_key`]) instead of
//! `client_id`, both in the authorization URL and in token requests, so the shared helpers
//! are bypassed. `client_id` is unused.

use async_trait::async_trait;
use serde_json::{Map, Value};
use url::Url;

use super::{create_placeholder_email, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::{Error, Result};
use crate::oauth2::{
    AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    RESERVED_AUTHORIZATION_PARAMS, TokenRequest, UserInfoRequest, UserInfoResult, ValidateCodeParams, as_object,
    bearer, get_json, get_oauth2_tokens, post_form, subject_from,
};

const TOKEN_ENDPOINT: &str = "https://open.tiktokapis.com/v2/oauth/token/";
const USER_FIELDS: &[&str] = &["open_id", "avatar_large_url", "display_name", "username"];

pub struct TikTok {
    pub options: ProviderOptions,
}

impl TikTok {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }

    fn client_key(&self) -> &str {
        self.options.client_key.as_deref().unwrap_or_default()
    }

    /// A form request authenticated with `client_key` / `client_secret` in the body.
    fn token_request(&self, mut body: Vec<(String, String)>) -> TokenRequest {
        body.push(("client_key".into(), self.client_key().to_owned()));
        body.push(("client_secret".into(), self.options.client_secret.clone()));
        TokenRequest {
            body,
            headers: vec![
                ("content-type".into(), "application/x-www-form-urlencoded".into()),
                ("accept".into(), "application/json".into()),
            ],
        }
    }

    fn code_request(&self, p: &ValidateCodeParams) -> TokenRequest {
        let redirect = self.options.redirect_uri.clone().filter(|r| !r.is_empty()).unwrap_or(p.redirect_uri.clone());
        let mut body =
            vec![("grant_type".to_owned(), "authorization_code".to_owned()), ("code".into(), p.code.clone())];
        if let Some(verifier) = p.code_verifier.as_ref().filter(|v| !v.is_empty()) {
            body.push(("code_verifier".into(), verifier.clone()));
        }
        body.push(("redirect_uri".into(), redirect));
        self.token_request(body)
    }
}

/// Map the profile. TikTok exposes no email, so a placeholder keyed to the `open_id` is used.
fn to_user(profile: &Value) -> OAuth2UserInfo {
    let user = profile.pointer("/data/user").cloned().unwrap_or(Value::Null);
    let open_id = subject_from(user.get("open_id")).unwrap_or_default();
    OAuth2UserInfo {
        email: Some(truthy_str(&user, "email").unwrap_or_else(|| create_placeholder_email(&open_id, "tiktok"))),
        name: Some(truthy_str(&user, "display_name").or_else(|| truthy_str(&user, "username")).unwrap_or_default()),
        image: str_of(&user, "avatar_large_url"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for TikTok {
    fn id(&self) -> &str {
        "tiktok"
    }
    fn name(&self) -> &str {
        "TikTok"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.pointer("/data/user/open_id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["user.info.profile"]);
        scopes.extend(p.scopes);
        let redirect = self.options.redirect_uri.clone().filter(|r| !r.is_empty()).unwrap_or(p.redirect_uri);
        let mut params: Vec<(String, String)> = vec![
            ("scope".into(), scopes.join(",")),
            ("response_type".into(), "code".into()),
            ("client_key".into(), self.client_key().to_owned()),
            ("redirect_uri".into(), redirect),
            ("state".into(), p.state),
        ];
        for (k, v) in p.additional_params {
            if RESERVED_AUTHORIZATION_PARAMS.contains(&k.as_str()) || k == "client_key" {
                continue;
            }
            match params.iter_mut().find(|(name, _)| *name == k) {
                Some(existing) => existing.1 = v,
                None => params.push((k, v)),
            }
        }
        let mut url =
            Url::parse("https://www.tiktok.com/v2/auth/authorize").map_err(|e| Error::Config(e.to_string()))?;
        url.query_pairs_mut().extend_pairs(params.iter());
        Ok(url)
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let data = post_form(TOKEN_ENDPOINT, &self.code_request(&p)).await?;
        Ok(get_oauth2_tokens(&as_object(data)))
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        let body =
            vec![("grant_type".to_owned(), "refresh_token".to_owned()), ("refresh_token".into(), refresh_token.into())];
        let data = post_form(TOKEN_ENDPOINT, &self.token_request(body)).await?;
        let mut tokens = get_oauth2_tokens(&as_object(data));
        tokens.raw = Map::new();
        Ok(tokens)
    }

    /// As in TS, `map_profile_to_user` is not applied to TikTok profiles.
    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let url = format!("https://open.tiktokapis.com/v2/user/info/?fields={}", USER_FIELDS.join(","));
        let Ok(profile) = get_json(&url, &[bearer(request.tokens.access_token.as_deref())]).await else {
            return Ok(None);
        };
        let user = to_user(&profile);
        Ok(Some(UserInfoResult { user, data: profile }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::social_providers::test_support::*;
    use serde_json::json;

    fn tiktok(key: &str) -> TikTok {
        let mut o = ProviderOptions::new("", "tiktok-client-secret");
        o.client_key = Some(key.into());
        TikTok::new(o)
    }

    fn sorted(req: &TokenRequest) -> Vec<(String, String)> {
        let mut body = req.body.clone();
        body.sort();
        body
    }

    #[tokio::test]
    async fn authorization_url_uses_client_key() {
        let url = tiktok("tk-key-1").create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://www.tiktok.com/v2/auth/authorize");
        assert_eq!(q["client_key"], "tk-key-1");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["redirect_uri"], CALLBACK);
        assert_eq!(q["state"], STATE);
        assert_eq!(q["scope"], "user.info.profile");
        assert!(!q.contains_key("client_id"));

        let p = with_additional(&[("custom", "value"), ("state", "attacker"), ("client_key", "attacker-key")]);
        let q = query(&tiktok("tk-key-1").create_authorization_url(p).await.unwrap());
        assert_eq!(q["custom"], "value");
        assert_eq!(q["state"], STATE);
        assert_eq!(q["client_key"], "tk-key-1");
    }

    #[test]
    fn token_requests_use_client_key() {
        let t = tiktok("tiktok-client-key");
        let req = t.code_request(&ValidateCodeParams {
            code: "authorization-code".into(),
            code_verifier: Some("code-verifier".into()),
            redirect_uri: "https://app.example.com/api/auth/callback/tiktok".into(),
            device_id: None,
        });
        let pairs = |v: &[(&str, &str)]| v.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
        assert_eq!(
            sorted(&req),
            pairs(&[
                ("client_key", "tiktok-client-key"),
                ("client_secret", "tiktok-client-secret"),
                ("code", "authorization-code"),
                ("code_verifier", "code-verifier"),
                ("grant_type", "authorization_code"),
                ("redirect_uri", "https://app.example.com/api/auth/callback/tiktok"),
            ])
        );
        let body = vec![("grant_type".to_owned(), "refresh_token".to_owned()), ("refresh_token".into(), "rt".into())];
        assert_eq!(
            sorted(&t.token_request(body)),
            pairs(&[
                ("client_key", "tiktok-client-key"),
                ("client_secret", "tiktok-client-secret"),
                ("grant_type", "refresh_token"),
                ("refresh_token", "rt"),
            ])
        );
    }

    #[test]
    fn maps_profile_with_placeholder_email() {
        let profile = json!({"data": {"user": {
            "open_id": "tiktok-user-1", "avatar_large_url": "https://example.com/avatar.png",
            "display_name": "TikTok User", "username": "tiktok-user"
        }}});
        let user = to_user(&profile);
        assert_eq!(user.email.as_deref(), Some("tiktok-user-1@tiktok.placeholder.invalid"));
        assert_eq!(user.name.as_deref(), Some("TikTok User"));
        assert_eq!(user.image.as_deref(), Some("https://example.com/avatar.png"));
        assert!(!user.email_verified);
        assert_eq!(tiktok("k").account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("tiktok-user-1"));
    }
}
