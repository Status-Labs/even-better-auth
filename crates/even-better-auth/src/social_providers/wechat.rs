//! WeChat Website App login (`social-providers/wechat.ts`).
//!
//! WeChat uses non-standard OAuth 2.0: `appid` / `secret` instead of `client_id` /
//! `client_secret`, GET token requests, and a `#wechat_redirect` fragment on the
//! authorization URL. The `openid` (and `unionid`) returned with the access token are kept
//! in [`OAuth2Tokens::raw`], where [`get_user_info`](OAuthProvider::get_user_info) reads them.

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value};
use url::Url;

use super::{create_placeholder_email, finish, refresh_override, str_of, truthy_str, user_info_override};
use crate::error::{Error, Result};
use crate::oauth2::{
    AuthorizationUrlParams, OAuth2Tokens, OAuth2UserInfo, OAuthProvider, ProviderOptions,
    RESERVED_AUTHORIZATION_PARAMS, UserInfoRequest, UserInfoResult, ValidateCodeParams, get_json,
};

pub struct WeChat {
    /// `client_id` is the WeChat App ID and `client_secret` the App Secret.
    pub options: ProviderOptions,
    /// Login page language: `cn` (default) or `en`.
    pub lang: Option<String>,
}

impl WeChat {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, lang: None }
    }
}

fn query_url(base: &str, params: &[(&str, &str)]) -> Result<Url> {
    let mut url = Url::parse(base).map_err(|e| Error::Config(e.to_string()))?;
    url.query_pairs_mut().extend_pairs(params.iter());
    Ok(url)
}

/// Parse a WeChat token response; `errcode` (or a request failure) is an error.
fn parse_token_response(data: Result<Value>, action: &str) -> Result<(OAuth2Tokens, Value)> {
    let data = data.map_err(|e| Error::Http(format!("Failed to {action}: {e}")))?;
    if data.get("errcode").is_some_and(|c| !c.is_null() && c.as_i64() != Some(0)) {
        let msg = truthy_str(&data, "errmsg").unwrap_or_else(|| "Unknown error".into());
        return Err(Error::Http(format!("Failed to {action}: {msg}")));
    }
    let expires_in = data.get("expires_in").and_then(Value::as_f64).unwrap_or(0.0);
    let tokens = OAuth2Tokens {
        token_type: Some("Bearer".into()),
        access_token: str_of(&data, "access_token"),
        refresh_token: str_of(&data, "refresh_token"),
        access_token_expires_at: Some(Utc::now() + chrono::Duration::milliseconds((expires_in * 1000.0) as i64)),
        scopes: str_of(&data, "scope").unwrap_or_default().split(',').map(str::to_owned).collect(),
        ..Default::default()
    };
    Ok((tokens, data))
}

/// Map the profile. WeChat exposes no email, so a placeholder keyed to the `unionid`
/// (else `openid`) is used unless the profile has one.
fn to_user(profile: &Value, token_openid: &str) -> OAuth2UserInfo {
    let user_id = truthy_str(profile, "unionid")
        .or_else(|| truthy_str(profile, "openid"))
        .unwrap_or_else(|| token_openid.to_owned());
    OAuth2UserInfo {
        name: str_of(profile, "nickname"),
        email: Some(truthy_str(profile, "email").unwrap_or_else(|| create_placeholder_email(&user_id, "wechat"))),
        image: str_of(profile, "headimgurl"),
        email_verified: false,
        extra: Default::default(),
    }
}

#[async_trait]
impl OAuthProvider for WeChat {
    fn id(&self) -> &str {
        "wechat"
    }
    fn name(&self) -> &str {
        "WeChat"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        truthy_str(profile, "unionid").or_else(|| truthy_str(profile, "openid"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes = self.options.scopes_with_defaults(&["snsapi_login"]);
        scopes.extend(p.scopes);
        let redirect = self.options.redirect_uri.clone().filter(|r| !r.is_empty()).unwrap_or(p.redirect_uri);
        let lang = self.lang.clone().filter(|l| !l.is_empty()).unwrap_or_else(|| "cn".into());
        let mut params: Vec<(String, String)> = vec![
            ("scope".into(), scopes.join(",")),
            ("response_type".into(), "code".into()),
            ("appid".into(), self.options.client_id.clone()),
            ("redirect_uri".into(), redirect),
            ("state".into(), p.state),
            ("lang".into(), lang),
        ];
        for (k, v) in p.additional_params {
            if RESERVED_AUTHORIZATION_PARAMS.contains(&k.as_str()) || k == "appid" {
                continue;
            }
            match params.iter_mut().find(|(name, _)| *name == k) {
                Some(existing) => existing.1 = v,
                None => params.push((k, v)),
            }
        }
        let mut url =
            Url::parse("https://open.weixin.qq.com/connect/qrconnect").map_err(|e| Error::Config(e.to_string()))?;
        url.query_pairs_mut().extend_pairs(params.iter());
        url.set_fragment(Some("wechat_redirect"));
        Ok(url)
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let url = query_url(
            "https://api.weixin.qq.com/sns/oauth2/access_token",
            &[
                ("appid", &self.options.client_id),
                ("secret", &self.options.client_secret),
                ("code", &p.code),
                ("grant_type", "authorization_code"),
            ],
        )?;
        let (mut tokens, data) =
            parse_token_response(get_json(url.as_str(), &[]).await, "validate authorization code")?;
        let mut raw = Map::new();
        for key in ["openid", "unionid"] {
            if let Some(v) = data.get(key).filter(|v| !v.is_null()) {
                raw.insert(key.into(), v.clone());
            }
        }
        tokens.raw = raw;
        Ok(tokens)
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens> {
        if let Some(r) = refresh_override(&self.options, refresh_token).await {
            return r;
        }
        let url = query_url(
            "https://api.weixin.qq.com/sns/oauth2/refresh_token",
            &[("appid", &self.options.client_id), ("grant_type", "refresh_token"), ("refresh_token", refresh_token)],
        )?;
        let (tokens, _) = parse_token_response(get_json(url.as_str(), &[]).await, "refresh access token")?;
        Ok(tokens)
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let Some(openid) = request.tokens.raw.get("openid").and_then(Value::as_str).filter(|o| !o.is_empty()) else {
            return Ok(None);
        };
        let access_token = request.tokens.access_token.as_deref().unwrap_or_default();
        let url = query_url(
            "https://api.weixin.qq.com/sns/userinfo",
            &[("access_token", access_token), ("openid", openid), ("lang", "zh_CN")],
        )?;
        let Ok(profile) = get_json(url.as_str(), &[]).await else { return Ok(None) };
        if profile.get("errcode").is_some_and(|c| !c.is_null() && c.as_i64() != Some(0)) {
            return Ok(None);
        }
        let user = to_user(&profile, openid);
        Ok(finish(&self.options, profile, user))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::social_providers::test_support::*;
    use serde_json::json;

    fn wechat() -> WeChat {
        WeChat::new(ProviderOptions::new("wx-app-1", "secret"))
    }

    #[tokio::test]
    async fn authorization_url_uses_appid_and_fragment() {
        let url = wechat().create_authorization_url(params()).await.unwrap();
        let q = query(&url);
        assert_eq!(endpoint(&url), "https://open.weixin.qq.com/connect/qrconnect");
        assert_eq!(q["appid"], "wx-app-1");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["scope"], "snsapi_login");
        assert_eq!(q["lang"], "cn");
        assert_eq!(url.fragment(), Some("wechat_redirect"));
        assert!(!q.contains_key("client_id"));

        let p = with_additional(&[("custom", "value"), ("state", "attacker"), ("appid", "attacker-app")]);
        let q = query(&wechat().create_authorization_url(p).await.unwrap());
        assert_eq!(q["custom"], "value");
        assert_eq!(q["state"], STATE);
        assert_eq!(q["appid"], "wx-app-1");
    }

    #[test]
    fn token_responses() {
        let ok = json!({"access_token": "at", "expires_in": 7200, "refresh_token": "rt", "openid": "o",
            "scope": "snsapi_login,snsapi_userinfo"});
        let (tokens, _) = parse_token_response(Ok(ok), "x").unwrap();
        assert_eq!(tokens.access_token.as_deref(), Some("at"));
        assert_eq!(tokens.refresh_token.as_deref(), Some("rt"));
        assert_eq!(tokens.scopes, vec!["snsapi_login", "snsapi_userinfo"]);
        assert!(tokens.access_token_expires_at.is_some());
        let err = parse_token_response(Ok(json!({"errcode": 40029, "errmsg": "invalid code"})), "x").unwrap_err();
        assert!(err.to_string().contains("invalid code"));
    }

    #[test]
    fn maps_profile_with_placeholder_email() {
        let profile = json!({"openid": "open-123", "unionid": "union-abc", "nickname": "WeChat User",
            "headimgurl": "https://example.com/avatar.png"});
        let user = to_user(&profile, "open-123");
        assert_eq!(user.email.as_deref(), Some("union-abc@wechat.placeholder.invalid"));
        assert_eq!(user.name.as_deref(), Some("WeChat User"));
        assert!(!user.email_verified);
        assert_eq!(wechat().account_subject(&profile, &OAuth2Tokens::default()).as_deref(), Some("union-abc"));

        let no_union = json!({"openid": "open-456", "nickname": "No Union"});
        assert_eq!(to_user(&no_union, "open-456").email.as_deref(), Some("open-456@wechat.placeholder.invalid"));
        assert_eq!(wechat().account_subject(&no_union, &OAuth2Tokens::default()).as_deref(), Some("open-456"));

        let mut mapped = wechat();
        mapped.options.map_profile_to_user =
            Some(Arc::new(|_| json!({"email": "real@example.com"}).as_object().unwrap().clone()));
        let user = mapped.options.map_profile(&profile, to_user(&profile, "open-123"));
        assert_eq!(user.email.as_deref(), Some("real@example.com"));
    }

    #[tokio::test]
    async fn user_info_requires_openid() {
        let tokens = OAuth2Tokens { access_token: Some("at".into()), ..Default::default() };
        assert!(wechat().get_user_info(&UserInfoRequest::from(tokens)).await.unwrap().is_none());
    }
}
