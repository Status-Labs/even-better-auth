//! Discord (`social-providers/discord.ts`).

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

const TOKEN_ENDPOINT: &str = "https://discord.com/api/oauth2/token";

pub struct Discord {
    pub options: ProviderOptions,
    /// Bot permissions, sent when the `bot` scope is requested.
    pub permissions: Option<u64>,
}

impl Discord {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options, permissions: None }
    }
}

/// The CDN avatar URL for a profile, or the default avatar when none is set.
pub fn avatar_url(profile: &Value) -> String {
    let id = str_of(profile, "id").unwrap_or_default();
    match str_of(profile, "avatar") {
        Some(avatar) => {
            let format = if avatar.starts_with("a_") { "gif" } else { "png" };
            format!("https://cdn.discordapp.com/avatars/{id}/{avatar}.{format}")
        }
        None => {
            let discriminator = str_of(profile, "discriminator").unwrap_or_default();
            let n = if discriminator == "0" {
                id.parse::<u64>().map(|id| (id >> 22) % 6).unwrap_or(0)
            } else {
                discriminator.parse::<u64>().map(|d| d % 5).unwrap_or(0)
            };
            format!("https://cdn.discordapp.com/embed/avatars/{n}.png")
        }
    }
}

#[async_trait]
impl OAuthProvider for Discord {
    fn id(&self) -> &str {
        "discord"
    }
    fn name(&self) -> &str {
        "Discord"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        subject_from(profile.get("id"))
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> Result<Url> {
        let mut scopes: Vec<String> =
            if self.options.disable_default_scope { vec![] } else { vec!["identify".into(), "email".into()] };
        scopes.extend(p.scopes);
        scopes.extend(self.options.scope.iter().cloned());
        let mut additional = vec![];
        if let (true, Some(perms)) = (scopes.iter().any(|s| s == "bot"), self.permissions) {
            additional.push(("permissions".to_owned(), perms.to_string()));
        }
        additional.extend(p.additional_params);
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://discord.com/api/oauth2/authorize".into(),
                scopes,
                state: p.state,
                redirect_uri: p.redirect_uri,
                prompt: Some(self.options.prompt.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "none".into())),
                additional_params: additional,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> Result<OAuth2Tokens> {
        let params = ValidateCodeParams { code_verifier: None, device_id: None, ..p };
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

    async fn get_user_info(&self, request: &UserInfoRequest) -> Result<Option<UserInfoResult>> {
        if let Some(r) = user_info_override(&self.options, request).await {
            return r;
        }
        let headers = [bearer(request.tokens.access_token.as_deref())];
        let Ok(mut profile) = get_json("https://discord.com/api/users/@me", &headers).await else {
            return Ok(None);
        };
        let image = avatar_url(&profile);
        profile["image_url"] = image.clone().into();
        let name = str_of(&profile, "global_name")
            .filter(|n| !n.is_empty())
            .or_else(|| str_of(&profile, "username"))
            .unwrap_or_default();
        let user = OAuth2UserInfo {
            name: Some(name),
            email: str_of(&profile, "email"),
            image: Some(image),
            email_verified: profile.get("verified").and_then(Value::as_bool).unwrap_or(false),
            extra: Default::default(),
        };
        Ok(finish(&self.options, profile, user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn avatars() {
        assert_eq!(
            avatar_url(&json!({"id": "1", "avatar": "a_abc"})),
            "https://cdn.discordapp.com/avatars/1/a_abc.gif"
        );
        assert_eq!(
            avatar_url(&json!({"id": "80351110224678912", "avatar": null, "discriminator": "0"})),
            format!("https://cdn.discordapp.com/embed/avatars/{}.png", (80351110224678912u64 >> 22) % 6)
        );
        assert_eq!(
            avatar_url(&json!({"id": "1", "avatar": null, "discriminator": "1337"})),
            "https://cdn.discordapp.com/embed/avatars/2.png"
        );
    }
}
