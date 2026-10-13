//! Built-in social providers (`core/src/social-providers`).

mod apple;
mod atlassian;
mod cloudflare;
mod cognito;
mod discord;
mod dropbox;
mod facebook;
mod figma;
mod github;
mod gitlab;
mod google;
mod huggingface;
mod kakao;
mod kick;
mod line;
mod linear;
mod linkedin;
mod microsoft;
mod naver;
mod notion;
mod paybin;
mod paypal;
mod polar;
mod railway;
mod reddit;
mod roblox;
mod salesforce;
mod slack;
mod spotify;
mod tiktok;
mod twitch;
mod twitter;
mod vercel;
mod vk;
mod wechat;
mod zoom;

pub use apple::Apple;
pub use atlassian::Atlassian;
pub use cloudflare::{Cloudflare, CloudflareTokenAuth};
pub use cognito::Cognito;
pub use discord::Discord;
pub use dropbox::Dropbox;
pub use facebook::Facebook;
pub use figma::Figma;
pub use github::GitHub;
pub use gitlab::GitLab;
pub use google::{Google, is_hosted_domain_allowed};
pub use huggingface::HuggingFace;
pub use kakao::Kakao;
pub use kick::Kick;
pub use line::Line;
pub use linear::Linear;
pub use linkedin::LinkedIn;
pub use microsoft::Microsoft;
pub use naver::Naver;
pub use notion::Notion;
pub use paybin::Paybin;
pub use paypal::{PayPal, PayPalEnvironment};
pub use polar::Polar;
pub use railway::Railway;
pub use reddit::Reddit;
pub use roblox::Roblox;
pub use salesforce::{Salesforce, SalesforceEnvironment};
pub use slack::Slack;
pub use spotify::Spotify;
pub use tiktok::TikTok;
pub use twitch::Twitch;
pub use twitter::Twitter;
pub use vercel::Vercel;
pub use vk::Vk;
pub use wechat::WeChat;
pub use zoom::Zoom;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::oauth2::{OAuth2Tokens, OAuth2UserInfo, ProviderOptions, UserInfoRequest, UserInfoResult};

fn str_of(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// A string field that is present and non-empty (JS truthiness, for `a || b` fallbacks).
fn truthy_str(v: &Value, key: &str) -> Option<String> {
    str_of(v, key).filter(|s| !s.is_empty())
}

/// A boolean field, `false` when absent or not a boolean.
fn bool_of(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Run the `get_user_info` override, if configured.
async fn user_info_override(
    options: &ProviderOptions,
    request: &UserInfoRequest,
) -> Option<Result<Option<UserInfoResult>>> {
    let f = options.get_user_info.as_ref()?;
    Some(f(request.tokens.clone()).await)
}

/// Run the `refresh_access_token` override, if configured.
async fn refresh_override(options: &ProviderOptions, refresh_token: &str) -> Option<Result<OAuth2Tokens>> {
    let f = options.refresh_access_token.as_ref()?;
    Some(f(refresh_token.to_owned()).await)
}

/// Apply `map_profile_to_user` and pair the user with the raw profile.
fn finish(options: &ProviderOptions, profile: Value, user: OAuth2UserInfo) -> Option<UserInfoResult> {
    let user = options.map_profile(&profile, user);
    Some(UserInfoResult { user, data: profile })
}

fn require_client_credentials(provider: &str, options: &ProviderOptions, require_secret: bool) -> Result<()> {
    if options.client_id.is_empty() || (require_secret && options.client_secret.is_empty()) {
        tracing::error!(
            "Client Id and Client Secret are required for {provider}. Make sure to provide them in the options."
        );
        return Err(Error::Config("CLIENT_ID_AND_SECRET_REQUIRED".into()));
    }
    Ok(())
}

/// Reject a missing PKCE verifier for providers that require one.
fn require_code_verifier(provider: &str, code_verifier: &str) -> Result<()> {
    if code_verifier.is_empty() {
        return Err(Error::Config(format!("codeVerifier is required for {provider}")));
    }
    Ok(())
}

/// A stable, non-routable email for accounts without one (`createPlaceholderEmail`).
pub fn create_placeholder_email(identifier: &str, namespace: &str) -> String {
    format!("{identifier}@{namespace}.placeholder.invalid")
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared fixtures for provider unit tests (mirrors `social-providers.test.ts`).

    use std::collections::HashMap;

    use url::Url;

    use crate::oauth2::AuthorizationUrlParams;

    pub const CALLBACK: &str = "https://app.example/callback";
    pub const STATE: &str = "state-xyz";

    pub fn params() -> AuthorizationUrlParams {
        AuthorizationUrlParams {
            state: STATE.into(),
            code_verifier: "v".repeat(64),
            redirect_uri: CALLBACK.into(),
            ..Default::default()
        }
    }

    pub fn with_additional(pairs: &[(&str, &str)]) -> AuthorizationUrlParams {
        let mut p = params();
        p.additional_params = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        p
    }

    /// `origin + pathname` of a URL.
    pub fn endpoint(url: &Url) -> String {
        format!("{}{}", url.origin().ascii_serialization(), url.path())
    }

    pub fn query(url: &Url) -> HashMap<String, String> {
        url.query_pairs().into_owned().collect()
    }
}
