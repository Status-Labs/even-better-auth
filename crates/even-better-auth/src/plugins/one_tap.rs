//! Google One Tap (`plugins/one-tap`): `POST /one-tap/callback` signs in with the ID token the
//! One Tap prompt hands the browser, resolving the account through the same path as the
//! redirect flow (the account owning the Google `sub` wins).

use std::any::Any;
use std::sync::Arc;

use http::StatusCode;
use jsonwebtoken::Algorithm;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::error::{ApiError, codes};
use crate::oauth2::link_account::{HandleOAuthUserInfo, OAuthAccountData, error_codes, handle_oauth_user_info};
use crate::oauth2::{
    IdTokenConfig, JwksIdTokenConfig, JwksSource, OAuth2UserInfo, OAuthProvider, decode_jwt_payload, verify_jwt,
    verify_provider_id_token,
};
use crate::plugin::Plugin;
use crate::social_providers::{Google, is_hosted_domain_allowed};

#[derive(Debug, Clone, Default)]
pub struct OneTapOptions {
    /// Refuse to create users (existing users still sign in).
    pub disable_signup: bool,
    /// Expected audience; defaults to the Google provider's client id.
    pub client_id: Option<String>,
}

fn bad(message: &str) -> ApiError {
    ApiError::message(StatusCode::BAD_REQUEST, message)
}

fn google_config(audience: Vec<String>) -> JwksIdTokenConfig {
    let mut config =
        JwksIdTokenConfig::new(JwksSource::Url("https://www.googleapis.com/oauth2/v3/certs".into()), audience);
    config.issuer = vec!["https://accounts.google.com".into(), "accounts.google.com".into()];
    config.algorithms = vec![Algorithm::RS256];
    config
}

/// Verify the token's signature, issuer and audience.
async fn verify(provider: Option<&dyn OAuthProvider>, client_id: Option<&str>, token: &str) -> Result<bool, ApiError> {
    let audience: Vec<String> = match (client_id, provider) {
        (Some(id), _) => vec![id.to_owned()],
        (None, Some(p)) => p.options().client_ids(),
        (None, None) => vec![],
    };
    // Fail closed: without an audience, a token minted for any Google client would pass.
    if audience.is_empty() {
        return Err(bad(
            "Google client ID is required for One Tap. Set it on the oneTap plugin (clientId) or on socialProviders.google.",
        ));
    }
    if let Some(p) = provider
        && client_id.is_none()
    {
        return Ok(verify_provider_id_token(p, token, None).await);
    }
    let config = match provider.and_then(|p| p.id_token()) {
        Some(IdTokenConfig::Jwks(mut config)) => {
            config.audience = audience;
            config
        }
        _ => google_config(audience),
    };
    Ok(verify_jwt(token, &config, None).await.is_ok())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallbackBody {
    id_token: String,
    #[serde(rename = "callbackURL")]
    #[allow(dead_code)]
    callback_url: Option<String>,
}

fn to_boolean(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

async fn one_tap_callback(options: Arc<OneTapOptions>, ctx: Ctx) -> EndpointResult {
    let body: CallbackBody = ctx.parse_body()?;
    let provider = ctx.auth.options.social_providers.iter().find(|p| p.id() == "google").cloned();
    if !verify(provider.as_deref(), options.client_id.as_deref(), &body.id_token).await? {
        return Err(bad("invalid id token"));
    }
    let Some(payload) = decode_jwt_payload(&body.id_token) else { return Err(bad("invalid id token")) };
    let sub = payload.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
    let Some(sub) = sub else { return Err(bad("invalid id token")) };
    let hd =
        provider.as_ref().and_then(|p| p.as_any()).and_then(|a| a.downcast_ref::<Google>()).and_then(|g| g.hd.clone());
    if !is_hosted_domain_allowed(hd.as_deref(), payload.get("hd")) {
        tracing::error!(
            "Google One Tap sign-in rejected: id token hosted domain (hd) {:?} does not satisfy the configured \"hd\" option {:?}.",
            payload.get("hd"),
            hd
        );
        return Err(bad("invalid id token"));
    }
    let Some(email) = payload.get("email").and_then(Value::as_str).filter(|e| !e.is_empty()) else {
        return Err(bad("Email not available in token"));
    };
    let user_info = OAuth2UserInfo {
        name: Some(payload.get("name").and_then(Value::as_str).unwrap_or_default().to_owned()),
        email: Some(email.to_lowercase()),
        image: payload.get("picture").and_then(Value::as_str).map(str::to_owned),
        email_verified: to_boolean(payload.get("email_verified")),
        extra: Default::default(),
    };
    let disable_sign_up = options.disable_signup || provider.as_ref().is_some_and(|p| p.options().disable_sign_up);
    let outcome = handle_oauth_user_info(
        &ctx,
        HandleOAuthUserInfo {
            user_info,
            account: OAuthAccountData {
                provider_id: "google".into(),
                account_id: sub,
                id_token: Some(body.id_token.clone()),
                scope: Some("openid,profile,email".into()),
                ..Default::default()
            },
            callback_url: None,
            disable_sign_up,
            override_user_info: false,
            is_trusted_provider: false,
            profile: Some(Value::Object(payload)),
        },
    )
    .await?;
    if let Some(error) = outcome.error {
        if error == error_codes::EMAIL_NOT_VERIFIED {
            return Err(ApiError::forbidden(codes::EMAIL_NOT_VERIFIED));
        }
        return Err(ApiError::message(StatusCode::UNAUTHORIZED, &error));
    }
    let data = outcome.data.expect("session on success");
    set_session_cookie(&ctx, &data, None, None).await;
    ctx.json(json!({ "token": data.session.token, "user": ctx.auth.user_output(&data.user) }))
}

pub struct OneTap {
    options: Arc<OneTapOptions>,
}

pub fn one_tap(options: OneTapOptions) -> Arc<dyn Plugin> {
    Arc::new(OneTap { options: Arc::new(options) })
}

impl Plugin for OneTap {
    fn id(&self) -> &str {
        "one-tap"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let options = self.options.clone();
        vec![Endpoint::post(
            "oneTapCallback",
            "/one-tap/callback",
            handler(move |ctx| one_tap_callback(options.clone(), ctx)),
        )]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
