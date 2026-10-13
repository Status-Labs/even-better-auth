//! `POST /sign-in/social` (`signInSocial` in `api/routes/sign-in.ts`).

use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::{additional_params, provider_not_found};
use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::error::{ApiError, codes};
use crate::oauth2::link_account::{HandleOAuthUserInfo, OAuthAccountData, error_codes, handle_oauth_user_info};
use crate::oauth2::state::{GenerateStateOptions, generate_id_token_nonce, generate_state};
use crate::oauth2::{
    AuthorizationUrlParams, OAuth2Tokens, UserInfoRequest, find_provider, oauth_callback_path, resolve_account_id,
    supports_id_token_sign_in, verify_provider_id_token,
};

#[derive(Deserialize)]
pub(super) struct IdTokenBody {
    pub token: String,
    pub nonce: Option<String>,
    #[serde(rename = "accessToken")]
    pub access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    pub refresh_token: Option<String>,
    pub user: Option<Value>,
}

#[derive(Deserialize)]
struct SocialSignInBody {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    provider: String,
    #[serde(rename = "disableRedirect")]
    disable_redirect: Option<bool>,
    #[serde(rename = "idToken")]
    id_token: Option<IdTokenBody>,
    scopes: Option<Vec<String>>,
    #[serde(rename = "requestSignUp")]
    request_sign_up: Option<bool>,
    #[serde(rename = "loginHint")]
    login_hint: Option<String>,
    #[serde(rename = "additionalParams")]
    additional_params: Option<Map<String, Value>>,
    #[serde(rename = "additionalData")]
    additional_data: Option<Map<String, Value>>,
}

async fn sign_in_social(ctx: Ctx) -> EndpointResult {
    let body: SocialSignInBody = ctx.parse_body()?;
    let extra_params = additional_params(body.additional_params.as_ref())?;
    let provider = find_provider(&ctx, &body.provider).ok_or_else(|| provider_not_found(&body.provider))?;

    if let Some(id_token) = &body.id_token {
        if !supports_id_token_sign_in(provider.as_ref()) {
            tracing::error!(provider = body.provider, "Provider does not support id token verification");
            return Err(ApiError::from_code(StatusCode::NOT_FOUND, codes::ID_TOKEN_NOT_SUPPORTED));
        }
        if !verify_provider_id_token(provider.as_ref(), &id_token.token, id_token.nonce.as_deref()).await {
            tracing::warn!(provider = body.provider, "Invalid id token");
            return Err(ApiError::unauthorized(codes::INVALID_TOKEN));
        }
        let tokens = OAuth2Tokens {
            id_token: Some(id_token.token.clone()),
            access_token: id_token.access_token.clone(),
            refresh_token: id_token.refresh_token.clone(),
            ..Default::default()
        };
        let request =
            UserInfoRequest { tokens: tokens.clone(), expected_id_token_nonce: None, user: id_token.user.clone() };
        let info = provider.get_user_info(&request).await?.ok_or_else(|| {
            tracing::error!(provider = body.provider, "Failed to get user info");
            ApiError::unauthorized(codes::FAILED_TO_GET_USER_INFO)
        })?;
        if info.user.email.as_deref().is_none_or(str::is_empty) {
            tracing::error!(provider = body.provider, "Provider did not return an email in the id token");
            return Err(ApiError::unauthorized(codes::USER_EMAIL_NOT_FOUND));
        }
        let account_id = resolve_account_id(provider.as_ref(), &tokens, &info.data)
            .map_err(|_| ApiError::unauthorized(codes::FAILED_TO_GET_USER_INFO))?;
        let options = provider.options();
        let outcome = handle_oauth_user_info(
            &ctx,
            HandleOAuthUserInfo {
                user_info: info.user,
                profile: Some(info.data),
                account: OAuthAccountData {
                    provider_id: provider.id().into(),
                    account_id,
                    access_token: id_token.access_token.clone(),
                    id_token: Some(id_token.token.clone()),
                    ..Default::default()
                },
                callback_url: body.callback_url.clone(),
                disable_sign_up: (options.disable_implicit_sign_up && body.request_sign_up != Some(true))
                    || options.disable_sign_up,
                override_user_info: false,
                is_trusted_provider: false,
            },
        )
        .await?;
        if let Some(error) = outcome.error {
            if error == error_codes::EMAIL_NOT_VERIFIED {
                return Err(ApiError::forbidden(codes::EMAIL_NOT_VERIFIED));
            }
            return Err(ApiError::new(StatusCode::UNAUTHORIZED, "OAUTH_LINK_ERROR", error));
        }
        let data = outcome.data.expect("session on success");
        set_session_cookie(&ctx, &data, None, None).await;
        return ctx.json(json!({
            "redirect": false,
            "token": data.session.token,
            "user": ctx.auth.user_output(&data.user),
        }));
    }

    let id_token_nonce = generate_id_token_nonce(provider.as_ref());
    let state = generate_state(
        &ctx,
        GenerateStateOptions {
            link: None,
            additional_data: body.additional_data.clone(),
            id_token_nonce: id_token_nonce.clone(),
        },
    )
    .await?;
    let url = provider
        .create_authorization_url(AuthorizationUrlParams {
            state: state.state,
            code_verifier: state.code_verifier,
            scopes: body.scopes.clone().unwrap_or_default(),
            redirect_uri: format!(
                "{}{}",
                crate::oauth2::state::oauth_base_url(&ctx),
                oauth_callback_path(provider.as_ref())
            ),
            display: None,
            login_hint: body.login_hint.clone(),
            id_token_nonce,
            additional_params: extra_params,
        })
        .await?
        .to_string();
    let redirect = !body.disable_redirect.unwrap_or(false);
    if redirect {
        ctx.set_header("location", &url);
    }
    ctx.json(json!({ "url": url, "redirect": redirect }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![Endpoint::post("signInSocial", "/sign-in/social", handler(sign_in_social))]
}
