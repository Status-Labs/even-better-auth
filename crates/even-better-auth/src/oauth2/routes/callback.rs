//! `GET|POST /callback/:id` (`api/routes/callback.ts`).

use http::Method;
use serde_json::Value;

use crate::api::routes::util::append_query_params;
use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::oauth2::link_account::{
    HandleOAuthUserInfo, OAuthAccountData, error_codes, handle_oauth_user_info, link_oauth_account,
};
use crate::oauth2::state::{
    GenerateStateOptions, default_error_url, generate_id_token_nonce, generate_state, parse_state, redirect_on_error,
};
use crate::oauth2::{
    AuthorizationUrlParams, UserInfoRequest, ValidateCodeParams, find_provider, oauth_callback_path, resolve_account_id,
};

const CALLBACK_FIELDS: &[&str] = &["code", "error", "device_id", "error_description", "state", "user", "iss"];

fn field(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

async fn callback(ctx: Ctx) -> EndpointResult {
    let default_error = default_error_url(&ctx);
    let id = ctx.param("id").unwrap_or_default().to_owned();

    // Re-issue form posts (response_mode=form_post) as a GET so SameSite=Lax cookies are sent.
    if ctx.method == Method::POST {
        let body = ctx.body();
        let query = Value::Object(ctx.query());
        let params: Vec<(&str, String)> = CALLBACK_FIELDS
            .iter()
            .filter_map(|k| field(&query, k).or_else(|| field(&body, k)).map(|v| (*k, v)))
            .collect();
        let encoded = serde_urlencoded::to_string(&params).unwrap_or_default();
        return ctx.redirect(format!("{}/callback/{id}?{encoded}", ctx.base_url));
    }

    let query = Value::Object(ctx.query());
    let get = |k: &str| field(&query, k);
    let (code, error, state) = (get("code"), get("error"), get("state"));

    if state.is_none()
        && code.is_some()
        && let Some(provider) = find_provider(&ctx, &id).filter(|p| p.allow_idp_initiated())
    {
        let id_token_nonce = generate_id_token_nonce(provider.as_ref());
        let fresh =
            generate_state(&ctx, GenerateStateOptions { id_token_nonce: id_token_nonce.clone(), ..Default::default() })
                .await?;
        let url = provider
            .create_authorization_url(AuthorizationUrlParams {
                state: fresh.state,
                code_verifier: fresh.code_verifier,
                redirect_uri: format!("{}{}", ctx.base_url, oauth_callback_path(provider.as_ref())),
                id_token_nonce,
                ..Default::default()
            })
            .await?;
        return ctx.redirect(url.to_string());
    }
    if state.is_none() {
        tracing::error!(error = ?error, "State not found");
        return ctx.redirect(append_query_params(&default_error, &[("error", "state_not_found")]));
    }

    let parsed = parse_state(&ctx).await?;
    let error_url = parsed.error_url.clone().unwrap_or(default_error);
    let fail = |code: &str, description: Option<&str>| -> EndpointResult {
        Err(redirect_on_error(&error_url, code, description))
    };

    if let Some(error) = &error {
        return fail(error, get("error_description").as_deref());
    }
    let Some(code) = code else {
        tracing::warn!("Code not found");
        return fail(error_codes::NO_CODE, None);
    };
    let Some(provider) = find_provider(&ctx, &id) else {
        tracing::warn!(provider_id = id, "OAuth provider not found");
        return fail(error_codes::PROVIDER_NOT_FOUND, None);
    };
    if let (Some(iss), Some(expected)) = (get("iss"), provider.issuer())
        && iss != expected
    {
        tracing::error!(expected, received = iss, "OAuth issuer mismatch");
        return fail(error_codes::ISSUER_MISMATCH, None);
    }
    if provider.requires_id_token_nonce() && parsed.id_token_nonce.is_none() {
        tracing::error!(
            provider_id = id,
            "OAuth id_token nonce binding required but no expected nonce was found in state"
        );
        return fail(error_codes::NONCE_BINDING_MISSING, None);
    }

    let redirect_uri = format!("{}{}", ctx.base_url, oauth_callback_path(provider.as_ref()));
    let tokens = match provider
        .validate_authorization_code(ValidateCodeParams {
            code,
            redirect_uri,
            code_verifier: Some(parsed.code_verifier.clone()),
            device_id: get("device_id"),
        })
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "failed to validate authorization code");
            return fail(error_codes::INVALID_CODE, None);
        }
    };
    let user_data = get("user").and_then(|u| serde_json::from_str::<Value>(&u).ok());
    let request = UserInfoRequest {
        tokens: tokens.clone(),
        expected_id_token_nonce: parsed.id_token_nonce.clone(),
        user: user_data,
    };
    let info = match provider.get_user_info(&request).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            tracing::error!("Unable to get user info");
            return fail(error_codes::UNABLE_TO_GET_USER_INFO, None);
        }
        Err(e) => {
            tracing::error!(error = %e, "Unable to get user info");
            return fail(error_codes::UNABLE_TO_GET_USER_INFO, None);
        }
    };
    let Ok(account_id) = resolve_account_id(provider.as_ref(), &tokens, &info.data) else {
        tracing::error!(provider_id = id, "Unable to derive provider account identity");
        return fail(error_codes::UNABLE_TO_GET_USER_INFO, None);
    };
    let callback_url = parsed.callback_url.clone();
    if callback_url.is_empty() {
        tracing::error!("No callback URL found");
        return fail(error_codes::NO_CALLBACK_URL, None);
    }
    let account = OAuthAccountData::from_tokens(provider.id(), &account_id, &tokens);

    if let Some(link) = &parsed.link {
        return match link_oauth_account(&ctx, link, &info.user, &account, &tokens.scopes, Some(info.data.clone()))
            .await?
        {
            Ok(()) => ctx.redirect(callback_url),
            Err(f) => fail(&f.code, f.message.as_deref()),
        };
    }

    if info.user.email.as_deref().is_none_or(str::is_empty) {
        tracing::error!(
            "Provider \"{id}\" did not return an email. Either request the provider's email scope, or create a placeholder via `mapProfileToUser`."
        );
        return fail(error_codes::EMAIL_NOT_FOUND, None);
    }
    let options = provider.options();
    let outcome = handle_oauth_user_info(
        &ctx,
        HandleOAuthUserInfo {
            user_info: info.user,
            profile: Some(info.data),
            account,
            callback_url: Some(callback_url.clone()),
            disable_sign_up: (options.disable_implicit_sign_up && parsed.request_sign_up != Some(true))
                || options.disable_sign_up,
            override_user_info: options.override_user_info_on_sign_in,
            is_trusted_provider: false,
        },
    )
    .await;
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) if e.status.is_redirection() => return Err(e),
        Err(e) => match e.code().map(str::to_owned) {
            Some(code) => return fail(&code, e.message_str()),
            None => return Err(e),
        },
    };
    if let Some(error) = outcome.error {
        let code = error.replace(' ', "_");
        tracing::error!("{code}");
        return fail(&code, None);
    }
    let data = outcome.data.expect("session on success");
    set_session_cookie(&ctx, &data, None, None).await;
    let target = match (&outcome.is_register, &parsed.new_user_url) {
        (true, Some(new_user)) if !new_user.is_empty() => new_user.clone(),
        _ => callback_url,
    };
    ctx.redirect(target)
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::get("callbackOAuth", "/callback/:id", handler(callback))
            .methods(&[Method::GET, Method::POST])
            .allow_form(),
    ]
}
