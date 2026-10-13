//! Account endpoints (`api/routes/account.ts`).

use chrono::{DateTime, Utc};
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::sign_in::IdTokenBody;
use super::{additional_params, provider_not_found};
use crate::api::middleware::{get_session_from_ctx, require_fresh_session, require_session};
use crate::api::routes::session::GetSessionOptions;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::{bind_account_cookie_to_session_user, get_account_cookie, merged_account, set_account_cookie};
use crate::db::Record;
use crate::error::{ApiError, codes};
use crate::oauth2::link_account::{apply_update_user_info_on_link, decrypt_oauth_token, set_token_util};
use crate::oauth2::state::{GenerateStateOptions, LinkData, generate_id_token_nonce, generate_state};
use crate::oauth2::{
    AuthorizationUrlParams, OAuth2Tokens, OAuthProvider, UserInfoRequest, find_provider, oauth_callback_path,
    resolve_account_id, supports_id_token_sign_in, verify_provider_id_token,
};
use crate::types::{Account, Model};
use crate::utils::date;

fn parse_stored_scopes(scope: Option<&str>) -> Vec<String> {
    scope.unwrap_or_default().split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

async fn list_user_accounts(ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let accounts = ctx.auth.internal_adapter.find_accounts(&session.user.id).await?;
    let out: Vec<Value> = accounts
        .iter()
        .map(|a| {
            let mut parsed = ctx.auth.account_output(a);
            let scope = parsed.remove("scope");
            parsed.insert("scopes".into(), json!(parse_stored_scopes(scope.as_ref().and_then(Value::as_str))));
            Value::Object(parsed)
        })
        .collect();
    ctx.json(Value::Array(out))
}

#[derive(Deserialize)]
struct LinkSocialBody {
    provider: String,
    #[serde(rename = "idToken")]
    id_token: Option<IdTokenBody>,
    scopes: Option<Vec<String>>,
    #[serde(rename = "disableRedirect")]
    disable_redirect: Option<bool>,
    #[serde(rename = "loginHint")]
    login_hint: Option<String>,
    #[serde(rename = "additionalParams")]
    additional_params: Option<Map<String, Value>>,
    #[serde(rename = "additionalData")]
    additional_data: Option<Map<String, Value>>,
}

fn put_opt(r: &mut Record, key: &str, value: Option<String>) {
    if let Some(v) = value {
        r.insert(key.into(), v.into());
    }
}

async fn link_social_account(ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body: LinkSocialBody = ctx.parse_body()?;
    let extra_params = additional_params(body.additional_params.as_ref())?;
    let provider = find_provider(&ctx, &body.provider).ok_or_else(|| provider_not_found(&body.provider))?;
    let auth = ctx.auth.clone();

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
        let info = provider
            .get_user_info(&UserInfoRequest::from(tokens.clone()))
            .await?
            .ok_or_else(|| ApiError::unauthorized(codes::FAILED_TO_GET_USER_INFO))?;
        let Some(email) = info.user.email.clone().filter(|e| !e.is_empty()) else {
            tracing::error!(provider = body.provider, "Provider did not return an email in the id token");
            return Err(ApiError::unauthorized(codes::USER_EMAIL_NOT_FOUND));
        };
        let account_id = resolve_account_id(provider.as_ref(), &tokens, &info.data)
            .map_err(|_| ApiError::unauthorized(codes::FAILED_TO_GET_USER_INFO))?;
        let mut token_data = Record::new();
        token_data.insert("providerId".into(), provider.id().into());
        put_opt(&mut token_data, "accessToken", set_token_util(id_token.access_token.as_deref(), &auth)?);
        token_data.insert("idToken".into(), id_token.token.clone().into());
        put_opt(&mut token_data, "refreshToken", set_token_util(id_token.refresh_token.as_deref(), &auth)?);

        let linked = auth.internal_adapter.find_account_by_key(provider.id(), &account_id).await?;
        if let Some(linked) = &linked {
            if linked.user_id != session.user.id {
                return Err(ApiError::from_code(StatusCode::CONFLICT, codes::SOCIAL_ACCOUNT_ALREADY_LINKED));
            }
            auth.internal_adapter.update_account(&linked.id, token_data).await?;
            apply_update_user_info_on_link(&ctx, &session.user.id, &info.user).await;
            return ctx.json(json!({ "url": "", "status": true, "redirect": false }));
        }
        let linking = &auth.options.account.account_linking;
        let trusted = linking.trusted_providers.iter().any(|p| p == provider.id());
        if (!trusted && !info.user.email_verified) || !linking.enabled {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "LINKING_NOT_ALLOWED",
                "Account not linked - linking not allowed",
            ));
        }
        if email.to_lowercase() != session.user.email.to_lowercase() && !linking.allow_different_emails {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
                "Account not linked - different emails not allowed",
            ));
        }
        token_data.insert("userId".into(), session.user.id.clone().into());
        token_data.insert("accountId".into(), account_id.into());
        if auth.internal_adapter.create_account(token_data).await.is_err() {
            return Err(ApiError::new(
                StatusCode::EXPECTATION_FAILED,
                "LINKING_FAILED",
                "Account not linked - unable to create account",
            ));
        }
        apply_update_user_info_on_link(&ctx, &session.user.id, &info.user).await;
        return ctx.json(json!({ "url": "", "status": true, "redirect": false }));
    }

    let id_token_nonce = generate_id_token_nonce(provider.as_ref());
    let state = generate_state(
        &ctx,
        GenerateStateOptions {
            link: Some(LinkData { email: session.user.email.clone(), user_id: session.user.id.clone() }),
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

#[derive(Deserialize)]
struct UnlinkAccountBody {
    #[serde(rename = "accountId")]
    account_id: String,
}

async fn unlink_account(ctx: Ctx) -> EndpointResult {
    let session = require_fresh_session(&ctx).await?;
    let body: UnlinkAccountBody = ctx.parse_body()?;
    let accounts = ctx.auth.internal_adapter.find_accounts(&session.user.id).await?;
    if accounts.len() == 1 && !ctx.auth.options.account.account_linking.allow_unlinking_all {
        return Err(ApiError::bad_request(codes::FAILED_TO_UNLINK_LAST_ACCOUNT));
    }
    let Some(account) = accounts.iter().find(|a| a.id == body.account_id) else {
        return Err(ApiError::bad_request(codes::ACCOUNT_NOT_FOUND));
    };
    ctx.auth.internal_adapter.delete_account(&account.id).await?;
    ctx.json(json!({ "status": true }))
}

/// `{ accountId, userId? }` or `{ useAccountCookie: true, userId? }`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountSelection {
    #[serde(rename = "accountId")]
    account_id: Option<String>,
    #[serde(rename = "useAccountCookie")]
    use_account_cookie: Option<bool>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

impl AccountSelection {
    fn validate(self) -> Result<Self, ApiError> {
        let ok = matches!((&self.account_id, self.use_account_cookie), (Some(_), None) | (None, Some(true)));
        if !ok {
            return Err(ApiError::bad_request(codes::VALIDATION_ERROR)
                .with_field("message", "Expected either accountId or useAccountCookie: true"));
        }
        Ok(self)
    }

    fn from_query(ctx: &EndpointContext) -> Result<Self, ApiError> {
        let query = ctx.query();
        if let Some(k) = query.keys().find(|k| !matches!(k.as_str(), "accountId" | "useAccountCookie" | "userId")) {
            return Err(
                ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", format!("Unrecognized key: {k}"))
            );
        }
        Self {
            account_id: ctx.query_str("accountId"),
            use_account_cookie: ctx.query_str("useAccountCookie").map(|v| v == "true"),
            user_id: ctx.query_str("userId"),
        }
        .validate()
    }
}

/// The user an account-token operation acts on: the session user over HTTP, or an explicit
/// `userId` for trusted server calls (`resolveUserId`).
async fn resolve_user_id(ctx: &EndpointContext, user_id: Option<String>) -> Result<String, ApiError> {
    let session = get_session_from_ctx(
        ctx,
        GetSessionOptions { disable_cookie_cache: ctx.auth.is_stateful(), ..Default::default() },
    )
    .await?;
    if session.is_none() && (ctx.is_request || !ctx.headers().is_empty()) {
        return Err(ApiError::unauthenticated());
    }
    session.map(|s| s.user.id).or(user_id).ok_or_else(|| {
        ApiError::new(StatusCode::BAD_REQUEST, "USER_ID_OR_SESSION_REQUIRED", "Either userId or session is required")
    })
}

/// Resolve the account from exactly one explicit source: a local account id (database) or,
/// when the caller selects it, the signed account cookie. Returns whether it came from the
/// cookie.
async fn resolve_user_account(
    ctx: &EndpointContext,
    user_id: &str,
    selection: &AccountSelection,
) -> Result<(Account, bool), ApiError> {
    if let Some(account_id) = &selection.account_id {
        let accounts = ctx.auth.internal_adapter.find_accounts(user_id).await?;
        if let Some(a) = accounts.into_iter().find(|a| &a.id == account_id) {
            return Ok((a, false));
        }
    } else if ctx.auth.options.account.store_account_cookie
        && let Some(account) = get_account_cookie(ctx)
        && (!bind_account_cookie_to_session_user(ctx) || account.user_id == user_id)
    {
        return Ok((account, true));
    }
    Err(ApiError::bad_request(codes::ACCOUNT_NOT_FOUND))
}

fn provider_for(ctx: &EndpointContext, account: &Account) -> Result<std::sync::Arc<dyn OAuthProvider>, ApiError> {
    find_provider(ctx, &account.provider_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "PROVIDER_NOT_SUPPORTED",
            format!("Provider {} is not supported.", account.provider_id),
        )
    })
}

struct ValidAccessToken {
    access_token: String,
    access_token_expires_at: Option<DateTime<Utc>>,
    scopes: Vec<String>,
    id_token: Option<String>,
}

impl ValidAccessToken {
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("accessToken".into(), self.access_token.clone().into());
        if let Some(d) = self.access_token_expires_at {
            m.insert("accessTokenExpiresAt".into(), date::to_value(d));
        }
        m.insert("scopes".into(), json!(self.scopes));
        if let Some(t) = &self.id_token {
            m.insert("idToken".into(), t.clone().into());
        }
        Value::Object(m)
    }
}

/// A currently-valid access token, refreshed and persisted when within five seconds of
/// expiry (`getValidAccessToken`).
async fn get_valid_access_token(ctx: &EndpointContext, account: &Account) -> Result<ValidAccessToken, ApiError> {
    let provider = provider_for(ctx, account)?;
    let auth = &ctx.auth;
    let result: crate::error::Result<ValidAccessToken> = async {
        let mut new_tokens: Option<OAuth2Tokens> = None;
        let expired = account.access_token_expires_at.is_some_and(|e| (e - Utc::now()).num_milliseconds() < 5_000);
        if let (Some(refresh), true, true) = (&account.refresh_token, expired, provider.supports_refresh()) {
            let refresh_token = decrypt_oauth_token(refresh, auth)?;
            let tokens = provider.refresh_access_token(&refresh_token).await?;
            let mut update = Record::new();
            put_opt(&mut update, "accessToken", set_token_util(tokens.access_token.as_deref(), auth)?);
            if let Some(d) = tokens.access_token_expires_at {
                update.insert("accessTokenExpiresAt".into(), date::to_value(d));
            }
            let new_refresh = match &tokens.refresh_token {
                Some(r) => set_token_util(Some(r), auth)?,
                None => account.refresh_token.clone(),
            };
            put_opt(&mut update, "refreshToken", new_refresh);
            if let Some(d) = tokens.refresh_token_expires_at.or(account.refresh_token_expires_at) {
                update.insert("refreshTokenExpiresAt".into(), date::to_value(d));
            }
            put_opt(&mut update, "idToken", tokens.id_token.clone().or_else(|| account.id_token.clone()));
            let updated = auth.internal_adapter.update_account(&account.id, update.clone()).await?;
            if auth.options.account.store_account_cookie {
                let record = match updated {
                    Some(u) => merged_account(account, &u.to_record()),
                    None => merged_account(account, &update),
                };
                set_account_cookie(ctx, &record);
            }
            new_tokens = Some(tokens);
        }
        let access_token = match new_tokens.as_ref().and_then(|t| t.access_token.clone()) {
            Some(t) => t,
            None => decrypt_oauth_token(account.access_token.as_deref().unwrap_or_default(), auth)?,
        };
        Ok(ValidAccessToken {
            access_token,
            access_token_expires_at: new_tokens
                .as_ref()
                .and_then(|t| t.access_token_expires_at)
                .or(account.access_token_expires_at),
            scopes: parse_stored_scopes(account.scope.as_deref()),
            id_token: new_tokens.as_ref().and_then(|t| t.id_token.clone()).or_else(|| account.id_token.clone()),
        })
    }
    .await;
    result.map_err(|e| {
        tracing::error!(error = %e, "failed to get a valid access token");
        ApiError::new(StatusCode::BAD_REQUEST, "FAILED_TO_GET_ACCESS_TOKEN", "Failed to get a valid access token")
    })
}

async fn get_access_token(ctx: Ctx) -> EndpointResult {
    let selection = ctx.parse_body::<AccountSelection>()?.validate()?;
    let user_id = resolve_user_id(&ctx, selection.user_id.clone()).await?;
    let (account, _) = resolve_user_account(&ctx, &user_id, &selection).await?;
    let tokens = get_valid_access_token(&ctx, &account).await?;
    ctx.json(tokens.to_json())
}

fn opt_value(v: Option<String>) -> Value {
    v.map(Value::from).unwrap_or(Value::Null)
}

async fn refresh_token(ctx: Ctx) -> EndpointResult {
    let selection = ctx.parse_body::<AccountSelection>()?.validate()?;
    let user_id = resolve_user_id(&ctx, selection.user_id.clone()).await?;
    let (account, from_cookie) = resolve_user_account(&ctx, &user_id, &selection).await?;
    let provider = provider_for(&ctx, &account)?;
    if !provider.supports_refresh() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "TOKEN_REFRESH_NOT_SUPPORTED",
            format!("Provider {} does not support token refreshing.", account.provider_id),
        ));
    }
    let Some(stored_refresh) = account.refresh_token.clone() else {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "REFRESH_TOKEN_NOT_FOUND", "Refresh token not found"));
    };
    let auth = ctx.auth.clone();
    let result: crate::error::Result<Value> = async {
        let decrypted = decrypt_oauth_token(&stored_refresh, &auth)?;
        let tokens = provider.refresh_access_token(&decrypted).await?;
        let refresh_expires = tokens.refresh_token_expires_at.or(account.refresh_token_expires_at);
        let id_token = tokens.id_token.clone().filter(|t| !t.is_empty()).or_else(|| account.id_token.clone());
        let mut update = Record::new();
        put_opt(&mut update, "accessToken", set_token_util(tokens.access_token.as_deref(), &auth)?);
        let resolved_refresh = match &tokens.refresh_token {
            Some(r) => set_token_util(Some(r), &auth)?,
            None => Some(stored_refresh.clone()),
        };
        put_opt(&mut update, "refreshToken", resolved_refresh);
        if let Some(d) = tokens.access_token_expires_at {
            update.insert("accessTokenExpiresAt".into(), date::to_value(d));
        }
        if let Some(d) = refresh_expires {
            update.insert("refreshTokenExpiresAt".into(), date::to_value(d));
        }
        put_opt(&mut update, "idToken", id_token.clone());
        let updated = auth.internal_adapter.update_account(&account.id, update.clone()).await?;
        if from_cookie && auth.options.account.store_account_cookie {
            let record = match &updated {
                Some(u) => merged_account(&account, &u.to_record()),
                None => merged_account(&account, &update),
            };
            set_account_cookie(&ctx, &record);
        }
        let scope = updated.and_then(|u| u.scope).or_else(|| account.scope.clone());
        let mut out = Map::new();
        if let Some(t) = &tokens.access_token {
            out.insert("accessToken".into(), t.clone().into());
        }
        out.insert("refreshToken".into(), tokens.refresh_token.clone().unwrap_or(decrypted).into());
        if let Some(d) = tokens.access_token_expires_at {
            out.insert("accessTokenExpiresAt".into(), date::to_value(d));
        }
        out.insert("refreshTokenExpiresAt".into(), refresh_expires.map(date::to_value).unwrap_or(Value::Null));
        out.insert("scope".into(), opt_value(scope));
        out.insert("idToken".into(), opt_value(id_token));
        out.insert("providerId".into(), account.provider_id.clone().into());
        out.insert("accountId".into(), account.id.clone().into());
        Ok(Value::Object(out))
    }
    .await;
    match result {
        Ok(v) => ctx.json(v),
        Err(e) => {
            tracing::error!(error = %e, "failed to refresh access token");
            Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "FAILED_TO_REFRESH_ACCESS_TOKEN",
                "Failed to refresh access token",
            ))
        }
    }
}

async fn account_info(ctx: Ctx) -> EndpointResult {
    let selection = AccountSelection::from_query(&ctx)?;
    let user_id = resolve_user_id(&ctx, selection.user_id.clone()).await?;
    let (account, _) = resolve_user_account(&ctx, &user_id, &selection).await?;
    let Some(provider) = find_provider(&ctx, &account.provider_id) else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "PROVIDER_NOT_CONFIGURED",
            "Account is not associated with a configured social provider.",
        ));
    };
    let tokens = get_valid_access_token(&ctx, &account).await?;
    if tokens.access_token.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "ACCESS_TOKEN_NOT_FOUND", "Access token not found"));
    }
    let request = UserInfoRequest::from(OAuth2Tokens {
        access_token: Some(tokens.access_token.clone()),
        access_token_expires_at: tokens.access_token_expires_at,
        scopes: tokens.scopes.clone(),
        id_token: tokens.id_token.clone(),
        ..Default::default()
    });
    let info = provider
        .get_user_info(&request)
        .await?
        .ok_or_else(|| ApiError::unauthorized(codes::FAILED_TO_GET_USER_INFO))?;
    ctx.json(json!({
        "user": info.user.to_json(),
        "data": info.data,
        "account": { "id": account.id, "providerId": account.provider_id, "accountId": account.account_id },
    }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::get("listUserAccounts", "/list-accounts", handler(list_user_accounts)),
        Endpoint::post("linkSocialAccount", "/link-social", handler(link_social_account)),
        Endpoint::post("unlinkAccount", "/unlink-account", handler(unlink_account)),
        Endpoint::post("getAccessToken", "/get-access-token", handler(get_access_token)),
        Endpoint::post("refreshToken", "/refresh-token", handler(refresh_token)),
        Endpoint::get("accountInfo", "/account-info", handler(account_info)),
    ]
}
