//! User updates, password changes, account deletion and email changes
//! (`api/routes/update-user.ts`).

use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::email_verification::{create_email_verification_token, verification_url};
use super::session::GetSessionOptions;
use super::sign_up::CORE_FIELDS;
use super::util::{assert_password_length, assert_password_not_too_long, body_field_error, is_valid_email, run_or_log};
use crate::api::middleware::{check_callback_urls, get_session_from_ctx, require_sensitive_session, require_session};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::{delete_session_cookie, set_session_cookie};
use crate::crypto::random_string;
use crate::db::{InputAction, Record, parse_input};
use crate::error::{ApiError, codes};
use crate::options::{ChangeEmailArgs, UserTokenEmail};
use crate::types::{Model, SessionWithUser, User};
use crate::utils::date;

fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

fn request_headers(ctx: &EndpointContext) -> Option<http::HeaderMap> {
    ctx.is_request.then(|| ctx.headers())
}

fn credential_record(user_id: &str, hash: String) -> Record {
    let mut account = Record::new();
    account.insert("userId".into(), user_id.into());
    account.insert("providerId".into(), "credential".into());
    account.insert("accountId".into(), user_id.into());
    account.insert("password".into(), hash.into());
    account
}

async fn update_user(ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = match ctx.body() {
        Value::Null => Map::new(),
        Value::Object(m) => m,
        _ => return Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT)),
    };
    if body.get("email").is_some_and(is_truthy) {
        return Err(ApiError::bad_request(codes::EMAIL_CAN_NOT_BE_UPDATED));
    }
    let name = body.get("name").filter(|v| !v.is_null()).cloned();
    let image = body.get("image").cloned();
    let mut rest = body.clone();
    rest.remove("name");
    rest.remove("image");
    let user_table = ctx.auth.schema.table("user").expect("user table");
    let additional = parse_input(user_table, &rest, InputAction::Update, CORE_FIELDS)?;
    if name.is_none() && image.is_none() && additional.is_empty() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "No fields to update"));
    }

    let mut update: Record = Record::new();
    if let Some(name) = name {
        update.insert("name".into(), name);
    }
    if let Some(image) = image {
        update.insert("image".into(), image);
    }
    update.extend(additional);
    let updated = match ctx.auth.internal_adapter.update_user(&session.user.id, update.clone()).await? {
        Some(u) => u,
        None => {
            let mut merged = session.user.to_record();
            merged.extend(update);
            User::from_record(merged)?
        }
    };
    set_session_cookie(&ctx, &SessionWithUser { session: session.session, user: updated }, None, None).await;
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePasswordBody {
    new_password: String,
    current_password: String,
    revoke_other_sessions: Option<bool>,
}

async fn change_password(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let body: ChangePasswordBody = ctx.parse_body()?;
    assert_password_length(&ctx, &body.new_password)?;
    assert_password_not_too_long(&ctx, &body.current_password)?;
    let auth = ctx.auth.clone();
    let account = auth.internal_adapter.find_credential_account(&session.user.id).await?;
    let Some((account, current_hash)) = account.and_then(|a| a.password.clone().map(|p| (a, p))) else {
        return Err(ApiError::bad_request(codes::CREDENTIAL_ACCOUNT_NOT_FOUND));
    };
    let hash = auth.hash_password(&body.new_password).await?;
    if !auth.verify_password(&current_hash, &body.current_password).await? {
        return Err(ApiError::bad_request(codes::INVALID_PASSWORD));
    }
    // Revoke before writing, in one transaction, so a failure never commits the new password
    // while the other sessions stay valid.
    let revoke = body.revoke_other_sessions == Some(true);
    let created = auth
        .transaction(async {
            if revoke {
                auth.internal_adapter.delete_user_sessions(&session.user.id).await?;
            }
            let mut update = Record::new();
            update.insert("password".into(), hash.into());
            auth.internal_adapter.update_account(&account.id, update).await?;
            if !revoke {
                return Ok(None);
            }
            let created = auth.internal_adapter.create_session(&session.user.id, false, None).await.map_err(|e| {
                e.api_or(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, codes::FAILED_TO_GET_SESSION))
            })?;
            Ok::<_, ApiError>(Some(created))
        })
        .await?;
    let mut token = Value::Null;
    if let Some(created) = created {
        token = created.token.clone().into();
        set_session_cookie(&ctx, &SessionWithUser { session: created, user: session.user.clone() }, None, None).await;
    }
    ctx.json(json!({ "token": token, "user": auth.user_output(&session.user) }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetPasswordBody {
    new_password: String,
}

async fn set_password(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let body: SetPasswordBody = ctx.parse_body()?;
    assert_password_length(&ctx, &body.new_password)?;
    let auth = ctx.auth.clone();
    let account = auth.internal_adapter.find_credential_account(&session.user.id).await?;
    let hash = auth.hash_password(&body.new_password).await?;
    match account {
        None => {
            auth.internal_adapter.link_account(credential_record(&session.user.id, hash)).await?;
        }
        Some(a) if a.password.is_none() => {
            let mut update = Record::new();
            update.insert("password".into(), hash.into());
            auth.internal_adapter.update_account(&a.id, update).await?;
        }
        Some(_) => return Err(ApiError::bad_request(codes::PASSWORD_ALREADY_SET)),
    }
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
struct DeleteUserBody {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    password: Option<String>,
    token: Option<String>,
}

async fn finish_delete(ctx: &EndpointContext, user: &User) -> Result<(), ApiError> {
    let opts = &ctx.auth.options.user.delete_user;
    if let Some(before) = &opts.before_delete {
        before.call(user.clone()).await?;
    }
    ctx.auth.internal_adapter.delete_user(&user.id).await?;
    delete_session_cookie(ctx, false);
    if let Some(after) = &opts.after_delete {
        after.call(user.clone()).await?;
    }
    Ok(())
}

/// Complete a deletion with a delete-account token (`deleteUserCallback`).
async fn delete_with_token(ctx: &EndpointContext, token: &str) -> Result<(), ApiError> {
    // Bypass the cookie cache so a revoked-but-cached session cannot complete the deletion.
    let session = get_session_from_ctx(
        ctx,
        GetSessionOptions { disable_cookie_cache: ctx.auth.is_stateful(), ..Default::default() },
    )
    .await?
    .ok_or_else(|| ApiError::not_found(codes::FAILED_TO_GET_USER_INFO))?;
    // Consume before any destructive work so concurrent callbacks delete only once.
    let consumed = ctx.auth.internal_adapter.consume_verification_value(&format!("delete-account-{token}")).await?;
    if consumed.is_none_or(|v| v.value != session.user.id) {
        return Err(ApiError::not_found(codes::INVALID_TOKEN));
    }
    finish_delete(ctx, &session.user).await
}

async fn delete_user(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let body: DeleteUserBody = ctx.parse_body()?;
    let auth = ctx.auth.clone();
    let opts = &auth.options.user.delete_user;
    if !opts.enabled {
        tracing::error!("Delete user is disabled. Enable it in the options");
        return Err(ApiError::status(StatusCode::NOT_FOUND));
    }
    let password = body.password.filter(|p| !p.is_empty());
    if let Some(password) = &password {
        assert_password_not_too_long(&ctx, password)?;
        let account = auth.internal_adapter.find_credential_account(&session.user.id).await?;
        let Some(hash) = account.and_then(|a| a.password) else {
            return Err(ApiError::bad_request(codes::CREDENTIAL_ACCOUNT_NOT_FOUND));
        };
        if !auth.verify_password(&hash, password).await? {
            return Err(ApiError::bad_request(codes::INVALID_PASSWORD));
        }
    }

    if let Some(token) = body.token.filter(|t| !t.is_empty()) {
        delete_with_token(&ctx, &token).await?;
        return ctx.json(json!({ "success": true, "message": "User deleted" }));
    }

    if let Some(send) = &opts.send_delete_account_verification {
        let token = random_string(32, b"0123456789abcdefghijklmnopqrstuvwxyz");
        let expires_in = opts.delete_token_expires_in.filter(|n| *n != 0).unwrap_or(60 * 60 * 24);
        auth.internal_adapter
            .create_verification_value(&format!("delete-account-{token}"), &session.user.id, date::in_secs(expires_in))
            .await?;
        let url = format!(
            "{}/delete-user/callback?token={token}&callbackURL={}",
            ctx.base_url,
            crate::utils::url::encode_uri_component(
                body.callback_url.as_deref().filter(|c| !c.is_empty()).unwrap_or("/")
            )
        );
        let email = UserTokenEmail { user: session.user.clone(), url, token, request_headers: request_headers(&ctx) };
        run_or_log(send.call(email)).await;
        return ctx.json(json!({ "success": true, "message": "Verification email sent" }));
    }

    let fresh_age = auth.options.session.fresh_age;
    if password.is_none() && fresh_age != 0 {
        let age = chrono::Utc::now() - session.session.created_at;
        if age.num_milliseconds() >= fresh_age * 1000 {
            return Err(ApiError::bad_request(codes::SESSION_EXPIRED));
        }
    }
    finish_delete(&ctx, &session.user).await?;
    ctx.json(json!({ "success": true, "message": "User deleted" }))
}

async fn delete_user_callback(ctx: Ctx) -> EndpointResult {
    let Some(token) = ctx.query_str("token") else {
        return Err(ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", "[query.token] Required"));
    };
    let callback_url = ctx.query_str("callbackURL");
    check_callback_urls(&ctx, std::slice::from_ref(&callback_url))?;
    if !ctx.auth.options.user.delete_user.enabled {
        tracing::error!("Delete user is disabled. Enable it in the options");
        return Err(ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND", "Not found"));
    }
    delete_with_token(&ctx, &token).await?;
    match callback_url.filter(|c| !c.is_empty()) {
        Some(cb) => ctx.redirect(cb),
        None => ctx.json(json!({ "success": true, "message": "User deleted" })),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailBody {
    new_email: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

async fn change_email(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let body: ChangeEmailBody = ctx.parse_body()?;
    if !is_valid_email(&body.new_email) {
        return Err(body_field_error("newEmail", "Invalid email address"));
    }
    let auth = ctx.auth.clone();
    let opts = &auth.options.user.change_email;
    if !opts.enabled {
        tracing::error!("Change email is disabled.");
        return Err(ApiError::bad_request(codes::CHANGE_EMAIL_DISABLED));
    }
    let new_email = body.new_email.to_lowercase();
    if new_email == session.user.email {
        tracing::warn!("Email is the same");
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Email is the same"));
    }

    // Fail early if no flow is available, so existing and new emails get the same error
    // and the response doesn't reveal whether the email is taken.
    let ev = &auth.options.email_verification;
    let can_update_without_verification = !session.user.email_verified && opts.update_email_without_verification;
    let send_verification = ev.send_verification_email.as_ref();
    let send_confirmation = opts
        .send_change_email_confirmation
        .as_ref()
        .filter(|_| send_verification.is_some() && session.user.email_verified);
    if !can_update_without_verification && send_confirmation.is_none() && send_verification.is_none() {
        tracing::error!("Verification email isn't enabled.");
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Verification email isn't enabled"));
    }

    if auth.internal_adapter.find_user_by_email(&new_email).await?.is_some() {
        // Simulate token generation so timing doesn't reveal that the email exists.
        create_email_verification_token(&auth.secret, &session.user.email, Some(&new_email), ev.expires_in, None)?;
        tracing::info!("Change email attempt for existing email");
        return ctx.json(json!({ "status": true }));
    }

    let callback_url = body.callback_url.as_deref().filter(|c| !c.is_empty());
    let mut target = session.user.clone();
    target.email = new_email.clone();

    if can_update_without_verification {
        let mut update = Record::new();
        update.insert("email".into(), new_email.clone().into());
        auth.internal_adapter.update_user(&session.user.id, update).await?;
        set_session_cookie(
            &ctx,
            &SessionWithUser { session: session.session.clone(), user: target.clone() },
            None,
            None,
        )
        .await;
        if let Some(send) = send_verification {
            let token = create_email_verification_token(&auth.secret, &new_email, None, ev.expires_in, None)?;
            let url = verification_url(&ctx, &token, callback_url);
            run_or_log(send.call(UserTokenEmail { user: target, url, token, request_headers: request_headers(&ctx) }))
                .await;
        }
        return ctx.json(json!({ "status": true }));
    }

    if let Some(send) = send_confirmation {
        let mut extra = Map::new();
        extra.insert("requestType".into(), "change-email-confirmation".into());
        let token = create_email_verification_token(
            &auth.secret,
            &session.user.email,
            Some(&new_email),
            ev.expires_in,
            Some(extra),
        )?;
        let url = verification_url(&ctx, &token, callback_url);
        let args = ChangeEmailArgs {
            user: session.user.clone(),
            new_email,
            url,
            token,
            request_headers: request_headers(&ctx),
        };
        run_or_log(send.call(args)).await;
        return ctx.json(json!({ "status": true }));
    }

    let Some(send) = send_verification else {
        tracing::error!("Verification email isn't enabled.");
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Verification email isn't enabled"));
    };
    let mut extra = Map::new();
    extra.insert("requestType".into(), "change-email-verification".into());
    let token = create_email_verification_token(
        &auth.secret,
        &session.user.email,
        Some(&new_email),
        ev.expires_in,
        Some(extra),
    )?;
    let url = verification_url(&ctx, &token, callback_url);
    run_or_log(send.call(UserTokenEmail { user: target, url, token, request_headers: request_headers(&ctx) })).await;
    ctx.json(json!({ "status": true }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::post("updateUser", "/update-user", handler(update_user)),
        Endpoint::post("changePassword", "/change-password", handler(change_password)),
        Endpoint::post("setPassword", "/set-password", handler(set_password)).server_only(),
        Endpoint::post("deleteUser", "/delete-user", handler(delete_user)),
        Endpoint::get("deleteUserCallback", "/delete-user/callback", handler(delete_user_callback)),
        Endpoint::post("changeEmail", "/change-email", handler(change_email)),
    ]
}
