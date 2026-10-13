//! Password reset and verification (`api/routes/password.ts`).

use http::StatusCode;
use serde::Deserialize;
use serde_json::json;

use super::util::{
    assert_password_length, assert_password_not_too_long, body_field_error, is_valid_email, resolve_url_with_params,
    run_or_log,
};
use crate::api::middleware::{check_callback_urls, require_sensitive_session};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::crypto::generate_id;
use crate::db::Record;
use crate::error::{ApiError, codes};
use crate::options::UserTokenEmail;
use crate::utils::date;

const RESET_MESSAGE: &str = "If this email exists in our system, check your email for the reset link";

fn reset_identifier(token: &str) -> String {
    format!("reset-password:{token}")
}

/// Set a user's credential password after a reset (`resetCredentialPassword`), revoking
/// their sessions when `revoke_sessions_on_password_reset` is enabled. `consume` spends the
/// single-use token first and fails if it is no longer valid.
pub async fn reset_credential_password<F>(
    ctx: &EndpointContext,
    user_id: &str,
    password_hash: &str,
    consume: Option<F>,
) -> Result<(), ApiError>
where
    F: std::future::Future<Output = Result<(), ApiError>>,
{
    // One transaction: a failure in any step leaves the token, sessions and password unchanged.
    ctx.auth
        .transaction(async {
            if let Some(consume) = consume {
                consume.await?;
            }
            let adapter = &ctx.auth.internal_adapter;
            if ctx.auth.options.email_and_password.revoke_sessions_on_password_reset {
                adapter.delete_user_sessions(user_id).await?;
            }
            if adapter.find_credential_account(user_id).await?.is_none() {
                let mut account = Record::new();
                account.insert("userId".into(), user_id.into());
                account.insert("providerId".into(), "credential".into());
                account.insert("accountId".into(), user_id.into());
                account.insert("password".into(), password_hash.into());
                adapter.create_account(account).await?;
                return Ok(());
            }
            adapter.update_password(user_id, password_hash).await?;
            Ok(())
        })
        .await
}

/// Require `password` to match the user's credential password (`checkPassword`), failing
/// with `INVALID_PASSWORD` otherwise (also when there is no credential account).
pub async fn check_password(ctx: &EndpointContext, user_id: &str, password: Option<&str>) -> Result<(), ApiError> {
    if let Some(password) = password {
        assert_password_not_too_long(ctx, password)?;
    }
    let account = ctx.auth.internal_adapter.find_credential_account(user_id).await?;
    let (Some(hash), Some(password)) = (account.and_then(|a| a.password), password) else {
        // Same error (and similar timing) as a failed verify, to avoid account enumeration.
        if let Some(password) = password {
            ctx.auth.hash_password(password).await?;
        }
        return Err(ApiError::bad_request(codes::INVALID_PASSWORD));
    };
    if !ctx.auth.verify_password(&hash, password).await? {
        return Err(ApiError::bad_request(codes::INVALID_PASSWORD));
    }
    Ok(())
}

/// Whether a password must be supplied (`shouldRequirePassword`): always, unless
/// `allow_passwordless` and the user has no credential password.
pub async fn should_require_password(
    ctx: &EndpointContext,
    user_id: &str,
    allow_passwordless: bool,
) -> Result<bool, ApiError> {
    if !allow_passwordless {
        return Ok(true);
    }
    let account = ctx.auth.internal_adapter.find_credential_account(user_id).await?;
    Ok(account.and_then(|a| a.password).is_some())
}

/// Whether `password` matches the user's credential password (`validatePassword`).
pub async fn validate_password(ctx: &EndpointContext, user_id: &str, password: &str) -> Result<bool, ApiError> {
    assert_password_not_too_long(ctx, password)?;
    let account = ctx.auth.internal_adapter.find_credential_account(user_id).await?;
    let Some(hash) = account.and_then(|a| a.password) else {
        return Ok(false);
    };
    Ok(ctx.auth.verify_password(&hash, password).await?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestResetBody {
    email: String,
    #[serde(rename = "redirectTo")]
    redirect_to: Option<String>,
}

async fn request_password_reset(ctx: Ctx) -> EndpointResult {
    let auth = ctx.auth.clone();
    let Some(send) = &auth.options.email_and_password.send_reset_password else {
        tracing::error!("Reset password isn't enabled. Set email_and_password.send_reset_password in your auth config");
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "RESET_PASSWORD_DISABLED", "Reset password isn't enabled"));
    };
    let body: RequestResetBody = ctx.parse_body()?;
    if !is_valid_email(&body.email) {
        return Err(body_field_error("email", "Invalid email address"));
    }
    let generic = json!({ "status": true, "message": RESET_MESSAGE });

    let Some(user) = auth.internal_adapter.find_user_by_email(&body.email).await? else {
        // Simulate token generation and the lookup so timing doesn't reveal the user's existence.
        let _ = generate_id(Some(24));
        auth.internal_adapter.find_verification_value("dummy-verification-token").await?;
        tracing::warn!("Reset Password: User not found");
        return ctx.json(generic);
    };
    let expires_in = match auth.options.email_and_password.reset_password_token_expires_in {
        0 => 60 * 60,
        n => n,
    };
    let token = generate_id(Some(24));
    auth.internal_adapter
        .create_verification_value(&reset_identifier(&token), &user.id, date::in_secs(expires_in))
        .await?;
    let callback_url = body.redirect_to.as_deref().map(crate::utils::url::encode_uri_component).unwrap_or_default();
    let url = format!("{}/reset-password/{token}?callbackURL={callback_url}", ctx.base_url);
    let request_headers = ctx.is_request.then(|| ctx.headers());
    run_or_log(send.call(UserTokenEmail { user, url, token, request_headers })).await;
    ctx.json(generic)
}

async fn request_password_reset_callback(ctx: Ctx) -> EndpointResult {
    let token = ctx.param("token").unwrap_or_default().to_owned();
    let Some(callback_url) = ctx.query_str("callbackURL") else {
        return Err(
            ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", "[query.callbackURL] Required")
        );
    };
    check_callback_urls(&ctx, &[Some(callback_url.clone())])?;
    let invalid = || resolve_url_with_params(&ctx.base_url, &callback_url, &[("error", "INVALID_TOKEN")]);
    if token.is_empty() || callback_url.is_empty() {
        let target = if callback_url.is_empty() {
            resolve_url_with_params(&ctx.base_url, &format!("{}/error", ctx.base_url), &[("error", "INVALID_TOKEN")])
        } else {
            invalid()
        };
        return ctx.redirect(target);
    }
    let verification = ctx.auth.internal_adapter.find_verification_value(&reset_identifier(&token)).await?;
    if verification.is_none_or(|v| v.expires_at < chrono::Utc::now()) {
        return ctx.redirect(invalid());
    }
    ctx.redirect(resolve_url_with_params(&ctx.base_url, &callback_url, &[("token", &token)]))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResetPasswordBody {
    new_password: String,
    token: Option<String>,
}

async fn reset_password(ctx: Ctx) -> EndpointResult {
    let body: ResetPasswordBody = ctx.parse_body()?;
    let token = body.token.filter(|t| !t.is_empty()).or_else(|| ctx.query_str("token").filter(|t| !t.is_empty()));
    let Some(token) = token else {
        return Err(ApiError::bad_request(codes::INVALID_TOKEN));
    };
    assert_password_length(&ctx, &body.new_password)?;

    let auth = ctx.auth.clone();
    let id = reset_identifier(&token);
    // Look the token up without spending it so a rejected password leaves the link usable;
    // it is consumed just before the password is written.
    let verification = auth.internal_adapter.find_verification_value(&id).await?;
    let Some(verification) = verification.filter(|v| v.expires_at >= chrono::Utc::now()) else {
        return Err(ApiError::bad_request(codes::INVALID_TOKEN));
    };
    let user_id = verification.value;
    let Some(user) = auth.internal_adapter.find_user_by_id(&user_id).await? else {
        return Err(ApiError::bad_request(codes::USER_NOT_FOUND));
    };
    let hash = auth.hash_password(&body.new_password).await?;
    let consume = async {
        // Consuming is the single-winner gate between concurrent resets with the same token.
        match auth.internal_adapter.consume_verification_value(&id).await? {
            Some(_) => Ok(()),
            None => Err(ApiError::bad_request(codes::INVALID_TOKEN)),
        }
    };
    reset_credential_password(&ctx, &user_id, &hash, Some(consume)).await?;

    if let Some(cb) = &auth.options.email_and_password.on_password_reset {
        cb.call(user).await?;
    }
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
struct VerifyPasswordBody {
    password: String,
}

async fn verify_password(ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let body: VerifyPasswordBody = ctx.parse_body()?;
    if !validate_password(&ctx, &session.user.id, &body.password).await? {
        return Err(ApiError::bad_request(codes::INVALID_PASSWORD));
    }
    ctx.json(json!({ "status": true }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::post("requestPasswordReset", "/request-password-reset", handler(request_password_reset)),
        Endpoint::get(
            "requestPasswordResetCallback",
            "/reset-password/:token",
            handler(request_password_reset_callback),
        ),
        Endpoint::post("resetPassword", "/reset-password", handler(reset_password)),
        Endpoint::post("verifyPassword", "/verify-password", handler(verify_password)),
    ]
}
