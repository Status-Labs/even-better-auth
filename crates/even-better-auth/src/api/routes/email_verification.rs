//! Email verification (`api/routes/email-verification.ts`).

use std::time::{Duration, Instant};

use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::api::middleware::{check_callback_urls, get_session_from_ctx};
use crate::api::routes::session::GetSessionOptions;
use crate::api::routes::util::append_query_params;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::crypto::sign_jwt;
use crate::db::Record;
use crate::error::{ApiError, ErrorCode, codes};
use crate::options::UserTokenEmail;
use crate::types::{SessionWithUser, User};
use crate::utils::url::encode_uri_component;

/// Create a signed verification JWT carrying `email` (and optionally `updateTo`).
pub fn create_email_verification_token(
    secret: &str,
    email: &str,
    update_to: Option<&str>,
    expires_in: i64,
    extra: Option<Map<String, Value>>,
) -> Result<String, ApiError> {
    let mut payload = Map::new();
    payload.insert("email".into(), email.to_lowercase().into());
    if let Some(u) = update_to {
        payload.insert("updateTo".into(), u.to_lowercase().into());
    }
    if let Some(extra) = extra {
        payload.extend(extra);
    }
    Ok(sign_jwt(&payload, secret, expires_in)?)
}

/// `{baseURL}/verify-email?token=...&callbackURL=...`
pub fn verification_url(ctx: &EndpointContext, token: &str, callback_url: Option<&str>) -> String {
    format!(
        "{}/verify-email?token={token}&callbackURL={}",
        ctx.base_url,
        encode_uri_component(callback_url.unwrap_or("/"))
    )
}

fn request_headers(ctx: &EndpointContext) -> Option<http::HeaderMap> {
    ctx.is_request.then(|| ctx.headers())
}

/// Send a verification email to `user` (`sendVerificationEmailFn`).
pub async fn send_verification_email_fn(
    ctx: &EndpointContext,
    user: &User,
    callback_url: Option<&str>,
) -> Result<(), ApiError> {
    let opts = &ctx.auth.options.email_verification;
    let Some(send) = &opts.send_verification_email else {
        tracing::error!("Verification email isn't enabled.");
        return Err(ApiError::bad_request(codes::VERIFICATION_EMAIL_NOT_ENABLED));
    };
    let token = create_email_verification_token(&ctx.auth.secret, &user.email, None, opts.expires_in, None)?;
    let url = verification_url(ctx, &token, callback_url);
    send.call(UserTokenEmail { user: user.clone(), url, token, request_headers: request_headers(ctx) }).await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendVerificationBody {
    email: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

async fn send_verification_email(ctx: Ctx) -> EndpointResult {
    if ctx.auth.options.email_verification.send_verification_email.is_none() {
        tracing::error!("Verification email isn't enabled.");
        return Err(ApiError::bad_request(codes::VERIFICATION_EMAIL_NOT_ENABLED));
    }
    let body: SendVerificationBody = ctx.parse_body()?;
    if !super::util::is_valid_email(&body.email) {
        return Err(ApiError::bad_request(codes::INVALID_EMAIL));
    }
    let session = get_session_from_ctx(&ctx, GetSessionOptions::default()).await?;
    let Some(session) = session else {
        // Enforce a constant-time floor so response times don't reveal whether the
        // email exists and is unverified.
        let start = Instant::now();
        let user = ctx.auth.internal_adapter.find_user_by_email(&body.email).await?;
        let result = match user {
            Some(u) if !u.email_verified => send_verification_email_fn(&ctx, &u, body.callback_url.as_deref()).await,
            _ => create_email_verification_token(
                &ctx.auth.secret,
                &body.email,
                None,
                ctx.auth.options.email_verification.expires_in,
                None,
            )
            .map(|_| ()),
        };
        let elapsed = start.elapsed();
        if elapsed < Duration::from_millis(500) {
            tokio::time::sleep(Duration::from_millis(500) - elapsed).await;
        }
        result?;
        return ctx.json(json!({ "status": true }));
    };
    if session.user.email.to_lowercase() != body.email.to_lowercase() {
        return Err(ApiError::bad_request(codes::EMAIL_MISMATCH));
    }
    if session.user.email_verified {
        return Err(ApiError::bad_request(codes::EMAIL_ALREADY_VERIFIED));
    }
    send_verification_email_fn(&ctx, &session.user, body.callback_url.as_deref()).await?;
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEmailClaims {
    email: String,
    update_to: Option<String>,
    request_type: Option<String>,
}

fn redirect_on_error(ctx: &EndpointContext, callback_url: Option<&str>, code: ErrorCode) -> EndpointResult {
    match callback_url {
        Some(cb) => ctx.redirect(append_query_params(cb, &[("error", code.code)])),
        None => Err(ApiError::unauthorized(code)),
    }
}

fn done(ctx: &EndpointContext, callback_url: Option<&str>, body: Value) -> EndpointResult {
    match callback_url {
        Some(cb) => ctx.redirect(cb),
        None => ctx.json(body),
    }
}

async fn ensure_session(
    ctx: &EndpointContext,
    session: Option<SessionWithUser>,
    user: &User,
) -> Result<SessionWithUser, ApiError> {
    if let Some(s) = session {
        return Ok(s);
    }
    let session = ctx.auth.internal_adapter.create_session(&user.id, false, None).await?;
    Ok(SessionWithUser { session, user: user.clone() })
}

async fn verify_email(ctx: Ctx) -> EndpointResult {
    let token = ctx.query_str("token").ok_or_else(|| ApiError::bad_request(codes::VALIDATION_ERROR))?;
    let callback_url = ctx.query_str("callbackURL");
    check_callback_urls(&ctx, std::slice::from_ref(&callback_url))?;
    let cb = callback_url.as_deref();
    let auth = ctx.auth.clone();
    let opts = &auth.options.email_verification;

    let claims = match decode_verification_jwt(&token, &auth.secret) {
        Ok(c) => c,
        Err(code) => return redirect_on_error(&ctx, cb, code),
    };
    let Some(user) = auth.internal_adapter.find_user_by_email(&claims.email).await? else {
        return redirect_on_error(&ctx, cb, codes::USER_NOT_FOUND);
    };
    let headers = request_headers(&ctx);

    if let Some(update_to) = &claims.update_to {
        let session = get_session_from_ctx(&ctx, GetSessionOptions::default()).await?;
        if session.as_ref().is_some_and(|s| s.user.email != claims.email) {
            return redirect_on_error(&ctx, cb, codes::INVALID_USER);
        }
        match claims.request_type.as_deref() {
            Some("change-email-confirmation") => {
                let mut extra = Map::new();
                extra.insert("requestType".into(), "change-email-verification".into());
                let new_token = create_email_verification_token(
                    &auth.secret,
                    &claims.email,
                    Some(update_to),
                    opts.expires_in,
                    Some(extra),
                )?;
                let url = verification_url(&ctx, &new_token, cb);
                if let Some(send) = &opts.send_verification_email {
                    let mut target = user.clone();
                    target.email = update_to.clone();
                    send.call(UserTokenEmail { user: target, url, token: new_token, request_headers: headers }).await?;
                }
                return done(&ctx, cb, json!({ "status": true }));
            }
            Some("change-email-verification") => {
                let active = ensure_session(&ctx, session, &user).await?;
                let mut update = Record::new();
                update.insert("email".into(), update_to.clone().into());
                update.insert("emailVerified".into(), true.into());
                let updated = auth
                    .internal_adapter
                    .update_user_by_email(&claims.email, update)
                    .await?
                    .ok_or_else(|| ApiError::bad_request(codes::USER_NOT_FOUND))?;
                if let Some(after) = &opts.after_email_verification {
                    after.call(updated.clone()).await?;
                }
                let mut u = active.user.clone();
                u.email = update_to.clone();
                u.email_verified = true;
                set_session_cookie(&ctx, &SessionWithUser { session: active.session, user: u }, None, None).await;
                return done(&ctx, cb, json!({ "status": true, "user": auth.user_output(&updated) }));
            }
            _ => {
                let active = ensure_session(&ctx, session, &user).await?;
                let mut update = Record::new();
                update.insert("email".into(), update_to.clone().into());
                update.insert("emailVerified".into(), false.into());
                let updated = auth
                    .internal_adapter
                    .update_user_by_email(&claims.email, update)
                    .await?
                    .ok_or_else(|| ApiError::bad_request(codes::USER_NOT_FOUND))?;
                let new_token = create_email_verification_token(&auth.secret, update_to, None, 3600, None)?;
                if let Some(send) = &opts.send_verification_email {
                    let url = verification_url(&ctx, &new_token, cb);
                    send.call(UserTokenEmail {
                        user: updated.clone(),
                        url,
                        token: new_token,
                        request_headers: headers,
                    })
                    .await?;
                }
                let mut u = active.user.clone();
                u.email = update_to.clone();
                u.email_verified = false;
                set_session_cookie(&ctx, &SessionWithUser { session: active.session, user: u }, None, None).await;
                return done(&ctx, cb, json!({ "status": true, "user": auth.user_output(&updated) }));
            }
        }
    }

    if user.email_verified {
        return done(&ctx, cb, json!({ "status": true, "user": null }));
    }
    if let Some(before) = &opts.before_email_verification {
        before.call(user.clone()).await?;
    }
    let mut update = Record::new();
    update.insert("emailVerified".into(), true.into());
    let updated = auth.internal_adapter.update_user_by_email(&claims.email, update).await?;
    if let (Some(after), Some(updated)) = (&opts.after_email_verification, &updated) {
        after.call(updated.clone()).await?;
    }
    if opts.auto_sign_in_after_verification {
        let current = get_session_from_ctx(&ctx, GetSessionOptions::default()).await?;
        match current.filter(|c| c.user.email == claims.email) {
            Some(c) => {
                let mut u = c.user.clone();
                u.email_verified = true;
                set_session_cookie(&ctx, &SessionWithUser { session: c.session, user: u }, None, None).await;
            }
            None => {
                let session = auth.internal_adapter.create_session(&user.id, false, None).await.map_err(|e| {
                    e.api_or(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, codes::FAILED_TO_CREATE_SESSION))
                })?;
                let mut u = user.clone();
                u.email_verified = true;
                set_session_cookie(&ctx, &SessionWithUser { session, user: u }, None, None).await;
            }
        }
    }
    done(&ctx, cb, json!({ "status": true, "user": null }))
}

fn decode_verification_jwt(token: &str, secret: &str) -> Result<VerifyEmailClaims, ErrorCode> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, errors::ErrorKind};
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.leeway = 0;
    match decode::<Map<String, Value>>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation) {
        Ok(data) => serde_json::from_value(Value::Object(data.claims))
            .ok()
            .filter(|c: &VerifyEmailClaims| super::util::is_valid_email(&c.email))
            .ok_or(codes::INVALID_TOKEN),
        Err(e) if matches!(e.kind(), ErrorKind::ExpiredSignature) => Err(codes::TOKEN_EXPIRED),
        Err(_) => Err(codes::INVALID_TOKEN),
    }
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![
        Endpoint::post("sendVerificationEmail", "/send-verification-email", handler(send_verification_email)),
        Endpoint::get("verifyEmail", "/verify-email", handler(verify_email)),
    ]
}
