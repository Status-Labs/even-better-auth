//! `POST /sign-in/email` (`api/routes/sign-in.ts`). Social sign-in lives in `oauth2::routes`.

use http::StatusCode;
use serde::Deserialize;
use serde_json::json;

use super::email_verification::{create_email_verification_token, verification_url};
use super::util::{assert_password_not_too_long, is_valid_email};
use crate::api::middleware::form_csrf;
use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::error::{ApiError, codes};
use crate::options::UserTokenEmail;
use crate::types::SessionWithUser;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInEmailBody {
    email: String,
    password: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    remember_me: Option<bool>,
}

async fn sign_in_email(ctx: Ctx) -> EndpointResult {
    form_csrf(&ctx)?;
    let auth = ctx.auth.clone();
    if !auth.options.email_and_password.enabled {
        tracing::error!("Email and password is not enabled");
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_DISABLED",
            "Email and password is not enabled",
        ));
    }
    let body: SignInEmailBody = ctx.parse_body()?;
    if !is_valid_email(&body.email) {
        return Err(ApiError::bad_request(codes::INVALID_EMAIL));
    }
    assert_password_not_too_long(&ctx, &body.password)?;

    let record = auth.internal_adapter.find_user_by_email_with_accounts(&body.email).await?;
    let found = record.and_then(|(user, accounts)| {
        let account = accounts.into_iter().find(|a| a.provider_id == "credential" && a.account_id == user.id)?;
        Some((user, account))
    });
    let Some((user, account)) = found else {
        // Hash anyway so response timing doesn't reveal whether the email exists.
        auth.hash_password(&body.password).await?;
        return Err(ApiError::unauthorized(codes::INVALID_EMAIL_OR_PASSWORD));
    };
    let Some(hash) = account.password.as_deref() else {
        auth.hash_password(&body.password).await?;
        return Err(ApiError::unauthorized(codes::INVALID_EMAIL_OR_PASSWORD));
    };
    if !auth.verify_password(hash, &body.password).await? {
        return Err(ApiError::unauthorized(codes::INVALID_EMAIL_OR_PASSWORD));
    }

    if auth.options.email_and_password.require_email_verification && !user.email_verified {
        let ev = &auth.options.email_verification;
        let Some(send) = &ev.send_verification_email else {
            return Err(ApiError::forbidden(codes::EMAIL_NOT_VERIFIED));
        };
        if ev.send_on_sign_in {
            let token = create_email_verification_token(&auth.secret, &user.email, None, ev.expires_in, None)?;
            let url = verification_url(&ctx, &token, body.callback_url.as_deref());
            let request_headers = ctx.is_request.then(|| ctx.headers());
            send.call(UserTokenEmail { user: user.clone(), url, token, request_headers }).await?;
        }
        return Err(ApiError::forbidden(codes::EMAIL_NOT_VERIFIED));
    }

    let dont_remember = body.remember_me == Some(false);
    let session = auth
        .internal_adapter
        .create_session(&user.id, dont_remember, None)
        .await
        .map_err(|e| e.api_or(ApiError::unauthorized(codes::FAILED_TO_CREATE_SESSION)))?;
    let token = session.token.clone();
    set_session_cookie(&ctx, &SessionWithUser { session, user: user.clone() }, Some(dont_remember), None).await;
    if let Some(cb) = &body.callback_url {
        ctx.set_header("location", cb);
    }
    ctx.json(json!({
        "redirect": body.callback_url.is_some(),
        "token": token,
        "url": body.callback_url,
        "user": auth.user_output(&user),
    }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![Endpoint::post("signInEmail", "/sign-in/email", handler(sign_in_email)).allow_form()]
}
