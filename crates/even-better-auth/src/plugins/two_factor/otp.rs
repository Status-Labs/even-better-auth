//! One-time codes sent by email or SMS (`two-factor/otp`): `POST /two-factor/send-otp` and
//! `POST /two-factor/verify-otp`.

use std::sync::Arc;

use http::HeaderMap;
use serde::Deserialize;
use serde_json::json;

use super::{
    Inner, assert_not_locked, error_codes as e, find_row, record_failure, reset_failures, rotate_session,
    set_two_factor_enabled, two_factor_enabled, verify_two_factor,
};
use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::crypto::{self, constant_time_eq};
use crate::error::{ApiError, codes};
use crate::options::Callback;
use crate::types::User;

/// Arguments for [`OtpOptions::send_otp`].
#[derive(Debug, Clone)]
pub struct TwoFactorOtp {
    pub user: User,
    pub otp: String,
    pub request_headers: Option<HeaderMap>,
}

pub type OtpFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// How codes are stored in the verification table.
#[derive(Clone, Default)]
pub enum StoreOtp {
    #[default]
    Plain,
    Encrypted,
    /// SHA-256, base64url.
    Hashed,
    CustomHash(OtpFn),
    CustomEncrypt {
        encrypt: OtpFn,
        decrypt: OtpFn,
    },
}

#[derive(Clone, Default)]
pub struct OtpOptions {
    /// Deliver the code; OTP is unavailable without it.
    pub send_otp: Option<Callback<TwoFactorOtp>>,
    /// Minutes the code is valid (default 3).
    pub period: Option<i64>,
    /// Default 6.
    pub digits: Option<usize>,
    /// Default 5.
    pub allowed_attempts: Option<u32>,
    pub store_otp: StoreOtp,
}

impl Inner {
    fn store_otp(&self, ctx: &crate::api::EndpointContext, code: &str) -> crate::error::Result<String> {
        Ok(match &self.options.otp.store_otp {
            StoreOtp::Plain => code.to_owned(),
            StoreOtp::Encrypted => crypto::symmetric_encrypt(&ctx.auth.secret_config, code)?,
            StoreOtp::Hashed => crypto::sha256_base64url(code),
            StoreOtp::CustomHash(hash) => hash(code),
            StoreOtp::CustomEncrypt { encrypt, .. } => encrypt(code),
        })
    }

    fn otp_matches(&self, ctx: &crate::api::EndpointContext, stored: &str, input: &str) -> crate::error::Result<bool> {
        let (a, b) = match &self.options.otp.store_otp {
            StoreOtp::Plain => (stored.to_owned(), input.to_owned()),
            StoreOtp::Encrypted => (crypto::symmetric_decrypt(&ctx.auth.secret_config, stored)?, input.to_owned()),
            StoreOtp::Hashed => (stored.to_owned(), crypto::sha256_base64url(input)),
            StoreOtp::CustomHash(hash) => (stored.to_owned(), hash(input)),
            StoreOtp::CustomEncrypt { decrypt, .. } => (decrypt(stored), input.to_owned()),
        };
        Ok(constant_time_eq(a.as_bytes(), b.as_bytes()))
    }
}

fn identifier(key: &str) -> String {
    format!("2fa-otp-{key}")
}

async fn send_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let Some(send) = inner.options.otp.send_otp.clone() else {
        tracing::error!("send otp isn't configured. Please configure the send otp function on otp options.");
        return Err(ApiError::new(http::StatusCode::BAD_REQUEST, "OTP_NOT_CONFIGURED", "otp isn't configured"));
    };
    let verification = verify_two_factor(&ctx).await?;
    let code = crypto::random_string(inner.options.otp.digits.unwrap_or(6), b"0123456789");
    let stored = inner.store_otp(&ctx, &code)?;
    let minutes = inner.options.otp.period.unwrap_or(3);
    let expires = chrono::Utc::now() + chrono::Duration::minutes(minutes);
    ctx.auth
        .internal_adapter
        .create_verification_value(&identifier(&verification.key), &format!("{stored}:0"), expires)
        .await?;
    let request_headers = ctx.is_request.then(|| ctx.headers());
    if let Err(err) = send.call(TwoFactorOtp { user: verification.user.clone(), otp: code, request_headers }).await {
        tracing::error!(error = %err, "Failed to send two-factor OTP");
    }
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
struct VerifyBody {
    code: String,
}

async fn verify_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: VerifyBody = ctx.parse_body()?;
    let verification = verify_two_factor(&ctx).await?;
    let sign_in = verification.is_sign_in();
    // OTP failures share the account lockout with TOTP and backup codes when a row exists.
    let row = if sign_in { find_row(&ctx, &verification.user.id).await? } else { None };
    if let Some(row) = &row {
        assert_not_locked(&ctx, &inner, row).await?;
    }
    let ia = &ctx.auth.internal_adapter;
    let id = identifier(&verification.key);
    let Some(consumed) = ia.consume_verification_value(&id).await? else {
        return Err(ApiError::bad_request(e::OTP_HAS_EXPIRED));
    };
    let (stored, counter) = consumed.value.split_once(':').unwrap_or((consumed.value.as_str(), "0"));
    let attempts = counter.parse::<u32>().unwrap_or(0);
    if attempts >= inner.options.otp.allowed_attempts.unwrap_or(5) {
        return Err(ApiError::bad_request(e::TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE));
    }
    if inner.otp_matches(&ctx, stored, &body.code)? {
        if let Some(row) = &row {
            reset_failures(&ctx, &inner, row).await?;
        }
        if !two_factor_enabled(&verification.user) {
            let Some(session) = &verification.session else {
                return Err(ApiError::bad_request(codes::FAILED_TO_CREATE_SESSION));
            };
            let updated = set_two_factor_enabled(&ctx, &verification.user.id, true).await?;
            let token = rotate_session(&ctx, session, updated.clone()).await?;
            return ctx.json(json!({ "token": token, "user": ctx.auth.user_output(&updated) }));
        }
        return verification.valid(&ctx, &inner).await;
    }
    // Wrong code within budget: re-arm with one more attempt counted and the original expiry.
    ia.create_verification_value(&id, &format!("{stored}:{}", attempts + 1), consumed.expires_at).await?;
    if let Some(row) = &row {
        record_failure(&ctx, &inner, row).await?;
    }
    Err(ApiError::unauthorized(e::INVALID_CODE))
}

pub(super) fn endpoints(inner: &Arc<Inner>) -> Vec<crate::api::Endpoint> {
    let (a, b) = (inner.clone(), inner.clone());
    vec![
        Endpoint::post("sendTwoFactorOTP", "/two-factor/send-otp", handler(move |ctx| send_otp(a.clone(), ctx))),
        Endpoint::post("verifyTwoFactorOTP", "/two-factor/verify-otp", handler(move |ctx| verify_otp(b.clone(), ctx))),
    ]
}
