//! TOTP (`two-factor/totp`): `POST /two-factor/get-totp-uri`, `POST /two-factor/verify-totp`
//! and the server-only `generateTOTP`.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;

use super::{
    DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS, Inner, TABLE, assert_not_locked, error_codes as e, find_row, record_failure,
    require_password, reset_failures, rotate_session, set_two_factor_enabled, two_factor_enabled, verify_two_factor,
};
use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::crypto::{self, otp};
use crate::db::{Record, Where};
use crate::error::ApiError;

#[derive(Debug, Clone, Copy, Default)]
pub struct TotpOptions {
    /// 6 or 8 (default 6).
    pub digits: Option<u32>,
    /// Seconds (default 30).
    pub period: Option<u64>,
    /// Disable TOTP entirely.
    pub disable: bool,
    /// Override the plugin-level `allow_passwordless` for these endpoints.
    pub allow_passwordless: Option<bool>,
}

impl TotpOptions {
    pub fn digits(&self) -> u32 {
        self.digits.unwrap_or(otp::DEFAULT_DIGITS)
    }

    pub fn period(&self) -> u64 {
        self.period.unwrap_or(otp::DEFAULT_PERIOD)
    }
}

fn not_configured() -> ApiError {
    tracing::error!("totp isn't configured. please pass totp option on two factor plugin to enable totp");
    ApiError::new(http::StatusCode::BAD_REQUEST, "TOTP_NOT_CONFIGURED", "totp isn't configured")
}

#[derive(Deserialize)]
struct GenerateBody {
    secret: String,
}

async fn generate_totp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    if inner.options.totp.disable {
        return Err(not_configured());
    }
    let body: GenerateBody = ctx.parse_body()?;
    let totp = &inner.options.totp;
    ctx.json(json!({ "code": otp::totp(&body.secret, totp.digits(), totp.period()) }))
}

#[derive(Deserialize)]
struct UriBody {
    password: Option<String>,
}

async fn get_totp_uri(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    if inner.options.totp.disable {
        return Err(not_configured());
    }
    let session = require_session(&ctx).await?;
    let body: UriBody = ctx.parse_body()?;
    let user = &session.user;
    let row = find_row(&ctx, &user.id).await?.ok_or_else(|| ApiError::bad_request(e::TOTP_NOT_ENABLED))?;
    let secret = crypto::symmetric_decrypt(&ctx.auth.secret_config, &row.secret)?;
    require_password(
        &ctx,
        &user.id,
        inner.passwordless(inner.options.totp.allow_passwordless),
        body.password.as_deref(),
    )
    .await?;
    let issuer = inner.options.issuer.clone().unwrap_or_else(|| ctx.auth.options.app_name.clone());
    let totp = &inner.options.totp;
    ctx.json(json!({ "totpURI": otp::totp_uri(&secret, &issuer, &user.email, totp.digits(), totp.period()) }))
}

#[derive(Deserialize)]
struct VerifyBody {
    code: String,
}

async fn verify_totp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    if inner.options.totp.disable {
        return Err(not_configured());
    }
    let body: VerifyBody = ctx.parse_body()?;
    let verification = verify_two_factor(&ctx).await?;
    let user = verification.user.clone();
    let sign_in = verification.is_sign_in();
    let row = find_row(&ctx, &user.id).await?.ok_or_else(|| ApiError::bad_request(e::TOTP_NOT_ENABLED))?;
    // During sign-in, reject abandoned (explicitly unverified) enrollments.
    if sign_in && row.verified == Some(false) {
        return Err(ApiError::bad_request(e::TOTP_NOT_ENABLED));
    }
    if sign_in {
        assert_not_locked(&ctx, &inner, &row).await?;
    }
    let attempt = verification.begin_attempt(&ctx, DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS).await?;
    let secret = match crypto::symmetric_decrypt(&ctx.auth.secret_config, &row.secret) {
        Ok(s) => s,
        Err(err) => {
            // A server error before the code is checked must not spend the slot.
            if let Some(a) = &attempt {
                a.restore(&ctx).await;
            }
            return Err(err.into());
        }
    };
    let totp = &inner.options.totp;
    if !otp::verify_totp(&secret, &body.code, totp.digits(), totp.period()) {
        if let Some(a) = &attempt {
            a.record_failure(&ctx).await;
        }
        if sign_in {
            record_failure(&ctx, &inner, &row).await?;
        }
        return Err(ApiError::unauthorized(e::INVALID_CODE));
    }
    if sign_in {
        reset_failures(&ctx, &inner, &row).await?;
    }
    // Enrollment: the row exists but has not been verified yet.
    if row.verified != Some(true) {
        if !two_factor_enabled(&user) {
            let session = verification.session.as_ref().expect("sign-in rejected unverified rows above");
            let updated = set_two_factor_enabled(&ctx, &user.id, true).await?;
            rotate_session(&ctx, session, updated).await?;
        }
        let mut update = Record::new();
        update.insert("verified".into(), true.into());
        ctx.auth.db.update(TABLE, &[Where::eq("id", row.id.clone())], update).await?;
    }
    verification.valid(&ctx, &inner).await
}

pub(super) fn endpoints(inner: &Arc<Inner>) -> Vec<Endpoint> {
    let (a, b, c) = (inner.clone(), inner.clone(), inner.clone());
    vec![
        Endpoint::post("generateTOTP", "/two-factor/generate-totp", handler(move |ctx| generate_totp(a.clone(), ctx)))
            .server_only(),
        Endpoint::post("getTOTPURI", "/two-factor/get-totp-uri", handler(move |ctx| get_totp_uri(b.clone(), ctx))),
        Endpoint::post("verifyTOTP", "/two-factor/verify-totp", handler(move |ctx| verify_totp(c.clone(), ctx))),
    ]
}
