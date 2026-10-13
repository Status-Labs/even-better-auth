//! Email one-time passwords (`plugins/email-otp`): sign in, verify an email, reset a
//! password or change an email with a code sent by email.

use std::any::Any;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::api::middleware::{form_csrf, get_session_from_ctx, require_sensitive_session};
use crate::api::routes::password::reset_credential_password;
use crate::api::routes::sign_up::CORE_FIELDS;
use crate::api::routes::util::{assert_password_length, is_valid_email};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointOutput, EndpointResult, current_request, handler, hook};
use crate::cookies::{set_cookie_cache, set_session_cookie};
use crate::crypto::{self, constant_time_eq};
use crate::db::{InputAction, Record, parse_input};
use crate::error::{ApiError, ErrorCode, codes};
use crate::options::{BetterAuthOptions, Callback, RateLimitRule, UserTokenEmail};
use crate::plugin::{MatchedHook, Plugin, PluginHooks, PluginRateLimit};
use crate::types::SessionWithUser;
use crate::utils::validate_user_info::UserSource;

/// Error codes (`EMAIL_OTP_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    pub const OTP_EXPIRED: ErrorCode = ErrorCode { code: "OTP_EXPIRED", message: "OTP expired" };
    pub const INVALID_OTP: ErrorCode = ErrorCode { code: "INVALID_OTP", message: "Invalid OTP" };
    pub const TOO_MANY_ATTEMPTS: ErrorCode = ErrorCode { code: "TOO_MANY_ATTEMPTS", message: "Too many attempts" };
    pub const ALL: &[ErrorCode] = &[OTP_EXPIRED, INVALID_OTP, TOO_MANY_ATTEMPTS];
}

use error_codes as e;

/// What an OTP is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OtpType {
    SignIn,
    EmailVerification,
    ForgetPassword,
    ChangeEmail,
}

impl OtpType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign-in",
            Self::EmailVerification => "email-verification",
            Self::ForgetPassword => "forget-password",
            Self::ChangeEmail => "change-email",
        }
    }
}

/// Arguments for [`EmailOtpOptions::send_verification_otp`].
#[derive(Debug, Clone)]
pub struct OtpEmail {
    pub email: String,
    pub otp: String,
    pub otp_type: OtpType,
    pub request_headers: Option<HeaderMap>,
}

pub type OtpFn = Arc<dyn Fn(&str) -> String + Send + Sync>;
pub type GenerateOtp = Arc<dyn Fn(&str, OtpType) -> Option<String> + Send + Sync>;

/// How OTPs are stored in the verification table (the emailed code is unchanged).
#[derive(Clone, Default)]
pub enum StoreOtp {
    #[default]
    Plain,
    /// SHA-256, base64url.
    Hashed,
    /// Encrypted with the auth secret.
    Encrypted,
    CustomHash(OtpFn),
    CustomEncrypt {
        encrypt: OtpFn,
        decrypt: OtpFn,
    },
}

/// What happens when a new OTP is requested while one is still valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResendStrategy {
    /// Always issue a new code.
    #[default]
    Rotate,
    /// Resend the existing code with a fresh expiry (only when it is recoverable).
    Reuse,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    /// Require an OTP sent to the current email before requesting a change.
    pub verify_current_email: bool,
}

#[derive(Clone)]
pub struct EmailOtpOptions {
    pub send_verification_otp: Callback<OtpEmail>,
    /// Default 6.
    pub otp_length: usize,
    /// Seconds (default 5 minutes).
    pub expires_in: i64,
    pub generate_otp: Option<GenerateOtp>,
    /// Send a verification OTP after sign-up.
    pub send_verification_on_sign_up: bool,
    /// Do not create users when signing in with an unknown email.
    pub disable_sign_up: bool,
    /// Default 3.
    pub allowed_attempts: u32,
    pub store_otp: StoreOtp,
    pub resend_strategy: ResendStrategy,
    pub change_email: ChangeEmailOptions,
    /// Send OTPs instead of verification links from the core email verification flow.
    pub override_default_email_verification: bool,
    /// Default: 3 requests per 60 seconds.
    pub rate_limit: RateLimitRule,
}

impl EmailOtpOptions {
    pub fn new(send_verification_otp: Callback<OtpEmail>) -> Self {
        Self {
            send_verification_otp,
            otp_length: 6,
            expires_in: 5 * 60,
            generate_otp: None,
            send_verification_on_sign_up: false,
            disable_sign_up: false,
            allowed_attempts: 3,
            store_otp: StoreOtp::Plain,
            resend_strategy: ResendStrategy::Rotate,
            change_email: ChangeEmailOptions::default(),
            override_default_email_verification: false,
            rate_limit: RateLimitRule { window: 60, max: 3 },
        }
    }
}

fn identifier(otp_type: OtpType, email: &str) -> String {
    format!("{}-otp-{email}", otp_type.as_str())
}

fn split_at_last_colon(s: &str) -> (&str, &str) {
    s.rsplit_once(':').unwrap_or((s, ""))
}

fn bad(code: ErrorCode) -> ApiError {
    ApiError::bad_request(code)
}

fn message(status: StatusCode, msg: &str) -> ApiError {
    ApiError::message(status, msg)
}

struct Inner {
    options: EmailOtpOptions,
}

impl Inner {
    fn generate(&self, email: &str, otp_type: OtpType) -> String {
        self.options
            .generate_otp
            .as_ref()
            .and_then(|f| f(email, otp_type))
            .unwrap_or_else(|| crypto::random_string(self.options.otp_length, b"0123456789"))
    }

    fn store(&self, auth: &crate::context::AuthContext, otp: &str) -> crate::error::Result<String> {
        Ok(match &self.options.store_otp {
            StoreOtp::Plain => otp.to_owned(),
            StoreOtp::Hashed => crypto::sha256_base64url(otp),
            StoreOtp::Encrypted => crypto::symmetric_encrypt(&auth.secret_config, otp)?,
            StoreOtp::CustomHash(hash) => hash(otp),
            StoreOtp::CustomEncrypt { encrypt, .. } => encrypt(otp),
        })
    }

    /// The plain OTP from a stored value, when it can be recovered.
    fn recover(&self, auth: &crate::context::AuthContext, stored: &str) -> Option<String> {
        match &self.options.store_otp {
            StoreOtp::Plain => Some(stored.to_owned()),
            StoreOtp::Encrypted => crypto::symmetric_decrypt(&auth.secret_config, stored).ok(),
            StoreOtp::CustomEncrypt { decrypt, .. } => Some(decrypt(stored)),
            StoreOtp::Hashed | StoreOtp::CustomHash(_) => None,
        }
    }

    fn matches(&self, auth: &crate::context::AuthContext, stored: &str, otp: &str) -> bool {
        let expected = match &self.options.store_otp {
            StoreOtp::Hashed => return constant_time_eq(crypto::sha256_base64url(otp).as_bytes(), stored.as_bytes()),
            StoreOtp::CustomHash(hash) => return constant_time_eq(hash(otp).as_bytes(), stored.as_bytes()),
            _ => self.recover(auth, stored),
        };
        expected.is_some_and(|plain| constant_time_eq(plain.as_bytes(), otp.as_bytes()))
    }

    fn expires_at(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::seconds(self.options.expires_in)
    }

    /// Store a new OTP for `identifier` (replacing any previous one) and return it.
    async fn issue(&self, ctx: &EndpointContext, id: &str, email: &str, otp_type: OtpType) -> Result<String, ApiError> {
        let ia = &ctx.auth.internal_adapter;
        let otp = self.generate(email, otp_type);
        let stored = self.store(&ctx.auth, &otp)?;
        ia.delete_verification_by_identifier(id).await?;
        ia.create_verification_value(id, &format!("{stored}:0"), self.expires_at()).await?;
        Ok(otp)
    }

    /// Reuse an unexpired, recoverable OTP (extending it) or issue a new one (`resolveOTP`).
    async fn resolve(&self, ctx: &EndpointContext, email: &str, otp_type: OtpType) -> Result<String, ApiError> {
        let id = identifier(otp_type, email);
        if self.options.resend_strategy == ResendStrategy::Reuse
            && let Some(existing) = ctx.auth.internal_adapter.find_verification_value(&id).await?
            && existing.expires_at >= Utc::now()
        {
            let (stored, attempts) = split_at_last_colon(&existing.value);
            let exhausted = attempts.parse::<u32>().is_ok_and(|a| a >= self.options.allowed_attempts);
            if !exhausted && let Some(plain) = self.recover(&ctx.auth, stored) {
                let mut update = Record::new();
                update.insert("expiresAt".into(), crate::utils::date::to_value(self.expires_at()));
                ctx.auth.internal_adapter.update_verification_by_identifier(&id, update).await?;
                return Ok(plain);
            }
        }
        self.issue(ctx, &id, email, otp_type).await
    }

    async fn send(&self, ctx: &EndpointContext, email: &str, otp: String, otp_type: OtpType) -> Result<(), ApiError> {
        let request_headers = ctx.is_request.then(|| ctx.headers());
        self.options
            .send_verification_otp
            .call(OtpEmail { email: email.to_owned(), otp, otp_type, request_headers })
            .await?;
        Ok(())
    }

    /// Whether `otp` matches a usable record, without consuming it or counting an attempt.
    async fn matches_usable(&self, ctx: &EndpointContext, id: &str, otp: &str) -> Result<bool, ApiError> {
        let Some(existing) = ctx.auth.internal_adapter.find_verification_value(id).await? else { return Ok(false) };
        if existing.expires_at < Utc::now() {
            return Ok(false);
        }
        let (stored, attempts) = split_at_last_colon(&existing.value);
        if attempts.parse::<u32>().unwrap_or(0) >= self.options.allowed_attempts {
            return Ok(false);
        }
        Ok(self.matches(&ctx.auth, stored, otp))
    }

    /// Single-use verification (`atomicVerifyOTP`): the atomic consume is the race gate; a
    /// wrong code is put back with one more attempt counted.
    async fn verify(&self, ctx: &EndpointContext, id: &str, otp: &str) -> Result<(), ApiError> {
        let ia = &ctx.auth.internal_adapter;
        if let Some(existing) = ia.find_verification_value(id).await?
            && existing.expires_at < Utc::now()
        {
            ia.delete_verification_by_identifier(id).await?;
            return Err(bad(e::OTP_EXPIRED));
        }
        let Some(consumed) = ia.consume_verification_value(id).await? else {
            return Err(bad(e::INVALID_OTP));
        };
        let (stored, attempts) = split_at_last_colon(&consumed.value);
        let used = attempts.parse::<u32>().unwrap_or(0);
        if used >= self.options.allowed_attempts {
            return Err(ApiError::forbidden(e::TOO_MANY_ATTEMPTS));
        }
        if !self.matches(&ctx.auth, stored, otp) {
            ia.create_verification_value(id, &format!("{stored}:{}", used + 1), consumed.expires_at).await?;
            return Err(bad(e::INVALID_OTP));
        }
        Ok(())
    }
}

fn lower_valid_email(email: &str) -> Result<String, ApiError> {
    let email = email.to_lowercase();
    if !is_valid_email(&email) {
        return Err(ApiError::bad_request(codes::INVALID_EMAIL));
    }
    Ok(email)
}

// ---- endpoints ----------------------------------------------------------------------

#[derive(Deserialize)]
struct SendBody {
    email: String,
    #[serde(rename = "type")]
    otp_type: OtpType,
}

async fn send_verification_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    form_csrf(&ctx)?;
    let body: SendBody = ctx.parse_body()?;
    let email = lower_valid_email(&body.email)?;
    if body.otp_type == OtpType::ChangeEmail {
        tracing::error!("Use the /email-otp/request-email-change endpoint to send OTP for changing email");
        return Err(message(StatusCode::BAD_REQUEST, "Invalid OTP type"));
    }
    let otp = inner.resolve(&ctx, &email, body.otp_type).await?;
    let may_sign_up = body.otp_type == OtpType::SignIn && !inner.options.disable_sign_up;
    if ctx.auth.internal_adapter.find_user_by_email(&email).await?.is_none() && !may_sign_up {
        // Don't reveal whether the account exists.
        ctx.auth.internal_adapter.delete_verification_by_identifier(&identifier(body.otp_type, &email)).await?;
        return ctx.json(json!({ "success": true }));
    }
    inner.send(&ctx, &email, otp, body.otp_type).await?;
    ctx.json(json!({ "success": true }))
}

async fn create_verification_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: SendBody = ctx.parse_body()?;
    let email = body.email.to_lowercase();
    let id = identifier(body.otp_type, &email);
    let otp = inner.generate(&email, body.otp_type);
    let stored = inner.store(&ctx.auth, &otp)?;
    ctx.auth.internal_adapter.create_verification_value(&id, &format!("{stored}:0"), inner.expires_at()).await?;
    ctx.json(Value::String(otp))
}

async fn get_verification_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let email = ctx.query_str("email").unwrap_or_default().to_lowercase();
    let otp_type: OtpType = serde_json::from_value(ctx.query().get("type").cloned().unwrap_or(Value::Null))
        .map_err(|_| ApiError::bad_request(codes::VALIDATION_ERROR))?;
    let found = ctx.auth.internal_adapter.find_verification_value(&identifier(otp_type, &email)).await?;
    let Some(found) = found.filter(|v| v.expires_at >= Utc::now()) else {
        return ctx.json(json!({ "otp": null }));
    };
    if matches!(inner.options.store_otp, StoreOtp::Hashed | StoreOtp::CustomHash(_)) {
        return Err(message(StatusCode::BAD_REQUEST, "OTP is hashed, cannot return the plain text OTP"));
    }
    let (stored, _) = split_at_last_colon(&found.value);
    ctx.json(json!({ "otp": inner.recover(&ctx.auth, stored) }))
}

#[derive(Deserialize)]
struct CheckBody {
    email: String,
    #[serde(rename = "type")]
    otp_type: OtpType,
    otp: String,
}

async fn check_verification_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: CheckBody = ctx.parse_body()?;
    let email = lower_valid_email(&body.email)?;
    let ia = &ctx.auth.internal_adapter;
    let id = identifier(body.otp_type, &email);
    let Some(found) = ia.find_verification_value(&id).await? else {
        return Err(bad(e::INVALID_OTP));
    };
    if found.expires_at < Utc::now() {
        ia.delete_verification_by_identifier(&id).await?;
        return Err(bad(e::OTP_EXPIRED));
    }
    let (stored, attempts) = split_at_last_colon(&found.value);
    let used = attempts.parse::<u32>().unwrap_or(0);
    if !attempts.is_empty() && used >= inner.options.allowed_attempts {
        ia.delete_verification_by_identifier(&id).await?;
        return Err(ApiError::forbidden(e::TOO_MANY_ATTEMPTS));
    }
    if !inner.matches(&ctx.auth, stored, &body.otp) {
        let mut update = Record::new();
        update.insert("value".into(), format!("{stored}:{}", used + 1).into());
        ia.update_verification_by_identifier(&id, update).await?;
        return Err(bad(e::INVALID_OTP));
    }
    if ia.find_user_by_email(&email).await?.is_none() {
        return Err(ApiError::bad_request(codes::USER_NOT_FOUND));
    }
    ctx.json(json!({ "success": true }))
}

#[derive(Deserialize)]
struct VerifyEmailBody {
    email: String,
    otp: String,
}

async fn verify_email_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: VerifyEmailBody = ctx.parse_body()?;
    let email = lower_valid_email(&body.email)?;
    inner.verify(&ctx, &identifier(OtpType::EmailVerification, &email), &body.otp).await?;
    let auth = ctx.auth.clone();
    let Some(user) = auth.internal_adapter.find_user_by_email(&email).await? else {
        return Err(ApiError::bad_request(codes::USER_NOT_FOUND));
    };
    let ev = &auth.options.email_verification;
    if let Some(before) = &ev.before_email_verification {
        before.call(user.clone()).await?;
    }
    let mut update = Record::new();
    update.insert("email".into(), email.into());
    update.insert("emailVerified".into(), true.into());
    let updated = auth.internal_adapter.update_user(&user.id, update).await?.unwrap_or(user);
    if let Some(after) = &ev.after_email_verification {
        after.call(updated.clone()).await?;
    }
    if ev.auto_sign_in_after_verification {
        let session = auth.internal_adapter.create_session(&updated.id, false, None).await?;
        let token = session.token.clone();
        set_session_cookie(&ctx, &SessionWithUser { session, user: updated.clone() }, None, None).await;
        return ctx.json(json!({ "status": true, "token": token, "user": auth.user_output(&updated) }));
    }
    if let Some(current) = get_session_from_ctx(&ctx, Default::default()).await?
        && current.user.id == updated.id
    {
        let dont_remember = ctx.get_signed_cookie(&auth.cookies.dont_remember.name, &auth.secret).is_some();
        let mut user = current.user.clone();
        user.email_verified = true;
        set_cookie_cache(&ctx, &SessionWithUser { session: current.session, user }, dont_remember).await;
    }
    ctx.json(json!({ "status": true, "token": null, "user": auth.user_output(&updated) }))
}

async fn sign_in_email_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let Value::Object(mut body) = ctx.body() else {
        return Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT));
    };
    let take_str = |body: &mut Map<String, Value>, k: &str| body.remove(k).and_then(|v| v.as_str().map(str::to_owned));
    let (Some(email), Some(otp)) = (take_str(&mut body, "email"), take_str(&mut body, "otp")) else {
        return Err(ApiError::bad_request(codes::VALIDATION_ERROR));
    };
    let name = take_str(&mut body, "name");
    let image = take_str(&mut body, "image");
    let email = email.to_lowercase();
    inner.verify(&ctx, &identifier(OtpType::SignIn, &email), &otp).await?;
    let auth = ctx.auth.clone();
    let user = match auth.internal_adapter.find_user_by_email(&email).await? {
        Some(mut user) => {
            if !user.email_verified {
                user = auth
                    .internal_adapter
                    .revoke_unproven_account_access(&user.id)
                    .await?
                    .ok_or_else(|| bad(e::INVALID_OTP))?;
            }
            user
        }
        None if inner.options.disable_sign_up => return Err(bad(e::INVALID_OTP)),
        None => {
            let table = auth.schema.table("user").expect("user table");
            let mut data = parse_input(table, &body, InputAction::Create, CORE_FIELDS)?;
            data.insert("email".into(), email.clone().into());
            data.insert("emailVerified".into(), true.into());
            data.insert("name".into(), name.unwrap_or_default().into());
            if let Some(image) = image {
                data.insert("image".into(), image.into());
            }
            auth.internal_adapter.create_user(data, &UserSource::method("email-otp")).await?
        }
    };
    let session = auth.internal_adapter.create_session(&user.id, false, None).await?;
    let token = session.token.clone();
    set_session_cookie(&ctx, &SessionWithUser { session, user: user.clone() }, None, None).await;
    ctx.json(json!({ "token": token, "user": auth.user_output(&user) }))
}

#[derive(Deserialize)]
struct EmailBody {
    email: String,
}

async fn request_password_reset(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: EmailBody = ctx.parse_body()?;
    let email = body.email.to_lowercase();
    let otp = inner.resolve(&ctx, &email, OtpType::ForgetPassword).await?;
    if ctx.auth.internal_adapter.find_user_by_email(&email).await?.is_none() {
        ctx.auth
            .internal_adapter
            .delete_verification_by_identifier(&identifier(OtpType::ForgetPassword, &email))
            .await?;
        return ctx.json(json!({ "success": true }));
    }
    inner.send(&ctx, &email, otp, OtpType::ForgetPassword).await?;
    ctx.json(json!({ "success": true }))
}

#[derive(Deserialize)]
struct ResetBody {
    email: String,
    otp: String,
    password: String,
}

async fn reset_password(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: ResetBody = ctx.parse_body()?;
    let email = body.email.to_lowercase();
    assert_password_length(&ctx, &body.password)?;
    // Check the code without spending it so a rejected password leaves it usable; a wrong
    // code goes through `verify`, which counts the attempt.
    let id = identifier(OtpType::ForgetPassword, &email);
    let mut consumed = false;
    if !inner.matches_usable(&ctx, &id, &body.otp).await? {
        inner.verify(&ctx, &id, &body.otp).await?;
        consumed = true;
    }
    let auth = ctx.auth.clone();
    let Some(user) = auth.internal_adapter.find_user_by_email(&email).await? else {
        return Err(ApiError::bad_request(codes::USER_NOT_FOUND));
    };
    let hash = auth.hash_password(&body.password).await?;
    let consume = (!consumed).then(|| inner.verify(&ctx, &id, &body.otp));
    reset_credential_password(&ctx, &user.id, &hash, consume).await?;
    if let Some(cb) = &auth.options.email_and_password.on_password_reset {
        cb.call(user.clone()).await?;
    }
    if !user.email_verified {
        let mut update = Record::new();
        update.insert("emailVerified".into(), true.into());
        auth.internal_adapter.update_user(&user.id, update).await?;
    }
    ctx.json(json!({ "success": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestChangeBody {
    new_email: String,
    otp: Option<String>,
}

fn change_disabled() -> ApiError {
    tracing::error!("Change email with OTP is disabled.");
    message(StatusCode::BAD_REQUEST, "Change email with OTP is disabled")
}

async fn request_email_change(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    if !inner.options.change_email.enabled {
        return Err(change_disabled());
    }
    let body: RequestChangeBody = ctx.parse_body()?;
    let email = session.user.email.to_lowercase();
    let new_email = lower_valid_email(&body.new_email)?;
    if new_email == email {
        return Err(message(StatusCode::BAD_REQUEST, "Email is the same"));
    }
    if inner.options.change_email.verify_current_email {
        let Some(otp) = &body.otp else {
            return Err(message(StatusCode::BAD_REQUEST, "OTP is required to verify current email"));
        };
        inner.verify(&ctx, &identifier(OtpType::EmailVerification, &email), otp).await?;
    } else if body.otp.is_some() {
        tracing::warn!(
            "OTP provided but not required for verifying current email. If you want to require OTP verification for current email, please set the changeEmail.verifyCurrentEmail option to true in the configuration"
        );
    }
    let id = identifier(OtpType::ChangeEmail, &format!("{email}-{new_email}"));
    let otp = inner.generate(&new_email, OtpType::ChangeEmail);
    let stored = inner.store(&ctx.auth, &otp)?;
    let ia = &ctx.auth.internal_adapter;
    ia.create_verification_value(&id, &format!("{stored}:0"), inner.expires_at()).await?;
    if ia.find_user_by_email(&new_email).await?.is_some() {
        ia.delete_verification_by_identifier(&id).await?;
        return ctx.json(json!({ "success": true }));
    }
    inner.send(&ctx, &new_email, otp, OtpType::ChangeEmail).await?;
    ctx.json(json!({ "success": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeBody {
    new_email: String,
    otp: String,
}

async fn change_email(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    if !inner.options.change_email.enabled {
        return Err(change_disabled());
    }
    let body: ChangeBody = ctx.parse_body()?;
    let email = session.user.email.to_lowercase();
    let new_email = lower_valid_email(&body.new_email)?;
    if new_email == email {
        return Err(message(StatusCode::BAD_REQUEST, "Email is the same"));
    }
    inner.verify(&ctx, &identifier(OtpType::ChangeEmail, &format!("{email}-{new_email}")), &body.otp).await?;
    let auth = ctx.auth.clone();
    let Some(current) = auth.internal_adapter.find_user_by_email(&email).await? else {
        return Err(ApiError::bad_request(codes::USER_NOT_FOUND));
    };
    if auth.internal_adapter.find_user_by_email(&new_email).await?.is_some() {
        return Err(message(StatusCode::BAD_REQUEST, "Email already in use"));
    }
    let ev = &auth.options.email_verification;
    if let Some(before) = &ev.before_email_verification {
        before.call(current.clone()).await?;
    }
    let mut update = Record::new();
    update.insert("email".into(), new_email.clone().into());
    update.insert("emailVerified".into(), true.into());
    let updated = auth.internal_adapter.update_user(&current.id, update).await?;
    if let (Some(after), Some(updated)) = (&ev.after_email_verification, updated) {
        after.call(updated).await?;
    }
    let mut user = session.user.clone();
    user.email = new_email;
    user.email_verified = true;
    set_session_cookie(&ctx, &SessionWithUser { session: session.session, user }, None, None).await;
    ctx.json(json!({ "success": true }))
}

/// After sign-up, email a verification OTP (`sendVerificationOnSignUp`).
async fn after_sign_up(inner: Arc<Inner>, ctx: Ctx) -> Result<(), ApiError> {
    let Some(Ok(EndpointOutput::Json(response))) = ctx.returned() else { return Ok(()) };
    let Some(email) = response.get("user").and_then(|u| u.get("email")).and_then(Value::as_str) else {
        return Ok(());
    };
    let id = identifier(OtpType::EmailVerification, email);
    let otp = inner.issue(&ctx, &id, email, OtpType::EmailVerification).await?;
    inner.send(&ctx, email, otp, OtpType::EmailVerification).await
}

pub struct EmailOtp {
    inner: Arc<Inner>,
}

pub fn email_otp(options: EmailOtpOptions) -> Arc<dyn Plugin> {
    Arc::new(EmailOtp { inner: Arc::new(Inner { options }) })
}

macro_rules! route {
    ($inner:expr, $method:ident, $key:literal, $path:literal, $f:ident) => {{
        let inner = $inner.clone();
        Endpoint::$method($key, $path, handler(move |ctx| $f(inner.clone(), ctx)))
    }};
}

impl Plugin for EmailOtp {
    fn id(&self) -> &str {
        "email-otp"
    }

    fn configure(&self, options: &mut BetterAuthOptions) {
        if !self.inner.options.override_default_email_verification {
            return;
        }
        let inner = self.inner.clone();
        options.email_verification.send_verification_email = Some(Callback::new(move |email: UserTokenEmail| {
            let inner = inner.clone();
            async move {
                let Some(ctx) = current_request() else {
                    return Err(crate::error::Error::Other("email OTP verification requires a request context".into()));
                };
                let address = email.user.email.to_lowercase();
                let otp = inner.resolve(&ctx, &address, OtpType::EmailVerification).await?;
                inner.send(&ctx, &address, otp, OtpType::EmailVerification).await?;
                Ok(())
            }
        }));
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let i = &self.inner;
        vec![
            route!(i, post, "sendVerificationOTP", "/email-otp/send-verification-otp", send_verification_otp)
                .allow_form(),
            route!(i, post, "createVerificationOTP", "/email-otp/create-verification-otp", create_verification_otp)
                .server_only(),
            route!(i, get, "getVerificationOTP", "/email-otp/get-verification-otp", get_verification_otp).server_only(),
            route!(i, post, "checkVerificationOTP", "/email-otp/check-verification-otp", check_verification_otp),
            route!(i, post, "verifyEmailOTP", "/email-otp/verify-email", verify_email_otp),
            route!(i, post, "signInEmailOTP", "/sign-in/email-otp", sign_in_email_otp),
            route!(
                i,
                post,
                "requestPasswordResetEmailOTP",
                "/email-otp/request-password-reset",
                request_password_reset
            ),
            route!(i, post, "forgetPasswordEmailOTP", "/forget-password/email-otp", request_password_reset),
            route!(i, post, "resetPasswordEmailOTP", "/email-otp/reset-password", reset_password),
            route!(i, post, "requestEmailChangeEmailOTP", "/email-otp/request-email-change", request_email_change),
            route!(i, post, "changeEmailEmailOTP", "/email-otp/change-email", change_email),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        let options = &self.inner.options;
        if !options.send_verification_on_sign_up || options.override_default_email_verification {
            return PluginHooks::default();
        }
        let inner = self.inner.clone();
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |ctx| ctx.path.starts_with("/sign-up"),
                hook(move |ctx| {
                    let inner = inner.clone();
                    async move {
                        after_sign_up(inner, ctx).await?;
                        Ok(None)
                    }
                }),
            )],
        }
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        const PATHS: &[&str] = &[
            "/email-otp/send-verification-otp",
            "/email-otp/check-verification-otp",
            "/email-otp/verify-email",
            "/sign-in/email-otp",
            "/email-otp/request-password-reset",
            "/email-otp/reset-password",
            "/forget-password/email-otp",
            "/email-otp/request-email-change",
            "/email-otp/change-email",
        ];
        vec![PluginRateLimit {
            path_matcher: Arc::new(|p: &str| PATHS.contains(&p)),
            rule: self.inner.options.rate_limit,
        }]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
