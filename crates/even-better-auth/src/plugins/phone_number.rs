//! Phone numbers (`plugins/phone-number`): sign in with a phone number and password, verify a
//! number with an SMS one-time code (optionally signing the user up), and reset a password
//! with a code.

use std::any::Any;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use futures::future::BoxFuture;
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::api::middleware::get_session_from_ctx;
use crate::api::routes::password::reset_credential_password;
use crate::api::routes::session::GetSessionOptions;
use crate::api::routes::sign_up::CORE_FIELDS;
use crate::api::routes::util::{assert_password_length, assert_password_not_too_long};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler, hook};
use crate::cookies::set_session_cookie;
use crate::db::hooks::{BeforeOutcome, DatabaseHooks, Operation};
use crate::db::{Field, InputAction, Record, TableExtension, Where, parse_input};
use crate::error::{ApiError, ErrorCode, Result, codes};
use crate::options::{Callback, RateLimitRule};
use crate::plugin::{MatchedHook, Plugin, PluginHooks, PluginRateLimit};
use crate::types::{Model, SessionWithUser, User};
use crate::utils::validate_user_info::UserSource;

/// Error codes (`PHONE_NUMBER_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        INVALID_PHONE_NUMBER => "Invalid phone number",
        PHONE_NUMBER_EXIST => "Phone number already exists",
        PHONE_NUMBER_NOT_EXIST => "phone number isn't registered",
        INVALID_PHONE_NUMBER_OR_PASSWORD => "Invalid phone number or password",
        UNEXPECTED_ERROR => "Unexpected error",
        OTP_NOT_FOUND => "OTP not found",
        OTP_EXPIRED => "OTP expired",
        INVALID_OTP => "Invalid OTP",
        PHONE_NUMBER_NOT_VERIFIED => "Phone number not verified",
        PHONE_NUMBER_CANNOT_BE_UPDATED => "Phone number cannot be updated",
        SEND_OTP_NOT_IMPLEMENTED => "sendOTP not implemented",
        TOO_MANY_ATTEMPTS => "Too many attempts",
    }
}

use error_codes as e;

const PHONE_NUMBER: &str = "phoneNumber";
const PHONE_NUMBER_VERIFIED: &str = "phoneNumberVerified";

/// Arguments for [`PhoneNumberOptions::send_otp`], `send_password_reset_otp` and `verify_otp`.
#[derive(Debug, Clone)]
pub struct PhoneOtp {
    pub phone_number: String,
    pub code: String,
    /// Headers of the request that triggered the code, if any.
    pub request_headers: Option<HeaderMap>,
}

/// Arguments for [`PhoneNumberOptions::callback_on_verification`].
#[derive(Debug, Clone)]
pub struct PhoneVerified {
    pub phone_number: String,
    pub user: User,
}

pub type VerifyOtpFn = Arc<dyn Fn(PhoneOtp) -> BoxFuture<'static, Result<bool>> + Send + Sync>;
pub type PhoneStringFn = Arc<dyn Fn(&str) -> String + Send + Sync>;
pub type PhoneValidator = Arc<dyn Fn(String) -> BoxFuture<'static, Result<bool>> + Send + Sync>;

/// Sign users up on first verification (`signUpOnVerification`).
#[derive(Clone)]
pub struct SignUpOnVerification {
    pub get_temp_email: PhoneStringFn,
    /// Default: the phone number.
    pub get_temp_name: Option<PhoneStringFn>,
}

#[derive(Clone)]
pub struct PhoneNumberOptions {
    /// Default 6.
    pub otp_length: usize,
    /// Sends a verification code. `/phone-number/send-otp` answers 501 without it.
    pub send_otp: Option<Callback<PhoneOtp>>,
    /// Replaces the built-in code check (e.g. a provider's verify API).
    pub verify_otp: Option<VerifyOtpFn>,
    pub send_password_reset_otp: Option<Callback<PhoneOtp>>,
    /// Code lifetime in seconds. Default 300.
    pub expires_in: i64,
    pub phone_number_validator: Option<PhoneValidator>,
    /// Refuse password sign-in until the number is verified (and send a code).
    pub require_verification: bool,
    pub callback_on_verification: Option<Callback<PhoneVerified>>,
    pub sign_up_on_verification: Option<SignUpOnVerification>,
    /// Wrong codes allowed before the code is burned. Default 3.
    pub allowed_attempts: u32,
    /// Applies to every `/phone-number/*` path. Default 10 per 60 seconds.
    pub rate_limit: RateLimitRule,
}

impl PhoneNumberOptions {
    pub fn new(send_otp: Callback<PhoneOtp>) -> Self {
        Self { send_otp: Some(send_otp), ..Self::default() }
    }
}

impl Default for PhoneNumberOptions {
    fn default() -> Self {
        Self {
            otp_length: 6,
            send_otp: None,
            verify_otp: None,
            send_password_reset_otp: None,
            expires_in: 300,
            phone_number_validator: None,
            require_verification: false,
            callback_on_verification: None,
            sign_up_on_verification: None,
            allowed_attempts: 3,
            rate_limit: RateLimitRule { window: 60, max: 10 },
        }
    }
}

struct Inner {
    options: PhoneNumberOptions,
}

fn bad(code: ErrorCode) -> ApiError {
    ApiError::bad_request(code)
}

/// The attempt counter after the last `:` (`parseVerificationAttempts`): anything that is
/// not a positive integer counts as zero.
fn parse_attempts(raw: Option<&str>) -> u32 {
    raw.and_then(|r| r.parse::<u32>().ok()).unwrap_or(0)
}

fn reset_identifier(phone_number: &str) -> String {
    format!("{phone_number}-request-password-reset")
}

impl Inner {
    fn generate(&self) -> String {
        crate::crypto::random_string(self.options.otp_length, b"0123456789")
    }

    fn expires_at(&self) -> DateTime<Utc> {
        Utc::now() + Duration::seconds(self.options.expires_in)
    }

    fn otp(&self, ctx: &EndpointContext, phone_number: &str, code: String) -> PhoneOtp {
        PhoneOtp { phone_number: phone_number.to_owned(), code, request_headers: ctx.is_request.then(|| ctx.headers()) }
    }

    async fn validate(&self, phone_number: &str) -> std::result::Result<(), ApiError> {
        if let Some(validator) = &self.options.phone_number_validator
            && !validator(phone_number.to_owned()).await?
        {
            return Err(bad(e::INVALID_PHONE_NUMBER));
        }
        Ok(())
    }

    fn allowed_attempts(&self) -> u32 {
        self.options.allowed_attempts
    }

    /// Single-use verification (`verifyPhoneNumberOTP`): the atomic consume is the race
    /// gate; a wrong code is put back with one more attempt counted.
    async fn verify_stored(&self, ctx: &EndpointContext, id: &str, code: &str) -> std::result::Result<(), ApiError> {
        let ia = &ctx.auth.internal_adapter;
        let Some(existing) = ia.find_verification_value(id).await? else {
            return Err(bad(e::OTP_NOT_FOUND));
        };
        if existing.expires_at < Utc::now() {
            ia.delete_verification_by_identifier(id).await?;
            return Err(bad(e::OTP_EXPIRED));
        }
        if parse_attempts(existing.value.split(':').nth(1)) >= self.allowed_attempts() {
            ia.delete_verification_by_identifier(id).await?;
            return Err(ApiError::forbidden(e::TOO_MANY_ATTEMPTS));
        }
        let Some(consumed) = ia.consume_verification_value(id).await? else {
            return Err(bad(e::INVALID_OTP));
        };
        let mut parts = consumed.value.split(':');
        let stored = parts.next().unwrap_or_default().to_owned();
        let attempts = parse_attempts(parts.next());
        if attempts >= self.allowed_attempts() {
            return Err(ApiError::forbidden(e::TOO_MANY_ATTEMPTS));
        }
        if !crate::crypto::constant_time_eq(stored.as_bytes(), code.as_bytes()) {
            ia.create_verification_value(id, &format!("{stored}:{}", attempts + 1), consumed.expires_at).await?;
            return Err(bad(e::INVALID_OTP));
        }
        Ok(())
    }

    /// Whether `code` matches a usable stored code, without consuming it or counting an attempt.
    async fn matches_usable(&self, ctx: &EndpointContext, id: &str, code: &str) -> std::result::Result<bool, ApiError> {
        let Some(existing) = ctx.auth.internal_adapter.find_verification_value(id).await? else { return Ok(false) };
        if existing.expires_at < Utc::now() {
            return Ok(false);
        }
        let mut parts = existing.value.split(':');
        let stored = parts.next().unwrap_or_default();
        if parse_attempts(parts.next()) >= self.allowed_attempts() {
            return Ok(false);
        }
        Ok(crate::crypto::constant_time_eq(stored.as_bytes(), code.as_bytes()))
    }

    /// `verifyAndConsumePhoneNumberOTP`: a custom `verify_otp`, or the stored code.
    async fn verify_and_consume(
        &self,
        ctx: &EndpointContext,
        phone_number: &str,
        code: &str,
    ) -> std::result::Result<(), ApiError> {
        if let Some(verify) = &self.options.verify_otp {
            if !verify(self.otp(ctx, phone_number, code.to_owned())).await? {
                return Err(bad(e::INVALID_OTP));
            }
            ctx.auth.internal_adapter.delete_verification_by_identifier(phone_number).await?;
            return Ok(());
        }
        self.verify_stored(ctx, phone_number, code).await
    }
}

async fn find_by_phone(ctx: &EndpointContext, phone_number: &str) -> std::result::Result<Option<User>, ApiError> {
    let row = ctx.auth.db.find_one("user", &[Where::eq(PHONE_NUMBER, phone_number)]).await?;
    Ok(row.map(User::from_record).transpose()?)
}

fn is_verified(user: &User) -> bool {
    user.extra.get(PHONE_NUMBER_VERIFIED).and_then(Value::as_bool).unwrap_or(false)
}

fn internal(code: ErrorCode) -> ApiError {
    ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, code)
}

// ---- endpoints ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInBody {
    phone_number: String,
    password: String,
    remember_me: Option<bool>,
}

async fn sign_in_phone_number(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: SignInBody = ctx.parse_body()?;
    inner.validate(&body.phone_number).await?;
    assert_password_not_too_long(&ctx, &body.password)?;
    let auth = ctx.auth.clone();
    let invalid = || ApiError::unauthorized(e::INVALID_PHONE_NUMBER_OR_PASSWORD);
    let Some(user) = find_by_phone(&ctx, &body.phone_number).await? else {
        return Err(invalid());
    };
    if inner.options.require_verification && !is_verified(&user) {
        let code = inner.generate();
        auth.internal_adapter.create_verification_value(&body.phone_number, &code, inner.expires_at()).await?;
        if let Some(send) = &inner.options.send_otp {
            send.call(inner.otp(&ctx, &body.phone_number, code)).await?;
        }
        return Err(ApiError::unauthorized(e::PHONE_NUMBER_NOT_VERIFIED));
    }
    let Some(account) = auth.internal_adapter.find_credential_account(&user.id).await? else {
        tracing::warn!("Credential account not found");
        return Err(invalid());
    };
    let Some(hash) = account.password else {
        tracing::warn!("Password not found");
        return Err(ApiError::unauthorized(e::UNEXPECTED_ERROR));
    };
    if !auth.verify_password(&hash, &body.password).await? {
        tracing::warn!("Invalid password");
        return Err(invalid());
    }
    let dont_remember = body.remember_me == Some(false);
    let session = auth
        .internal_adapter
        .create_session(&user.id, dont_remember, None)
        .await
        .map_err(|err| err.api_or(ApiError::unauthorized(codes::FAILED_TO_CREATE_SESSION)))?;
    let token = session.token.clone();
    set_session_cookie(&ctx, &SessionWithUser { session, user: user.clone() }, Some(dont_remember), None).await;
    ctx.json(json!({ "token": token, "user": auth.user_output(&user) }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhoneBody {
    phone_number: String,
}

async fn send_phone_number_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: PhoneBody = ctx.parse_body()?;
    let Some(send) = &inner.options.send_otp else {
        tracing::warn!("sendOTP not implemented");
        return Err(ApiError::from_code(StatusCode::NOT_IMPLEMENTED, e::SEND_OTP_NOT_IMPLEMENTED));
    };
    inner.validate(&body.phone_number).await?;
    let code = inner.generate();
    ctx.auth
        .internal_adapter
        .create_verification_value(&body.phone_number, &format!("{code}:0"), inner.expires_at())
        .await?;
    send.call(inner.otp(&ctx, &body.phone_number, code)).await?;
    ctx.json(json!({ "message": "code sent" }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CodeBody {
    phone_number: String,
    code: String,
}

async fn consume_phone_number_otp(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: CodeBody = ctx.parse_body()?;
    inner.verify_and_consume(&ctx, &body.phone_number, &body.code).await?;
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyBody {
    phone_number: String,
    code: String,
    disable_session: Option<bool>,
    update_phone_number: Option<bool>,
}

async fn verify_phone_number(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: VerifyBody = ctx.parse_body()?;
    let phone = body.phone_number.clone();
    inner.verify_and_consume(&ctx, &phone, &body.code).await?;
    let auth = ctx.auth.clone();
    let ia = &auth.internal_adapter;
    let verified_update = || {
        let mut data = Record::new();
        data.insert(PHONE_NUMBER_VERIFIED.into(), true.into());
        data
    };

    if body.update_phone_number == Some(true) {
        let Some(session) = get_session_from_ctx(&ctx, GetSessionOptions::default()).await? else {
            return Err(ApiError::unauthorized(codes::USER_NOT_FOUND));
        };
        if find_by_phone(&ctx, &phone).await?.is_some() {
            return Err(bad(e::PHONE_NUMBER_EXIST));
        }
        let mut data = verified_update();
        data.insert(PHONE_NUMBER.into(), phone.clone().into());
        let user =
            ia.update_user(&session.user.id, data).await?.ok_or_else(|| internal(codes::FAILED_TO_UPDATE_USER))?;
        if let Some(cb) = &inner.options.callback_on_verification {
            cb.call(PhoneVerified { phone_number: phone, user: user.clone() }).await?;
        }
        return ctx.json(json!({ "status": true, "token": session.session.token, "user": auth.user_output(&user) }));
    }

    let user = match find_by_phone(&ctx, &phone).await? {
        Some(user) => ia.update_user(&user.id, verified_update()).await?,
        None => match &inner.options.sign_up_on_verification {
            Some(sign_up) => {
                let Value::Object(mut rest) = ctx.body() else { return Err(bad(codes::BODY_MUST_BE_AN_OBJECT)) };
                for key in ["phoneNumber", "code", "disableSession", "updatePhoneNumber"] {
                    rest.remove(key);
                }
                let table = auth.schema.table("user").expect("user table");
                let mut data = parse_input(table, &rest, InputAction::Create, CORE_FIELDS)?;
                let name = sign_up.get_temp_name.as_ref().map_or_else(|| phone.clone(), |f| f(&phone));
                data.insert("email".into(), (sign_up.get_temp_email)(&phone).into());
                data.insert("name".into(), name.into());
                data.insert(PHONE_NUMBER.into(), phone.clone().into());
                data.insert(PHONE_NUMBER_VERIFIED.into(), true.into());
                let user = ia
                    .create_user(data, &UserSource::method("phone-number"))
                    .await
                    .map_err(|err| err.api_or(internal(codes::FAILED_TO_CREATE_USER)))?;
                Some(user)
            }
            None => None,
        },
    };
    let user = user.ok_or_else(|| internal(codes::FAILED_TO_UPDATE_USER))?;
    if let Some(cb) = &inner.options.callback_on_verification {
        cb.call(PhoneVerified { phone_number: phone, user: user.clone() }).await?;
    }
    if body.disable_session == Some(true) {
        return ctx.json(json!({ "status": true, "token": null, "user": auth.user_output(&user) }));
    }
    let session = ia
        .create_session(&user.id, false, None)
        .await
        .map_err(|err| err.api_or(internal(codes::FAILED_TO_CREATE_SESSION)))?;
    let token = session.token.clone();
    set_session_cookie(&ctx, &SessionWithUser { session, user: user.clone() }, None, None).await;
    ctx.json(json!({ "status": true, "token": token, "user": auth.user_output(&user) }))
}

async fn request_password_reset(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: PhoneBody = ctx.parse_body()?;
    let user = find_by_phone(&ctx, &body.phone_number).await?;
    let code = inner.generate();
    ctx.auth
        .internal_adapter
        .create_verification_value(&reset_identifier(&body.phone_number), &format!("{code}:0"), inner.expires_at())
        .await?;
    // Answer the same either way so the endpoint does not reveal which numbers exist.
    if user.is_some()
        && let Some(send) = &inner.options.send_password_reset_otp
    {
        send.call(inner.otp(&ctx, &body.phone_number, code)).await?;
    }
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResetBody {
    otp: String,
    phone_number: String,
    new_password: String,
}

async fn reset_password(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: ResetBody = ctx.parse_body()?;
    let id = reset_identifier(&body.phone_number);
    // Check the code without spending it so a rejected password leaves it usable; a wrong
    // code goes through `verify_stored`, which counts the attempt.
    let mut consumed = false;
    if !inner.matches_usable(&ctx, &id, &body.otp).await? {
        inner.verify_stored(&ctx, &id, &body.otp).await?;
        consumed = true;
    }
    let Some(user) = find_by_phone(&ctx, &body.phone_number).await? else {
        return Err(bad(e::UNEXPECTED_ERROR));
    };
    assert_password_length(&ctx, &body.new_password)?;
    let auth = ctx.auth.clone();
    let hash = auth.hash_password(&body.new_password).await?;
    let consume = (!consumed).then(|| inner.verify_stored(&ctx, &id, &body.otp));
    reset_credential_password(&ctx, &user.id, &hash, consume).await?;
    if let Some(cb) = &auth.options.email_and_password.on_password_reset {
        cb.call(user).await?;
    }
    ctx.json(json!({ "status": true }))
}

macro_rules! route {
    ($inner:expr, $method:ident, $key:literal, $path:literal, $f:ident) => {{
        let inner = $inner.clone();
        Endpoint::$method($key, $path, handler(move |ctx| $f(inner.clone(), ctx)))
    }};
}

pub struct PhoneNumber {
    inner: Arc<Inner>,
}

pub fn phone_number(options: PhoneNumberOptions) -> Arc<dyn Plugin> {
    Arc::new(PhoneNumber { inner: Arc::new(Inner { options }) })
}

impl Plugin for PhoneNumber {
    fn id(&self) -> &str {
        "phone-number"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![TableExtension {
            key: "user".into(),
            fields: vec![
                (PHONE_NUMBER.into(), Field::string().optional().unique().sortable()),
                (PHONE_NUMBER_VERIFIED.into(), Field::boolean().optional().no_input()),
            ],
            ..Default::default()
        }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let i = &self.inner;
        vec![
            route!(i, post, "signInPhoneNumber", "/sign-in/phone-number", sign_in_phone_number),
            route!(i, post, "sendPhoneNumberOTP", "/phone-number/send-otp", send_phone_number_otp),
            route!(i, post, "consumePhoneNumberOTP", "/phone-number/consume-otp", consume_phone_number_otp)
                .server_only(),
            route!(i, post, "verifyPhoneNumber", "/phone-number/verify", verify_phone_number),
            route!(
                i,
                post,
                "requestPasswordResetPhoneNumber",
                "/phone-number/request-password-reset",
                request_password_reset
            ),
            route!(i, post, "resetPasswordPhoneNumber", "/phone-number/reset-password", reset_password),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        PluginHooks {
            // Only clearing the number is allowed through update-user; changing it needs a code.
            before: vec![MatchedHook::new(
                |ctx| {
                    ctx.path == "/update-user"
                        && matches!(ctx.body(), Value::Object(b) if b.get(PHONE_NUMBER).is_some_and(|v| !v.is_null()))
                },
                hook(|_ctx| async move { Err(bad(e::PHONE_NUMBER_CANNOT_BE_UPDATED)) }),
            )],
            after: vec![],
        }
    }

    fn database_hooks(&self) -> DatabaseHooks {
        // Clearing the number also clears its verification, in the same write.
        DatabaseHooks::new().before("user", Operation::Update, |data| async move {
            if data.get(PHONE_NUMBER).is_some_and(Value::is_null) {
                let mut merge = Map::new();
                merge.insert(PHONE_NUMBER_VERIFIED.into(), false.into());
                return Ok(BeforeOutcome::Merge(merge));
            }
            Ok(BeforeOutcome::Continue)
        })
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path_matcher: Arc::new(|p: &str| p.starts_with("/phone-number")),
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
