//! Two-factor authentication (`plugins/two-factor`): TOTP, emailed/SMS OTP and backup
//! codes, with trusted devices and account lockout.
//!
//! When a user with two factors enabled signs in (`/sign-in/email`, `/sign-in/username`,
//! `/sign-in/phone-number`), the session is withheld: the response becomes
//! `{ twoFactorRedirect: true, twoFactorMethods }` and a signed `two_factor` cookie carries
//! the pending challenge, which a `/two-factor/verify-*` call completes.

mod backup_codes;
mod otp;
mod totp;

use std::any::Any;
use std::sync::Arc;

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

pub use backup_codes::{BackupCodeOptions, StoreBackupCodes};
pub use otp::{OtpOptions, StoreOtp, TwoFactorOtp};
pub use totp::TotpOptions;

use crate::api::middleware::{require_sensitive_session, require_session};
use crate::api::routes::password::{check_password, should_require_password};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointOutput, EndpointResult, handler, hook};
use crate::cookies::{AuthCookie, delete_session_cookie, set_session_cookie};
use crate::crypto::{self, hmac_sign_base64url};
use crate::db::SessionOverrides;
use crate::db::{Field, OnDelete, Record, TableExtension, Where};
use crate::error::{ApiError, ErrorCode, Result};
use crate::options::RateLimitRule;
use crate::plugin::{MatchedHook, Plugin, PluginHooks, PluginRateLimit};
use crate::types::{Model, SessionWithUser, User};

pub const TWO_FACTOR_COOKIE_NAME: &str = "two_factor";
pub const TRUST_DEVICE_COOKIE_NAME: &str = "trust_device";
pub const TRUST_DEVICE_COOKIE_MAX_AGE: i64 = 30 * 24 * 60 * 60;
/// Per-challenge attempt budget for TOTP and backup codes.
pub const DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS: u32 = 5;
const TABLE: &str = "twoFactor";

/// Error codes (`TWO_FACTOR_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        OTP_NOT_ENABLED => "OTP not enabled",
        OTP_NOT_CONFIGURED => "OTP is not available",
        OTP_HAS_EXPIRED => "OTP has expired",
        TOTP_NOT_ENABLED => "TOTP not enabled",
        TOTP_ALREADY_ENABLED => "TOTP is already enabled",
        TOTP_NOT_CONFIGURED => "TOTP is not available",
        TWO_FACTOR_NOT_ENABLED => "Two factor isn't enabled",
        BACKUP_CODES_NOT_ENABLED => "Backup codes aren't enabled",
        INVALID_BACKUP_CODE => "Invalid backup code",
        INVALID_CODE => "Invalid code",
        TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE => "Too many attempts. Please request a new code.",
        ACCOUNT_TEMPORARILY_LOCKED => "Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
        INVALID_TWO_FACTOR_COOKIE => "Invalid two factor cookie",
    }
}

use error_codes as e;

/// Account-level lockout after consecutive failed second-factor verifications.
#[derive(Debug, Clone, Copy)]
pub struct AccountLockout {
    pub enabled: bool,
    /// Default 10.
    pub max_failed_attempts: i64,
    /// Default 15 minutes.
    pub duration_seconds: i64,
}

impl Default for AccountLockout {
    fn default() -> Self {
        Self { enabled: true, max_failed_attempts: 10, duration_seconds: 15 * 60 }
    }
}

#[derive(Clone, Default)]
pub struct TwoFactorOptions {
    /// Issuer shown in authenticator apps (default: the app name).
    pub issuer: Option<String>,
    pub totp: TotpOptions,
    pub otp: OtpOptions,
    pub backup_codes: BackupCodeOptions,
    /// Enable two factor immediately, without verifying a first code.
    pub skip_verification_on_enable: bool,
    /// Allow managing 2FA without a password for users that have no credential account.
    pub allow_passwordless: bool,
    /// Seconds to finish the second step after signing in (default 10 minutes).
    pub two_factor_cookie_max_age: Option<i64>,
    /// Seconds a trusted device skips the second factor (default 30 days).
    pub trust_device_max_age: Option<i64>,
    pub account_lockout: AccountLockout,
}

pub(crate) struct Inner {
    pub(crate) options: TwoFactorOptions,
}

impl Inner {
    fn trust_max_age(&self) -> i64 {
        self.options.trust_device_max_age.unwrap_or(TRUST_DEVICE_COOKIE_MAX_AGE)
    }

    fn trust_cookie(&self, ctx: &EndpointContext) -> AuthCookie {
        ctx.auth.cookie_factory.create(TRUST_DEVICE_COOKIE_NAME, Some(self.trust_max_age()))
    }

    fn passwordless(&self, specific: Option<bool>) -> bool {
        specific.unwrap_or(self.options.allow_passwordless)
    }
}

/// A user's `twoFactor` row.
#[derive(Debug, Clone)]
pub(crate) struct TwoFactorRow {
    pub id: String,
    pub secret: String,
    pub backup_codes: String,
    /// `None` on rows created before the column existed (treated as verified).
    pub verified: Option<bool>,
    pub failed_count: i64,
    pub locked_until: Option<chrono::DateTime<Utc>>,
}

impl TwoFactorRow {
    fn from_record(r: &Record) -> Option<Self> {
        let s = |k: &str| r.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            id: s("id")?,
            secret: s("secret").unwrap_or_default(),
            backup_codes: s("backupCodes").unwrap_or_default(),
            verified: r.get("verified").and_then(Value::as_bool),
            failed_count: r.get("failedVerificationCount").and_then(Value::as_i64).unwrap_or(0),
            locked_until: r.get("lockedUntil").and_then(crate::utils::date::parse_value),
        })
    }
}

pub(crate) async fn find_row(ctx: &EndpointContext, user_id: &str) -> Result<Option<TwoFactorRow>> {
    Ok(ctx.auth.db.find_one(TABLE, &[Where::eq("userId", user_id)]).await?.as_ref().and_then(TwoFactorRow::from_record))
}

fn two_factor_enabled(user: &User) -> bool {
    user.extra.get("twoFactorEnabled").and_then(Value::as_bool).unwrap_or(false)
}

// ---- lockout --------------------------------------------------------------------------

pub(crate) async fn assert_not_locked(
    ctx: &EndpointContext,
    inner: &Inner,
    row: &TwoFactorRow,
) -> Result<(), ApiError> {
    let lockout = inner.options.account_lockout;
    let Some(until) = row.locked_until.filter(|_| lockout.enabled) else { return Ok(()) };
    if until > Utc::now() {
        return Err(ApiError::from_code(http::StatusCode::TOO_MANY_REQUESTS, e::ACCOUNT_TEMPORARILY_LOCKED));
    }
    // Clear the expired lock, guarded on it still being expired.
    let mut update = Record::new();
    update.insert("failedVerificationCount".into(), 0.into());
    update.insert("lockedUntil".into(), Value::Null);
    let guard = [
        Where::eq("id", row.id.clone()),
        Where::new("lockedUntil", crate::db::Operator::Lte, crate::utils::date::now_value()),
    ];
    ctx.auth.db.update_many(TABLE, &guard, update).await?;
    Ok(())
}

/// Count a failure (compare-and-swap so concurrent failures are not lost) and lock the
/// account once the limit is reached.
pub(crate) async fn record_failure(ctx: &EndpointContext, inner: &Inner, row: &TwoFactorRow) -> Result<(), ApiError> {
    let lockout = inner.options.account_lockout;
    if !lockout.enabled {
        return Ok(());
    }
    let db = &ctx.auth.db;
    let mut current = row.failed_count;
    for _ in 0..10 {
        let mut update = Record::new();
        update.insert("failedVerificationCount".into(), (current + 1).into());
        let guard = [Where::eq("id", row.id.clone()), Where::eq("failedVerificationCount", current)];
        if db.update_many(TABLE, &guard, update).await? > 0 {
            if current + 1 >= lockout.max_failed_attempts {
                let mut lock = Record::new();
                let until = Utc::now() + chrono::Duration::seconds(lockout.duration_seconds);
                lock.insert("lockedUntil".into(), crate::utils::date::to_value(until));
                db.update_many(TABLE, &[Where::eq("id", row.id.clone())], lock).await?;
            }
            return Ok(());
        }
        let Some(fresh) = db.find_one(TABLE, &[Where::eq("id", row.id.clone())]).await? else { return Ok(()) };
        current = fresh.get("failedVerificationCount").and_then(Value::as_i64).unwrap_or(0);
    }
    Ok(())
}

pub(crate) async fn reset_failures(ctx: &EndpointContext, inner: &Inner, row: &TwoFactorRow) -> Result<(), ApiError> {
    if !inner.options.account_lockout.enabled {
        return Ok(());
    }
    let mut update = Record::new();
    update.insert("failedVerificationCount".into(), 0.into());
    update.insert("lockedUntil".into(), Value::Null);
    ctx.auth.db.update_many(TABLE, &[Where::eq("id", row.id.clone())], update).await?;
    Ok(())
}

// ---- verification context (verify-two-factor.ts) ------------------------------------------

/// The party completing a second-factor step: a pending sign-in challenge (from the
/// `two_factor` cookie) or an already signed-in user re-verifying.
pub(crate) struct Verification {
    pub user: User,
    pub session: Option<SessionWithUser>,
    /// Identifies the challenge (or session) for OTP storage.
    pub key: String,
    challenge: Option<Challenge>,
}

struct Challenge {
    identifier: String,
    cookie: AuthCookie,
    expires_at: chrono::DateTime<Utc>,
    dont_remember: bool,
}

/// An attempt slot taken from the challenge budget.
pub(crate) struct Attempt {
    identifier: String,
    attempts: u32,
    expires_at: chrono::DateTime<Utc>,
}

impl Attempt {
    async fn rearm(&self, ctx: &EndpointContext, count: u32) {
        let _ = ctx
            .auth
            .internal_adapter
            .create_verification_value(&self.identifier, &count.to_string(), self.expires_at)
            .await;
    }

    pub async fn record_failure(&self, ctx: &EndpointContext) {
        self.rearm(ctx, self.attempts + 1).await;
    }

    pub async fn restore(&self, ctx: &EndpointContext) {
        self.rearm(ctx, self.attempts).await;
    }
}

fn invalid_cookie() -> ApiError {
    ApiError::unauthorized(e::INVALID_TWO_FACTOR_COOKIE)
}

pub(crate) async fn verify_two_factor(ctx: &EndpointContext) -> Result<Verification, ApiError> {
    if let Some(session) = crate::api::middleware::get_session_from_ctx(ctx, Default::default()).await? {
        return Ok(Verification {
            key: format!("{}!{}", session.user.id, session.session.id),
            user: session.user.clone(),
            session: Some(session),
            challenge: None,
        });
    }
    let auth = &ctx.auth;
    let cookie = auth.cookie_factory.create(TWO_FACTOR_COOKIE_NAME, None);
    let identifier = ctx.get_signed_cookie(&cookie.name, &auth.secret).ok_or_else(invalid_cookie)?;
    let token = auth.internal_adapter.find_verification_value(&identifier).await?.ok_or_else(invalid_cookie)?;
    let user = auth.internal_adapter.find_user_by_id(&token.value).await?.ok_or_else(invalid_cookie)?;
    let dont_remember = ctx.get_signed_cookie(&auth.cookies.dont_remember.name, &auth.secret).is_some();
    Ok(Verification {
        user,
        session: None,
        key: identifier.clone(),
        challenge: Some(Challenge { identifier, cookie, expires_at: token.expires_at, dont_remember }),
    })
}

impl Verification {
    pub fn is_sign_in(&self) -> bool {
        self.session.is_none()
    }

    /// Take a slot from the challenge's attempt budget (sign-in only; re-verification is
    /// already authenticated and uncapped).
    pub async fn begin_attempt(&self, ctx: &EndpointContext, allowed: u32) -> Result<Option<Attempt>, ApiError> {
        let Some(challenge) = &self.challenge else { return Ok(None) };
        let identifier = format!("2fa-attempts-{}", challenge.identifier);
        let ia = &ctx.auth.internal_adapter;
        let consumed = ia.consume_verification_value(&identifier).await.ok().flatten().ok_or_else(invalid_cookie)?;
        let attempts = consumed.value.parse::<u32>().unwrap_or(allowed);
        if attempts >= allowed {
            // Budget spent: cancel the whole challenge.
            ia.consume_verification_value(&challenge.identifier).await?;
            ctx.expire_cookie(&challenge.cookie);
            return Err(ApiError::bad_request(e::TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE));
        }
        Ok(Some(Attempt { identifier, attempts, expires_at: challenge.expires_at }))
    }

    /// Complete the step: for a sign-in challenge, burn it and create the session (and a
    /// trusted-device cookie when asked); for re-verification, return the current session.
    pub async fn valid(&self, ctx: &EndpointContext, inner: &Inner) -> EndpointResult {
        let auth = &ctx.auth;
        let Some(challenge) = &self.challenge else {
            let session = self.session.as_ref().expect("re-verification has a session");
            return ctx.json(json!({ "token": session.session.token, "user": auth.user_output(&session.user) }));
        };
        let consumed = auth.internal_adapter.consume_verification_value(&challenge.identifier).await?;
        if consumed.is_none_or(|c| c.value != self.user.id) {
            ctx.expire_cookie(&challenge.cookie);
            return Err(invalid_cookie());
        }
        let session = auth.internal_adapter.create_session(&self.user.id, challenge.dont_remember, None).await?;
        let token = session.token.clone();
        set_session_cookie(ctx, &SessionWithUser { session, user: self.user.clone() }, None, None).await;
        ctx.expire_cookie(&challenge.cookie);
        if ctx.body().get("trustDevice").and_then(Value::as_bool) == Some(true) {
            issue_trust_cookie(ctx, inner, &self.user.id).await?;
            ctx.expire_cookie(&auth.cookies.dont_remember);
        }
        ctx.json(json!({ "token": token, "user": auth.user_output(&self.user) }))
    }
}

async fn issue_trust_cookie(ctx: &EndpointContext, inner: &Inner, user_id: &str) -> Result<(), ApiError> {
    let auth = &ctx.auth;
    let max_age = inner.trust_max_age();
    let identifier = format!("trust-device-{}", crypto::generate_random_string(32));
    let token = hmac_sign_base64url(&auth.secret, &format!("{user_id}!{identifier}"));
    let expires = Utc::now() + chrono::Duration::seconds(max_age);
    auth.internal_adapter.create_verification_value(&identifier, user_id, expires).await?;
    let cookie = inner.trust_cookie(ctx);
    ctx.set_signed_cookie(&cookie.name, &format!("{token}!{identifier}"), &auth.secret, &cookie.attributes);
    Ok(())
}

/// Replace the current session with a new one for an updated user (after enabling or
/// disabling two factors).
pub(crate) async fn rotate_session(
    ctx: &EndpointContext,
    current: &SessionWithUser,
    user: User,
) -> Result<String, ApiError> {
    let ia = &ctx.auth.internal_adapter;
    let overrides = SessionOverrides { data: current.session.to_record(), override_all: false };
    let session = ia.create_session(&user.id, false, Some(overrides)).await?;
    let token = session.token.clone();
    set_session_cookie(ctx, &SessionWithUser { session, user }, None, None).await;
    ia.delete_session(&current.session.token).await?;
    Ok(token)
}

async fn set_two_factor_enabled(ctx: &EndpointContext, user_id: &str, enabled: bool) -> Result<User, ApiError> {
    let mut update = Record::new();
    update.insert("twoFactorEnabled".into(), enabled.into());
    ctx.auth
        .internal_adapter
        .update_user(user_id, update)
        .await?
        .ok_or_else(|| ApiError::bad_request(crate::error::codes::USER_NOT_FOUND))
}

async fn require_password(
    ctx: &EndpointContext,
    user_id: &str,
    allow_passwordless: bool,
    password: Option<&str>,
) -> Result<(), ApiError> {
    if should_require_password(ctx, user_id, allow_passwordless).await? {
        check_password(ctx, user_id, password).await?;
    }
    Ok(())
}

// ---- enable / disable --------------------------------------------------------------------

#[derive(Deserialize)]
struct EnableBody {
    password: Option<String>,
    #[serde(default)]
    method: Option<String>,
    issuer: Option<String>,
}

async fn enable_two_factor(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body: EnableBody = ctx.parse_body()?;
    let user = session.user.clone();
    require_password(&ctx, &user.id, inner.options.allow_passwordless, body.password.as_deref()).await?;
    let method = body.method.as_deref().unwrap_or("totp");
    match method {
        "otp" if inner.options.otp.send_otp.is_none() => return Err(ApiError::bad_request(e::OTP_NOT_CONFIGURED)),
        "totp" if inner.options.totp.disable => return Err(ApiError::bad_request(e::TOTP_NOT_CONFIGURED)),
        "otp" | "totp" => {}
        _ => return Err(ApiError::bad_request(crate::error::codes::VALIDATION_ERROR)),
    }
    if method == "otp" {
        let updated = set_two_factor_enabled(&ctx, &user.id, true).await?;
        rotate_session(&ctx, &session, updated).await?;
        return ctx.json(json!({ "method": "otp" }));
    }
    let existing = find_row(&ctx, &user.id).await?;
    if existing.as_ref().is_some_and(|r| r.verified != Some(false)) {
        return Err(ApiError::bad_request(e::TOTP_ALREADY_ENABLED));
    }
    let auth = &ctx.auth;
    let codes = backup_codes::generate(&inner.options.backup_codes);
    let encoded_codes = backup_codes::encode(&codes, &auth.secret_config, &inner.options.backup_codes)?;
    let secret = crypto::generate_random_string(32);
    let encrypted_secret = crypto::symmetric_encrypt(&auth.secret_config, &secret)?;
    if inner.options.skip_verification_on_enable {
        let updated = set_two_factor_enabled(&ctx, &user.id, true).await?;
        rotate_session(&ctx, &session, updated).await?;
    }
    let mut data = Record::new();
    data.insert("secret".into(), encrypted_secret.into());
    data.insert("backupCodes".into(), encoded_codes.into());
    data.insert("verified".into(), inner.options.skip_verification_on_enable.into());
    match existing {
        Some(row) => {
            auth.db.update(TABLE, &[Where::eq("id", row.id)], data).await?;
        }
        None => {
            data.insert("userId".into(), user.id.clone().into());
            auth.db.create(TABLE, data, false).await?;
        }
    }
    let issuer = body.issuer.or_else(|| inner.options.issuer.clone()).unwrap_or_else(|| auth.options.app_name.clone());
    let uri =
        crypto::otp::totp_uri(&secret, &issuer, &user.email, inner.options.totp.digits(), inner.options.totp.period());
    ctx.json(json!({ "method": "totp", "totpURI": uri, "backupCodes": codes }))
}

#[derive(Deserialize)]
struct DisableBody {
    password: Option<String>,
}

async fn disable_two_factor(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    let body: DisableBody = ctx.parse_body()?;
    let user_id = session.user.id.clone();
    require_password(&ctx, &user_id, inner.options.allow_passwordless, body.password.as_deref()).await?;
    let updated = set_two_factor_enabled(&ctx, &user_id, false).await?;
    ctx.auth.db.delete(TABLE, &[Where::eq("userId", user_id)]).await?;
    rotate_session(&ctx, &session, updated).await?;
    let cookie = inner.trust_cookie(&ctx);
    if let Some(value) = ctx.get_signed_cookie(&cookie.name, &ctx.auth.secret) {
        if let Some((_, trust_id)) = value.split_once('!') {
            ctx.auth.internal_adapter.delete_verification_by_identifier(trust_id).await?;
        }
        ctx.expire_cookie(&cookie);
    }
    ctx.json(json!({ "status": true }))
}

// ---- sign-in interception --------------------------------------------------------------

/// Whether a valid, server-backed trusted-device cookie is present; rotates it if so.
async fn trusted_device(ctx: &EndpointContext, inner: &Inner, user_id: &str) -> Result<bool, ApiError> {
    let auth = &ctx.auth;
    let cookie = inner.trust_cookie(ctx);
    let Some(value) = ctx.get_signed_cookie(&cookie.name, &auth.secret) else { return Ok(false) };
    if let Some((token, identifier)) = value.split_once('!') {
        let expected = hmac_sign_base64url(&auth.secret, &format!("{user_id}!{identifier}"));
        if crypto::constant_time_eq(token.as_bytes(), expected.as_bytes()) {
            let record = auth.internal_adapter.find_verification_value(identifier).await?;
            if record.is_some_and(|r| r.value == user_id && r.expires_at > Utc::now()) {
                auth.internal_adapter.delete_verification_by_identifier(identifier).await?;
                issue_trust_cookie(ctx, inner, user_id).await?;
                return Ok(true);
            }
        }
    }
    ctx.expire_cookie(&cookie);
    Ok(false)
}

async fn after_sign_in(inner: Arc<Inner>, ctx: Ctx) -> Result<Option<EndpointOutput>, ApiError> {
    let Some(data) = ctx.new_session() else { return Ok(None) };
    if !two_factor_enabled(&data.user) || trusted_device(&ctx, &inner, &data.user.id).await? {
        return Ok(None);
    }
    let auth = ctx.auth.clone();
    delete_session_cookie(&ctx, true);
    auth.internal_adapter.delete_session(&data.session.token).await?;
    ctx.clear_new_session();
    let max_age = inner.options.two_factor_cookie_max_age.unwrap_or(10 * 60);
    let cookie = auth.cookie_factory.create(TWO_FACTOR_COOKIE_NAME, Some(max_age));
    let identifier = format!("2fa-{}", crypto::generate_random_string(20));
    let expires = Utc::now() + chrono::Duration::seconds(max_age);
    auth.internal_adapter.create_verification_value(&identifier, &data.user.id, expires).await?;
    // Per-challenge attempt counter, consumed atomically by the verify endpoints.
    auth.internal_adapter.create_verification_value(&format!("2fa-attempts-{identifier}"), "0", expires).await?;
    ctx.set_signed_cookie(&cookie.name, &identifier, &auth.secret, &cookie.attributes);
    let mut methods = vec![];
    if !inner.options.totp.disable && find_row(&ctx, &data.user.id).await?.is_some_and(|r| r.verified != Some(false)) {
        methods.push("totp");
    }
    if inner.options.otp.send_otp.is_some() {
        methods.push("otp");
    }
    Ok(Some(EndpointOutput::Json(json!({ "twoFactorRedirect": true, "twoFactorMethods": methods }))))
}

// ---- plugin -------------------------------------------------------------------------

pub struct TwoFactor {
    inner: Arc<Inner>,
}

pub fn two_factor(options: TwoFactorOptions) -> Arc<dyn Plugin> {
    Arc::new(TwoFactor { inner: Arc::new(Inner { options }) })
}

impl Plugin for TwoFactor {
    fn id(&self) -> &str {
        "two-factor"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![
            TableExtension {
                key: "user".into(),
                fields: vec![("twoFactorEnabled".into(), Field::boolean().optional().default(false).no_input())],
                ..Default::default()
            },
            TableExtension {
                key: TABLE.into(),
                fields: vec![
                    ("secret".into(), Field::string().hidden().indexed()),
                    ("backupCodes".into(), Field::string().hidden()),
                    ("userId".into(), Field::string().hidden().references("user", "id", OnDelete::Cascade).indexed()),
                    ("verified".into(), Field::boolean().optional().default(true).no_input()),
                    ("failedVerificationCount".into(), Field::number().optional().default(0).no_input().hidden()),
                    ("lockedUntil".into(), Field::date().optional().no_input().hidden()),
                ],
                ..Default::default()
            },
        ]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let i = &self.inner;
        let (a, b) = (i.clone(), i.clone());
        let mut endpoints = vec![
            Endpoint::post(
                "enableTwoFactor",
                "/two-factor/enable",
                handler(move |ctx| enable_two_factor(a.clone(), ctx)),
            ),
            Endpoint::post(
                "disableTwoFactor",
                "/two-factor/disable",
                handler(move |ctx| disable_two_factor(b.clone(), ctx)),
            ),
        ];
        endpoints.extend(totp::endpoints(i));
        endpoints.extend(otp::endpoints(i));
        endpoints.extend(backup_codes::endpoints(i));
        endpoints
    }

    fn hooks(&self) -> PluginHooks {
        let inner = self.inner.clone();
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |ctx| matches!(ctx.path.as_str(), "/sign-in/email" | "/sign-in/username" | "/sign-in/phone-number"),
                hook(move |ctx| after_sign_in(inner.clone(), ctx)),
            )],
        }
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path_matcher: Arc::new(|p: &str| p.starts_with("/two-factor/")),
            rule: RateLimitRule { window: 10, max: 3 },
        }]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
