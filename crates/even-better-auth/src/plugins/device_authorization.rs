//! OAuth 2.0 Device Authorization Grant (`plugins/device-authorization`, RFC 8628): a device
//! gets a device code and a short user code, the user approves it at `/device` while signed
//! in, and the device polls `/device/token` for a session token.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::future::BoxFuture;
use http::StatusCode;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use url::Url;

use crate::api::middleware::get_session_from_ctx;
use crate::api::routes::session::GetSessionOptions;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::db::{Field, Record, TableExtension, Where};
use crate::error::{ApiError, Error, ErrorCode, Result};
use crate::options::RateLimitRule;
use crate::plugin::{Plugin, PluginRateLimit};
use crate::types::SessionWithUser;

/// Error codes (`DEVICE_AUTHORIZATION_ERROR_CODES`); their messages are the
/// `error_description`s of the OAuth-style errors.
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        INVALID_DEVICE_CODE => "Invalid device code",
        EXPIRED_DEVICE_CODE => "Device code has expired",
        EXPIRED_USER_CODE => "User code has expired",
        AUTHORIZATION_PENDING => "Authorization pending",
        ACCESS_DENIED => "Access denied",
        INVALID_USER_CODE => "Invalid user code",
        DEVICE_CODE_ALREADY_PROCESSED => "Device code already processed",
        DEVICE_CODE_NOT_CLAIMED => "Device code has not been claimed by a verifying session; call `GET /device` with the `user_code` while signed in before approving or denying",
        POLLING_TOO_FREQUENTLY => "Polling too frequently",
        USER_NOT_FOUND => "User not found",
        FAILED_TO_CREATE_SESSION => "Failed to create session",
        INVALID_DEVICE_CODE_STATUS => "Invalid device code status",
        AUTHENTICATION_REQUIRED => "Authentication required",
    }
}

use error_codes as e;

/// Maximum device/user code length (indexed columns).
pub const CODE_MAX_LENGTH: usize = 191;
const DEFAULT_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const MAX_GENERATION_ATTEMPTS: usize = 3;
const MODEL: &str = "deviceCode";

pub type CodeFn = Arc<dyn Fn() -> BoxFuture<'static, Result<String>> + Send + Sync>;
pub type ValidateClientFn = Arc<dyn Fn(String) -> BoxFuture<'static, Result<bool>> + Send + Sync>;
pub type DeviceAuthRequestFn = Arc<dyn Fn(String, Option<String>) -> BoxFuture<'static, Result<()>> + Send + Sync>;

#[derive(Clone)]
pub struct DeviceAuthorizationOptions {
    /// Device code lifetime. Default 30 minutes.
    pub expires_in: Duration,
    /// Minimum polling interval. Default 5 seconds.
    pub interval: Duration,
    /// Default 40 (at most [`CODE_MAX_LENGTH`]).
    pub device_code_length: usize,
    /// Default 8 (at most [`CODE_MAX_LENGTH`]).
    pub user_code_length: usize,
    pub generate_device_code: Option<CodeFn>,
    pub generate_user_code: Option<CodeFn>,
    pub validate_client: Option<ValidateClientFn>,
    pub on_device_auth_request: Option<DeviceAuthRequestFn>,
    /// Absolute URL or path (relative to the base URL). Default `/device`.
    pub verification_uri: Option<String>,
}

impl Default for DeviceAuthorizationOptions {
    fn default() -> Self {
        Self {
            expires_in: Duration::from_secs(30 * 60),
            interval: Duration::from_secs(5),
            device_code_length: 40,
            user_code_length: 8,
            generate_device_code: None,
            generate_user_code: None,
            validate_client: None,
            on_device_auth_request: None,
            verification_uri: None,
        }
    }
}

/// An RFC 6749 error response: `{ "error": ..., "error_description": ... }`.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> ApiError {
    let mut body = Map::new();
    body.insert("error".into(), error.into());
    body.insert("error_description".into(), description.into());
    ApiError { status, body, headers: Default::default() }
}

fn bad(error: &str, code: ErrorCode) -> ApiError {
    oauth_error(StatusCode::BAD_REQUEST, error, code.message)
}

fn server_error(code: ErrorCode) -> ApiError {
    oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", code.message)
}

fn normalize_user_code(code: &str) -> String {
    code.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_uppercase()
}

fn is_default_user_code(code: &str) -> bool {
    !code.is_empty() && code.bytes().all(|b| DEFAULT_CHARSET.contains(&b.to_ascii_uppercase()))
}

/// A device-code row.
#[derive(Debug, Clone)]
struct DeviceCode {
    id: String,
    user_code: String,
    user_id: Option<String>,
    expires_at: chrono::DateTime<Utc>,
    status: String,
    last_polled_at: Option<chrono::DateTime<Utc>>,
    polling_interval: Option<i64>,
    client_id: Option<String>,
    scope: Option<String>,
}

fn parse_date(v: Option<&Value>) -> Option<chrono::DateTime<Utc>> {
    crate::utils::date::parse_value(v?)
}

impl DeviceCode {
    fn from_record(r: &Record) -> Option<Self> {
        let s = |k: &str| r.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            id: s("id")?,
            user_code: s("userCode")?,
            user_id: s("userId"),
            expires_at: parse_date(r.get("expiresAt"))?,
            status: s("status")?,
            last_polled_at: parse_date(r.get("lastPolledAt")),
            polling_interval: r.get("pollingInterval").and_then(Value::as_i64),
            client_id: s("clientId"),
            scope: s("scope"),
        })
    }
}

async fn find_by(ctx: &EndpointContext, field: &str, value: &str) -> Result<Option<DeviceCode>> {
    let row = ctx.auth.db.find_one(MODEL, &[Where::eq(field, value)]).await?;
    Ok(row.as_ref().and_then(DeviceCode::from_record))
}

/// Exact match first, then the normalized form of default-alphabet codes (`ABCD-EFGH`).
async fn find_by_user_code(ctx: &EndpointContext, user_code: &str) -> Result<Option<DeviceCode>> {
    let exact = |d: Option<DeviceCode>, v: &str| d.filter(|d| d.user_code == v);
    if let Some(found) = exact(find_by(ctx, "userCode", user_code).await?, user_code) {
        return Ok(Some(found));
    }
    let normalized = normalize_user_code(user_code);
    if normalized == user_code || !is_default_user_code(&normalized) {
        return Ok(None);
    }
    Ok(exact(find_by(ctx, "userCode", &normalized).await?, &normalized))
}

fn id_where(id: &str) -> Where {
    Where::eq("id", id)
}

struct Inner {
    options: DeviceAuthorizationOptions,
}

impl Inner {
    async fn code(
        &self,
        custom: &Option<CodeFn>,
        label: &str,
        default: impl Fn() -> String,
    ) -> std::result::Result<String, ApiError> {
        let code = match custom {
            Some(f) => f().await?,
            None => default(),
        };
        if code.chars().count() > CODE_MAX_LENGTH {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("Generated {label} code must be at most {CODE_MAX_LENGTH} characters"),
            ));
        }
        Ok(code)
    }

    fn verification_uris(&self, ctx: &EndpointContext, user_code: &str) -> (String, String) {
        let uri = self.options.verification_uri.as_deref().unwrap_or("/device");
        let base = ctx.base_url.clone();
        let url = Url::parse(uri)
            .or_else(|_| Url::parse(&base).and_then(|b| b.join(uri)))
            .map(String::from)
            .unwrap_or_else(|_| uri.to_owned());
        let complete = match Url::parse(&url) {
            Ok(mut u) => {
                let pairs: Vec<(String, String)> = u
                    .query_pairs()
                    .filter(|(k, _)| k != "user_code")
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                u.query_pairs_mut().clear().extend_pairs(pairs).append_pair("user_code", user_code);
                u.to_string()
            }
            Err(_) => format!("{url}?user_code={user_code}"),
        };
        (url, complete)
    }
}

#[derive(Default)]
struct CodeRequest {
    client_id: Option<String>,
    user_id: Option<String>,
    scope: Option<String>,
}

/// Body fields, with RFC 8628 §3.1 semantics: empty values are omitted, repeated form
/// parameters are rejected.
fn code_request(ctx: &EndpointContext) -> std::result::Result<CodeRequest, ApiError> {
    let invalid = |d: &str| oauth_error(StatusCode::BAD_REQUEST, "invalid_request", d);
    let raw_form = ctx
        .header("content-type")
        .is_some_and(|c| c.to_lowercase().contains("application/x-www-form-urlencoded"))
        .then(|| ctx.raw_body())
        .flatten();
    let mut req = CodeRequest::default();
    if let Some(raw) = raw_form {
        for field in ["client_id", "user_id", "scope"] {
            let values: Vec<String> = url::form_urlencoded::parse(&raw)
                .filter(|(k, v)| k == field && !v.is_empty())
                .map(|(_, v)| v.into_owned())
                .collect();
            if values.len() > 1 {
                return Err(invalid(&format!("{field} must not be repeated")));
            }
            let value = values.into_iter().next();
            match field {
                "client_id" => req.client_id = value,
                "user_id" => req.user_id = value,
                _ => req.scope = value,
            }
        }
        return Ok(req);
    }
    let Value::Object(body) = ctx.body() else { return Err(invalid("Invalid body")) };
    let field = |k: &str| -> std::result::Result<Option<String>, ApiError> {
        match body.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone()).filter(|s| !s.is_empty())),
            Some(_) => Err(invalid(&format!("[body.{k}] Invalid input: expected string"))),
        }
    };
    if !body.contains_key("client_id") {
        return Err(invalid("[body.client_id] Invalid input: expected string, received undefined"));
    }
    req.client_id = field("client_id")?;
    req.user_id = field("user_id")?;
    req.scope = field("scope")?;
    Ok(req)
}

fn is_unique_violation(err: &Error) -> bool {
    let msg = err.to_string().to_lowercase();
    ["unique", "duplicate", "e11000", "23505", "1062", "2067"].iter().any(|k| msg.contains(k))
}

async fn device_code(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let opts = &inner.options;
    let request = code_request(&ctx)?;
    let Some(client_id) = request.client_id.clone() else {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "client_id is required"));
    };
    if let Some(validate) = &opts.validate_client
        && !validate(client_id.clone()).await?
    {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_client", "Invalid client ID"));
    }
    if let Some(cb) = &opts.on_device_auth_request {
        cb(client_id.clone(), request.scope.clone()).await?;
    }
    let expires_at = Utc::now() + chrono::Duration::from_std(opts.expires_in).unwrap_or_default();
    for _ in 0..MAX_GENERATION_ATTEMPTS {
        let device_code = inner
            .code(&opts.generate_device_code, "device", || {
                crate::crypto::generate_random_string(opts.device_code_length)
            })
            .await?;
        let user_code = inner
            .code(&opts.generate_user_code, "user", || {
                crate::crypto::random_string(opts.user_code_length, DEFAULT_CHARSET)
            })
            .await?;
        let mut row = Record::new();
        row.insert("deviceCode".into(), device_code.clone().into());
        row.insert("userCode".into(), user_code.clone().into());
        row.insert("userId".into(), request.user_id.clone().map(Value::from).unwrap_or(Value::Null));
        row.insert("expiresAt".into(), crate::utils::date::to_value(expires_at));
        row.insert("status".into(), "pending".into());
        row.insert("pollingInterval".into(), (opts.interval.as_millis() as i64).into());
        row.insert("clientId".into(), client_id.clone().into());
        row.insert("scope".into(), request.scope.clone().map(Value::from).unwrap_or(Value::Null));
        match ctx.auth.db.create(MODEL, row, false).await {
            Ok(_) => {}
            Err(err) if is_unique_violation(&err) => continue,
            Err(err) => return Err(err.into()),
        }
        let (uri, complete) = inner.verification_uris(&ctx, &user_code);
        ctx.set_header("cache-control", "no-store");
        ctx.set_header("pragma", "no-cache");
        return ctx.json(json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": uri,
            "verification_uri_complete": complete,
            "expires_in": opts.expires_in.as_secs(),
            "interval": opts.interval.as_secs(),
        }));
    }
    Err(oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "Failed to generate a unique device code"))
}

#[derive(Deserialize)]
struct TokenBody {
    grant_type: String,
    device_code: String,
    client_id: String,
}

async fn device_token(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: TokenBody = ctx.parse_body()?;
    if body.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "Invalid grant_type"));
    }
    if let Some(validate) = &inner.options.validate_client
        && !validate(body.client_id.clone()).await?
    {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid client ID"));
    }
    let db = &ctx.auth.db;
    let Some(record) = find_by(&ctx, "deviceCode", &body.device_code).await? else {
        return Err(bad("invalid_grant", e::INVALID_DEVICE_CODE));
    };
    if record.client_id.as_deref().is_some_and(|c| c != body.client_id) {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "Client ID mismatch"));
    }
    let now = Utc::now();
    if let (Some(last), Some(interval)) = (record.last_polled_at, record.polling_interval)
        && (now - last).num_milliseconds() < interval
    {
        return Err(bad("slow_down", e::POLLING_TOO_FREQUENTLY));
    }
    let mut polled = Record::new();
    polled.insert("lastPolledAt".into(), crate::utils::date::to_value(now));
    db.update(MODEL, &[id_where(&record.id)], polled).await?;
    if record.expires_at < now {
        db.delete(MODEL, &[id_where(&record.id)]).await?;
        return Err(bad("expired_token", e::EXPIRED_DEVICE_CODE));
    }
    match record.status.as_str() {
        "pending" => return Err(bad("authorization_pending", e::AUTHORIZATION_PENDING)),
        "denied" => {
            db.delete(MODEL, &[id_where(&record.id)]).await?;
            return Err(bad("access_denied", e::ACCESS_DENIED));
        }
        _ => {}
    }
    let Some(user_id) = record.user_id.clone().filter(|_| record.status == "approved") else {
        return Err(server_error(e::INVALID_DEVICE_CODE_STATUS));
    };
    let Some(user) = ctx.auth.internal_adapter.find_user_by_id(&user_id).await? else {
        return Err(server_error(e::USER_NOT_FOUND));
    };
    // Every fallible check happens before this destructive claim, so concurrent polls
    // cannot both issue credentials from the same code.
    let claimed = db
        .consume_one(
            MODEL,
            &[id_where(&record.id), Where::eq("clientId", body.client_id.as_str()), Where::eq("status", "approved")],
        )
        .await?;
    let claimed = claimed.as_ref().and_then(DeviceCode::from_record).filter(|c| c.user_id.is_some());
    let Some(claimed) = claimed else { return Err(bad("invalid_grant", e::INVALID_DEVICE_CODE)) };
    let session = ctx
        .auth
        .internal_adapter
        .create_session(&user.id, false, None)
        .await
        .map_err(|_| server_error(e::FAILED_TO_CREATE_SESSION))?;
    let expires_in = (session.expires_at - Utc::now()).num_seconds();
    let token = session.token.clone();
    ctx.set_new_session(SessionWithUser { session, user });
    ctx.set_header("cache-control", "no-store");
    ctx.set_header("pragma", "no-cache");
    ctx.json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": claimed.scope.unwrap_or_default(),
    }))
}

async fn device_verify(ctx: Ctx) -> EndpointResult {
    let Some(user_code) = ctx.query_str("user_code") else {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "[query.user_code] Invalid input"));
    };
    let Some(mut record) = find_by_user_code(&ctx, &user_code).await? else {
        return Err(bad("invalid_request", e::INVALID_USER_CODE));
    };
    if record.expires_at < Utc::now() {
        return Err(bad("expired_token", e::EXPIRED_USER_CODE));
    }
    let session = get_session_from_ctx(&ctx, GetSessionOptions::default()).await?;
    if let Some(s) = &session
        && record.user_id.is_none()
        && record.status == "pending"
    {
        let mut set = Record::new();
        set.insert("userId".into(), s.user.id.clone().into());
        let guard = [id_where(&record.id), Where::eq("status", "pending"), Where::eq("userId", Value::Null)];
        if ctx.auth.db.update(MODEL, &guard, set).await?.is_some() {
            record.user_id = Some(s.user.id.clone());
        }
    }
    let can_review = session.as_ref().is_some_and(|s| record.user_id.as_deref() == Some(s.user.id.as_str()));
    let mut out = json!({ "user_code": user_code, "status": record.status });
    if can_review {
        out["client_id"] = record.client_id.map(Value::from).unwrap_or(Value::Null);
        out["scope"] = record.scope.map(Value::from).unwrap_or(Value::Null);
    }
    ctx.json(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecisionBody {
    user_code: String,
}

async fn decide(ctx: Ctx, approve: bool) -> EndpointResult {
    let Some(session) = get_session_from_ctx(&ctx, GetSessionOptions::default()).await? else {
        return Err(oauth_error(StatusCode::UNAUTHORIZED, "unauthorized", e::AUTHENTICATION_REQUIRED.message));
    };
    let body: DecisionBody = ctx.parse_body()?;
    let Some(record) = find_by_user_code(&ctx, &body.user_code).await? else {
        return Err(bad("invalid_request", e::INVALID_USER_CODE));
    };
    if record.expires_at < Utc::now() {
        return Err(bad("expired_token", e::EXPIRED_USER_CODE));
    }
    if record.status != "pending" {
        return Err(bad("invalid_request", e::DEVICE_CODE_ALREADY_PROCESSED));
    }
    let Some(owner) = &record.user_id else { return Err(bad("invalid_request", e::DEVICE_CODE_NOT_CLAIMED)) };
    if *owner != session.user.id {
        let verb = if approve { "approve" } else { "deny" };
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            &format!("You are not authorized to {verb} this device authorization"),
        ));
    }
    let mut update = Record::new();
    update.insert("status".into(), if approve { "approved" } else { "denied" }.into());
    update.insert("userId".into(), session.user.id.clone().into());
    ctx.auth.db.update(MODEL, &[id_where(&record.id)], update).await?;
    ctx.json(json!({ "success": true }))
}

pub struct DeviceAuthorization {
    inner: Arc<Inner>,
}

/// Fails when a code length is zero or above [`CODE_MAX_LENGTH`].
pub fn device_authorization(options: DeviceAuthorizationOptions) -> Result<Arc<dyn Plugin>> {
    for (name, len) in [("deviceCodeLength", options.device_code_length), ("userCodeLength", options.user_code_length)]
    {
        if len == 0 || len > CODE_MAX_LENGTH {
            return Err(Error::Config(format!("{name} must be between 1 and {CODE_MAX_LENGTH}")));
        }
    }
    Ok(Arc::new(DeviceAuthorization { inner: Arc::new(Inner { options }) }))
}

impl Plugin for DeviceAuthorization {
    fn id(&self) -> &str {
        "device-authorization"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![TableExtension {
            key: MODEL.into(),
            fields: vec![
                ("deviceCode".into(), Field::string().unique()),
                ("userCode".into(), Field::string().unique()),
                ("userId".into(), Field::string().optional()),
                ("expiresAt".into(), Field::date()),
                ("status".into(), Field::string()),
                ("lastPolledAt".into(), Field::date().optional()),
                ("pollingInterval".into(), Field::number().optional()),
                ("clientId".into(), Field::string().optional()),
                ("scope".into(), Field::string().optional()),
            ],
            ..Default::default()
        }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b) = (self.inner.clone(), self.inner.clone());
        vec![
            Endpoint::post("deviceCode", "/device/code", handler(move |ctx| device_code(a.clone(), ctx))).allow_form(),
            Endpoint::post("deviceToken", "/device/token", handler(move |ctx| device_token(b.clone(), ctx)))
                .allow_form(),
            Endpoint::get("deviceVerify", "/device", handler(device_verify)),
            Endpoint::post("deviceApprove", "/device/approve", handler(|ctx| decide(ctx, true))),
            Endpoint::post("deviceDeny", "/device/deny", handler(|ctx| decide(ctx, false))),
        ]
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path_matcher: Arc::new(|p: &str| p == "/device"),
            rule: RateLimitRule { window: self.inner.options.expires_in.as_secs(), max: 5 },
        }]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes() {
        assert_eq!(normalize_user_code("abcd-efgh"), "ABCDEFGH");
        assert!(is_default_user_code("ABCDEFGH"));
        assert!(!is_default_user_code("ABCD0EFG"), "0 is not in the default alphabet");
    }
}
