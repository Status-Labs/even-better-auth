//! Endpoints and key validation (`routes/*`, `rate-limit.ts`, `org-authorization.ts`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use http::StatusCode;
use serde_json::{Map, Value, json};

use super::store::{self, Record, Sort, date_field, int_field, str_field};
use super::{
    API_KEY_TABLE, ApiKeyOptions, ApiKeyReferences, ApiKeyStorage, DefaultPermissions, Inner, config_id_matches,
    error_codes as e, is_default_config_id, public_key, status_error,
};
use crate::api::middleware::{get_session_from_ctx, require_session};
use crate::api::routes::session::GetSessionOptions;
use crate::api::{Ctx, EndpointContext, EndpointResult};
use crate::db::Where;
use crate::error::{ApiError, ErrorCode, codes};
use crate::plugins::access::{Connector, Role};
use crate::plugins::organization::Organization;
use crate::types::SessionWithUser;
use crate::utils::date;

/// The access-control resource organization roles grant for API keys
/// (`apiKey: ["create", "read", "update", "delete"]`).
pub const API_KEY_PERMISSION_RESOURCE: &str = "apiKey";

type ApiResult<T> = std::result::Result<T, ApiError>;

// ---- body and query parsing ---------------------------------------------------------------

fn invalid(location: &str, field: &str, message: &str) -> ApiError {
    ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", format!("[{location}.{field}] {message}"))
}

/// Typed access to a JSON body, distinguishing absent from `null` like zod.
struct Body(Map<String, Value>);

impl Body {
    fn new(ctx: &EndpointContext) -> ApiResult<Self> {
        match ctx.body() {
            Value::Object(m) => Ok(Self(m)),
            Value::Null => Ok(Self(Map::new())),
            _ => Err(invalid("body", "", "Invalid input: expected object")),
        }
    }

    fn get(&self, k: &str) -> Option<&Value> {
        self.0.get(k)
    }

    fn string(&self, k: &str) -> ApiResult<Option<String>> {
        match self.get(k) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(invalid("body", k, "Invalid input: expected string")),
        }
    }

    /// `z.coerce.string()`.
    fn coerced_string(&self, k: &str) -> ApiResult<Option<String>> {
        Ok(match self.get(k) {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(v) => Some(v.to_string()),
        })
    }

    fn required_string(&self, k: &str) -> ApiResult<String> {
        self.string(k)?.ok_or_else(|| invalid("body", k, "Invalid input: expected string, received undefined"))
    }

    fn boolean(&self, k: &str) -> ApiResult<Option<bool>> {
        match self.get(k) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(invalid("body", k, "Invalid input: expected boolean")),
        }
    }

    /// An integer: absent, `null` (when `nullable`), or a number not below `min`.
    fn int(&self, k: &str, min: Option<i64>, nullable: bool) -> ApiResult<Option<Option<i64>>> {
        let n = match self.get(k) {
            None => return Ok(None),
            Some(Value::Null) if nullable => return Ok(Some(None)),
            Some(Value::Number(n)) => {
                match n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)) {
                    Some(n) => n,
                    None => return Err(invalid("body", k, "Invalid input: expected int")),
                }
            }
            Some(_) => return Err(invalid("body", k, "Invalid input: expected number")),
        };
        if let Some(min) = min
            && n < min
        {
            return Err(invalid("body", k, &format!("Too small: expected number to be >={min}")));
        }
        Ok(Some(Some(n)))
    }

    fn permissions(&self, k: &str, nullable: bool) -> ApiResult<Option<Option<Map<String, Value>>>> {
        match self.get(k) {
            None => Ok(None),
            Some(Value::Null) if nullable => Ok(Some(None)),
            Some(Value::Object(m))
                if m.values().all(|v| v.as_array().is_some_and(|a| a.iter().all(Value::is_string))) =>
            {
                Ok(Some(Some(m.clone())))
            }
            Some(_) => Err(invalid("body", k, "Invalid input: expected record")),
        }
    }
}

/// JavaScript truthiness, for checks the TS code makes with `if (value)`.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

// ---- helpers ------------------------------------------------------------------------------

fn hash_key(key: &str, opts: &ApiKeyOptions) -> String {
    if opts.disable_key_hashing { key.to_owned() } else { crate::crypto::sha256_base64url(key) }
}

const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Delete expired keys at most every 10 seconds (`deleteAllExpiredApiKeys`) unless `bypass`.
async fn cleanup(auth: &crate::context::AuthContext, inner: &Inner, bypass: bool) -> crate::error::Result<()> {
    {
        let mut last = inner.last_cleanup.lock().expect("lock");
        if !bypass && last.is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
            return Ok(());
        }
        *last = Some(Instant::now());
    }
    auth.db
        .delete_many(API_KEY_TABLE, &[Where::lt("expiresAt", date::now_value()), Where::ne("expiresAt", Value::Null)])
        .await
        .map(|_| ())
}

/// Run the expired-key cleanup without waiting for it.
pub(super) fn spawn_cleanup(ctx: &EndpointContext, inner: &Arc<Inner>) {
    let (auth, inner) = (ctx.auth.clone(), inner.clone());
    tokio::spawn(async move {
        if let Err(e) = cleanup(&auth, &inner, false).await {
            tracing::error!(error = %e, "Failed to delete expired API keys");
        }
    });
}

/// Remove a key, now or (with `defer_updates`) in the background.
async fn discard(ctx: &EndpointContext, inner: &Arc<Inner>, key: &Record, opts: &ApiKeyOptions) -> ApiResult<()> {
    if opts.defer_updates {
        let (auth, inner, key, opts) = (ctx.auth.clone(), inner.clone(), key.clone(), opts.clone());
        tokio::spawn(async move {
            if let Err(e) = store::delete_everywhere(&auth, &inner, &key, &opts).await {
                tracing::error!(error = %e, "Deferred update failed");
            }
        });
        return Ok(());
    }
    Ok(store::delete_everywhere(&ctx.auth, inner, key, opts).await?)
}

/// `checkOrgApiKeyPermission`: the user must be a member of the organization whose role
/// grants `apiKey: [action]` (owners always do).
async fn check_org_permission(
    ctx: &EndpointContext,
    user_id: &str,
    organization_id: &str,
    action: &str,
) -> ApiResult<()> {
    let Some(org) = ctx.auth.plugin("organization").and_then(|p| p.as_any().downcast_ref::<Organization>()) else {
        return Err(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::ORGANIZATION_PLUGIN_REQUIRED));
    };
    let member = ctx
        .auth
        .db
        .find_one("member", &[Where::eq("userId", user_id), Where::eq("organizationId", organization_id)])
        .await?;
    let Some(member) = member else {
        return Err(ApiError::forbidden(e::USER_NOT_MEMBER_OF_ORGANIZATION));
    };
    let permissions = Map::from_iter([(API_KEY_PERMISSION_RESOURCE.to_owned(), json!([action]))]);
    let role = str_field(&member, "role").unwrap_or_default();
    let allowed = org.role_has_permission(ctx, organization_id, role, &permissions, true).await.unwrap_or(false);
    if !allowed {
        return Err(ApiError::forbidden(e::INSUFFICIENT_API_KEY_PERMISSIONS));
    }
    Ok(())
}

/// The session from the store, not the cookie cache: keys are long-lived credentials, so a
/// revoked session must not mint or change one.
async fn authoritative(ctx: &EndpointContext) -> ApiResult<Option<SessionWithUser>> {
    get_session_from_ctx(ctx, GetSessionOptions { disable_cookie_cache: ctx.auth.is_stateful(), ..Default::default() })
        .await
}

/// Called over HTTP or with request headers (as opposed to a bare server call).
fn is_client_call(ctx: &EndpointContext) -> bool {
    ctx.is_request || !ctx.headers().is_empty()
}

/// Look up a key by id and check the caller may `action` it; returns the key and its own
/// configuration.
async fn owned_key<'a>(
    ctx: &EndpointContext,
    inner: &'a Arc<Inner>,
    config_id: Option<&str>,
    key_id: &str,
    user_id: &str,
    action: &str,
) -> ApiResult<(Record, &'a ApiKeyOptions)> {
    let lookup = inner.resolve(config_id)?;
    let key = store::get_by_id(&ctx.auth, inner, key_id, lookup).await?;
    let Some(key) = key.filter(|k| config_id_matches(str_field(k, "configId"), Some(lookup.id()))) else {
        return Err(ApiError::not_found(e::KEY_NOT_FOUND));
    };
    let opts = inner.resolve(str_field(&key, "configId"))?;
    let reference_id = str_field(&key, "referenceId").unwrap_or_default();
    match opts.references {
        ApiKeyReferences::Organization => check_org_permission(ctx, user_id, reference_id, action).await?,
        ApiKeyReferences::User if reference_id != user_id => return Err(ApiError::not_found(e::KEY_NOT_FOUND)),
        ApiKeyReferences::User => {}
    }
    Ok((key, opts))
}

// ---- validation and usage -----------------------------------------------------------------

/// `validateApiKey`: find the key, check it is usable and allowed `permissions`, then claim
/// one use (quota and rate limit). Returns the updated key and its configuration.
pub(super) async fn validate_api_key<'a>(
    inner: &'a Arc<Inner>,
    ctx: &EndpointContext,
    key: &str,
    lookup: &ApiKeyOptions,
    permissions: Option<&Map<String, Value>>,
    expected_config_id: Option<&str>,
    run_custom_validator: bool,
) -> ApiResult<(Record, &'a ApiKeyOptions)> {
    let hashed = hash_key(key, lookup);
    let Some(api_key) = store::get_by_hash(&ctx.auth, inner, &hashed, lookup).await? else {
        return Err(ApiError::unauthorized(e::INVALID_API_KEY));
    };
    if let Some(expected) = expected_config_id
        && !config_id_matches(str_field(&api_key, "configId"), Some(expected))
    {
        return Err(ApiError::unauthorized(e::INVALID_API_KEY));
    }
    // Validate and update with the key's own configuration.
    let opts = inner.resolve(str_field(&api_key, "configId"))?;
    if run_custom_validator
        && let Some(validate) = &opts.custom_api_key_validator
        && !validate(ctx, key).await?
    {
        return Err(ApiError::unauthorized(e::KEY_NOT_FOUND));
    }
    if api_key.get("enabled") == Some(&Value::Bool(false)) {
        return Err(ApiError::unauthorized(e::KEY_DISABLED));
    }
    if date_field(&api_key, "expiresAt").is_some_and(|exp| Utc::now() > exp) {
        discard(ctx, inner, &api_key, opts).await?;
        return Err(ApiError::unauthorized(e::KEY_EXPIRED));
    }
    if let Some(requested) = permissions {
        let Some(granted) = store::parse_permissions(&api_key) else {
            return Err(ApiError::unauthorized(e::KEY_NOT_FOUND));
        };
        let statements = granted
            .into_iter()
            .map(|(r, a)| {
                let actions = a.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect());
                (r, actions.unwrap_or_default())
            })
            .collect();
        if !Role::new(statements).authorize(requested, Connector::And).success() {
            return Err(ApiError::unauthorized(e::KEY_NOT_FOUND));
        }
    }
    // A non-refillable key that is used up is removed.
    if int_field(&api_key, "remaining") == Some(0) && int_field(&api_key, "refillAmount").is_none() {
        discard(ctx, inner, &api_key, opts).await?;
        return Err(ApiError::from_code(StatusCode::TOO_MANY_REQUESTS, e::USAGE_EXCEEDED));
    }
    let updated = if opts.uses_database() {
        claim_usage_in_database(ctx, inner, api_key, opts).await?
    } else {
        claim_usage_in_secondary_storage(ctx, inner, api_key, opts, hashed).await?
    };
    Ok((updated, opts))
}

/// How a request affects the key's rate-limit window (`evaluateRateLimit`).
enum RateLimitDecision {
    /// Rate limiting does not apply; stamp `lastRequest` when given.
    Skip(Option<chrono::DateTime<Utc>>),
    /// First request ever: open a window.
    Start,
    /// The window elapsed: open a new one, guarded on `lastRequest` predating `window_start`.
    Reset {
        window_start: chrono::DateTime<Utc>,
    },
    /// Within the window and under `max`.
    Increment {
        max: i64,
        window_start: chrono::DateTime<Utc>,
    },
    Deny {
        try_again_in: i64,
    },
}

fn evaluate_rate_limit(key: &Record, opts: &ApiKeyOptions, now: chrono::DateTime<Utc>) -> RateLimitDecision {
    if !opts.rate_limit.enabled || key.get("rateLimitEnabled") == Some(&Value::Bool(false)) {
        return RateLimitDecision::Skip(Some(now));
    }
    let (Some(window), Some(max)) = (int_field(key, "rateLimitTimeWindow"), int_field(key, "rateLimitMax")) else {
        return RateLimitDecision::Skip(None);
    };
    let Some(last) = date_field(key, "lastRequest") else { return RateLimitDecision::Start };
    let since = (now - last).num_milliseconds();
    let window_start = now - chrono::Duration::milliseconds(window);
    if since > window {
        RateLimitDecision::Reset { window_start }
    } else if int_field(key, "requestCount").unwrap_or(0) >= max {
        RateLimitDecision::Deny { try_again_in: window - since }
    } else {
        RateLimitDecision::Increment { max, window_start }
    }
}

fn rate_limited(try_again_in: i64) -> ApiError {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED", e::RATE_LIMIT_EXCEEDED.message)
        .with_field("details", json!({ "tryAgainIn": try_again_in }))
}

fn record(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Record {
    entries.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

/// Claim one use against the database row, the source of truth. Every write is guarded, so
/// concurrent verifications cannot drive `remaining` below zero or `requestCount` past the
/// maximum.
async fn claim_usage_in_database(
    ctx: &EndpointContext,
    inner: &Inner,
    api_key: Record,
    opts: &ApiKeyOptions,
) -> ApiResult<Record> {
    let db = &ctx.auth.db;
    let id = str_field(&api_key, "id").unwrap_or_default().to_owned();
    let mut row = api_key;
    if row.get("remaining").is_some_and(|v| !v.is_null()) {
        row = consume_remaining(ctx, row).await?;
    }
    let claimed = consume_rate_limit(ctx, row, opts).await?;
    let updated =
        db.update(API_KEY_TABLE, &[Where::eq("id", id.as_str())], record([("updatedAt", date::now_value())])).await?;
    match updated.map(store::from_db) {
        Some(updated) => {
            if opts.uses_fallback() {
                store::set(&ctx.auth, inner, &updated, opts).await?;
            }
            Ok(updated)
        }
        // The row was deleted after this request claimed its use: another verification
        // found the key used up, or it was revoked meanwhile. The claim stands (TS rejects
        // it, so concurrent last uses could be refused), but the gone key is not re-cached.
        None => Ok(store::from_db(claimed)),
    }
}

/// Guarded quota use. When a refill is due exactly one verification wins it
/// (compare-and-swap on `lastRefillAt`); the decrement only applies while `remaining > 0`.
async fn consume_remaining(ctx: &EndpointContext, key: Record) -> ApiResult<Record> {
    let db = &ctx.auth.db;
    let now = Utc::now();
    let id = str_field(&key, "id").unwrap_or_default().to_owned();
    if let (Some(interval), Some(amount)) = (int_field(&key, "refillInterval"), int_field(&key, "refillAmount"))
        && interval != 0
        && amount != 0
    {
        let last = date_field(&key, "lastRefillAt").or_else(|| date_field(&key, "createdAt")).unwrap_or(now);
        if (now - last).num_milliseconds() > interval {
            let observed = key.get("lastRefillAt").cloned().unwrap_or(Value::Null);
            let refilled = db
                .increment_one(
                    API_KEY_TABLE,
                    &[Where::eq("id", id.as_str()), Where::eq("lastRefillAt", observed)],
                    &[],
                    record([("remaining", (amount - 1).into()), ("lastRefillAt", date::to_value(now))]),
                )
                .await?;
            if let Some(row) = refilled {
                return Ok(row);
            }
            // Another verification refilled first; decrement the refreshed value.
        }
    }
    db.increment_one(
        API_KEY_TABLE,
        &[Where::eq("id", id.as_str()), Where::gt("remaining", 0)],
        &[("remaining", -1)],
        Map::new(),
    )
    .await?
    .ok_or_else(|| ApiError::from_code(StatusCode::TOO_MANY_REQUESTS, e::USAGE_EXCEEDED))
}

/// Guarded rate-limit use: increments only while under the maximum; window starts and
/// resets are conditional sets. A request that loses a race re-evaluates the fresh row.
async fn consume_rate_limit(ctx: &EndpointContext, mut key: Record, opts: &ApiKeyOptions) -> ApiResult<Record> {
    let db = &ctx.auth.db;
    let id = str_field(&key, "id").unwrap_or_default().to_owned();
    for _ in 0..16 {
        let now = Utc::now();
        let id_eq = Where::eq("id", id.as_str());
        let won = match evaluate_rate_limit(&key, opts, now) {
            RateLimitDecision::Deny { try_again_in } => return Err(rate_limited(try_again_in)),
            RateLimitDecision::Skip(None) => return Ok(key),
            RateLimitDecision::Skip(Some(at)) => {
                let updated = db.update(API_KEY_TABLE, &[id_eq], record([("lastRequest", date::to_value(at))])).await?;
                return Ok(updated.unwrap_or(key));
            }
            RateLimitDecision::Increment { max, window_start } => {
                db.increment_one(
                    API_KEY_TABLE,
                    &[id_eq, Where::gt("lastRequest", date::to_value(window_start)), Where::lt("requestCount", max)],
                    &[("requestCount", 1)],
                    record([("lastRequest", date::to_value(now))]),
                )
                .await?
            }
            decision @ (RateLimitDecision::Start | RateLimitDecision::Reset { .. }) => {
                let guard = match decision {
                    RateLimitDecision::Reset { window_start } => {
                        Where::new("lastRequest", crate::db::Operator::Lte, date::to_value(window_start))
                    }
                    _ => Where::eq("lastRequest", Value::Null),
                };
                db.increment_one(
                    API_KEY_TABLE,
                    &[id_eq, guard],
                    &[],
                    record([("requestCount", 1.into()), ("lastRequest", date::to_value(now))]),
                )
                .await?
            }
        };
        if let Some(row) = won {
            return Ok(row);
        }
        // Lost a race: re-evaluate against the freshest row.
        key = db
            .find_one(API_KEY_TABLE, &[Where::eq("id", id.as_str())])
            .await?
            .ok_or_else(|| ApiError::unauthorized(e::INVALID_API_KEY))?;
    }
    Err(rate_limited(0))
}

/// Secondary-storage-only mode has no row to guard: a read-modify-write of the stored key,
/// which is not atomic across concurrent verifications (as in TS).
async fn claim_usage_in_secondary_storage(
    ctx: &EndpointContext,
    inner: &Arc<Inner>,
    key: Record,
    opts: &ApiKeyOptions,
    hashed: String,
) -> ApiResult<Record> {
    let now = Utc::now();
    let mut mutations = Map::new();
    if let Some(mut remaining) = int_field(&key, "remaining") {
        let mut last_refill = key.get("lastRefillAt").cloned().unwrap_or(Value::Null);
        if let (Some(interval), Some(amount)) = (int_field(&key, "refillInterval"), int_field(&key, "refillAmount"))
            && interval != 0
            && amount != 0
        {
            let last = date_field(&key, "lastRefillAt").or_else(|| date_field(&key, "createdAt")).unwrap_or(now);
            if (now - last).num_milliseconds() > interval {
                remaining = amount;
                last_refill = date::to_value(now);
            }
        }
        if remaining == 0 {
            return Err(ApiError::from_code(StatusCode::TOO_MANY_REQUESTS, e::USAGE_EXCEEDED));
        }
        mutations.insert("remaining".into(), (remaining - 1).into());
        mutations.insert("lastRefillAt".into(), last_refill);
    }
    match evaluate_rate_limit(&key, opts, now) {
        RateLimitDecision::Deny { try_again_in } => return Err(rate_limited(try_again_in)),
        RateLimitDecision::Skip(None) => {}
        RateLimitDecision::Skip(Some(at)) => {
            mutations.insert("lastRequest".into(), date::to_value(at));
        }
        RateLimitDecision::Start | RateLimitDecision::Reset { .. } => {
            mutations.insert("lastRequest".into(), date::to_value(now));
            mutations.insert("requestCount".into(), 1.into());
        }
        RateLimitDecision::Increment { .. } => {
            mutations.insert("lastRequest".into(), date::to_value(now));
            let count = int_field(&key, "requestCount").unwrap_or(0) + 1;
            mutations.insert("requestCount".into(), count.into());
        }
    }
    mutations.insert("updatedAt".into(), date::to_value(now));

    async fn perform(
        auth: &crate::context::AuthContext,
        inner: &Inner,
        hashed: &str,
        opts: &ApiKeyOptions,
        mutations: &Record,
    ) -> crate::error::Result<Option<Record>> {
        let Some(mut fresh) = store::get_by_hash(auth, inner, hashed, opts).await? else { return Ok(None) };
        fresh.extend(mutations.clone());
        store::set(auth, inner, &fresh, opts).await?;
        Ok(Some(fresh))
    }

    if opts.defer_updates {
        let (auth, inner, opts2, muts) = (ctx.auth.clone(), inner.clone(), opts.clone(), mutations.clone());
        tokio::spawn(async move {
            if let Err(e) = perform(&auth, &inner, &hashed, &opts2, &muts).await {
                tracing::error!(error = %e, "Failed to update API key");
            }
        });
        let mut optimistic = key;
        optimistic.extend(mutations);
        return Ok(optimistic);
    }
    perform(&ctx.auth, inner, &hashed, opts, &mutations)
        .await?
        .ok_or_else(|| ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_UPDATE_API_KEY))
}

// ---- endpoints ----------------------------------------------------------------------------

fn check_length(len: usize, min: usize, max: usize, code: ErrorCode) -> ApiResult<()> {
    if len < min || len > max { Err(ApiError::bad_request(code)) } else { Ok(()) }
}

fn check_expires_in(expires_in: i64, opts: &ApiKeyOptions) -> ApiResult<()> {
    let days = expires_in as f64 / (60.0 * 60.0 * 24.0);
    if days < opts.key_expiration.min_expires_in_days {
        return Err(ApiError::bad_request(e::EXPIRES_IN_IS_TOO_SMALL));
    }
    if days > opts.key_expiration.max_expires_in_days {
        return Err(ApiError::bad_request(e::EXPIRES_IN_IS_TOO_LARGE));
    }
    Ok(())
}

/// `POST /api-key/create`
pub(super) async fn create(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let b = Body::new(&ctx)?;
    let config_id = b.string("configId")?;
    let name = b.string("name")?;
    let expires_in = b.int("expiresIn", Some(1), true)?.flatten();
    let prefix = b.string("prefix")?;
    if let Some(p) = &prefix
        && !p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(invalid(
            "body",
            "prefix",
            "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens.",
        ));
    }
    let remaining = b.int("remaining", Some(0), true)?.flatten();
    let metadata = b.get("metadata").cloned().unwrap_or(Value::Null);
    let refill_amount = b.int("refillAmount", Some(1), false)?.flatten();
    let refill_interval = b.int("refillInterval", None, false)?.flatten();
    let rate_limit_time_window = b.int("rateLimitTimeWindow", None, false)?.flatten();
    let rate_limit_max = b.int("rateLimitMax", None, false)?.flatten();
    let rate_limit_enabled = b.boolean("rateLimitEnabled")?;
    let permissions = b.permissions("permissions", false)?.flatten();
    let body_user_id = b.coerced_string("userId")?;
    let organization_id = b.coerced_string("organizationId")?;

    let opts = inner.resolve(config_id.as_deref())?;
    let session = authoritative(&ctx).await?;
    let is_client = is_client_call(&ctx);

    let server_only = refill_amount.is_some()
        || refill_interval.is_some()
        || rate_limit_max.is_some()
        || rate_limit_time_window.is_some()
        || rate_limit_enabled.is_some()
        || permissions.is_some()
        || remaining.is_some();
    if is_client && server_only {
        return Err(ApiError::bad_request(e::SERVER_ONLY_PROPERTY));
    }
    // Over HTTP the owner always comes from the session.
    if ctx.is_request && body_user_id.is_some() {
        return Err(ApiError::unauthorized(e::UNAUTHORIZED_SESSION));
    }
    let session_user = session.as_ref().map(|s| s.user.id.clone());
    let reference_id = match opts.references {
        ApiKeyReferences::Organization => {
            let Some(org_id) = organization_id.filter(|o| !o.is_empty()) else {
                return Err(ApiError::bad_request(e::ORGANIZATION_ID_REQUIRED));
            };
            let Some(user_id) = session_user.or(body_user_id).filter(|u| !u.is_empty()) else {
                return Err(ApiError::unauthorized(e::UNAUTHORIZED_SESSION));
            };
            check_org_permission(&ctx, &user_id, &org_id, "create").await?;
            org_id
        }
        ApiKeyReferences::User if is_client => {
            session_user.ok_or_else(|| ApiError::unauthorized(e::UNAUTHORIZED_SESSION))?
        }
        ApiKeyReferences::User => {
            // The session and the body must not name different users.
            if let (Some(s), Some(b)) = (&session_user, &body_user_id)
                && s != b
            {
                return Err(ApiError::unauthorized(e::UNAUTHORIZED_SESSION));
            }
            session_user.or(body_user_id).ok_or_else(|| ApiError::unauthorized(e::UNAUTHORIZED_SESSION))?
        }
    };

    if truthy(&metadata) {
        if !opts.enable_metadata {
            return Err(ApiError::bad_request(e::METADATA_DISABLED));
        }
        if !metadata.is_object() && !metadata.is_array() {
            return Err(ApiError::bad_request(e::INVALID_METADATA_TYPE));
        }
    }
    let (refill_amount_set, refill_interval_set) =
        (refill_amount.is_some_and(|n| n != 0), refill_interval.is_some_and(|n| n != 0));
    if refill_amount_set && !refill_interval_set {
        return Err(ApiError::bad_request(e::REFILL_AMOUNT_AND_INTERVAL_REQUIRED));
    }
    if refill_interval_set && !refill_amount_set {
        return Err(ApiError::bad_request(e::REFILL_INTERVAL_AND_AMOUNT_REQUIRED));
    }
    if let Some(secs) = expires_in {
        if opts.key_expiration.disable_custom_expires_time {
            return Err(ApiError::bad_request(e::KEY_DISABLED_EXPIRATION));
        }
        check_expires_in(secs, opts)?;
    }
    if let Some(p) = &prefix {
        check_length(p.len(), opts.minimum_prefix_length, opts.maximum_prefix_length, e::INVALID_PREFIX_LENGTH)?;
    }
    match name.as_deref().filter(|n| !n.is_empty()) {
        Some(n) => {
            check_length(n.chars().count(), opts.minimum_name_length, opts.maximum_name_length, e::INVALID_NAME_LENGTH)?
        }
        None if opts.require_name => return Err(ApiError::bad_request(e::NAME_REQUIRED)),
        None => {}
    }

    spawn_cleanup(&ctx, &inner);

    let key_prefix = prefix.clone().filter(|p| !p.is_empty()).or_else(|| opts.default_prefix.clone());
    let key = match &opts.custom_key_generator {
        Some(generate) => generate(opts.default_key_length, key_prefix.clone()).await?,
        None => format!(
            "{}{}",
            key_prefix.as_deref().unwrap_or_default(),
            crate::crypto::random_string(opts.default_key_length, LETTERS)
        ),
    };
    let start = opts
        .starting_characters
        .should_store
        .then(|| key.chars().take(opts.starting_characters.characters_length).collect::<String>());
    let default_permissions = match &opts.default_permissions {
        None => None,
        Some(DefaultPermissions::Static(s)) => Some(s.clone()),
        Some(DefaultPermissions::Dynamic(f)) => Some(f(reference_id.clone()).await?),
    };
    let permissions_json = match (&permissions, default_permissions) {
        (Some(p), _) => Some(Value::Object(p.clone()).to_string()),
        (None, Some(d)) => Some(serde_json::to_string(&d).expect("serializable")),
        (None, None) => None,
    };
    let now = date::now_value();
    let expires_at = expires_in
        .map(|secs| date::to_value(Utc::now() + chrono::Duration::seconds(secs)))
        .or_else(|| {
            let default = opts.key_expiration.default_expires_in.filter(|d| !d.is_zero())?;
            Some(date::to_value(Utc::now() + chrono::Duration::seconds(default.as_secs() as i64)))
        })
        .unwrap_or(Value::Null);
    let mut data = record([
        ("configId", opts.id().into()),
        ("createdAt", now.clone()),
        ("updatedAt", now),
        ("name", name.map_or(Value::Null, Value::from)),
        ("prefix", prefix.or_else(|| opts.default_prefix.clone()).map_or(Value::Null, Value::from)),
        ("start", start.map_or(Value::Null, Value::from)),
        ("key", hash_key(&key, opts).into()),
        ("enabled", true.into()),
        ("expiresAt", expires_at),
        ("referenceId", reference_id.into()),
        ("lastRefillAt", Value::Null),
        ("lastRequest", Value::Null),
        ("metadata", if truthy(&metadata) { metadata.clone() } else { Value::Null }),
        ("rateLimitMax", rate_limit_max.unwrap_or(opts.rate_limit.max_requests).into()),
        (
            "rateLimitTimeWindow",
            rate_limit_time_window.unwrap_or(opts.rate_limit.time_window.as_millis() as i64).into(),
        ),
        ("remaining", remaining.map_or(Value::Null, Value::from)),
        ("refillAmount", refill_amount.map_or(Value::Null, Value::from)),
        ("refillInterval", refill_interval.map_or(Value::Null, Value::from)),
        ("rateLimitEnabled", rate_limit_enabled.unwrap_or(opts.rate_limit.enabled).into()),
        ("requestCount", 0.into()),
    ]);
    if let Some(p) = permissions_json {
        data.insert("permissions".into(), p.into());
    }

    let api_key = match opts.storage {
        ApiKeyStorage::SecondaryStorage if !opts.fallback_to_database => {
            data.insert("id".into(), ctx.auth.db.generate_id(API_KEY_TABLE).into());
            store::set(&ctx.auth, &inner, &data, opts).await?;
            data
        }
        _ => {
            let created = store::from_db(ctx.auth.db.create(API_KEY_TABLE, store::to_db(data), false).await?);
            store::set(&ctx.auth, &inner, &created, opts).await?;
            created
        }
    };
    let mut out = public_key(api_key, if truthy(&metadata) { metadata } else { Value::Null });
    out["key"] = key.into();
    ctx.json(out)
}

/// `POST /api-key/verify` (server only)
pub(super) async fn verify(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let b = Body::new(&ctx)?;
    let config_id = b.string("configId")?;
    let key = b.required_string("key")?;
    let permissions = b.permissions("permissions", false)?.flatten();
    let lookup = inner.resolve(config_id.as_deref())?;

    // Scoped: the lookup configuration is the key's, so validate now. Unscoped validation
    // runs once the key's configuration is known.
    if config_id.is_some()
        && let Some(validate) = &lookup.custom_api_key_validator
        && !validate(&ctx, &key).await?
    {
        // TS puts the whole error-code object in `message` here.
        let message = json!({ "code": e::INVALID_API_KEY.code, "message": e::INVALID_API_KEY.message });
        return ctx
            .json(json!({ "valid": false, "error": { "message": message, "code": "KEY_NOT_FOUND" }, "key": null }));
    }

    let result =
        validate_api_key(&inner, &ctx, &key, lookup, permissions.as_ref(), config_id.as_deref(), config_id.is_none())
            .await;
    let (api_key, opts) = match result {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = ?err.to_json(), "Failed to validate API key");
            return ctx.json(json!({ "valid": false, "error": err.to_json(), "key": null }));
        }
    };
    if opts.defer_updates {
        spawn_cleanup(&ctx, &inner);
    }
    let metadata = store::migrate_metadata(&ctx.auth, &api_key, opts).await;
    ctx.json(json!({ "valid": true, "error": null, "key": public_key(api_key, metadata) }))
}

/// `GET /api-key/get`
pub(super) async fn get(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let config_id = ctx.query_str("configId");
    let Some(id) = ctx.query_str("id") else {
        return Err(invalid("query", "id", "Invalid input: expected string, received undefined"));
    };
    let (api_key, opts) = owned_key(&ctx, &inner, config_id.as_deref(), &id, &session.user.id, "read").await?;
    spawn_cleanup(&ctx, &inner);
    let metadata = store::migrate_metadata(&ctx.auth, &api_key, opts).await;
    ctx.json(public_key(api_key, metadata))
}

/// `POST /api-key/update`
pub(super) async fn update(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let b = Body::new(&ctx)?;
    let config_id = b.string("configId")?;
    let key_id = b.required_string("keyId")?;
    let body_user_id = b.coerced_string("userId")?;
    let name = b.string("name")?;
    let enabled = b.boolean("enabled")?;
    let remaining = b.int("remaining", Some(1), false)?.flatten();
    let refill_amount = b.int("refillAmount", None, false)?.flatten();
    let refill_interval = b.int("refillInterval", None, false)?.flatten();
    let metadata = b.get("metadata").cloned();
    let expires_in = b.int("expiresIn", Some(1), true)?;
    let rate_limit_enabled = b.boolean("rateLimitEnabled")?;
    let rate_limit_time_window = b.int("rateLimitTimeWindow", None, false)?.flatten();
    let rate_limit_max = b.int("rateLimitMax", None, false)?.flatten();
    let permissions = b.permissions("permissions", true)?;

    let session = authoritative(&ctx).await?;
    let auth_required = is_client_call(&ctx);
    let user_id = match &session {
        Some(s) => Some(s.user.id.clone()),
        None if auth_required => None,
        None => body_user_id.clone(),
    };
    let Some(user_id) = user_id.filter(|u| !u.is_empty()) else {
        return Err(ApiError::unauthorized(e::UNAUTHORIZED_SESSION));
    };
    if session.is_some() && body_user_id.as_ref().is_some_and(|b| !b.is_empty() && *b != user_id) {
        return Err(ApiError::unauthorized(e::UNAUTHORIZED_SESSION));
    }
    if auth_required
        && (refill_amount.is_some()
            || refill_interval.is_some()
            || rate_limit_max.is_some()
            || rate_limit_time_window.is_some()
            || rate_limit_enabled.is_some()
            || remaining.is_some()
            || permissions.is_some())
    {
        return Err(ApiError::bad_request(e::SERVER_ONLY_PROPERTY));
    }

    let (api_key, opts) = owned_key(&ctx, &inner, config_id.as_deref(), &key_id, &user_id, "update").await?;

    let mut changes = Map::new();
    if let Some(n) = name {
        check_length(n.chars().count(), opts.minimum_name_length, opts.maximum_name_length, e::INVALID_NAME_LENGTH)?;
        changes.insert("name".into(), n.into());
    }
    if let Some(enabled) = enabled {
        changes.insert("enabled".into(), enabled.into());
    }
    if let Some(expires_in) = expires_in {
        if opts.key_expiration.disable_custom_expires_time {
            return Err(ApiError::bad_request(e::KEY_DISABLED_EXPIRATION));
        }
        // `null` removes the expiry.
        let expires_at = match expires_in {
            Some(secs) => {
                check_expires_in(secs, opts)?;
                date::to_value(Utc::now() + chrono::Duration::seconds(secs))
            }
            None => Value::Null,
        };
        changes.insert("expiresAt".into(), expires_at);
    }
    if let Some(meta) = metadata
        && opts.enable_metadata
    {
        if !matches!(meta, Value::Object(_) | Value::Array(_) | Value::Null) {
            return Err(ApiError::bad_request(e::INVALID_METADATA_TYPE));
        }
        changes.insert("metadata".into(), meta);
    }
    if let Some(r) = remaining {
        changes.insert("remaining".into(), r.into());
    }
    match (refill_amount, refill_interval) {
        (None, None) => {}
        (Some(_), None) => return Err(ApiError::bad_request(e::REFILL_AMOUNT_AND_INTERVAL_REQUIRED)),
        (None, Some(_)) => return Err(ApiError::bad_request(e::REFILL_INTERVAL_AND_AMOUNT_REQUIRED)),
        (Some(amount), Some(interval)) => {
            changes.insert("refillAmount".into(), amount.into());
            changes.insert("refillInterval".into(), interval.into());
        }
    }
    if let Some(enabled) = rate_limit_enabled {
        changes.insert("rateLimitEnabled".into(), enabled.into());
    }
    if let Some(window) = rate_limit_time_window {
        changes.insert("rateLimitTimeWindow".into(), window.into());
    }
    if let Some(max) = rate_limit_max {
        changes.insert("rateLimitMax".into(), max.into());
    }
    if let Some(p) = permissions {
        changes.insert("permissions".into(), p.map_or(Value::Null, |p| Value::Object(p).to_string().into()));
    }
    if changes.is_empty() {
        return Err(ApiError::bad_request(e::NO_VALUES_TO_UPDATE));
    }
    changes.insert("updatedAt".into(), date::now_value());

    let id = str_field(&api_key, "id").unwrap_or_default().to_owned();
    let write = async {
        if opts.uses_database() {
            let updated =
                ctx.auth.db.update(API_KEY_TABLE, &[Where::eq("id", id.as_str())], store::to_db(changes)).await?;
            let updated = updated.map(store::from_db);
            if let Some(u) = &updated {
                store::set(&ctx.auth, &inner, u, opts).await?;
            }
            Ok::<_, crate::error::Error>(updated.unwrap_or_else(|| api_key.clone()))
        } else {
            let mut merged = api_key.clone();
            merged.extend(changes);
            store::set(&ctx.auth, &inner, &merged, opts).await?;
            Ok(merged)
        }
    };
    let updated = write.await.map_err(|err| status_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    spawn_cleanup(&ctx, &inner);
    let metadata = store::migrate_metadata(&ctx.auth, &updated, opts).await;
    ctx.json(public_key(updated, metadata))
}

/// `POST /api-key/delete`
pub(super) async fn delete(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let b = Body::new(&ctx)?;
    let config_id = b.string("configId")?;
    let key_id = b.required_string("keyId")?;
    if session.user.extra.get("banned") == Some(&Value::Bool(true)) {
        return Err(ApiError::unauthorized(e::USER_BANNED));
    }
    let (api_key, opts) = owned_key(&ctx, &inner, config_id.as_deref(), &key_id, &session.user.id, "delete").await?;
    store::delete_everywhere(&ctx.auth, &inner, &api_key, opts)
        .await
        .map_err(|err| status_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    spawn_cleanup(&ctx, &inner);
    ctx.json(json!({ "success": true }))
}

/// Configurations sharing a backend are listed once.
fn storage_identifier(opts: &ApiKeyOptions) -> String {
    match opts.storage {
        ApiKeyStorage::Database => "database".into(),
        _ if opts.custom_storage.is_some() => format!("custom:{}", opts.id()),
        _ if opts.fallback_to_database => "secondary-storage-with-fallback".into(),
        _ => "secondary-storage".into(),
    }
}

fn query_index(ctx: &EndpointContext, k: &str) -> ApiResult<Option<usize>> {
    ctx.query_str(k)
        .map(|v| v.trim().parse::<usize>().map_err(|_| invalid("query", k, "Invalid input: expected number")))
        .transpose()
}

/// `GET /api-key/list`
pub(super) async fn list(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let config_id = ctx.query_str("configId");
    let organization_id = ctx.query_str("organizationId").filter(|o| !o.is_empty());
    let limit = query_index(&ctx, "limit")?;
    let offset = query_index(&ctx, "offset")?;
    let descending = match ctx.query_str("sortDirection").as_deref() {
        None | Some("asc") => false,
        Some("desc") => true,
        Some(_) => return Err(invalid("query", "sortDirection", "Invalid option: expected one of \"asc\"|\"desc\"")),
    };
    let sort = Sort { by: ctx.query_str("sortBy"), descending };

    if let Some(org) = &organization_id {
        check_org_permission(&ctx, &session.user.id, org, "read").await?;
    }
    let reference_id = organization_id.clone().unwrap_or_else(|| session.user.id.clone());
    let expected = if organization_id.is_some() { ApiKeyReferences::Organization } else { ApiKeyReferences::User };

    let mut keys: Vec<Record> = vec![];
    if config_id.is_some() {
        let opts = inner.resolve(config_id.as_deref())?;
        keys = store::list(&ctx.auth, &inner, &reference_id, opts, &sort).await?;
    } else {
        let mut seen_backends = vec![];
        let mut seen_ids = std::collections::HashSet::new();
        for opts in &inner.configs {
            let backend = storage_identifier(opts);
            if seen_backends.contains(&backend) {
                continue;
            }
            seen_backends.push(backend);
            for key in store::list(&ctx.auth, &inner, &reference_id, opts, &sort).await? {
                if seen_ids.insert(str_field(&key, "id").unwrap_or_default().to_owned()) {
                    keys.push(key);
                }
            }
        }
    }

    // Keep keys whose configuration owns them the way this listing asks for.
    keys.retain(|key| {
        let key_config = str_field(key, "configId");
        let config = inner.configs.iter().find(|c| {
            if is_default_config_id(key_config) { c.is_default() } else { c.config_id.as_deref() == key_config }
        });
        config.map_or(ApiKeyReferences::User, |c| c.references) == expected
            && str_field(key, "referenceId") == Some(reference_id.as_str())
            && config_id.as_deref().is_none_or(|id| config_id_matches(key_config, Some(id)))
    });
    let total = keys.len();
    let page: Vec<Record> = keys.into_iter().skip(offset.unwrap_or(0)).take(limit.unwrap_or(usize::MAX)).collect();

    spawn_cleanup(&ctx, &inner);
    let api_keys: Vec<Value> =
        page.iter().map(|k| public_key(k.clone(), store::parse_metadata(k.get("metadata")))).collect();
    if let Some(db_config) = inner.configs.iter().find(|c| c.uses_database()) {
        store::batch_migrate_metadata(&ctx.auth, &page, db_config).await;
    }
    let mut out = json!({ "apiKeys": api_keys, "total": total });
    if let Some(l) = limit {
        out["limit"] = l.into();
    }
    if let Some(o) = offset {
        out["offset"] = o.into();
    }
    ctx.json(out)
}

/// `deleteAllExpiredApiKeys` (server only).
pub(super) async fn delete_all_expired(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    match cleanup(&ctx.auth, &inner, true).await {
        Ok(()) => ctx.json(json!({ "success": true, "error": null })),
        Err(err) => {
            tracing::error!(error = %err, "[API KEY PLUGIN] Failed to delete expired API keys");
            ctx.json(json!({ "success": false, "error": err.to_string() }))
        }
    }
}
