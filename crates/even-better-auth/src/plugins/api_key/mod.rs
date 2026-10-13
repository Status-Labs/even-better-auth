//! API keys (`@better-auth/api-key`): create, verify, list, update and delete keys owned by a
//! user or an organization, with hashing, prefixes, expiry, usage quotas with refills, per-key
//! rate limits, permissions and metadata. Keys live in the database, in secondary storage, or
//! in secondary storage backed by the database. With `enable_session_for_api_keys`, a request
//! carrying a key in the configured header is treated as signed in as the key's owner.

mod routes;
mod store;

use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use http::StatusCode;
use serde_json::{Map, Value};

use crate::api::{Endpoint, EndpointContext, handler, hook};
use crate::db::schema::{Field, TableExtension};
use crate::error::{ApiError, Error, ErrorCode, Result};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::plugins::access::Statements;
use crate::storage::SecondaryStorage;

pub use routes::API_KEY_PERMISSION_RESOURCE;

/// Error codes (`API_KEY_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        INVALID_METADATA_TYPE => "metadata must be an object or undefined",
        REFILL_AMOUNT_AND_INTERVAL_REQUIRED => "refillAmount is required when refillInterval is provided",
        REFILL_INTERVAL_AND_AMOUNT_REQUIRED => "refillInterval is required when refillAmount is provided",
        USER_BANNED => "User is banned",
        UNAUTHORIZED_SESSION => "Unauthorized or invalid session",
        KEY_NOT_FOUND => "API Key not found",
        KEY_DISABLED => "API Key is disabled",
        KEY_EXPIRED => "API Key has expired",
        USAGE_EXCEEDED => "API Key has reached its usage limit",
        KEY_NOT_RECOVERABLE => "API Key is not recoverable",
        EXPIRES_IN_IS_TOO_SMALL => "The expiresIn is smaller than the predefined minimum value.",
        EXPIRES_IN_IS_TOO_LARGE => "The expiresIn is larger than the predefined maximum value.",
        INVALID_REMAINING => "The remaining count is either too large or too small.",
        INVALID_PREFIX_LENGTH => "The prefix length is either too large or too small.",
        INVALID_NAME_LENGTH => "The name length is either too large or too small.",
        METADATA_DISABLED => "Metadata is disabled.",
        RATE_LIMIT_EXCEEDED => "Rate limit exceeded.",
        NO_VALUES_TO_UPDATE => "No values to update.",
        KEY_DISABLED_EXPIRATION => "Custom key expiration values are disabled.",
        INVALID_API_KEY => "Invalid API key.",
        INVALID_USER_ID_FROM_API_KEY => "The user id from the API key is invalid.",
        INVALID_REFERENCE_ID_FROM_API_KEY => "The reference id from the API key is invalid.",
        INVALID_API_KEY_GETTER_RETURN_TYPE => "API Key getter returned an invalid key type. Expected string.",
        SERVER_ONLY_PROPERTY => "The property you're trying to set can only be set from the server auth instance only.",
        FAILED_TO_UPDATE_API_KEY => "Failed to update API key",
        NAME_REQUIRED => "API Key name is required.",
        ORGANIZATION_ID_REQUIRED => "Organization ID is required for organization-owned API keys.",
        USER_NOT_MEMBER_OF_ORGANIZATION => "You are not a member of the organization that owns this API key.",
        INSUFFICIENT_API_KEY_PERMISSIONS => "You do not have permission to perform this action on organization API keys.",
        NO_DEFAULT_API_KEY_CONFIGURATION_FOUND => "No default api-key configuration found.",
        ORGANIZATION_PLUGIN_REQUIRED => "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.",
    }
}

/// The model name (`API_KEY_TABLE_NAME`).
pub const API_KEY_TABLE: &str = "apikey";

/// Where keys are stored.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApiKeyStorage {
    #[default]
    Database,
    /// The auth's `secondary_storage` (or `custom_storage`).
    SecondaryStorage,
}

/// What owns the keys of a configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ApiKeyReferences {
    #[default]
    User,
    /// Keys belong to an organization; access is checked against the member's role
    /// (`apiKey: create | read | update | delete`). Requires the organization plugin.
    Organization,
}

/// Reads the key from the request (`customAPIKeyGetter`).
pub type ApiKeyGetter = Arc<dyn Fn(&EndpointContext) -> Option<String> + Send + Sync>;
/// Extra validation of a presented key (`customAPIKeyValidator`).
pub type ApiKeyValidator =
    Arc<dyn for<'a> Fn(&'a EndpointContext, &'a str) -> BoxFuture<'a, Result<bool>> + Send + Sync>;
/// Generates a key from `(length, prefix)` (`customKeyGenerator`).
pub type KeyGenerator = Arc<dyn Fn(usize, Option<String>) -> BoxFuture<'static, Result<String>> + Send + Sync>;
/// Default permissions for a new key, from its reference id.
pub type DefaultPermissionsFn = Arc<dyn Fn(String) -> BoxFuture<'static, Result<Statements>> + Send + Sync>;

#[derive(Clone)]
pub enum DefaultPermissions {
    Static(Statements),
    Dynamic(DefaultPermissionsFn),
}

#[derive(Clone, Debug)]
pub struct KeyExpiration {
    /// Expiry for keys created without `expiresIn`. Default: none.
    pub default_expires_in: Option<Duration>,
    /// Ignore `expiresIn` from callers (it is then rejected).
    pub disable_custom_expires_time: bool,
    /// Bounds for `expiresIn`, in days. Defaults 1 and 365.
    pub min_expires_in_days: f64,
    pub max_expires_in_days: f64,
}

impl Default for KeyExpiration {
    fn default() -> Self {
        Self {
            default_expires_in: None,
            disable_custom_expires_time: false,
            min_expires_in_days: 1.0,
            max_expires_in_days: 365.0,
        }
    }
}

/// Default per-key rate limit; each key can override it.
#[derive(Clone, Debug)]
pub struct ApiKeyRateLimit {
    pub enabled: bool,
    /// Default one day.
    pub time_window: Duration,
    /// Default 10.
    pub max_requests: i64,
}

impl Default for ApiKeyRateLimit {
    fn default() -> Self {
        Self { enabled: true, time_window: Duration::from_secs(60 * 60 * 24), max_requests: 10 }
    }
}

/// Store the first characters (including the prefix) so UIs can identify a key.
#[derive(Clone, Debug)]
pub struct StartingCharacters {
    pub should_store: bool,
    pub characters_length: usize,
}

impl Default for StartingCharacters {
    fn default() -> Self {
        Self { should_store: true, characters_length: 6 }
    }
}

/// One API key configuration (`ApiKeyConfigurationOptions`).
#[derive(Clone)]
pub struct ApiKeyOptions {
    /// Required, and unique, when there are several configurations. A configuration without
    /// one (or with `"default"`) is the default.
    pub config_id: Option<String>,
    /// Headers checked for a key, in order. Default `x-api-key`.
    pub api_key_headers: Vec<String>,
    /// Store keys in plaintext. Strongly discouraged.
    pub disable_key_hashing: bool,
    pub custom_api_key_getter: Option<ApiKeyGetter>,
    pub custom_api_key_validator: Option<ApiKeyValidator>,
    /// Default: `prefix` + `default_key_length` random letters.
    pub custom_key_generator: Option<KeyGenerator>,
    pub starting_characters: StartingCharacters,
    /// Default 64, not counting the prefix.
    pub default_key_length: usize,
    pub default_prefix: Option<String>,
    /// Prefix length bounds. Defaults 1 and 32.
    pub minimum_prefix_length: usize,
    pub maximum_prefix_length: usize,
    pub require_name: bool,
    /// Name length bounds. Defaults 1 and 32.
    pub minimum_name_length: usize,
    pub maximum_name_length: usize,
    pub enable_metadata: bool,
    pub key_expiration: KeyExpiration,
    pub rate_limit: ApiKeyRateLimit,
    /// Treat requests carrying a key as signed in as its (user) owner.
    pub enable_session_for_api_keys: bool,
    pub default_permissions: Option<DefaultPermissions>,
    pub storage: ApiKeyStorage,
    /// With secondary storage: read through to the database, which stays the source of truth.
    pub fallback_to_database: bool,
    /// Used instead of the auth's `secondary_storage`.
    pub custom_storage: Option<Arc<dyn SecondaryStorage>>,
    /// Apply counter and timestamp writes after responding (spawned tasks): lower latency,
    /// eventually consistent.
    pub defer_updates: bool,
    pub references: ApiKeyReferences,
}

impl Default for ApiKeyOptions {
    fn default() -> Self {
        Self {
            config_id: None,
            api_key_headers: vec!["x-api-key".into()],
            disable_key_hashing: false,
            custom_api_key_getter: None,
            custom_api_key_validator: None,
            custom_key_generator: None,
            starting_characters: StartingCharacters::default(),
            default_key_length: 64,
            default_prefix: None,
            minimum_prefix_length: 1,
            maximum_prefix_length: 32,
            require_name: false,
            minimum_name_length: 1,
            maximum_name_length: 32,
            enable_metadata: false,
            key_expiration: KeyExpiration::default(),
            rate_limit: ApiKeyRateLimit::default(),
            enable_session_for_api_keys: false,
            default_permissions: None,
            storage: ApiKeyStorage::Database,
            fallback_to_database: false,
            custom_storage: None,
            defer_updates: false,
            references: ApiKeyReferences::User,
        }
    }
}

impl ApiKeyOptions {
    /// The configuration id, `"default"` when unset.
    pub fn id(&self) -> &str {
        self.config_id.as_deref().unwrap_or("default")
    }

    fn is_default(&self) -> bool {
        is_default_config_id(self.config_id.as_deref())
    }

    fn uses_fallback(&self) -> bool {
        self.storage == ApiKeyStorage::SecondaryStorage && self.fallback_to_database
    }

    /// The database is the source of truth for counters.
    fn uses_database(&self) -> bool {
        self.storage == ApiKeyStorage::Database || self.uses_fallback()
    }
}

/// `null`, missing and `"default"` all name the default configuration (keys created before
/// `configId` existed have none).
fn is_default_config_id(id: Option<&str>) -> bool {
    id.is_none_or(|id| id.is_empty() || id == "default")
}

fn config_id_matches(key: Option<&str>, expected: Option<&str>) -> bool {
    (is_default_config_id(key) && is_default_config_id(expected)) || key == expected
}

pub(crate) struct Inner {
    configs: Vec<ApiKeyOptions>,
    last_cleanup: Mutex<Option<Instant>>,
    /// Serializes read-modify-write of reference lists in secondary storage (in-process only,
    /// as in TS).
    ref_list_lock: tokio::sync::Mutex<()>,
}

impl Inner {
    /// `resolveConfiguration`: the named configuration, else the default one.
    fn resolve(&self, config_id: Option<&str>) -> std::result::Result<&ApiKeyOptions, ApiError> {
        let named = config_id.filter(|id| !id.is_empty()).and_then(|id| {
            self.configs.iter().find(|c| c.config_id.as_deref() == Some(id) || (id == "default" && c.is_default()))
        });
        if let Some(c) = named {
            return Ok(c);
        }
        self.configs.iter().find(|c| c.is_default()).ok_or_else(|| {
            tracing::error!(
                "No default api-key configuration found. Either provide an api-key configuration with configId 'default' or provide a configuration with no `configId` set."
            );
            ApiError::bad_request(error_codes::NO_DEFAULT_API_KEY_CONFIGURATION_FOUND)
        })
    }

    /// The first session-enabled configuration whose key is present on the request.
    fn find_key(&self, ctx: &EndpointContext) -> Option<(String, &ApiKeyOptions)> {
        self.configs.iter().filter(|c| c.enable_session_for_api_keys).find_map(|c| {
            let key = match &c.custom_api_key_getter {
                Some(get) => get(ctx),
                None => c.api_key_headers.iter().find_map(|h| ctx.header(h).filter(|v| !v.is_empty())),
            };
            key.map(|k| (k, c))
        })
    }
}

/// The session-mocking before hook.
async fn session_from_api_key(
    inner: Arc<Inner>,
    ctx: &EndpointContext,
) -> std::result::Result<Option<crate::api::EndpointOutput>, ApiError> {
    use error_codes as e;
    let Some((key, config)) = inner.find_key(ctx) else { return Ok(None) };
    if key.len() < config.default_key_length {
        return Err(ApiError::forbidden(e::INVALID_API_KEY));
    }
    if let Some(validate) = &config.custom_api_key_validator
        && !validate(ctx, &key).await?
    {
        return Err(ApiError::forbidden(e::INVALID_API_KEY));
    }
    let (api_key, _) =
        routes::validate_api_key(&inner, ctx, &key, config, None, config.config_id.as_deref(), false).await?;
    routes::spawn_cleanup(ctx, &inner);
    // Session mocking only works for user-owned keys.
    if config.references != ApiKeyReferences::User {
        return Err(ApiError::unauthorized(e::INVALID_REFERENCE_ID_FROM_API_KEY));
    }
    let reference_id = store::str_field(&api_key, "referenceId").unwrap_or_default().to_owned();
    let Some(user) = ctx.auth.internal_adapter.find_user_by_id(&reference_id).await? else {
        return Err(ApiError::unauthorized(e::INVALID_REFERENCE_ID_FROM_API_KEY));
    };
    let now = chrono::Utc::now();
    let headers = ctx.headers();
    let expires_at = store::date_field(&api_key, "expiresAt")
        .unwrap_or_else(|| now + chrono::Duration::seconds(ctx.auth.options.session.expires_in));
    let session = crate::types::SessionWithUser {
        session: crate::types::Session {
            id: store::str_field(&api_key, "id").unwrap_or_default().to_owned(),
            token: key,
            user_id: reference_id,
            user_agent: ctx.header("user-agent"),
            ip_address: crate::utils::ip::get_ip(&headers, &ctx.auth.options.advanced.ip_address),
            created_at: now,
            updated_at: now,
            expires_at,
            extra: Map::new(),
        },
        user,
    };
    ctx.set_session(Some(session.clone()));
    if ctx.path == "/get-session" {
        return Ok(Some(crate::api::EndpointOutput::Json(crate::api::routes::session::session_json(ctx, &session))));
    }
    Ok(None)
}

pub struct ApiKey {
    inner: Arc<Inner>,
}

/// The api-key plugin with a single (default) configuration.
pub fn api_key(options: ApiKeyOptions) -> Arc<dyn Plugin> {
    Arc::new(ApiKey { inner: Arc::new(new_inner(vec![options])) })
}

/// The api-key plugin with several configurations, each with a unique `config_id`.
pub fn api_key_configurations(configs: Vec<ApiKeyOptions>) -> Result<Arc<dyn Plugin>> {
    if configs.is_empty() {
        return Ok(api_key(ApiKeyOptions::default()));
    }
    if configs.iter().any(|c| c.config_id.is_none()) {
        return Err(Error::Config("configId is required for each API key configuration in the api-key plugin.".into()));
    }
    let mut ids: Vec<&str> = configs.iter().map(ApiKeyOptions::id).collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != configs.len() {
        return Err(Error::Config(
            "configId must be unique for each API key configuration in the api-key plugin.".into(),
        ));
    }
    Ok(Arc::new(ApiKey { inner: Arc::new(new_inner(configs)) }))
}

fn new_inner(configs: Vec<ApiKeyOptions>) -> Inner {
    Inner { configs, last_cleanup: Mutex::new(None), ref_list_lock: tokio::sync::Mutex::new(()) }
}

impl Plugin for ApiKey {
    fn id(&self) -> &str {
        "api-key"
    }

    fn schema(&self) -> Vec<TableExtension> {
        // Column defaults come from the configuration when there is exactly one.
        let single = (self.inner.configs.len() == 1).then(|| &self.inner.configs[0].rate_limit);
        let window = single.map_or(86_400_000, |r| r.time_window.as_millis() as i64);
        let max = single.map_or(10, |r| r.max_requests);
        vec![TableExtension {
            key: API_KEY_TABLE.into(),
            fields: vec![
                ("configId".into(), Field::string().default("default").no_input().indexed()),
                ("name".into(), Field::string().optional().no_input()),
                ("start".into(), Field::string().optional().no_input()),
                ("referenceId".into(), Field::string().no_input().indexed()),
                ("prefix".into(), Field::string().optional().no_input()),
                ("key".into(), Field::string().no_input().indexed()),
                // Milliseconds; BIGINT so intervals beyond ~24 days fit.
                ("refillInterval".into(), Field::number().bigint().optional().no_input()),
                ("refillAmount".into(), Field::number().optional().no_input()),
                ("lastRefillAt".into(), Field::date().optional().no_input()),
                ("enabled".into(), Field::boolean().optional().no_input().default(true)),
                ("rateLimitEnabled".into(), Field::boolean().optional().no_input().default(true)),
                ("rateLimitTimeWindow".into(), Field::number().bigint().optional().no_input().default(window)),
                ("rateLimitMax".into(), Field::number().optional().no_input().default(max)),
                ("requestCount".into(), Field::number().optional().no_input().default(0)),
                ("remaining".into(), Field::number().optional().no_input()),
                ("lastRequest".into(), Field::date().optional().no_input()),
                ("expiresAt".into(), Field::date().optional().no_input()),
                ("createdAt".into(), Field::date().no_input()),
                ("updatedAt".into(), Field::date().no_input()),
                // JSON strings, as in TS.
                ("permissions".into(), Field::string().optional().no_input()),
                ("metadata".into(), Field::string().optional()),
            ],
            ..Default::default()
        }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let i = &self.inner;
        let (a, b, c, d, e, f, g) = (i.clone(), i.clone(), i.clone(), i.clone(), i.clone(), i.clone(), i.clone());
        vec![
            Endpoint::post("createApiKey", "/api-key/create", handler(move |ctx| routes::create(a.clone(), ctx))),
            Endpoint::post("verifyApiKey", "/api-key/verify", handler(move |ctx| routes::verify(b.clone(), ctx)))
                .server_only(),
            Endpoint::get("getApiKey", "/api-key/get", handler(move |ctx| routes::get(c.clone(), ctx))),
            Endpoint::post("updateApiKey", "/api-key/update", handler(move |ctx| routes::update(d.clone(), ctx))),
            Endpoint::post("deleteApiKey", "/api-key/delete", handler(move |ctx| routes::delete(e.clone(), ctx))),
            Endpoint::get("listApiKeys", "/api-key/list", handler(move |ctx| routes::list(f.clone(), ctx))),
            Endpoint::post(
                "deleteAllExpiredApiKeys",
                "/api-key/delete-all-expired-api-keys",
                handler(move |ctx| routes::delete_all_expired(g.clone(), ctx)),
            )
            .server_only(),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        if !self.inner.configs.iter().any(|c| c.enable_session_for_api_keys) {
            return PluginHooks::default();
        }
        let (matcher_inner, inner) = (self.inner.clone(), self.inner.clone());
        PluginHooks {
            before: vec![MatchedHook::new(
                move |ctx| matcher_inner.find_key(ctx).is_some(),
                hook(move |ctx| {
                    let inner = inner.clone();
                    async move { session_from_api_key(inner, &ctx).await }
                }),
            )],
            after: vec![],
        }
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        error_codes::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// `ApiError` with a status and message only.
fn status_error(status: StatusCode, message: impl Into<String>) -> ApiError {
    ApiError::message(status, message)
}

/// The JSON body of an API key for responses: no `key`, parsed `permissions`, and the
/// given metadata.
fn public_key(mut api_key: Map<String, Value>, metadata: Value) -> Value {
    api_key.remove("key");
    let permissions = store::parse_permissions(&api_key).map(Value::Object).unwrap_or(Value::Null);
    api_key.insert("permissions".into(), permissions);
    api_key.insert("metadata".into(), metadata);
    Value::Object(api_key)
}
