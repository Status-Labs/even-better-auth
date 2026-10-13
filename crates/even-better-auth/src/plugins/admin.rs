//! User administration (`plugins/admin`): roles and permissions, user CRUD, bans,
//! impersonation and session management under `/admin/*`.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::Utc;
use http::StatusCode;
use serde_json::{Map, Value, json};

use super::access::{AccessControl, Connector, Role, Statements, statements};
use crate::api::middleware::{authoritative_session, get_session_from_ctx};
use crate::api::routes::util::{assert_password_length, assert_password_not_too_long, is_valid_email};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointOutput, EndpointResult, current_request, handler, hook};
use crate::cookies::{delete_session_cookie, set_session_cookie};
use crate::db::hooks::{BeforeOutcome, DatabaseHooks, Operation};
use crate::db::{Field, Operator, Record, SessionOverrides, SortBy, SortDirection, TableExtension, Where};
use crate::error::{ApiError, Error, ErrorCode, Result, codes};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::types::{Model, SessionWithUser, User};
use crate::utils::date;
use crate::utils::validate_user_info::UserSource;

/// Error codes (`ADMIN_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        FAILED_TO_CREATE_USER => "Failed to create user",
        USER_ALREADY_EXISTS => "User already exists.",
        USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL => "User already exists. Use another email.",
        YOU_CANNOT_BAN_YOURSELF => "You cannot ban yourself",
        YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE => "You are not allowed to change users role",
        YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS => "You are not allowed to create users",
        YOU_ARE_NOT_ALLOWED_TO_LIST_USERS => "You are not allowed to list users",
        YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS => "You are not allowed to list users sessions",
        YOU_ARE_NOT_ALLOWED_TO_BAN_USERS => "You are not allowed to ban users",
        YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS => "You are not allowed to impersonate users",
        YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS => "You are not allowed to revoke users sessions",
        YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS => "You are not allowed to delete users",
        YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD => "You are not allowed to set users password",
        BANNED_USER => "You have been banned from this application",
        YOU_ARE_NOT_ALLOWED_TO_GET_USER => "You are not allowed to get user",
        NO_DATA_TO_UPDATE => "No data to update",
        YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS => "You are not allowed to update users",
        YOU_CANNOT_REMOVE_YOURSELF => "You cannot remove yourself",
        YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE => "You are not allowed to set a non-existent role value",
        YOU_CANNOT_IMPERSONATE_ADMINS => "You cannot impersonate admins",
        INVALID_ROLE_TYPE => "Invalid role type",
        YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL => "You are not allowed to update users email",
        PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER => "Password cannot be updated through update-user. Use the set-user-password endpoint instead",
    }
}

use error_codes as e;

/// The admin plugin's default statements (`defaultStatements`).
pub fn default_statements() -> Statements {
    statements(&[
        (
            "user",
            &[
                "create",
                "list",
                "set-role",
                "ban",
                "impersonate",
                "impersonate-admins",
                "delete",
                "set-password",
                "set-email",
                "get",
                "update",
            ],
        ),
        ("session", &["list", "revoke", "delete"]),
    ])
}

/// The default `admin` and `user` roles (`defaultRoles`).
pub fn default_roles() -> BTreeMap<String, Role> {
    let ac = AccessControl::new(default_statements());
    let admin = ac.new_role(statements(&[
        (
            "user",
            &[
                "create",
                "list",
                "set-role",
                "ban",
                "impersonate",
                "delete",
                "set-password",
                "set-email",
                "get",
                "update",
            ],
        ),
        ("session", &["list", "revoke", "delete"]),
    ]));
    let user = ac.new_role(statements(&[("user", &[]), ("session", &[])]));
    BTreeMap::from([("admin".to_owned(), admin), ("user".to_owned(), user)])
}

/// The message shown to banned users.
#[derive(Clone)]
pub enum BannedUserMessage {
    Text(String),
    Dynamic(Arc<dyn Fn(&User) -> String + Send + Sync>),
}

#[derive(Clone)]
pub struct AdminOptions {
    /// Default `"user"`.
    pub default_role: String,
    /// Roles treated as admins for impersonation checks (default `["admin"]`).
    pub admin_roles: Vec<String>,
    pub default_ban_reason: Option<String>,
    /// Seconds.
    pub default_ban_expires_in: Option<i64>,
    /// Seconds (default 1 hour).
    pub impersonation_session_duration: Option<i64>,
    /// Custom roles; `None` uses [`default_roles`].
    pub roles: Option<BTreeMap<String, Role>>,
    /// Users with every permission regardless of role.
    pub admin_user_ids: Vec<String>,
    pub banned_user_message: BannedUserMessage,
    pub allow_impersonating_admins: bool,
}

impl Default for AdminOptions {
    fn default() -> Self {
        Self {
            default_role: "user".into(),
            admin_roles: vec!["admin".into()],
            default_ban_reason: None,
            default_ban_expires_in: None,
            impersonation_session_duration: None,
            roles: None,
            admin_user_ids: vec![],
            banned_user_message: BannedUserMessage::Text(
                "You have been banned from this application. Please contact support if you believe this is an error."
                    .into(),
            ),
            allow_impersonating_admins: false,
        }
    }
}

struct Inner {
    options: AdminOptions,
    roles: BTreeMap<String, Role>,
}

fn user_role(user: &User) -> Option<&str> {
    user.extra.get("role").and_then(Value::as_str)
}

impl Inner {
    /// `hasPermission`: admin user ids pass; otherwise any of the (comma-separated) roles must
    /// authorize every requested permission.
    fn has_permission(&self, user_id: Option<&str>, role: Option<&str>, permissions: &Map<String, Value>) -> bool {
        if user_id.is_some_and(|id| self.options.admin_user_ids.iter().any(|a| a == id)) {
            return true;
        }
        let role = role.unwrap_or(&self.options.default_role);
        role.split(',')
            .any(|r| self.roles.get(r).is_some_and(|role| role.authorize(permissions, Connector::And).success()))
    }

    fn can(&self, user: &User, resource: &str, action: &str) -> bool {
        let mut permissions = Map::new();
        permissions.insert(resource.into(), json!([action]));
        self.has_permission(Some(&user.id), user_role(user), &permissions)
    }

    fn require(&self, user: &User, resource: &str, action: &str, code: ErrorCode) -> Result<(), ApiError> {
        if self.can(user, resource, action) { Ok(()) } else { Err(ApiError::forbidden(code)) }
    }

    /// Validate requested role(s) against the configured roles and join them.
    fn parse_roles(&self, value: &Value) -> Result<String, ApiError> {
        let roles: Vec<&Value> = match value {
            Value::Array(list) => list.iter().collect(),
            v => vec![v],
        };
        let mut names = vec![];
        for role in roles {
            let Some(role) = role.as_str() else { return Err(ApiError::bad_request(e::INVALID_ROLE_TYPE)) };
            if self.options.roles.is_some() && !self.roles.contains_key(role) {
                return Err(ApiError::bad_request(e::YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE));
            }
            names.push(role);
        }
        Ok(names.join(","))
    }
}

fn coerce_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn body_object(ctx: &EndpointContext) -> Result<Map<String, Value>, ApiError> {
    match ctx.body() {
        Value::Object(m) => Ok(m),
        _ => Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT)),
    }
}

fn required_string(body: &Map<String, Value>, key: &str) -> Result<String, ApiError> {
    coerce_string(body.get(key)).ok_or_else(|| {
        ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", format!("{key} is required"))
    })
}

async fn admin_session(ctx: &EndpointContext) -> Result<SessionWithUser, ApiError> {
    authoritative_session(ctx).await?.ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED))
}

async fn find_user(ctx: &EndpointContext, id: &str) -> Result<User, ApiError> {
    ctx.auth.internal_adapter.find_user_by_id(id).await?.ok_or_else(|| ApiError::not_found(codes::USER_NOT_FOUND))
}

fn user_json(ctx: &EndpointContext, user: &User) -> Value {
    Value::Object(ctx.auth.user_output(user))
}

async fn update_user(ctx: &EndpointContext, id: &str, data: Record) -> Result<User, ApiError> {
    ctx.auth.internal_adapter.update_user(id, data).await?.ok_or_else(|| ApiError::not_found(codes::USER_NOT_FOUND))
}

// ---- endpoints ----------------------------------------------------------------------

async fn set_role(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    let body = body_object(&ctx)?;
    inner.require(&session.user, "user", "set-role", e::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE)?;
    let user_id = required_string(&body, "userId")?;
    let role = inner.parse_roles(body.get("role").unwrap_or(&Value::Null))?;
    find_user(&ctx, &user_id).await?;
    let mut update = Record::new();
    update.insert("role".into(), role.into());
    let user = update_user(&ctx, &user_id, update).await?;
    ctx.json(json!({ "user": user_json(&ctx, &user) }))
}

async fn get_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "user", "get", e::YOU_ARE_NOT_ALLOWED_TO_GET_USER)?;
    let id = ctx.query_str("id").ok_or_else(|| ApiError::bad_request(codes::VALIDATION_ERROR))?;
    let user = find_user(&ctx, &id).await?;
    ctx.json(user_json(&ctx, &user))
}

async fn create_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = authoritative_session(&ctx).await?;
    if session.is_none() && (ctx.is_request || !ctx.headers().is_empty()) {
        return Err(ApiError::status(StatusCode::UNAUTHORIZED));
    }
    let body = body_object(&ctx)?;
    if let Some(s) = &session {
        inner.require(&s.user, "user", "create", e::YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS)?;
    }
    // `data.role` gets the same checks as `role`, so `user:create` cannot assign roles.
    let mut data = body.get("data").and_then(Value::as_object).cloned().unwrap_or_default();
    let data_role = data.remove("role");
    let requested_role = body.get("role").cloned().or(data_role);
    let mut role = inner.options.default_role.clone();
    if let Some(requested) = &requested_role {
        if let Some(s) = &session {
            inner.require(&s.user, "user", "set-role", e::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE)?;
        }
        role = inner.parse_roles(requested)?;
    }
    if let Some(s) = &session
        && ["banned", "banReason", "banExpires"].iter().any(|k| data.contains_key(*k))
    {
        inner.require(&s.user, "user", "ban", e::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS)?;
    }
    let email = required_string(&body, "email")?.to_lowercase();
    if !is_valid_email(&email) {
        return Err(ApiError::bad_request(codes::INVALID_EMAIL));
    }
    let name = required_string(&body, "name")?;
    let password = body.get("password").and_then(Value::as_str).filter(|p| !p.is_empty()).map(str::to_owned);
    if let Some(p) = &password {
        assert_password_not_too_long(&ctx, p)?;
    }
    let ia = &ctx.auth.internal_adapter;
    if ia.find_user_by_email(&email).await?.is_some() {
        return Err(ApiError::bad_request(e::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL));
    }
    data.insert("email".into(), email.into());
    data.insert("name".into(), name.into());
    data.insert("role".into(), role.into());
    let user = ia
        .create_user(data, &UserSource::method("admin"))
        .await
        .map_err(|err| err.api_or(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_CREATE_USER)))?;
    if let Some(password) = password {
        let hash = ctx.auth.hash_password(&password).await?;
        let mut account = Record::new();
        account.insert("providerId".into(), "credential".into());
        account.insert("accountId".into(), user.id.clone().into());
        account.insert("password".into(), hash.into());
        account.insert("userId".into(), user.id.clone().into());
        ia.link_account(account).await?;
    }
    ctx.json(json!({ "user": user_json(&ctx, &user) }))
}

async fn admin_update_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let admin = &session.user;
    inner.require(admin, "user", "update", e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS)?;
    let user_id = required_string(&body, "userId")?;
    let mut data = body.get("data").and_then(Value::as_object).cloned().unwrap_or_default();
    if data.is_empty() {
        return Err(ApiError::bad_request(e::NO_DATA_TO_UPDATE));
    }
    // Passwords live hashed on the credential account, never on the user.
    if data.contains_key("password") {
        return Err(ApiError::bad_request(e::PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER));
    }
    if let Some(role) = data.get("role").cloned() {
        inner.require(admin, "user", "set-role", e::YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE)?;
        data.insert("role".into(), inner.parse_roles(&role)?.into());
    }
    if ["banned", "banReason", "banExpires"].iter().any(|k| data.contains_key(*k)) {
        inner.require(admin, "user", "ban", e::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS)?;
        if data.get("banned") == Some(&Value::Bool(true)) && user_id == admin.id {
            return Err(ApiError::bad_request(e::YOU_CANNOT_BAN_YOURSELF));
        }
    }
    if data.contains_key("email") || data.contains_key("emailVerified") {
        inner.require(admin, "user", "set-email", e::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL)?;
        if let Some(email) = data.get("email") {
            let email = match email {
                Value::String(s) => s.to_lowercase(),
                other => other.to_string().to_lowercase(),
            };
            if !is_valid_email(&email) {
                return Err(ApiError::bad_request(codes::INVALID_EMAIL));
            }
            if ctx.auth.internal_adapter.find_user_by_email(&email).await?.is_some_and(|u| u.id != user_id) {
                return Err(ApiError::bad_request(e::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL));
            }
            data.insert("email".into(), email.into());
        }
    }
    find_user(&ctx, &user_id).await?;
    let banned = data.get("banned") == Some(&Value::Bool(true));
    let user = update_user(&ctx, &user_id, data).await?;
    if banned {
        ctx.auth.internal_adapter.delete_user_sessions(&user_id).await?;
    }
    ctx.json(user_json(&ctx, &user))
}

fn parse_operator(op: &str) -> Option<Operator> {
    Some(match op {
        "eq" => Operator::Eq,
        "ne" => Operator::Ne,
        "lt" => Operator::Lt,
        "lte" => Operator::Lte,
        "gt" => Operator::Gt,
        "gte" => Operator::Gte,
        "in" => Operator::In,
        "not_in" => Operator::NotIn,
        "contains" => Operator::Contains,
        "starts_with" => Operator::StartsWith,
        "ends_with" => Operator::EndsWith,
        _ => return None,
    })
}

/// A query value as it would arrive in JSON (`true`/numbers/arrays stay typed).
fn query_value(v: &Value) -> Value {
    match v {
        Value::String(s) => match s.as_str() {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => s.parse::<i64>().map(Value::from).unwrap_or_else(|_| v.clone()),
        },
        other => other.clone(),
    }
}

fn positive_number(v: Option<&Value>) -> Option<usize> {
    let n = match v? {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => s.parse::<f64>().ok()?,
        _ => return None,
    };
    (n >= 1.0).then_some(n as usize)
}

async fn list_users(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "user", "list", e::YOU_ARE_NOT_ALLOWED_TO_LIST_USERS)?;
    let query = ctx.query();
    let s = |k: &str| query.get(k).and_then(Value::as_str);
    let mut where_ = vec![];
    if let Some(search) = s("searchValue").filter(|v| !v.is_empty()) {
        let field = s("searchField").unwrap_or("email");
        if !matches!(field, "email" | "name") {
            return Err(ApiError::bad_request(codes::VALIDATION_ERROR));
        }
        let op = match s("searchOperator").unwrap_or("contains") {
            "contains" => Operator::Contains,
            "starts_with" => Operator::StartsWith,
            "ends_with" => Operator::EndsWith,
            _ => return Err(ApiError::bad_request(codes::VALIDATION_ERROR)),
        };
        where_.push(Where::new(field, op, search));
    }
    if let Some(value) = query.get("filterValue") {
        let op = match s("filterOperator") {
            Some(op) => parse_operator(op).ok_or_else(|| ApiError::bad_request(codes::VALIDATION_ERROR))?,
            None => Operator::Eq,
        };
        where_.push(Where::new(s("filterField").unwrap_or("email"), op, query_value(value)));
    }
    let limit = positive_number(query.get("limit"));
    let offset = positive_number(query.get("offset"));
    let sort_by = s("sortBy").map(|field| SortBy {
        field: field.to_owned(),
        direction: if s("sortDirection") == Some("desc") { SortDirection::Desc } else { SortDirection::Asc },
    });
    let ia = &ctx.auth.internal_adapter;
    let result = async {
        let users = ia.list_users(limit, offset, sort_by, where_.clone()).await?;
        let total = ia.count_total_users(&where_).await?;
        Ok::<_, Error>((users, total))
    }
    .await;
    match result {
        Ok((users, total)) => {
            let users: Vec<Value> = users.iter().map(|u| user_json(&ctx, u)).collect();
            ctx.json(json!({ "users": users, "total": total, "limit": limit, "offset": offset }))
        }
        Err(_) => ctx.json(json!({ "users": [], "total": 0 })),
    }
}

async fn list_user_sessions(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "session", "list", e::YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS)?;
    let user_id = required_string(&body_object(&ctx)?, "userId")?;
    let sessions = ctx.auth.internal_adapter.list_sessions(&user_id).await?;
    let sessions: Vec<Value> = sessions.iter().map(|s| Value::Object(ctx.auth.session_output(s))).collect();
    ctx.json(json!({ "sessions": sessions }))
}

async fn unban_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "user", "ban", e::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS)?;
    let user_id = required_string(&body_object(&ctx)?, "userId")?;
    find_user(&ctx, &user_id).await?;
    let mut update = Record::new();
    update.insert("banned".into(), false.into());
    update.insert("banExpires".into(), Value::Null);
    update.insert("banReason".into(), Value::Null);
    update.insert("updatedAt".into(), date::now_value());
    let user = update_user(&ctx, &user_id, update).await?;
    ctx.json(json!({ "user": user_json(&ctx, &user) }))
}

async fn ban_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "user", "ban", e::YOU_ARE_NOT_ALLOWED_TO_BAN_USERS)?;
    let body = body_object(&ctx)?;
    let user_id = required_string(&body, "userId")?;
    find_user(&ctx, &user_id).await?;
    if user_id == session.user.id {
        return Err(ApiError::bad_request(e::YOU_CANNOT_BAN_YOURSELF));
    }
    let reason = body
        .get("banReason")
        .and_then(Value::as_str)
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
        .or_else(|| inner.options.default_ban_reason.clone())
        .unwrap_or_else(|| "No reason".into());
    let expires_in =
        body.get("banExpiresIn").and_then(Value::as_i64).filter(|s| *s != 0).or(inner.options.default_ban_expires_in);
    let mut update = Record::new();
    update.insert("banned".into(), true.into());
    update.insert("banReason".into(), reason.into());
    // A permanent ban clears any expiry left from a previous temporary ban.
    update.insert("banExpires".into(), expires_in.map(|s| date::to_value(date::in_secs(s))).unwrap_or(Value::Null));
    update.insert("updatedAt".into(), date::now_value());
    let user = update_user(&ctx, &user_id, update).await?;
    ctx.auth.internal_adapter.delete_user_sessions(&user_id).await?;
    ctx.json(json!({ "user": user_json(&ctx, &user) }))
}

async fn impersonate_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    let admin = &session.user;
    inner.require(admin, "user", "impersonate", e::YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS)?;
    let user_id = required_string(&body_object(&ctx)?, "userId")?;
    let target = find_user(&ctx, &user_id).await?;
    let target_roles = user_role(&target).unwrap_or(&inner.options.default_role);
    let is_admin = target_roles.split(',').any(|r| inner.options.admin_roles.iter().any(|a| a.trim() == r))
        || inner.options.admin_user_ids.contains(&target.id);
    if is_admin && !inner.options.allow_impersonating_admins && !inner.can(admin, "user", "impersonate-admins") {
        return Err(ApiError::forbidden(e::YOU_CANNOT_IMPERSONATE_ADMINS));
    }
    let auth = ctx.auth.clone();
    let duration = inner.options.impersonation_session_duration.unwrap_or(60 * 60);
    let mut data = Record::new();
    data.insert("impersonatedBy".into(), admin.id.clone().into());
    data.insert("expiresAt".into(), date::to_value(date::in_secs(duration)));
    let impersonation = auth
        .internal_adapter
        .create_session(&target.id, true, Some(SessionOverrides { data, override_all: true }))
        .await
        .map_err(|err| err.api_or(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_CREATE_USER)))?;
    delete_session_cookie(&ctx, false);
    let dont_remember = ctx.get_signed_cookie(&auth.cookies.dont_remember.name, &auth.secret).unwrap_or_default();
    let admin_cookie = auth.cookie_factory.create("admin_session", None);
    ctx.set_signed_cookie(
        &admin_cookie.name,
        &format!("{}:{dont_remember}", session.session.token),
        &auth.secret,
        &auth.cookies.session_token.attributes,
    );
    set_session_cookie(
        &ctx,
        &SessionWithUser { session: impersonation.clone(), user: target.clone() },
        Some(true),
        None,
    )
    .await;
    ctx.json(json!({ "session": Value::Object(impersonation.to_record()), "user": user_json(&ctx, &target) }))
}

async fn stop_impersonating(ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default())
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED))?;
    let Some(admin_id) = session.session.extra.get("impersonatedBy").and_then(Value::as_str).filter(|s| !s.is_empty())
    else {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "You are not impersonating anyone"));
    };
    let auth = ctx.auth.clone();
    let internal = |msg: &str| ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, msg);
    let admin =
        auth.internal_adapter.find_user_by_id(admin_id).await?.ok_or_else(|| internal("Failed to find user"))?;
    let admin_cookie = auth.cookie_factory.create("admin_session", None);
    let value = ctx
        .get_signed_cookie(&admin_cookie.name, &auth.secret)
        .ok_or_else(|| internal("Failed to find admin session"))?;
    let (token, dont_remember) = value.split_once(':').unwrap_or((&value, ""));
    let admin_session = auth
        .internal_adapter
        .find_session(token)
        .await?
        .filter(|s| s.session.user_id == admin.id)
        .ok_or_else(|| internal("Failed to find admin session"))?;
    auth.internal_adapter.delete_session(&session.session.token).await?;
    set_session_cookie(&ctx, &admin_session, Some(!dont_remember.is_empty()), None).await;
    ctx.expire_cookie(&admin_cookie);
    ctx.json(json!({
        "session": auth.session_output(&admin_session.session),
        "user": auth.user_output(&admin_session.user),
    }))
}

async fn revoke_user_session(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "session", "revoke", e::YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS)?;
    let token = required_string(&body_object(&ctx)?, "sessionToken")?;
    ctx.auth.internal_adapter.delete_session(&token).await?;
    ctx.json(json!({ "success": true }))
}

async fn revoke_user_sessions(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "session", "revoke", e::YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS)?;
    let user_id = required_string(&body_object(&ctx)?, "userId")?;
    ctx.auth.internal_adapter.delete_user_sessions(&user_id).await?;
    ctx.json(json!({ "success": true }))
}

async fn remove_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "user", "delete", e::YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS)?;
    let user_id = required_string(&body_object(&ctx)?, "userId")?;
    if user_id == session.user.id {
        return Err(ApiError::bad_request(e::YOU_CANNOT_REMOVE_YOURSELF));
    }
    find_user(&ctx, &user_id).await?;
    let ia = &ctx.auth.internal_adapter;
    ia.delete_user_sessions(&user_id).await?;
    ia.delete_user(&user_id).await?;
    ctx.json(json!({ "success": true }))
}

async fn set_user_password(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = admin_session(&ctx).await?;
    inner.require(&session.user, "user", "set-password", e::YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD)?;
    let body = body_object(&ctx)?;
    let password = body.get("newPassword").and_then(Value::as_str).filter(|p| !p.is_empty()).ok_or_else(|| {
        ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", "newPassword cannot be empty")
    })?;
    let user_id = coerce_string(body.get("userId")).filter(|u| !u.is_empty()).ok_or_else(|| {
        ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", "userId cannot be empty")
    })?;
    assert_password_length(&ctx, password)?;
    let user = find_user(&ctx, &user_id).await?;
    let ia = &ctx.auth.internal_adapter;
    let hash = ctx.auth.hash_password(password).await?;
    if ia.find_credential_account(&user_id).await?.is_some() {
        ia.update_password(&user_id, &hash).await?;
    } else {
        let mut account = Record::new();
        account.insert("userId".into(), user_id.into());
        account.insert("providerId".into(), "credential".into());
        account.insert("accountId".into(), user.id.into());
        account.insert("password".into(), hash.into());
        ia.create_account(account).await?;
    }
    ctx.json(json!({ "status": true }))
}

async fn user_has_permission(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body = body_object(&ctx)?;
    let Some(permissions) = body.get("permissions").and_then(Value::as_object) else {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "invalid permission check. no permission(s) were passed.",
        ));
    };
    let session = authoritative_session(&ctx).await?;
    if session.is_none() && (ctx.is_request || !ctx.headers().is_empty()) {
        return Err(ApiError::status(StatusCode::UNAUTHORIZED));
    }
    let user_id = coerce_string(body.get("userId"));
    let role = body.get("role").and_then(Value::as_str).map(str::to_owned);
    if session.is_none() && user_id.is_none() && role.is_none() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "user id or role is required"));
    }
    let (id, role) = match (&session, role, user_id) {
        (Some(s), _, _) => (s.user.id.clone(), user_role(&s.user).map(str::to_owned)),
        (None, Some(role), id) => (id.unwrap_or_default(), Some(role)),
        (None, None, Some(id)) => {
            let user = ctx.auth.internal_adapter.find_user_by_id(&id).await?;
            let user = user.ok_or_else(|| ApiError::message(StatusCode::BAD_REQUEST, "user not found"))?;
            (user.id.clone(), user_role(&user).map(str::to_owned))
        }
        (None, None, None) => unreachable!("checked above"),
    };
    let success = inner.has_permission(Some(&id), role.as_deref(), permissions);
    ctx.json(json!({ "error": null, "success": success }))
}

// ---- hooks ---------------------------------------------------------------------------

/// Reject session creation for banned users (lifting expired bans).
async fn check_ban(inner: Arc<Inner>, session: Record) -> Result<BeforeOutcome> {
    let Some(ctx) = current_request() else { return Ok(BeforeOutcome::Continue) };
    let Some(user_id) = session.get("userId").and_then(Value::as_str) else { return Ok(BeforeOutcome::Continue) };
    let Some(user) = ctx.auth.internal_adapter.find_user_by_id(user_id).await? else {
        return Ok(BeforeOutcome::Continue);
    };
    if user.extra.get("banned") != Some(&Value::Bool(true)) {
        return Ok(BeforeOutcome::Continue);
    }
    let expires = user.extra.get("banExpires").and_then(date::parse_value);
    if expires.is_some_and(|e| e < Utc::now()) {
        let mut update = Record::new();
        update.insert("banned".into(), false.into());
        update.insert("banReason".into(), Value::Null);
        update.insert("banExpires".into(), Value::Null);
        ctx.auth.internal_adapter.update_user(user_id, update).await?;
        return Ok(BeforeOutcome::Continue);
    }
    let message = match &inner.options.banned_user_message {
        BannedUserMessage::Text(t) => t.clone(),
        BannedUserMessage::Dynamic(f) => f(&user),
    };
    Err(Error::Api(ApiError::new(StatusCode::FORBIDDEN, "BANNED_USER", message)))
}

/// Hide impersonation sessions from `/list-sessions`.
fn filter_impersonations(ctx: &EndpointContext) -> Option<EndpointOutput> {
    let Some(Ok(EndpointOutput::Json(Value::Array(sessions)))) = ctx.returned() else { return None };
    let kept: Vec<Value> = sessions
        .into_iter()
        .filter(|s| s.get("impersonatedBy").is_none_or(|v| v.is_null() || v.as_str() == Some("")))
        .collect();
    Some(EndpointOutput::Json(Value::Array(kept)))
}

// ---- plugin -------------------------------------------------------------------------

pub struct Admin {
    inner: Arc<Inner>,
}

/// Create the plugin; fails if `admin_roles` names a role that is not configured.
pub fn admin(options: AdminOptions) -> Result<Arc<dyn Plugin>> {
    let roles = options.roles.clone().unwrap_or_else(default_roles);
    let known: Vec<String> = roles.keys().map(|r| r.to_lowercase()).collect();
    let invalid: Vec<&str> =
        options.admin_roles.iter().map(String::as_str).filter(|r| !known.contains(&r.to_lowercase())).collect();
    if !invalid.is_empty() {
        return Err(Error::Config(format!(
            "Invalid admin roles: {}. Admin roles must be defined in the 'roles' configuration.",
            invalid.join(", ")
        )));
    }
    Ok(Arc::new(Admin { inner: Arc::new(Inner { options, roles }) }))
}

macro_rules! route {
    ($inner:expr, $method:ident, $key:literal, $path:literal, $f:ident) => {{
        let inner = $inner.clone();
        Endpoint::$method($key, $path, handler(move |ctx| $f(inner.clone(), ctx)))
    }};
}

impl Plugin for Admin {
    fn id(&self) -> &str {
        "admin"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![
            TableExtension {
                key: "user".into(),
                fields: vec![
                    ("role".into(), Field::string().optional().no_input()),
                    ("banned".into(), Field::boolean().optional().default(false).no_input()),
                    ("banReason".into(), Field::string().optional().no_input()),
                    ("banExpires".into(), Field::date().optional().no_input()),
                ],
                ..Default::default()
            },
            TableExtension {
                key: "session".into(),
                fields: vec![("impersonatedBy".into(), Field::string().optional().no_input())],
                ..Default::default()
            },
        ]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let i = &self.inner;
        vec![
            route!(i, post, "setRole", "/admin/set-role", set_role),
            route!(i, get, "getUser", "/admin/get-user", get_user),
            route!(i, post, "createUser", "/admin/create-user", create_user),
            route!(i, post, "adminUpdateUser", "/admin/update-user", admin_update_user),
            route!(i, get, "listUsers", "/admin/list-users", list_users),
            route!(i, post, "listUserSessions", "/admin/list-user-sessions", list_user_sessions),
            route!(i, post, "unbanUser", "/admin/unban-user", unban_user),
            route!(i, post, "banUser", "/admin/ban-user", ban_user),
            route!(i, post, "impersonateUser", "/admin/impersonate-user", impersonate_user),
            Endpoint::post("stopImpersonating", "/admin/stop-impersonating", handler(stop_impersonating)),
            route!(i, post, "revokeUserSession", "/admin/revoke-user-session", revoke_user_session),
            route!(i, post, "revokeUserSessions", "/admin/revoke-user-sessions", revoke_user_sessions),
            route!(i, post, "removeUser", "/admin/remove-user", remove_user),
            route!(i, post, "setUserPassword", "/admin/set-user-password", set_user_password),
            route!(i, post, "userHasPermission", "/admin/has-permission", user_has_permission),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |ctx| ctx.path == "/list-sessions",
                hook(|ctx| async move { Ok(filter_impersonations(&ctx)) }),
            )],
        }
    }

    fn database_hooks(&self) -> DatabaseHooks {
        let default_role = self.inner.options.default_role.clone();
        let inner = self.inner.clone();
        DatabaseHooks::new()
            .before("user", Operation::Create, move |user| {
                let default_role = default_role.clone();
                async move {
                    if user.get("role").is_some_and(|r| !r.is_null()) {
                        return Ok(BeforeOutcome::Continue);
                    }
                    let mut data = Record::new();
                    data.insert("role".into(), default_role.into());
                    Ok(BeforeOutcome::Merge(data))
                }
            })
            .before("session", Operation::Create, move |session| check_ban(inner.clone(), session))
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
