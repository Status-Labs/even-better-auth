//! Dynamic access control: per-organization roles stored in `organizationRole`
//! (`routes/crud-access-control.ts`).

use std::collections::BTreeMap;

use http::StatusCode;
use serde_json::{Map, Value, json};

use super::{
    In, active_org, bad, body_object, coerce_string, e, forbidden, has_permission, permission, route, str_field,
};
use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult};
use crate::db::{FindManyQuery, InputAction, Record, Where, parse_input};
use crate::error::{ApiError, ErrorCode};
use crate::plugins::access::AccessControl;
use crate::types::SessionWithUser;
use crate::utils::date;

type Permission = BTreeMap<String, Vec<String>>;
const CORE_FIELDS: &[&str] = &["organizationId", "role", "permission", "createdAt", "updatedAt"];

fn missing_ac() -> ApiError {
    tracing::error!(
        "[Dynamic Access Control] The organization plugin is missing a pre-defined ac instance. Please refer to the documentation here: https://better-auth.com/docs/plugins/organization#dynamic-access-control"
    );
    ApiError::from_code(StatusCode::NOT_IMPLEMENTED, e::MISSING_AC_INSTANCE)
}

fn parse_permission(v: Option<&Value>) -> Result<Permission, ApiError> {
    serde_json::from_value(v.cloned().unwrap_or(Value::Null)).map_err(|_| {
        ApiError::bad_request(crate::error::codes::VALIDATION_ERROR).with_field("message", "invalid permission")
    })
}

fn predefined_roles(inner: &In) -> Vec<String> {
    match &inner.options.roles {
        Some(roles) => roles.keys().cloned().collect(),
        None => vec!["owner".into(), "admin".into(), "member".into()],
    }
}

/// The caller's membership and role in `organization_id`.
async fn member_role(
    ctx: &EndpointContext,
    session: &SessionWithUser,
    organization_id: &str,
) -> Result<String, ApiError> {
    let member = ctx
        .auth
        .db
        .find_one(
            "member",
            &[Where::eq("organizationId", organization_id), Where::eq("userId", session.user.id.clone())],
        )
        .await?
        .ok_or_else(|| forbidden(e::YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION))?;
    Ok(str_field(&member, "role").to_owned())
}

async fn require_ac(
    ctx: &EndpointContext,
    inner: &In,
    org_id: &str,
    role: &str,
    action: &str,
    denied: ErrorCode,
) -> Result<(), ApiError> {
    if !has_permission(ctx, inner, org_id, role, &permission("ac", action), false).await? {
        return Err(forbidden(denied));
    }
    Ok(())
}

fn check_resources(ac: &AccessControl, permission: &Permission) -> Result<(), ApiError> {
    if permission.keys().any(|r| !ac.statements.contains_key(r)) {
        return Err(bad(e::INVALID_RESOURCE));
    }
    Ok(())
}

/// The member may only grant permissions they hold themselves.
async fn check_member_has(
    ctx: &EndpointContext,
    inner: &In,
    org_id: &str,
    role: &str,
    permission_required: &Permission,
    denied: ErrorCode,
) -> Result<(), ApiError> {
    let mut missing = vec![];
    for (resource, actions) in permission_required {
        for action in actions {
            if !has_permission(ctx, inner, org_id, role, &permission(resource, action), false).await? {
                missing.push(format!("{resource}:{action}"));
            }
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    Err(ApiError::new(StatusCode::FORBIDDEN, denied.code, denied.message)
        .with_field("missingPermissions", json!(missing)))
}

fn check_not_predefined(inner: &In, role: &str) -> Result<(), ApiError> {
    if predefined_roles(inner).iter().any(|r| r == role) {
        return Err(bad(e::ROLE_NAME_IS_ALREADY_TAKEN));
    }
    Ok(())
}

async fn check_not_in_db(ctx: &EndpointContext, org_id: &str, role: &str) -> Result<(), ApiError> {
    if ctx
        .auth
        .db
        .find_one("organizationRole", &[Where::eq("organizationId", org_id), Where::eq("role", role)])
        .await?
        .is_some()
    {
        return Err(bad(e::ROLE_NAME_IS_ALREADY_TAKEN));
    }
    Ok(())
}

/// A stored role with its `permission` parsed.
fn role_output(mut row: Map<String, Value>) -> Map<String, Value> {
    let parsed = row.get("permission").and_then(Value::as_str).and_then(|s| serde_json::from_str::<Value>(s).ok());
    row.insert("permission".into(), parsed.unwrap_or(Value::Null));
    row
}

/// `roleName` or `roleId` from a body or query, as a where clause.
fn role_condition(source: &Map<String, Value>) -> Result<Where, ApiError> {
    if let Some(name) = source.get("roleName").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        return Ok(Where::eq("role", name));
    }
    if let Some(id) = source.get("roleId").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        return Ok(Where::eq("id", id));
    }
    Err(bad(e::ROLE_NOT_FOUND))
}

fn org_from(source: &Map<String, Value>, session: &SessionWithUser) -> Option<String> {
    coerce_string(source.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(session))
}

async fn create_role(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let ac = inner.options.ac.clone().ok_or_else(missing_ac)?;
    let org_id = org_from(&body, &session).ok_or_else(|| bad(e::YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE))?;
    let role_name = body
        .get("role")
        .and_then(Value::as_str)
        .ok_or_else(|| bad(crate::error::codes::VALIDATION_ERROR))?
        .to_lowercase();
    let permission = parse_permission(body.get("permission"))?;
    check_not_predefined(&inner, &role_name)?;
    let role = member_role(&ctx, &session, &org_id).await?;
    require_ac(&ctx, &inner, &org_id, &role, "create", e::YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE).await?;
    if let Some(limit) = &inner.options.dynamic_access_control.maximum_roles_per_organization {
        let max = limit.resolve(|| Value::String(org_id.clone())).await?;
        let count = ctx.auth.db.count("organizationRole", &[Where::eq("organizationId", org_id.clone())]).await?;
        if count as usize >= max {
            return Err(bad(e::TOO_MANY_ROLES));
        }
    }
    check_resources(&ac, &permission)?;
    check_member_has(&ctx, &inner, &org_id, &role, &permission, e::YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE).await?;
    check_not_in_db(&ctx, &org_id, &role_name).await?;
    let table = ctx.auth.schema.table("organizationRole").expect("organizationRole table");
    let extra = body.get("additionalFields").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut data = parse_input(table, &extra, InputAction::Create, CORE_FIELDS)?;
    data.insert("createdAt".into(), date::now_value());
    data.insert("organizationId".into(), org_id.into());
    data.insert("permission".into(), serde_json::to_string(&permission).unwrap_or_default().into());
    data.insert("role".into(), role_name.into());
    let created = ctx.auth.db.create("organizationRole", data, false).await?;
    let mut role_data = role_output(created);
    role_data.insert("permission".into(), json!(permission));
    ctx.json(json!({ "success": true, "roleData": role_data, "statements": permission }))
}

async fn delete_role(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let org_id = org_from(&body, &session).ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let role = member_role(&ctx, &session, &org_id).await?;
    require_ac(&ctx, &inner, &org_id, &role, "delete", e::YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE).await?;
    if let Some(name) = body.get("roleName").and_then(Value::as_str)
        && predefined_roles(&inner).iter().any(|r| r == name)
    {
        return Err(bad(e::CANNOT_DELETE_A_PRE_DEFINED_ROLE));
    }
    let condition = role_condition(&body)?;
    let where_ = [Where::eq("organizationId", org_id.clone()), condition];
    let db = &ctx.auth.db;
    let existing = db.find_one("organizationRole", &where_).await?.ok_or_else(|| bad(e::ROLE_NOT_FOUND))?;
    let name = str_field(&existing, "role").to_owned();
    let members = db
        .find_many(
            "member",
            FindManyQuery {
                where_: vec![
                    Where::eq("organizationId", org_id.clone()),
                    Where::new("role", crate::db::Operator::Contains, name.clone()),
                ],
                ..Default::default()
            },
        )
        .await?;
    if members.iter().any(|m| super::split_roles(str_field(m, "role")).contains(&name)) {
        return Err(bad(e::ROLE_IS_ASSIGNED_TO_MEMBERS));
    }
    db.delete("organizationRole", &where_).await?;
    ctx.json(json!({ "success": true }))
}

async fn list_roles(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let org_id = org_from(&ctx.query(), &session).ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let role = member_role(&ctx, &session, &org_id).await?;
    require_ac(&ctx, &inner, &org_id, &role, "read", e::YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE).await?;
    let roles = ctx
        .auth
        .db
        .find_many(
            "organizationRole",
            FindManyQuery { where_: vec![Where::eq("organizationId", org_id)], ..Default::default() },
        )
        .await?;
    ctx.json(Value::Array(roles.into_iter().map(|r| Value::Object(role_output(r))).collect()))
}

async fn get_role(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let query = ctx.query();
    let org_id = org_from(&query, &session).ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let role = member_role(&ctx, &session, &org_id).await?;
    require_ac(&ctx, &inner, &org_id, &role, "read", e::YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE).await?;
    let condition = role_condition(&query)?;
    let found = ctx
        .auth
        .db
        .find_one("organizationRole", &[Where::eq("organizationId", org_id), condition])
        .await?
        .ok_or_else(|| bad(e::ROLE_NOT_FOUND))?;
    ctx.json(Value::Object(role_output(found)))
}

async fn update_role(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let ac = inner.options.ac.clone().ok_or_else(missing_ac)?;
    let org_id = org_from(&body, &session).ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let role = member_role(&ctx, &session, &org_id).await?;
    require_ac(&ctx, &inner, &org_id, &role, "update", e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE).await?;
    let condition = role_condition(&body)?;
    let where_ = [Where::eq("organizationId", org_id.clone()), condition];
    let db = &ctx.auth.db;
    let existing = role_output(db.find_one("organizationRole", &where_).await?.ok_or_else(|| bad(e::ROLE_NOT_FOUND))?);
    let data = body.get("data").and_then(Value::as_object).cloned().unwrap_or_default();
    let table = ctx.auth.schema.table("organizationRole").expect("organizationRole table");
    let mut update: Record = parse_input(table, &data, InputAction::Update, CORE_FIELDS)?;
    let mut new_permission = None;
    if let Some(p) = data.get("permission").filter(|p| !p.is_null()) {
        let p = parse_permission(Some(p))?;
        check_resources(&ac, &p)?;
        check_member_has(&ctx, &inner, &org_id, &role, &p, e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE).await?;
        update.insert("permission".into(), serde_json::to_string(&p).unwrap_or_default().into());
        new_permission = Some(p);
    }
    if let Some(name) = data.get("roleName").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let name = name.to_lowercase();
        check_not_predefined(&inner, &name)?;
        check_not_in_db(&ctx, &org_id, &name).await?;
        update.insert("role".into(), name.into());
    }
    db.update_many("organizationRole", &where_, update.clone()).await?;
    let mut role_data = existing.clone();
    role_data.extend(update);
    role_data.insert(
        "permission".into(),
        new_permission.map(|p| json!(p)).unwrap_or_else(|| existing.get("permission").cloned().unwrap_or(Value::Null)),
    );
    ctx.json(json!({ "success": true, "roleData": role_data }))
}

pub(super) fn endpoints(i: &In) -> Vec<Endpoint> {
    vec![
        route!(i, post, "createOrgRole", "/organization/create-role", create_role),
        route!(i, post, "deleteOrgRole", "/organization/delete-role", delete_role),
        route!(i, get, "listOrgRoles", "/organization/list-roles", list_roles),
        route!(i, get, "getOrgRole", "/organization/get-role", get_role),
        route!(i, post, "updateOrgRole", "/organization/update-role", update_role),
    ]
}
