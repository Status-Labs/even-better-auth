//! Members (`routes/crud-members.ts`).

use http::StatusCode;
use serde_json::{Map, Value, json};

use super::adapter::{AddTeamMember, OrgAdapter};
use super::{
    In, Limit, active_org, bad, body_object, coerce_string, e, forbidden, has_permission, parse_roles, permission,
    required, route, run_hook, split_roles, str_field,
};
use crate::api::middleware::{get_session_from_ctx, require_session};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult};
use crate::db::{InputAction, Operator, Record, Where, parse_input};
use crate::error::{ApiError, codes};
use crate::types::User;

const CORE_FIELDS: &[&str] = &["organizationId", "userId", "role", "createdAt"];

/// Resolve the membership limit for adding `user` to `organization`.
pub(super) async fn membership_limit(
    inner: &In,
    ctx: &EndpointContext,
    user: &User,
    organization: &Map<String, Value>,
) -> Result<usize, ApiError> {
    let limit = inner
        .options
        .membership_limit
        .resolve(|| json!({ "user": ctx.auth.user_output(user), "organization": organization }))
        .await?;
    Ok(if limit == 0 { 100 } else { limit })
}

/// Validate roles against static roles and, with dynamic access control, the org's roles.
pub(super) async fn check_roles_exist(
    ctx: &EndpointContext,
    inner: &In,
    organization_id: &str,
    roles: &[String],
    with_code: bool,
) -> Result<(), ApiError> {
    let unknown: Vec<&String> = roles.iter().filter(|r| !inner.roles.contains_key(*r)).collect();
    if unknown.is_empty() {
        return Ok(());
    }
    let mut still_invalid: Vec<String> = unknown.iter().map(|r| (*r).clone()).collect();
    if inner.options.dynamic_access_control.enabled {
        let found = ctx
            .auth
            .db
            .find_many(
                "organizationRole",
                crate::db::FindManyQuery {
                    where_: vec![
                        Where::eq("organizationId", organization_id),
                        Where::is_in("role", still_invalid.iter().map(|r| Value::String(r.clone())).collect()),
                    ],
                    ..Default::default()
                },
            )
            .await?;
        still_invalid.retain(|r| !found.iter().any(|f| str_field(f, "role") == r));
    }
    if still_invalid.is_empty() {
        return Ok(());
    }
    let message = format!("ROLE_NOT_FOUND: {}", still_invalid.join(", "));
    Err(if with_code {
        ApiError::new(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND", message)
    } else {
        ApiError::message(StatusCode::BAD_REQUEST, message)
    })
}

/// Resolve a team-size limit.
pub(super) async fn team_limit(
    limit: &Limit,
    team_id: &str,
    organization_id: &str,
    session: Value,
) -> Result<usize, ApiError> {
    Ok(limit.resolve(|| json!({ "teamId": team_id, "session": session, "organizationId": organization_id })).await?)
}

async fn add_member(inner: In, ctx: Ctx) -> EndpointResult {
    let body = body_object(&ctx)?;
    let session = if body.contains_key("userId") {
        get_session_from_ctx(&ctx, Default::default()).await.ok().flatten()
    } else {
        None
    };
    let org_id = coerce_string(body.get("organizationId"))
        .filter(|s| !s.is_empty())
        .or_else(|| session.as_ref().and_then(active_org));
    let Some(org_id) = org_id else { return Err(bad(e::NO_ACTIVE_ORGANIZATION)) };
    let team_id = body.get("teamId").and_then(Value::as_str).map(str::to_owned);
    if team_id.is_some() && !inner.options.teams.enabled {
        tracing::error!("Teams are not enabled");
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "Teams are not enabled"));
    }
    let user_id = required(&body, "userId")?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let auth = ctx.auth.clone();
    let user = auth.internal_adapter.find_user_by_id(&user_id).await?.ok_or_else(|| bad(codes::USER_NOT_FOUND))?;
    if adapter.find_member_by_email(&user.email, &org_id).await?.is_some() {
        return Err(bad(e::USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION));
    }
    if let Some(team_id) = &team_id {
        let team = adapter.find_team_by_id(team_id, Some(&org_id)).await?;
        if team.is_none_or(|t| str_field(&t, "organizationId") != org_id) {
            return Err(bad(e::TEAM_NOT_FOUND));
        }
    }
    let count = adapter.count_members(&org_id).await?;
    let organization = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    if count as usize >= membership_limit(&inner, &ctx, &user, &organization).await? {
        return Err(forbidden(e::ORGANIZATION_MEMBERSHIP_LIMIT_REACHED));
    }
    let table = auth.schema.table("member").expect("member table");
    let mut extra = body.clone();
    extra.remove("teamId");
    let additional = parse_input(table, &extra, InputAction::Create, CORE_FIELDS)?;
    let role = parse_roles(body.get("role").unwrap_or(&Value::Null));
    let mut data = Record::new();
    data.insert("organizationId".into(), org_id.clone().into());
    data.insert("userId".into(), user.id.clone().into());
    data.insert("role".into(), role.clone().into());
    data.extend(additional.clone());
    let user_json = Value::Object(auth.user_output(&user));
    let mut hook_member = additional;
    hook_member.insert("userId".into(), user.id.clone().into());
    hook_member.insert("organizationId".into(), org_id.clone().into());
    hook_member.insert("role".into(), role.into());
    let hooks = &inner.options.hooks;
    if let Some(extra) = run_hook(
        &hooks.before_add_member,
        json!({ "member": hook_member, "user": user_json, "organization": organization }),
    )
    .await?
    {
        data.extend(extra);
    }
    let created = adapter.create_member(data).await?;
    if let Some(team_id) = &team_id {
        let result: Result<(), ApiError> = async {
            match &inner.options.teams.maximum_members_per_team {
                Some(limit) => {
                    if matches!(limit, Limit::Dynamic(_)) && session.is_none() {
                        return Err(ApiError::status(StatusCode::UNAUTHORIZED));
                    }
                    let session_json = session.as_ref().map(|s| super::session_json(&ctx, s)).unwrap_or(Value::Null);
                    let max = team_limit(limit, team_id, &org_id, session_json).await?;
                    if let AddTeamMember::LimitReached =
                        adapter.add_team_member_with_limit(team_id, &user.id, max).await?
                    {
                        return Err(forbidden(e::TEAM_MEMBER_LIMIT_REACHED));
                    }
                }
                None => {
                    adapter.find_or_create_team_member(team_id, &user.id).await?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(err) = result {
            adapter.delete_member(str_field(&created, "id"), &org_id, &user.id).await?;
            return Err(err);
        }
    }
    run_hook(&hooks.after_add_member, json!({ "member": created, "user": user_json, "organization": organization }))
        .await?;
    ctx.json(Value::Object(created))
}

fn without_user(mut member: Map<String, Value>) -> Map<String, Value> {
    member.remove("user");
    member
}

fn owner_count(members: &[Map<String, Value>], creator_role: &str) -> usize {
    members.iter().filter(|m| split_roles(str_field(m, "role")).iter().any(|r| r == creator_role)).count()
}

async fn remove_member(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let org_id = coerce_string(body.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(&session));
    let Some(org_id) = org_id else { return Err(bad(e::NO_ACTIVE_ORGANIZATION)) };
    let adapter = OrgAdapter::new(&ctx, &inner);
    let member =
        adapter.find_member_by_org_id(&session.user.id, &org_id).await?.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    let target_key = required(&body, "memberIdOrEmail")?;
    let target = if target_key.contains('@') {
        adapter.find_member_by_email(&target_key, &org_id).await?
    } else {
        adapter.find_member_by_id(&target_key).await?.map(without_user)
    };
    let target = target.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    let creator = &inner.options.creator_role;
    if split_roles(str_field(&target, "role")).iter().any(|r| r == creator) {
        if !split_roles(str_field(&member, "role")).iter().any(|r| r == creator) {
            return Err(bad(e::YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER));
        }
        if owner_count(&adapter.all_members(&org_id).await?, creator) <= 1 {
            return Err(bad(e::YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER));
        }
    }
    if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("member", "delete"), false)
        .await?
    {
        return Err(ApiError::unauthorized(e::YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER));
    }
    if str_field(&target, "organizationId") != org_id {
        return Err(bad(e::MEMBER_NOT_FOUND));
    }
    let organization = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    let target_user_id = str_field(&target, "userId").to_owned();
    let user = ctx
        .auth
        .internal_adapter
        .find_user_by_id(&target_user_id)
        .await?
        .ok_or_else(|| ApiError::message(StatusCode::BAD_REQUEST, "User not found"))?;
    let arg = json!({ "member": target, "user": ctx.auth.user_output(&user), "organization": organization });
    run_hook(&inner.options.hooks.before_remove_member, arg.clone()).await?;
    adapter.delete_member(str_field(&target, "id"), &org_id, &target_user_id).await?;
    if session.user.id == target_user_id
        && active_org(&session).as_deref() == Some(str_field(&target, "organizationId"))
    {
        adapter.set_active_organization(&session.session.token, None).await?;
    }
    run_hook(&inner.options.hooks.after_remove_member, arg).await?;
    ctx.json(json!({ "member": target }))
}

async fn update_member_role(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let role_value = body.get("role").cloned().unwrap_or(Value::Null);
    if role_value.is_null() || role_value == Value::String(String::new()) {
        return Err(ApiError::status(StatusCode::BAD_REQUEST));
    }
    let org_id = coerce_string(body.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(&session));
    let Some(org_id) = org_id else { return Err(bad(e::NO_ACTIVE_ORGANIZATION)) };
    let roles_to_set: Vec<String> = match &role_value {
        Value::Array(list) => list.iter().filter_map(Value::as_str).flat_map(split_roles).collect(),
        Value::String(s) => split_roles(s),
        _ => vec![],
    };
    if roles_to_set.is_empty() {
        return Err(ApiError::status(StatusCode::BAD_REQUEST));
    }
    let member_id = required(&body, "memberId")?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let member =
        adapter.find_member_by_org_id(&session.user.id, &org_id).await?.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    let target = if str_field(&member, "id") != member_id {
        adapter.find_member_by_id(&member_id).await?.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?
    } else {
        member.clone()
    };
    if str_field(&target, "organizationId") != org_id {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER));
    }
    let creator = &inner.options.creator_role;
    let updater_is_creator = split_roles(str_field(&member, "role")).contains(creator);
    let updating_creator = split_roles(str_field(&target, "role")).contains(creator);
    let setting_creator = roles_to_set.contains(creator);
    if (updating_creator || setting_creator) && !updater_is_creator {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER));
    }
    if updater_is_creator && str_field(&member, "id") == str_field(&target, "id") && !setting_creator {
        let owners = owner_count(&adapter.all_members(&org_id).await?, creator);
        if owners <= 1 {
            return Err(bad(e::YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER));
        }
    }
    if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("member", "update"), true).await?
    {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER));
    }
    check_roles_exist(&ctx, &inner, &org_id, &roles_to_set, true).await?;
    let organization = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    let target_user = ctx
        .auth
        .internal_adapter
        .find_user_by_id(str_field(&target, "userId"))
        .await?
        .ok_or_else(|| ApiError::message(StatusCode::BAD_REQUEST, "User not found"))?;
    let previous_role = str_field(&target, "role").to_owned();
    let mut new_role = roles_to_set.join(",");
    let user_json = ctx.auth.user_output(&target_user);
    let hooks = &inner.options.hooks;
    let arg = json!({ "member": target, "newRole": new_role, "user": user_json, "organization": organization });
    if let Some(extra) = run_hook(&hooks.before_update_member_role, arg).await?
        && let Some(role) = extra.get("role").and_then(Value::as_str)
    {
        new_role = role.to_owned();
    }
    let updated = adapter.update_member(&member_id, &new_role).await?.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    let arg =
        json!({ "member": updated, "previousRole": previous_role, "user": user_json, "organization": organization });
    run_hook(&hooks.after_update_member_role, arg).await?;
    ctx.json(Value::Object(updated))
}

async fn get_active_member(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let org_id = active_org(&session).ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let member = OrgAdapter::new(&ctx, &inner)
        .find_member_by_org_id(&session.user.id, &org_id)
        .await?
        .ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    ctx.json(Value::Object(member))
}

async fn leave_organization(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let org_id = required(&body_object(&ctx)?, "organizationId")?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let member =
        adapter.find_member_by_org_id(&session.user.id, &org_id).await?.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    let creator = &inner.options.creator_role;
    if split_roles(str_field(&member, "role")).contains(creator)
        && owner_count(&adapter.all_members(&org_id).await?, creator) <= 1
    {
        return Err(bad(e::YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER));
    }
    adapter.delete_member(str_field(&member, "id"), &org_id, &session.user.id).await?;
    if active_org(&session).as_deref() == Some(org_id.as_str()) {
        adapter.set_active_organization(&session.session.token, None).await?;
    }
    ctx.json(Value::Object(member))
}

/// The organization addressed by `organizationSlug`/`organizationId` query parameters or the
/// session, which the caller must belong to.
async fn queried_member_org(
    ctx: &EndpointContext,
    inner: &In,
    session: &crate::types::SessionWithUser,
) -> Result<(String, Map<String, Value>), ApiError> {
    let adapter = OrgAdapter::new(ctx, inner);
    let mut org_id = ctx.query_str("organizationId").filter(|s| !s.is_empty()).or_else(|| active_org(session));
    if let Some(slug) = ctx.query_str("organizationSlug").filter(|s| !s.is_empty()) {
        let org = adapter.find_organization_by_slug(&slug).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
        org_id = Some(str_field(&org, "id").to_owned());
    }
    let org_id = org_id.ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let member = adapter
        .find_member_by_org_id(&session.user.id, &org_id)
        .await?
        .ok_or_else(|| forbidden(e::YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION))?;
    Ok((org_id, member))
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

async fn list_members(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let (org_id, _) = queried_member_org(&ctx, &inner, &session).await?;
    let query = ctx.query();
    let number = |k: &str| match query.get(k) {
        Some(Value::Number(n)) => n.as_u64().map(|n| n as usize),
        Some(Value::String(s)) => s.parse::<usize>().ok(),
        _ => None,
    };
    let filter = match query.get("filterField").and_then(Value::as_str) {
        Some(field) => {
            let op = match query.get("filterOperator").and_then(Value::as_str) {
                Some(op) => parse_operator(op).ok_or_else(|| bad(codes::VALIDATION_ERROR))?,
                None => Operator::Eq,
            };
            Some(Where::new(field, op, query.get("filterValue").cloned().unwrap_or(Value::Null)))
        }
        None => None,
    };
    let sort = OrgAdapter::sort(ctx.query_str("sortBy"), ctx.query_str("sortDirection").as_deref());
    let (members, total) =
        OrgAdapter::new(&ctx, &inner).list_members(&org_id, number("limit"), number("offset"), sort, filter).await?;
    ctx.json(json!({ "members": members, "total": total }))
}

async fn get_active_member_role(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let (org_id, member) = queried_member_org(&ctx, &inner, &session).await?;
    let Some(user_id) = ctx.query_str("userId").filter(|s| !s.is_empty()) else {
        return ctx.json(json!({ "role": member["role"] }));
    };
    let other = OrgAdapter::new(&ctx, &inner)
        .find_member_by_org_id(&user_id, &org_id)
        .await?
        .ok_or_else(|| forbidden(e::YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION))?;
    ctx.json(json!({ "role": other["role"] }))
}

pub(super) fn endpoints(i: &In) -> Vec<Endpoint> {
    vec![
        route!(i, post, "addMember", "/organization/add-member", add_member).server_only(),
        route!(i, post, "removeMember", "/organization/remove-member", remove_member),
        route!(i, post, "updateMemberRole", "/organization/update-member-role", update_member_role),
        route!(i, get, "getActiveMember", "/organization/get-active-member", get_active_member),
        route!(i, post, "leaveOrganization", "/organization/leave", leave_organization),
        route!(i, get, "listMembers", "/organization/list-members", list_members),
        route!(i, get, "getActiveMemberRole", "/organization/get-active-member-role", get_active_member_role),
    ]
}
