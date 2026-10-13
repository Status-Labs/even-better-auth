//! Teams (`routes/crud-team.ts`).

use http::StatusCode;
use serde_json::{Map, Value, json};

use super::adapter::{AddTeamMember, OrgAdapter};
use super::members::team_limit;
use super::{
    In, active_org, active_team, bad, body_object, coerce_string, e, forbidden, has_permission, permission, required,
    route, run_hook, session_json, str_field,
};
use crate::api::middleware::{get_session_from_ctx, require_session};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult};
use crate::cookies::set_session_cookie;
use crate::db::{InputAction, Record, parse_input};
use crate::error::ApiError;
use crate::types::SessionWithUser;
use crate::utils::date;

const CORE_FIELDS: &[&str] = &["name", "organizationId", "memberCount", "createdAt", "updatedAt"];

fn team_fields(ctx: &EndpointContext, body: &Map<String, Value>, action: InputAction) -> Result<Record, ApiError> {
    let table = ctx.auth.schema.table("team").expect("team table");
    parse_input(table, body, action, CORE_FIELDS)
}

async fn org_or_user_error(ctx: &EndpointContext, inner: &In, org_id: &str) -> Result<Map<String, Value>, ApiError> {
    OrgAdapter::new(ctx, inner).find_organization_by_id(org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))
}

async fn create_team(inner: In, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default()).await?;
    let body = body_object(&ctx)?;
    let org_id = coerce_string(body.get("organizationId"))
        .filter(|s| !s.is_empty())
        .or_else(|| session.as_ref().and_then(active_org));
    if session.is_none() && (ctx.is_request || !ctx.headers().is_empty()) {
        return Err(ApiError::status(StatusCode::UNAUTHORIZED));
    }
    let org_id = org_id.ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    if let Some(s) = &session {
        let member = adapter
            .find_member_by_org_id(&s.user.id, &org_id)
            .await?
            .ok_or_else(|| forbidden(e::YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION))?;
        if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("team", "create"), false)
            .await?
        {
            return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION));
        }
    }
    let existing = adapter.list_teams(&org_id).await?;
    if let Some(limit) = &inner.options.teams.maximum_teams {
        let session_value = session.as_ref().map(|s| session_json(&ctx, s)).unwrap_or(Value::Null);
        let max = limit.resolve(|| json!({ "organizationId": org_id, "session": session_value })).await?;
        if max > 0 && existing.len() >= max {
            return Err(bad(e::YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS));
        }
    }
    let name = required(&body, "name")?;
    let additional = team_fields(&ctx, &body, InputAction::Create)?;
    let organization = org_or_user_error(&ctx, &inner, &org_id).await?;
    let mut data = additional.clone();
    data.insert("name".into(), name.clone().into());
    data.insert("organizationId".into(), org_id.clone().into());
    data.insert("createdAt".into(), date::now_value());
    data.insert("updatedAt".into(), date::now_value());
    let user_json = session.as_ref().map(|s| Value::Object(ctx.auth.user_output(&s.user))).unwrap_or(Value::Null);
    let mut hook_team = additional;
    hook_team.insert("name".into(), name.into());
    hook_team.insert("organizationId".into(), org_id.into());
    let hooks = &inner.options.hooks;
    if let Some(extra) = run_hook(
        &hooks.before_create_team,
        json!({ "team": hook_team, "user": user_json, "organization": organization }),
    )
    .await?
    {
        data.extend(extra);
    }
    let team = adapter.create_team(data).await?;
    run_hook(&hooks.after_create_team, json!({ "team": team, "user": user_json, "organization": organization }))
        .await?;
    ctx.json(Value::Object(team))
}

async fn remove_team(inner: In, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default()).await?;
    let body = body_object(&ctx)?;
    let org_id = coerce_string(body.get("organizationId"))
        .filter(|s| !s.is_empty())
        .or_else(|| session.as_ref().and_then(active_org));
    let org_id = org_id.ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    if session.is_none() && (ctx.is_request || !ctx.headers().is_empty()) {
        return Err(ApiError::status(StatusCode::UNAUTHORIZED));
    }
    let team_id = required(&body, "teamId")?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    if let Some(s) = &session {
        let member = adapter.find_member_by_org_id(&s.user.id, &org_id).await?;
        let Some(member) = member.filter(|_| active_team(s).as_deref() != Some(team_id.as_str())) else {
            return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM));
        };
        if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("team", "delete"), false)
            .await?
        {
            return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION));
        }
    }
    let team = adapter
        .find_team_by_id(&team_id, Some(&org_id))
        .await?
        .filter(|t| str_field(t, "organizationId") == org_id)
        .ok_or_else(|| bad(e::TEAM_NOT_FOUND))?;
    if !inner.options.teams.allow_removing_all_teams && adapter.list_teams(&org_id).await?.len() <= 1 {
        return Err(bad(e::UNABLE_TO_REMOVE_LAST_TEAM));
    }
    let organization = org_or_user_error(&ctx, &inner, &org_id).await?;
    let user_json = session.as_ref().map(|s| Value::Object(ctx.auth.user_output(&s.user))).unwrap_or(Value::Null);
    let arg = json!({ "team": team, "user": user_json, "organization": organization });
    run_hook(&inner.options.hooks.before_delete_team, arg.clone()).await?;
    ctx.auth
        .transaction(async {
            adapter.delete_team(&team_id).await?;
            // Drop the team from pending invitations that referenced it.
            for invitation in adapter.find_pending_invitations(&org_id).await? {
                let ids = str_field(&invitation, "teamId");
                if ids.is_empty() || !ids.split(',').any(|id| id == team_id) {
                    continue;
                }
                let remaining: Vec<&str> = ids.split(',').filter(|id| *id != team_id).collect();
                let mut update = Record::new();
                update.insert(
                    "teamId".into(),
                    if remaining.is_empty() { Value::Null } else { remaining.join(",").into() },
                );
                adapter.update_invitation_fields(str_field(&invitation, "id"), update).await?;
            }
            Ok::<_, crate::error::Error>(())
        })
        .await?;
    run_hook(&inner.options.hooks.after_delete_team, arg).await?;
    ctx.json(json!({ "message": "Team removed successfully." }))
}

async fn update_team(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let input = body.get("data").and_then(Value::as_object).cloned().unwrap_or_default();
    let org_id = coerce_string(input.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(&session));
    let org_id = org_id.ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let member = adapter
        .find_member_by_org_id(&session.user.id, &org_id)
        .await?
        .ok_or_else(|| forbidden(e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM))?;
    if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("team", "update"), false).await? {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM));
    }
    let team_id = required(&body, "teamId")?;
    let team = adapter
        .find_team_by_id(&team_id, Some(&org_id))
        .await?
        .filter(|t| str_field(t, "organizationId") == org_id)
        .ok_or_else(|| bad(e::TEAM_NOT_FOUND))?;
    let mut updates = team_fields(&ctx, &input, InputAction::Update)?;
    if let Some(name) = input.get("name") {
        if name.as_str().is_none_or(str::is_empty) {
            return Err(bad(crate::error::codes::VALIDATION_ERROR));
        }
        updates.insert("name".into(), name.clone());
    }
    let organization = org_or_user_error(&ctx, &inner, &org_id).await?;
    let user_json = Value::Object(ctx.auth.user_output(&session.user));
    let hooks = &inner.options.hooks;
    let arg = json!({ "team": team, "updates": updates, "user": user_json, "organization": organization });
    if let Some(replacement) = run_hook(&hooks.before_update_team, arg).await? {
        updates = replacement;
    }
    let updated = adapter.update_team(str_field(&team, "id"), updates).await?;
    run_hook(&hooks.after_update_team, json!({ "team": updated, "user": user_json, "organization": organization }))
        .await?;
    ctx.json(updated.map(Value::Object).unwrap_or(Value::Null))
}

async fn list_teams(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let org_id = ctx.query_str("organizationId").filter(|s| !s.is_empty()).or_else(|| active_org(&session));
    let org_id = org_id.ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    if adapter.find_member_by_org_id(&session.user.id, &org_id).await?.is_none() {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION));
    }
    let teams = adapter.list_teams(&org_id).await?;
    ctx.json(Value::Array(teams.into_iter().map(Value::Object).collect()))
}

async fn set_active_team(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let set_cookie = |updated: Option<crate::types::Session>| {
        let ctx = ctx.clone();
        let user = session.user.clone();
        async move {
            if let Some(updated) = updated {
                set_session_cookie(&ctx, &SessionWithUser { session: updated, user }, None, None).await;
            }
        }
    };
    if body.get("teamId") == Some(&Value::Null) {
        if active_team(&session).is_none() {
            return ctx.json(Value::Null);
        }
        let updated = adapter.set_active_team(&session.session.token, None).await?;
        set_cookie(updated).await;
        return ctx.json(Value::Null);
    }
    let team_id = match body.get("teamId").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(id) => id.to_owned(),
        None => match active_team(&session) {
            Some(id) => id,
            None => return ctx.json(Value::Null),
        },
    };
    let org_id = active_org(&session).ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let team = adapter.find_team_by_id(&team_id, Some(&org_id)).await?.ok_or_else(|| bad(e::TEAM_NOT_FOUND))?;
    if adapter.find_team_member(&team_id, &session.user.id).await?.is_none() {
        return Err(forbidden(e::USER_IS_NOT_A_MEMBER_OF_THE_TEAM));
    }
    let updated = adapter.set_active_team(&session.session.token, Some(str_field(&team, "id"))).await?;
    set_cookie(updated).await;
    ctx.json(Value::Object(team))
}

async fn list_user_teams(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let target = ctx.query_str("userId").filter(|s| !s.is_empty()).unwrap_or_else(|| session.user.id.clone());
    let explicit_org = ctx.query_str("organizationId").filter(|s| !s.is_empty());
    let org_id = explicit_org.clone().or_else(|| active_org(&session));
    let in_org = |teams: Vec<Map<String, Value>>, org: &str| -> Value {
        Value::Array(teams.into_iter().filter(|t| str_field(t, "organizationId") == org).map(Value::Object).collect())
    };
    if target != session.user.id {
        let org_id = org_id.ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
        let requester = adapter
            .find_member_by_org_id(&session.user.id, &org_id)
            .await?
            .ok_or_else(|| forbidden(e::YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION))?;
        if !has_permission(&ctx, &inner, &org_id, str_field(&requester, "role"), &permission("member", "update"), false)
            .await?
        {
            return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER));
        }
        if adapter.find_member_by_org_id(&target, &org_id).await?.is_none() {
            return Err(bad(e::USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION));
        }
        return ctx.json(in_org(adapter.list_teams_by_user(&target).await?, &org_id));
    }
    if let Some(org_id) = explicit_org {
        if adapter.find_member_by_org_id(&session.user.id, &org_id).await?.is_none() {
            return Err(forbidden(e::YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION));
        }
        return ctx.json(in_org(adapter.list_teams_by_user(&session.user.id).await?, &org_id));
    }
    let teams = adapter.list_teams_by_user(&session.user.id).await?;
    let mut out = vec![];
    for team in teams {
        if adapter.check_membership(&session.user.id, str_field(&team, "organizationId")).await?.is_some() {
            out.push(Value::Object(team));
        }
    }
    ctx.json(Value::Array(out))
}

async fn list_team_members(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let team_id = ctx.query_str("teamId").filter(|s| !s.is_empty()).or_else(|| active_team(&session));
    let team_id = team_id.ok_or_else(|| bad(e::YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM))?;
    let team = adapter.find_team_by_id(&team_id, None).await?.ok_or_else(|| bad(e::TEAM_NOT_FOUND))?;
    if adapter.check_membership(&session.user.id, str_field(&team, "organizationId")).await?.is_none() {
        return Err(bad(e::USER_IS_NOT_A_MEMBER_OF_THE_TEAM));
    }
    if adapter.find_team_member(&team_id, &session.user.id).await?.is_none() {
        return Err(bad(e::USER_IS_NOT_A_MEMBER_OF_THE_TEAM));
    }
    let members = adapter.list_team_members(&team_id).await?;
    ctx.json(Value::Array(members.into_iter().map(Value::Object).collect()))
}

/// Common checks for adding/removing team members: returns the org id, team, organization
/// and the affected user.
async fn team_member_context(
    ctx: &EndpointContext,
    inner: &In,
    session: &SessionWithUser,
    action: &str,
    denied: crate::error::ErrorCode,
) -> Result<(String, Map<String, Value>, Map<String, Value>, crate::types::User, String), ApiError> {
    let body = body_object(ctx)?;
    let org_id = coerce_string(body.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(session));
    let org_id = org_id.ok_or_else(|| bad(e::NO_ACTIVE_ORGANIZATION))?;
    let adapter = OrgAdapter::new(ctx, inner);
    let current = adapter
        .find_member_by_org_id(&session.user.id, &org_id)
        .await?
        .ok_or_else(|| bad(e::USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION))?;
    if !has_permission(ctx, inner, &org_id, str_field(&current, "role"), &permission("member", action), false).await? {
        return Err(forbidden(denied));
    }
    let user_id = required(&body, "userId")?;
    if adapter.find_member_by_org_id(&user_id, &org_id).await?.is_none() {
        return Err(bad(e::USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION));
    }
    let team_id = required(&body, "teamId")?;
    let team = adapter.find_team_by_id(&team_id, Some(&org_id)).await?.ok_or_else(|| bad(e::TEAM_NOT_FOUND))?;
    let organization = org_or_user_error(ctx, inner, &org_id).await?;
    let user = ctx
        .auth
        .internal_adapter
        .find_user_by_id(&user_id)
        .await?
        .ok_or_else(|| ApiError::message(StatusCode::BAD_REQUEST, "User not found"))?;
    Ok((org_id, team, organization, user, team_id))
}

async fn add_team_member(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let (org_id, team, organization, user, team_id) =
        team_member_context(&ctx, &inner, &session, "update", e::YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER)
            .await?;
    let user_json = Value::Object(ctx.auth.user_output(&user));
    let hooks = &inner.options.hooks;
    let arg = json!({ "teamMember": { "teamId": team_id, "userId": user.id }, "team": team, "user": user_json, "organization": organization });
    run_hook(&hooks.before_add_team_member, arg).await?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let team_member = match &inner.options.teams.maximum_members_per_team {
        Some(limit) => {
            let max = team_limit(limit, &team_id, &org_id, session_json(&ctx, &session)).await?;
            match adapter.add_team_member_with_limit(&team_id, &user.id, max).await? {
                AddTeamMember::Added(m) => m,
                AddTeamMember::LimitReached => return Err(forbidden(e::TEAM_MEMBER_LIMIT_REACHED)),
            }
        }
        None => adapter.find_or_create_team_member(&team_id, &user.id).await?,
    };
    let arg = json!({ "teamMember": team_member, "team": team, "user": user_json, "organization": organization });
    run_hook(&hooks.after_add_team_member, arg).await?;
    ctx.json(Value::Object(team_member))
}

async fn remove_team_member(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let (_, team, organization, user, team_id) =
        team_member_context(&ctx, &inner, &session, "delete", e::YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER).await?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let team_member =
        adapter.find_team_member(&team_id, &user.id).await?.ok_or_else(|| bad(e::USER_IS_NOT_A_MEMBER_OF_THE_TEAM))?;
    let arg = json!({ "teamMember": team_member, "team": team, "user": ctx.auth.user_output(&user), "organization": organization });
    let hooks = &inner.options.hooks;
    run_hook(&hooks.before_remove_team_member, arg.clone()).await?;
    adapter.remove_team_member(&team_id, &user.id).await?;
    run_hook(&hooks.after_remove_team_member, arg).await?;
    ctx.json(json!({ "message": "Team member removed successfully." }))
}

pub(super) fn endpoints(i: &In) -> Vec<Endpoint> {
    vec![
        route!(i, post, "createTeam", "/organization/create-team", create_team),
        route!(i, post, "removeTeam", "/organization/remove-team", remove_team),
        route!(i, post, "updateTeam", "/organization/update-team", update_team),
        route!(i, get, "listOrganizationTeams", "/organization/list-teams", list_teams),
        route!(i, post, "setActiveTeam", "/organization/set-active-team", set_active_team),
        route!(i, get, "listUserTeams", "/organization/list-user-teams", list_user_teams),
        route!(i, get, "listTeamMembers", "/organization/list-team-members", list_team_members),
        route!(i, post, "addTeamMember", "/organization/add-team-member", add_team_member),
        route!(i, post, "removeTeamMember", "/organization/remove-team-member", remove_team_member),
    ]
}
