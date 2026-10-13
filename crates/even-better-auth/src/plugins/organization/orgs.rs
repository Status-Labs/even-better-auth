//! Organization CRUD (`routes/crud-org.ts`).

use http::StatusCode;
use serde_json::{Map, Value, json};

use super::adapter::OrgAdapter;
use super::{
    In, OrganizationLimit, active_org, bad, body_object, coerce_string, e, forbidden, has_permission, permission,
    required, route, run_hook, str_field,
};
use crate::api::middleware::{get_session_from_ctx, request_only_session, require_session};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult};
use crate::cookies::set_session_cookie;
use crate::db::{InputAction, Record, parse_input};
use crate::error::ApiError;
use crate::types::{SessionWithUser, User};
use crate::utils::date;

const CORE_FIELDS: &[&str] = &["name", "slug", "logo", "createdAt", "metadata"];

fn unauthorized() -> ApiError {
    ApiError::status(StatusCode::UNAUTHORIZED)
}

/// Validate and collect organization fields from a request body.
fn organization_fields(
    ctx: &EndpointContext,
    body: &Map<String, Value>,
    action: InputAction,
) -> Result<Record, ApiError> {
    let table = ctx.auth.schema.table("organization").expect("organization table");
    let mut data = parse_input(table, body, action, CORE_FIELDS)?;
    for key in ["name", "slug"] {
        match body.get(key) {
            Some(Value::String(s)) if !s.is_empty() => {
                data.insert(key.into(), s.clone().into());
            }
            None if action == InputAction::Update => {}
            _ => {
                return Err(ApiError::bad_request(crate::error::codes::VALIDATION_ERROR)
                    .with_field("message", format!("{key} must be a non-empty string")));
            }
        }
    }
    if let Some(logo) = body.get("logo") {
        data.insert("logo".into(), logo.clone());
    }
    match body.get("metadata") {
        Some(Value::Object(m)) => {
            data.insert("metadata".into(), Value::Object(m.clone()));
        }
        Some(Value::Null) | None => {}
        Some(_) => return Err(ApiError::bad_request(crate::error::codes::VALIDATION_ERROR)),
    }
    Ok(data)
}

async fn create_organization(inner: In, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default()).await?;
    if session.is_none() && (ctx.is_request || !ctx.headers().is_empty()) {
        return Err(unauthorized());
    }
    let body = body_object(&ctx)?;
    let auth = ctx.auth.clone();
    let user: User = match &session {
        Some(s) => s.user.clone(),
        None => {
            let id = coerce_string(body.get("userId")).ok_or_else(unauthorized)?;
            auth.internal_adapter.find_user_by_id(&id).await?.ok_or_else(unauthorized)?
        }
    };
    let opts = &inner.options;
    let user_json = Value::Object(auth.user_output(&user));
    let can_create = match &opts.allow_user_to_create_organization {
        Some(f) => f(user_json.clone()).await?,
        None => true,
    };
    let system_action = session.is_none() && body.contains_key("userId");
    if !can_create && !system_action {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION));
    }
    let adapter = OrgAdapter::new(&ctx, &inner);
    let reached = match &opts.organization_limit {
        Some(OrganizationLimit::Count(n)) => adapter.list_organizations(&user.id).await?.len() >= *n,
        Some(OrganizationLimit::Reached(f)) => f(user_json.clone()).await?,
        None => false,
    };
    if reached {
        return Err(forbidden(e::YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS));
    }
    let mut data = organization_fields(&ctx, &body, InputAction::Create)?;
    if adapter.find_organization_by_slug(str_field(&data, "slug")).await?.is_some() {
        return Err(bad(e::ORGANIZATION_ALREADY_EXISTS));
    }
    let hook_arg = json!({ "organization": data, "user": user_json });
    if let Some(extra) = run_hook(&opts.hooks.before_create_organization, hook_arg).await? {
        data.extend(extra);
    }
    data.insert("createdAt".into(), date::now_value());
    let organization = adapter.create_organization(data).await?;
    let org_id = str_field(&organization, "id").to_owned();
    let mut member_data = Record::new();
    member_data.insert("userId".into(), user.id.clone().into());
    member_data.insert("organizationId".into(), org_id.clone().into());
    member_data.insert("role".into(), opts.creator_role.clone().into());
    let arg = json!({ "member": member_data, "user": user_json, "organization": organization });
    if let Some(extra) = run_hook(&opts.hooks.before_add_member, arg).await? {
        member_data.extend(extra);
    }
    let member = adapter.create_member(member_data).await?;
    run_hook(
        &opts.hooks.after_add_member,
        json!({ "member": member, "user": user_json, "organization": organization }),
    )
    .await?;

    let mut team_member = None;
    if opts.teams.enabled && !opts.teams.default_team.disabled {
        let mut team_data = Record::new();
        team_data.insert("organizationId".into(), org_id.clone().into());
        team_data.insert("name".into(), organization.get("name").cloned().unwrap_or_default());
        team_data.insert("createdAt".into(), date::now_value());
        let arg = json!({ "team": { "organizationId": org_id, "name": organization["name"] }, "user": user_json, "organization": organization });
        if let Some(extra) = run_hook(&opts.hooks.before_create_team, arg).await? {
            team_data.extend(extra);
        }
        let team = match &opts.teams.default_team.custom_create {
            Some(create) => create(Value::Object(organization.clone())).await?,
            None => adapter.create_team(team_data).await?,
        };
        team_member = Some(adapter.find_or_create_team_member(str_field(&team, "id"), &user.id).await?);
        run_hook(
            &opts.hooks.after_create_team,
            json!({ "team": team, "user": user_json, "organization": organization }),
        )
        .await?;
    }
    run_hook(
        &opts.hooks.after_create_organization,
        json!({ "organization": organization, "user": user_json, "member": member }),
    )
    .await?;
    let keep_active = body.get("keepCurrentActiveOrganization").and_then(Value::as_bool) == Some(true);
    if let Some(s) = &session
        && !keep_active
    {
        adapter.set_active_organization(&s.session.token, Some(&org_id)).await?;
        if let Some(tm) = &team_member {
            adapter.set_active_team(&s.session.token, Some(str_field(tm, "teamId"))).await?;
        }
    }
    let mut out = organization;
    out.insert("members".into(), json!([member]));
    ctx.json(Value::Object(out))
}

async fn check_slug(inner: In, ctx: Ctx) -> EndpointResult {
    request_only_session(&ctx).await?;
    let slug = required(&body_object(&ctx)?, "slug")?;
    if OrgAdapter::new(&ctx, &inner).find_organization_by_slug(&slug).await?.is_none() {
        return ctx.json(json!({ "status": true }));
    }
    Err(bad(e::ORGANIZATION_SLUG_ALREADY_TAKEN))
}

/// The caller's membership in `organization_id`, or `error`.
async fn membership(
    ctx: &EndpointContext,
    inner: &In,
    user_id: &str,
    organization_id: &str,
    error: ApiError,
) -> Result<Map<String, Value>, ApiError> {
    OrgAdapter::new(ctx, inner).find_member_by_org_id(user_id, organization_id).await?.ok_or(error)
}

async fn update_organization(inner: In, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default())
        .await?
        .ok_or_else(|| ApiError::message(StatusCode::UNAUTHORIZED, "User not found"))?;
    let body = body_object(&ctx)?;
    let org_id = coerce_string(body.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(&session));
    let Some(org_id) = org_id else { return Err(bad(e::ORGANIZATION_NOT_FOUND)) };
    let member =
        membership(&ctx, &inner, &session.user.id, &org_id, bad(e::USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION)).await?;
    let role = str_field(&member, "role");
    if !has_permission(&ctx, &inner, &org_id, role, &permission("organization", "update"), false).await? {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION));
    }
    let input = body.get("data").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut data = organization_fields(&ctx, &input, InputAction::Update)?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    if let Some(slug) = data.get("slug").and_then(Value::as_str)
        && adapter.find_organization_by_slug(slug).await?.is_some_and(|o| str_field(&o, "id") != org_id)
    {
        return Err(bad(e::ORGANIZATION_SLUG_ALREADY_TAKEN));
    }
    let user_json = Value::Object(ctx.auth.user_output(&session.user));
    let hooks = &inner.options.hooks;
    if let Some(extra) = run_hook(
        &hooks.before_update_organization,
        json!({ "organization": data, "user": user_json, "member": member }),
    )
    .await?
    {
        data.extend(extra);
    }
    let updated = adapter.update_organization(&org_id, data).await?;
    run_hook(&hooks.after_update_organization, json!({ "organization": updated, "user": user_json, "member": member }))
        .await?;
    ctx.json(updated.map(Value::Object).unwrap_or(Value::Null))
}

async fn delete_organization(inner: In, ctx: Ctx) -> EndpointResult {
    if inner.options.disable_organization_deletion {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "ORGANIZATION_DELETION_DISABLED",
            "Organization deletion is disabled",
        ));
    }
    let session = get_session_from_ctx(&ctx, Default::default()).await?.ok_or_else(unauthorized)?;
    let org_id = required(&body_object(&ctx)?, "organizationId")?;
    let member =
        membership(&ctx, &inner, &session.user.id, &org_id, bad(e::USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION)).await?;
    if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("organization", "delete"), false)
        .await?
    {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION));
    }
    let adapter = OrgAdapter::new(&ctx, &inner);
    if active_org(&session).as_deref() == Some(org_id.as_str()) {
        adapter.set_active_organization(&session.session.token, None).await?;
    }
    let org =
        adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| ApiError::status(StatusCode::BAD_REQUEST))?;
    let arg = json!({ "organization": org, "user": ctx.auth.user_output(&session.user) });
    run_hook(&inner.options.hooks.before_delete_organization, arg.clone()).await?;
    adapter.delete_organization(&org_id).await?;
    run_hook(&inner.options.hooks.after_delete_organization, arg).await?;
    ctx.json(Value::Object(org))
}

/// The organization id or slug requested in the query, falling back to the active one.
fn requested_org(ctx: &EndpointContext, session: &SessionWithUser) -> Option<(String, bool)> {
    if let Some(slug) = ctx.query_str("organizationSlug").filter(|s| !s.is_empty()) {
        return Some((slug, true));
    }
    ctx.query_str("organizationId").filter(|s| !s.is_empty()).or_else(|| active_org(session)).map(|id| (id, false))
}

async fn reject_non_member(
    ctx: &EndpointContext,
    inner: &In,
    session: &SessionWithUser,
    org_id: &str,
) -> Result<(), ApiError> {
    let adapter = OrgAdapter::new(ctx, inner);
    if adapter.check_membership(&session.user.id, org_id).await?.is_none() {
        adapter.set_active_organization(&session.session.token, None).await?;
        return Err(forbidden(e::USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION));
    }
    Ok(())
}

async fn get_organization(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let Some((id, is_slug)) = requested_org(&ctx, &session) else { return ctx.json(Value::Null) };
    let adapter = OrgAdapter::new(&ctx, &inner);
    let org = if is_slug {
        adapter.find_organization_by_slug(&id).await?
    } else {
        adapter.find_organization_by_id(&id).await?
    };
    let org = org.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    reject_non_member(&ctx, &inner, &session, str_field(&org, "id")).await?;
    ctx.json(Value::Object(org))
}

async fn get_full_organization(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let Some((id, is_slug)) = requested_org(&ctx, &session) else { return ctx.json(Value::Null) };
    let members_limit = ctx.query().get("membersLimit").and_then(|v| match v {
        Value::Number(n) => n.as_u64().map(|n| n as usize),
        Value::String(s) => s.parse().ok(),
        _ => None,
    });
    let adapter = OrgAdapter::new(&ctx, &inner);
    let org = adapter
        .find_full_organization(&id, is_slug, inner.options.teams.enabled, members_limit)
        .await?
        .ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    reject_non_member(&ctx, &inner, &session, str_field(&org, "id")).await?;
    ctx.json(Value::Object(org))
}

async fn set_active_organization(inner: In, ctx: Ctx) -> EndpointResult {
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
    if body.get("organizationId") == Some(&Value::Null) {
        if active_org(&session).is_none() {
            return ctx.json(Value::Null);
        }
        let updated = adapter.set_active_organization(&session.session.token, None).await?;
        set_cookie(updated).await;
        return ctx.json(Value::Null);
    }
    let mut org_id = coerce_string(body.get("organizationId")).filter(|s| !s.is_empty());
    let slug = body.get("organizationSlug").and_then(Value::as_str).filter(|s| !s.is_empty());
    if org_id.is_none() && slug.is_none() {
        let Some(active) = active_org(&session) else { return ctx.json(Value::Null) };
        org_id = Some(active);
    }
    if org_id.is_none()
        && let Some(slug) = slug
    {
        let org = adapter.find_organization_by_slug(slug).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
        org_id = Some(str_field(&org, "id").to_owned());
    }
    let org_id = org_id.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    reject_non_member(&ctx, &inner, &session, &org_id).await?;
    let org = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    let updated = adapter.set_active_organization(&session.session.token, Some(&org_id)).await?;
    set_cookie(updated).await;
    ctx.json(Value::Object(org))
}

async fn list_organizations(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let orgs = OrgAdapter::new(&ctx, &inner).list_organizations(&session.user.id).await?;
    ctx.json(Value::Array(orgs.into_iter().map(Value::Object).collect()))
}

pub(super) fn endpoints(i: &In) -> Vec<Endpoint> {
    vec![
        route!(i, post, "createOrganization", "/organization/create", create_organization),
        route!(i, post, "checkOrganizationSlug", "/organization/check-slug", check_slug),
        route!(i, post, "updateOrganization", "/organization/update", update_organization),
        route!(i, post, "deleteOrganization", "/organization/delete", delete_organization),
        route!(i, get, "getOrganization", "/organization/get-organization", get_organization),
        route!(i, get, "getFullOrganization", "/organization/get-full-organization", get_full_organization),
        route!(i, post, "setActiveOrganization", "/organization/set-active", set_active_organization),
        route!(i, get, "listOrganizations", "/organization/list", list_organizations),
    ]
}
