//! Invitations (`routes/crud-invites.ts`).

use chrono::Utc;
use http::StatusCode;
use serde_json::{Map, Value, json};

use super::adapter::{AddTeamMember, OrgAdapter};
use super::members::{check_roles_exist, membership_limit, team_limit};
use super::{
    In, InvitationEmail, active_org, bad, body_object, coerce_string, e, forbidden, has_permission,
    invitation_requires_verified_email, parse_roles, permission, required, route, run_hook, session_json, split_roles,
    str_field,
};
use crate::api::middleware::{get_session_from_ctx, require_session};
use crate::api::routes::util::is_valid_email;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult};
use crate::cookies::set_session_cookie;
use crate::db::{InputAction, Record, parse_input};
use crate::error::{ApiError, codes};
use crate::types::SessionWithUser;
use crate::utils::date;

const CORE_FIELDS: &[&str] =
    &["organizationId", "email", "role", "teamId", "status", "expiresAt", "createdAt", "inviterId"];

fn expired(invitation: &Map<String, Value>) -> bool {
    invitation.get("expiresAt").and_then(date::parse_value).is_none_or(|e| e < Utc::now())
}

async fn send_invitation(
    ctx: &EndpointContext,
    inner: &In,
    invitation: &Map<String, Value>,
    organization: &Map<String, Value>,
    inviter: &Map<String, Value>,
) -> Result<(), ApiError> {
    let Some(send) = &inner.options.send_invitation_email else { return Ok(()) };
    send.call(InvitationEmail {
        id: str_field(invitation, "id").to_owned(),
        role: str_field(invitation, "role").to_owned(),
        email: str_field(invitation, "email").to_lowercase(),
        organization: organization.clone(),
        invitation: invitation.clone(),
        inviter: inviter.clone(),
        request_headers: ctx.is_request.then(|| ctx.headers()),
    })
    .await?;
    Ok(())
}

fn requested_team_ids(body: &Map<String, Value>) -> Vec<String> {
    match body.get("teamId") {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        _ => vec![],
    }
}

async fn create_invitation(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let org_id = coerce_string(body.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(&session));
    let Some(org_id) = org_id else { return Err(bad(e::ORGANIZATION_NOT_FOUND)) };
    let email = required(&body, "email")?.to_lowercase();
    if !is_valid_email(&email) {
        return Err(bad(codes::INVALID_EMAIL));
    }
    let adapter = OrgAdapter::new(&ctx, &inner);
    let member =
        adapter.find_member_by_org_id(&session.user.id, &org_id).await?.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("invitation", "create"), false)
        .await?
    {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION));
    }
    let roles = parse_roles(body.get("role").unwrap_or(&Value::Null));
    let role_list = split_roles(&roles);
    check_roles_exist(&ctx, &inner, &org_id, &role_list, false).await?;
    let creator = &inner.options.creator_role;
    if !split_roles(str_field(&member, "role")).contains(creator) && roles.split(',').any(|r| r == creator) {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE));
    }
    if adapter.find_member_by_email(&email, &org_id).await?.is_some() {
        return Err(bad(e::USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION));
    }
    let already = adapter.find_pending_invitation(&email, &org_id).await?;
    let resend = body.get("resend").and_then(Value::as_bool) == Some(true);
    let cancel_pending = inner.options.cancel_pending_invitations_on_re_invite;
    if !already.is_empty() && !resend && !cancel_pending {
        return Err(bad(e::USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION));
    }
    let organization = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    let mut inviter = member.clone();
    inviter.insert("user".into(), Value::Object(ctx.auth.user_output(&session.user)));
    if let (Some(existing), true) = (already.first(), resend) {
        let expires = Utc::now() + chrono::Duration::seconds(inner.options.invitation_expires_in);
        let mut update = Record::new();
        update.insert("expiresAt".into(), date::to_value(expires));
        adapter.update_invitation_fields(str_field(existing, "id"), update).await?;
        let mut updated = existing.clone();
        updated.insert("expiresAt".into(), date::to_value(expires));
        send_invitation(&ctx, &inner, &updated, &organization, &inviter).await?;
        return ctx.json(Value::Object(updated));
    }
    if let (Some(existing), true) = (already.first(), cancel_pending) {
        adapter.update_invitation(str_field(existing, "id"), "canceled", None).await?;
    }
    let limit = match &inner.options.invitation_limit {
        Some(limit) => {
            limit
                .resolve(|| json!({ "user": ctx.auth.user_output(&session.user), "organization": organization, "member": member }))
                .await?
        }
        None => 100,
    };
    if adapter.find_pending_invitations(&org_id).await?.len() >= limit {
        return Err(forbidden(e::INVITATION_LIMIT_REACHED));
    }
    let teams = &inner.options.teams;
    let team_ids = if teams.enabled { requested_team_ids(&body) } else { vec![] };
    if team_ids.iter().any(|id| id.contains(',')) {
        return Err(bad(e::INVALID_TEAM_ID));
    }
    for team_id in &team_ids {
        if adapter.find_team_by_id(team_id, Some(&org_id)).await?.is_none() {
            return Err(bad(e::TEAM_NOT_FOUND));
        }
        if let Some(limit) = &teams.maximum_members_per_team {
            let max = team_limit(limit, team_id, &org_id, session_json(&ctx, &session)).await?;
            if adapter.count_team_members(team_id).await? as usize >= max {
                return Err(forbidden(e::TEAM_MEMBER_LIMIT_REACHED));
            }
        }
    }
    let table = ctx.auth.schema.table("invitation").expect("invitation table");
    let mut data = parse_input(table, &body, InputAction::Create, CORE_FIELDS)?;
    data.insert("role".into(), roles.into());
    data.insert("email".into(), email.into());
    data.insert("organizationId".into(), org_id.clone().into());
    let user_json = Value::Object(ctx.auth.user_output(&session.user));
    let mut hook_invitation = data.clone();
    hook_invitation.insert("inviterId".into(), session.user.id.clone().into());
    if let Some(first) = team_ids.first() {
        hook_invitation.insert("teamId".into(), first.clone().into());
    }
    let hooks = &inner.options.hooks;
    let arg = json!({ "invitation": hook_invitation, "inviter": user_json, "organization": organization });
    if let Some(extra) = run_hook(&hooks.before_create_invitation, arg).await? {
        data.extend(extra);
    }
    let invitation = adapter.create_invitation(data, &team_ids, &session.user.id).await?;
    send_invitation(&ctx, &inner, &invitation, &organization, &inviter).await?;
    let arg = json!({ "invitation": invitation, "inviter": user_json, "organization": organization });
    run_hook(&hooks.after_create_invitation, arg).await?;
    ctx.json(Value::Object(invitation))
}

fn require_recipient(invitation: &Map<String, Value>, session: &SessionWithUser) -> Result<(), ApiError> {
    if str_field(invitation, "email").to_lowercase() != session.user.email.to_lowercase() {
        return Err(forbidden(e::YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION));
    }
    Ok(())
}

async fn accept_invitation(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let invitation_id = required(&body_object(&ctx)?, "invitationId")?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let invitation = adapter.find_invitation_by_id(&invitation_id).await?;
    let invitation = invitation
        .filter(|i| !expired(i) && str_field(i, "status") == "pending")
        .ok_or_else(|| bad(e::INVITATION_NOT_FOUND))?;
    require_recipient(&invitation, &session)?;
    if invitation_requires_verified_email(&ctx, &inner) && !session.user.email_verified {
        return Err(forbidden(e::EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION));
    }
    let org_id = str_field(&invitation, "organizationId").to_owned();
    let count = adapter.count_members(&org_id).await?;
    let organization = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    if count as usize >= membership_limit(&inner, &ctx, &session.user, &organization).await? {
        return Err(forbidden(e::ORGANIZATION_MEMBERSHIP_LIMIT_REACHED));
    }
    let user_json = Value::Object(ctx.auth.user_output(&session.user));
    let hooks = &inner.options.hooks;
    run_hook(
        &hooks.before_accept_invitation,
        json!({ "invitation": invitation, "user": user_json, "organization": organization }),
    )
    .await?;
    let accepted = adapter
        .update_invitation(&invitation_id, "accepted", Some("pending"))
        .await?
        .ok_or_else(|| bad(e::INVITATION_NOT_FOUND))?;
    let result: Result<Map<String, Value>, ApiError> = ctx
        .auth
        .transaction(async {
            let team_value = str_field(&accepted, "teamId");
            if inner.options.teams.enabled && !team_value.is_empty() {
                let team_ids: Vec<&str> = team_value.split(',').collect();
                for team_id in &team_ids {
                    if adapter.find_team_by_id(team_id, Some(&org_id)).await?.is_none() {
                        return Err(bad(e::TEAM_NOT_FOUND));
                    }
                    match &inner.options.teams.maximum_members_per_team {
                        Some(limit) => {
                            let max = team_limit(limit, team_id, &org_id, session_json(&ctx, &session)).await?;
                            if let AddTeamMember::LimitReached =
                                adapter.add_team_member_with_limit(team_id, &session.user.id, max).await?
                            {
                                return Err(forbidden(e::TEAM_MEMBER_LIMIT_REACHED));
                            }
                        }
                        None => {
                            adapter.find_or_create_team_member(team_id, &session.user.id).await?;
                        }
                    }
                }
                if let [only] = team_ids.as_slice()
                    && let Some(updated) = adapter.set_active_team(&session.session.token, Some(only)).await?
                {
                    set_session_cookie(
                        &ctx,
                        &SessionWithUser { session: updated, user: session.user.clone() },
                        None,
                        None,
                    )
                    .await;
                }
            }
            let mut data = Record::new();
            data.insert("organizationId".into(), org_id.clone().into());
            data.insert("userId".into(), session.user.id.clone().into());
            data.insert("role".into(), accepted.get("role").cloned().unwrap_or_default());
            let member = adapter.create_member(data).await?;
            adapter.set_active_organization(&session.session.token, Some(&org_id)).await?;
            Ok::<_, ApiError>(member)
        })
        .await;
    let member = match result {
        Ok(member) => member,
        Err(err) => {
            adapter.update_invitation(&invitation_id, "pending", Some("accepted")).await?;
            return Err(err);
        }
    };
    let arg = json!({ "invitation": accepted, "member": member, "user": user_json, "organization": organization });
    run_hook(&hooks.after_accept_invitation, arg).await?;
    ctx.json(json!({ "invitation": accepted, "member": member }))
}

async fn reject_invitation(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let invitation_id = required(&body_object(&ctx)?, "invitationId")?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let invitation = adapter
        .find_invitation_by_id(&invitation_id)
        .await?
        .filter(|i| str_field(i, "status") == "pending")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND", "Invitation not found!"))?;
    require_recipient(&invitation, &session)?;
    if invitation_requires_verified_email(&ctx, &inner) && !session.user.email_verified {
        return Err(forbidden(e::EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION));
    }
    let organization = adapter
        .find_organization_by_id(str_field(&invitation, "organizationId"))
        .await?
        .ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    let user_json = Value::Object(ctx.auth.user_output(&session.user));
    let hooks = &inner.options.hooks;
    run_hook(
        &hooks.before_reject_invitation,
        json!({ "invitation": invitation, "user": user_json, "organization": organization }),
    )
    .await?;
    let rejected = adapter.update_invitation(&invitation_id, "rejected", None).await?;
    let arg = json!({ "invitation": rejected.clone().unwrap_or(invitation), "user": user_json, "organization": organization });
    run_hook(&hooks.after_reject_invitation, arg).await?;
    ctx.json(json!({ "invitation": rejected, "member": null }))
}

async fn cancel_invitation(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let invitation_id = required(&body_object(&ctx)?, "invitationId")?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let invitation =
        adapter.find_invitation_by_id(&invitation_id).await?.ok_or_else(|| bad(e::INVITATION_NOT_FOUND))?;
    let org_id = str_field(&invitation, "organizationId").to_owned();
    let member =
        adapter.find_member_by_org_id(&session.user.id, &org_id).await?.ok_or_else(|| bad(e::MEMBER_NOT_FOUND))?;
    if !has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permission("invitation", "cancel"), false)
        .await?
    {
        return Err(forbidden(e::YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION));
    }
    let organization = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    let user_json = Value::Object(ctx.auth.user_output(&session.user));
    let hooks = &inner.options.hooks;
    let arg = json!({ "invitation": invitation, "cancelledBy": user_json, "organization": organization });
    run_hook(&hooks.before_cancel_invitation, arg).await?;
    let canceled = adapter.update_invitation(&invitation_id, "canceled", None).await?;
    let arg = json!({ "invitation": canceled.clone().unwrap_or(invitation), "cancelledBy": user_json, "organization": organization });
    run_hook(&hooks.after_cancel_invitation, arg).await?;
    ctx.json(canceled.map(Value::Object).unwrap_or(Value::Null))
}

fn not_authenticated() -> ApiError {
    ApiError::message(StatusCode::UNAUTHORIZED, "Not authenticated")
}

async fn get_invitation(inner: In, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default()).await?.ok_or_else(not_authenticated)?;
    let id = ctx.query_str("id").ok_or_else(|| bad(codes::VALIDATION_ERROR))?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    let invitation = adapter
        .find_invitation_by_id(&id)
        .await?
        .filter(|i| str_field(i, "status") == "pending" && !expired(i))
        .ok_or_else(|| ApiError::message(StatusCode::BAD_REQUEST, "Invitation not found!"))?;
    require_recipient(&invitation, &session)?;
    if invitation_requires_verified_email(&ctx, &inner) && !session.user.email_verified {
        return Err(forbidden(e::EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION));
    }
    let org_id = str_field(&invitation, "organizationId").to_owned();
    let organization = adapter.find_organization_by_id(&org_id).await?.ok_or_else(|| bad(e::ORGANIZATION_NOT_FOUND))?;
    let inviter = adapter
        .find_member_by_org_id(str_field(&invitation, "inviterId"), &org_id)
        .await?
        .ok_or_else(|| bad(e::INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION))?;
    let mut out = invitation;
    out.insert("organizationName".into(), organization["name"].clone());
    out.insert("organizationSlug".into(), organization["slug"].clone());
    out.insert("inviterEmail".into(), inviter["user"]["email"].clone());
    ctx.json(Value::Object(out))
}

async fn list_invitations(inner: In, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default()).await?.ok_or_else(not_authenticated)?;
    let org_id = ctx
        .query_str("organizationId")
        .filter(|s| !s.is_empty())
        .or_else(|| active_org(&session))
        .ok_or_else(|| ApiError::message(StatusCode::BAD_REQUEST, "Organization ID is required"))?;
    let adapter = OrgAdapter::new(&ctx, &inner);
    if adapter.find_member_by_org_id(&session.user.id, &org_id).await?.is_none() {
        return Err(ApiError::message(StatusCode::FORBIDDEN, "You are not a member of this organization"));
    }
    let invitations = adapter.list_invitations(&org_id).await?;
    ctx.json(Value::Array(invitations.into_iter().map(Value::Object).collect()))
}

async fn list_user_invitations(inner: In, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, Default::default()).await?;
    let query_email = ctx.query_str("email").filter(|s| !s.is_empty());
    if ctx.is_request && query_email.is_some() {
        return Err(ApiError::message(
            StatusCode::BAD_REQUEST,
            "User email cannot be passed for client side API calls.",
        ));
    }
    if session.as_ref().is_some_and(|s| !s.user.email_verified) {
        return Err(forbidden(e::EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION));
    }
    let email = session.map(|s| s.user.email).or(query_email).ok_or_else(|| {
        ApiError::message(StatusCode::BAD_REQUEST, "Missing session headers, or email query parameter.")
    })?;
    let invitations = OrgAdapter::new(&ctx, &inner).list_user_invitations(&email).await?;
    let pending: Vec<Value> =
        invitations.into_iter().filter(|i| str_field(i, "status") == "pending").map(Value::Object).collect();
    ctx.json(Value::Array(pending))
}

pub(super) fn endpoints(i: &In) -> Vec<Endpoint> {
    vec![
        route!(i, post, "createInvitation", "/organization/invite-member", create_invitation),
        route!(i, post, "acceptInvitation", "/organization/accept-invitation", accept_invitation),
        route!(i, post, "rejectInvitation", "/organization/reject-invitation", reject_invitation),
        route!(i, post, "cancelInvitation", "/organization/cancel-invitation", cancel_invitation),
        route!(i, get, "getInvitation", "/organization/get-invitation", get_invitation),
        route!(i, get, "listInvitations", "/organization/list-invitations", list_invitations),
        route!(i, get, "listUserInvitations", "/organization/list-user-invitations", list_user_invitations),
    ]
}
