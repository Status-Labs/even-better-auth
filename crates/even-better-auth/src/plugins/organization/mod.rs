//! Organizations (`plugins/organization`): organizations, members with roles, invitations,
//! optional teams and optional per-organization dynamic roles, under `/organization/*`.
//!
//! Hook and limit callbacks receive JSON objects shaped like the TypeScript arguments
//! (`{ organization, user, member, ... }`); "before" hooks may return fields to merge into
//! the data being written.

mod adapter;
mod invitations;
mod members;
mod orgs;
mod roles;
mod teams;

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::Arc;

use futures::future::BoxFuture;
use http::HeaderMap;
use serde_json::{Map, Value, json};

use super::access::{AccessControl, Connector, Role, Statements, statements};
use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult};
use crate::db::{Field, IdGenerator, OnDelete, TableExtension, Where};
use crate::error::{ApiError, ErrorCode, Result, codes};
use crate::options::Callback;
use crate::plugin::Plugin;
use crate::types::SessionWithUser;

pub use adapter::OrgAdapter;

/// Error codes (`ORGANIZATION_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION => "You are not allowed to create a new organization",
        YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS => "You have reached the maximum number of organizations",
        ORGANIZATION_ALREADY_EXISTS => "Organization already exists",
        ORGANIZATION_SLUG_ALREADY_TAKEN => "Organization slug already taken",
        ORGANIZATION_NOT_FOUND => "Organization not found",
        USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION => "User is not a member of the organization",
        YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION => "You are not allowed to update this organization",
        YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION => "You are not allowed to delete this organization",
        NO_ACTIVE_ORGANIZATION => "No active organization",
        USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION => "User is already a member of this organization",
        MEMBER_NOT_FOUND => "Member not found",
        ROLE_NOT_FOUND => "Role not found",
        YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM => "You are not allowed to create a new team",
        TEAM_ALREADY_EXISTS => "Team already exists",
        TEAM_NOT_FOUND => "Team not found",
        YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER => "You cannot leave the organization as the only owner",
        YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER => "You cannot leave the organization without an owner",
        YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER => "You are not allowed to delete this member",
        YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION => "You are not allowed to invite users to this organization",
        USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION => "User is already invited to this organization",
        INVITATION_NOT_FOUND => "Invitation not found",
        YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION => "You are not the recipient of the invitation",
        EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION => "Email verification required before accepting or rejecting invitation",
        EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION => "Email verification required to view or list invitations for the session email",
        YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION => "You are not allowed to cancel this invitation",
        INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION => "Inviter is no longer a member of the organization",
        YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE => "You are not allowed to invite a user with this role",
        FAILED_TO_RETRIEVE_INVITATION => "Failed to retrieve invitation",
        YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS => "You have reached the maximum number of teams",
        UNABLE_TO_REMOVE_LAST_TEAM => "Unable to remove last team",
        YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER => "You are not allowed to update this member",
        ORGANIZATION_MEMBERSHIP_LIMIT_REACHED => "Organization membership limit reached",
        YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION => "You are not allowed to create teams in this organization",
        YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION => "You are not allowed to delete teams in this organization",
        YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM => "You are not allowed to update this team",
        YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM => "You are not allowed to delete this team",
        INVITATION_LIMIT_REACHED => "Invitation limit reached",
        TEAM_MEMBER_LIMIT_REACHED => "Team member limit reached",
        USER_IS_NOT_A_MEMBER_OF_THE_TEAM => "User is not a member of the team",
        YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM => "You are not allowed to list the members of this team",
        YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM => "You do not have an active team",
        YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER => "You are not allowed to create a new member",
        YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER => "You are not allowed to remove a team member",
        YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION => "You are not allowed to access this organization as an owner",
        YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION => "You are not a member of this organization",
        MISSING_AC_INSTANCE => "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin. Read server logs for more information",
        YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE => "You must be in an organization to create a role",
        YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE => "You are not allowed to create a role",
        YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE => "You are not allowed to update a role",
        YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE => "You are not allowed to delete a role",
        YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE => "You are not allowed to read a role",
        YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE => "You are not allowed to list a role",
        YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE => "You are not allowed to get a role",
        TOO_MANY_ROLES => "This organization has too many roles",
        INVALID_RESOURCE => "The provided permission includes an invalid resource",
        ROLE_NAME_IS_ALREADY_TAKEN => "That role name is already taken",
        CANNOT_DELETE_A_PRE_DEFINED_ROLE => "Cannot delete a pre-defined role",
        ROLE_IS_ASSIGNED_TO_MEMBERS => "Cannot delete a role that is assigned to members. Please reassign the members to a different role first",
        INVALID_TEAM_ID => "Team id contains a reserved character",
    }
}

pub(crate) use error_codes as e;

// ---- access control -------------------------------------------------------------------

/// The plugin's default statements (`defaultStatements`).
pub fn default_statements() -> Statements {
    statements(&[
        ("organization", &["update", "delete"]),
        ("member", &["create", "update", "delete"]),
        ("invitation", &["create", "cancel"]),
        ("team", &["create", "update", "delete"]),
        ("ac", &["create", "read", "update", "delete"]),
    ])
}

/// The default `admin`, `owner` and `member` roles (`defaultRoles`).
pub fn default_roles() -> BTreeMap<String, Role> {
    let ac = AccessControl::new(default_statements());
    let admin = ac.new_role(statements(&[
        ("organization", &["update"]),
        ("invitation", &["create", "cancel"]),
        ("member", &["create", "update", "delete"]),
        ("team", &["create", "update", "delete"]),
        ("ac", &["create", "read", "update", "delete"]),
    ]));
    let owner = ac.new_role(default_statements());
    let member = ac.new_role(statements(&[
        ("organization", &[]),
        ("member", &[]),
        ("invitation", &[]),
        ("team", &[]),
        ("ac", &["read"]),
    ]));
    BTreeMap::from([("admin".into(), admin), ("owner".into(), owner), ("member".into(), member)])
}

// ---- options -----------------------------------------------------------------------------

/// A callback over a JSON argument shaped like the TS one.
pub type ValueFn<T> = Arc<dyn Fn(Value) -> BoxFuture<'static, Result<T>> + Send + Sync>;

/// Wrap an async closure as a [`ValueFn`].
pub fn value_fn<T, F, Fut>(f: F) -> ValueFn<T>
where
    F: Fn(Value) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<T>> + Send + 'static,
{
    Arc::new(move |v| Box::pin(f(v)))
}

/// A lifecycle hook. "before" hooks may return fields to merge into the data being written.
pub type OrgHook = ValueFn<Option<Map<String, Value>>>;

/// A fixed number or one computed from a JSON argument.
#[derive(Clone)]
pub enum Limit {
    Fixed(usize),
    Dynamic(ValueFn<usize>),
}

impl Limit {
    async fn resolve(&self, arg: impl FnOnce() -> Value) -> Result<usize> {
        match self {
            Limit::Fixed(n) => Ok(*n),
            Limit::Dynamic(f) => f(arg()).await,
        }
    }
}

/// How many organizations a user may create.
#[derive(Clone)]
pub enum OrganizationLimit {
    Count(usize),
    /// Receives the user; returns whether the limit is reached.
    Reached(ValueFn<bool>),
}

#[derive(Clone, Default)]
pub struct DefaultTeamOptions {
    /// Create a team named after the organization (default true when teams are enabled).
    pub disabled: bool,
    /// Create the default team yourself: receives the organization, returns the team.
    pub custom_create: Option<ValueFn<Map<String, Value>>>,
}

#[derive(Clone, Default)]
pub struct TeamOptions {
    pub enabled: bool,
    pub default_team: DefaultTeamOptions,
    /// Receives `{ organizationId, session }`.
    pub maximum_teams: Option<Limit>,
    /// Receives `{ teamId, session, organizationId }`.
    pub maximum_members_per_team: Option<Limit>,
    pub allow_removing_all_teams: bool,
}

#[derive(Clone, Default)]
pub struct DynamicAccessControl {
    pub enabled: bool,
    /// Receives the organization id. Default: unlimited.
    pub maximum_roles_per_organization: Option<Limit>,
}

/// Arguments for [`OrganizationOptions::send_invitation_email`].
#[derive(Debug, Clone)]
pub struct InvitationEmail {
    pub id: String,
    pub role: String,
    pub email: String,
    pub organization: Map<String, Value>,
    pub invitation: Map<String, Value>,
    /// The inviting member, with a `user` object.
    pub inviter: Map<String, Value>,
    pub request_headers: Option<HeaderMap>,
}

/// Model name, column names and extra fields for one of the plugin's tables.
#[derive(Clone, Default)]
pub struct TableCustomization {
    pub model_name: Option<String>,
    /// Logical field name -> column name.
    pub field_names: BTreeMap<String, String>,
    pub additional_fields: Vec<(String, Field)>,
}

/// Lifecycle hooks (`organizationHooks`).
#[derive(Clone, Default)]
pub struct OrganizationHooks {
    pub before_create_organization: Option<OrgHook>,
    pub after_create_organization: Option<OrgHook>,
    pub before_update_organization: Option<OrgHook>,
    pub after_update_organization: Option<OrgHook>,
    pub before_delete_organization: Option<OrgHook>,
    pub after_delete_organization: Option<OrgHook>,
    pub before_add_member: Option<OrgHook>,
    pub after_add_member: Option<OrgHook>,
    pub before_remove_member: Option<OrgHook>,
    pub after_remove_member: Option<OrgHook>,
    pub before_update_member_role: Option<OrgHook>,
    pub after_update_member_role: Option<OrgHook>,
    pub before_create_invitation: Option<OrgHook>,
    pub after_create_invitation: Option<OrgHook>,
    pub before_accept_invitation: Option<OrgHook>,
    pub after_accept_invitation: Option<OrgHook>,
    pub before_reject_invitation: Option<OrgHook>,
    pub after_reject_invitation: Option<OrgHook>,
    pub before_cancel_invitation: Option<OrgHook>,
    pub after_cancel_invitation: Option<OrgHook>,
    pub before_create_team: Option<OrgHook>,
    pub after_create_team: Option<OrgHook>,
    pub before_update_team: Option<OrgHook>,
    pub after_update_team: Option<OrgHook>,
    pub before_delete_team: Option<OrgHook>,
    pub after_delete_team: Option<OrgHook>,
    pub before_add_team_member: Option<OrgHook>,
    pub after_add_team_member: Option<OrgHook>,
    pub before_remove_team_member: Option<OrgHook>,
    pub after_remove_team_member: Option<OrgHook>,
}

#[derive(Clone)]
pub struct OrganizationOptions {
    /// Default: everyone may create organizations. Receives the user.
    pub allow_user_to_create_organization: Option<ValueFn<bool>>,
    pub organization_limit: Option<OrganizationLimit>,
    /// Role given to an organization's creator (default `"owner"`).
    pub creator_role: String,
    /// Receives `{ user, organization }` (default 100).
    pub membership_limit: Limit,
    /// Required for dynamic access control.
    pub ac: Option<AccessControl>,
    /// Custom roles; merged over the defaults.
    pub roles: Option<BTreeMap<String, Role>>,
    pub dynamic_access_control: DynamicAccessControl,
    pub teams: TeamOptions,
    /// Seconds (default 48 hours).
    pub invitation_expires_in: i64,
    /// Receives `{ user, organization, member }` (default 100 pending invitations).
    pub invitation_limit: Option<Limit>,
    pub cancel_pending_invitations_on_re_invite: bool,
    /// Require a verified email to view, accept or reject invitations by id. Defaults to
    /// requiring it only when invitation ids are guessable (custom or database ids).
    pub require_email_verification_on_invitation: Option<bool>,
    pub send_invitation_email: Option<Callback<InvitationEmail>>,
    /// Keyed by `"organization"`, `"member"`, `"invitation"`, `"team"`, `"teamMember"`,
    /// `"organizationRole"` or `"session"`.
    pub schema: BTreeMap<String, TableCustomization>,
    pub disable_organization_deletion: bool,
    pub hooks: OrganizationHooks,
}

impl Default for OrganizationOptions {
    fn default() -> Self {
        Self {
            allow_user_to_create_organization: None,
            organization_limit: None,
            creator_role: "owner".into(),
            membership_limit: Limit::Fixed(100),
            ac: None,
            roles: None,
            dynamic_access_control: DynamicAccessControl::default(),
            teams: TeamOptions::default(),
            invitation_expires_in: 60 * 60 * 48,
            invitation_limit: None,
            cancel_pending_invitations_on_re_invite: false,
            require_email_verification_on_invitation: None,
            send_invitation_email: None,
            schema: BTreeMap::new(),
            disable_organization_deletion: false,
            hooks: OrganizationHooks::default(),
        }
    }
}

// ---- shared state & helpers ---------------------------------------------------------------

pub(crate) struct Inner {
    pub options: OrganizationOptions,
    /// Static roles: defaults overlaid with custom roles.
    pub roles: BTreeMap<String, Role>,
}

pub(crate) type In = Arc<Inner>;

/// Run a hook, returning fields it asked to merge.
pub(crate) async fn run_hook(hook: &Option<OrgHook>, arg: Value) -> Result<Option<Map<String, Value>>> {
    match hook {
        Some(h) => h(arg).await,
        None => Ok(None),
    }
}

pub(crate) fn parse_roles(value: &Value) -> String {
    match value {
        Value::Array(list) => list.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","),
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

pub(crate) fn split_roles(role: &str) -> Vec<String> {
    role.split(',').map(|r| r.trim().to_owned()).filter(|r| !r.is_empty()).collect()
}

pub(crate) fn str_field<'a>(r: &'a Map<String, Value>, k: &str) -> &'a str {
    r.get(k).and_then(Value::as_str).unwrap_or_default()
}

pub(crate) fn coerce_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub(crate) fn body_object(ctx: &EndpointContext) -> Result<Map<String, Value>, ApiError> {
    match ctx.body() {
        Value::Object(m) => Ok(m),
        Value::Null => Ok(Map::new()),
        _ => Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT)),
    }
}

pub(crate) fn required(body: &Map<String, Value>, key: &str) -> Result<String, ApiError> {
    coerce_string(body.get(key)).ok_or_else(|| {
        ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", format!("{key} is required"))
    })
}

pub(crate) fn bad(code: ErrorCode) -> ApiError {
    ApiError::bad_request(code)
}

pub(crate) fn forbidden(code: ErrorCode) -> ApiError {
    ApiError::forbidden(code)
}

/// The session's active organization / team.
pub(crate) fn active_org(session: &SessionWithUser) -> Option<String> {
    session
        .session
        .extra
        .get("activeOrganizationId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

pub(crate) fn active_team(session: &SessionWithUser) -> Option<String> {
    session.session.extra.get("activeTeamId").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned)
}

pub(crate) fn session_json(ctx: &EndpointContext, s: &SessionWithUser) -> Value {
    json!({ "session": ctx.auth.session_output(&s.session), "user": ctx.auth.user_output(&s.user) })
}

/// `hasPermission`: does `role` (comma-separated) grant `permissions` in the organization,
/// including roles defined in the database when dynamic access control is enabled?
pub(crate) async fn has_permission(
    ctx: &EndpointContext,
    inner: &Inner,
    organization_id: &str,
    role: &str,
    permissions: &Map<String, Value>,
    allow_creator_all: bool,
) -> Result<bool, ApiError> {
    if permissions.is_empty() {
        return Ok(false);
    }
    let roles = split_roles(role);
    if allow_creator_all && roles.iter().any(|r| r == &inner.options.creator_role) {
        return Ok(true);
    }
    let mut ac_roles = inner.roles.clone();
    if inner.options.dynamic_access_control.enabled
        && let Some(ac) = &inner.options.ac
        && !organization_id.is_empty()
    {
        let rows = ctx
            .auth
            .db
            .find_many(
                "organizationRole",
                crate::db::FindManyQuery {
                    where_: vec![Where::eq("organizationId", organization_id)],
                    ..Default::default()
                },
            )
            .await?;
        for row in rows {
            let name = str_field(&row, "role").to_owned();
            let parsed: Option<BTreeMap<String, Vec<String>>> =
                serde_json::from_str(str_field(&row, "permission")).ok();
            let Some(parsed) = parsed else {
                tracing::error!(role = %name, "[hasPermission] Invalid permissions for role");
                return Err(ApiError::message(
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Invalid permissions for role {name}"),
                ));
            };
            let mut merged = ac_roles.get(&name).map(|r| r.statements.clone()).unwrap_or_default();
            for (resource, actions) in parsed {
                let entry = merged.entry(resource).or_default();
                for a in actions {
                    if !entry.contains(&a) {
                        entry.push(a);
                    }
                }
            }
            ac_roles.insert(name, ac.new_role(merged));
        }
    }
    Ok(roles.iter().any(|r| ac_roles.get(r).is_some_and(|role| role.authorize(permissions, Connector::And).success())))
}

pub(crate) fn permission(resource: &str, action: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(resource.into(), json!([action]));
    m
}

/// Whether invitation ids may be guessable, which requires a verified email to act on them.
pub(crate) fn invitation_requires_verified_email(ctx: &EndpointContext, inner: &Inner) -> bool {
    if let Some(v) = inner.options.require_email_verification_on_invitation {
        return v;
    }
    !matches!(ctx.auth.options.advanced.generate_id, IdGenerator::Random | IdGenerator::Uuid)
}

// ---- has-permission endpoint ------------------------------------------------------------

async fn has_permission_endpoint(inner: In, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = body_object(&ctx)?;
    let org_id = coerce_string(body.get("organizationId")).filter(|s| !s.is_empty()).or_else(|| active_org(&session));
    let Some(org_id) = org_id else { return Err(bad(e::NO_ACTIVE_ORGANIZATION)) };
    let adapter = OrgAdapter::new(&ctx, &inner);
    let Some(member) = adapter.find_member_by_org_id(&session.user.id, &org_id).await? else {
        return Err(ApiError::unauthorized(e::USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION));
    };
    let permissions = body.get("permissions").and_then(Value::as_object).cloned().unwrap_or_default();
    let success = has_permission(&ctx, &inner, &org_id, str_field(&member, "role"), &permissions, false).await?;
    ctx.json(json!({ "error": null, "success": success }))
}

// ---- plugin --------------------------------------------------------------------------

pub struct Organization {
    inner: In,
}

pub fn organization(options: OrganizationOptions) -> Arc<dyn Plugin> {
    let mut roles = default_roles();
    if let Some(custom) = &options.roles {
        roles.extend(custom.clone());
    }
    Arc::new(Organization { inner: Arc::new(Inner { options, roles }) })
}

impl Organization {
    /// [`has_permission`] for other plugins (api-key's organization-owned keys).
    pub(crate) async fn role_has_permission(
        &self,
        ctx: &EndpointContext,
        organization_id: &str,
        role: &str,
        permissions: &Map<String, Value>,
        allow_creator_all: bool,
    ) -> Result<bool, ApiError> {
        has_permission(ctx, &self.inner, organization_id, role, permissions, allow_creator_all).await
    }

    fn table(&self, key: &str, fields: Vec<(&str, Field)>) -> TableExtension {
        let custom = self.inner.options.schema.get(key).cloned().unwrap_or_default();
        let mut fields: Vec<(String, Field)> = fields
            .into_iter()
            .map(|(name, field)| {
                let field = match custom.field_names.get(name) {
                    Some(column) => field.field_name(column.clone()),
                    None => field,
                };
                (name.to_owned(), field)
            })
            .collect();
        fields.extend(custom.additional_fields);
        TableExtension { key: key.into(), model_name: custom.model_name, fields, ..Default::default() }
    }
}

macro_rules! route {
    ($inner:expr, $method:ident, $key:literal, $path:literal, $f:path) => {{
        let inner = $inner.clone();
        $crate::api::Endpoint::$method($key, $path, $crate::api::handler(move |ctx| $f(inner.clone(), ctx)))
    }};
}
pub(crate) use route;

impl Plugin for Organization {
    fn id(&self) -> &str {
        "organization"
    }

    fn schema(&self) -> Vec<TableExtension> {
        let opts = &self.inner.options;
        let teams = opts.teams.enabled;
        let mut tables = vec![self.table(
            "organization",
            vec![
                ("name", Field::string().sortable()),
                ("slug", Field::string().unique().sortable().indexed()),
                ("logo", Field::string().optional()),
                ("createdAt", Field::date()),
                ("metadata", Field::string().optional()),
            ],
        )];
        if opts.dynamic_access_control.enabled {
            tables.push(self.table(
                "organizationRole",
                vec![
                    ("organizationId", Field::string().references("organization", "id", OnDelete::Cascade).indexed()),
                    ("role", Field::string().indexed()),
                    ("permission", Field::string()),
                    ("createdAt", Field::date().default_now()),
                    ("updatedAt", Field::date().optional().on_update_now()),
                ],
            ));
        }
        if teams {
            tables.push(self.table(
                "team",
                vec![
                    ("name", Field::string()),
                    ("memberCount", Field::number().default(0).no_input().hidden()),
                    ("organizationId", Field::string().references("organization", "id", OnDelete::Cascade).indexed()),
                    ("createdAt", Field::date()),
                    ("updatedAt", Field::date().optional().on_update_now()),
                ],
            ));
            tables.push(self.table(
                "teamMember",
                vec![
                    ("teamId", Field::string().references("team", "id", OnDelete::Cascade).indexed()),
                    ("userId", Field::string().references("user", "id", OnDelete::Cascade).indexed()),
                    ("membershipKey", Field::string().optional().unique().no_input().hidden()),
                    ("createdAt", Field::date().optional()),
                ],
            ));
        }
        tables.push(self.table(
            "member",
            vec![
                ("organizationId", Field::string().references("organization", "id", OnDelete::Cascade).indexed()),
                ("userId", Field::string().references("user", "id", OnDelete::Cascade).indexed()),
                ("role", Field::string().sortable().default("member")),
                ("createdAt", Field::date()),
            ],
        ));
        let mut invitation = vec![
            ("organizationId", Field::string().references("organization", "id", OnDelete::Cascade).indexed()),
            ("email", Field::string().sortable().indexed()),
            ("role", Field::string().optional().sortable()),
        ];
        if teams {
            invitation.push(("teamId", Field::string().optional().sortable()));
        }
        invitation.extend([
            ("status", Field::string().sortable().default("pending")),
            ("expiresAt", Field::date()),
            ("createdAt", Field::date().default_now()),
            ("inviterId", Field::string().references("user", "id", OnDelete::Cascade)),
        ]);
        tables.push(self.table("invitation", invitation));
        let mut session = vec![("activeOrganizationId", Field::string().optional().no_input())];
        if teams {
            session.push(("activeTeamId", Field::string().optional().no_input()));
        }
        let mut session = self.table("session", session);
        session.model_name = None;
        tables.push(session);
        tables
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let i = &self.inner;
        let mut endpoints =
            vec![route!(i, post, "hasPermission", "/organization/has-permission", has_permission_endpoint)];
        endpoints.extend(orgs::endpoints(i));
        endpoints.extend(members::endpoints(i));
        endpoints.extend(invitations::endpoints(i));
        if i.options.teams.enabled {
            endpoints.extend(teams::endpoints(i));
        }
        if i.options.dynamic_access_control.enabled {
            endpoints.extend(roles::endpoints(i));
        }
        endpoints
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
