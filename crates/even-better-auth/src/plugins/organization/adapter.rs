//! Data access for the organization plugin (`getOrgAdapter`). Records are returned in API
//! shape: fields marked `returned: false` are removed.

use std::sync::Arc;

use chrono::Utc;
use serde_json::{Map, Value, json};

use super::{Inner, str_field};
use crate::api::EndpointContext;
use crate::context::AuthContext;
use crate::db::{FindManyQuery, Operator, Record, SortBy, SortDirection, Where, filter_output};
use crate::error::{Error, Result};
use crate::types::{Session, User};
use crate::utils::date;

pub(crate) type Row = Map<String, Value>;

/// Result of [`OrgAdapter::add_team_member_with_limit`].
pub(crate) enum AddTeamMember {
    Added(Row),
    LimitReached,
}

/// The organization plugin's queries over the current [`AuthContext`].
pub struct OrgAdapter<'a> {
    auth: &'a Arc<AuthContext>,
    inner: &'a Inner,
}

fn ids(values: impl IntoIterator<Item = String>) -> Vec<Value> {
    values.into_iter().map(Value::String).collect()
}

fn user_summary(user: &User) -> Value {
    json!({ "id": user.id, "name": user.name, "email": user.email, "image": user.image })
}

fn membership_key(team_id: &str, user_id: &str) -> String {
    crate::crypto::sha256_base64url(&Value::Array(vec![team_id.into(), user_id.into()]).to_string())
}

impl<'a> OrgAdapter<'a> {
    pub(crate) fn new(ctx: &'a EndpointContext, inner: &'a Inner) -> Self {
        Self { auth: &ctx.auth, inner }
    }

    fn db(&self) -> &crate::db::Db {
        &self.auth.db
    }

    /// Strip fields that are not returned.
    pub(crate) fn output(&self, model: &str, row: Row) -> Row {
        match self.auth.schema.table(model) {
            Some(t) => filter_output(t, row),
            None => row,
        }
    }

    async fn find_one(&self, model: &str, where_: &[Where]) -> Result<Option<Row>> {
        self.db().find_one(model, where_).await
    }

    async fn find_many(&self, model: &str, where_: Vec<Where>) -> Result<Vec<Row>> {
        self.db().find_many(model, FindManyQuery { where_, ..Default::default() }).await
    }

    fn membership_limit(&self) -> usize {
        match self.inner.options.membership_limit {
            super::Limit::Fixed(n) if n > 0 => n,
            _ => 100,
        }
    }

    // ---- organizations ------------------------------------------------------------------

    pub(crate) async fn find_organization_by_slug(&self, slug: &str) -> Result<Option<Row>> {
        Ok(self.find_one("organization", &[Where::eq("slug", slug)]).await?.map(|o| self.output("organization", o)))
    }

    /// The organization as stored (its `metadata` stays a JSON string, as in TS).
    pub(crate) async fn find_organization_by_id(&self, id: &str) -> Result<Option<Row>> {
        Ok(self.find_one("organization", &[Where::eq("id", id)]).await?.map(|o| self.output("organization", o)))
    }

    fn parse_metadata(mut org: Row) -> Row {
        let parsed = match org.get("metadata") {
            Some(Value::String(s)) => serde_json::from_str::<Value>(s).ok(),
            Some(Value::Object(m)) => Some(Value::Object(m.clone())),
            _ => None,
        };
        match parsed {
            Some(v) => org.insert("metadata".into(), v),
            None => org.remove("metadata"),
        };
        org
    }

    fn stringify_metadata(data: &mut Record) {
        if let Some(meta) = data.get("metadata").cloned() {
            match meta {
                Value::Object(_) => {
                    data.insert("metadata".into(), meta.to_string().into());
                }
                Value::Null => {
                    data.remove("metadata");
                }
                _ => {}
            }
        }
    }

    pub(crate) async fn create_organization(&self, mut data: Record) -> Result<Row> {
        Self::stringify_metadata(&mut data);
        let org = self.db().create("organization", data, true).await?;
        Ok(self.output("organization", Self::parse_metadata(org)))
    }

    pub(crate) async fn update_organization(&self, id: &str, mut data: Record) -> Result<Option<Row>> {
        if let Some(Value::Object(_)) = data.get("metadata") {
            Self::stringify_metadata(&mut data);
        }
        data.remove("id");
        let updated = self.db().update("organization", &[Where::eq("id", id)], data).await?;
        Ok(updated.map(|o| self.output("organization", Self::parse_metadata(o))))
    }

    pub(crate) async fn delete_organization(&self, id: &str) -> Result<()> {
        self.auth
            .transaction(async {
                self.db().delete_many("member", &[Where::eq("organizationId", id)]).await?;
                self.db().delete_many("invitation", &[Where::eq("organizationId", id)]).await?;
                self.db().delete("organization", &[Where::eq("id", id)]).await?;
                Ok::<_, Error>(())
            })
            .await
    }

    pub(crate) async fn list_organizations(&self, user_id: &str) -> Result<Vec<Row>> {
        let members = self.find_many("member", vec![Where::eq("userId", user_id)]).await?;
        if members.is_empty() {
            return Ok(vec![]);
        }
        let org_ids = ids(members.iter().map(|m| str_field(m, "organizationId").to_owned()));
        let orgs = self.find_many("organization", vec![Where::is_in("id", org_ids)]).await?;
        // Keep membership order, as the TS join does.
        Ok(members
            .iter()
            .filter_map(|m| orgs.iter().find(|o| str_field(o, "id") == str_field(m, "organizationId")).cloned())
            .map(|o| self.output("organization", o))
            .collect())
    }

    pub(crate) async fn set_active_organization(
        &self,
        token: &str,
        organization_id: Option<&str>,
    ) -> Result<Option<Session>> {
        let mut data = Record::new();
        data.insert("activeOrganizationId".into(), organization_id.map(Value::from).unwrap_or(Value::Null));
        self.auth.internal_adapter.update_session(token, data).await
    }

    pub(crate) async fn set_active_team(&self, token: &str, team_id: Option<&str>) -> Result<Option<Session>> {
        let mut data = Record::new();
        data.insert("activeTeamId".into(), team_id.map(Value::from).unwrap_or(Value::Null));
        self.auth.internal_adapter.update_session(token, data).await
    }

    /// The organization with `members` (each with `user`), `invitations` and, when teams
    /// are enabled, `teams`.
    pub(crate) async fn find_full_organization(
        &self,
        id_or_slug: &str,
        is_slug: bool,
        include_teams: bool,
        members_limit: Option<usize>,
    ) -> Result<Option<Row>> {
        let field = if is_slug { "slug" } else { "id" };
        let Some(org) = self.find_one("organization", &[Where::eq(field, id_or_slug)]).await? else {
            return Ok(None);
        };
        let org_id = str_field(&org, "id").to_owned();
        let invitations = self.find_many("invitation", vec![Where::eq("organizationId", org_id.clone())]).await?;
        let members = self
            .db()
            .find_many(
                "member",
                FindManyQuery {
                    where_: vec![Where::eq("organizationId", org_id.clone())],
                    limit: members_limit,
                    ..Default::default()
                },
            )
            .await?;
        let users = if members.is_empty() {
            vec![]
        } else {
            let user_ids = ids(members.iter().map(|m| str_field(m, "userId").to_owned()));
            self.auth
                .internal_adapter
                .list_users(Some(self.membership_limit()), None, None, vec![Where::is_in("id", user_ids)])
                .await?
        };
        let mut member_rows = vec![];
        for m in members {
            let user = users
                .iter()
                .find(|u| u.id == str_field(&m, "userId"))
                .ok_or_else(|| Error::Database("Unexpected error: User not found for member".into()))?;
            let mut row = self.output("member", m);
            row.insert("user".into(), user_summary(user));
            member_rows.push(Value::Object(row));
        }
        let mut out = self.output("organization", org);
        out.insert(
            "invitations".into(),
            Value::Array(invitations.into_iter().map(|i| Value::Object(self.output("invitation", i))).collect()),
        );
        out.insert("members".into(), Value::Array(member_rows));
        if include_teams {
            let teams = self.list_teams(&org_id).await?;
            out.insert("teams".into(), Value::Array(teams.into_iter().map(Value::Object).collect()));
        }
        Ok(Some(out))
    }

    // ---- members ------------------------------------------------------------------------

    async fn with_user(&self, member: Row) -> Result<Option<Row>> {
        let Some(user) = self.auth.internal_adapter.find_user_by_id(str_field(&member, "userId")).await? else {
            return Ok(None);
        };
        let mut row = self.output("member", member);
        row.insert("user".into(), user_summary(&user));
        Ok(Some(row))
    }

    pub(crate) async fn find_member_by_org_id(&self, user_id: &str, organization_id: &str) -> Result<Option<Row>> {
        let member = self
            .find_one("member", &[Where::eq("userId", user_id), Where::eq("organizationId", organization_id)])
            .await?;
        match member {
            Some(m) => self.with_user(m).await,
            None => Ok(None),
        }
    }

    pub(crate) async fn find_member_by_id(&self, id: &str) -> Result<Option<Row>> {
        match self.find_one("member", &[Where::eq("id", id)]).await? {
            Some(m) => self.with_user(m).await,
            None => Ok(None),
        }
    }

    pub(crate) async fn find_member_by_email(&self, email: &str, organization_id: &str) -> Result<Option<Row>> {
        let Some(user) = self.auth.internal_adapter.find_user_by_email(email).await? else { return Ok(None) };
        let member = self
            .find_one("member", &[Where::eq("organizationId", organization_id), Where::eq("userId", user.id.clone())])
            .await?;
        Ok(member.map(|m| {
            let mut row = self.output("member", m);
            row.insert("user".into(), user_summary(&user));
            row
        }))
    }

    /// The raw membership row, if any (`checkMembership`).
    pub(crate) async fn check_membership(&self, user_id: &str, organization_id: &str) -> Result<Option<Row>> {
        self.find_one("member", &[Where::eq("userId", user_id), Where::eq("organizationId", organization_id)]).await
    }

    pub(crate) async fn create_member(&self, mut data: Record) -> Result<Row> {
        data.insert("createdAt".into(), date::now_value());
        let member = self.db().create("member", data, false).await?;
        Ok(self.output("member", member))
    }

    pub(crate) async fn update_member(&self, id: &str, role: &str) -> Result<Option<Row>> {
        let mut data = Record::new();
        data.insert("role".into(), role.into());
        Ok(self.db().update("member", &[Where::eq("id", id)], data).await?.map(|m| self.output("member", m)))
    }

    pub(crate) async fn count_members(&self, organization_id: &str) -> Result<u64> {
        self.db().count("member", &[Where::eq("organizationId", organization_id)]).await
    }

    pub(crate) async fn all_members(&self, organization_id: &str) -> Result<Vec<Row>> {
        self.find_many("member", vec![Where::eq("organizationId", organization_id)]).await
    }

    /// Remove a member and their team memberships in the organization.
    pub(crate) async fn delete_member(&self, member_id: &str, organization_id: &str, user_id: &str) -> Result<()> {
        self.auth
            .transaction(async {
                self.db().delete("member", &[Where::eq("id", member_id)]).await?;
                if self.inner.options.teams.enabled {
                    for team in self.find_many("team", vec![Where::eq("organizationId", organization_id)]).await? {
                        let team_id = str_field(&team, "id").to_owned();
                        let deleted = self
                            .db()
                            .delete_many(
                                "teamMember",
                                &[Where::eq("userId", user_id), Where::eq("teamId", team_id.clone())],
                            )
                            .await?;
                        self.release_team_seats(&team_id, deleted as i64).await?;
                    }
                }
                Ok::<_, Error>(())
            })
            .await
    }

    pub(crate) async fn list_members(
        &self,
        organization_id: &str,
        limit: Option<usize>,
        offset: Option<usize>,
        sort_by: Option<SortBy>,
        filter: Option<Where>,
    ) -> Result<(Vec<Row>, u64)> {
        let mut where_ = vec![Where::eq("organizationId", organization_id)];
        where_.extend(filter);
        let members = self
            .db()
            .find_many(
                "member",
                FindManyQuery {
                    where_: where_.clone(),
                    limit: Some(limit.filter(|l| *l > 0).unwrap_or_else(|| self.membership_limit())),
                    offset: Some(offset.unwrap_or(0)),
                    sort_by,
                },
            )
            .await?;
        let total = self.db().count("member", &where_).await?;
        let user_ids = ids(members.iter().map(|m| str_field(m, "userId").to_owned()));
        let users = if members.is_empty() {
            vec![]
        } else {
            self.auth
                .internal_adapter
                .list_users(Some(members.len()), None, None, vec![Where::is_in("id", user_ids)])
                .await?
        };
        let mut out = vec![];
        for m in members {
            let user = users
                .iter()
                .find(|u| u.id == str_field(&m, "userId"))
                .ok_or_else(|| Error::Database("Unexpected error: User not found for member".into()))?;
            let mut row = self.output("member", m);
            row.insert("user".into(), user_summary(user));
            out.push(row);
        }
        Ok((out, total))
    }

    // ---- teams --------------------------------------------------------------------------

    pub(crate) async fn create_team(&self, mut data: Record) -> Result<Row> {
        data.insert("memberCount".into(), 0.into());
        let team = self.db().create("team", data, true).await?;
        Ok(self.output("team", team))
    }

    pub(crate) async fn find_team_by_id(&self, team_id: &str, organization_id: Option<&str>) -> Result<Option<Row>> {
        let mut where_ = vec![Where::eq("id", team_id)];
        if let Some(org) = organization_id {
            where_.push(Where::eq("organizationId", org));
        }
        Ok(self.find_one("team", &where_).await?.map(|t| self.output("team", t)))
    }

    pub(crate) async fn update_team(&self, team_id: &str, mut data: Record) -> Result<Option<Row>> {
        data.remove("id");
        Ok(self.db().update("team", &[Where::eq("id", team_id)], data).await?.map(|t| self.output("team", t)))
    }

    pub(crate) async fn delete_team(&self, team_id: &str) -> Result<()> {
        self.db().delete_many("teamMember", &[Where::eq("teamId", team_id)]).await?;
        self.db().delete("team", &[Where::eq("id", team_id)]).await
    }

    pub(crate) async fn list_teams(&self, organization_id: &str) -> Result<Vec<Row>> {
        let teams = self.find_many("team", vec![Where::eq("organizationId", organization_id)]).await?;
        Ok(teams.into_iter().map(|t| self.output("team", t)).collect())
    }

    pub(crate) async fn list_teams_by_user(&self, user_id: &str) -> Result<Vec<Row>> {
        let memberships = self.find_many("teamMember", vec![Where::eq("userId", user_id)]).await?;
        if memberships.is_empty() {
            return Ok(vec![]);
        }
        let team_ids = ids(memberships.iter().map(|m| str_field(m, "teamId").to_owned()));
        let teams = self.find_many("team", vec![Where::is_in("id", team_ids)]).await?;
        Ok(memberships
            .iter()
            .filter_map(|m| teams.iter().find(|t| str_field(t, "id") == str_field(m, "teamId")).cloned())
            .map(|t| self.output("team", t))
            .collect())
    }

    pub(crate) async fn list_team_members(&self, team_id: &str) -> Result<Vec<Row>> {
        let members = self.find_many("teamMember", vec![Where::eq("teamId", team_id)]).await?;
        Ok(members.into_iter().map(|m| self.output("teamMember", m)).collect())
    }

    pub(crate) async fn count_team_members(&self, team_id: &str) -> Result<u64> {
        self.db().count("teamMember", &[Where::eq("teamId", team_id)]).await
    }

    pub(crate) async fn find_team_member(&self, team_id: &str, user_id: &str) -> Result<Option<Row>> {
        let member = self.find_one("teamMember", &[Where::eq("teamId", team_id), Where::eq("userId", user_id)]).await?;
        Ok(member.map(|m| self.output("teamMember", m)))
    }

    async fn find_by_key_or_pair(&self, team_id: &str, user_id: &str, key: &str) -> Result<Option<Row>> {
        if let Some(m) = self.find_one("teamMember", &[Where::eq("membershipKey", key)]).await? {
            return Ok(Some(m));
        }
        self.find_one("teamMember", &[Where::eq("teamId", team_id), Where::eq("userId", user_id)]).await
    }

    /// Bring `memberCount` up to the real count (rows created before the counter existed).
    async fn sync_team_member_count(&self, team_id: &str) -> Result<()> {
        let count = self.count_team_members(team_id).await? as i64;
        let mut set = Record::new();
        set.insert("memberCount".into(), count.into());
        let guard = [Where::eq("id", team_id), Where::new("memberCount", Operator::Lt, count)];
        self.db().increment_one("team", &guard, &[], set).await?;
        Ok(())
    }

    async fn release_team_seats(&self, team_id: &str, count: i64) -> Result<()> {
        if count <= 0 {
            return Ok(());
        }
        let guard = [Where::eq("id", team_id), Where::new("memberCount", Operator::Gte, count)];
        self.db().increment_one("team", &guard, &[("memberCount", -count)], Record::new()).await?;
        Ok(())
    }

    /// Create a membership keyed by a deterministic key; an existing one wins a race.
    async fn create_team_member(&self, team_id: &str, user_id: &str, key: &str) -> Result<(bool, Row)> {
        let mut data = Record::new();
        data.insert("teamId".into(), team_id.into());
        data.insert("userId".into(), user_id.into());
        data.insert("membershipKey".into(), key.into());
        data.insert("createdAt".into(), date::now_value());
        match self.db().create("teamMember", data, false).await {
            Ok(m) => Ok((true, m)),
            Err(e) => match self.find_by_key_or_pair(team_id, user_id, key).await? {
                Some(existing) => Ok((false, existing)),
                None => Err(e),
            },
        }
    }

    pub(crate) async fn find_or_create_team_member(&self, team_id: &str, user_id: &str) -> Result<Row> {
        self.auth
            .transaction(async {
                let key = membership_key(team_id, user_id);
                if let Some(existing) = self.find_by_key_or_pair(team_id, user_id, &key).await? {
                    return Ok(self.output("teamMember", existing));
                }
                self.sync_team_member_count(team_id).await?;
                let (created, member) = self.create_team_member(team_id, user_id, &key).await?;
                if created {
                    self.db()
                        .increment_one("team", &[Where::eq("id", team_id)], &[("memberCount", 1)], Record::new())
                        .await?;
                }
                Ok::<_, Error>(self.output("teamMember", member))
            })
            .await
    }

    pub(crate) async fn add_team_member_with_limit(
        &self,
        team_id: &str,
        user_id: &str,
        maximum: usize,
    ) -> Result<AddTeamMember> {
        self.auth
            .transaction(async {
                let key = membership_key(team_id, user_id);
                if let Some(existing) = self.find_by_key_or_pair(team_id, user_id, &key).await? {
                    return Ok(AddTeamMember::Added(self.output("teamMember", existing)));
                }
                self.sync_team_member_count(team_id).await?;
                let guard = [Where::eq("id", team_id), Where::new("memberCount", Operator::Lt, maximum as i64)];
                if self.db().increment_one("team", &guard, &[("memberCount", 1)], Record::new()).await?.is_none() {
                    return Ok(AddTeamMember::LimitReached);
                }
                let created = self.create_team_member(team_id, user_id, &key).await;
                let (created, member) = match created {
                    Ok(r) => r,
                    Err(e) => {
                        self.release_team_seats(team_id, 1).await?;
                        return Err(e);
                    }
                };
                if !created {
                    self.release_team_seats(team_id, 1).await?;
                }
                Ok::<_, Error>(AddTeamMember::Added(self.output("teamMember", member)))
            })
            .await
    }

    pub(crate) async fn remove_team_member(&self, team_id: &str, user_id: &str) -> Result<()> {
        let deleted =
            self.db().delete_many("teamMember", &[Where::eq("teamId", team_id), Where::eq("userId", user_id)]).await?;
        self.release_team_seats(team_id, deleted as i64).await
    }

    // ---- invitations ----------------------------------------------------------------------

    pub(crate) async fn create_invitation(
        &self,
        mut data: Record,
        team_ids: &[String],
        inviter_id: &str,
    ) -> Result<Row> {
        let expires = Utc::now() + chrono::Duration::seconds(self.inner.options.invitation_expires_in);
        let mut row = Record::new();
        row.insert("status".into(), "pending".into());
        row.insert("expiresAt".into(), date::to_value(expires));
        row.insert("createdAt".into(), date::now_value());
        row.insert("inviterId".into(), inviter_id.into());
        data.remove("teamIds");
        row.extend(data);
        if self.inner.options.teams.enabled {
            row.insert("teamId".into(), if team_ids.is_empty() { Value::Null } else { team_ids.join(",").into() });
        } else {
            row.remove("teamId");
        }
        let invitation = self.db().create("invitation", row, true).await?;
        Ok(self.output("invitation", invitation))
    }

    pub(crate) async fn find_invitation_by_id(&self, id: &str) -> Result<Option<Row>> {
        Ok(self.find_one("invitation", &[Where::eq("id", id)]).await?.map(|i| self.output("invitation", i)))
    }

    fn unexpired(rows: Vec<Row>) -> Vec<Row> {
        let now = Utc::now();
        rows.into_iter().filter(|i| i.get("expiresAt").and_then(date::parse_value).is_some_and(|e| e > now)).collect()
    }

    pub(crate) async fn find_pending_invitation(&self, email: &str, organization_id: &str) -> Result<Vec<Row>> {
        let rows = self
            .find_many(
                "invitation",
                vec![
                    Where::eq("email", email.to_lowercase()),
                    Where::eq("organizationId", organization_id),
                    Where::eq("status", "pending"),
                ],
            )
            .await?;
        Ok(Self::unexpired(rows).into_iter().map(|i| self.output("invitation", i)).collect())
    }

    pub(crate) async fn find_pending_invitations(&self, organization_id: &str) -> Result<Vec<Row>> {
        let rows = self
            .find_many("invitation", vec![Where::eq("organizationId", organization_id), Where::eq("status", "pending")])
            .await?;
        Ok(Self::unexpired(rows).into_iter().map(|i| self.output("invitation", i)).collect())
    }

    pub(crate) async fn list_invitations(&self, organization_id: &str) -> Result<Vec<Row>> {
        let rows = self.find_many("invitation", vec![Where::eq("organizationId", organization_id)]).await?;
        Ok(rows.into_iter().map(|i| self.output("invitation", i)).collect())
    }

    /// Pending and other invitations addressed to `email`, with `organizationName`.
    pub(crate) async fn list_user_invitations(&self, email: &str) -> Result<Vec<Row>> {
        let rows = self.find_many("invitation", vec![Where::eq("email", email.to_lowercase())]).await?;
        let org_ids = ids(rows.iter().map(|i| str_field(i, "organizationId").to_owned()));
        let orgs = if rows.is_empty() {
            vec![]
        } else {
            self.find_many("organization", vec![Where::is_in("id", org_ids)]).await?
        };
        Ok(rows
            .into_iter()
            .map(|i| {
                let name = orgs
                    .iter()
                    .find(|o| str_field(o, "id") == str_field(&i, "organizationId"))
                    .map(|o| o["name"].clone());
                let mut row = self.output("invitation", i);
                row.insert("organizationName".into(), name.unwrap_or(Value::Null));
                row
            })
            .collect())
    }

    /// Set an invitation's status, optionally only from `from_status` (compare-and-swap).
    pub(crate) async fn update_invitation(
        &self,
        id: &str,
        status: &str,
        from_status: Option<&str>,
    ) -> Result<Option<Row>> {
        let mut where_ = vec![Where::eq("id", id)];
        if let Some(from) = from_status {
            where_.push(Where::eq("status", from));
        }
        let mut set = Record::new();
        set.insert("status".into(), status.into());
        Ok(self.db().increment_one("invitation", &where_, &[], set).await?.map(|i| self.output("invitation", i)))
    }

    pub(crate) async fn update_invitation_fields(&self, id: &str, data: Record) -> Result<Option<Row>> {
        Ok(self.db().update("invitation", &[Where::eq("id", id)], data).await?.map(|i| self.output("invitation", i)))
    }

    // ---- misc ---------------------------------------------------------------------------

    pub(crate) fn sort(field: Option<String>, direction: Option<&str>) -> Option<SortBy> {
        field.map(|field| SortBy {
            field,
            direction: if direction == Some("desc") { SortDirection::Desc } else { SortDirection::Asc },
        })
    }
}
