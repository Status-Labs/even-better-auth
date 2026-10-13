mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::api::ApiCall;
use even_better_auth::plugins::access::{AccessControl, statements};
use even_better_auth::plugins::organization::{
    InvitationEmail, Limit, OrganizationOptions, TeamOptions, default_statements, organization, value_fn,
};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Invites(Arc<Mutex<Vec<InvitationEmail>>>);

async fn setup(configure: impl FnOnce(&mut OrganizationOptions)) -> (Client, Invites) {
    let (mut o, _) = options();
    let invites = Invites::default();
    let sink = invites.0.clone();
    let mut opts = OrganizationOptions {
        send_invitation_email: Some(even_better_auth::options::Callback::new(move |m: InvitationEmail| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(m);
                Ok(())
            }
        })),
        ..Default::default()
    };
    configure(&mut opts);
    o.plugins.push(organization(opts));
    let mut owner = Client::build(o).await;
    owner.sign_up("owner@test.com", "password1234").await;
    (owner, invites)
}

/// A signed-in user with a verified email.
async fn user(owner: &Client, email: &str) -> (Client, String) {
    let mut c = Client::new(owner.auth.clone());
    let res = c.sign_up(email, "password1234").await;
    let mut verified = serde_json::Map::new();
    verified.insert("emailVerified".into(), true.into());
    owner.auth.context().internal_adapter.update_user_by_email(email, verified).await.unwrap();
    (c, res.body["user"]["id"].as_str().unwrap().to_owned())
}

async fn create_org(c: &mut Client, slug: &str) -> Value {
    let res = c.post("/organization/create", json!({ "name": format!("Org {slug}"), "slug": slug })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    res.body
}

/// Invite `email` as `role` and accept as `invitee`, returning the membership.
async fn invite_and_accept(owner: &mut Client, invitee: &mut Client, email: &str, role: &str) -> Value {
    let inv = owner.post("/organization/invite-member", json!({ "email": email, "role": role })).await;
    assert_eq!(inv.status, 200, "{}", inv.text);
    let res = invitee.post("/organization/accept-invitation", json!({ "invitationId": inv.body["id"] })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    res.body["member"].clone()
}

#[tokio::test]
async fn organization_lifecycle() {
    let (mut owner, _) = setup(|_| {}).await;
    let org = create_org(&mut owner, "acme").await;
    assert_eq!(org["members"][0]["role"], "owner");
    let org_id = org["id"].as_str().unwrap().to_owned();
    assert_eq!(owner.get("/get-session").await.body["session"]["activeOrganizationId"], org_id.as_str());

    assert_eq!(
        owner.post("/organization/check-slug", json!({ "slug": "acme" })).await.body["code"],
        "ORGANIZATION_SLUG_ALREADY_TAKEN"
    );
    assert_eq!(owner.post("/organization/check-slug", json!({ "slug": "free" })).await.body["status"], true);
    let dup = owner.post("/organization/create", json!({ "name": "Again", "slug": "acme" })).await;
    assert_eq!(dup.body["code"], "ORGANIZATION_ALREADY_EXISTS");

    let res = owner
        .post("/organization/update", json!({ "data": { "name": "Acme Inc", "metadata": { "tier": "pro" } } }))
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!((res.body["name"].as_str(), res.body["metadata"]["tier"].as_str()), (Some("Acme Inc"), Some("pro")));

    let full = owner.get("/organization/get-full-organization").await.body;
    assert_eq!(full["slug"], "acme");
    assert_eq!(full["members"][0]["user"]["email"], "owner@test.com");
    assert!(full["invitations"].as_array().unwrap().is_empty());
    assert_eq!(owner.get("/organization/get-organization?organizationSlug=acme").await.body["id"], org_id.as_str());

    create_org(&mut owner, "beta").await;
    assert_eq!(owner.get("/organization/list").await.body.as_array().unwrap().len(), 2);
    let res = owner.post("/organization/set-active", json!({ "organizationSlug": "acme" })).await;
    assert_eq!(res.body["id"], org_id.as_str());
    assert_eq!(owner.post("/organization/set-active", json!({ "organizationId": null })).await.body, Value::Null);
    assert!(owner.get("/get-session").await.body["session"]["activeOrganizationId"].is_null());

    let (mut stranger, _) = user(&owner, "stranger@test.com").await;
    let res = stranger.post("/organization/set-active", json!({ "organizationId": org_id })).await;
    assert_eq!(res.body["code"], "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
    let res = stranger.post("/organization/delete", json!({ "organizationId": org_id })).await;
    assert_eq!(res.body["code"], "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION");
    let res = owner.post("/organization/delete", json!({ "organizationId": org_id })).await;
    assert_eq!((res.status, res.body["id"].as_str()), (200, Some(org_id.as_str())), "{}", res.text);
    assert_eq!(owner.get("/organization/list").await.body.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn invitations_and_roles() {
    let (mut owner, invites) = setup(|_| {}).await;
    create_org(&mut owner, "acme").await;
    let (mut admin, admin_id) = user(&owner, "admin@test.com").await;
    let (mut member, _) = user(&owner, "member@test.com").await;

    let inv = owner.post("/organization/invite-member", json!({ "email": "Admin@Test.com", "role": "admin" })).await;
    assert_eq!(inv.status, 200, "{}", inv.text);
    assert_eq!((inv.body["email"].as_str(), inv.body["status"].as_str()), (Some("admin@test.com"), Some("pending")));
    let email = invites.0.lock().unwrap().last().cloned().unwrap();
    assert_eq!((email.email.as_str(), email.role.as_str()), ("admin@test.com", "admin"));
    assert_eq!(email.inviter["user"]["email"], "owner@test.com");
    let again = owner.post("/organization/invite-member", json!({ "email": "admin@test.com", "role": "admin" })).await;
    assert_eq!(again.body["code"], "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION");

    let (mut unverified, _) = (Client::new(owner.auth.clone()), ());
    unverified.sign_up("unverified@test.com", "password1234").await;
    let res = unverified.get("/organization/list-user-invitations").await;
    assert_eq!(res.body["code"], "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION");
    let pending = admin.get("/organization/list-user-invitations").await;
    assert_eq!(pending.body[0]["organizationName"], "Org acme");
    let details = admin.get(&format!("/organization/get-invitation?id={}", inv.body["id"].as_str().unwrap())).await;
    assert_eq!(details.body["inviterEmail"], "owner@test.com");
    assert_eq!(
        member.post("/organization/accept-invitation", json!({ "invitationId": inv.body["id"] })).await.body["code"],
        "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"
    );
    let accepted = admin.post("/organization/accept-invitation", json!({ "invitationId": inv.body["id"] })).await;
    assert_eq!(accepted.status, 200, "{}", accepted.text);
    assert_eq!(
        (accepted.body["invitation"]["status"].as_str(), accepted.body["member"]["role"].as_str()),
        (Some("accepted"), Some("admin"))
    );
    assert_eq!(admin.get("/organization/get-active-member").await.body["user"]["email"], "admin@test.com");

    // Admins may invite but not as owner; unknown roles are rejected.
    let res = admin.post("/organization/invite-member", json!({ "email": "x@test.com", "role": "owner" })).await;
    assert_eq!(res.body["code"], "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE");
    let res = admin.post("/organization/invite-member", json!({ "email": "x@test.com", "role": "wizard" })).await;
    assert_eq!(res.status, 400);
    assert!(res.body["message"].as_str().unwrap().contains("wizard"));

    let m_inv =
        admin.post("/organization/invite-member", json!({ "email": "member@test.com", "role": "member" })).await;
    let res = member.post("/organization/reject-invitation", json!({ "invitationId": m_inv.body["id"] })).await;
    assert_eq!(res.body["invitation"]["status"], "rejected");
    let m_inv =
        admin.post("/organization/invite-member", json!({ "email": "member@test.com", "role": "member" })).await;
    let res = admin.post("/organization/cancel-invitation", json!({ "invitationId": m_inv.body["id"] })).await;
    assert_eq!(res.body["status"], "canceled");
    let member_row = invite_and_accept(&mut admin, &mut member, "member@test.com", "member").await;
    assert_eq!(owner.get("/organization/list-invitations").await.body.as_array().unwrap().len(), 4);

    // Members cannot invite; permission checks reflect roles.
    assert_eq!(
        member.post("/organization/invite-member", json!({ "email": "y@test.com", "role": "member" })).await.status,
        403
    );
    let check = json!({ "permissions": { "member": ["delete"] } });
    assert_eq!(member.post("/organization/has-permission", check.clone()).await.body["success"], false);
    assert_eq!(admin.post("/organization/has-permission", check).await.body["success"], true);
    assert_eq!(member.get("/organization/get-active-member-role").await.body["role"], "member");
    let role = member.get(&format!("/organization/get-active-member-role?userId={admin_id}")).await;
    assert_eq!(role.body["role"], "admin");

    // Role changes: admins can't touch owners or grant owner.
    let me_owner = owner.get("/organization/get-active-member").await.body["id"].clone();
    let res = admin.post("/organization/update-member-role", json!({ "memberId": me_owner, "role": "member" })).await;
    assert_eq!(res.body["code"], "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER");
    let res =
        admin.post("/organization/update-member-role", json!({ "memberId": member_row["id"], "role": "owner" })).await;
    assert_eq!(res.body["code"], "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER");
    let res = admin
        .post("/organization/update-member-role", json!({ "memberId": member_row["id"], "role": ["admin", "member"] }))
        .await;
    assert_eq!(res.body["role"], "admin,member", "{}", res.text);
    let res = owner.post("/organization/update-member-role", json!({ "memberId": me_owner, "role": "admin" })).await;
    assert_eq!(res.body["code"], "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER");

    // Listing, removal and leaving.
    let list = owner.get("/organization/list-members?limit=2&sortBy=createdAt").await.body;
    assert_eq!((list["total"].as_u64(), list["members"].as_array().unwrap().len()), (Some(3), 2));
    let res =
        owner.post("/organization/leave", json!({ "organizationId": list["members"][0]["organizationId"] })).await;
    assert_eq!(res.body["code"], "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER");
    let res = member.post("/organization/remove-member", json!({ "memberIdOrEmail": "admin@test.com" })).await;
    assert_eq!(res.status, 200, "member now has admin role too: {}", res.text);
    let res = owner.post("/organization/remove-member", json!({ "memberIdOrEmail": member_row["id"] })).await;
    assert_eq!(res.body["member"]["userId"], member_row["userId"], "{}", res.text);
    assert_eq!(owner.get("/organization/list-members").await.body["total"], 1);
}

#[tokio::test]
async fn teams() {
    let (mut owner, _) = setup(|o| {
        o.teams = TeamOptions { enabled: true, maximum_members_per_team: Some(Limit::Fixed(2)), ..Default::default() };
    })
    .await;
    let org = create_org(&mut owner, "teams").await;
    let teams = owner.get("/organization/list-teams").await.body;
    assert_eq!(teams.as_array().unwrap().len(), 1, "a default team is created");
    assert_eq!(teams[0]["name"], "Org teams");
    assert!(teams[0].get("memberCount").is_none(), "the seat counter is internal");
    let default_team = teams[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(owner.get("/get-session").await.body["session"]["activeTeamId"], default_team.as_str());

    let team = owner.post("/organization/create-team", json!({ "name": "Eng" })).await;
    assert_eq!(team.status, 200, "{}", team.text);
    let team_id = team.body["id"].as_str().unwrap().to_owned();
    let (mut a, a_id) = user(&owner, "a@test.com").await;
    let (mut b, b_id) = user(&owner, "b@test.com").await;
    let (mut c, c_id) = user(&owner, "c@test.com").await;
    let inv = owner
        .post("/organization/invite-member", json!({ "email": "a@test.com", "role": "member", "teamId": team_id }))
        .await;
    assert_eq!(inv.body["teamId"], team_id.as_str(), "{}", inv.text);
    a.post("/organization/accept-invitation", json!({ "invitationId": inv.body["id"] })).await;
    assert_eq!(a.get("/get-session").await.body["session"]["activeTeamId"], team_id.as_str());
    invite_and_accept(&mut owner, &mut b, "b@test.com", "member").await;
    invite_and_accept(&mut owner, &mut c, "c@test.com", "member").await;

    let res = owner.post("/organization/add-team-member", json!({ "teamId": team_id, "userId": b_id })).await;
    assert_eq!(res.body["userId"], b_id.as_str(), "{}", res.text);
    let res = owner.post("/organization/add-team-member", json!({ "teamId": team_id, "userId": c_id })).await;
    assert_eq!(res.body["code"], "TEAM_MEMBER_LIMIT_REACHED");
    let members = a.get("/organization/list-team-members").await.body;
    assert_eq!(members.as_array().unwrap().len(), 2);
    assert!(members[0].get("membershipKey").is_none());
    let mine = a.get("/organization/list-user-teams").await.body;
    assert_eq!(mine.as_array().unwrap().iter().map(|t| t["id"].clone()).collect::<Vec<_>>(), vec![json!(team_id)]);
    let other = owner.get(&format!("/organization/list-user-teams?userId={a_id}")).await.body;
    assert_eq!(other.as_array().unwrap().len(), 1);

    let res = owner.post("/organization/remove-team-member", json!({ "teamId": team_id, "userId": b_id })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let res = owner.post("/organization/add-team-member", json!({ "teamId": team_id, "userId": c_id })).await;
    assert_eq!(res.status, 200, "a seat was released: {}", res.text);

    let res =
        owner.post("/organization/update-team", json!({ "teamId": team_id, "data": { "name": "Engineering" } })).await;
    assert_eq!(res.body["name"], "Engineering");
    assert_eq!(
        owner.post("/organization/set-active-team", json!({ "teamId": team_id })).await.status,
        403,
        "owner is not on the team"
    );
    let res = owner.post("/organization/remove-team", json!({ "teamId": team_id })).await;
    assert_eq!(res.body["message"], "Team removed successfully.", "{}", res.text);
    let res = a.post("/organization/remove-team", json!({ "teamId": default_team })).await;
    assert_eq!(res.status, 403, "members cannot remove teams");
    let res = owner.post("/organization/set-active-team", json!({ "teamId": null })).await;
    assert_eq!(res.body, Value::Null);
    let res =
        owner.post("/organization/remove-team", json!({ "teamId": default_team, "organizationId": org["id"] })).await;
    assert_eq!(res.body["code"], "UNABLE_TO_REMOVE_LAST_TEAM");
}

#[tokio::test]
async fn dynamic_roles() {
    let ac = AccessControl::new(default_statements());
    let (mut owner, _) = setup(move |o| {
        o.ac = Some(ac);
        o.dynamic_access_control.enabled = true;
    })
    .await;
    create_org(&mut owner, "dyn").await;
    let res = owner
        .post(
            "/organization/create-role",
            json!({ "role": "Support", "permission": { "member": ["delete"], "invitation": ["create"] } }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(
        (res.body["roleData"]["role"].as_str(), res.body["roleData"]["permission"]["member"][0].as_str()),
        (Some("support"), Some("delete"))
    );
    let res = owner.post("/organization/create-role", json!({ "role": "admin", "permission": {} })).await;
    assert_eq!(res.body["code"], "ROLE_NAME_IS_ALREADY_TAKEN");
    let res =
        owner.post("/organization/create-role", json!({ "role": "x", "permission": { "billing": ["read"] } })).await;
    assert_eq!(res.body["code"], "INVALID_RESOURCE");

    let (mut s, _) = user(&owner, "support@test.com").await;
    let row = invite_and_accept(&mut owner, &mut s, "support@test.com", "support").await;
    assert_eq!(row["role"], "support");
    let check = s.post("/organization/has-permission", json!({ "permissions": { "member": ["delete"] } })).await;
    assert_eq!(check.body["success"], true, "database roles grant permissions");
    assert_eq!(
        s.post("/organization/has-permission", json!({ "permissions": { "organization": ["delete"] } })).await.body["success"],
        false
    );

    assert_eq!(owner.get("/organization/list-roles").await.body.as_array().unwrap().len(), 1);
    assert_eq!(
        owner.get("/organization/get-role?roleName=support").await.body["permission"]["invitation"][0],
        "create"
    );
    let res = owner
        .post(
            "/organization/update-role",
            json!({ "roleName": "support", "data": { "permission": { "member": ["delete", "update"] } } }),
        )
        .await;
    assert_eq!(res.body["roleData"]["permission"]["member"], json!(["delete", "update"]), "{}", res.text);
    let res = owner.post("/organization/delete-role", json!({ "roleName": "support" })).await;
    assert_eq!(res.body["code"], "ROLE_IS_ASSIGNED_TO_MEMBERS");
    assert_eq!(
        owner.post("/organization/delete-role", json!({ "roleName": "owner" })).await.body["code"],
        "CANNOT_DELETE_A_PRE_DEFINED_ROLE"
    );
    owner.post("/organization/remove-member", json!({ "memberIdOrEmail": "support@test.com" })).await;
    assert_eq!(owner.post("/organization/delete-role", json!({ "roleName": "support" })).await.body["success"], true);
}

#[tokio::test]
async fn hooks_limits_and_server_calls() {
    let created = Arc::new(Mutex::new(Vec::<Value>::new()));
    let log = created.clone();
    let (mut owner, _) = setup(move |o| {
        o.organization_limit = Some(even_better_auth::plugins::organization::OrganizationLimit::Count(1));
        o.hooks.before_create_organization = Some(value_fn(|arg: Value| async move {
            let mut extra = serde_json::Map::new();
            extra.insert(
                "logo".into(),
                format!("https://logo/{}", arg["organization"]["slug"].as_str().unwrap()).into(),
            );
            Ok(Some(extra))
        }));
        o.hooks.after_create_organization = Some(value_fn(move |arg: Value| {
            let log = log.clone();
            async move {
                log.lock().unwrap().push(arg);
                Ok(None)
            }
        }));
    })
    .await;
    let org = create_org(&mut owner, "hooked").await;
    assert_eq!(org["logo"], "https://logo/hooked");
    assert_eq!(created.lock().unwrap()[0]["member"]["role"], "owner");
    let res = owner.post("/organization/create", json!({ "name": "Two", "slug": "two" })).await;
    assert_eq!(res.body["code"], "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS");

    // addMember is server-only.
    let (_, new_id) = user(&owner, "added@test.com").await;
    assert_eq!(owner.post("/organization/add-member", json!({ "userId": new_id, "role": "member" })).await.status, 404);
    let added = owner
        .auth
        .api(
            ApiCall::new("addMember")
                .body(json!({ "userId": new_id, "role": ["member", "admin"], "organizationId": org["id"] })),
        )
        .await
        .unwrap();
    assert_eq!(added.json()["role"], "member,admin");
    let again = owner
        .auth
        .api(ApiCall::new("addMember").body(json!({ "userId": new_id, "role": "member", "organizationId": org["id"] })))
        .await;
    assert_eq!(again.unwrap_err().code(), Some("USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION"));
    let _ = statements(&[]);
}
