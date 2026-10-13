mod common;

use std::collections::BTreeMap;

use common::{Client, options};
use even_better_auth::api::ApiCall;
use even_better_auth::plugins::access::{AccessControl, statements};
use even_better_auth::plugins::admin::{AdminOptions, admin};
use serde_json::{Value, json};

/// A server with an admin (`admin@test.com`) and a regular user, both signed in.
async fn setup(configure: impl FnOnce(&mut AdminOptions)) -> (Client, Client, String) {
    let (mut o, _) = options();
    let mut opts = AdminOptions::default();
    configure(&mut opts);
    o.plugins.push(admin(opts).unwrap());
    let mut admin = Client::build(o).await;
    admin.sign_up("admin@test.com", "password1234").await;
    let mut user = Client::new(admin.auth.clone());
    let res = user.sign_up("user@test.com", "password1234").await;
    let user_id = res.body["user"]["id"].as_str().unwrap().to_owned();
    let admin_id = admin.get("/get-session").await.body["user"]["id"].as_str().unwrap().to_owned();
    let mut update = serde_json::Map::new();
    update.insert("role".into(), "admin".into());
    admin.auth.context().internal_adapter.update_user(&admin_id, update).await.unwrap();
    (admin, user, user_id)
}

#[tokio::test]
async fn roles_and_permissions() {
    let (mut admin, mut user, user_id) = setup(|_| {}).await;
    assert_eq!(user.get("/get-session").await.body["user"]["role"], "user", "new users get the default role");
    let res = user.get("/admin/list-users").await;
    assert_eq!((res.status, res.body["code"].as_str()), (403, Some("YOU_ARE_NOT_ALLOWED_TO_LIST_USERS")));
    let res = user
        .post(
            "/sign-up/email",
            json!({ "email": "x@test.com", "password": "password1234", "name": "x", "role": "admin" }),
        )
        .await;
    assert_eq!(res.status, 400, "role is not user input: {}", res.text);

    let res = admin.get("/admin/list-users?limit=1&sortBy=email&sortDirection=asc").await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!((res.body["total"].as_u64(), res.body["limit"].as_u64()), (Some(2), Some(1)));
    assert_eq!(res.body["users"][0]["email"], "admin@test.com");
    let res = admin.get("/admin/list-users?searchValue=user&searchField=email&searchOperator=starts_with").await;
    assert_eq!(res.body["users"].as_array().unwrap().len(), 1);
    let res = admin.get("/admin/list-users?filterField=role&filterValue=admin").await;
    assert_eq!(res.body["users"][0]["email"], "admin@test.com");

    let res = admin.get(&format!("/admin/get-user?id={user_id}")).await;
    assert_eq!(res.body["email"], "user@test.com");
    let res = admin.post("/admin/set-role", json!({ "userId": user_id, "role": ["user", "admin"] })).await;
    assert_eq!(res.body["user"]["role"], "user,admin", "{}", res.text);

    let res = admin.post("/admin/has-permission", json!({ "permissions": { "user": ["ban"] } })).await;
    assert_eq!(res.body["success"], true);
    let check = |role: &str| {
        ApiCall::new("userHasPermission").body(json!({ "role": role, "permissions": { "user": ["list"] } }))
    };
    assert_eq!(admin.auth.api(check("user")).await.unwrap().json()["success"], false);
    assert_eq!(admin.auth.api(check("admin")).await.unwrap().json()["success"], true);
}

#[tokio::test]
async fn create_update_and_remove_users() {
    let (mut admin, _, user_id) = setup(|_| {}).await;
    let res = admin
        .post("/admin/create-user", json!({ "email": "New@Test.com", "password": "password1234", "name": "New", "role": "admin", "data": { "image": "i.png" } }))
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(
        (res.body["user"]["email"].as_str(), res.body["user"]["role"].as_str()),
        (Some("new@test.com"), Some("admin"))
    );
    let mut created = Client::new(admin.auth.clone());
    assert_eq!(created.sign_in("new@test.com", "password1234").await.status, 200);
    assert_eq!(
        admin.post("/admin/create-user", json!({ "email": "new@test.com", "name": "x" })).await.body["code"],
        "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
    );

    let res = admin
        .post(
            "/admin/update-user",
            json!({ "userId": user_id, "data": { "name": "Renamed", "email": "Moved@Test.com" } }),
        )
        .await;
    assert_eq!(
        (res.body["name"].as_str(), res.body["email"].as_str()),
        (Some("Renamed"), Some("moved@test.com")),
        "{}",
        res.text
    );
    let res = admin.post("/admin/update-user", json!({ "userId": user_id, "data": { "password": "x" } })).await;
    assert_eq!(res.body["code"], "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER");
    assert_eq!(
        admin.post("/admin/update-user", json!({ "userId": user_id, "data": {} })).await.body["code"],
        "NO_DATA_TO_UPDATE"
    );

    assert_eq!(
        admin
            .post("/admin/set-user-password", json!({ "userId": user_id, "newPassword": "brand-new-pass" }))
            .await
            .status,
        200
    );
    let mut moved = Client::new(admin.auth.clone());
    assert_eq!(moved.sign_in("moved@test.com", "brand-new-pass").await.status, 200);

    let me = admin.get("/get-session").await.body["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        admin.post("/admin/remove-user", json!({ "userId": me })).await.body["code"],
        "YOU_CANNOT_REMOVE_YOURSELF"
    );
    assert_eq!(admin.post("/admin/remove-user", json!({ "userId": user_id })).await.status, 200);
    assert_eq!(moved.get("/get-session").await.body, Value::Null);
    assert_eq!(admin.get(&format!("/admin/get-user?id={user_id}")).await.status, 404);
}

#[tokio::test]
async fn bans_block_sign_in_until_lifted_or_expired() {
    let (mut admin, mut user, user_id) = setup(|_| {}).await;
    let res = admin.post("/admin/ban-user", json!({ "userId": user_id, "banReason": "spam" })).await;
    assert_eq!(
        (res.body["user"]["banned"].as_bool(), res.body["user"]["banReason"].as_str()),
        (Some(true), Some("spam"))
    );
    assert_eq!(user.get("/get-session").await.body, Value::Null, "sessions are revoked");
    user.jar.clear();
    let res = user.sign_in("user@test.com", "password1234").await;
    assert_eq!((res.status, res.body["code"].as_str()), (403, Some("BANNED_USER")), "{}", res.text);
    assert!(res.body["message"].as_str().unwrap().contains("banned"));

    admin.post("/admin/unban-user", json!({ "userId": user_id })).await;
    assert_eq!(user.sign_in("user@test.com", "password1234").await.status, 200);

    admin.post("/admin/ban-user", json!({ "userId": user_id, "banExpiresIn": 1 })).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    user.jar.clear();
    assert_eq!(user.sign_in("user@test.com", "password1234").await.status, 200, "an expired ban is lifted at sign-in");
    let me = admin.get("/get-session").await.body["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(admin.post("/admin/ban-user", json!({ "userId": me })).await.body["code"], "YOU_CANNOT_BAN_YOURSELF");
}

#[tokio::test]
async fn impersonation_round_trip() {
    let (mut admin, _, user_id) = setup(|_| {}).await;
    let res = admin.post("/admin/impersonate-user", json!({ "userId": user_id })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(res.body["session"]["impersonatedBy"].is_string());
    assert_eq!(admin.get("/get-session").await.body["user"]["email"], "user@test.com");
    let sessions = admin.get("/list-sessions").await.body;
    let sessions = sessions.as_array().unwrap();
    assert_eq!(sessions.len(), 1, "only the user's own session is listed");
    assert!(sessions.iter().all(|s| s.get("impersonatedBy").is_none()), "impersonation sessions are hidden");
    let res = admin.post("/admin/stop-impersonating", json!({})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(admin.get("/get-session").await.body["user"]["email"], "admin@test.com");
    assert_eq!(admin.post("/admin/stop-impersonating", json!({})).await.status, 400);

    let res = admin.post("/admin/list-user-sessions", json!({ "userId": user_id })).await;
    assert_eq!(res.body["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(admin.post("/admin/revoke-user-sessions", json!({ "userId": user_id })).await.body["success"], true);
    let res = admin.post("/admin/list-user-sessions", json!({ "userId": user_id })).await;
    assert!(res.body["sessions"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn admins_cannot_be_impersonated_without_permission() {
    let (mut admin, _, user_id) = setup(|_| {}).await;
    admin.post("/admin/set-role", json!({ "userId": user_id, "role": "admin" })).await;
    let res = admin.post("/admin/impersonate-user", json!({ "userId": user_id })).await;
    assert_eq!(res.body["code"], "YOU_CANNOT_IMPERSONATE_ADMINS");
    let (mut admin, _, user_id) = setup(|o| o.allow_impersonating_admins = true).await;
    admin.post("/admin/set-role", json!({ "userId": user_id, "role": "admin" })).await;
    assert_eq!(admin.post("/admin/impersonate-user", json!({ "userId": user_id })).await.status, 200);
}

#[tokio::test]
async fn custom_roles() {
    let ac = AccessControl::new(statements(&[("user", &["list", "get"]), ("project", &["create"])]));
    let roles = BTreeMap::from([
        ("admin".to_owned(), ac.new_role(statements(&[("user", &["list", "get"])]))),
        ("support".to_owned(), ac.new_role(statements(&[("user", &["get"])]))),
        ("user".to_owned(), ac.new_role(statements(&[]))),
    ]);
    let (mut admin, _, user_id) = setup(|o| o.roles = Some(roles)).await;
    assert_eq!(admin.get("/admin/list-users").await.status, 200);
    let res = admin.post("/admin/set-role", json!({ "userId": user_id, "role": "support" })).await;
    assert_eq!(res.body["code"], "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE", "custom admin role lacks set-role");
    assert!(
        even_better_auth::plugins::admin::admin(AdminOptions {
            admin_roles: vec!["owner".into()],
            ..Default::default()
        })
        .is_err()
    );
}
