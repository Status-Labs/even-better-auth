//! The full better-auth stack on a SQL database: migrate, sign up, sign in, get session,
//! sign out. SQLite always runs; Postgres/MySQL run when their URL env var is set.

use std::sync::Arc;

use bytes::Bytes;
use even_better_auth::db::Where;
use even_better_auth::{BetterAuth, BetterAuthOptions, EmailAndPasswordOptions};
use even_better_auth_sqlx::SqlxAdapter;
use serde_json::{Value, json};

const BASE: &str = "http://localhost:3000";

struct Res {
    status: u16,
    body: Value,
    cookies: Vec<String>,
}

async fn request(auth: &BetterAuth, method: &str, path: &str, cookie: Option<&str>, body: Option<Value>) -> Res {
    let mut req = http::Request::builder().method(method).uri(format!("{BASE}/api/auth{path}")).header("origin", BASE);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    let bytes = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Bytes::from(b.to_string())
        }
        None => Bytes::new(),
    };
    let res = auth.handler(req.body(bytes).unwrap()).await;
    let cookies = res.headers().get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_owned()).collect();
    let body = serde_json::from_slice(res.body()).unwrap_or(Value::Null);
    Res { status: res.status().as_u16(), body, cookies }
}

fn session_cookie(res: &Res) -> String {
    let c = res.cookies.iter().find(|c| c.starts_with("better-auth.session_token=")).expect("session cookie");
    c.split(';').next().unwrap().to_owned()
}

async fn run_stack(adapter: SqlxAdapter) {
    let email = format!("{}@test.com", even_better_auth::db::testing::random_suffix());
    let mut o = BetterAuthOptions::new(Arc::new(adapter));
    o.base_url = Some(BASE.into());
    o.secret = Some("better-auth-secret-that-is-long-enough-for-tests".into());
    o.email_and_password = EmailAndPasswordOptions::enabled();
    o.rate_limit.enabled = Some(false);
    let auth = BetterAuth::new(o).await.unwrap();
    auth.migrate().await.unwrap();
    auth.migrate().await.unwrap();

    let body = json!({ "email": email, "password": "password1234", "name": "E2E" });
    let res = request(&auth, "POST", "/sign-up/email", None, Some(body.clone())).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert_eq!(res.body["user"]["email"], email);
    assert_eq!(res.body["user"]["emailVerified"], false);
    assert!(res.body["user"]["createdAt"].as_str().is_some_and(|s| s.ends_with('Z')));

    let dup = request(&auth, "POST", "/sign-up/email", None, Some(body)).await;
    assert_eq!(dup.status, 422);
    assert_eq!(dup.body["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");

    let creds = json!({ "email": email, "password": "password1234" });
    let res = request(&auth, "POST", "/sign-in/email", None, Some(creds)).await;
    assert_eq!(res.status, 200, "{}", res.body);
    let cookie = session_cookie(&res);

    let session = request(&auth, "GET", "/get-session", Some(&cookie), None).await;
    assert_eq!(session.status, 200);
    assert_eq!(session.body["user"]["email"], email);
    assert_eq!(session.body["user"]["name"], "E2E");
    assert!(session.body["session"]["expiresAt"].as_str().is_some());

    let db = auth.context().db.clone();
    let user_id = session.body["user"]["id"].clone();
    assert_eq!(
        db.count("session", &[Where::eq("userId", user_id.clone())]).await.unwrap(),
        2,
        "sign-up and sign-in sessions"
    );
    let account = db.find_one("account", &[Where::eq("userId", user_id)]).await.unwrap().unwrap();
    assert_eq!(account["providerId"], "credential");
    assert!(account["password"].as_str().is_some_and(|p| !p.is_empty()));

    let wrong = json!({ "email": email, "password": "wrong-password" });
    assert_eq!(request(&auth, "POST", "/sign-in/email", None, Some(wrong)).await.status, 401);

    let res = request(&auth, "POST", "/sign-out", Some(&cookie), Some(json!({}))).await;
    assert_eq!(res.status, 200);
    let session = request(&auth, "GET", "/get-session", Some(&cookie), None).await;
    assert!(session.body.is_null());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn full_stack_on_sqlite() {
    run_stack(SqlxAdapter::connect("sqlite::memory:").await.unwrap()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn full_stack_on_postgres() {
    match std::env::var("DATABASE_URL_POSTGRES") {
        Ok(url) if !url.is_empty() => run_stack(SqlxAdapter::connect(&url).await.unwrap()).await,
        _ => eprintln!("skipping: DATABASE_URL_POSTGRES is not set"),
    }
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn full_stack_on_mysql() {
    match std::env::var("DATABASE_URL_MYSQL") {
        Ok(url) if !url.is_empty() => run_stack(SqlxAdapter::connect(&url).await.unwrap()).await,
        _ => eprintln!("skipping: DATABASE_URL_MYSQL is not set"),
    }
}

/// Plugin tables migrate and work on SQL: organization (with teams), admin, two-factor,
/// username and jwt.
async fn run_plugins(adapter: SqlxAdapter) {
    use even_better_auth::plugins;
    let suffix = even_better_auth::db::testing::random_suffix();
    let mut o = BetterAuthOptions::new(Arc::new(adapter));
    o.base_url = Some(BASE.into());
    o.secret = Some("better-auth-secret-that-is-long-enough-for-tests".into());
    o.email_and_password = EmailAndPasswordOptions::enabled();
    o.rate_limit.enabled = Some(false);
    o.plugins.push(plugins::organization::organization(plugins::organization::OrganizationOptions {
        teams: plugins::organization::TeamOptions { enabled: true, ..Default::default() },
        require_email_verification_on_invitation: Some(false),
        ..Default::default()
    }));
    o.plugins.push(plugins::admin::admin(Default::default()).unwrap());
    o.plugins.push(plugins::two_factor::two_factor(Default::default()));
    o.plugins.push(plugins::username::username(Default::default()));
    o.plugins.push(plugins::jwt::jwt(Default::default()).unwrap());
    o.plugins.push(plugins::api_key::api_key(plugins::api_key::ApiKeyOptions {
        enable_metadata: true,
        ..Default::default()
    }));
    o.plugins.push(plugins::passkey::passkey(Default::default()));
    let auth = BetterAuth::new(o).await.unwrap();
    auth.migrate().await.unwrap();
    auth.migrate().await.unwrap();

    let owner_email = format!("owner-{suffix}@test.com");
    let body = json!({ "email": owner_email, "password": "password1234", "name": "Owner", "username": format!("owner_{suffix}") });
    let res = request(&auth, "POST", "/sign-up/email", None, Some(body)).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert_eq!(res.body["user"]["role"], "user");
    let owner = session_cookie(&res);
    let res = request(
        &auth,
        "POST",
        "/sign-in/username",
        None,
        Some(json!({ "username": format!("OWNER_{suffix}"), "password": "password1234" })),
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.body);

    let res = request(
        &auth,
        "POST",
        "/organization/create",
        Some(&owner),
        Some(json!({ "name": "SQL Org", "slug": format!("sql-{suffix}") })),
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.body);
    let res = request(&auth, "POST", "/organization/create-team", Some(&owner), Some(json!({ "name": "Team" }))).await;
    assert_eq!(res.status, 200, "{}", res.body);
    let team_id = res.body["id"].as_str().unwrap().to_owned();

    let member_email = format!("member-{suffix}@test.com");
    let res = request(
        &auth,
        "POST",
        "/sign-up/email",
        None,
        Some(json!({ "email": member_email, "password": "password1234", "name": "M" })),
    )
    .await;
    let member = session_cookie(&res);
    let member_id = res.body["user"]["id"].as_str().unwrap().to_owned();
    let invite = json!({ "email": member_email, "role": "member", "teamId": team_id });
    let res = request(&auth, "POST", "/organization/invite-member", Some(&owner), Some(invite)).await;
    assert_eq!(res.status, 200, "{}", res.body);
    let res = request(
        &auth,
        "POST",
        "/organization/accept-invitation",
        Some(&member),
        Some(json!({ "invitationId": res.body["id"] })),
    )
    .await;
    assert_eq!(res.status, 200, "{}", res.body);
    let res =
        request(&auth, "GET", &format!("/organization/list-team-members?teamId={team_id}"), Some(&member), None).await;
    assert_eq!(res.body.as_array().map(Vec::len), Some(1), "{}", res.body);
    assert_eq!(res.body[0]["userId"], member_id.as_str());
    let full = request(&auth, "GET", "/organization/get-full-organization", Some(&owner), None).await;
    assert_eq!(full.body["members"].as_array().map(Vec::len), Some(2), "{}", full.body);

    let res =
        request(&auth, "POST", "/two-factor/enable", Some(&owner), Some(json!({ "password": "password1234" }))).await;
    assert_eq!(res.status, 200, "{}", res.body);
    let res = request(&auth, "GET", "/token", Some(&owner), None).await;
    assert!(res.body["token"].as_str().is_some_and(|t| t.split('.').count() == 3), "{}", res.body);
    let res = request(&auth, "GET", "/jwks", None, None).await;
    assert_eq!(res.body["keys"][0]["alg"], "EdDSA");

    let res = request(&auth, "GET", "/passkey/generate-register-options", Some(&owner), None).await;
    assert_eq!(res.body["rp"]["id"], "localhost", "{}", res.body);
    let res = request(&auth, "GET", "/passkey/list-user-passkeys", Some(&owner), None).await;
    assert_eq!(res.body, json!([]));

    run_api_keys(&auth, &owner).await;
}

/// API keys on SQL: the guarded quota, refill and rate-limit writes rely on the database's
/// NULL and date comparisons.
async fn run_api_keys(auth: &BetterAuth, cookie: &str) {
    use even_better_auth::api::ApiCall;
    let call = |endpoint: &'static str, body: Value| async move {
        match auth.api(ApiCall::new(endpoint).body(body)).await {
            Ok(r) => r.json(),
            Err(e) => e.to_json(),
        }
    };
    let res = request(auth, "POST", "/api-key/create", Some(cookie), Some(json!({ "metadata": { "tier": 1 } }))).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert_eq!(res.body["metadata"], json!({ "tier": 1 }));
    let user_id = res.body["referenceId"].clone();
    let listed = request(auth, "GET", "/api-key/list?sortBy=createdAt&sortDirection=desc", Some(cookie), None).await;
    assert_eq!(listed.body["total"], 1, "{}", listed.body);
    assert_eq!(listed.body["apiKeys"][0]["metadata"], json!({ "tier": 1 }));

    // Quota, enforced under concurrency.
    let key = call("createApiKey", json!({ "userId": user_id, "remaining": 3, "rateLimitEnabled": false })).await;
    let key = key["key"].as_str().unwrap().to_owned();
    let results = futures::future::join_all((0..8).map(|_| call("verifyApiKey", json!({ "key": key })))).await;
    assert_eq!(results.iter().filter(|r| r["valid"] == true).count(), 3, "{results:?}");

    // Refill after the interval (wide enough that a slow first request cannot cross it).
    let key = call(
        "createApiKey",
        json!({ "userId": user_id, "remaining": 1, "refillAmount": 2, "refillInterval": 1000, "rateLimitEnabled": false }),
    )
    .await;
    let key = key["key"].as_str().unwrap().to_owned();
    assert_eq!(call("verifyApiKey", json!({ "key": key })).await["key"]["remaining"], 0);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let res = call("verifyApiKey", json!({ "key": key })).await;
    assert_eq!(res["key"]["remaining"], 1, "{res}");

    // Rate limit window.
    let key = call("createApiKey", json!({ "userId": user_id, "rateLimitMax": 2, "rateLimitTimeWindow": 60000 })).await;
    let key = key["key"].as_str().unwrap().to_owned();
    for expected in [1, 2] {
        assert_eq!(call("verifyApiKey", json!({ "key": key })).await["key"]["requestCount"], expected);
    }
    assert_eq!(call("verifyApiKey", json!({ "key": key })).await["error"]["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn plugins_on_sqlite() {
    run_plugins(SqlxAdapter::connect("sqlite::memory:").await.unwrap()).await;
}

#[tokio::test]
async fn plugins_on_postgres() {
    if let Ok(url) = std::env::var("DATABASE_URL_POSTGRES").map(|u| u.trim().to_owned())
        && !url.is_empty()
    {
        run_plugins(SqlxAdapter::connect(&url).await.unwrap()).await;
    }
}

#[tokio::test]
async fn plugins_on_mysql() {
    if let Ok(url) = std::env::var("DATABASE_URL_MYSQL").map(|u| u.trim().to_owned())
        && !url.is_empty()
    {
        run_plugins(SqlxAdapter::connect(&url).await.unwrap()).await;
    }
}
