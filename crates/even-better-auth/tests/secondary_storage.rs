mod common;

use std::sync::Arc;

use common::{Client, Outbox, options};
use even_better_auth::{MemoryStorage, RateLimitStorage, SecondaryStorage};
use serde_json::{Value, json};

const EMAIL: &str = "test@test.com";
const PASSWORD: &str = "password1234";

struct Setup {
    c: Client,
    db: Arc<even_better_auth::MemoryAdapter>,
    storage: Arc<MemoryStorage>,
    outbox: Outbox,
}

async fn setup(store_in_db: bool, preserve: bool) -> Setup {
    let (mut o, db) = options();
    let storage = Arc::new(MemoryStorage::new());
    o.secondary_storage = Some(storage.clone());
    o.session.store_session_in_database = store_in_db;
    o.session.preserve_session_in_database = preserve;
    let outbox = Outbox::default();
    o.email_and_password.send_reset_password = outbox.callback();
    let c = Client::build(o).await;
    Setup { c, db, storage, outbox }
}

fn token_of(res: &common::Res) -> String {
    res.body["token"].as_str().expect("token").to_owned()
}

async fn cached(storage: &MemoryStorage, key: &str) -> Option<Value> {
    storage.get(key).await.unwrap().map(|raw| serde_json::from_str(&raw).unwrap())
}

#[tokio::test]
async fn sessions_live_only_in_secondary_storage() {
    let Setup { mut c, db, storage, .. } = setup(false, false).await;
    let res = c.sign_up(EMAIL, PASSWORD).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let token = token_of(&res);
    let user_id = res.body["user"]["id"].as_str().unwrap().to_owned();

    assert!(db.dump("session").await.is_empty(), "sessions are not written to the database");
    let entry = cached(&storage, &token).await.expect("cached session");
    assert_eq!(entry["session"]["token"], token);
    assert_eq!(entry["user"]["email"], EMAIL);
    let list = cached(&storage, &format!("active-sessions-{user_id}")).await.expect("active list");
    assert_eq!(list[0]["token"], token);
    assert!(list[0]["expiresAt"].is_i64(), "expiresAt is epoch milliseconds");

    let res = c.get("/get-session").await;
    assert_eq!(res.body["user"]["email"], EMAIL);

    // A user update is reflected in the cached session.
    let res = c.post("/update-user", json!({ "name": "Renamed" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(cached(&storage, &token).await.unwrap()["user"]["name"], "Renamed");

    // A second session, then revoke the others.
    let mut other = Client::new(c.auth.clone());
    let res = other.sign_in(EMAIL, PASSWORD).await;
    let other_token = token_of(&res);
    let res = c.get("/list-sessions").await;
    assert_eq!(res.body.as_array().unwrap().len(), 2);
    let res = c.post("/revoke-other-sessions", json!({})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(cached(&storage, &other_token).await.is_none());
    assert_eq!(other.get("/get-session").await.body, Value::Null);
    assert_eq!(c.get("/list-sessions").await.body.as_array().unwrap().len(), 1);

    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.status, 200);
    assert!(cached(&storage, &token).await.is_none());
    let list = cached(&storage, &format!("active-sessions-{user_id}")).await.unwrap_or(json!([]));
    assert!(list.as_array().unwrap().iter().all(|r| r["token"] != token.as_str()), "signed-out token leaves the list");
}

#[tokio::test]
async fn verification_values_live_in_secondary_storage() {
    let Setup { mut c, db, storage, outbox } = setup(false, false).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let res = c.post("/request-password-reset", json!({ "email": EMAIL })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let url = outbox.last().unwrap().url;
    let reset = url.split('?').next().unwrap().rsplit('/').next().unwrap().to_owned();
    assert!(db.dump("verification").await.is_empty(), "verification values are not written to the database");
    let key = format!("verification:reset-password:{reset}");
    assert!(cached(&storage, &key).await.is_some());

    let res = c.post("/reset-password", json!({ "newPassword": "new-password", "token": reset })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(cached(&storage, &key).await.is_none(), "the token is consumed");
    let res = c.post("/reset-password", json!({ "newPassword": "new-password-2", "token": reset })).await;
    assert_eq!(res.status, 400, "a token works once");
    assert_eq!(c.sign_in(EMAIL, "new-password").await.status, 200);
}

#[tokio::test]
async fn sessions_in_both_stores_fall_back_to_the_database() {
    let Setup { mut c, db, storage, .. } = setup(true, false).await;
    let res = c.sign_up(EMAIL, PASSWORD).await;
    let token = token_of(&res);
    assert_eq!(db.dump("session").await.len(), 1);
    assert!(cached(&storage, &token).await.is_some());

    // A missing cache entry is served from the database.
    storage.delete(&token).await.unwrap();
    assert_eq!(c.get("/get-session").await.body["user"]["email"], EMAIL);

    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.status, 200);
    assert!(db.dump("session").await.is_empty());
}

#[tokio::test]
async fn preserved_sessions_are_ended_not_deleted() {
    let Setup { mut c, db, storage, .. } = setup(true, true).await;
    let res = c.sign_up(EMAIL, PASSWORD).await;
    let token = token_of(&res);
    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.status, 200);
    assert!(cached(&storage, &token).await.is_none());
    let rows = db.dump("session").await;
    assert_eq!(rows.len(), 1, "the row is kept for audit");
    let expires = chrono::DateTime::parse_from_rfc3339(rows[0]["expiresAt"].as_str().unwrap()).unwrap();
    assert!(expires <= chrono::Utc::now(), "and has ended");

    // The preserved row cannot be used to restore the session.
    c.jar.insert("better-auth.session_token".into(), "x".into());
    let found = c.auth.context().internal_adapter.find_session(&token).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn rate_limits_use_secondary_storage() {
    let (mut o, _) = options();
    let storage = Arc::new(MemoryStorage::new());
    o.secondary_storage = Some(storage.clone());
    o.rate_limit.enabled = Some(true);
    assert_eq!(o.rate_limit_storage(), RateLimitStorage::SecondaryStorage);
    let mut c = Client::build(o).await;
    let mut statuses = vec![];
    for _ in 0..4 {
        statuses.push(c.sign_in(EMAIL, PASSWORD).await.status);
    }
    assert_eq!(statuses[..3], [401, 401, 401]);
    assert_eq!(statuses[3], 429);
    assert!(!storage.is_empty());
}
