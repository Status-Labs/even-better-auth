mod common;

use common::{Client, options};
use even_better_auth::plugins::multi_session::{MultiSessionOptions, multi_session};
use serde_json::{Value, json};

async fn setup(maximum_sessions: usize) -> (Client, std::sync::Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    o.plugins.push(multi_session(MultiSessionOptions { maximum_sessions }));
    (Client::build(o).await, db)
}

fn multi_cookies(c: &Client) -> usize {
    c.jar.keys().filter(|k| k.contains("_multi-")).count()
}

fn token_of(list: &Value, email: &str) -> String {
    let item = list.as_array().unwrap().iter().find(|s| s["user"]["email"] == email).unwrap();
    item["session"]["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn multi_session_list_switch_and_revoke() {
    let (mut c, db) = setup(5).await;
    let res = c.sign_up("a@test.com", "password1234").await;
    let token = res.body["token"].as_str().unwrap().to_lowercase();
    assert!(res.cookie(&format!("better-auth.session_token_multi-{token}")).is_some());
    c.sign_up("b@test.com", "password1234").await;
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "b@test.com");

    let list = c.get("/multi-session/list-device-sessions").await;
    assert_eq!(list.body.as_array().unwrap().len(), 2, "{}", list.text);
    let a = token_of(&list.body, "a@test.com");

    let res = c.post("/multi-session/set-active", json!({ "sessionToken": a })).await;
    assert_eq!(res.body["user"]["email"], "a@test.com", "{}", res.text);
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "a@test.com");

    let res = c.post("/multi-session/set-active", json!({ "sessionToken": "nope" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("INVALID_SESSION_TOKEN")));

    // Signing in again as the same user replaces the remembered session.
    c.sign_in("a@test.com", "password1234").await;
    assert_eq!(multi_cookies(&c), 2);
    let list = c.get("/multi-session/list-device-sessions").await;
    assert_eq!(list.body.as_array().unwrap().len(), 2);
    assert_ne!(token_of(&list.body, "a@test.com"), a);

    // Revoking the active session switches to another remembered one.
    let a = token_of(&list.body, "a@test.com");
    let res = c.post("/multi-session/revoke", json!({ "sessionToken": a })).await;
    assert_eq!(res.body["status"], true, "{}", res.text);
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "b@test.com");
    assert_eq!(c.get("/multi-session/list-device-sessions").await.body.as_array().unwrap().len(), 1);

    c.post("/sign-out", json!({})).await;
    assert_eq!(multi_cookies(&c), 0);
    assert!(db.dump("session").await.is_empty(), "sign-out revokes every device session");
}

#[tokio::test]
async fn multi_session_maximum() {
    let (mut c, _) = setup(2).await;
    c.sign_up("a@test.com", "password1234").await;
    c.sign_up("b@test.com", "password1234").await;
    c.sign_up("c@test.com", "password1234").await;
    assert_eq!(multi_cookies(&c), 2, "the third session is not remembered");
    assert_eq!(c.get("/multi-session/list-device-sessions").await.body.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn multi_session_cookie_must_match_value() {
    let (mut c, _) = setup(5).await;
    c.sign_up("a@test.com", "password1234").await;
    let mut other = Client::new(c.auth.clone());
    other.sign_up("b@test.com", "password1234").await;
    let b = other.get("/get-session").await.body["session"]["token"].as_str().unwrap().to_owned();
    // A request naming another user's token without holding its cookie gets nothing.
    let res = c.post("/multi-session/revoke", json!({ "sessionToken": b })).await;
    assert_eq!(res.status, 401);
    assert_eq!(other.get("/get-session").await.body["user"]["email"], "b@test.com");
}
