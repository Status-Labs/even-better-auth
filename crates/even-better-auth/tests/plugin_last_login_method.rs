mod common;

use std::sync::Arc;

use common::{Client, options};
use even_better_auth::plugins::last_login_method::{LastLoginMethodOptions, last_login_method};
use serde_json::json;

const COOKIE: &str = "better-auth.last_used_login_method";

async fn setup(configure: impl FnOnce(&mut LastLoginMethodOptions)) -> (Client, Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    let mut opts = LastLoginMethodOptions::default();
    configure(&mut opts);
    o.plugins.push(last_login_method(opts));
    (Client::build(o).await, db)
}

#[tokio::test]
async fn cookie_on_sign_in() {
    let (mut c, db) = setup(|_| {}).await;
    let res = c.sign_up("a@test.com", "password1234").await;
    let cookie = res.set_cookies().into_iter().find(|s| s.starts_with(COOKIE)).expect("cookie set");
    assert!(cookie.starts_with(&format!("{COOKIE}=email;")), "{cookie}");
    assert!(!cookie.contains("HttpOnly"));
    assert!(cookie.contains("Max-Age=2592000"));
    assert!(!db.dump("user").await[0].contains_key("lastLoginMethod"));

    // Requests that don't set a session leave it alone.
    let res = c.get("/get-session").await;
    assert!(res.cookie(COOKIE).is_none());
    let res = c.sign_in("a@test.com", "wrong-password").await;
    assert!(res.cookie(COOKIE).is_none());
}

#[tokio::test]
async fn store_in_database_and_custom_resolve() {
    let (mut c, db) = setup(|o| {
        o.store_in_database = true;
        o.custom_resolve_method =
            Some(Arc::new(|ctx| (ctx.path == "/sign-in/email").then(|| "custom-email".to_owned())));
    })
    .await;
    c.sign_up("a@test.com", "password1234").await;
    assert_eq!(db.dump("user").await[0]["lastLoginMethod"], "email");
    let res = c.get("/get-session").await;
    assert_eq!(res.body["user"]["lastLoginMethod"], "email");

    let res = c.sign_in("a@test.com", "password1234").await;
    assert!(res.set_cookies().iter().any(|s| s.starts_with(&format!("{COOKIE}=custom-email;"))));
    assert_eq!(db.dump("user").await[0]["lastLoginMethod"], "custom-email");

    // Not client-writable.
    c.post("/update-user", json!({ "lastLoginMethod": "x" })).await;
    assert_eq!(db.dump("user").await[0]["lastLoginMethod"], "custom-email");
}

#[tokio::test]
async fn before_store_cookie_can_refuse() {
    let (mut c, _) = setup(|o| {
        o.cookie_name = "llm".into();
        o.before_store_cookie = Some(Arc::new(|_ctx, method| Box::pin(async move { Ok(method != "email") })));
    })
    .await;
    let res = c.sign_up("a@test.com", "password1234").await;
    assert!(res.set_cookies().iter().all(|s| !s.starts_with("llm=")));
}
