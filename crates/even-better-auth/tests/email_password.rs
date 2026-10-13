mod common;

use common::{Client, Outbox, options};
use serde_json::json;

#[tokio::test]
async fn sign_up_sign_in_session_sign_out() {
    let (o, _) = options();
    let mut c = Client::build(o).await;

    let res = c.sign_up("test@test.com", "password1234").await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(res.body["token"].is_string());
    assert_eq!(res.body["user"]["email"], "test@test.com");
    assert_eq!(res.body["user"]["emailVerified"], false);
    let cookie = res.cookie("better-auth.session_token").unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Path=/"));
    assert!(cookie.contains(&format!("Max-Age={}", 60 * 60 * 24 * 7)));

    let res = c.get("/get-session").await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body["user"]["email"], "test@test.com");
    assert!(res.body["session"]["token"].is_string());
    assert_eq!(res.headers["cache-control"], "no-store");

    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body["success"], true);
    assert!(!c.has_session_cookie());
    assert_eq!(c.get("/get-session").await.body, serde_json::Value::Null);

    let res = c.sign_in("test@test.com", "password1234").await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["redirect"], false);
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "test@test.com");
}

#[tokio::test]
async fn rejects_bad_credentials_and_duplicates() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up("dup@test.com", "password1234").await;

    let res = c.sign_up("dup@test.com", "password1234").await;
    assert_eq!(res.status, 422);
    assert_eq!(res.body["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");

    let res = c.sign_in("dup@test.com", "wrong-password").await;
    assert_eq!(res.status, 401);
    assert_eq!(res.body["code"], "INVALID_EMAIL_OR_PASSWORD");

    let res = c.sign_in("nobody@test.com", "password1234").await;
    assert_eq!(res.status, 401);

    let res = c.sign_up("short@test.com", "short").await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "PASSWORD_TOO_SHORT");

    let res = c.sign_up("not-an-email", "password1234").await;
    assert_eq!(res.body["code"], "INVALID_EMAIL");
}

#[tokio::test]
async fn origin_check_blocks_untrusted_origins() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up("o@test.com", "password1234").await;
    c.origin = Some("http://evil.com".into());
    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.status, 403);
    assert_eq!(res.body["code"], "INVALID_ORIGIN");

    c.origin = Some(common::BASE.into());
    let res = c
        .post(
            "/sign-in/email",
            json!({"email": "o@test.com", "password": "password1234", "callbackURL": "http://evil.com/x"}),
        )
        .await;
    assert_eq!(res.status, 403);
    assert_eq!(res.body["code"], "INVALID_CALLBACK_URL");
    let res = c
        .post("/sign-in/email", json!({"email": "o@test.com", "password": "password1234", "callbackURL": "/dashboard"}))
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["url"], "/dashboard", "{}", res.text);
}

#[tokio::test]
async fn email_verification_flow() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    o.email_and_password.require_email_verification = true;
    o.email_verification.send_verification_email = outbox.callback();
    o.email_verification.auto_sign_in_after_verification = true;
    let mut c = Client::build(o).await;

    let res = c.sign_up("verify@test.com", "password1234").await;
    assert_eq!(res.status, 200);
    assert!(res.body["token"].is_null(), "no auto sign-in when verification is required");
    assert_eq!(outbox.len(), 1);

    let res = c.sign_in("verify@test.com", "password1234").await;
    assert_eq!(res.status, 403);
    assert_eq!(res.body["code"], "EMAIL_NOT_VERIFIED");

    let email = outbox.last().unwrap();
    assert!(email.url.starts_with("http://localhost:3000/api/auth/verify-email?token="));
    let res = c.get(&format!("/verify-email?token={}", email.token)).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["status"], true);
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["emailVerified"], true);

    let res = c.get("/verify-email?token=garbage&callbackURL=/done").await;
    assert_eq!(res.status, 302);
    assert_eq!(res.location().unwrap(), "/done?error=INVALID_TOKEN");
}

#[tokio::test]
async fn generic_duplicate_response_when_verification_required() {
    let (mut o, _) = options();
    o.email_and_password.require_email_verification = true;
    let mut c = Client::build(o).await;
    let a = c.sign_up("same@test.com", "password1234").await;
    let b = c.sign_up("same@test.com", "password1234").await;
    assert_eq!(a.status, 200);
    assert_eq!(b.status, 200, "duplicate must look like success: {}", b.text);
    assert!(b.body["token"].is_null());
    assert_ne!(a.body["user"]["id"], b.body["user"]["id"]);
}

#[tokio::test]
async fn session_management() {
    let (o, _) = options();
    let mut a = Client::build(o).await;
    a.sign_up("multi@test.com", "password1234").await;
    let mut b = Client::new(a.auth.clone());
    b.sign_in("multi@test.com", "password1234").await;

    let list = a.get("/list-sessions").await;
    assert_eq!(list.status, 200, "{}", list.text);
    assert_eq!(list.body.as_array().unwrap().len(), 2);

    let res = a.post("/revoke-other-sessions", json!({})).await;
    assert_eq!(res.status, 200);
    assert!(b.get("/get-session").await.body.is_null());
    assert!(!a.get("/get-session").await.body.is_null());

    let res = a.post("/revoke-sessions", json!({})).await;
    assert_eq!(res.status, 200);
    assert!(a.get("/get-session").await.body.is_null());
}

#[tokio::test]
async fn dont_remember_me_uses_session_cookie() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up("rm@test.com", "password1234").await;
    c.jar.clear();
    let res = c
        .post("/sign-in/email", json!({"email": "rm@test.com", "password": "password1234", "rememberMe": false}))
        .await;
    let token = res.cookie("better-auth.session_token").unwrap();
    assert!(!token.contains("Max-Age"), "{token}");
    assert!(res.cookie("better-auth.dont_remember").is_some());
}

#[tokio::test]
async fn cookie_cache_strategies() {
    for strategy in [
        even_better_auth::CookieCacheStrategy::Compact,
        even_better_auth::CookieCacheStrategy::Jwt,
        even_better_auth::CookieCacheStrategy::Jwe,
    ] {
        let (mut o, db) = options();
        o.session.cookie_cache.enabled = true;
        o.session.cookie_cache.strategy = strategy;
        let mut c = Client::build(o).await;
        c.sign_up("cache@test.com", "password1234").await;
        assert!(c.jar.contains_key("better-auth.session_data"), "{strategy:?}");
        // With a valid cache the session resolves even if the DB row disappears.
        let table = c.auth.context().schema.table("session").unwrap().clone();
        even_better_auth::Adapter::delete_many(&*db, &table, &[]).await.unwrap();
        let res = c.get("/get-session").await;
        assert_eq!(res.body["user"]["email"], "cache@test.com", "{strategy:?}");
        let res = c.get("/get-session?disableCookieCache=true").await;
        assert!(res.body.is_null(), "{strategy:?}");
    }
}

#[tokio::test]
async fn server_api_get_session() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up("api@test.com", "password1234").await;
    let mut headers = http::HeaderMap::new();
    headers.insert("cookie", c.cookie_header().parse().unwrap());
    let session = c.auth.get_session(&headers).await.unwrap().unwrap();
    assert_eq!(session.user.email, "api@test.com");
}

#[tokio::test]
async fn ok_and_not_found() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    assert_eq!(c.get("/ok").await.body["ok"], true);
    assert_eq!(c.get("/nope").await.status, 404);
}

#[tokio::test]
async fn sign_up_rolls_back_when_a_later_write_fails() {
    use even_better_auth::db::hooks::{BeforeOutcome, DatabaseHooks, Operation};

    let (mut o, db) = options();
    let created_hook_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = created_hook_ran.clone();
    o.database_hooks = DatabaseHooks::new()
        .after("user", Operation::Create, move |_| {
            let flag = flag.clone();
            async move {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        })
        .before("account", Operation::Create, |_| async {
            Err::<BeforeOutcome, _>(even_better_auth::Error::Database("account write failed".into()))
        });
    let mut c = Client::build(o).await;

    let res = c.sign_up("rollback@test.com", "password1234").await;
    assert_eq!(res.status, 500, "{}", res.text);
    assert!(db.dump("user").await.is_empty(), "the user insert is rolled back");
    assert!(!created_hook_ran.load(std::sync::atomic::Ordering::SeqCst), "after hooks wait for the commit");
}
