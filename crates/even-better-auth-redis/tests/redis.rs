//! Runs against a real server when `REDIS_URL` is set (e.g. `redis://127.0.0.1:6379/`).

use std::sync::Arc;

use bytes::Bytes;
use even_better_auth::{BetterAuth, BetterAuthOptions, EmailAndPasswordOptions, MemoryAdapter, SecondaryStorage};
use even_better_auth_redis::RedisStorage;

async fn storage() -> Option<RedisStorage> {
    let url = std::env::var("REDIS_URL").ok()?;
    let prefix = format!("ba-test-{}:", even_better_auth::crypto::generate_id(Some(8)));
    Some(RedisStorage::connect(&url).await.expect("connect").with_prefix(prefix))
}

#[tokio::test]
async fn storage_operations() {
    let Some(s) = storage().await else { return };
    s.set("a", "1", None).await.unwrap();
    assert_eq!(s.get("a").await.unwrap().as_deref(), Some("1"));
    s.set("b", "2", Some(60)).await.unwrap();
    assert_eq!(s.get_and_delete("b").await.unwrap().as_deref(), Some("2"));
    assert_eq!(s.get("b").await.unwrap(), None);
    assert_eq!(s.get_and_delete("b").await.unwrap(), None);
    assert_eq!(s.increment("n", 60).await.unwrap(), 1);
    assert_eq!(s.increment("n", 60).await.unwrap(), 2);
    s.delete("a").await.unwrap();
    s.delete("n").await.unwrap();
    assert_eq!(s.get("a").await.unwrap(), None);
}

#[tokio::test]
async fn sessions_in_redis() {
    let Some(s) = storage().await else { return };
    let mut o = BetterAuthOptions::new(Arc::new(MemoryAdapter::new()));
    o.base_url = Some("http://localhost:3000".into());
    o.secret = Some("better-auth-secret-that-is-long-enough-for-tests".into());
    o.email_and_password = EmailAndPasswordOptions::enabled();
    o.rate_limit.enabled = Some(false);
    o.secondary_storage = Some(Arc::new(s.clone()));
    let auth = BetterAuth::new(o).await.unwrap();

    let body = r#"{"email":"redis@test.com","password":"password1234","name":"R"}"#;
    let req = http::Request::post("http://localhost:3000/api/auth/sign-up/email")
        .header("content-type", "application/json")
        .header("origin", "http://localhost:3000")
        .body(Bytes::from(body))
        .unwrap();
    let res = auth.handler(req).await;
    assert_eq!(res.status(), 200);
    let json: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
    let token = json["token"].as_str().unwrap();
    let cached = s.get(token).await.unwrap().expect("session cached in redis");
    assert!(cached.contains("redis@test.com"));
    let cookie = res.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_owned();

    let mut headers = http::HeaderMap::new();
    headers.insert("cookie", cookie.parse().unwrap());
    let session = auth.get_session(&headers).await.unwrap().expect("session");
    assert_eq!(session.user.email, "redis@test.com");
    s.delete(token).await.unwrap();
}
