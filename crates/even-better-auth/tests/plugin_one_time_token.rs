mod common;

use std::sync::Arc;

use common::{Client, options};
use even_better_auth::api::ApiCall;
use even_better_auth::plugins::one_time_token::{OneTimeTokenOptions, StoreToken, one_time_token};
use serde_json::json;

async fn setup(configure: impl FnOnce(&mut OneTimeTokenOptions)) -> Client {
    let (mut o, _) = options();
    let mut opts = OneTimeTokenOptions::default();
    configure(&mut opts);
    o.plugins.push(one_time_token(opts));
    Client::build(o).await
}

#[tokio::test]
async fn generate_and_redeem_once() {
    for store in [StoreToken::Plain, StoreToken::Hashed] {
        let mut c = setup(|o| o.store_token = store).await;
        c.sign_up("a@test.com", "password1234").await;
        let session = c.get("/get-session").await.body;
        let res = c.get("/one-time-token/generate").await;
        let token = res.body["token"].as_str().expect("token").to_owned();
        assert_eq!(token.len(), 32);

        let mut other = Client::new(c.auth.clone());
        let res = other.post("/one-time-token/verify", json!({ "token": token })).await;
        assert_eq!(res.body["session"]["token"], session["session"]["token"], "{}", res.text);
        assert_eq!(res.body["user"]["email"], "a@test.com");
        assert_eq!(other.get("/get-session").await.body["user"]["email"], "a@test.com", "cookie set");

        let res = other.post("/one-time-token/verify", json!({ "token": token })).await;
        assert_eq!((res.status, res.body["message"].as_str()), (400, Some("Invalid token")));
    }
}

#[tokio::test]
async fn custom_options() {
    let mut c = setup(|o| {
        o.disable_client_request = true;
        o.disable_set_session_cookie = true;
        o.generate_token = Some(Arc::new(|s| Box::pin(async move { Ok(format!("ott-{}", s.user.id)) })));
        o.store_token = StoreToken::CustomHasher(Arc::new(|t| Box::pin(async move { Ok(t.to_uppercase()) })));
    })
    .await;
    c.sign_up("a@test.com", "password1234").await;
    let res = c.get("/one-time-token/generate").await;
    assert_eq!(res.body["message"], "Client requests are disabled");

    let mut headers = http::HeaderMap::new();
    headers.insert("cookie", c.cookie_header().parse().unwrap());
    let res = c.auth.api(ApiCall::new("generateOneTimeToken").headers(headers)).await.unwrap();
    let token = res.json()["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("ott-"));

    let mut other = Client::new(c.auth.clone());
    let res = other.post("/one-time-token/verify", json!({ "token": token })).await;
    assert_eq!(res.body["user"]["email"], "a@test.com", "{}", res.text);
    assert!(!other.has_session_cookie());
}

#[tokio::test]
async fn ott_header_on_new_session() {
    let mut c = setup(|o| o.set_ott_header_on_new_session = true).await;
    let res = c.sign_up("a@test.com", "password1234").await;
    let token = res.headers.get("set-ott").expect("set-ott header").to_str().unwrap().to_owned();
    assert!(res.headers["access-control-expose-headers"].to_str().unwrap().contains("set-ott"));
    let mut other = Client::new(c.auth.clone());
    let res = other.post("/one-time-token/verify", json!({ "token": token })).await;
    assert_eq!(res.body["user"]["email"], "a@test.com", "{}", res.text);
}
