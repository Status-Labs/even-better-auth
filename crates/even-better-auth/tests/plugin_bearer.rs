mod common;

use bytes::Bytes;
use common::{BASE, Client, options};
use even_better_auth::plugins::bearer::{BearerOptions, bearer};
use serde_json::{Value, json};

async fn get_session_with(c: &Client, authorization: &str) -> Value {
    let req = http::Request::get(format!("{BASE}/api/auth/get-session"))
        .header("authorization", authorization)
        .body(Bytes::new())
        .unwrap();
    let res = c.auth.handler(req).await;
    serde_json::from_slice(res.body()).unwrap_or(Value::Null)
}

#[tokio::test]
async fn bearer_tokens_authenticate_requests() {
    let (mut o, _) = options();
    o.plugins.push(bearer(BearerOptions::default()));
    let mut c = Client::build(o).await;
    let res = c.sign_up("bearer@test.com", "password1234").await;
    let signed = res.headers["set-auth-token"].to_str().unwrap().to_owned();
    assert!(signed.contains('.'), "the header carries the signed token");
    let exposed = res.headers["access-control-expose-headers"].to_str().unwrap();
    assert!(exposed.contains("set-auth-token"));
    let raw = res.body["token"].as_str().unwrap().to_owned();
    assert!(signed.starts_with(&format!("{raw}.")));

    // Signed, URL-encoded signed and bare tokens all work without cookies.
    for auth in [
        format!("Bearer {signed}"),
        format!("bearer {}", even_better_auth::utils::url::encode_uri_component(&signed)),
        format!("Bearer {raw}"),
    ] {
        assert_eq!(get_session_with(&c, &auth).await["user"]["email"], "bearer@test.com", "{auth}");
    }
    // Bad signatures and other schemes are ignored.
    let tampered = format!("Bearer {raw}.AAAA");
    assert_eq!(get_session_with(&c, &tampered).await, Value::Null);
    assert_eq!(get_session_with(&c, &format!("Basic {raw}")).await, Value::Null);

    // Endpoints that require a session accept the bearer token too.
    c.jar.clear();
    c.origin = None;
    let req = http::Request::post(format!("{BASE}/api/auth/update-user"))
        .header("authorization", format!("Bearer {signed}"))
        .header("content-type", "application/json")
        .body(Bytes::from(json!({ "name": "Bearer" }).to_string()))
        .unwrap();
    let res = c.auth.handler(req).await;
    assert_eq!(res.status(), 200, "{}", String::from_utf8_lossy(res.body()));
    assert_eq!(get_session_with(&c, &format!("Bearer {signed}")).await["user"]["name"], "Bearer");
}

#[tokio::test]
async fn require_signature_rejects_bare_tokens() {
    let (mut o, _) = options();
    o.plugins.push(bearer(BearerOptions { require_signature: true }));
    let mut c = Client::build(o).await;
    let res = c.sign_up("signed@test.com", "password1234").await;
    let signed = res.headers["set-auth-token"].to_str().unwrap().to_owned();
    let raw = res.body["token"].as_str().unwrap().to_owned();
    assert_eq!(get_session_with(&c, &format!("Bearer {raw}")).await, Value::Null);
    assert_eq!(get_session_with(&c, &format!("Bearer {signed}")).await["user"]["email"], "signed@test.com");
}

#[tokio::test]
async fn sign_out_does_not_expose_a_token() {
    let (mut o, _) = options();
    o.plugins.push(bearer(BearerOptions::default()));
    let mut c = Client::build(o).await;
    c.sign_up("out@test.com", "password1234").await;
    let res = c.post("/sign-out", json!({})).await;
    assert!(res.headers.get("set-auth-token").is_none());
}
