mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{BASE, Client, options};
use even_better_auth::plugins::device_authorization::{DeviceAuthorizationOptions, device_authorization};
use serde_json::{Value, json};

async fn setup(configure: impl FnOnce(&mut DeviceAuthorizationOptions)) -> Client {
    let (mut o, _) = options();
    let mut opts = DeviceAuthorizationOptions { interval: Duration::from_millis(0), ..Default::default() };
    configure(&mut opts);
    o.plugins.push(device_authorization(opts).unwrap());
    Client::build(o).await
}

async fn poll(device: &mut Client, code: &str, client_id: &str) -> (u16, Value) {
    let res = device
        .post(
            "/device/token",
            json!({ "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": code, "client_id": client_id }),
        )
        .await;
    (res.status, res.body)
}

#[tokio::test]
async fn device_flow() {
    let mut device = setup(|_| {}).await;
    let res = device.post("/device/code", json!({ "client_id": "tv-app", "scope": "openid profile" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.headers["cache-control"], "no-store");
    let code = res.body["device_code"].as_str().unwrap().to_owned();
    let user_code = res.body["user_code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 40);
    assert_eq!(user_code.len(), 8);
    assert_eq!(res.body["verification_uri"], "http://localhost:3000/device");
    assert_eq!(res.body["verification_uri_complete"], format!("http://localhost:3000/device?user_code={user_code}"));
    assert_eq!(res.body["expires_in"], 1800);

    let (status, body) = poll(&mut device, &code, "tv-app").await;
    assert_eq!((status, body["error"].as_str()), (400, Some("authorization_pending")));
    assert_eq!(body["error_description"], "Authorization pending");
    assert!(body.get("code").is_none(), "OAuth error bodies carry only error/error_description");

    // The user signs in on another device and reviews the request.
    let mut user = Client::new(device.auth.clone());
    let anonymous = user.get(&format!("/device?user_code={user_code}")).await;
    assert_eq!(anonymous.body, json!({ "user_code": user_code, "status": "pending" }));
    user.sign_up("u@test.com", "password1234").await;
    let res = user.post("/device/approve", json!({ "userCode": user_code })).await;
    assert_eq!(
        res.body["error_description"].as_str().unwrap().split(';').next(),
        Some("Device code has not been claimed by a verifying session")
    );
    // Dashes and lowercase are accepted for default-alphabet codes.
    let dashed = format!("{}-{}", &user_code[..4], &user_code[4..]).to_lowercase();
    let review = user.get(&format!("/device?user_code={dashed}")).await;
    assert_eq!(review.body["client_id"], "tv-app", "{}", review.text);
    assert_eq!(review.body["scope"], "openid profile");

    // Someone else can't approve a code claimed by this user.
    let mut other = Client::new(device.auth.clone());
    other.sign_up("o@test.com", "password1234").await;
    let res = other.post("/device/approve", json!({ "userCode": user_code })).await;
    assert_eq!((res.status, res.body["error"].as_str()), (403, Some("access_denied")));

    let res = user.post("/device/approve", json!({ "userCode": user_code })).await;
    assert_eq!(res.body["success"], true, "{}", res.text);

    let (status, body) = poll(&mut device, &code, "other-app").await;
    assert_eq!((status, body["error_description"].as_str()), (400, Some("Client ID mismatch")));
    let (status, body) = poll(&mut device, &code, "tv-app").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "openid profile");
    let token = body["access_token"].as_str().unwrap();
    let mut bearer = http::HeaderMap::new();
    bearer.insert("cookie", format!("better-auth.session_token={}", sign(&device, token)).parse().unwrap());
    let session = device.auth.api(even_better_auth::api::ApiCall::new("getSession").headers(bearer)).await.unwrap();
    assert_eq!(session.json()["user"]["email"], "u@test.com");

    // Single use.
    let (_, body) = poll(&mut device, &code, "tv-app").await;
    assert_eq!(body["error"], "invalid_grant");
}

fn sign(c: &Client, token: &str) -> String {
    use base64::Engine;
    use hmac::{Hmac, KeyInit, Mac};
    let secret = &c.auth.context().secret;
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(token.as_bytes());
    let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    even_better_auth::utils::url::encode_uri_component(&format!("{token}.{sig}"))
}

#[tokio::test]
async fn deny_slow_down_and_expiry() {
    let mut device = setup(|o| o.interval = Duration::from_secs(5)).await;
    let res = device.post("/device/code", json!({ "client_id": "tv" })).await;
    let code = res.body["device_code"].as_str().unwrap().to_owned();
    let user_code = res.body["user_code"].as_str().unwrap().to_owned();
    assert_eq!(poll(&mut device, &code, "tv").await.1["error"], "authorization_pending");
    assert_eq!(poll(&mut device, &code, "tv").await.1["error"], "slow_down");

    let mut device = setup(|_| {}).await;
    let res = device.post("/device/code", json!({ "client_id": "tv" })).await;
    let code = res.body["device_code"].as_str().unwrap().to_owned();
    let user_code_2 = res.body["user_code"].as_str().unwrap().to_owned();
    let mut user = Client::new(device.auth.clone());
    user.sign_up("u@test.com", "password1234").await;
    user.get(&format!("/device?user_code={user_code_2}")).await;
    assert_eq!(user.post("/device/deny", json!({ "userCode": user_code_2 })).await.body["success"], true);
    let (_, body) = poll(&mut device, &code, "tv").await;
    assert_eq!(body["error"], "access_denied");
    assert_eq!(poll(&mut device, &code, "tv").await.1["error"], "invalid_grant", "denied codes are deleted");
    let _ = user_code;

    let mut device = setup(|o| o.expires_in = Duration::from_secs(0)).await;
    let res = device.post("/device/code", json!({ "client_id": "tv" })).await;
    let code = res.body["device_code"].as_str().unwrap().to_owned();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(poll(&mut device, &code, "tv").await.1["error"], "expired_token");
}

#[tokio::test]
async fn request_validation() {
    let mut c = setup(|o| {
        o.validate_client = Some(Arc::new(|id| Box::pin(async move { Ok(id == "good") })));
        o.verification_uri = Some("https://app.example.com/activate?src=tv".into());
        o.generate_user_code = Some(Arc::new(|| Box::pin(async { Ok("CUSTOM12".to_owned()) })));
    })
    .await;
    let res = c.post("/device/code", json!({ "client_id": "bad" })).await;
    assert_eq!(res.body, json!({ "error": "invalid_client", "error_description": "Invalid client ID" }));
    let res = c.post("/device/code", json!({ "client_id": "" })).await;
    assert_eq!(res.body["error_description"], "client_id is required");
    let res = c.post("/device/code", json!({ "client_id": "good" })).await;
    assert_eq!(res.body["user_code"], "CUSTOM12");
    assert_eq!(res.body["verification_uri_complete"], "https://app.example.com/activate?src=tv&user_code=CUSTOM12");

    // Form bodies: repeated parameters are rejected (RFC 8628 §3.1).
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("{BASE}/api/auth/device/code"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("client_id=good&scope=a&scope=b".into())
        .unwrap();
    let res = c.auth.handler(req).await;
    let body: Value = serde_json::from_slice(res.body()).unwrap();
    assert_eq!(body["error_description"], "scope must not be repeated");

    assert!(device_authorization(DeviceAuthorizationOptions { user_code_length: 0, ..Default::default() }).is_err());
}
