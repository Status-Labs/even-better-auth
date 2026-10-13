#![cfg(feature = "oauth")]

mod common;

use std::sync::Arc;

use common::{Client, options};
use even_better_auth::oauth2::ProviderOptions;
use even_better_auth::plugins::one_tap::{OneTapOptions, one_tap};
use even_better_auth::social_providers::Google;
use serde_json::{Value, json};

const KEY: &[u8] = b"one-tap-test-key";

fn token(claims: Value) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(KEY),
    )
    .unwrap()
}

/// A Google provider whose ID tokens are checked by a custom verifier (HS256 test key).
async fn setup(hd: Option<&str>, plugin: OneTapOptions) -> Client {
    let (mut o, _) = options();
    let mut provider = ProviderOptions::new("google-client", "secret");
    provider.verify_id_token = Some(Arc::new(|token, _nonce| {
        Box::pin(async move {
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
            validation.set_audience(&["google-client"]);
            validation.required_spec_claims.clear();
            jsonwebtoken::decode::<Value>(&token, &jsonwebtoken::DecodingKey::from_secret(KEY), &validation).is_ok()
        })
    }));
    let mut google = Google::new(provider);
    google.hd = hd.map(str::to_owned);
    o.social_providers = vec![Arc::new(google)];
    o.plugins.push(one_tap(plugin));
    Client::build(o).await
}

fn claims(email: &str) -> Value {
    json!({ "aud": "google-client", "sub": "g-123", "email": email, "email_verified": true, "name": "G User", "picture": "https://img/g.png" })
}

#[tokio::test]
async fn signs_in_with_one_tap() {
    let mut c = setup(None, Default::default()).await;
    let res = c.post("/one-tap/callback", json!({ "idToken": token(claims("G@Example.com")) })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["user"]["email"], "g@example.com");
    assert_eq!(res.body["user"]["emailVerified"], true);
    assert!(res.body["token"].is_string());
    let accounts = c.get("/list-accounts").await;
    assert_eq!(accounts.body[0]["providerId"], "google");
    assert_eq!(accounts.body[0]["accountId"], "g-123");

    let mut wrong_aud = claims("g@example.com");
    wrong_aud["aud"] = "someone-else".into();
    let res = c.post("/one-tap/callback", json!({ "idToken": token(wrong_aud) })).await;
    assert_eq!((res.status, res.body["message"].as_str()), (400, Some("invalid id token")));

    let mut no_email = claims("x@example.com");
    no_email.as_object_mut().unwrap().remove("email");
    let res = c.post("/one-tap/callback", json!({ "idToken": token(no_email) })).await;
    assert_eq!(res.body["message"], "Email not available in token");
}

#[tokio::test]
async fn hosted_domain_and_sign_up_restrictions() {
    let mut c = setup(Some("corp.com"), Default::default()).await;
    let res = c.post("/one-tap/callback", json!({ "idToken": token(claims("a@gmail.com")) })).await;
    assert_eq!(res.body["message"], "invalid id token", "missing hd is rejected");
    let mut corp = claims("a@corp.com");
    corp["hd"] = "corp.com".into();
    assert_eq!(c.post("/one-tap/callback", json!({ "idToken": token(corp) })).await.status, 200);

    let mut c = setup(None, OneTapOptions { disable_signup: true, ..Default::default() }).await;
    let res = c.post("/one-tap/callback", json!({ "idToken": token(claims("new@example.com")) })).await;
    assert_eq!(res.status, 401, "{}", res.text);
}

#[tokio::test]
async fn requires_an_audience() {
    let (mut o, _) = options();
    o.plugins.push(one_tap(Default::default()));
    let mut c = Client::build(o).await;
    let res = c.post("/one-tap/callback", json!({ "idToken": token(claims("a@example.com")) })).await;
    assert_eq!(res.status, 400);
    assert!(res.body["message"].as_str().unwrap().contains("Google client ID is required"));
}
