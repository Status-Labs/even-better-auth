#![cfg(feature = "oauth")]

mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::plugins::haveibeenpwned::{HaveIBeenPwnedOptions, have_i_been_pwned};
use serde_json::json;

// SHA-1("password1234") = E6B6AFBD6D76BB5D2041542D7D2E3FAC5BB05593
const PWNED_SUFFIX: &str = "FBD6D76BB5D2041542D7D2E3FAC5BB05593";

async fn setup(configure: impl FnOnce(&mut HaveIBeenPwnedOptions)) -> (Client, Arc<Mutex<Vec<String>>>) {
    let (mut o, _) = options();
    let prefixes = Arc::new(Mutex::new(vec![]));
    let seen = prefixes.clone();
    let mut opts = HaveIBeenPwnedOptions {
        range_fetcher: Some(Arc::new(move |prefix: String| {
            seen.lock().unwrap().push(prefix.clone());
            Box::pin(async move {
                Ok(if prefix == "E6B6A" {
                    format!("0000000000000000000000000000000000A:0\r\n{PWNED_SUFFIX}:12")
                } else {
                    String::new()
                })
            })
        })),
        ..Default::default()
    };
    configure(&mut opts);
    o.plugins.push(have_i_been_pwned(opts));
    (Client::build(o).await, prefixes)
}

#[tokio::test]
async fn rejects_compromised_passwords_on_checked_paths() {
    let (mut c, prefixes) = setup(|_| {}).await;
    let res = c.sign_up("a@test.com", "password1234").await;
    assert_eq!((res.status, res.body["code"].as_str()), (400, Some("PASSWORD_COMPROMISED")), "{}", res.text);
    assert_eq!(prefixes.lock().unwrap().as_slice(), ["E6B6A"], "only the 5-char prefix is sent");

    let res = c.sign_up("a@test.com", "a-safe-password-1").await;
    assert_eq!(res.status, 200, "{}", res.text);
    let res = c
        .post("/change-password", json!({ "currentPassword": "a-safe-password-1", "newPassword": "password1234" }))
        .await;
    assert_eq!(res.body["code"], "PASSWORD_COMPROMISED");

    // Sign-in hashing isn't checked (only verification happens there anyway).
    let res = c.sign_in("a@test.com", "a-safe-password-1").await;
    assert_eq!(res.status, 200);
}

#[tokio::test]
async fn custom_message_and_disabled() {
    let (mut c, _) = setup(|o| o.custom_password_compromised_message = Some("pick another".into())).await;
    let res = c.sign_up("a@test.com", "password1234").await;
    assert_eq!(res.body["message"], "pick another");

    let (mut c, prefixes) = setup(|o| o.enabled = false).await;
    assert_eq!(c.sign_up("a@test.com", "password1234").await.status, 200);
    assert!(prefixes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lookup_failure_is_an_error() {
    let (mut c, _) = setup(|o| {
        o.range_fetcher = Some(Arc::new(|_| Box::pin(async { Err(even_better_auth::Error::Http("down".into())) })));
    })
    .await;
    let res = c.sign_up("a@test.com", "password1234").await;
    assert_eq!(res.status, 500);
    assert_eq!(res.body["message"], "Failed to check password. Please try again later.");
}
