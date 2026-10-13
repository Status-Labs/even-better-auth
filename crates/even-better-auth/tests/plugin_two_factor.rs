mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::crypto::otp;
use even_better_auth::plugins::two_factor::{AccountLockout, OtpOptions, TwoFactorOptions, TwoFactorOtp, two_factor};
use serde_json::{Value, json};

const EMAIL: &str = "2fa@test.com";
const PASSWORD: &str = "password1234";

fn base32_decode(s: &str) -> Vec<u8> {
    let (mut buffer, mut bits, mut out) = (0u32, 0u32, vec![]);
    for c in s.chars() {
        let v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".find(c).unwrap() as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

fn secret_from_uri(uri: &str) -> String {
    let url = url::Url::parse(uri).unwrap();
    let secret = url.query_pairs().find(|(k, _)| k == "secret").unwrap().1.into_owned();
    String::from_utf8(base32_decode(&secret)).unwrap()
}

#[derive(Clone, Default)]
struct Sms(Arc<Mutex<Vec<TwoFactorOtp>>>);

async fn setup(configure: impl FnOnce(&mut TwoFactorOptions)) -> (Client, Sms) {
    let (mut o, _) = options();
    let sms = Sms::default();
    let inner = sms.0.clone();
    let mut opts = TwoFactorOptions {
        otp: OtpOptions {
            send_otp: Some(even_better_auth::options::Callback::new(move |m: TwoFactorOtp| {
                let inner = inner.clone();
                async move {
                    inner.lock().unwrap().push(m);
                    Ok(())
                }
            })),
            ..Default::default()
        },
        ..Default::default()
    };
    configure(&mut opts);
    o.plugins.push(two_factor(opts));
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    (c, sms)
}

/// Enable TOTP for the signed-in client and return the secret and backup codes.
async fn enable_totp(c: &mut Client) -> (String, Vec<String>) {
    let res = c.post("/two-factor/enable", json!({ "password": PASSWORD })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let uri = res.body["totpURI"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/Better%20Auth:2fa%40test.com?secret="), "{uri}");
    let secret = secret_from_uri(uri);
    let codes: Vec<String> = serde_json::from_value(res.body["backupCodes"].clone()).unwrap();
    assert_eq!(codes.len(), 10);
    assert!(codes.iter().all(|c| c.len() == 11 && c.as_bytes()[5] == b'-'));
    assert_eq!(
        c.get("/get-session").await.body["user"]["twoFactorEnabled"],
        false,
        "enabled only after the first code"
    );
    let res = c.post("/two-factor/verify-totp", json!({ "code": otp::totp(&secret, 6, 30) })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(c.get("/get-session").await.body["user"]["twoFactorEnabled"], true);
    (secret, codes)
}

async fn sign_in_challenge(c: &mut Client) -> Value {
    c.jar.clear();
    let res = c.sign_in(EMAIL, PASSWORD).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(!c.has_session_cookie(), "no session before the second factor");
    assert!(c.jar.contains_key("better-auth.two_factor"));
    res.body
}

#[tokio::test]
async fn totp_enrollment_and_sign_in() {
    let (mut c, _) = setup(|_| {}).await;
    assert_eq!(
        c.post("/two-factor/enable", json!({ "password": "wrong-password" })).await.body["code"],
        "INVALID_PASSWORD"
    );
    let (secret, _) = enable_totp(&mut c).await;
    assert_eq!(
        c.post("/two-factor/enable", json!({ "password": PASSWORD })).await.body["code"],
        "TOTP_ALREADY_ENABLED"
    );

    let body = sign_in_challenge(&mut c).await;
    assert_eq!(body, json!({ "twoFactorRedirect": true, "twoFactorMethods": ["totp", "otp"] }));
    assert_eq!(c.get("/get-session").await.body, Value::Null);
    let res = c.post("/two-factor/verify-totp", json!({ "code": "000000" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("INVALID_CODE")));
    let res = c.post("/two-factor/verify-totp", json!({ "code": otp::totp(&secret, 6, 30) })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(res.body["token"].is_string());
    assert_eq!(c.get("/get-session").await.body["user"]["email"], EMAIL);
    assert!(!c.jar.contains_key("better-auth.two_factor"), "the challenge cookie is cleared");

    let uri = c.post("/two-factor/get-totp-uri", json!({ "password": PASSWORD })).await;
    assert_eq!(secret_from_uri(uri.body["totpURI"].as_str().unwrap()), secret);
}

#[tokio::test]
async fn trusted_devices_skip_the_second_factor() {
    let (mut c, _) = setup(|_| {}).await;
    let (secret, _) = enable_totp(&mut c).await;
    sign_in_challenge(&mut c).await;
    let res =
        c.post("/two-factor/verify-totp", json!({ "code": otp::totp(&secret, 6, 30), "trustDevice": true })).await;
    assert_eq!(res.status, 200);
    let trust = c.jar.get("better-auth.trust_device").cloned().expect("trust cookie");
    c.jar.retain(|k, _| k == "better-auth.trust_device");
    let res = c.sign_in(EMAIL, PASSWORD).await;
    assert!(res.body.get("twoFactorRedirect").is_none(), "{}", res.text);
    assert!(c.has_session_cookie());
    assert_ne!(c.jar.get("better-auth.trust_device"), Some(&trust), "the trust cookie rotates");
}

#[tokio::test]
async fn backup_codes_are_single_use() {
    let (mut c, _) = setup(|_| {}).await;
    let (_, codes) = enable_totp(&mut c).await;
    sign_in_challenge(&mut c).await;
    let res = c.post("/two-factor/verify-backup-code", json!({ "code": codes[0] })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(c.has_session_cookie());
    sign_in_challenge(&mut c).await;
    let res = c.post("/two-factor/verify-backup-code", json!({ "code": codes[0] })).await;
    assert_eq!(res.body["code"], "INVALID_BACKUP_CODE");

    let user_id = res_user_id(&mut c).await;
    let view = c
        .auth
        .api(even_better_auth::api::ApiCall::new("viewBackupCodes").body(json!({ "userId": user_id })))
        .await
        .unwrap();
    assert_eq!(view.json()["backupCodes"].as_array().unwrap().len(), 9);
}

async fn res_user_id(c: &mut Client) -> String {
    let rows = c.auth.context().db.find_many("user", Default::default()).await.unwrap();
    rows[0]["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn per_challenge_attempt_budget() {
    let (mut c, _) = setup(|o| o.account_lockout.enabled = false).await;
    let (secret, _) = enable_totp(&mut c).await;
    sign_in_challenge(&mut c).await;
    for _ in 0..5 {
        assert_eq!(c.post("/two-factor/verify-totp", json!({ "code": "000000" })).await.body["code"], "INVALID_CODE");
    }
    let res = c.post("/two-factor/verify-totp", json!({ "code": otp::totp(&secret, 6, 30) })).await;
    assert_eq!(res.body["code"], "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");
    let res = c.post("/two-factor/verify-totp", json!({ "code": otp::totp(&secret, 6, 30) })).await;
    assert_eq!(res.body["code"], "INVALID_TWO_FACTOR_COOKIE", "the challenge is cancelled");
}

#[tokio::test]
async fn account_lockout_spans_challenges() {
    let (mut c, _) =
        setup(|o| o.account_lockout = AccountLockout { enabled: true, max_failed_attempts: 3, duration_seconds: 60 })
            .await;
    let (secret, _) = enable_totp(&mut c).await;
    sign_in_challenge(&mut c).await;
    for _ in 0..2 {
        c.post("/two-factor/verify-totp", json!({ "code": "000000" })).await;
    }
    sign_in_challenge(&mut c).await;
    c.post("/two-factor/verify-totp", json!({ "code": "000000" })).await;
    let res = c.post("/two-factor/verify-totp", json!({ "code": otp::totp(&secret, 6, 30) })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (429, Some("ACCOUNT_TEMPORARILY_LOCKED")));
}

#[tokio::test]
async fn otp_method() {
    let (mut c, sms) = setup(|_| {}).await;
    let res = c.post("/two-factor/enable", json!({ "password": PASSWORD, "method": "otp" })).await;
    assert_eq!(res.body["method"], "otp", "{}", res.text);
    assert_eq!(c.get("/get-session").await.body["user"]["twoFactorEnabled"], true);
    let body = sign_in_challenge(&mut c).await;
    assert_eq!(body["twoFactorMethods"], json!(["otp"]));
    assert_eq!(c.post("/two-factor/send-otp", json!({})).await.body["status"], true);
    let code = sms.0.lock().unwrap().last().unwrap().otp.clone();
    assert_eq!(code.len(), 6);
    assert_eq!(c.post("/two-factor/verify-otp", json!({ "code": "x" })).await.body["code"], "INVALID_CODE");
    let res = c.post("/two-factor/verify-otp", json!({ "code": code })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(c.has_session_cookie());
    let res = c.post("/two-factor/verify-otp", json!({ "code": code })).await;
    assert_eq!(res.body["code"], "OTP_HAS_EXPIRED", "codes are single use");
    // Re-verification while signed in uses its own code.
    c.post("/two-factor/send-otp", json!({})).await;
    let code = sms.0.lock().unwrap().last().unwrap().otp.clone();
    assert_eq!(c.post("/two-factor/verify-otp", json!({ "code": code })).await.status, 200);
}

#[tokio::test]
async fn disable_two_factor() {
    let (mut c, _) = setup(|_| {}).await;
    let (secret, _) = enable_totp(&mut c).await;
    sign_in_challenge(&mut c).await;
    c.post("/two-factor/verify-totp", json!({ "code": otp::totp(&secret, 6, 30), "trustDevice": true })).await;
    let res = c.post("/two-factor/disable", json!({ "password": PASSWORD })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(c.get("/get-session").await.body["user"]["twoFactorEnabled"], false);
    assert!(!c.jar.contains_key("better-auth.trust_device"));
    c.jar.clear();
    let res = c.sign_in(EMAIL, PASSWORD).await;
    assert!(res.body.get("twoFactorRedirect").is_none());
    assert!(c.has_session_cookie());
}
