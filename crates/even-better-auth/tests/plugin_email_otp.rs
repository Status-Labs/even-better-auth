mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::api::ApiCall;
use even_better_auth::plugins::email_otp::{EmailOtpOptions, OtpEmail, OtpType, ResendStrategy, StoreOtp, email_otp};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Inbox(Arc<Mutex<Vec<OtpEmail>>>);

impl Inbox {
    fn options(&self) -> EmailOtpOptions {
        let inner = self.0.clone();
        EmailOtpOptions::new(even_better_auth::options::Callback::new(move |e: OtpEmail| {
            let inner = inner.clone();
            async move {
                inner.lock().unwrap().push(e);
                Ok(())
            }
        }))
    }
    fn last_for(&self, email: &str) -> Option<OtpEmail> {
        self.0.lock().unwrap().iter().rev().find(|e| e.email == email).cloned()
    }
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

async fn setup(
    configure: impl FnOnce(&mut EmailOtpOptions, &mut even_better_auth::BetterAuthOptions),
) -> (Client, Inbox) {
    let (mut o, _) = options();
    let inbox = Inbox::default();
    let mut opts = inbox.options();
    configure(&mut opts, &mut o);
    o.plugins.push(email_otp(opts));
    (Client::build(o).await, inbox)
}

async fn send(c: &mut Client, email: &str, otp_type: &str) -> common::Res {
    c.post("/email-otp/send-verification-otp", json!({ "email": email, "type": otp_type })).await
}

#[tokio::test]
async fn sign_in_with_otp_signs_up_new_users() {
    let (mut c, inbox) = setup(|_, _| {}).await;
    assert_eq!(send(&mut c, "Otp@Test.com", "sign-in").await.body["success"], true);
    let email = inbox.last_for("otp@test.com").expect("otp sent");
    assert_eq!((email.otp.len(), email.otp_type), (6, OtpType::SignIn));
    assert!(email.otp.chars().all(|c| c.is_ascii_digit()));

    let res = c.post("/sign-in/email-otp", json!({ "email": "otp@test.com", "otp": "000000x", "name": "N" })).await;
    assert_eq!(res.body["code"], "INVALID_OTP");
    let res =
        c.post("/sign-in/email-otp", json!({ "email": "otp@test.com", "otp": email.otp, "name": "Otp User" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(res.body["token"].is_string());
    assert_eq!(res.body["user"]["emailVerified"], true);
    assert_eq!(c.get("/get-session").await.body["user"]["name"], "Otp User");
    let res = c.post("/sign-in/email-otp", json!({ "email": "otp@test.com", "otp": email.otp })).await;
    assert_eq!(res.body["code"], "INVALID_OTP", "codes are single use");
}

#[tokio::test]
async fn attempts_are_limited_and_codes_expire() {
    let (mut c, inbox) = setup(|o, _| {
        o.allowed_attempts = 2;
        o.expires_in = 1;
    })
    .await;
    send(&mut c, "a@test.com", "sign-in").await;
    let otp = inbox.last_for("a@test.com").unwrap().otp;
    for _ in 0..2 {
        assert_eq!(
            c.post("/sign-in/email-otp", json!({ "email": "a@test.com", "otp": "999999x" })).await.body["code"],
            "INVALID_OTP"
        );
    }
    let res = c.post("/sign-in/email-otp", json!({ "email": "a@test.com", "otp": otp })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (403, Some("TOO_MANY_ATTEMPTS")));

    send(&mut c, "a@test.com", "sign-in").await;
    let otp = inbox.last_for("a@test.com").unwrap().otp;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let res = c.post("/sign-in/email-otp", json!({ "email": "a@test.com", "otp": otp })).await;
    assert_eq!(res.body["code"], "OTP_EXPIRED");
}

#[tokio::test]
async fn unknown_users_get_no_email_for_other_purposes() {
    let (mut c, inbox) = setup(|o, _| o.disable_sign_up = true).await;
    assert_eq!(send(&mut c, "ghost@test.com", "sign-in").await.body["success"], true);
    assert_eq!(send(&mut c, "ghost@test.com", "email-verification").await.body["success"], true);
    assert_eq!(c.post("/email-otp/request-password-reset", json!({ "email": "ghost@test.com" })).await.status, 200);
    assert_eq!(inbox.len(), 0);
    assert_eq!(send(&mut c, "x@test.com", "change-email").await.status, 400);
}

#[tokio::test]
async fn verify_email_and_reset_password() {
    let (mut c, inbox) = setup(|_, _| {}).await;
    c.sign_up("v@test.com", "password1234").await;
    send(&mut c, "v@test.com", "email-verification").await;
    let otp = inbox.last_for("v@test.com").unwrap().otp;
    let res = c
        .post(
            "/email-otp/check-verification-otp",
            json!({ "email": "v@test.com", "type": "email-verification", "otp": otp }),
        )
        .await;
    assert_eq!(res.body["success"], true, "checking does not consume the code");
    let res = c.post("/email-otp/verify-email", json!({ "email": "v@test.com", "otp": otp })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!((res.body["status"].as_bool(), res.body["user"]["emailVerified"].as_bool()), (Some(true), Some(true)));
    assert_eq!(c.get("/get-session").await.body["user"]["emailVerified"], true, "the cookie cache is refreshed");

    c.post("/email-otp/request-password-reset", json!({ "email": "v@test.com" })).await;
    let otp = inbox.last_for("v@test.com").unwrap();
    assert_eq!(otp.otp_type, OtpType::ForgetPassword);
    let res = c
        .post("/email-otp/reset-password", json!({ "email": "v@test.com", "otp": otp.otp, "password": "short" }))
        .await;
    assert_eq!(res.body["code"], "PASSWORD_TOO_SHORT");
    let res = c
        .post(
            "/email-otp/reset-password",
            json!({ "email": "v@test.com", "otp": otp.otp, "password": "new-password-1" }),
        )
        .await;
    assert_eq!(res.status, 200, "a rejected password leaves the code usable: {}", res.text);
    c.jar.clear();
    assert_eq!(c.sign_in("v@test.com", "new-password-1").await.status, 200);
}

#[tokio::test]
async fn unverified_accounts_lose_unproven_access_on_otp_sign_in() {
    let (mut c, inbox) = setup(|_, _| {}).await;
    let mut squatter = Client::new(c.auth.clone());
    squatter.sign_up("owner@test.com", "password1234").await;
    send(&mut c, "owner@test.com", "sign-in").await;
    let otp = inbox.last_for("owner@test.com").unwrap().otp;
    let res = c.post("/sign-in/email-otp", json!({ "email": "owner@test.com", "otp": otp })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(squatter.get("/get-session").await.body, Value::Null);
    let mut retry = Client::new(c.auth.clone());
    assert_eq!(retry.sign_in("owner@test.com", "password1234").await.status, 401, "the unproven password is removed");
}

#[tokio::test]
async fn change_email_with_otp() {
    let (mut c, inbox) = setup(|o, _| o.change_email.enabled = true).await;
    c.sign_up("old@test.com", "password1234").await;
    let res = c.post("/email-otp/request-email-change", json!({ "newEmail": "New@Test.com" })).await;
    assert_eq!(res.body["success"], true, "{}", res.text);
    let otp = inbox.last_for("new@test.com").unwrap();
    assert_eq!(otp.otp_type, OtpType::ChangeEmail);
    let res = c.post("/email-otp/change-email", json!({ "newEmail": "new@test.com", "otp": otp.otp })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let user = c.get("/get-session").await.body["user"].clone();
    assert_eq!((user["email"].as_str(), user["emailVerified"].as_bool()), (Some("new@test.com"), Some(true)));
}

#[tokio::test]
async fn storage_modes_reuse_and_server_endpoints() {
    for store in [StoreOtp::Hashed, StoreOtp::Encrypted] {
        let hashed = matches!(store, StoreOtp::Hashed);
        let (mut c, inbox) = setup(|o, _| {
            o.store_otp = store;
            o.resend_strategy = ResendStrategy::Reuse;
        })
        .await;
        send(&mut c, "s@test.com", "sign-in").await;
        send(&mut c, "s@test.com", "sign-in").await;
        let mails = inbox.0.lock().unwrap().clone();
        assert_eq!(mails[0].otp == mails[1].otp, !hashed, "only recoverable codes are reused");
        let got = c
            .auth
            .api(
                ApiCall::new("getVerificationOTP")
                    .query(json!({ "email": "s@test.com", "type": "sign-in" }).as_object().unwrap().clone()),
            )
            .await;
        if hashed {
            assert!(got.is_err());
        } else {
            assert_eq!(got.unwrap().json()["otp"], mails[1].otp.as_str());
        }
        let created = c
            .auth
            .api(ApiCall::new("createVerificationOTP").body(json!({ "email": "t@test.com", "type": "sign-in" })))
            .await
            .unwrap();
        let otp = created.json().as_str().unwrap().to_owned();
        let res = c.post("/sign-in/email-otp", json!({ "email": "t@test.com", "otp": otp })).await;
        assert_eq!(res.status, 200, "{}", res.text);
    }
}

#[tokio::test]
async fn override_default_email_verification_sends_otps() {
    let (mut c, inbox) = setup(|o, auth| {
        o.override_default_email_verification = true;
        auth.email_verification.send_on_sign_up = Some(true);
    })
    .await;
    c.sign_up("ov@test.com", "password1234").await;
    let otp = inbox.last_for("ov@test.com").expect("sign-up sent an OTP instead of a link");
    assert_eq!(otp.otp_type, OtpType::EmailVerification);
    let res = c.post("/email-otp/verify-email", json!({ "email": "ov@test.com", "otp": otp.otp })).await;
    assert_eq!(res.status, 200, "{}", res.text);

    let (mut c, inbox) = setup(|o, _| o.send_verification_on_sign_up = true).await;
    c.sign_up("hook@test.com", "password1234").await;
    assert_eq!(inbox.last_for("hook@test.com").unwrap().otp_type, OtpType::EmailVerification);
}
