mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::options::Callback;
use even_better_auth::plugins::phone_number::{
    PhoneNumberOptions, PhoneOtp, PhoneVerified, SignUpOnVerification, phone_number,
};
use serde_json::{Value, json};

type Codes = Arc<Mutex<Vec<PhoneOtp>>>;

fn sink(codes: &Codes) -> Callback<PhoneOtp> {
    let codes = codes.clone();
    Callback::new(move |otp: PhoneOtp| {
        let codes = codes.clone();
        async move {
            codes.lock().unwrap().push(otp);
            Ok(())
        }
    })
}

fn last(codes: &Codes) -> String {
    codes.lock().unwrap().last().expect("a code was sent").code.clone()
}

async fn setup(
    configure: impl FnOnce(&mut PhoneNumberOptions),
) -> (Client, Codes, Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    let codes: Codes = Arc::default();
    let mut opts = PhoneNumberOptions::new(sink(&codes));
    opts.send_password_reset_otp = Some(sink(&codes));
    opts.sign_up_on_verification = Some(SignUpOnVerification {
        get_temp_email: Arc::new(|p| format!("{}@phone.test", p.trim_start_matches('+'))),
        get_temp_name: None,
    });
    configure(&mut opts);
    o.plugins.push(phone_number(opts));
    (Client::build(o).await, codes, db)
}

const PHONE: &str = "+251911121314";

#[tokio::test]
async fn verify_signs_up_and_signs_in() {
    let verified = Arc::new(Mutex::new(vec![]));
    let seen = verified.clone();
    let (mut c, codes, _) = setup(|o| {
        o.callback_on_verification = Some(Callback::new(move |v: PhoneVerified| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(v.user.id);
                Ok(())
            }
        }))
    })
    .await;
    let res = c.post("/phone-number/send-otp", json!({ "phoneNumber": PHONE })).await;
    assert_eq!(res.body["message"], "code sent", "{}", res.text);
    let code = last(&codes);
    assert_eq!(code.len(), 6);

    let res = c.post("/phone-number/verify", json!({ "phoneNumber": PHONE, "code": "000000" })).await;
    assert_eq!(res.body["code"], "INVALID_OTP");
    let res = c.post("/phone-number/verify", json!({ "phoneNumber": PHONE, "code": code })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["user"]["phoneNumber"], PHONE);
    assert_eq!(res.body["user"]["phoneNumberVerified"], true);
    assert_eq!(res.body["user"]["name"], PHONE);
    assert_eq!(res.body["user"]["email"], "251911121314@phone.test");
    assert!(res.body["token"].is_string());
    assert_eq!(verified.lock().unwrap().len(), 1);
    assert_eq!(c.get("/get-session").await.body["user"]["phoneNumber"], PHONE);

    // The code is single-use.
    let res = c.post("/phone-number/verify", json!({ "phoneNumber": PHONE, "code": code })).await;
    assert_eq!(res.body["code"], "OTP_NOT_FOUND");

    // Verifying again finds the same user; disableSession returns no token.
    c.post("/phone-number/send-otp", json!({ "phoneNumber": PHONE })).await;
    let res = c
        .post("/phone-number/verify", json!({ "phoneNumber": PHONE, "code": last(&codes), "disableSession": true }))
        .await;
    assert_eq!(res.body["token"], Value::Null, "{}", res.text);
}

#[tokio::test]
async fn attempts_are_limited() {
    let (mut c, codes, _) = setup(|_| {}).await;
    c.post("/phone-number/send-otp", json!({ "phoneNumber": PHONE })).await;
    let code = last(&codes);
    for _ in 0..3 {
        let res = c.post("/phone-number/verify", json!({ "phoneNumber": PHONE, "code": "000000" })).await;
        assert_eq!(res.body["code"], "INVALID_OTP");
    }
    let res = c.post("/phone-number/verify", json!({ "phoneNumber": PHONE, "code": code })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (403, Some("TOO_MANY_ATTEMPTS")));
}

#[tokio::test]
async fn password_sign_in_update_and_reset() {
    let (mut c, codes, db) = setup(|o| o.require_verification = true).await;
    c.sign_up("p@test.com", "password1234").await;

    // Attach a number to the signed-in user.
    c.post("/phone-number/send-otp", json!({ "phoneNumber": PHONE })).await;
    let res = c
        .post("/phone-number/verify", json!({ "phoneNumber": PHONE, "code": last(&codes), "updatePhoneNumber": true }))
        .await;
    assert_eq!(res.body["user"]["email"], "p@test.com", "{}", res.text);
    assert_eq!(res.body["user"]["phoneNumberVerified"], true);

    // Changing the number through update-user is refused; clearing it resets verification.
    let res = c.post("/update-user", json!({ "phoneNumber": "+1555" })).await;
    assert_eq!(res.body["code"], "PHONE_NUMBER_CANNOT_BE_UPDATED");

    c.post("/sign-out", json!({})).await;
    let res = c.post("/sign-in/phone-number", json!({ "phoneNumber": PHONE, "password": "wrong-password" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("INVALID_PHONE_NUMBER_OR_PASSWORD")));
    let res = c.post("/sign-in/phone-number", json!({ "phoneNumber": PHONE, "password": "password1234" })).await;
    assert_eq!(res.body["user"]["email"], "p@test.com", "{}", res.text);

    // Reset the password with a code.
    let res = c.post("/phone-number/request-password-reset", json!({ "phoneNumber": PHONE })).await;
    assert_eq!(res.body["status"], true);
    let otp = last(&codes);
    let res = c
        .post("/phone-number/reset-password", json!({ "phoneNumber": PHONE, "otp": otp, "newPassword": "short" }))
        .await;
    assert_eq!(res.body["code"], "PASSWORD_TOO_SHORT");
    let res = c
        .post(
            "/phone-number/reset-password",
            json!({ "phoneNumber": PHONE, "otp": otp, "newPassword": "new-password-1" }),
        )
        .await;
    assert_eq!(res.body["status"], true, "{}", res.text);
    let res = c.post("/sign-in/phone-number", json!({ "phoneNumber": PHONE, "password": "new-password-1" })).await;
    assert_eq!(res.status, 200, "{}", res.text);

    let res = c.post("/update-user", json!({ "phoneNumber": null })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let users = db.dump("user").await;
    assert_eq!(users[0]["phoneNumber"], Value::Null);
    assert_eq!(users[0]["phoneNumberVerified"], false);

    // An unverified number cannot sign in with a password; a code is sent instead.
    let sent = codes.lock().unwrap().len();
    c.post("/sign-out", json!({})).await;
    c.sign_up("q@test.com", "password1234").await;
    let mut update = even_better_auth::db::Record::new();
    update.insert("phoneNumber".into(), "+1999".into());
    c.auth.context().internal_adapter.update_user_by_email("q@test.com", update).await.unwrap();
    let res = c.post("/sign-in/phone-number", json!({ "phoneNumber": "+1999", "password": "password1234" })).await;
    assert_eq!(res.body["code"], "PHONE_NUMBER_NOT_VERIFIED", "{}", res.text);
    assert_eq!(codes.lock().unwrap().len(), sent + 1);
}

#[tokio::test]
async fn send_otp_requires_sender_and_valid_number() {
    let (mut c, _, _) = setup(|o| {
        o.send_otp = None;
    })
    .await;
    let res = c.post("/phone-number/send-otp", json!({ "phoneNumber": PHONE })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (501, Some("SEND_OTP_NOT_IMPLEMENTED")));

    let (mut c, _, _) = setup(|o| {
        o.phone_number_validator = Some(Arc::new(|p: String| Box::pin(async move { Ok(p.starts_with('+')) })));
    })
    .await;
    let res = c.post("/phone-number/send-otp", json!({ "phoneNumber": "123" })).await;
    assert_eq!(res.body["code"], "INVALID_PHONE_NUMBER");
}
