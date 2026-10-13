mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Client, Outbox, options};
use even_better_auth::api::ApiCall;
use even_better_auth::db::Field;
use even_better_auth::{ChangeEmailArgs, Error};
use serde_json::{Map, json};

const EMAIL: &str = "test@test.com";
const PASSWORD: &str = "password1234";

/// Extract the reset token from `{base}/reset-password/{token}?callbackURL=...`.
fn reset_token(outbox: &Outbox) -> String {
    let url = outbox.last().unwrap().url;
    url.split('?').next().unwrap().rsplit('/').next().unwrap().to_owned()
}

fn headers(c: &Client) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    h.insert("cookie", c.cookie_header().parse().unwrap());
    h
}

async fn set_email_verified(c: &Client, email: &str) {
    let mut update = Map::new();
    update.insert("emailVerified".into(), true.into());
    c.auth.context().internal_adapter.update_user_by_email(email, update).await.unwrap();
}

async fn reset_client() -> (Client, Outbox) {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    o.email_and_password.send_reset_password = outbox.callback();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    (c, outbox)
}

#[tokio::test]
async fn request_password_reset_sends_email() {
    let (mut c, outbox) = reset_client().await;
    let res = c.post("/request-password-reset", json!({ "email": EMAIL, "redirectTo": "/reset" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["status"], true);
    assert_eq!(res.body["message"], "If this email exists in our system, check your email for the reset link");
    let email = outbox.last().unwrap();
    assert_eq!(email.user.email, EMAIL);
    assert_eq!(email.token.len(), 24);
    assert_eq!(
        email.url,
        format!("http://localhost:3000/api/auth/reset-password/{}?callbackURL=%2Freset", email.token)
    );

    let res = c.post("/request-password-reset", json!({ "email": EMAIL, "redirectTo": "http://evil.com" })).await;
    assert_eq!(res.status, 403);
    assert_eq!(res.body["message"], "Invalid redirectURL");

    let redirect = "http://localhost:3000?foo=bar&baz=qux";
    c.post("/request-password-reset", json!({ "email": EMAIL, "redirectTo": redirect })).await;
    let url = outbox.last().unwrap().url;
    assert!(!url.contains("foo=bar&baz=qux"));
    assert!(url.contains("callbackURL=http%3A%2F%2Flocalhost%3A3000%3Ffoo%3Dbar%26baz%3Dqux"), "{url}");

    let res = c.post("/request-password-reset", json!({ "email": "not-an-email" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn request_password_reset_does_not_reveal_users() {
    let (mut o, _) = options();
    o.email_and_password.send_reset_password =
        even_better_auth::callback(|_| async { Err(Error::Other("smtp down".into())) });
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;

    let existing = c.post("/request-password-reset", json!({ "email": EMAIL })).await;
    let missing = c.post("/request-password-reset", json!({ "email": "nobody@test.com" })).await;
    assert_eq!(existing.status, 200, "email failures must not surface: {}", existing.text);
    assert_eq!(existing.body, missing.body);
}

#[tokio::test]
async fn request_password_reset_disabled() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    let res = c.post("/request-password-reset", json!({ "email": EMAIL })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "RESET_PASSWORD_DISABLED");
}

#[tokio::test]
async fn reset_password_callback_redirects() {
    let (mut c, outbox) = reset_client().await;
    c.post("/request-password-reset", json!({ "email": EMAIL })).await;
    let token = reset_token(&outbox);

    let res = c.get(&format!("/reset-password/{token}?callbackURL=/cb")).await;
    assert_eq!(res.status, 302);
    assert_eq!(res.location().unwrap(), format!("http://localhost:3000/cb?token={token}"));

    let res = c.get("/reset-password/bogus?callbackURL=/cb").await;
    assert_eq!(res.status, 302);
    assert_eq!(res.location().unwrap(), "http://localhost:3000/cb?error=INVALID_TOKEN");

    let res = c.get(&format!("/reset-password/{token}?callbackURL=http://evil.com")).await;
    assert_eq!(res.status, 403);
    assert_eq!(res.body["code"], "INVALID_CALLBACK_URL");
}

#[tokio::test]
async fn reset_password_flow() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    let resets = Arc::new(AtomicUsize::new(0));
    let counter = resets.clone();
    o.email_and_password.send_reset_password = outbox.callback();
    o.email_and_password.on_password_reset = even_better_auth::callback(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    });
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    c.post("/request-password-reset", json!({ "email": EMAIL })).await;
    let token = reset_token(&outbox);

    let res = c.post("/reset-password", json!({ "newPassword": "short", "token": token })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "PASSWORD_TOO_SHORT");

    let res = c.post("/reset-password", json!({ "newPassword": "new-password" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "INVALID_TOKEN");

    let res = c.post(&format!("/reset-password?token={token}"), json!({ "newPassword": "new-password" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body, json!({ "status": true }));
    assert_eq!(resets.load(Ordering::SeqCst), 1);

    assert_eq!(c.sign_in(EMAIL, PASSWORD).await.status, 401);
    assert_eq!(c.sign_in(EMAIL, "new-password").await.status, 200);

    let res = c.post("/reset-password", json!({ "newPassword": "another-password", "token": token })).await;
    assert_eq!(res.status, 400, "token must be single use");
    assert_eq!(res.body["code"], "INVALID_TOKEN");
    assert_eq!(resets.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reset_password_token_expires() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    o.email_and_password.send_reset_password = outbox.callback();
    o.email_and_password.reset_password_token_expires_in = 1;
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    c.post("/request-password-reset", json!({ "email": EMAIL })).await;
    let token = reset_token(&outbox);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let res = c.get(&format!("/reset-password/{token}?callbackURL=/cb")).await;
    assert_eq!(res.location().unwrap(), "http://localhost:3000/cb?error=INVALID_TOKEN");
    let res = c.post("/reset-password", json!({ "newPassword": "new-password", "token": token })).await;
    assert_eq!(res.status, 400);
    assert_eq!(c.sign_in(EMAIL, PASSWORD).await.status, 200);
}

#[tokio::test]
async fn concurrent_resets_with_same_token() {
    let (mut c, outbox) = reset_client().await;
    c.post("/request-password-reset", json!({ "email": EMAIL })).await;
    let token = reset_token(&outbox);
    let mut a = Client::new(c.auth.clone());
    let mut b = Client::new(c.auth.clone());
    let (ra, rb) = tokio::join!(
        a.post("/reset-password", json!({ "newPassword": "password-a", "token": token })),
        b.post("/reset-password", json!({ "newPassword": "password-b", "token": token })),
    );
    let mut statuses = [ra.status, rb.status];
    statuses.sort();
    assert_eq!(statuses, [200, 400]);
    let winner = if ra.status == 200 { "password-a" } else { "password-b" };
    let loser = if ra.status == 200 { "password-b" } else { "password-a" };
    assert_eq!(c.sign_in(EMAIL, winner).await.status, 200);
    assert_eq!(c.sign_in(EMAIL, loser).await.status, 401);
}

#[tokio::test]
async fn reset_password_session_revocation() {
    for revoke in [true, false] {
        let (mut o, _) = options();
        let outbox = Outbox::default();
        o.email_and_password.send_reset_password = outbox.callback();
        o.email_and_password.revoke_sessions_on_password_reset = revoke;
        let mut c = Client::build(o).await;
        c.sign_up(EMAIL, PASSWORD).await;
        let mut other = Client::new(c.auth.clone());
        other.post("/request-password-reset", json!({ "email": EMAIL })).await;
        let res = other
            .post("/reset-password", json!({ "newPassword": "new-password", "token": reset_token(&outbox) }))
            .await;
        assert_eq!(res.status, 200);
        let session = c.get("/get-session").await;
        assert_eq!(session.body.is_null(), revoke, "revoke = {revoke}");
    }
}

#[tokio::test]
async fn verify_password() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let res = c.post("/verify-password", json!({ "password": PASSWORD })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body, json!({ "status": true }));

    let res = c.post("/verify-password", json!({ "password": "wrong-password" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "INVALID_PASSWORD");
    assert_eq!(res.body["message"], "Invalid password");

    let res = c.post("/verify-password", json!({ "password": "x".repeat(200) })).await;
    assert_eq!(res.body["code"], "PASSWORD_TOO_LONG");

    c.jar.clear();
    let res = c.post("/verify-password", json!({ "password": PASSWORD })).await;
    assert_eq!(res.status, 401);
}

#[tokio::test]
async fn update_user() {
    let (mut o, _) = options();
    o.user.table.additional_fields.push(("newField".into(), Field::string().optional()));
    o.user.table.additional_fields.push(("locked".into(), Field::string().optional().no_input()));
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;

    let res = c.post("/update-user", json!({ "name": "newName", "image": "https://img", "newField": "new" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body, json!({ "status": true }));
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["name"], "newName");
    assert_eq!(session.body["user"]["image"], "https://img");
    assert_eq!(session.body["user"]["newField"], "new");

    let res = c.post("/update-user", json!({ "image": null })).await;
    assert_eq!(res.status, 200);
    let session = c.get("/get-session?disableCookieCache=true").await;
    assert!(session.body["user"]["image"].is_null());

    let res = c.post("/update-user", json!({ "email": "other@test.com" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "EMAIL_CAN_NOT_BE_UPDATED");

    let res = c.post("/update-user", json!({})).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["message"], "No fields to update");

    let res = c.post("/update-user", json!({ "locked": "x" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["message"], "locked is not allowed to be set");

    let res = c.post("/update-user", json!(["not", "an", "object"])).await;
    assert_eq!(res.body["code"], "BODY_MUST_BE_AN_OBJECT");

    c.jar.clear();
    assert_eq!(c.post("/update-user", json!({ "name": "x" })).await.status, 401);
}

#[tokio::test]
async fn change_password() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;

    let res =
        c.post("/change-password", json!({ "currentPassword": "wrong-password", "newPassword": "new-password" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "INVALID_PASSWORD");
    assert_eq!(c.sign_in(EMAIL, "new-password").await.status, 401);

    let res = c.post("/change-password", json!({ "currentPassword": PASSWORD, "newPassword": "short" })).await;
    assert_eq!(res.body["code"], "PASSWORD_TOO_SHORT");

    let res = c.post("/change-password", json!({ "currentPassword": PASSWORD, "newPassword": "new-password" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(res.body["token"].is_null());
    assert_eq!(res.body["user"]["email"], EMAIL);
    assert!(res.body["user"].get("password").is_none());
    assert_eq!(c.sign_in(EMAIL, PASSWORD).await.status, 401);
    assert_eq!(c.sign_in(EMAIL, "new-password").await.status, 200);
}

#[tokio::test]
async fn change_password_revokes_other_sessions() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let mut other = Client::new(c.auth.clone());
    other.sign_in(EMAIL, PASSWORD).await;
    let old_cookie = c.jar["better-auth.session_token"].clone();

    let res = c
        .post(
            "/change-password",
            json!({ "currentPassword": PASSWORD, "newPassword": "new-password", "revokeOtherSessions": true }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    let token = res.body["token"].as_str().unwrap();
    assert_ne!(c.jar["better-auth.session_token"], old_cookie);
    assert!(other.get("/get-session").await.body.is_null());
    let session = c.get("/get-session").await;
    assert_eq!(session.body["session"]["token"], token);
}

#[tokio::test]
async fn set_password_is_server_only() {
    let (o, db) = options();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    assert_eq!(c.post("/set-password", json!({ "newPassword": "new-password" })).await.status, 404);

    let call = || ApiCall::new("setPassword").headers(headers(&c)).body(json!({ "newPassword": "new-password" }));
    let err = c.auth.api(call()).await.unwrap_err();
    assert_eq!(err.code(), Some("PASSWORD_ALREADY_SET"));

    let table = c.auth.context().schema.table("account").unwrap().clone();
    even_better_auth::Adapter::delete_many(&*db, &table, &[]).await.unwrap();
    let res = c.auth.api(call()).await.unwrap();
    assert_eq!(res.json(), json!({ "status": true }));
    assert_eq!(c.sign_in(EMAIL, "new-password").await.status, 200);
}

#[tokio::test]
async fn delete_user_disabled() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    assert_eq!(c.post("/delete-user", json!({})).await.status, 404);
    assert_eq!(c.get("/delete-user/callback?token=x").await.status, 404);
}

#[tokio::test]
async fn delete_user_with_fresh_session_or_password() {
    let (mut o, _) = options();
    o.user.delete_user.enabled = true;
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let res = c.post("/delete-user", json!({})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body, json!({ "success": true, "message": "User deleted" }));
    assert!(c.get("/get-session").await.body.is_null());
    assert_eq!(c.sign_in(EMAIL, PASSWORD).await.status, 401);

    let (mut o, _) = options();
    o.user.delete_user.enabled = true;
    o.session.fresh_age = 1;
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let res = c.post("/delete-user", json!({})).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "SESSION_EXPIRED");
    let res = c.post("/delete-user", json!({ "password": "wrong-password" })).await;
    assert_eq!(res.body["code"], "INVALID_PASSWORD");
    let res = c.post("/delete-user", json!({ "password": PASSWORD })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(c.sign_in(EMAIL, PASSWORD).await.status, 401);
}

#[tokio::test]
async fn delete_user_with_verification() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    let deleted = Arc::new(AtomicUsize::new(0));
    let counter = deleted.clone();
    o.user.delete_user.enabled = true;
    o.user.delete_user.send_delete_account_verification = outbox.callback();
    o.user.delete_user.after_delete = even_better_auth::callback(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        async { Ok(()) }
    });
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;

    let res = c.post("/delete-user", json!({ "password": PASSWORD, "callbackURL": "/bye" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body, json!({ "success": true, "message": "Verification email sent" }));
    let email = outbox.last().unwrap();
    assert_eq!(email.token.len(), 32);
    assert_eq!(
        email.url,
        format!("http://localhost:3000/api/auth/delete-user/callback?token={}&callbackURL=%2Fbye", email.token)
    );
    assert!(!c.get("/get-session").await.body.is_null());

    let res = c.get("/delete-user/callback?token=wrong").await;
    assert_eq!(res.status, 404);
    assert_eq!(res.body["code"], "INVALID_TOKEN");

    // A token is only valid for the user it was issued to.
    let mut other = Client::new(c.auth.clone());
    other.sign_up("other@test.com", PASSWORD).await;
    let res = other.get(&format!("/delete-user/callback?token={}", email.token)).await;
    assert_eq!(res.status, 404);
    assert_eq!(deleted.load(Ordering::SeqCst), 0);

    c.post("/delete-user", json!({})).await;
    let token = outbox.last().unwrap().token;
    let res = c.get(&format!("/delete-user/callback?token={token}&callbackURL=/bye")).await;
    assert_eq!(res.status, 302, "{}", res.text);
    assert_eq!(res.location().unwrap(), "/bye");
    assert_eq!(deleted.load(Ordering::SeqCst), 1);
    assert!(c.get("/get-session").await.body.is_null());
    assert!(!other.get("/get-session").await.body.is_null());
}

#[tokio::test]
async fn delete_user_with_token_in_body() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    o.user.delete_user.enabled = true;
    o.user.delete_user.send_delete_account_verification = outbox.callback();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    c.post("/delete-user", json!({})).await;
    let token = outbox.last().unwrap().token;
    let res = c.post("/delete-user", json!({ "token": token })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["message"], "User deleted");
    assert!(c.get("/get-session").await.body.is_null());
}

#[derive(Clone, Default)]
struct ChangeOutbox(Arc<Mutex<Vec<ChangeEmailArgs>>>);

impl ChangeOutbox {
    fn callback(&self) -> Option<even_better_auth::Callback<ChangeEmailArgs>> {
        let inner = self.0.clone();
        even_better_auth::callback(move |e: ChangeEmailArgs| {
            let inner = inner.clone();
            async move {
                inner.lock().unwrap().push(e);
                Ok(())
            }
        })
    }
    fn last(&self) -> Option<ChangeEmailArgs> {
        self.0.lock().unwrap().last().cloned()
    }
}

#[tokio::test]
async fn change_email_disabled_and_same() {
    let (o, _) = options();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let res = c.post("/change-email", json!({ "newEmail": "new@test.com" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "CHANGE_EMAIL_DISABLED");

    let (mut o, _) = options();
    o.user.change_email.enabled = true;
    o.user.change_email.update_email_without_verification = true;
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let res = c.post("/change-email", json!({ "newEmail": "TEST@test.com" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["message"], "Email is the same");
    let res = c.post("/change-email", json!({ "newEmail": "bad" })).await;
    assert_eq!(res.body["code"], "VALIDATION_ERROR");
}

#[tokio::test]
async fn change_email_without_verification() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    o.user.change_email.enabled = true;
    o.user.change_email.update_email_without_verification = true;
    o.email_verification.send_verification_email = outbox.callback();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;

    let res = c.post("/change-email", json!({ "newEmail": "New@Test.com", "callbackURL": "/done" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body, json!({ "status": true }));
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "new@test.com");
    let sent = outbox.last().unwrap();
    assert_eq!(sent.user.email, "new@test.com");
    assert!(sent.url.ends_with("&callbackURL=%2Fdone"), "{}", sent.url);

    // The credential account follows the user, so the new email signs in.
    assert_eq!(c.sign_in("new@test.com", PASSWORD).await.status, 200);
    assert_eq!(c.sign_in(EMAIL, PASSWORD).await.status, 401);
}

#[tokio::test]
async fn change_email_with_confirmation() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    let confirmations = ChangeOutbox::default();
    o.user.change_email.enabled = true;
    o.user.change_email.send_change_email_confirmation = confirmations.callback();
    o.email_verification.send_verification_email = outbox.callback();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    set_email_verified(&c, EMAIL).await;
    c.jar.clear();
    c.sign_in(EMAIL, PASSWORD).await;
    let new_email = "new@test.com";

    let res = c.post("/change-email", json!({ "newEmail": new_email, "callbackURL": "/x?from=y" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let confirmation = confirmations.last().unwrap();
    assert_eq!(confirmation.user.email, EMAIL);
    assert_eq!(confirmation.new_email, new_email);
    assert!(confirmation.url.ends_with("&callbackURL=%2Fx%3Ffrom%3Dy"), "{}", confirmation.url);
    assert_eq!(outbox.len(), 0);
    assert_eq!(c.get("/get-session").await.body["user"]["email"], EMAIL);

    let res = c.get(&format!("/verify-email?token={}", confirmation.token)).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(outbox.len(), 1);
    let verification = outbox.last().unwrap();
    assert_eq!(verification.user.email, new_email);
    assert_eq!(c.get("/get-session").await.body["user"]["email"], EMAIL);

    let res = c.get(&format!("/verify-email?token={}", verification.token)).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["email"], new_email);
    assert_eq!(session.body["user"]["emailVerified"], true);
}

#[tokio::test]
async fn change_email_verification_only() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    o.user.change_email.enabled = true;
    o.email_verification.send_verification_email = outbox.callback();
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let res = c.post("/change-email", json!({ "newEmail": "new@test.com" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let sent = outbox.last().unwrap();
    assert_eq!(sent.user.email, "new@test.com");
    c.get(&format!("/verify-email?token={}", sent.token)).await;
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["email"], "new@test.com");
    assert_eq!(session.body["user"]["emailVerified"], true);
}

#[tokio::test]
async fn change_email_enumeration_protection() {
    let (mut o, _) = options();
    let outbox = Outbox::default();
    o.user.change_email.enabled = true;
    o.email_verification.send_verification_email = outbox.callback();
    let mut c = Client::build(o).await;
    Client::new(c.auth.clone()).sign_up("taken@test.com", PASSWORD).await;
    c.sign_up(EMAIL, PASSWORD).await;
    let res = c.post("/change-email", json!({ "newEmail": "taken@test.com" })).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.body, json!({ "status": true }));
    assert_eq!(outbox.len(), 0);
    assert_eq!(c.get("/get-session").await.body["user"]["email"], EMAIL);

    // Without any usable flow, existing and new emails get the same error.
    let (mut o, _) = options();
    o.user.change_email.enabled = true;
    o.user.change_email.send_change_email_confirmation = ChangeOutbox::default().callback();
    let mut c = Client::build(o).await;
    Client::new(c.auth.clone()).sign_up("taken@test.com", PASSWORD).await;
    c.sign_up(EMAIL, PASSWORD).await;
    set_email_verified(&c, EMAIL).await;
    c.jar.clear();
    c.sign_in(EMAIL, PASSWORD).await;
    let existing = c.post("/change-email", json!({ "newEmail": "taken@test.com" })).await;
    let fresh = c.post("/change-email", json!({ "newEmail": "fresh@test.com" })).await;
    assert_eq!(existing.status, 400);
    assert_eq!(fresh.status, 400);
    assert_eq!(existing.body, fresh.body);
}

#[tokio::test]
async fn update_session() {
    let (mut o, _) = options();
    o.session.table.additional_fields.push(("theme".into(), Field::string().optional()));
    o.session.cookie_cache.enabled = true;
    let mut c = Client::build(o).await;
    c.sign_up(EMAIL, PASSWORD).await;

    let res = c.post("/update-session", json!({ "theme": "dark", "token": "hijack" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["session"]["theme"], "dark");
    assert_ne!(res.body["session"]["token"], "hijack");
    assert_eq!(c.get("/get-session").await.body["session"]["theme"], "dark");
    assert_eq!(c.get("/get-session?disableCookieCache=true").await.body["session"]["theme"], "dark");

    let res = c.post("/update-session", json!({ "expiresAt": "2099-01-01T00:00:00.000Z" })).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["message"], "No fields to update");

    // A cached session whose row is gone must not be re-minted.
    let token = c.get("/get-session").await.body["session"]["token"].as_str().unwrap().to_owned();
    c.auth.context().internal_adapter.delete_session(&token).await.unwrap();
    let res = c.post("/update-session", json!({ "theme": "light" })).await;
    assert_eq!(res.status, 401);
    assert_eq!(res.body["code"], "FAILED_TO_GET_SESSION");
    assert!(!c.has_session_cookie());
}
