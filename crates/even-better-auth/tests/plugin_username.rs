mod common;

use std::sync::Arc;

use common::{Client, options};
use even_better_auth::plugins::username::{UsernameOptions, ValidationOrder, username};
use serde_json::{Value, json};

async fn client(configure: impl FnOnce(&mut UsernameOptions)) -> Client {
    let (mut o, _) = options();
    let mut opts = UsernameOptions::default();
    configure(&mut opts);
    o.plugins.push(username(opts));
    Client::build(o).await
}

async fn sign_up(c: &mut Client, email: &str, extra: Value) -> common::Res {
    let mut body = json!({ "email": email, "password": "password1234", "name": "N" });
    body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    c.post("/sign-up/email", body).await
}

async fn me(c: &mut Client) -> Value {
    c.get("/get-session").await.body["user"].clone()
}

#[tokio::test]
async fn sign_up_and_sign_in_with_username() {
    let mut c = client(|_| {}).await;
    let res = sign_up(&mut c, "u1@test.com", json!({ "username": "Custom_User" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let user = me(&mut c).await;
    assert_eq!(user["username"], "custom_user", "usernames are lowercased");
    assert_eq!(user["displayUsername"], "Custom_User", "displayUsername defaults to the input");

    c.jar.clear();
    let res = c.post("/sign-in/username", json!({ "username": "Custom_User", "password": "password1234" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(res.body["token"].is_string());
    assert_eq!(res.body["redirect"], false);
    assert_eq!(res.body["user"]["username"], "custom_user");
    assert!(c.has_session_cookie());

    let res = c
        .post(
            "/sign-in/username",
            json!({ "username": "custom_user", "password": "password1234", "callbackURL": "/home" }),
        )
        .await;
    assert_eq!(res.body["redirect"], true);
    assert_eq!(res.body["url"], "/home");
    assert_eq!(res.location().as_deref(), Some("/home"));

    let res = c.post("/sign-in/username", json!({ "username": "custom_user", "password": "wrong-password" })).await;
    assert_eq!(res.status, 401);
    assert_eq!(res.body["code"], "INVALID_USERNAME_OR_PASSWORD");
    let res = c.post("/sign-in/username", json!({ "username": "nobody", "password": "password1234" })).await;
    assert_eq!(res.status, 401);
}

#[tokio::test]
async fn validation_and_uniqueness() {
    let mut c = client(|_| {}).await;
    sign_up(&mut c, "a@test.com", json!({ "username": "taken_name" })).await;

    let mut other = Client::new(c.auth.clone());
    let res = sign_up(&mut other, "b@test.com", json!({ "username": "Taken_Name" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (400, Some("USERNAME_IS_ALREADY_TAKEN")));
    let res = sign_up(&mut other, "b@test.com", json!({ "username": "bad name!" })).await;
    assert_eq!(res.body["code"], "INVALID_USERNAME");
    let res = sign_up(&mut other, "b@test.com", json!({ "username": "ab" })).await;
    assert_eq!(res.body["code"], "USERNAME_TOO_SHORT");
    let res = sign_up(&mut other, "b@test.com", json!({ "username": "", "displayUsername": "valid_name" })).await;
    assert_eq!(res.body["code"], "USERNAME_TOO_SHORT", "an explicit empty username is not replaced");
    let res = sign_up(&mut other, "b@test.com", json!({ "username": "x".repeat(31) })).await;
    assert_eq!(res.body["code"], "USERNAME_TOO_LONG");

    // A valid displayUsername alone becomes the username; an invalid one does not.
    let res = sign_up(&mut other, "c@test.com", json!({ "displayUsername": "Display_Only" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let user = me(&mut other).await;
    assert_eq!(
        (user["username"].as_str(), user["displayUsername"].as_str()),
        (Some("display_only"), Some("Display_Only"))
    );
    let mut third = Client::new(c.auth.clone());
    let res = sign_up(&mut third, "d@test.com", json!({ "displayUsername": "Invalid Username" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let user = me(&mut third).await;
    assert!(user["username"].is_null());
    assert_eq!(user["displayUsername"], "Invalid Username");

    for (name, available) in [("TAKEN_NAME", false), ("free_name", true)] {
        let res = c.post("/is-username-available", json!({ "username": name })).await;
        assert_eq!(res.body["available"], available, "{name}");
    }
    let res = c.post("/is-username-available", json!({ "username": "no spaces" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (422, Some("INVALID_USERNAME")));
}

#[tokio::test]
async fn update_user_username() {
    let mut c = client(|_| {}).await;
    sign_up(&mut c, "a@test.com", json!({ "username": "first_user" })).await;
    let mut b = Client::new(c.auth.clone());
    sign_up(&mut b, "b@test.com", json!({ "username": "second_user" })).await;

    let res = c.post("/update-user", json!({ "username": "Renamed_User", "displayUsername": "Renamed!" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let user = me(&mut c).await;
    assert_eq!((user["username"].as_str(), user["displayUsername"].as_str()), (Some("renamed_user"), Some("Renamed!")));

    let res = c.post("/update-user", json!({ "username": "SECOND_USER" })).await;
    assert_eq!(res.body["code"], "USERNAME_IS_ALREADY_TAKEN");
    let res = c.post("/update-user", json!({ "username": "renamed_user" })).await;
    assert_eq!(res.status, 200, "keeping your own username is fine");
}

#[tokio::test]
async fn immutable_username() {
    let mut c = client(|o| o.immutable_username = true).await;
    sign_up(&mut c, "a@test.com", json!({ "username": "fixed_name" })).await;
    let res = c.post("/update-user", json!({ "username": "other_name" })).await;
    assert_eq!(res.body["code"], "USERNAME_IS_IMMUTABLE");
    assert_eq!(c.post("/update-user", json!({ "username": "Fixed_Name" })).await.status, 200);
    assert_eq!(c.post("/update-user", json!({ "displayUsername": "Anything" })).await.status, 200);

    let mut late = Client::new(c.auth.clone());
    sign_up(&mut late, "b@test.com", json!({})).await;
    assert_eq!(
        late.post("/update-user", json!({ "username": "now_set" })).await.status,
        200,
        "setting it once is allowed"
    );
}

#[tokio::test]
async fn custom_normalization_validation_and_display_rules() {
    let mut c = client(|o| {
        o.username_validation_order = ValidationOrder::PostNormalization;
        o.username_normalization = Some(Arc::new(|u: &str| u.split(' ').collect::<Vec<_>>().join("_").to_lowercase()));
        o.display_username_validator = Some(Arc::new(|d: &str| !d.contains("admin")));
    })
    .await;
    let res = sign_up(&mut c, "a@test.com", json!({ "username": "Test Username" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let user = me(&mut c).await;
    assert_eq!(
        (user["username"].as_str(), user["displayUsername"].as_str()),
        (Some("test_username"), Some("Test Username"))
    );
    let res = c.post("/update-user", json!({ "displayUsername": "the admin" })).await;
    assert_eq!(res.body["code"], "INVALID_DISPLAY_USERNAME");

    let mut no_display = client(|o| o.display_username = false).await;
    let res = sign_up(&mut no_display, "x@test.com", json!({ "username": "No_Display" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let user = me(&mut no_display).await;
    assert_eq!(user["username"], "no_display");
    assert!(user.get("displayUsername").is_none());
}

#[tokio::test]
async fn email_verification_is_checked_after_the_password() {
    let (mut o, _) = options();
    o.email_and_password.require_email_verification = true;
    o.plugins.push(username(UsernameOptions::default()));
    let mut c = Client::build(o).await;
    sign_up(&mut c, "v@test.com", json!({ "username": "verify_me" })).await;
    let res = c.post("/sign-in/username", json!({ "username": "verify_me", "password": "wrong-password" })).await;
    assert_eq!(res.body["code"], "INVALID_USERNAME_OR_PASSWORD");
    let res = c.post("/sign-in/username", json!({ "username": "verify_me", "password": "password1234" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (403, Some("EMAIL_NOT_VERIFIED")));
}
