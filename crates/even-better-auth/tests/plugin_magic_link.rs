mod common;

use std::sync::{Arc, Mutex};

use common::{BASE, Client, options};
use even_better_auth::plugins::magic_link::{MagicLinkEmail, MagicLinkOptions, StoreToken, magic_link};
use serde_json::json;

#[derive(Clone, Default)]
struct Inbox(Arc<Mutex<Vec<MagicLinkEmail>>>);

impl Inbox {
    fn options(&self) -> MagicLinkOptions {
        let inner = self.0.clone();
        MagicLinkOptions::new(even_better_auth::options::Callback::new(move |e: MagicLinkEmail| {
            let inner = inner.clone();
            async move {
                inner.lock().unwrap().push(e);
                Ok(())
            }
        }))
    }
    fn last(&self) -> MagicLinkEmail {
        self.0.lock().unwrap().last().cloned().expect("an email was sent")
    }
}

async fn setup(configure: impl FnOnce(&mut MagicLinkOptions)) -> (Client, Inbox, Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    let inbox = Inbox::default();
    let mut opts = inbox.options();
    configure(&mut opts);
    o.plugins.push(magic_link(opts));
    (Client::build(o).await, inbox, db)
}

/// The verify path + query of an emailed link, relative to `/api/auth`.
fn link_path(url: &str) -> String {
    url.strip_prefix(&format!("{BASE}/api/auth")).unwrap().to_owned()
}

#[tokio::test]
async fn sign_in_signs_up_new_users_and_links_are_single_use() {
    let (mut c, inbox, _) = setup(|_| {}).await;
    let res = c
        .post("/sign-in/magic-link", json!({ "email": "new@test.com", "name": "New", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome", "metadata": { "a": 1 } }))
        .await;
    assert_eq!((res.status, res.body["status"].as_bool()), (200, Some(true)), "{}", res.text);
    let email = inbox.last();
    assert_eq!(email.email, "new@test.com");
    assert_eq!(email.token.len(), 32);
    assert_eq!(email.metadata.as_ref().unwrap()["a"], 1);
    assert!(email.url.starts_with(&format!("{BASE}/api/auth/magic-link/verify?token={}", email.token)));

    let res = c.get(&link_path(&email.url)).await;
    assert_eq!(res.status, 302, "{}", res.text);
    assert_eq!(res.location().as_deref(), Some("http://localhost:3000/welcome"), "new users go to newUserCallbackURL");
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["email"], "new@test.com");
    assert_eq!(session.body["user"]["name"], "New");
    assert_eq!(session.body["user"]["emailVerified"], true);

    let res = c.get(&link_path(&email.url)).await;
    assert_eq!(res.location().as_deref(), Some("http://localhost:3000/dashboard?error=INVALID_TOKEN"));

    // A returning user lands on callbackURL; without a callbackURL the session is returned as JSON.
    c.post("/sign-in/magic-link", json!({ "email": "new@test.com", "callbackURL": "/dashboard" })).await;
    assert_eq!(
        c.get(&link_path(&inbox.last().url)).await.location().as_deref(),
        Some("http://localhost:3000/dashboard")
    );
    c.post("/sign-in/magic-link", json!({ "email": "new@test.com" })).await;
    let res = c.get(&format!("/magic-link/verify?token={}", inbox.last().token)).await;
    assert_eq!(res.status, 200);
    assert!(res.body["token"].is_string());
    assert_eq!(res.body["user"]["email"], "new@test.com");
}

#[tokio::test]
async fn unverified_accounts_lose_unproven_access() {
    let (mut c, inbox, db) = setup(|_| {}).await;
    let mut squatter = Client::new(c.auth.clone());
    squatter.sign_up("victim@test.com", "password1234").await;
    assert_eq!(db.dump("account").await.len(), 1);

    c.post("/sign-in/magic-link", json!({ "email": "victim@test.com" })).await;
    let res = c.get(&format!("/magic-link/verify?token={}", inbox.last().token)).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["user"]["emailVerified"], true);
    assert!(db.dump("account").await.is_empty(), "the unproven password account is removed");
    assert_eq!(squatter.get("/get-session").await.body, serde_json::Value::Null, "standing sessions are revoked");
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "victim@test.com");
}

#[tokio::test]
async fn disabled_sign_up_errors_and_expiry() {
    let (mut c, inbox, _) = setup(|o| {
        o.disable_sign_up = true;
        o.expires_in = 1;
    })
    .await;
    c.post(
        "/sign-in/magic-link",
        json!({ "email": "nobody@test.com", "callbackURL": "/app", "errorCallbackURL": "/oops" }),
    )
    .await;
    let res = c.get(&link_path(&inbox.last().url)).await;
    assert_eq!(res.location().as_deref(), Some("http://localhost:3000/oops?error=new_user_signup_disabled"));

    c.post("/sign-in/magic-link", json!({ "email": "nobody@test.com", "callbackURL": "/app" })).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let res = c.get(&link_path(&inbox.last().url)).await;
    assert_eq!(res.location().as_deref(), Some("http://localhost:3000/app?error=INVALID_TOKEN"));

    let res = c.post("/sign-in/magic-link", json!({ "email": "a@test.com", "callbackURL": "http://evil.com" })).await;
    assert_eq!(res.status, 403);
    let res = c.get(&format!("/magic-link/verify?token=x&callbackURL={}", "http%3A%2F%2Fevil.com")).await;
    assert_eq!(res.status, 403);
}

#[tokio::test]
async fn hashed_tokens_are_not_stored_in_plain_text() {
    let (mut c, inbox, db) = setup(|o| o.store_token = StoreToken::Hashed).await;
    c.post("/sign-in/magic-link", json!({ "email": "hash@test.com" })).await;
    let token = inbox.last().token;
    let rows = db.dump("verification").await;
    let identifier = rows[0]["identifier"].as_str().unwrap();
    assert!(!identifier.contains(&token));
    assert_eq!(identifier, format!("magic-link:{}", even_better_auth::crypto::sha256_base64url(&token)));
    let res = c.get(&format!("/magic-link/verify?token={token}")).await;
    assert_eq!(res.body["user"]["email"], "hash@test.com");
}
