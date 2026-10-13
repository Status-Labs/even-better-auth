mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::plugins::anonymous::{AnonymousLink, AnonymousOptions, anonymous};
use serde_json::{Value, json};

async fn setup(
    configure: impl FnOnce(&mut AnonymousOptions),
) -> (Client, Arc<Mutex<Vec<AnonymousLink>>>, Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    let links = Arc::new(Mutex::new(vec![]));
    let sink = links.clone();
    let mut opts = AnonymousOptions {
        on_link_account: Some(even_better_auth::options::Callback::new(move |l: AnonymousLink| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(l);
                Ok(())
            }
        })),
        ..Default::default()
    };
    configure(&mut opts);
    o.plugins.push(anonymous(opts));
    (Client::build(o).await, links, db)
}

#[tokio::test]
async fn anonymous_sign_in_and_linking() {
    let (mut c, links, db) = setup(|_| {}).await;
    let res = c.post("/sign-in/anonymous", json!({})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let anon_id = res.body["user"]["id"].as_str().unwrap().to_owned();
    assert_eq!(res.body["user"]["isAnonymous"], true);
    assert_eq!(res.body["user"]["name"], "Anonymous");
    assert!(res.body["user"]["email"].as_str().unwrap().ends_with("@anonymous.placeholder.invalid"));
    let again = c.post("/sign-in/anonymous", json!({})).await;
    assert_eq!(again.body["code"], "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY");

    let res = c.sign_up("real@test.com", "password1234").await;
    assert_eq!(res.status, 200, "{}", res.text);
    let link = links.lock().unwrap().last().cloned().expect("on_link_account ran");
    assert_eq!(link.anonymous_user.user.id, anon_id);
    assert_eq!(link.new_user.user.email, "real@test.com");
    assert!(db.dump("user").await.iter().all(|u| u["id"] != anon_id.as_str()), "the anonymous user is deleted");
    assert_eq!(c.get("/get-session").await.body["user"]["isAnonymous"], false);
}

#[tokio::test]
async fn delete_anonymous_user_and_options() {
    let (mut c, _, _) = setup(|o| {
        o.email_domain_name = Some("example.com".into());
        o.generate_name = Some(Arc::new(|| "Guest".into()));
    })
    .await;
    let res = c.post("/sign-in/anonymous", json!({})).await;
    assert!(res.body["user"]["email"].as_str().unwrap().starts_with("temp-"));
    assert!(res.body["user"]["email"].as_str().unwrap().ends_with("@example.com"));
    assert_eq!(res.body["user"]["name"], "Guest");
    let res = c.post("/delete-anonymous-user", json!({})).await;
    assert_eq!(res.body["success"], true, "{}", res.text);
    assert_eq!(c.get("/get-session").await.body, Value::Null);

    c.sign_up("x@test.com", "password1234").await;
    assert_eq!(c.post("/delete-anonymous-user", json!({})).await.body["code"], "USER_IS_NOT_ANONYMOUS");

    let (mut keep, _, db) = setup(|o| o.disable_delete_anonymous_user = true).await;
    keep.post("/sign-in/anonymous", json!({})).await;
    keep.sign_up("y@test.com", "password1234").await;
    assert_eq!(db.dump("user").await.len(), 2, "anonymous users are kept");
    assert_eq!(keep.post("/delete-anonymous-user", json!({})).await.body["code"], "DELETE_ANONYMOUS_USER_DISABLED");
}
