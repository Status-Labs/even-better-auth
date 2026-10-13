mod common;

use common::{Client, options};
use even_better_auth::plugins::custom_session::{CustomSessionOptions, custom_session, custom_session_fn};
use even_better_auth::plugins::multi_session::multi_session;
use serde_json::{Value, json};

async fn setup() -> Client {
    let (mut o, _) = options();
    o.plugins.push(multi_session(Default::default()));
    o.plugins.push(custom_session(
        custom_session_fn(|s, _ctx| async move {
            Ok(json!({
                "roles": ["editor"],
                "user": { "id": s.user.id, "email": s.user.email, "newField": "newField" },
                "session": { "token": s.session.token },
            }))
        }),
        CustomSessionOptions { should_mutate_list_device_sessions_endpoint: true },
    ));
    Client::build(o).await
}

#[tokio::test]
async fn custom_get_session() {
    let mut c = setup().await;
    assert_eq!(c.get("/get-session").await.body, Value::Null);
    c.sign_up("a@test.com", "password1234").await;
    let res = c.get("/get-session").await;
    assert_eq!(res.body["roles"], json!(["editor"]), "{}", res.text);
    assert_eq!(res.body["user"]["newField"], "newField");
    assert_eq!(res.headers["cache-control"], "no-store");
}

#[tokio::test]
async fn custom_device_sessions() {
    let mut c = setup().await;
    c.sign_up("a@test.com", "password1234").await;
    c.sign_up("b@test.com", "password1234").await;
    let res = c.get("/multi-session/list-device-sessions").await;
    let list = res.body.as_array().unwrap_or_else(|| panic!("{}", res.text));
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|s| s["roles"] == json!(["editor"])));
}
