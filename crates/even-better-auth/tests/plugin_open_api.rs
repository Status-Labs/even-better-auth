mod common;

use common::{Client, options};
use even_better_auth::db::Field;
use even_better_auth::plugins::open_api::{OpenApiOptions, open_api};
use even_better_auth::plugins::username::username;

async fn setup(opts: OpenApiOptions) -> Client {
    let (mut o, _) = options();
    o.user.table.additional_fields.push(("favoriteColor".into(), Field::string()));
    o.plugins.push(username(Default::default()));
    o.plugins.push(open_api(opts));
    Client::build(o).await
}

#[tokio::test]
async fn generates_schema() {
    let mut c = setup(Default::default()).await;
    let res = c.get("/open-api/generate-schema").await;
    assert_eq!(res.status, 200, "{}", res.text);
    let doc = res.body;
    assert_eq!(doc["openapi"], "3.1.1");

    let user = &doc["components"]["schemas"]["User"];
    assert_eq!(user["properties"]["email"]["type"], "string");
    assert_eq!(user["properties"]["createdAt"]["format"], "date-time");
    assert!(user["required"].as_array().unwrap().iter().any(|r| r == "email"));
    assert!(doc["components"]["schemas"]["Session"].is_object());

    let sign_up = &doc["paths"]["/sign-up/email"]["post"];
    assert_eq!(sign_up["operationId"], "signUpEmail");
    assert_eq!(sign_up["tags"], serde_json::json!(["Default"]));
    let body = &sign_up["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(body["properties"]["favoriteColor"]["type"], "string");
    assert_eq!(body["required"], serde_json::json!(["favoriteColor"]));
    assert!(body["properties"]["username"].is_object(), "plugin user fields are writable");
    assert!(sign_up["responses"]["401"].is_object());

    let reset = &doc["paths"]["/reset-password/{token}"]["get"];
    assert_eq!(reset["parameters"][0]["name"], "token");
    assert_eq!(doc["paths"]["/sign-in/username"]["post"]["tags"], serde_json::json!(["Username"]));
    assert!(doc["paths"]["/get-session"]["get"].is_object());
    assert!(doc["paths"].get("/open-api/generate-schema").is_none());
    assert!(doc["paths"].get("/set-password").is_none(), "server-only endpoints are left out");
}

#[tokio::test]
async fn reference_page() {
    let mut c = setup(OpenApiOptions { nonce: Some("abc".into()), ..Default::default() }).await;
    let res = c.get("/reference").await;
    assert_eq!(res.status, 200);
    assert_eq!(res.headers["content-type"], "text/html");
    assert!(res.text.contains(r#"<script nonce="abc">"#));
    assert!(res.text.contains("\"operationId\":\"signUpEmail\""));

    let mut c =
        setup(OpenApiOptions { disable_default_reference: true, path: "/docs".into(), ..Default::default() }).await;
    assert_eq!(c.get("/docs").await.status, 404);
    assert_eq!(c.get("/open-api/generate-schema").await.status, 200);
}
