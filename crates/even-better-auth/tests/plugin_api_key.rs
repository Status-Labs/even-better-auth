mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{BASE, Client, options};
use even_better_auth::api::ApiCall;
use even_better_auth::db::Where;
use even_better_auth::plugins::api_key::{
    ApiKeyOptions, ApiKeyReferences, ApiKeyStorage, api_key, api_key_configurations,
};
use even_better_auth::plugins::organization::{OrganizationOptions, organization};
use even_better_auth::{MemoryAdapter, MemoryStorage};
use serde_json::{Value, json};

async fn setup(configure: impl FnOnce(&mut ApiKeyOptions)) -> (Client, Arc<MemoryAdapter>) {
    let (mut o, db) = options();
    let mut opts = ApiKeyOptions::default();
    configure(&mut opts);
    o.plugins.push(api_key(opts));
    (Client::build(o).await, db)
}

/// A server-side call (no request headers, so server-only fields are allowed).
async fn server(c: &Client, endpoint: &str, body: Value) -> Value {
    match c.auth.api(ApiCall::new(endpoint).body(body)).await {
        Ok(res) => res.json(),
        Err(e) => e.to_json(),
    }
}

async fn verify(c: &Client, key: &str) -> Value {
    server(c, "verifyApiKey", json!({ "key": key })).await
}

async fn user_id(c: &mut Client) -> String {
    c.get("/get-session").await.body["user"]["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn create_get_list_update_delete() {
    let (mut c, db) = setup(|_| {}).await;
    c.sign_up("u@test.com", "password1234").await;
    let res = c.post("/api-key/create", json!({ "name": "ci", "prefix": "my_" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let key = res.body["key"].as_str().unwrap().to_owned();
    assert!(key.starts_with("my_") && key.len() == 3 + 64, "{key}");
    assert!(key[3..].chars().all(|c| c.is_ascii_alphabetic()));
    assert_eq!(res.body["start"], &key[..6]);
    assert_eq!(res.body["prefix"], "my_");
    assert_eq!(res.body["configId"], "default");
    assert_eq!(res.body["rateLimitMax"], 10);
    assert_eq!(res.body["rateLimitTimeWindow"], 86_400_000);
    assert_eq!(res.body["permissions"], Value::Null);
    let id = res.body["id"].as_str().unwrap().to_owned();
    // Only the SHA-256 hash is stored.
    let rows = db.dump("apikey").await;
    assert_eq!(rows[0]["key"], even_better_auth::crypto::sha256_base64url(&key));

    let got = c.get(&format!("/api-key/get?id={id}")).await;
    assert_eq!(got.body["name"], "ci", "{}", got.text);
    assert!(got.body.get("key").is_none());

    let listed = c.get("/api-key/list").await;
    assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["apiKeys"][0]["id"], id.as_str());
    assert!(listed.body.get("limit").is_none());

    let res = c.post("/api-key/update", json!({ "keyId": id, "name": "renamed", "enabled": true })).await;
    assert_eq!(res.body["name"], "renamed", "{}", res.text);
    let res = c.post("/api-key/update", json!({ "keyId": id, "remaining": 5 })).await;
    assert_eq!(res.body["code"], "SERVER_ONLY_PROPERTY");
    let res = c.post("/api-key/update", json!({ "keyId": id })).await;
    assert_eq!(res.body["code"], "NO_VALUES_TO_UPDATE");

    // Server-only properties are rejected over HTTP; the owner comes from the session.
    let res = c.post("/api-key/create", json!({ "remaining": 3 })).await;
    assert_eq!(res.body["code"], "SERVER_ONLY_PROPERTY");
    let res = c.post("/api-key/create", json!({ "userId": "someone-else" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("UNAUTHORIZED_SESSION")));
    let res = c.post("/api-key/create", json!({ "prefix": "bad prefix!" })).await;
    assert_eq!(res.status, 400);

    // Other users can't see or delete the key.
    let mut other = Client::new(c.auth.clone());
    other.sign_up("o@test.com", "password1234").await;
    assert_eq!(other.get(&format!("/api-key/get?id={id}")).await.status, 404);
    assert_eq!(other.post("/api-key/delete", json!({ "keyId": id })).await.status, 404);
    assert_eq!(other.get("/api-key/list").await.body["total"], 0);

    let res = verify(&c, &key).await;
    assert_eq!(res["valid"], true, "{res}");
    assert!(res["key"].get("key").is_none());
    assert_eq!(res["key"]["requestCount"], 1);
    assert_eq!(verify(&c, "my_wrong").await["error"]["code"], "INVALID_API_KEY");
    // Verification is server-only.
    assert_eq!(c.post("/api-key/verify", json!({ "key": key })).await.status, 404);

    let res = c.post("/api-key/delete", json!({ "keyId": id })).await;
    assert_eq!(res.body, json!({ "success": true }));
    assert_eq!(c.get("/api-key/list").await.body["total"], 0);
    assert_eq!(verify(&c, &key).await["valid"], false);
}

#[tokio::test]
async fn quotas_refills_and_rate_limits() {
    let (mut c, _) = setup(|_| {}).await;
    c.sign_up("u@test.com", "password1234").await;
    let uid = user_id(&mut c).await;

    let limited = server(&c, "createApiKey", json!({ "userId": uid, "remaining": 2 })).await;
    let key = limited["key"].as_str().unwrap();
    assert_eq!(verify(&c, key).await["key"]["remaining"], 1);
    assert_eq!(verify(&c, key).await["key"]["remaining"], 0);
    let used_up = verify(&c, key).await;
    assert_eq!(used_up["error"]["code"], "USAGE_EXCEEDED", "{used_up}");
    assert_eq!(verify(&c, key).await["error"]["code"], "INVALID_API_KEY", "a used-up key is deleted");

    let refilling = server(
        &c,
        "createApiKey",
        json!({ "userId": uid, "remaining": 1, "refillAmount": 5, "refillInterval": 1000, "rateLimitEnabled": false }),
    )
    .await;
    let key = refilling["key"].as_str().unwrap();
    assert_eq!(verify(&c, key).await["key"]["remaining"], 0);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let res = verify(&c, key).await;
    assert_eq!(res["key"]["remaining"], 4, "{res}");
    assert!(res["key"]["lastRefillAt"].is_string());

    let rated =
        server(&c, "createApiKey", json!({ "userId": uid, "rateLimitMax": 2, "rateLimitTimeWindow": 60_000 })).await;
    let key = rated["key"].as_str().unwrap();
    assert_eq!(verify(&c, key).await["key"]["requestCount"], 1);
    assert_eq!(verify(&c, key).await["key"]["requestCount"], 2);
    let denied = verify(&c, key).await;
    assert_eq!(denied["error"]["code"], "RATE_LIMITED", "{denied}");
    assert_eq!(denied["error"]["message"], "Rate limit exceeded.");
    assert!(denied["error"]["details"]["tryAgainIn"].as_i64().unwrap() > 59_000);

    let res = server(&c, "createApiKey", json!({ "userId": uid, "refillAmount": 5 })).await;
    assert_eq!(res["code"], "REFILL_AMOUNT_AND_INTERVAL_REQUIRED");
    let res = server(&c, "createApiKey", json!({ "userId": uid, "expiresIn": 60 })).await;
    assert_eq!(res["code"], "EXPIRES_IN_IS_TOO_SMALL");
    let res = server(&c, "createApiKey", json!({})).await;
    assert_eq!(res["code"], "UNAUTHORIZED_SESSION");
}

#[tokio::test]
async fn expiry_disabled_keys_and_cleanup() {
    let (mut c, db) = setup(|_| {}).await;
    c.sign_up("u@test.com", "password1234").await;
    let res = c.post("/api-key/create", json!({ "expiresIn": 60 * 60 * 24 * 2 })).await;
    assert!(res.body["expiresAt"].is_string(), "{}", res.text);
    let (key, id) = (res.body["key"].as_str().unwrap().to_owned(), res.body["id"].as_str().unwrap().to_owned());

    let res = c.post("/api-key/update", json!({ "keyId": id, "enabled": false })).await;
    assert_eq!(res.body["enabled"], false);
    assert_eq!(verify(&c, &key).await["error"]["code"], "KEY_DISABLED");
    c.post("/api-key/update", json!({ "keyId": id, "enabled": true })).await;

    let past = json!("2020-01-01T00:00:00.000Z");
    let auth = c.auth.clone();
    let ctx = auth.context();
    ctx.db
        .update("apikey", &[Where::eq("id", id.as_str())], json!({ "expiresAt": past }).as_object().unwrap().clone())
        .await
        .unwrap();
    assert_eq!(verify(&c, &key).await["error"]["code"], "KEY_EXPIRED");
    assert!(db.dump("apikey").await.is_empty(), "expired keys are deleted on use");

    // Server-only bulk cleanup.
    let res = c.post("/api-key/create", json!({ "expiresIn": 60 * 60 * 24 * 2 })).await;
    let id = res.body["id"].as_str().unwrap();
    ctx.db
        .update("apikey", &[Where::eq("id", id)], json!({ "expiresAt": past }).as_object().unwrap().clone())
        .await
        .unwrap();
    let res = server(&c, "deleteAllExpiredApiKeys", json!({})).await;
    assert_eq!(res, json!({ "success": true, "error": null }));
    assert!(db.dump("apikey").await.is_empty());
}

#[tokio::test]
async fn permissions_and_metadata() {
    let (mut c, db) = setup(|o| o.enable_metadata = true).await;
    c.sign_up("u@test.com", "password1234").await;
    let uid = user_id(&mut c).await;
    let res = server(
        &c,
        "createApiKey",
        json!({ "userId": uid, "permissions": { "files": ["read", "list"] }, "metadata": { "plan": "pro" } }),
    )
    .await;
    assert_eq!(res["permissions"], json!({ "files": ["read", "list"] }), "{res}");
    assert_eq!(res["metadata"], json!({ "plan": "pro" }));
    assert_eq!(db.dump("apikey").await[0]["metadata"], "{\"plan\":\"pro\"}", "stored as a JSON string");
    let key = res["key"].as_str().unwrap();

    let check = |perms: Value| {
        let c = &c;
        async move { server(c, "verifyApiKey", json!({ "key": key, "permissions": perms })).await }
    };
    let ok = check(json!({ "files": ["read"] })).await;
    assert_eq!(ok["valid"], true, "{ok}");
    assert_eq!(ok["key"]["metadata"], json!({ "plan": "pro" }));
    assert_eq!(check(json!({ "files": ["write"] })).await["error"]["code"], "KEY_NOT_FOUND");
    assert_eq!(check(json!({ "users": ["read"] })).await["error"]["code"], "KEY_NOT_FOUND");

    let res = c.post("/api-key/create", json!({ "metadata": "not-an-object" })).await;
    assert_eq!(res.body["code"], "INVALID_METADATA_TYPE");

    let (mut c, _) = setup(|_| {}).await;
    c.sign_up("u@test.com", "password1234").await;
    let res = c.post("/api-key/create", json!({ "metadata": { "a": 1 } })).await;
    assert_eq!(res.body["code"], "METADATA_DISABLED");
}

async fn with_api_key(c: &Client, path: &str, key: &str) -> (u16, Value) {
    let req = http::Request::builder()
        .uri(format!("{BASE}/api/auth{path}"))
        .header("x-api-key", key)
        .body(bytes::Bytes::new())
        .unwrap();
    let res = c.auth.handler(req).await;
    (res.status().as_u16(), serde_json::from_slice(res.body()).unwrap_or(Value::Null))
}

#[tokio::test]
async fn sessions_from_api_keys() {
    let (mut c, _) = setup(|o| o.enable_session_for_api_keys = true).await;
    c.sign_up("u@test.com", "password1234").await;
    let key = c.post("/api-key/create", json!({})).await.body["key"].as_str().unwrap().to_owned();

    let (status, body) = with_api_key(&c, "/get-session", &key).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["user"]["email"], "u@test.com");
    // The key also authenticates other endpoints.
    let (status, body) = with_api_key(&c, "/api-key/list", &key).await;
    assert_eq!((status, body["total"].as_u64()), (200, Some(1)), "{body}");

    let (status, body) = with_api_key(&c, "/get-session", "short").await;
    assert_eq!((status, body["code"].as_str()), (403, Some("INVALID_API_KEY")));
    let (status, _) = with_api_key(&c, "/get-session", &"x".repeat(64)).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn secondary_storage() {
    for fallback in [false, true] {
        let (mut o, db) = options();
        o.secondary_storage = Some(Arc::new(MemoryStorage::default()));
        o.plugins.push(api_key(ApiKeyOptions {
            storage: ApiKeyStorage::SecondaryStorage,
            fallback_to_database: fallback,
            ..Default::default()
        }));
        let mut c = Client::build(o).await;
        c.sign_up("u@test.com", "password1234").await;
        let created = c.post("/api-key/create", json!({ "name": "a" })).await;
        assert_eq!(created.status, 200, "{}", created.text);
        c.post("/api-key/create", json!({ "name": "b" })).await;
        let (key, id) = (created.body["key"].as_str().unwrap(), created.body["id"].as_str().unwrap());
        assert_eq!(db.dump("apikey").await.len(), if fallback { 2 } else { 0 });

        let listed = c.get("/api-key/list?sortBy=name&sortDirection=desc&limit=1").await;
        assert_eq!(listed.body["total"], 2, "{}", listed.text);
        assert_eq!(listed.body["apiKeys"][0]["name"], "b");
        assert_eq!(listed.body["limit"], 1);

        let res = verify(&c, key).await;
        assert_eq!(res["key"]["requestCount"], 1, "{res}");
        assert_eq!(verify(&c, key).await["key"]["requestCount"], 2);
        let res = c.post("/api-key/update", json!({ "keyId": id, "name": "renamed" })).await;
        assert_eq!(res.body["name"], "renamed", "{}", res.text);
        assert_eq!(c.get(&format!("/api-key/get?id={id}")).await.body["requestCount"], 2);

        c.post("/api-key/delete", json!({ "keyId": id })).await;
        assert_eq!(c.get("/api-key/list").await.body["total"], 1);
        assert_eq!(verify(&c, key).await["valid"], false);
    }
}

#[tokio::test]
async fn organization_keys() {
    let (mut o, _) = options();
    o.plugins.push(organization(OrganizationOptions::default()));
    o.plugins.push(
        api_key_configurations(vec![
            ApiKeyOptions { config_id: Some("default".into()), ..Default::default() },
            ApiKeyOptions {
                config_id: Some("org".into()),
                references: ApiKeyReferences::Organization,
                default_prefix: Some("org_".into()),
                ..Default::default()
            },
        ])
        .unwrap(),
    );
    let mut owner = Client::build(o).await;
    owner.sign_up("owner@test.com", "password1234").await;
    let org = owner.post("/organization/create", json!({ "name": "Acme", "slug": "acme" })).await;
    let org_id = org.body["id"].as_str().unwrap().to_owned();

    let res = owner.post("/api-key/create", json!({ "configId": "org" })).await;
    assert_eq!(res.body["code"], "ORGANIZATION_ID_REQUIRED");
    let res = owner.post("/api-key/create", json!({ "configId": "org", "organizationId": org_id })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert!(res.body["key"].as_str().unwrap().starts_with("org_"));
    assert_eq!(res.body["referenceId"], org_id.as_str());
    let id = res.body["id"].as_str().unwrap().to_owned();
    owner.post("/api-key/create", json!({})).await;

    let org_list = owner.get(&format!("/api-key/list?organizationId={org_id}")).await;
    assert_eq!(org_list.body["total"], 1, "{}", org_list.text);
    let user_list = owner.get("/api-key/list").await;
    assert_eq!(user_list.body["total"], 1, "user and organization keys are listed separately");
    let got = owner.get(&format!("/api-key/get?id={id}&configId=org")).await;
    assert_eq!(got.status, 200, "{}", got.text);
    assert_eq!(owner.get(&format!("/api-key/get?id={id}")).await.status, 404, "wrong configuration");

    let mut outsider = Client::new(owner.auth.clone());
    outsider.sign_up("x@test.com", "password1234").await;
    let res = outsider.post("/api-key/create", json!({ "configId": "org", "organizationId": org_id })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (403, Some("USER_NOT_MEMBER_OF_ORGANIZATION")));
    let res = outsider.get(&format!("/api-key/get?id={id}&configId=org")).await;
    assert_eq!(res.body["code"], "USER_NOT_MEMBER_OF_ORGANIZATION");

    let res = owner.post("/api-key/delete", json!({ "keyId": id, "configId": "org" })).await;
    assert_eq!(res.body["success"], true, "{}", res.text);

    assert!(
        api_key_configurations(vec![
            ApiKeyOptions { config_id: Some("a".into()), ..Default::default() },
            ApiKeyOptions { config_id: Some("a".into()), ..Default::default() },
        ])
        .is_err()
    );
    assert!(api_key_configurations(vec![ApiKeyOptions::default(), ApiKeyOptions::default()]).is_err());
}

#[tokio::test]
async fn organization_keys_require_the_plugin() {
    let (mut o, _) = options();
    o.plugins.push(api_key(ApiKeyOptions { references: ApiKeyReferences::Organization, ..Default::default() }));
    let mut c = Client::build(o).await;
    c.sign_up("u@test.com", "password1234").await;
    let res = c.post("/api-key/create", json!({ "organizationId": "org-1" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (500, Some("ORGANIZATION_PLUGIN_REQUIRED")));
}

#[tokio::test]
async fn concurrent_verifications_respect_the_quota() {
    let (mut c, _) = setup(|o| o.rate_limit.enabled = false).await;
    c.sign_up("u@test.com", "password1234").await;
    let uid = user_id(&mut c).await;
    let key =
        server(&c, "createApiKey", json!({ "userId": uid, "remaining": 5 })).await["key"].as_str().unwrap().to_owned();
    let results = futures::future::join_all((0..20).map(|_| verify(&c, &key))).await;
    let valid = results.iter().filter(|r| r["valid"] == true).count();
    assert_eq!(valid, 5, "{results:?}");
}

/// Delays the final `updatedAt` stamp of a verification, so other verifications run while a
/// claim is finishing.
struct SlowStamp(Arc<MemoryAdapter>);

#[async_trait::async_trait]
impl even_better_auth::db::Adapter for SlowStamp {
    fn id(&self) -> &str {
        "slow-stamp"
    }
    async fn create(
        &self,
        t: &even_better_auth::db::Table,
        d: even_better_auth::db::Record,
    ) -> even_better_auth::Result<even_better_auth::db::Record> {
        self.0.create(t, d).await
    }
    async fn find_one(
        &self,
        t: &even_better_auth::db::Table,
        w: &[Where],
    ) -> even_better_auth::Result<Option<even_better_auth::db::Record>> {
        self.0.find_one(t, w).await
    }
    async fn find_many(
        &self,
        t: &even_better_auth::db::Table,
        q: &even_better_auth::db::FindManyQuery,
    ) -> even_better_auth::Result<Vec<even_better_auth::db::Record>> {
        self.0.find_many(t, q).await
    }
    async fn count(&self, t: &even_better_auth::db::Table, w: &[Where]) -> even_better_auth::Result<u64> {
        self.0.count(t, w).await
    }
    async fn update(
        &self,
        t: &even_better_auth::db::Table,
        w: &[Where],
        u: even_better_auth::db::Record,
    ) -> even_better_auth::Result<Option<even_better_auth::db::Record>> {
        if t.key == "apikey" && u.len() == 1 && u.contains_key("updatedAt") {
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        self.0.update(t, w, u).await
    }
    async fn update_many(
        &self,
        t: &even_better_auth::db::Table,
        w: &[Where],
        u: even_better_auth::db::Record,
    ) -> even_better_auth::Result<u64> {
        self.0.update_many(t, w, u).await
    }
    async fn delete(&self, t: &even_better_auth::db::Table, w: &[Where]) -> even_better_auth::Result<()> {
        self.0.delete(t, w).await
    }
    async fn delete_many(&self, t: &even_better_auth::db::Table, w: &[Where]) -> even_better_auth::Result<u64> {
        self.0.delete_many(t, w).await
    }
}

#[tokio::test]
async fn claimed_uses_survive_exhaustion_cleanup() {
    let (mut o, _) = options();
    let memory = Arc::new(MemoryAdapter::new());
    o.database = Arc::new(SlowStamp(memory));
    o.plugins.push(api_key(ApiKeyOptions { rate_limit: Default::default(), ..Default::default() }));
    let mut c = Client::build(o).await;
    c.sign_up("u@test.com", "password1234").await;
    let uid = user_id(&mut c).await;
    let key =
        server(&c, "createApiKey", json!({ "userId": uid, "remaining": 2, "rateLimitEnabled": false })).await["key"]
            .as_str()
            .unwrap()
            .to_owned();
    // Two verifications claim both uses and stall on their final write; a third then finds the
    // key used up and deletes it. The two claims must still succeed.
    let late = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        verify(&c, &key).await
    };
    let (a, b, third) = tokio::join!(verify(&c, &key), verify(&c, &key), late);
    assert_eq!(third["error"]["code"], "USAGE_EXCEEDED", "{third}");
    assert_eq!((a["valid"].clone(), b["valid"].clone()), (json!(true), json!(true)), "{a} {b}");
    assert_eq!(verify(&c, &key).await["error"]["code"], "INVALID_API_KEY", "the exhausted key was deleted");
}
