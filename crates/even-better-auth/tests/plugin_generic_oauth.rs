#![cfg(feature = "oauth")]

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{Client, options};
use even_better_auth::BetterAuth;
use even_better_auth::oauth2::ClientAuthentication;
use even_better_auth::plugins::generic_oauth::{GenericOAuthConfig, GenericOAuthOptions, generic_oauth};
use serde_json::{Value, json};

const KEY: &[u8] = b"generic-oauth-idp-signing-key-0123456789";

#[derive(Default)]
struct Idp {
    base: String,
    /// Nonce to put in the next ID token (`None`: none).
    nonce: Option<String>,
    issue_id_token: bool,
    /// Returned by the user-info endpoint.
    profile: Value,
    token_requests: Vec<(HashMap<String, String>, Option<String>)>,
}

type Shared = Arc<Mutex<Idp>>;

fn sign(claims: Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("k1".into());
    jsonwebtoken::encode(&header, &claims, &jsonwebtoken::EncodingKey::from_secret(KEY)).unwrap()
}

async fn discovery(State(s): State<Shared>) -> Json<Value> {
    let base = s.lock().unwrap().base.clone();
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "userinfo_endpoint": format!("{base}/userinfo"),
        "end_session_endpoint": format!("{base}/logout"),
        "jwks_uri": "/jwks",
        "id_token_signing_alg_values_supported": ["HS256"],
    }))
}

async fn token(State(s): State<Shared>, headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Json<Value> {
    let mut idp = s.lock().unwrap();
    let auth = headers.get("authorization").map(|v| v.to_str().unwrap().to_owned());
    idp.token_requests.push((form, auth));
    let mut out = json!({ "access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer" });
    if idp.issue_id_token {
        let now = chrono::Utc::now().timestamp();
        let mut claims = json!({ "iss": idp.base, "aud": "client-1", "sub": "oidc-sub-1", "email": "oidc@example.com",
                                 "email_verified": true, "name": "OIDC User", "iat": now, "exp": now + 300 });
        if let Some(n) = &idp.nonce {
            claims["nonce"] = n.clone().into();
        }
        out["id_token"] = sign(claims).into();
    }
    Json(out)
}

async fn userinfo(State(s): State<Shared>, headers: HeaderMap) -> Json<Value> {
    assert_eq!(headers.get("authorization").unwrap(), "Bearer at-1");
    Json(s.lock().unwrap().profile.clone())
}

async fn idp() -> (String, Shared) {
    let state: Shared = Arc::default();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/jwks", get(|| async { Json(json!({ "keys": [{ "kty": "oct", "kid": "k1", "alg": "HS256", "k": URL_SAFE_NO_PAD.encode(KEY) }] })) }))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    state.lock().unwrap().base = base.clone();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, state)
}

fn query(url: &str) -> HashMap<String, String> {
    url::Url::parse(url).unwrap().query_pairs().into_owned().collect()
}

async fn build(configs: Vec<GenericOAuthConfig>) -> even_better_auth::Result<Client> {
    let (mut o, _) = options();
    o.plugins.push(generic_oauth(GenericOAuthOptions { config: configs })?);
    Ok(Client::new(BetterAuth::new(o).await?))
}

/// Start sign-in; returns the authorization URL's query.
async fn start(c: &mut Client, provider: &str) -> HashMap<String, String> {
    let res = c.post("/sign-in/social", json!({ "provider": provider, "callbackURL": "/home" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    query(res.body["url"].as_str().unwrap())
}

#[tokio::test]
async fn oidc_discovery_flow() {
    let (base, state) = idp().await;
    let mut config = GenericOAuthConfig::new("idp", "client-1");
    config.client_secret = Some("secret-1".into());
    config.discovery_url = Some(format!("{base}/.well-known/openid-configuration"));
    config.post_logout_redirect_uri = Some("/bye".into());
    let mut c = build(vec![config]).await.unwrap();

    let q = start(&mut c, "idp").await;
    assert_eq!(q["scope"], "openid", "openid added for OIDC providers");
    assert_eq!(q["client_id"], "client-1");
    assert_eq!(q["code_challenge_method"], "S256");
    let nonce = q.get("nonce").expect("nonce bound").clone();
    {
        let mut idp = state.lock().unwrap();
        idp.issue_id_token = true;
        idp.nonce = Some(nonce);
    }
    let res = c.get(&format!("/callback/idp?code=c1&state={}", q["state"])).await;
    assert_eq!(res.status, 302, "{}", res.text);
    assert_eq!(res.location().as_deref(), Some("/home"));
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["email"], "oidc@example.com");
    assert_eq!(session.body["user"]["emailVerified"], true);
    let accounts = c.get("/list-accounts").await;
    assert_eq!(accounts.body[0]["accountId"], "oidc-sub-1", "OIDC accounts are keyed by sub");
    let (form, auth) = state.lock().unwrap().token_requests[0].clone();
    assert_eq!(form["client_secret"], "secret-1");
    assert!(form.contains_key("code_verifier"));
    assert_eq!(auth, None);

    // A token whose nonce doesn't match the flow is rejected.
    let mut other = Client::new(c.auth.clone());
    let q = start(&mut other, "idp").await;
    state.lock().unwrap().nonce = Some("wrong".into());
    let res = other.get(&format!("/callback/idp?code=c2&state={}", q["state"])).await;
    assert!(res.location().unwrap().contains("error="), "{:?}", res.location());
    assert!(!other.has_session_cookie());

    // RP-initiated logout uses the discovered end_session_endpoint.
    let provider = c.auth.options().social_providers.iter().find(|p| p.id() == "idp").unwrap().clone();
    let url = provider
        .create_end_session_url(even_better_auth::oauth2::EndSessionParams {
            id_token: Some("tok".into()),
            post_logout_redirect_uri: None,
            state: Some("s".into()),
        })
        .unwrap();
    assert!(url.as_str().starts_with(&format!("{base}/logout?id_token_hint=tok")));
    let q = query(url.as_str());
    assert_eq!(q["post_logout_redirect_uri"], "http://localhost:3000/bye");
    assert_eq!(q["client_id"], "client-1");
    assert_eq!(q["state"], "s");
}

#[tokio::test]
async fn oauth2_endpoints_and_user_info() {
    let (base, state) = idp().await;
    state.lock().unwrap().profile =
        json!({ "id": 42, "email": "plain@example.com", "name": "Plain", "picture": "https://img/p.png", "team": "x" });
    let mut config = GenericOAuthConfig::new("plain", "client-1");
    config.client_secret = Some("secret-1".into());
    config.authorization_url = Some(format!("{base}/authorize?tenant=t1"));
    config.token_url = Some(format!("{base}/token"));
    config.user_info_url = Some(format!("{base}/userinfo"));
    config.token_endpoint_auth = Some(ClientAuthentication::Basic);
    config.scopes = vec!["read".into()];
    config.pkce = Some(false);
    config.authorization_url_params = vec![("audience".into(), "api".into())];
    config.token_url_params = vec![("resource".into(), "r1".into())];
    config.access_token_expires_in = Some(3600);
    config.map_profile_to_user = Some(Arc::new(|p| {
        serde_json::Map::from_iter([("name".to_owned(), json!(format!("{}!", p["name"].as_str().unwrap())))])
    }));
    let mut c = build(vec![config]).await.unwrap();

    let q = start(&mut c, "plain").await;
    assert_eq!(q["scope"], "read");
    assert_eq!(q["tenant"], "t1");
    assert_eq!(q["audience"], "api");
    assert!(!q.contains_key("code_challenge"));
    assert!(!q.contains_key("nonce"));
    let res = c.get(&format!("/callback/plain?code=c1&state={}", q["state"])).await;
    assert_eq!(res.status, 302, "{}", res.text);
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["email"], "plain@example.com", "{}", session.text);
    assert_eq!(session.body["user"]["name"], "Plain!");
    assert_eq!(session.body["user"]["image"], "https://img/p.png");
    assert_eq!(session.body["user"]["emailVerified"], false);
    assert_eq!(c.get("/list-accounts").await.body[0]["accountId"], "42");

    let (form, auth) = state.lock().unwrap().token_requests[0].clone();
    assert!(auth.unwrap().starts_with("Basic "));
    assert!(!form.contains_key("client_secret"));
    assert!(!form.contains_key("code_verifier"));
    assert_eq!(form["resource"], "r1");

    let account_id = c.get("/list-accounts").await.body[0]["id"].as_str().unwrap().to_owned();
    let token = c.post("/get-access-token", json!({ "accountId": account_id })).await;
    assert_eq!(token.body["accessToken"], "at-1", "{}", token.text);
    assert!(token.body["accessTokenExpiresAt"].is_string(), "default expiry applied");
}

#[tokio::test]
async fn configuration_errors() {
    let mut bad = GenericOAuthConfig::new("x", "client-1");
    bad.token_endpoint_auth = Some(ClientAuthentication::Basic);
    let err = generic_oauth(GenericOAuthOptions { config: vec![bad] }).err().unwrap();
    assert!(err.to_string().contains("requires clientSecret"), "{err}");

    let mut strict = GenericOAuthConfig::new("x", "client-1");
    strict.authorization_url = Some("https://idp/authorize".into());
    strict.token_url = Some("https://idp/token".into());
    strict.require_id_token_verification = true;
    let err = build(vec![strict]).await.err().unwrap();
    assert!(err.to_string().contains("requires verified ID tokens"), "{err}");

    // Failed discovery skips the provider instead of failing startup.
    let mut broken = GenericOAuthConfig::new("broken", "client-1");
    broken.discovery_url = Some("http://127.0.0.1:9/.well-known/openid-configuration".into());
    let mut c = build(vec![broken]).await.unwrap();
    let res = c.post("/sign-in/social", json!({ "provider": "broken" })).await;
    assert_eq!(res.status, 404, "{}", res.text);
}
