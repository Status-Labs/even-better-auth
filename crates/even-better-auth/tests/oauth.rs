#![cfg(feature = "oauth")]

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use common::{BASE, Client, Res, options};
use even_better_auth::oauth2::{
    AuthorizationRequest, AuthorizationUrlParams, IdTokenConfig, JwksIdTokenConfig, JwksSource, OAuth2Tokens,
    OAuth2UserInfo, OAuthProvider, ProviderOptions, UserInfoRequest, UserInfoResult, ValidateCodeParams,
    create_authorization_url, decode_jwt_payload, generate_code_challenge,
};
use even_better_auth::{BetterAuthOptions, Error};
use serde_json::{Map, Value, json};

const JWT_KEY: &[u8] = b"mock-provider-id-token-signing-key";

#[derive(Default)]
struct MockState {
    /// Authorization code -> provider profile.
    profiles: HashMap<String, Value>,
    /// The PKCE challenge sent with the last authorization URL.
    challenge: Option<String>,
    refreshes: u32,
}

#[derive(Clone)]
struct Mock {
    options: ProviderOptions,
    state: Arc<Mutex<MockState>>,
}

impl Mock {
    fn new() -> Self {
        Self::with_options(ProviderOptions::new("mock-client", "mock-secret"))
    }

    fn with_options(options: ProviderOptions) -> Self {
        Self { options, state: Default::default() }
    }

    fn profile(&self, code: &str, profile: Value) {
        self.state.lock().unwrap().profiles.insert(code.into(), profile);
    }
}

#[async_trait]
impl OAuthProvider for Mock {
    fn id(&self) -> &str {
        "mock"
    }
    fn name(&self) -> &str {
        "Mock"
    }
    fn options(&self) -> &ProviderOptions {
        &self.options
    }

    fn account_subject(&self, profile: &Value, _tokens: &OAuth2Tokens) -> Option<String> {
        profile.get("id").or_else(|| profile.get("sub")).and_then(Value::as_str).map(str::to_owned)
    }

    async fn create_authorization_url(&self, p: AuthorizationUrlParams) -> even_better_auth::Result<url::Url> {
        let mut scopes = self.options.scopes_with_defaults(&["openid", "email"]);
        scopes.extend(p.scopes);
        self.state.lock().unwrap().challenge = Some(generate_code_challenge(&p.code_verifier));
        create_authorization_url(
            &self.options,
            AuthorizationRequest {
                authorization_endpoint: "https://idp.example.com/authorize".into(),
                redirect_uri: p.redirect_uri,
                state: p.state,
                code_verifier: Some(p.code_verifier),
                scopes,
                login_hint: p.login_hint,
                additional_params: p.additional_params,
                ..Default::default()
            },
        )
    }

    async fn validate_authorization_code(&self, p: ValidateCodeParams) -> even_better_auth::Result<OAuth2Tokens> {
        let state = self.state.lock().unwrap();
        let verifier = p.code_verifier.unwrap_or_default();
        if state.challenge.as_deref() != Some(generate_code_challenge(&verifier).as_str()) {
            return Err(Error::Other("PKCE verification failed".into()));
        }
        if !state.profiles.contains_key(&p.code) {
            return Err(Error::Other("invalid code".into()));
        }
        let data = json!({
            "access_token": format!("at-{}", p.code),
            "refresh_token": format!("rt-{}", p.code),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid email",
        });
        Ok(even_better_auth::oauth2::get_oauth2_tokens(data.as_object().unwrap()))
    }

    async fn get_user_info(&self, request: &UserInfoRequest) -> even_better_auth::Result<Option<UserInfoResult>> {
        let profile = match (&request.tokens.id_token, &request.tokens.access_token) {
            (Some(id_token), _) => Value::Object(decode_jwt_payload(id_token).unwrap_or_default()),
            (None, Some(at)) => {
                let code = at.strip_prefix("at-").unwrap_or(at);
                match self.state.lock().unwrap().profiles.get(code) {
                    Some(p) => p.clone(),
                    None => return Ok(None),
                }
            }
            _ => return Ok(None),
        };
        let user = OAuth2UserInfo {
            name: profile.get("name").and_then(Value::as_str).map(str::to_owned),
            email: profile.get("email").and_then(Value::as_str).map(str::to_owned),
            image: profile.get("picture").and_then(Value::as_str).map(str::to_owned),
            email_verified: profile.get("email_verified").and_then(Value::as_bool).unwrap_or(false),
            extra: Map::new(),
        };
        let user = self.options.map_profile(&profile, user);
        Ok(Some(UserInfoResult { user, data: profile }))
    }

    fn supports_refresh(&self) -> bool {
        true
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> even_better_auth::Result<OAuth2Tokens> {
        if !refresh_token.starts_with("rt-") {
            return Err(Error::Other("bad refresh token".into()));
        }
        let mut state = self.state.lock().unwrap();
        state.refreshes += 1;
        let data = json!({
            "access_token": format!("refreshed-{}", state.refreshes),
            "refresh_token": "rt-rotated",
            "expires_in": 3600,
        });
        Ok(even_better_auth::oauth2::get_oauth2_tokens(data.as_object().unwrap()))
    }

    fn id_token(&self) -> Option<IdTokenConfig> {
        let jwks = serde_json::from_value(
            json!({"keys": [{"kty": "oct", "kid": "mock", "k": URL_SAFE_NO_PAD.encode(JWT_KEY)}]}),
        )
        .unwrap();
        let mut config = JwksIdTokenConfig::new(JwksSource::Static(jwks), vec!["mock-client".into()]);
        config.issuer = vec!["https://idp.example.com".into()];
        Some(IdTokenConfig::Jwks(config))
    }
}

fn setup(configure: impl FnOnce(&mut BetterAuthOptions)) -> (BetterAuthOptions, Mock) {
    let (mut o, _) = options();
    let mock = Mock::new();
    o.social_providers = vec![Arc::new(mock.clone())];
    configure(&mut o);
    (o, mock)
}

fn profile(id: &str, email: &str, verified: bool) -> Value {
    json!({ "id": id, "email": email, "email_verified": verified, "name": "OAuth User", "picture": "https://img/x.png" })
}

fn query(url: &str) -> HashMap<String, String> {
    url::Url::parse(url).unwrap().query_pairs().into_owned().collect()
}

/// Start a social sign-in and return the `state` sent to the provider.
async fn start(c: &mut Client, path: &str, body: Value) -> String {
    let res = c.post(path, body).await;
    assert_eq!(res.status, 200, "{}", res.text);
    query(res.body["url"].as_str().unwrap())["state"].clone()
}

async fn callback(c: &mut Client, code: &str, state: &str) -> Res {
    c.get(&format!("/callback/mock?code={code}&state={state}")).await
}

/// Full redirect flow: sign-in/social, then the provider callback with `code`.
async fn oauth_sign_in(c: &mut Client, mock: &Mock, code: &str, profile: Value, body: Value) -> Res {
    mock.profile(code, profile);
    let state = start(c, "/sign-in/social", body).await;
    callback(c, code, &state).await
}

async fn account_id(c: &mut Client, provider: &str) -> String {
    let list = c.get("/list-accounts").await;
    list.body.as_array().unwrap().iter().find(|a| a["providerId"] == provider).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn sign_in_social_returns_authorization_url_and_state_cookie() {
    let (o, mock) = setup(|_| {});
    let mut c = Client::build(o).await;
    let res = c
        .post(
            "/sign-in/social",
            json!({"provider": "mock", "callbackURL": "/dashboard", "scopes": ["profile"], "loginHint": "a@b.com",
                   "additionalParams": {"foo": "bar"}, "additionalData": {"ref": "home"}}),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["redirect"], true);
    let url = res.body["url"].as_str().unwrap();
    assert_eq!(res.location().as_deref(), Some(url));
    assert!(url.starts_with("https://idp.example.com/authorize?"));
    let q = query(url);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], "mock-client");
    assert_eq!(q["redirect_uri"], format!("{BASE}/api/auth/callback/mock"));
    assert_eq!(q["scope"], "openid email profile");
    assert_eq!(q["login_hint"], "a@b.com");
    assert_eq!(q["foo"], "bar");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["state"].len(), 32);

    let cookie = res.cookie("better-auth.state").unwrap();
    assert!(cookie.contains("Max-Age=300") && cookie.contains("HttpOnly"), "{cookie}");

    let identifier = format!("auth-state:{}", q["state"]);
    let row = c.auth.context().internal_adapter.find_verification_value(&identifier).await.unwrap().unwrap();
    let data: Value = serde_json::from_str(&row.value).unwrap();
    assert_eq!(data["callbackURL"], "/dashboard");
    assert_eq!(data["oauthState"], q["state"].as_str());
    assert_eq!(data["ref"], "home");
    let verifier = data["codeVerifier"].as_str().unwrap();
    assert_eq!(verifier.len(), 128);
    assert_eq!(q["code_challenge"], generate_code_challenge(verifier));
    assert!(data["expiresAt"].as_i64().unwrap() > chrono::Utc::now().timestamp_millis());
    assert_eq!(mock.state.lock().unwrap().challenge.as_deref(), Some(q["code_challenge"].as_str()));

    let res = c.post("/sign-in/social", json!({"provider": "mock", "disableRedirect": true})).await;
    assert_eq!(res.body["redirect"], false);
    assert!(res.location().is_none());

    let res = c.post("/sign-in/social", json!({"provider": "nope"})).await;
    assert_eq!(res.status, 404);
    assert_eq!(res.body["code"], "PROVIDER_NOT_FOUND");

    let res = c.post("/sign-in/social", json!({"provider": "mock", "additionalParams": {"state": "x"}})).await;
    assert_eq!(res.status, 400);

    let res = c.post("/sign-in/social", json!({"provider": "mock", "callbackURL": "https://evil.com"})).await;
    assert_eq!(res.status, 403);
    assert_eq!(res.body["code"], "INVALID_CALLBACK_URL");
}

#[tokio::test]
async fn callback_creates_user_account_and_session() {
    let (o, mock) = setup(|_| {});
    let mut c = Client::build(o).await;
    let res = oauth_sign_in(
        &mut c,
        &mock,
        "code1",
        profile("123", "New@Example.com", true),
        json!({"provider": "mock", "callbackURL": "/dashboard"}),
    )
    .await;
    assert_eq!(res.status, 302, "{}", res.text);
    assert_eq!(res.location().as_deref(), Some("/dashboard"));
    assert!(c.has_session_cookie());
    assert!(res.cookie("better-auth.state").unwrap().contains("Max-Age=0"));

    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["email"], "new@example.com");
    assert_eq!(session.body["user"]["emailVerified"], true);
    assert_eq!(session.body["user"]["name"], "OAuth User");
    assert_eq!(session.body["user"]["image"], "https://img/x.png");

    let accounts = c.get("/list-accounts").await;
    let list = accounts.body.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["providerId"], "mock");
    assert_eq!(list[0]["accountId"], "123");
    assert_eq!(list[0]["scopes"], json!(["openid", "email"]));
    assert!(list[0].get("accessToken").is_none());
    assert!(list[0].get("scope").is_none());

    // The state is single-use.
    let state = start(&mut c, "/sign-in/social", json!({"provider": "mock"})).await;
    assert_eq!(callback(&mut c, "code1", &state).await.status, 302);
    let identifier = format!("auth-state:{state}");
    assert!(c.auth.context().internal_adapter.find_verification_value(&identifier).await.unwrap().is_none());
}

#[tokio::test]
async fn existing_user_signs_in_again_and_new_user_url() {
    let (o, mock) = setup(|_| {});
    let mut c = Client::build(o).await;
    let body = json!({"provider": "mock", "callbackURL": "/dashboard", "newUserCallbackURL": "/welcome"});
    let res = oauth_sign_in(&mut c, &mock, "first", profile("42", "repeat@example.com", true), body.clone()).await;
    assert_eq!(res.location().as_deref(), Some("/welcome"));
    let first_user = c.get("/get-session").await.body["user"]["id"].clone();

    c.jar.clear();
    let res = oauth_sign_in(&mut c, &mock, "second", profile("42", "repeat@example.com", true), body).await;
    assert_eq!(res.location().as_deref(), Some("/dashboard"));
    assert_eq!(c.get("/get-session").await.body["user"]["id"], first_user);
    assert_eq!(c.get("/list-accounts").await.body.as_array().unwrap().len(), 1);

    let id = account_id(&mut c, "mock").await;
    let res = c.post("/get-access-token", json!({"accountId": id})).await;
    assert_eq!(res.body["accessToken"], "at-second", "tokens are refreshed on sign-in");
}

async fn sign_up_verified(c: &mut Client, email: &str) {
    c.sign_up(email, "password1234").await;
    let mut update = Map::new();
    update.insert("emailVerified".into(), true.into());
    c.auth.context().internal_adapter.update_user_by_email(email, update).await.unwrap();
}

#[tokio::test]
async fn implicit_linking_rules() {
    // Untrusted provider with an unverified email: no linking.
    let (o, mock) = setup(|_| {});
    let mut c = Client::build(o).await;
    sign_up_verified(&mut c, "link@example.com").await;
    c.jar.clear();
    let body = json!({"provider": "mock", "callbackURL": "/dashboard", "errorCallbackURL": "/oops"});
    let res = oauth_sign_in(&mut c, &mock, "c1", profile("1", "link@example.com", false), body.clone()).await;
    assert_eq!(res.location().as_deref(), Some("/oops?error=account_not_linked"));
    assert!(!c.has_session_cookie());

    // Verified provider email links to the verified local user.
    let res = oauth_sign_in(&mut c, &mock, "c2", profile("1", "link@example.com", true), body.clone()).await;
    assert_eq!(res.location().as_deref(), Some("/dashboard"), "{:?}", res.location());
    assert_eq!(c.get("/list-accounts").await.body.as_array().unwrap().len(), 2);

    // Trusted provider links even when the provider email is unverified.
    let (o, mock) = setup(|o| o.account.account_linking.trusted_providers = vec!["mock".into()]);
    let mut c = Client::build(o).await;
    sign_up_verified(&mut c, "trusted@example.com").await;
    c.jar.clear();
    let res = oauth_sign_in(&mut c, &mock, "c3", profile("7", "trusted@example.com", false), body.clone()).await;
    assert_eq!(res.location().as_deref(), Some("/dashboard"));

    // The local user's email must be verified before implicit linking.
    c.jar.clear();
    c.sign_up("unverified@example.com", "password1234").await;
    c.jar.clear();
    let res = oauth_sign_in(&mut c, &mock, "c4", profile("8", "unverified@example.com", true), body.clone()).await;
    assert_eq!(res.location().as_deref(), Some("/oops?error=account_not_linked"));

    // Linking disabled entirely.
    let (o, mock) = setup(|o| o.account.account_linking.enabled = false);
    let mut c = Client::build(o).await;
    sign_up_verified(&mut c, "off@example.com").await;
    c.jar.clear();
    let res = oauth_sign_in(&mut c, &mock, "c5", profile("9", "off@example.com", true), body).await;
    assert_eq!(res.location().as_deref(), Some("/oops?error=account_not_linked"));
}

#[tokio::test]
async fn sign_up_restrictions() {
    let mut opts = ProviderOptions::new("mock-client", "mock-secret");
    opts.disable_implicit_sign_up = true;
    let mock = Mock::with_options(opts);
    let (mut o, _) = options();
    o.social_providers = vec![Arc::new(mock.clone())];
    let mut c = Client::build(o).await;
    let res = oauth_sign_in(&mut c, &mock, "a", profile("1", "a@example.com", true), json!({"provider": "mock"})).await;
    assert_eq!(res.location().as_deref(), Some(format!("{BASE}/api/auth/error?error=signup_disabled").as_str()));
    let res = oauth_sign_in(
        &mut c,
        &mock,
        "b",
        profile("1", "a@example.com", true),
        json!({"provider": "mock", "requestSignUp": true, "callbackURL": "/in"}),
    )
    .await;
    assert_eq!(res.location().as_deref(), Some("/in"));
}

#[tokio::test]
async fn state_errors() {
    let (o, mock) = setup(|_| {});
    let mut c = Client::build(o).await;
    mock.profile("code", profile("1", "s@example.com", true));
    let error_page = format!("{BASE}/api/auth/error");

    let res = c.get("/callback/mock?code=code").await;
    assert_eq!(res.location(), Some(format!("{error_page}?error=state_not_found")));

    let res = callback(&mut c, "code", "unknown-state").await;
    assert_eq!(res.location(), Some(format!("{error_page}?error=state_mismatch")));

    // Missing state cookie (e.g. a different browser) redirects to the flow's errorCallbackURL.
    let state = start(&mut c, "/sign-in/social", json!({"provider": "mock", "errorCallbackURL": "/err"})).await;
    c.jar.clear();
    let res = callback(&mut c, "code", &state).await;
    assert_eq!(res.location().as_deref(), Some("/err?error=state_mismatch"));

    // Expired state.
    let state = start(&mut c, "/sign-in/social", json!({"provider": "mock", "errorCallbackURL": "/err"})).await;
    let ia = &c.auth.context().internal_adapter;
    let identifier = format!("auth-state:{state}");
    let row = ia.find_verification_value(&identifier).await.unwrap().unwrap();
    let mut data: Value = serde_json::from_str(&row.value).unwrap();
    data["expiresAt"] = (chrono::Utc::now().timestamp_millis() - 1000).into();
    let mut update = Map::new();
    update.insert("value".into(), data.to_string().into());
    ia.update_verification_by_identifier(&identifier, update).await.unwrap();
    let res = callback(&mut c, "code", &state).await;
    assert_eq!(res.location().as_deref(), Some("/err?error=state_mismatch"));
    assert!(!c.has_session_cookie());

    // Provider-reported errors are forwarded.
    let state = start(&mut c, "/sign-in/social", json!({"provider": "mock"})).await;
    let res = c.get(&format!("/callback/mock?error=access_denied&error_description=nope&state={state}")).await;
    assert_eq!(res.location(), Some(format!("{error_page}?error=access_denied&error_description=nope")));

    // A bad code fails the exchange.
    let state = start(&mut c, "/sign-in/social", json!({"provider": "mock"})).await;
    let res = callback(&mut c, "bad", &state).await;
    assert_eq!(res.location(), Some(format!("{error_page}?error=invalid_code")));
}

#[tokio::test]
async fn cookie_state_strategy() {
    let (o, mock) = setup(|o| o.account.store_state_in_cookie = true);
    let mut c = Client::build(o).await;
    mock.profile("code", profile("5", "cookie@example.com", true));
    let res = c.post("/sign-in/social", json!({"provider": "mock", "callbackURL": "/home"})).await;
    let cookie = res.cookie("better-auth.oauth_state").unwrap();
    assert!(cookie.contains("Max-Age=600"), "{cookie}");
    assert!(res.cookie("better-auth.state").is_none());
    let state = query(res.body["url"].as_str().unwrap())["state"].clone();
    assert!(
        c.auth
            .context()
            .internal_adapter
            .find_verification_value(&format!("auth-state:{state}"))
            .await
            .unwrap()
            .is_none()
    );

    let res = callback(&mut c, "code", "tampered").await;
    assert_eq!(res.location(), Some(format!("{BASE}/api/auth/error?error=state_mismatch")));

    let res = callback(&mut c, "code", &state).await;
    assert_eq!(res.location().as_deref(), Some("/home"));
    assert!(res.cookie("better-auth.oauth_state").unwrap().contains("Max-Age=0"));
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "cookie@example.com");

    let res = callback(&mut c, "code", &state).await;
    assert_eq!(res.location(), Some(format!("{BASE}/api/auth/error?error=state_mismatch")));
}

#[tokio::test]
async fn form_post_callback_redirects_to_get() {
    let (o, _) = setup(|_| {});
    let c = Client::build(o).await;
    let req = http::Request::builder()
        .method("POST")
        .uri(format!("{BASE}/api/auth/callback/mock"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Bytes::from("code=abc&state=xyz&user=%7B%22name%22%3A1%7D&ignored=1"))
        .unwrap();
    let res = c.auth.handler(req).await;
    assert_eq!(res.status(), 302);
    let location = res.headers()["location"].to_str().unwrap();
    assert_eq!(location, format!("{BASE}/api/auth/callback/mock?code=abc&state=xyz&user=%7B%22name%22%3A1%7D"));
}

#[tokio::test]
async fn link_list_and_unlink_accounts() {
    let (o, mock) = setup(|_| {});
    let mut c = Client::build(o).await;
    sign_up_verified(&mut c, "me@example.com").await;

    let credential = account_id(&mut c, "credential").await;
    let res = c.post("/unlink-account", json!({"accountId": credential})).await;
    assert_eq!(res.status, 400);
    assert_eq!(res.body["code"], "FAILED_TO_UNLINK_LAST_ACCOUNT");

    mock.profile("link", profile("gh-1", "me@example.com", true));
    let state = start(&mut c, "/link-social", json!({"provider": "mock", "callbackURL": "/settings"})).await;
    let res = callback(&mut c, "link", &state).await;
    assert_eq!(res.location().as_deref(), Some("/settings"));
    let list = c.get("/list-accounts").await;
    let providers: Vec<&str> =
        list.body.as_array().unwrap().iter().map(|a| a["providerId"].as_str().unwrap()).collect();
    assert_eq!(providers.len(), 2);
    assert!(providers.contains(&"mock") && providers.contains(&"credential"));

    // A provider account with a different email is rejected.
    mock.profile("other", profile("gh-2", "someone@example.com", true));
    let state = start(
        &mut c,
        "/link-social",
        json!({"provider": "mock", "callbackURL": "/settings", "errorCallbackURL": "/settings"}),
    )
    .await;
    let res = callback(&mut c, "other", &state).await;
    assert_eq!(res.location().as_deref(), Some("/settings?error=email_does_not_match"));

    let res = c.post("/unlink-account", json!({"accountId": "missing"})).await;
    assert_eq!(res.body["code"], "ACCOUNT_NOT_FOUND");
    let linked = account_id(&mut c, "mock").await;
    let res = c.post("/unlink-account", json!({"accountId": linked})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["status"], true);
    assert_eq!(c.get("/list-accounts").await.body.as_array().unwrap().len(), 1);

    c.jar.clear();
    assert_eq!(c.post("/link-social", json!({"provider": "mock"})).await.status, 401);
    assert_eq!(c.get("/list-accounts").await.status, 401);
}

#[tokio::test]
async fn access_tokens_and_refresh() {
    let (o, mock) = setup(|o| o.account.encrypt_oauth_tokens = true);
    let mut c = Client::build(o).await;
    oauth_sign_in(&mut c, &mock, "tok", profile("t1", "tok@example.com", true), json!({"provider": "mock"})).await;
    let id = account_id(&mut c, "mock").await;
    let ia = c.auth.context().internal_adapter.clone();
    let stored = ia.find_account_by_id(&id).await.unwrap().unwrap();
    assert_ne!(stored.access_token.as_deref(), Some("at-tok"), "tokens are encrypted at rest");

    let res = c.post("/get-access-token", json!({"accountId": id})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["accessToken"], "at-tok");
    assert_eq!(res.body["scopes"], json!(["openid", "email"]));
    assert!(res.body["accessTokenExpiresAt"].is_string());

    // An expired token is refreshed and persisted.
    let mut expire = Map::new();
    expire.insert("accessTokenExpiresAt".into(), even_better_auth::utils::date::to_value(chrono::Utc::now()));
    ia.update_account(&id, expire).await.unwrap();
    let res = c.post("/get-access-token", json!({"accountId": id})).await;
    assert_eq!(res.body["accessToken"], "refreshed-1", "{}", res.text);
    let res = c.post("/get-access-token", json!({"accountId": id})).await;
    assert_eq!(res.body["accessToken"], "refreshed-1");

    let res = c.post("/refresh-token", json!({"accountId": id})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["accessToken"], "refreshed-2");
    assert_eq!(res.body["refreshToken"], "rt-rotated");
    assert_eq!(res.body["providerId"], "mock");
    assert_eq!(res.body["accountId"], id.as_str());
    assert_eq!(res.body["scope"], "openid,email");
    assert_eq!(c.post("/get-access-token", json!({"accountId": id})).await.body["accessToken"], "refreshed-2");

    let res = c.get(&format!("/account-info?accountId={id}")).await;
    assert_eq!(res.status, 401, "the refreshed token maps to no mock profile: {}", res.text);
    assert_eq!(res.body["code"], "FAILED_TO_GET_USER_INFO");

    let res = c.post("/get-access-token", json!({"accountId": "nope"})).await;
    assert_eq!(res.body["code"], "ACCOUNT_NOT_FOUND");
    let res = c.post("/get-access-token", json!({"accountId": id, "extra": 1})).await;
    assert_eq!(res.status, 400);
    let credential_less = c.post("/refresh-token", json!({})).await;
    assert_eq!(credential_less.status, 400);

    c.jar.clear();
    let res = c.post("/get-access-token", json!({"accountId": id})).await;
    assert_eq!(res.status, 401);
}

#[tokio::test]
async fn account_info_returns_provider_profile() {
    let (o, mock) = setup(|_| {});
    let mut c = Client::build(o).await;
    oauth_sign_in(&mut c, &mock, "info", profile("i1", "info@example.com", true), json!({"provider": "mock"})).await;
    let id = account_id(&mut c, "mock").await;
    let res = c.get(&format!("/account-info?accountId={id}")).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["user"]["email"], "info@example.com");
    assert_eq!(res.body["user"]["emailVerified"], true);
    assert_eq!(res.body["data"]["id"], "i1");
    assert_eq!(res.body["account"], json!({"id": id, "providerId": "mock", "accountId": "i1"}));
}

fn id_token(sub: &str, email: &str, verified: bool) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let now = chrono::Utc::now().timestamp();
    let claims = json!({"iss": "https://idp.example.com", "aud": "mock-client", "sub": sub, "email": email,
                        "email_verified": verified, "name": "Token User", "iat": now, "exp": now + 300});
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("mock".into());
    encode(&header, &claims, &EncodingKey::from_secret(JWT_KEY)).unwrap()
}

#[tokio::test]
async fn id_token_sign_in() {
    let (o, _) = setup(|_| {});
    let mut c = Client::build(o).await;
    let res = c
        .post("/sign-in/social", json!({"provider": "mock", "idToken": {"token": id_token("sub-1", "idt@example.com", true), "accessToken": "at-direct"}}))
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["redirect"], false);
    assert!(res.body["token"].is_string());
    assert!(res.body.get("url").is_none());
    assert_eq!(res.body["user"]["email"], "idt@example.com");
    assert!(c.has_session_cookie());
    let list = c.get("/list-accounts").await;
    assert_eq!(list.body[0]["accountId"], "sub-1");

    let forged = format!("{}x", id_token("sub-1", "idt@example.com", true));
    let res = c.post("/sign-in/social", json!({"provider": "mock", "idToken": {"token": forged}})).await;
    assert_eq!(res.status, 401);
    assert_eq!(res.body["code"], "INVALID_TOKEN");

    // An existing unlinked user with an unverified provider email is not linked.
    c.jar.clear();
    sign_up_verified(&mut c, "taken@example.com").await;
    c.jar.clear();
    let res = c
        .post(
            "/sign-in/social",
            json!({"provider": "mock", "idToken": {"token": id_token("sub-2", "taken@example.com", false)}}),
        )
        .await;
    assert_eq!(res.status, 401);
    assert_eq!(res.body["code"], "OAUTH_LINK_ERROR");
    assert_eq!(res.body["message"], "account not linked");

    // Linking an ID token to the signed-in user.
    c.sign_in("taken@example.com", "password1234").await;
    let res = c
        .post(
            "/link-social",
            json!({"provider": "mock", "idToken": {"token": id_token("sub-3", "taken@example.com", true)}}),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body, json!({"url": "", "status": true, "redirect": false}));
    assert_eq!(c.get("/list-accounts").await.body.as_array().unwrap().len(), 2);
    let res = c
        .post(
            "/link-social",
            json!({"provider": "mock", "idToken": {"token": id_token("sub-1", "taken@example.com", true)}}),
        )
        .await;
    assert_eq!(res.status, 409);
    assert_eq!(res.body["code"], "SOCIAL_ACCOUNT_ALREADY_LINKED");
}

#[tokio::test]
async fn require_email_verification_blocks_unverified_sign_in() {
    let mut opts = ProviderOptions::new("mock-client", "mock-secret");
    opts.require_email_verification = true;
    let mock = Mock::with_options(opts);
    let (mut o, _) = options();
    o.social_providers = vec![Arc::new(mock.clone())];
    let mut c = Client::build(o).await;
    let res = oauth_sign_in(
        &mut c,
        &mock,
        "u",
        profile("u1", "unv@example.com", false),
        json!({"provider": "mock", "errorCallbackURL": "/e"}),
    )
    .await;
    assert_eq!(res.location().as_deref(), Some("/e?error=email_not_verified"));
    assert!(!c.has_session_cookie());
}

#[tokio::test]
async fn override_user_info_and_profile_mapping() {
    let mut opts = ProviderOptions::new("mock-client", "mock-secret");
    opts.override_user_info_on_sign_in = true;
    opts.map_profile_to_user = Some(Arc::new(|p: &Value| {
        let mut m = Map::new();
        m.insert("name".into(), format!("Mapped {}", p["name"].as_str().unwrap_or_default()).into());
        m
    }));
    let mock = Mock::with_options(opts);
    let (mut o, _) = options();
    o.social_providers = vec![Arc::new(mock.clone())];
    let mut c = Client::build(o).await;
    oauth_sign_in(&mut c, &mock, "a", profile("m1", "map@example.com", true), json!({"provider": "mock"})).await;
    assert_eq!(c.get("/get-session").await.body["user"]["name"], "Mapped OAuth User");
    let mut changed = profile("m1", "map@example.com", true);
    changed["name"] = "Renamed".into();
    c.jar.clear();
    oauth_sign_in(&mut c, &mock, "b", changed, json!({"provider": "mock"})).await;
    assert_eq!(c.get("/get-session").await.body["user"]["name"], "Mapped Renamed");
}

#[tokio::test]
async fn validate_user_info_gates_creation_and_sign_in() {
    use even_better_auth::{UserInfoRejection, ValidateUserInfoFn};

    let seen = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let log = seen.clone();
    let (o, mock) = setup(move |o| {
        o.user.validate_user_info = Some(ValidateUserInfoFn::new(move |v| {
            let log = log.clone();
            async move {
                let email = v.user["email"].as_str().unwrap_or_default().to_owned();
                log.lock().unwrap().push((v.action.as_str().into(), v.source.method.clone(), email.clone()));
                assert!(v.source.oauth.as_ref().is_none_or(|p| p.profile.is_some()), "raw profile is passed");
                if email.ends_with("@blocked.com") {
                    return Ok(Some(UserInfoRejection::new("domain_blocked").with_description("Blocked domain")));
                }
                Ok(None)
            }
        }));
    });
    let mut c = Client::build(o).await;
    let body = json!({"provider": "mock", "callbackURL": "/dashboard"});

    let res = oauth_sign_in(&mut c, &mock, "c1", profile("1", "user@blocked.com", true), body.clone()).await;
    assert_eq!(res.status, 302);
    let location = res.location().unwrap();
    assert!(location.contains("error=domain_blocked"), "{location}");
    assert!(!c.has_session_cookie());

    let res = oauth_sign_in(&mut c, &mock, "c2", profile("2", "user@ok.com", true), body.clone()).await;
    assert_eq!(res.location().as_deref(), Some("/dashboard"));

    // The provider later reports a blocked email for the same account: sign-in is re-validated.
    c.jar.clear();
    let res = oauth_sign_in(&mut c, &mock, "c3", profile("2", "user@blocked.com", true), body).await;
    assert!(res.location().unwrap().contains("error=domain_blocked"));

    let mut sign_up = Client::new(c.auth.clone());
    let res = sign_up.sign_up("someone@blocked.com", "password1234").await;
    assert_eq!(res.status, 403, "{}", res.text);
    assert_eq!(res.body["code"], "domain_blocked");
    assert_eq!(res.body["message"], "Blocked domain");

    let log = seen.lock().unwrap().clone();
    let actions: Vec<(&str, &str)> = log.iter().map(|(a, m, _)| (a.as_str(), m.as_str())).collect();
    assert_eq!(
        actions,
        [("create-user", "oauth"), ("create-user", "oauth"), ("sign-in", "oauth"), ("create-user", "email-password")]
    );
}

#[tokio::test]
async fn stateless_mode_survives_a_restart() {
    let mock = Mock::new();
    let build = |mock: &Mock| {
        let mut o = BetterAuthOptions::stateless();
        o.base_url = Some(BASE.into());
        o.secret = Some("better-auth-secret-that-is-long-enough-for-tests".into());
        o.rate_limit.enabled = Some(false);
        o.social_providers = vec![Arc::new(mock.clone())];
        o
    };
    let mut c = Client::build(build(&mock)).await;
    let res = oauth_sign_in(
        &mut c,
        &mock,
        "sl1",
        profile("77", "stateless@example.com", true),
        json!({"provider": "mock", "callbackURL": "/app"}),
    )
    .await;
    assert_eq!(res.status, 302, "{}", res.text);
    assert!(res.cookie("better-auth.account_data").is_some(), "account cookie is set");
    assert!(res.cookie("better-auth.session_data").is_some(), "session lives in the cookie cache");

    // A new process: same secret, empty memory database.
    c.auth = even_better_auth::BetterAuth::new(build(&mock)).await.unwrap();
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["email"], "stateless@example.com", "{}", session.text);

    let res = c.post("/get-access-token", json!({"useAccountCookie": true})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["accessToken"], "at-sl1");

    let res = c.post("/refresh-token", json!({"useAccountCookie": true})).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["accessToken"], "refreshed-1");
    assert!(res.cookie("better-auth.account_data").is_some(), "refreshed tokens go back into the cookie");

    let res = c.post("/sign-out", json!({})).await;
    assert_eq!(res.status, 200);
    assert!(!c.jar.contains_key("better-auth.account_data"), "sign-out clears the account cookie");
}

#[tokio::test]
async fn last_login_method_records_provider() {
    use even_better_auth::plugins::last_login_method::{LastLoginMethodOptions, last_login_method};
    let (o, mock) = setup(|o| {
        o.plugins.push(last_login_method(LastLoginMethodOptions { store_in_database: true, ..Default::default() }))
    });
    let mut c = Client::build(o).await;
    let res =
        oauth_sign_in(&mut c, &mock, "code1", profile("123", "llm@example.com", true), json!({"provider": "mock"}))
            .await;
    assert!(
        res.cookie("better-auth.last_used_login_method")
            .unwrap()
            .starts_with("better-auth.last_used_login_method=mock;")
    );
    assert_eq!(c.get("/get-session").await.body["user"]["lastLoginMethod"], "mock");
}

#[tokio::test]
async fn oauth_proxy_preview_to_production() {
    use even_better_auth::plugins::oauth_proxy::{OAuthProxyOptions, oauth_proxy};
    let mock = Mock::new();
    let proxy = || {
        oauth_proxy(OAuthProxyOptions {
            current_url: Some("http://preview.test".into()),
            production_url: Some(BASE.into()),
            ..Default::default()
        })
    };
    let (mut preview_opts, preview_db) = options();
    preview_opts.base_url = Some("http://preview.test".into());
    preview_opts.social_providers = vec![Arc::new(mock.clone())];
    preview_opts.plugins.push(proxy());
    let mut preview = Client::build(preview_opts).await;
    let (mut prod_opts, prod_db) = options();
    prod_opts.social_providers = vec![Arc::new(mock.clone())];
    prod_opts.plugins.push(oauth_proxy(OAuthProxyOptions { production_url: Some(BASE.into()), ..Default::default() }));
    let mut production = Client::build(prod_opts).await;

    // Preview: the provider is told to redirect to production, with a proxy state package.
    mock.profile("pc1", profile("p-1", "proxy@example.com", true));
    let res = preview.post("/sign-in/social", json!({ "provider": "mock", "callbackURL": "/dashboard" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    let q = query(res.body["url"].as_str().unwrap());
    assert_eq!(q["redirect_uri"], format!("{BASE}/api/auth/callback/mock"));
    let package = q["state"].clone();
    assert!(package.len() > 64, "state is an encrypted package");

    // Production: exchanges the code and bounces back to the preview with the profile.
    let res = production.get(&format!("/callback/mock?code=pc1&state={}", encode_uri_component(&package))).await;
    assert_eq!(res.status, 302, "{}", res.text);
    let location = res.location().unwrap();
    assert!(
        location
            .starts_with("http://preview.test/api/auth/callback/mock/oauth-proxy?callbackURL=%2Fdashboard&profile="),
        "{location}"
    );
    assert!(prod_db.dump("user").await.is_empty(), "production creates no user");

    // Preview: completes the sign-in.
    let path = location.trim_start_matches("http://preview.test/api/auth");
    let res = preview.get(path).await;
    assert_eq!(res.status, 302, "{}", res.text);
    assert_eq!(res.location().as_deref(), Some("/dashboard"));
    assert_eq!(preview.get("/get-session").await.body["user"]["email"], "proxy@example.com");
    assert_eq!(preview_db.dump("account").await[0]["accountId"], "p-1");

    // A replayed or tampered profile is rejected.
    let res = preview.get(path).await;
    assert!(res.location().unwrap().contains("error=state_mismatch"), "{:?}", res.location());
    let res = preview.get("/callback/mock/oauth-proxy?callbackURL=%2Fdashboard&profile=garbage").await;
    assert!(res.location().unwrap().contains("error=invalid_profile"));

    // Production signing in through itself is not proxied.
    mock.profile("pc2", profile("p-2", "direct@example.com", true));
    let res = production.post("/sign-in/social", json!({ "provider": "mock", "callbackURL": "/home" })).await;
    let state = query(res.body["url"].as_str().unwrap())["state"].clone();
    assert_eq!(state.len(), 32, "plain state");
    let res = production.get(&format!("/callback/mock?code=pc2&state={state}")).await;
    assert_eq!(res.location().as_deref(), Some("/home"), "{}", res.text);
}

fn encode_uri_component(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::test]
async fn oauth_popup_flow() {
    use even_better_auth::plugins::oauth_popup::oauth_popup;
    let (mut o, mock) = setup(|o| o.trusted_origins = vec!["https://app.example.com".into()]);
    o.plugins.push(oauth_popup());
    o.plugins.push(even_better_auth::plugins::bearer::bearer(Default::default()));
    let mut c = Client::build(o).await;
    let popup_data = |html: &str| -> Value {
        let start = html.find(r#"id="better-auth-oauth-popup">"#).unwrap() + r#"id="better-auth-oauth-popup">"#.len();
        serde_json::from_str(&html[start..start + html[start..].find("</script>").unwrap()]).unwrap()
    };

    let res = c.get("/oauth-popup/start?provider=mock&popupOrigin=https%3A%2F%2Fevil.example&popupNonce=n1").await;
    assert_eq!(res.status, 403);

    let res = c
        .get("/oauth-popup/start?provider=mock&popupOrigin=https%3A%2F%2Fapp.example.com&popupNonce=n1&callbackURL=https%3A%2F%2Fevil.example")
        .await;
    assert_eq!(res.status, 200);
    let data = popup_data(&res.text);
    assert_eq!(data["error"]["code"], "invalid_callback_url");
    assert_eq!(data["targetOrigin"], "https://app.example.com");

    mock.profile("pop1", profile("pp-1", "popup@example.com", true));
    let res = c
        .get("/oauth-popup/start?provider=mock&popupOrigin=https%3A%2F%2Fapp.example.com&popupNonce=n2&callbackURL=%2Fhome")
        .await;
    assert_eq!(res.status, 302, "{}", res.text);
    let state = query(&res.location().unwrap())["state"].clone();
    assert!(c.jar.contains_key("better-auth.oauth_popup"));
    let res = c.get(&format!("/callback/mock?code=pop1&state={state}")).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.headers["content-type"], "text/html; charset=utf-8");
    assert!(res.headers["content-security-policy"].to_str().unwrap().contains("sha256-tIo2K8VBC9"));
    let data = popup_data(&res.text);
    assert_eq!(data["type"], "better-auth:oauth-popup");
    assert_eq!(data["nonce"], "n2");
    assert_eq!(data["redirectTo"], "/home");
    let token = data["token"].as_str().unwrap();
    assert_eq!(
        Some(token.to_owned()),
        c.jar.get("better-auth.session_token").cloned(),
        "the session cookie rides along"
    );
    assert!(!c.jar.contains_key("better-auth.oauth_popup"), "marker cleared");

    // Errors from the callback are relayed too.
    let res = c.get("/oauth-popup/start?provider=mock&popupOrigin=https%3A%2F%2Fapp.example.com&popupNonce=n3").await;
    let state = query(&res.location().unwrap())["state"].clone();
    let res = c.get(&format!("/callback/mock?error=access_denied&state={state}")).await;
    let data = popup_data(&res.text);
    assert_eq!(data["error"]["code"], "access_denied", "{}", res.text);

    // Ordinary redirect flows are untouched.
    mock.profile("plain", profile("pp-2", "plain@example.com", true));
    let state = start(&mut c, "/sign-in/social", json!({ "provider": "mock", "callbackURL": "/x" })).await;
    assert_eq!(callback(&mut c, "plain", &state).await.location().as_deref(), Some("/x"));
}
