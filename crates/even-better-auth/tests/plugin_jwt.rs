mod common;

use common::{BASE, Client, options};
use even_better_auth::api::ApiCall;
use even_better_auth::crypto::jose::{JwsAlgorithm, PublicKey, verify_jws};
use even_better_auth::plugins::jwt::{JwtOptions, KeyPairConfig, jwt};
use even_better_auth::{BetterAuthOptions, CookieCacheStrategy};
use serde_json::{Map, Value, json};

async fn client(
    configure: impl FnOnce(&mut JwtOptions, &mut BetterAuthOptions),
) -> (Client, std::sync::Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    let mut opts = JwtOptions::default();
    configure(&mut opts, &mut o);
    o.plugins.push(jwt(opts).unwrap());
    (Client::build(o).await, db)
}

/// Verify `token` against the server's JWKS, returning its claims.
async fn verify_with_jwks(c: &mut Client, token: &str) -> Map<String, Value> {
    let jwks = c.get("/jwks").await.body;
    let header: Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    let key = jwks["keys"].as_array().unwrap().iter().find(|k| k["kid"] == header["kid"]).expect("kid in JWKS");
    let alg = JwsAlgorithm::parse(key["alg"].as_str().unwrap()).unwrap();
    let public = PublicKey::from_jwk(key.as_object().unwrap()).unwrap();
    verify_jws(token, &public, &[alg]).expect("signature verifies").payload
}

#[tokio::test]
async fn jwks_token_and_session_header() {
    let (mut c, db) = client(|_, _| {}).await;
    let res = c.get("/jwks").await;
    assert_eq!(res.status, 200);
    let keys = res.body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        (keys[0]["alg"].as_str(), keys[0]["kty"].as_str(), keys[0]["crv"].as_str()),
        (Some("EdDSA"), Some("OKP"), Some("Ed25519"))
    );
    assert!(keys[0].get("d").is_none(), "private material is never published");
    let stored = db.dump("jwks").await;
    assert!(!stored[0]["privateKey"].as_str().unwrap().contains("\"d\""), "private keys are encrypted at rest");

    assert_eq!(c.get("/token").await.status, 401);
    let up = c.sign_up("jwt@test.com", "password1234").await;
    let user_id = up.body["user"]["id"].as_str().unwrap().to_owned();
    let token = c.get("/token").await.body["token"].as_str().unwrap().to_owned();
    let claims = verify_with_jwks(&mut c, &token).await;
    assert_eq!(claims["sub"], user_id.as_str());
    assert_eq!(claims["email"], "jwt@test.com");
    assert_eq!(claims["iss"], BASE);
    assert_eq!(claims["aud"], BASE);
    assert_eq!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(), 900);

    let res = c.get("/get-session").await;
    let header = res.headers["set-auth-jwt"].to_str().unwrap().to_owned();
    assert_eq!(verify_with_jwks(&mut c, &header).await["sub"], user_id.as_str());
    assert!(res.headers["access-control-expose-headers"].to_str().unwrap().contains("set-auth-jwt"));

    // Server-side verification; the server-only endpoints are not reachable over HTTP.
    let verified = c.auth.api(ApiCall::new("verifyJWT").body(json!({ "token": token }))).await.unwrap();
    assert_eq!(verified.json()["payload"]["sub"], user_id.as_str());
    let forged = format!("{}x", &token[..token.len() - 2]);
    let rejected = c.auth.api(ApiCall::new("verifyJWT").body(json!({ "token": forged }))).await.unwrap();
    assert!(rejected.json()["payload"].is_null());
    let wrong_issuer =
        c.auth.api(ApiCall::new("verifyJWT").body(json!({ "token": token, "issuer": "https://other" }))).await.unwrap();
    assert!(wrong_issuer.json()["payload"].is_null());
    let signed =
        c.auth.api(ApiCall::new("signJWT").body(json!({ "payload": { "sub": "svc", "scope": "x" } }))).await.unwrap();
    let claims = verify_with_jwks(&mut c, signed.json()["token"].as_str().unwrap()).await;
    assert_eq!((claims["sub"].as_str(), claims["scope"].as_str()), (Some("svc"), Some("x")));
    assert_eq!(c.post("/sign-jwt", json!({ "payload": {} })).await.status, 404);
}

#[tokio::test]
async fn other_algorithms_and_claims() {
    for alg in [JwsAlgorithm::ES256, JwsAlgorithm::ES512, JwsAlgorithm::RS256, JwsAlgorithm::PS256] {
        let (mut c, _) = client(|o, _| {
            o.jwks.key_pair_config = KeyPairConfig::from(alg);
            o.jwt.issuer = Some("https://issuer.example".into());
            o.jwt.audience = Some(vec!["api-a".into(), "api-b".into()]);
            o.disable_setting_jwt_header = true;
        })
        .await;
        c.sign_up(&format!("{alg}@test.com"), "password1234").await;
        assert!(c.get("/get-session").await.headers.get("set-auth-jwt").is_none());
        let token = c.get("/token").await.body["token"].as_str().unwrap().to_owned();
        let claims = verify_with_jwks(&mut c, &token).await;
        assert_eq!(claims["iss"], "https://issuer.example", "{alg}");
        assert_eq!(claims["aud"], json!(["api-a", "api-b"]));
        let jwks = c.get("/jwks").await.body;
        assert_eq!(jwks["keys"][0]["alg"], alg.as_str());
    }
}

#[tokio::test]
async fn keys_rotate_and_expired_keys_stay_published_for_the_grace_period() {
    let (mut c, db) = client(|o, _| {
        o.jwks.rotation_interval = Some(1);
        o.jwks.grace_period = Some(60);
    })
    .await;
    c.sign_up("rotate@test.com", "password1234").await;
    let first = c.get("/token").await.body["token"].as_str().unwrap().to_owned();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let second = c.get("/token").await.body["token"].as_str().unwrap().to_owned();
    assert_eq!(db.dump("jwks").await.len(), 2, "a new key is minted once the old one expires");
    let jwks = c.get("/jwks").await.body;
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2, "the expired key is still published");
    verify_with_jwks(&mut c, &first).await;
    verify_with_jwks(&mut c, &second).await;
}

#[tokio::test]
async fn custom_jwks_path_and_option_validation() {
    let (mut c, _) = client(|o, _| o.jwks.jwks_path = "/.well-known/jwks.json".into()).await;
    assert_eq!(c.get("/.well-known/jwks.json").await.status, 200);
    assert_eq!(c.get("/jwks").await.status, 404);
    assert!(
        jwt(JwtOptions {
            jwks: even_better_auth::plugins::jwt::JwksOptions { jwks_path: "jwks".into(), ..Default::default() },
            ..Default::default()
        })
        .is_err()
    );
}

#[tokio::test]
async fn session_cookie_cache_is_signed_with_jwks_keys() {
    let (mut o, _) = options();
    o.session.cookie_cache.enabled = true;
    o.session.cookie_cache.strategy = CookieCacheStrategy::Compact;
    o.plugins.push(jwt(JwtOptions { session_cookie_cache: true, ..Default::default() }).unwrap());
    assert!(even_better_auth::BetterAuth::new(o).await.is_err(), "requires the jwt cookie-cache strategy");

    let (mut c, _) = client(|o, auth| {
        o.session_cookie_cache = true;
        auth.session.cookie_cache.enabled = true;
        auth.session.cookie_cache.strategy = CookieCacheStrategy::Jwt;
    })
    .await;
    let up = c.sign_up("cache@test.com", "password1234").await;
    let cookie = up.cookie("better-auth.session_data").unwrap();
    let value = cookie.split(';').next().unwrap().split_once('=').unwrap().1.to_owned();
    let header: Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["typ"], "better-auth.session-cache+jwt");
    assert_eq!(header["alg"], "EdDSA");
    let claims = verify_with_jwks(&mut c, &value).await;
    assert_eq!(claims["aud"], "better-auth:session-cache");
    assert_eq!(claims["sid"], up.body["token"]);
    // Served from the cache.
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "cache@test.com");
}
