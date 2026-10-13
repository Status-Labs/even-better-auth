//! JWT plugin (`plugins/jwt`): signs JWTs for sessions with asymmetric keys stored in a
//! `jwks` table (private keys encrypted with the auth secret), publishes them as a JWKS,
//! and supports rotation with a grace period.
//!
//! Endpoints: `GET /jwks` (configurable path), `GET /token`, and the server-only
//! `signJWT` / `verifyJWT`. A `set-auth-jwt` header is added to `/get-session` responses.
//! With `session_cookie_cache`, JWT-strategy session cookie caches are signed with these keys.

use std::any::Any;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler, hook};
use crate::context::AuthContext;
use crate::crypto::jose::{JwsAlgorithm, PrivateKey, PublicKey, decode_jws, sign_jws};
use crate::crypto::{symmetric_decrypt, symmetric_encrypt};
use crate::db::{Field, FindManyQuery, Record, TableExtension};
use crate::error::{ApiError, Error, Result};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::types::SessionWithUser;
use crate::utils::date;

/// A stored key (`Jwk`). `public_key` / `private_key` are JSON (the private key possibly
/// encrypted).
#[derive(Debug, Clone)]
pub struct Jwk {
    pub id: String,
    pub public_key: String,
    pub private_key: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub alg: Option<String>,
    pub crv: Option<String>,
}

impl Jwk {
    fn from_record(r: &Record) -> Option<Self> {
        let s = |k: &str| r.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            id: s("id")?,
            public_key: s("publicKey")?,
            private_key: s("privateKey")?,
            created_at: r.get("createdAt").and_then(date::parse_value)?,
            expires_at: r.get("expiresAt").and_then(date::parse_value),
            alg: s("alg"),
            crv: s("crv"),
        })
    }

    fn to_record(&self) -> Record {
        let mut r = Record::new();
        r.insert("publicKey".into(), self.public_key.clone().into());
        r.insert("privateKey".into(), self.private_key.clone().into());
        r.insert("createdAt".into(), date::to_value(self.created_at));
        if let Some(e) = self.expires_at {
            r.insert("expiresAt".into(), date::to_value(e));
        }
        if let Some(a) = &self.alg {
            r.insert("alg".into(), a.clone().into());
        }
        if let Some(c) = &self.crv {
            r.insert("crv".into(), c.clone().into());
        }
        r
    }

    fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|e| e > now)
    }
}

/// Key generation parameters (`JWKOptions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPairConfig {
    pub alg: JwsAlgorithm,
    /// RSA modulus length in bits (default 2048).
    pub modulus_length: Option<usize>,
}

impl Default for KeyPairConfig {
    fn default() -> Self {
        Self { alg: JwsAlgorithm::EdDSA, modulus_length: None }
    }
}

impl From<JwsAlgorithm> for KeyPairConfig {
    fn from(alg: JwsAlgorithm) -> Self {
        Self { alg, modulus_length: None }
    }
}

#[derive(Debug, Clone)]
pub struct JwksOptions {
    /// Serve keys from elsewhere: disables the JWKS endpoint (requires `key_pair_config`).
    pub remote_url: Option<String>,
    pub key_pair_config: KeyPairConfig,
    /// Further algorithms minted on first use by [`sign_jwt`] with `signing_algorithm`.
    pub key_pair_configs: Vec<KeyPairConfig>,
    /// Store private keys unencrypted.
    pub disable_private_key_encryption: bool,
    /// Rotate keys after this many seconds.
    pub rotation_interval: Option<i64>,
    /// Keep publishing expired keys for this many seconds (default 30 days).
    pub grace_period: Option<i64>,
    /// Path of the JWKS endpoint (default `/jwks`).
    pub jwks_path: String,
}

impl Default for JwksOptions {
    fn default() -> Self {
        Self {
            remote_url: None,
            key_pair_config: KeyPairConfig::default(),
            key_pair_configs: vec![],
            disable_private_key_encryption: false,
            rotation_interval: None,
            grace_period: None,
            jwks_path: "/jwks".into(),
        }
    }
}

/// When issued JWTs expire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiration {
    /// Seconds after `iat`.
    In(i64),
    /// An absolute `exp` (seconds since the epoch).
    At(i64),
}

pub type DefinePayload = Arc<dyn Fn(SessionWithUser) -> BoxFuture<'static, Result<Map<String, Value>>> + Send + Sync>;
pub type GetSubject = Arc<dyn Fn(SessionWithUser) -> BoxFuture<'static, Result<String>> + Send + Sync>;
/// Remote signing: receives the claims, extra protected-header members and overrides, and
/// returns a compact JWS (it must set `alg` and `kid` itself).
pub type RemoteSigner = Arc<
    dyn Fn(Map<String, Value>, Map<String, Value>, SigningOverrides) -> BoxFuture<'static, Result<String>>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct JwtClaimsOptions {
    /// Default: the base URL.
    pub issuer: Option<String>,
    /// Default: the base URL.
    pub audience: Option<Vec<String>>,
    /// Default 15 minutes.
    pub expiration_time: Expiration,
    pub define_payload: Option<DefinePayload>,
    /// Default: the user id.
    pub get_subject: Option<GetSubject>,
    /// Sign remotely (requires `jwks.remote_url`).
    pub sign: Option<RemoteSigner>,
}

impl Default for JwtClaimsOptions {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            expiration_time: Expiration::In(15 * 60),
            define_payload: None,
            get_subject: None,
            sign: None,
        }
    }
}

pub type GetJwks = Arc<dyn Fn(Arc<AuthContext>) -> BoxFuture<'static, Result<Vec<Jwk>>> + Send + Sync>;
pub type CreateJwk = Arc<dyn Fn(Jwk, Arc<AuthContext>) -> BoxFuture<'static, Result<Jwk>> + Send + Sync>;

/// Replace the database as the key store.
#[derive(Clone, Default)]
pub struct JwksAdapterOptions {
    pub get_jwks: Option<GetJwks>,
    pub create_jwk: Option<CreateJwk>,
}

#[derive(Clone, Default)]
pub struct JwtOptions {
    pub jwks: JwksOptions,
    pub jwt: JwtClaimsOptions,
    /// Do not add `set-auth-jwt` to `/get-session` responses.
    pub disable_setting_jwt_header: bool,
    /// Sign JWT-strategy session cookie caches with these keys
    /// (requires `session.cookie_cache.strategy = Jwt`).
    pub session_cookie_cache: bool,
    pub adapter: JwksAdapterOptions,
}

/// Per-call key selection (`SigningKeyOverrides`).
#[derive(Debug, Clone, Default)]
pub struct SigningOverrides {
    pub signing_key_id: Option<String>,
    pub signing_algorithm: Option<JwsAlgorithm>,
}

const DEFAULT_GRACE_PERIOD: i64 = 60 * 60 * 24 * 30;

// ---- key store ----------------------------------------------------------------------

async fn all_keys(auth: &Arc<AuthContext>, options: &JwtOptions) -> Result<Vec<Jwk>> {
    if let Some(get) = &options.adapter.get_jwks {
        return get(auth.clone()).await;
    }
    let rows = auth.db.find_many("jwks", FindManyQuery::default()).await?;
    Ok(rows.iter().filter_map(Jwk::from_record).collect())
}

fn newest(mut keys: Vec<Jwk>) -> Option<Jwk> {
    keys.sort_by_key(|k| std::cmp::Reverse(k.created_at));
    keys.into_iter().next()
}

fn primary_alg(options: &JwtOptions) -> JwsAlgorithm {
    options.jwks.key_pair_config.alg
}

fn key_alg(key: &Jwk, options: &JwtOptions) -> Option<JwsAlgorithm> {
    match &key.alg {
        Some(a) => JwsAlgorithm::parse(a),
        None => Some(primary_alg(options)),
    }
}

async fn latest_key_by_alg(auth: &Arc<AuthContext>, options: &JwtOptions, alg: JwsAlgorithm) -> Result<Option<Jwk>> {
    let now = Utc::now();
    let keys = all_keys(auth, options).await?;
    Ok(newest(keys.into_iter().filter(|k| key_alg(k, options) == Some(alg) && k.is_live(now)).collect()))
}

/// Generate a key for `config` and store it (`createJwk`).
pub async fn create_jwk(auth: &Arc<AuthContext>, options: &JwtOptions, config: KeyPairConfig) -> Result<Jwk> {
    let key = tokio::task::spawn_blocking(move || PrivateKey::generate(config.alg, config.modulus_length))
        .await
        .map_err(|e| Error::Crypto(e.to_string()))??;
    let public = key.public_key().to_jwk();
    let private = Value::Object(key.to_jwk()).to_string();
    let private_key = if options.jwks.disable_private_key_encryption {
        private
    } else {
        Value::String(symmetric_encrypt(&auth.secret_config, &private)?).to_string()
    };
    let now = Utc::now();
    let jwk = Jwk {
        id: String::new(),
        crv: public.get("crv").and_then(Value::as_str).map(str::to_owned),
        public_key: Value::Object(public).to_string(),
        private_key,
        created_at: now,
        expires_at: options.jwks.rotation_interval.map(|s| now + chrono::Duration::seconds(s)),
        alg: Some(config.alg.as_str().to_owned()),
    };
    if let Some(create) = &options.adapter.create_jwk {
        return create(jwk, auth.clone()).await;
    }
    let row = auth.db.create("jwks", jwk.to_record(), false).await?;
    Jwk::from_record(&row).ok_or_else(|| Error::Database("invalid jwks row".into()))
}

/// A decrypted signing key (`ResolvedSigningKey`).
#[derive(Clone)]
pub struct ResolvedSigningKey {
    pub alg: JwsAlgorithm,
    pub kid: String,
    pub key: PrivateKey,
}

fn decrypt_private_key(auth: &AuthContext, options: &JwtOptions, key: &Jwk) -> Result<PrivateKey> {
    let json = if options.jwks.disable_private_key_encryption {
        key.private_key.clone()
    } else {
        let encrypted: String = serde_json::from_str(&key.private_key)?;
        symmetric_decrypt(&auth.secret_config, &encrypted).map_err(|_| {
            Error::Crypto(
                "Failed to decrypt private key. Make sure the secret currently in use is the same as the one used to encrypt the private key. If you are using a different secret, either clean up your JWKS or disable private key encryption.".into(),
            )
        })?
    };
    let jwk: Map<String, Value> = serde_json::from_str(&json)?;
    PrivateKey::from_jwk(&jwk)
}

/// Pick, mint if needed, and decrypt the signing key (`resolveSigningKey`).
pub async fn resolve_signing_key(
    auth: &Arc<AuthContext>,
    options: &JwtOptions,
    overrides: &SigningOverrides,
) -> Result<ResolvedSigningKey> {
    let now = Utc::now();
    let pinned = overrides.signing_key_id.is_some() || overrides.signing_algorithm.is_some();
    let mut key = if let Some(kid) = &overrides.signing_key_id {
        let key = all_keys(auth, options).await?.into_iter().find(|k| &k.id == kid).ok_or_else(|| {
            Error::Config(format!(
                "signJWT: signingKeyId \"{kid}\" not found in JWKS. The key must be provisioned before it can be referenced."
            ))
        })?;
        if let Some(alg) = overrides.signing_algorithm
            && key_alg(&key, options) != Some(alg)
        {
            return Err(Error::Config(format!(
                "signJWT: signingKeyId \"{kid}\" has alg \"{}\" but signingAlgorithm was set to \"{alg}\".",
                key.alg.clone().unwrap_or_else(|| primary_alg(options).to_string())
            )));
        }
        Some(key)
    } else if let Some(alg) = overrides.signing_algorithm {
        match latest_key_by_alg(auth, options, alg).await? {
            Some(k) => Some(k),
            None => {
                let config = options.jwks.key_pair_configs.iter().find(|c| c.alg == alg).copied();
                let config = config.or((alg == primary_alg(options)).then_some(options.jwks.key_pair_config));
                let Some(config) = config else {
                    let extra: Vec<String> = options.jwks.key_pair_configs.iter().map(|c| c.alg.to_string()).collect();
                    let extra = if extra.is_empty() { "none".to_owned() } else { extra.join(", ") };
                    return Err(Error::Config(format!(
                        "signJWT: no key with alg \"{alg}\" found in JWKS. The plugin auto-mints only one key matching keyPairConfig.alg=\"{}\"; additional algs configured via keyPairConfigs: {extra}. Add \"{alg}\" to jwks.keyPairConfigs so the plugin provisions it on first use, or mint the key explicitly via createJwk().",
                        primary_alg(options)
                    )));
                };
                Some(create_jwk(auth, options, config).await?)
            }
        }
    } else {
        // Unpinned tokens stay on the primary algorithm even after extra algs are minted.
        match latest_key_by_alg(auth, options, primary_alg(options)).await? {
            Some(k) => Some(k),
            None => {
                let keys = all_keys(auth, options).await?;
                newest(keys.into_iter().filter(|k| k.is_live(now)).collect())
            }
        }
    };
    if key.as_ref().is_none_or(|k| !k.is_live(now)) {
        if pinned {
            return Err(Error::Config(
                "signJWT: requested signing key is expired and an explicit kid/alg was provided; not auto-minting a replacement. Rotate the key explicitly.".into(),
            ));
        }
        key = Some(create_jwk(auth, options, options.jwks.key_pair_config).await?);
    }
    let key = key.expect("resolved above");
    let alg = key_alg(&key, options).ok_or_else(|| Error::Crypto(format!("unsupported key alg {:?}", key.alg)))?;
    Ok(ResolvedSigningKey { alg, kid: key.id.clone(), key: decrypt_private_key(auth, options, &key)? })
}

// ---- signing and verification ----------------------------------------------------------

fn default_url(auth: &AuthContext) -> Option<String> {
    auth.options.base_url.clone()
}

fn audience_value(aud: &[String]) -> Value {
    match aud {
        [one] => Value::String(one.clone()),
        many => json!(many),
    }
}

/// Sign `payload` as a JWT (`signJWT`). `iss`, `aud` and `exp` default from the options;
/// `header` adds protected-header members such as `typ`.
pub async fn sign_jwt(
    auth: &Arc<AuthContext>,
    options: &JwtOptions,
    mut payload: Map<String, Value>,
    header: Map<String, Value>,
    overrides: SigningOverrides,
) -> Result<String> {
    let now = Utc::now().timestamp();
    let iat = payload.get("iat").and_then(Value::as_i64);
    if !payload.contains_key("exp") {
        let exp = match options.jwt.expiration_time {
            Expiration::In(s) => iat.unwrap_or(now) + s,
            Expiration::At(t) => t,
        };
        payload.insert("exp".into(), exp.into());
    }
    let base = default_url(auth);
    if !payload.contains_key("iss")
        && let Some(iss) = options.jwt.issuer.clone().or(base.clone())
    {
        payload.insert("iss".into(), iss.into());
    }
    if !payload.contains_key("aud") {
        let aud = options.jwt.audience.clone().or(base.map(|b| vec![b]));
        if let Some(aud) = aud {
            payload.insert("aud".into(), audience_value(&aud));
        }
    }
    if let Some(sign) = &options.jwt.sign {
        return sign(payload, header, overrides).await;
    }
    let resolved = resolve_signing_key(auth, options, &overrides).await?;
    sign_with(&resolved, header, &payload)
}

fn sign_with(key: &ResolvedSigningKey, mut header: Map<String, Value>, payload: &Map<String, Value>) -> Result<String> {
    header.insert("kid".into(), key.kid.clone().into());
    sign_jws(&key.key, key.alg, header, payload)
}

/// The public key for a JWS `kid` from the key store.
async fn public_key_for(auth: &Arc<AuthContext>, options: &JwtOptions, kid: &str) -> Option<(JwsAlgorithm, PublicKey)> {
    let keys = all_keys(auth, options).await.ok()?;
    let key = keys.into_iter().find(|k| k.id == kid)?;
    let alg = key_alg(&key, options)?;
    let jwk: Map<String, Value> = serde_json::from_str(&key.public_key).ok()?;
    Some((alg, PublicKey::from_jwk(&jwk).ok()?))
}

fn audience_matches(aud: Option<&Value>, expected: &[String]) -> bool {
    match aud {
        Some(Value::String(a)) => expected.contains(a),
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).any(|a| expected.iter().any(|e| e == a)),
        _ => false,
    }
}

/// Verify a JWT issued by this plugin (`verifyJWT`): signature (by `kid`), `exp`/`nbf`, and
/// `iss`/`aud` against the configured (or base URL) values. Requires `sub` and `aud`.
pub async fn verify_jwt(auth: &Arc<AuthContext>, options: &JwtOptions, token: &str) -> Option<Map<String, Value>> {
    let decoded = decode_jws(token)?;
    let kid = decoded.kid()?.to_owned();
    let (alg, key) = public_key_for(auth, options, &kid).await?;
    if decoded.alg() != Some(alg) || !key.verify(alg, decoded.signing_input.as_bytes(), &decoded.signature) {
        return None;
    }
    let claims = decoded.payload;
    let now = Utc::now().timestamp();
    if claims.get("exp").and_then(Value::as_i64).is_some_and(|exp| exp <= now) {
        return None;
    }
    if claims.get("nbf").and_then(Value::as_i64).is_some_and(|nbf| nbf > now) {
        return None;
    }
    let base = default_url(auth);
    if let Some(iss) = options.jwt.issuer.clone().or(base.clone())
        && claims.get("iss").and_then(Value::as_str) != Some(iss.as_str())
    {
        return None;
    }
    if let Some(aud) = options.jwt.audience.clone().or(base.map(|b| vec![b]))
        && !audience_matches(claims.get("aud"), &aud)
    {
        return None;
    }
    (claims.get("sub").is_some() && claims.get("aud").is_some()).then_some(claims)
}

/// A session JWT (`getJwtToken`).
pub async fn get_jwt_token(auth: &Arc<AuthContext>, options: &JwtOptions, session: &SessionWithUser) -> Result<String> {
    let mut payload = match &options.jwt.define_payload {
        Some(define) => define(session.clone()).await?,
        None => auth.user_output(&session.user),
    };
    let mut claims = Map::new();
    claims.insert("iat".into(), Utc::now().timestamp().into());
    claims.append(&mut payload);
    let sub = match &options.jwt.get_subject {
        Some(f) => f(session.clone()).await?,
        None => session.user.id.clone(),
    };
    claims.insert("sub".into(), sub.into());
    sign_jwt(auth, options, claims, Map::new(), SigningOverrides::default()).await
}

// ---- endpoints ----------------------------------------------------------------------

async fn get_jwks(options: Arc<JwtOptions>, ctx: Ctx) -> EndpointResult {
    if options.jwks.remote_url.is_some() {
        return Err(ApiError::status(http::StatusCode::NOT_FOUND));
    }
    let auth = ctx.auth.clone();
    let mut keys = all_keys(&auth, &options).await?;
    if keys.is_empty() {
        create_jwk(&auth, &options, options.jwks.key_pair_config).await?;
        keys = all_keys(&auth, &options).await?;
    }
    let grace = options.jwks.grace_period.unwrap_or(DEFAULT_GRACE_PERIOD);
    let cutoff = Utc::now() - chrono::Duration::seconds(grace);
    let keys: Vec<Value> = keys
        .into_iter()
        .filter(|k| k.expires_at.is_none_or(|e| e > cutoff))
        .map(|k| {
            let mut out = Map::new();
            let alg = k.alg.clone().unwrap_or_else(|| primary_alg(&options).to_string());
            out.insert("alg".into(), alg.into());
            if let Some(crv) = &k.crv {
                out.insert("crv".into(), crv.clone().into());
            }
            if let Ok(Value::Object(public)) = serde_json::from_str::<Value>(&k.public_key) {
                out.extend(public);
            }
            out.insert("kid".into(), k.id.into());
            Value::Object(out)
        })
        .collect();
    ctx.json(json!({ "keys": keys }))
}

async fn get_token(options: Arc<JwtOptions>, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let token = get_jwt_token(&ctx.auth, &options, &session).await?;
    ctx.json(json!({ "token": token }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignBody {
    payload: Map<String, Value>,
}

async fn sign_endpoint(options: Arc<JwtOptions>, ctx: Ctx) -> EndpointResult {
    let body: SignBody = ctx.parse_body()?;
    let token = sign_jwt(&ctx.auth, &options, body.payload, Map::new(), SigningOverrides::default()).await?;
    ctx.json(json!({ "token": token }))
}

#[derive(Deserialize)]
struct VerifyBody {
    token: String,
    issuer: Option<String>,
}

async fn verify_endpoint(options: Arc<JwtOptions>, ctx: Ctx) -> EndpointResult {
    let body: VerifyBody = ctx.parse_body()?;
    let mut options = (*options).clone();
    if let Some(iss) = body.issuer {
        options.jwt.issuer = Some(iss);
    }
    let payload = verify_jwt(&ctx.auth, &options, &body.token).await;
    ctx.json(json!({ "payload": payload }))
}

async fn set_jwt_header(options: &JwtOptions, ctx: &EndpointContext) -> Result<(), ApiError> {
    if options.disable_setting_jwt_header {
        return Ok(());
    }
    let Some(session) = ctx.session().or_else(|| ctx.new_session()) else { return Ok(()) };
    let token = get_jwt_token(&ctx.auth, options, &session).await?;
    ctx.set_header("set-auth-jwt", &token);
    let mut exposed: Vec<String> = ctx
        .response_header("access-control-expose-headers")
        .unwrap_or_default()
        .split(',')
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .collect();
    if !exposed.iter().any(|h| h == "set-auth-jwt") {
        exposed.push("set-auth-jwt".into());
    }
    ctx.set_header("access-control-expose-headers", &exposed.join(", "));
    Ok(())
}

// ---- session cookie cache ----------------------------------------------------------------

pub const SESSION_COOKIE_JWT_TYPE: &str = "better-auth.session-cache+jwt";
pub const SESSION_COOKIE_JWT_AUDIENCE: &str = "better-auth:session-cache";
pub const SESSION_COOKIE_JWT_ISSUER: &str = "better-auth:session-cache";
const COOKIE_CLOCK_TOLERANCE: i64 = 15;

fn cookie_cache_issuer(ctx: &EndpointContext) -> String {
    match &ctx.auth.options.base_url {
        Some(b) if !b.is_empty() => b.clone(),
        Some(_) => SESSION_COOKIE_JWT_ISSUER.into(),
        None if !ctx.base_url.is_empty() => ctx.base_url.clone(),
        None => SESSION_COOKIE_JWT_ISSUER.into(),
    }
}

/// Signs session cookie caches with the plugin's keys (`createCookieCacheSigner`).
struct CookieCacheJwtSigner {
    options: Arc<JwtOptions>,
}

#[async_trait::async_trait]
impl crate::cookies::CookieCacheSigner for CookieCacheJwtSigner {
    async fn sign(&self, ctx: &EndpointContext, payload: &Map<String, Value>, expires_in: i64) -> Result<String> {
        let key = resolve_signing_key(&ctx.auth, &self.options, &SigningOverrides::default()).await?;
        let now = Utc::now().timestamp();
        let mut claims = payload.clone();
        let sid = payload.get("session").and_then(|s| s.get("token")).cloned().unwrap_or(Value::Null);
        let sub = payload.get("user").and_then(|u| u.get("id")).cloned().unwrap_or(Value::Null);
        claims.insert("sid".into(), sid);
        claims.insert("iat".into(), now.into());
        claims.insert("exp".into(), (now + expires_in).into());
        claims.insert("iss".into(), cookie_cache_issuer(ctx).into());
        claims.insert("aud".into(), SESSION_COOKIE_JWT_AUDIENCE.into());
        claims.insert("sub".into(), sub);
        let mut header = Map::new();
        header.insert("typ".into(), SESSION_COOKIE_JWT_TYPE.into());
        sign_with(&key, header, &claims)
    }

    async fn verify(&self, ctx: &EndpointContext, token: &str) -> Option<(Map<String, Value>, i64)> {
        let decoded = decode_jws(token)?;
        if decoded.header.get("typ").and_then(Value::as_str) != Some(SESSION_COOKIE_JWT_TYPE) {
            return None;
        }
        let (alg, key) = public_key_for(&ctx.auth, &self.options, decoded.kid()?).await?;
        if decoded.alg() != Some(alg) || !key.verify(alg, decoded.signing_input.as_bytes(), &decoded.signature) {
            return None;
        }
        let claims = decoded.payload;
        let now = Utc::now().timestamp();
        let exp = claims.get("exp").and_then(Value::as_i64)?;
        if exp + COOKIE_CLOCK_TOLERANCE < now {
            return None;
        }
        let str_claim = |k: &str| claims.get(k).and_then(Value::as_str);
        if str_claim("aud") != Some(SESSION_COOKIE_JWT_AUDIENCE) || str_claim("iss") != Some(&cookie_cache_issuer(ctx))
        {
            return None;
        }
        let user_id = claims.get("user").and_then(|u| u.get("id")).and_then(Value::as_str);
        let token_sid = claims.get("session").and_then(|s| s.get("token")).and_then(Value::as_str);
        if str_claim("sub") != user_id || str_claim("sid") != token_sid {
            return None;
        }
        Some((claims, exp * 1000))
    }
}

// ---- plugin -------------------------------------------------------------------------

pub struct JwtPlugin {
    options: Arc<JwtOptions>,
}

impl JwtPlugin {
    pub fn options(&self) -> &JwtOptions {
        &self.options
    }
}

/// Create the plugin, validating option combinations as TS does.
pub fn jwt(options: JwtOptions) -> Result<Arc<dyn Plugin>> {
    if options.jwt.sign.is_some() && options.jwks.remote_url.is_none() {
        return Err(Error::Config("options.jwks.remoteUrl must be set when using options.jwt.sign".into()));
    }
    let path = &options.jwks.jwks_path;
    if path.is_empty() || !path.starts_with('/') || path.contains("..") {
        return Err(Error::Config(
            "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'".into(),
        ));
    }
    if options.session_cookie_cache && options.jwt.sign.is_some() {
        return Err(Error::Config(
            "`jwt({ sessionCookieCache: true })` requires locally managed JWT plugin keys and does not support `jwt.sign`."
                .into(),
        ));
    }
    Ok(Arc::new(JwtPlugin { options: Arc::new(options) }))
}

impl Plugin for JwtPlugin {
    fn id(&self) -> &str {
        "jwt"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![TableExtension {
            key: "jwks".into(),
            fields: vec![
                ("publicKey".into(), Field::string()),
                ("privateKey".into(), Field::string()),
                ("createdAt".into(), Field::date()),
                ("expiresAt".into(), Field::date().optional()),
                ("alg".into(), Field::string().optional()),
                ("crv".into(), Field::string().optional()),
            ],
            ..Default::default()
        }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let o = &self.options;
        let (a, b, c, d) = (o.clone(), o.clone(), o.clone(), o.clone());
        vec![
            Endpoint::get("getJwks", &o.jwks.jwks_path, handler(move |ctx| get_jwks(a.clone(), ctx))),
            Endpoint::get("getToken", "/token", handler(move |ctx| get_token(b.clone(), ctx))),
            Endpoint::post("signJWT", "/sign-jwt", handler(move |ctx| sign_endpoint(c.clone(), ctx))).server_only(),
            Endpoint::post("verifyJWT", "/verify-jwt", handler(move |ctx| verify_endpoint(d.clone(), ctx)))
                .server_only(),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        let options = self.options.clone();
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |ctx| ctx.path == "/get-session",
                hook(move |ctx| {
                    let options = options.clone();
                    async move {
                        set_jwt_header(&options, &ctx).await?;
                        Ok(None)
                    }
                }),
            )],
        }
    }

    fn init(&self, ctx: &AuthContext) -> Result<()> {
        if self.options.session_cookie_cache
            && ctx.options.session.cookie_cache.strategy != crate::options::CookieCacheStrategy::Jwt
        {
            return Err(Error::Config(
                "`jwt({ sessionCookieCache: true })` requires `session.cookieCache.strategy = \"jwt\"`.".into(),
            ));
        }
        if let Some(grace) = self.options.jwks.grace_period
            && self.options.session_cookie_cache
            && ctx.options.session.cookie_cache.max_age > grace
        {
            tracing::warn!(
                "`session.cookieCache.maxAge` ({}s) exceeds the JWT plugin JWKS grace period ({grace}s). Rotated keys may stop verifying cookie-cache JWTs before the cookie expires.",
                ctx.options.session.cookie_cache.max_age
            );
        }
        Ok(())
    }

    fn cookie_cache_signer(&self) -> Option<Arc<dyn crate::cookies::CookieCacheSigner>> {
        self.options.session_cookie_cache.then(|| {
            Arc::new(CookieCacheJwtSigner { options: self.options.clone() })
                as Arc<dyn crate::cookies::CookieCacheSigner>
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
