//! ID token verification against a provider's JWKS (`verify-id-token.ts`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::{Map, Value};

use super::{IdTokenVerifier, OAuthProvider, get_json};
use crate::error::{Error, Result};

/// Where to obtain verification keys.
#[derive(Clone)]
pub enum JwksSource {
    /// A remote JWKS endpoint, cached for five minutes (refetched on an unknown `kid`).
    Url(String),
    /// A fixed key set.
    Static(JwkSet),
}

/// How the `nonce` claim is compared with the expected nonce.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NonceComparison {
    #[default]
    Exact,
    /// The raw nonce or its SHA-256 hex digest (Apple).
    ExactOrSha256,
}

pub type ClaimsCheck = Arc<dyn Fn(&Map<String, Value>) -> bool + Send + Sync>;

/// JWKS-based ID token verification settings.
#[derive(Clone)]
pub struct JwksIdTokenConfig {
    pub jwks: JwksSource,
    /// Accepted issuers; empty skips the check (tenant-dependent issuers).
    pub issuer: Vec<String>,
    /// Accepted audiences, usually the client ids.
    pub audience: Vec<String>,
    /// Permitted algorithms; empty means the token's own `alg`.
    pub algorithms: Vec<Algorithm>,
    /// Maximum age in seconds since `iat`.
    pub max_token_age: Option<i64>,
    pub nonce_comparison: NonceComparison,
    /// Accept non-JWS (opaque) tokens; identity then comes from `get_user_info`.
    pub allow_opaque_token: bool,
    /// Provider-specific check on the verified claims.
    pub verify_claims: Option<ClaimsCheck>,
}

impl JwksIdTokenConfig {
    pub fn new(jwks: JwksSource, audience: Vec<String>) -> Self {
        Self {
            jwks,
            issuer: vec![],
            audience,
            algorithms: vec![],
            max_token_age: None,
            nonce_comparison: NonceComparison::Exact,
            allow_opaque_token: false,
            verify_claims: None,
        }
    }
}

/// How a provider verifies client-submitted ID tokens (`OAuthIdTokenConfig`).
#[derive(Clone)]
pub enum IdTokenConfig {
    Jwks(JwksIdTokenConfig),
    /// A custom verifier, e.g. a remote verification endpoint.
    Custom(IdTokenVerifier),
}

/// Whether the provider can verify a client-submitted ID token (`supportsIdTokenSignIn`).
pub fn supports_id_token_sign_in(provider: &dyn OAuthProvider) -> bool {
    let options = provider.options();
    !options.disable_id_token_sign_in && (options.verify_id_token.is_some() || provider.id_token().is_some())
}

/// Verify a client-submitted ID token for a provider (`verifyProviderIdToken`). Fail-closed:
/// any error, or a provider without a verification config, yields `false`.
pub async fn verify_provider_id_token(provider: &dyn OAuthProvider, token: &str, nonce: Option<&str>) -> bool {
    let options = provider.options();
    if options.disable_id_token_sign_in {
        return false;
    }
    if let Some(verify) = &options.verify_id_token {
        return verify(token.to_owned(), nonce.map(str::to_owned)).await;
    }
    match provider.id_token() {
        None => false,
        Some(IdTokenConfig::Custom(verify)) => verify(token.to_owned(), nonce.map(str::to_owned)).await,
        Some(IdTokenConfig::Jwks(config)) => {
            if token.split('.').count() != 3 {
                return config.allow_opaque_token;
            }
            match verify_jwt(token, &config, nonce).await {
                Ok(_) => true,
                Err(e) => {
                    tracing::debug!(error = %e, provider = provider.id(), "id token verification failed");
                    false
                }
            }
        }
    }
}

fn sha256_hex(s: &str) -> String {
    hex::encode(crate::crypto::sha256(s.as_bytes()))
}

/// Verify a JWS against a JWKS config and return its claims.
pub async fn verify_jwt(token: &str, config: &JwksIdTokenConfig, nonce: Option<&str>) -> Result<Map<String, Value>> {
    let header = decode_header(token).map_err(|e| Error::Crypto(e.to_string()))?;
    let algorithms = if config.algorithms.is_empty() { vec![header.alg] } else { config.algorithms.clone() };
    if !algorithms.contains(&header.alg) {
        return Err(Error::Crypto("unexpected JWS algorithm".into()));
    }
    let mut validation = Validation::new(header.alg);
    validation.algorithms = algorithms;
    validation.leeway = 0;
    validation.validate_nbf = true;
    validation.required_spec_claims.clear();
    if !config.issuer.is_empty() {
        validation.set_issuer(&config.issuer);
        validation.required_spec_claims.insert("iss".into());
    }
    if config.audience.is_empty() {
        validation.validate_aud = false;
    } else {
        validation.set_audience(&config.audience);
        validation.required_spec_claims.insert("aud".into());
    }

    let mut last_err = Error::Crypto("no matching key".into());
    let mut claims = None;
    for force in [false, true] {
        let keys = match &config.jwks {
            JwksSource::Static(set) => set.keys.clone(),
            JwksSource::Url(url) => fetch_jwks(url, force).await?.keys,
        };
        let candidates: Vec<&Jwk> = match &header.kid {
            Some(kid) => keys.iter().filter(|k| k.common.key_id.as_deref() == Some(kid)).collect(),
            None => keys.iter().collect(),
        };
        for jwk in candidates {
            let Ok(key) = DecodingKey::from_jwk(jwk) else { continue };
            match decode::<Map<String, Value>>(token, &key, &validation) {
                Ok(data) => {
                    claims = Some(data.claims);
                    break;
                }
                Err(e) => last_err = Error::Crypto(e.to_string()),
            }
        }
        if claims.is_some() || matches!(config.jwks, JwksSource::Static(_)) {
            break;
        }
    }
    let claims = claims.ok_or(last_err)?;

    if let Some(max_age) = config.max_token_age {
        let iat = claims.get("iat").and_then(Value::as_f64).ok_or_else(|| Error::Crypto("missing iat".into()))?;
        let age = chrono::Utc::now().timestamp() as f64 - iat;
        if age < 0.0 || age > max_age as f64 {
            return Err(Error::Crypto("token too old".into()));
        }
    }
    if let Some(nonce) = nonce.filter(|n| !n.is_empty()) {
        let matches = match claims.get("nonce").and_then(Value::as_str) {
            Some(c) if c == nonce => true,
            Some(c) => config.nonce_comparison == NonceComparison::ExactOrSha256 && c == sha256_hex(nonce),
            None => false,
        };
        if !matches {
            return Err(Error::Crypto("nonce mismatch".into()));
        }
    }
    if let Some(check) = &config.verify_claims
        && !check(&claims)
    {
        return Err(Error::Crypto("claims rejected".into()));
    }
    Ok(claims)
}

const JWKS_TTL: Duration = Duration::from_secs(5 * 60);

fn jwks_cache() -> &'static Mutex<HashMap<String, (Instant, JwkSet)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, JwkSet)>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Parse a JWKS document, skipping keys of unsupported types.
pub fn parse_jwks(value: &Value) -> JwkSet {
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .map(|keys| keys.iter().filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok()).collect())
        .unwrap_or_default();
    JwkSet { keys }
}

/// Fetch (or reuse a cached copy of) a remote JWKS.
pub async fn fetch_jwks(url: &str, force_refresh: bool) -> Result<JwkSet> {
    if !force_refresh
        && let Some((at, set)) = jwks_cache().lock().unwrap().get(url)
        && at.elapsed() < JWKS_TTL
    {
        return Ok(set.clone());
    }
    let value = get_json(url, &[]).await?;
    let set = parse_jwks(&value);
    if set.keys.is_empty() {
        return Err(Error::Http("Keys not found".into()));
    }
    jwks_cache().lock().unwrap().insert(url.to_owned(), (Instant::now(), set.clone()));
    Ok(set)
}

/// Decode a JWT payload without verifying it (`decodeJwt`).
pub fn decode_jwt_payload(token: &str) -> Option<Map<String, Value>> {
    let mut parts = token.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    const SECRET: &[u8] = b"an-hmac-key-used-only-for-id-token-tests";

    fn jwks() -> JwkSet {
        serde_json::from_value(json!({
            "keys": [{ "kty": "oct", "kid": "k1", "k": URL_SAFE_NO_PAD.encode(SECRET) }]
        }))
        .unwrap()
    }

    fn config() -> JwksIdTokenConfig {
        let mut c = JwksIdTokenConfig::new(JwksSource::Static(jwks()), vec!["client".into()]);
        c.issuer = vec!["https://issuer.example".into()];
        c.max_token_age = Some(3600);
        c
    }

    fn token(claims: Value, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = kid.map(str::to_owned);
        encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap()
    }

    fn claims() -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({ "iss": "https://issuer.example", "aud": "client", "sub": "123", "iat": now, "exp": now + 600, "nonce": "n1" })
    }

    #[tokio::test]
    async fn verifies_signature_and_claims() {
        let t = token(claims(), Some("k1"));
        let c = verify_jwt(&t, &config(), Some("n1")).await.unwrap();
        assert_eq!(c["sub"], "123");
        assert!(verify_jwt(&t, &config(), None).await.is_ok());
        assert!(verify_jwt(&t, &config(), Some("other")).await.is_err());
        assert!(verify_jwt(&token(claims(), None), &config(), None).await.is_ok());
        assert!(verify_jwt(&token(claims(), Some("unknown")), &config(), None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_bad_tokens() {
        let mut bad = claims();
        bad["aud"] = "someone-else".into();
        assert!(verify_jwt(&token(bad, Some("k1")), &config(), None).await.is_err());
        let mut bad = claims();
        bad["iss"] = "https://evil".into();
        assert!(verify_jwt(&token(bad, Some("k1")), &config(), None).await.is_err());
        let mut bad = claims();
        bad["exp"] = (chrono::Utc::now().timestamp() - 10).into();
        assert!(verify_jwt(&token(bad, Some("k1")), &config(), None).await.is_err());
        let mut bad = claims();
        bad["iat"] = (chrono::Utc::now().timestamp() - 7200).into();
        assert!(verify_jwt(&token(bad, Some("k1")), &config(), None).await.is_err());
        let mut bad = claims();
        bad.as_object_mut().unwrap().remove("aud");
        assert!(verify_jwt(&token(bad, Some("k1")), &config(), None).await.is_err());
        let forged = encode(&Header::new(Algorithm::HS256), &claims(), &EncodingKey::from_secret(b"wrong")).unwrap();
        assert!(verify_jwt(&forged, &config(), None).await.is_err());
        let mut rs_only = config();
        rs_only.algorithms = vec![Algorithm::RS256];
        assert!(verify_jwt(&token(claims(), Some("k1")), &rs_only, None).await.is_err());
    }

    #[tokio::test]
    async fn sha256_nonce_and_claim_checks() {
        let mut c = claims();
        c["nonce"] = sha256_hex("raw").into();
        let t = token(c, Some("k1"));
        assert!(verify_jwt(&t, &config(), Some("raw")).await.is_err());
        let mut apple = config();
        apple.nonce_comparison = NonceComparison::ExactOrSha256;
        assert!(verify_jwt(&t, &apple, Some("raw")).await.is_ok());
        apple.verify_claims = Some(Arc::new(|c| c.get("hd").is_some()));
        assert!(verify_jwt(&t, &apple, Some("raw")).await.is_err());
    }

    #[test]
    fn decodes_payload() {
        let t = token(claims(), None);
        assert_eq!(decode_jwt_payload(&t).unwrap()["sub"], "123");
        assert!(decode_jwt_payload("opaque").is_none());
    }
}
