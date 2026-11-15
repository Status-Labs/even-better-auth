//! HS256 JWTs signed with the raw secret (`signJWT` / `verifyJWT`).

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::{Map, Value};

use crate::error::{Error, Result};

pub fn sign_jwt(payload: &Map<String, Value>, secret: &str, expires_in_secs: i64) -> Result<String> {
    let now = chrono::Utc::now().timestamp();
    let mut claims = payload.clone();
    claims.retain(|_, v| !v.is_null());
    claims.insert("iat".into(), now.into());
    claims.insert("exp".into(), (now + expires_in_secs).into());
    EncodingKey::from_secret(secret.as_bytes())
        .and_then(|key| encode(&Header::new(Algorithm::HS256), &claims, &key))
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Verify signature and expiry; returns the claims or `None`.
pub fn verify_jwt(token: &str, secret: &str) -> Option<Map<String, Value>> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.clear();
    validation.leeway = 0;
    let key = DecodingKey::from_secret(secret.as_bytes()).ok()?;
    decode::<Map<String, Value>>(token, &key, &validation).ok().map(|d| d.claims)
}
