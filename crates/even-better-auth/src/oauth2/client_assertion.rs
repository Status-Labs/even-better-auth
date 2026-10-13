//! `private_key_jwt` client authentication (RFC 7523, `oauth2/client-assertion.ts`).

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::crypto::jose::{JwsAlgorithm, PrivateKey, sign_jws};
use crate::error::{Error, Result};

pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// What a client assertion is for.
#[derive(Debug, Clone)]
pub struct ClientAssertionContext {
    pub client_id: String,
    pub token_endpoint: String,
    /// `authorization_code`, `refresh_token` or `client_credentials`.
    pub grant_type: String,
}

type AssertionFn = dyn Fn(&ClientAssertionContext) -> Result<String> + Send + Sync;

/// Produces a signed `client_assertion` for each token request.
#[derive(Clone)]
pub struct ClientAssertion(Arc<AssertionFn>);

impl std::fmt::Debug for ClientAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientAssertion")
    }
}

/// Key material for [`ClientAssertion::private_key_jwt`]: a private JWK or a PKCS#8 PEM.
#[derive(Debug, Clone, Default)]
pub struct PrivateKeyJwtOptions {
    pub private_key_jwk: Option<Map<String, Value>>,
    pub private_key_pem: Option<String>,
    /// Header `kid`; defaults to the JWK's `kid`.
    pub kid: Option<String>,
    /// Asymmetric algorithm. Defaults to the JWK's `alg`, else RS256.
    pub algorithm: Option<JwsAlgorithm>,
    /// Assertion lifetime in seconds (default 120).
    pub expires_in: Option<i64>,
}

impl ClientAssertion {
    /// A custom assertion source.
    pub fn new(f: impl Fn(&ClientAssertionContext) -> Result<String> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Sign RFC 7523 assertions (`iss` = `sub` = client id, `aud` = token endpoint, `jti`,
    /// `iat`, `exp`) with a private key. Validates the configuration eagerly.
    pub fn private_key_jwt(options: PrivateKeyJwtOptions) -> Result<Self> {
        let jwk_alg = options.private_key_jwk.as_ref().and_then(|j| j.get("alg")).and_then(Value::as_str);
        let jwk_alg = match jwk_alg {
            Some(a) => Some(JwsAlgorithm::parse(a).ok_or_else(|| unsupported(a))?),
            None => None,
        };
        if let (Some(configured), Some(jwk)) = (options.algorithm, jwk_alg)
            && configured != jwk
        {
            return Err(Error::Config(format!(
                "JWK alg \"{jwk}\" does not match configured algorithm \"{configured}\". Remove the JWK alg field, or pass an algorithm that matches the JWK."
            )));
        }
        let alg = options.algorithm.or(jwk_alg).unwrap_or(JwsAlgorithm::RS256);
        let key = match (&options.private_key_jwk, &options.private_key_pem) {
            (Some(jwk), _) => PrivateKey::from_jwk(jwk)?,
            (None, Some(pem)) => PrivateKey::from_pkcs8_pem(pem, alg)?,
            (None, None) => {
                return Err(Error::Config("private_key_jwt requires either privateKeyJwk or privateKeyPem".into()));
            }
        };
        if !key.supports(alg) {
            return Err(Error::Config(format!("private_key_jwt key cannot sign {alg}")));
        }
        let kid =
            options.kid.clone().or_else(|| options.private_key_jwk.as_ref()?.get("kid")?.as_str().map(str::to_owned));
        let expires_in = options.expires_in.unwrap_or(120);
        Ok(Self::new(move |ctx| {
            let now = chrono::Utc::now().timestamp();
            let mut header = Map::new();
            header.insert("typ".into(), "JWT".into());
            if let Some(kid) = &kid {
                header.insert("kid".into(), kid.clone().into());
            }
            let mut claims = Map::new();
            claims.insert("iss".into(), ctx.client_id.clone().into());
            claims.insert("sub".into(), ctx.client_id.clone().into());
            claims.insert("aud".into(), ctx.token_endpoint.clone().into());
            claims.insert("iat".into(), now.into());
            claims.insert("exp".into(), (now + expires_in).into());
            claims.insert("jti".into(), crate::crypto::generate_id(Some(32)).into());
            sign_jws(&key, alg, header, &claims)
        }))
    }

    pub fn sign(&self, ctx: &ClientAssertionContext) -> Result<String> {
        (self.0)(ctx)
    }
}

fn unsupported(alg: &str) -> Error {
    let all: Vec<&str> = JwsAlgorithm::ALL.iter().map(|a| a.as_str()).collect();
    Error::Config(format!("Unsupported private_key_jwt signing algorithm: {alg}. Use one of {}.", all.join(", ")))
}
