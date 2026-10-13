//! Asymmetric JOSE: JWK import/export, key generation and compact JWS signing and
//! verification for EdDSA (Ed25519), ES256/ES384/ES512 and RS*/PS* — the algorithms the
//! TypeScript implementation supports through `jose`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};

use crate::error::{Error, Result};

/// A JWS signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwsAlgorithm {
    EdDSA,
    ES256,
    ES384,
    ES512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
}

impl JwsAlgorithm {
    pub const ALL: [JwsAlgorithm; 10] = [
        Self::EdDSA,
        Self::ES256,
        Self::ES384,
        Self::ES512,
        Self::RS256,
        Self::RS384,
        Self::RS512,
        Self::PS256,
        Self::PS384,
        Self::PS512,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }

    fn is_rsa(self) -> bool {
        matches!(self, Self::RS256 | Self::RS384 | Self::RS512 | Self::PS256 | Self::PS384 | Self::PS512)
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).map_err(|e| Error::Crypto(format!("invalid base64url: {e}")))
}

fn jwk_field(jwk: &Map<String, Value>, k: &str) -> Result<Vec<u8>> {
    unb64(jwk.get(k).and_then(Value::as_str).ok_or_else(|| Error::Crypto(format!("JWK is missing \"{k}\"")))?)
}

fn crypto_err(e: impl std::fmt::Display) -> Error {
    Error::Crypto(e.to_string())
}

/// A private signing key.
#[derive(Clone)]
pub enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

/// A public verification key.
#[derive(Clone)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
    Rsa(Box<rsa::RsaPublicKey>),
}

macro_rules! ec_point_jwk {
    ($vk:expr, $crv:literal, $len:expr) => {{
        let point = $vk.to_sec1_bytes();
        // Uncompressed SEC1: 0x04 || X || Y.
        let (x, y) = point[1..].split_at($len);
        json!({ "kty": "EC", "crv": $crv, "x": b64(x), "y": b64(y) })
    }};
}

macro_rules! ec_point_from_jwk {
    ($ty:ty, $jwk:expr, $len:expr) => {{
        let (x, y) = (jwk_field($jwk, "x")?, jwk_field($jwk, "y")?);
        if x.len() != $len || y.len() != $len {
            return Err(Error::Crypto("invalid EC JWK coordinates".into()));
        }
        let mut sec1 = vec![4u8];
        sec1.extend(x);
        sec1.extend(y);
        <$ty>::from_sec1_bytes(&sec1).map_err(crypto_err)?
    }};
}

impl PrivateKey {
    /// Generate a key for `alg`. RSA keys use `modulus_length` bits (default 2048).
    pub fn generate(alg: JwsAlgorithm, modulus_length: Option<usize>) -> Result<Self> {
        use p256::elliptic_curve::Generate;
        let mut rng = rand::rng();
        Ok(match alg {
            JwsAlgorithm::EdDSA => Self::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng)),
            JwsAlgorithm::ES256 => Self::P256(p256::ecdsa::SigningKey::generate_from_rng(&mut rng)),
            JwsAlgorithm::ES384 => Self::P384(p384::ecdsa::SigningKey::generate_from_rng(&mut rng)),
            JwsAlgorithm::ES512 => Self::P521(p521::ecdsa::SigningKey::generate_from_rng(&mut rng)),
            _ => {
                let bits = modulus_length.unwrap_or(2048);
                let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).map_err(crypto_err)?;
                Self::Rsa(Box::new(key))
            }
        })
    }

    /// Import a private JWK (`kty` `OKP`/Ed25519, `EC` P-256/P-384/P-521, or `RSA`).
    pub fn from_jwk(jwk: &Map<String, Value>) -> Result<Self> {
        let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or_default();
        let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or_default();
        Ok(match (kty, crv) {
            ("OKP", "Ed25519") => {
                let d: [u8; 32] =
                    jwk_field(jwk, "d")?.try_into().map_err(|_| Error::Crypto("invalid Ed25519 key".into()))?;
                Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&d))
            }
            ("EC", "P-256") => {
                Self::P256(p256::ecdsa::SigningKey::from_slice(&jwk_field(jwk, "d")?).map_err(crypto_err)?)
            }
            ("EC", "P-384") => {
                Self::P384(p384::ecdsa::SigningKey::from_slice(&jwk_field(jwk, "d")?).map_err(crypto_err)?)
            }
            ("EC", "P-521") => {
                Self::P521(p521::ecdsa::SigningKey::from_slice(&jwk_field(jwk, "d")?).map_err(crypto_err)?)
            }
            ("RSA", _) => {
                use rsa::BigUint;
                let int = |k: &str| jwk_field(jwk, k).map(|b| BigUint::from_bytes_be(&b));
                let primes = vec![int("p")?, int("q")?];
                let mut key =
                    rsa::RsaPrivateKey::from_components(int("n")?, int("e")?, int("d")?, primes).map_err(crypto_err)?;
                key.precompute().map_err(crypto_err)?;
                Self::Rsa(Box::new(key))
            }
            _ => return Err(Error::Crypto(format!("unsupported private JWK: kty={kty} crv={crv}"))),
        })
    }

    /// Import a PKCS#8 PEM private key, interpreted for `alg`.
    pub fn from_pkcs8_pem(pem: &str, alg: JwsAlgorithm) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey;
        Ok(match alg {
            JwsAlgorithm::EdDSA => {
                use ed25519_dalek::pkcs8::DecodePrivateKey as _;
                Self::Ed25519(ed25519_dalek::SigningKey::from_pkcs8_pem(pem).map_err(crypto_err)?)
            }
            JwsAlgorithm::ES256 => Self::P256(p256::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(crypto_err)?),
            JwsAlgorithm::ES384 => Self::P384(p384::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(crypto_err)?),
            JwsAlgorithm::ES512 => Self::P521(p521::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(crypto_err)?),
            _ => {
                use rsa::pkcs8::DecodePrivateKey as _;
                Self::Rsa(Box::new(rsa::RsaPrivateKey::from_pkcs8_pem(pem).map_err(crypto_err)?))
            }
        })
    }

    /// Whether this key can sign with `alg`.
    pub fn supports(&self, alg: JwsAlgorithm) -> bool {
        match self {
            Self::Ed25519(_) => alg == JwsAlgorithm::EdDSA,
            Self::P256(_) => alg == JwsAlgorithm::ES256,
            Self::P384(_) => alg == JwsAlgorithm::ES384,
            Self::P521(_) => alg == JwsAlgorithm::ES512,
            Self::Rsa(_) => alg.is_rsa(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Ed25519(k) => PublicKey::Ed25519(k.verifying_key()),
            Self::P256(k) => PublicKey::P256(*k.verifying_key()),
            Self::P384(k) => PublicKey::P384(*k.verifying_key()),
            Self::P521(k) => PublicKey::P521(*k.verifying_key()),
            Self::Rsa(k) => PublicKey::Rsa(Box::new(k.to_public_key())),
        }
    }

    /// The private JWK (public members plus `d`, and RSA CRT parameters).
    pub fn to_jwk(&self) -> Map<String, Value> {
        let mut jwk = self.public_key().to_jwk();
        match self {
            Self::Ed25519(k) => {
                jwk.insert("d".into(), b64(&k.to_bytes()).into());
            }
            Self::P256(k) => {
                jwk.insert("d".into(), b64(&k.to_bytes()).into());
            }
            Self::P384(k) => {
                jwk.insert("d".into(), b64(&k.to_bytes()).into());
            }
            Self::P521(k) => {
                jwk.insert("d".into(), b64(&k.to_bytes()).into());
            }
            Self::Rsa(k) => {
                use rsa::traits::PrivateKeyParts;
                let enc = |n: &rsa::BigUint| Value::String(b64(&n.to_bytes_be()));
                jwk.insert("d".into(), enc(k.d()));
                if let [p, q] = k.primes() {
                    jwk.insert("p".into(), enc(p));
                    jwk.insert("q".into(), enc(q));
                }
                if let Some(dp) = k.dp() {
                    jwk.insert("dp".into(), enc(dp));
                }
                if let Some(dq) = k.dq() {
                    jwk.insert("dq".into(), enc(dq));
                }
                if let Some(qi) = k.qinv().and_then(|q| q.to_biguint()) {
                    jwk.insert("qi".into(), enc(&qi));
                }
            }
        }
        jwk
    }

    /// Sign `data` with `alg` (ECDSA signatures are raw `r || s`, as JWS requires).
    pub fn sign(&self, alg: JwsAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
        if !self.supports(alg) {
            return Err(Error::Crypto(format!("key does not support {alg}")));
        }
        Ok(match self {
            Self::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(data).to_bytes().to_vec()
            }
            Self::P256(k) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = k.try_sign(data).map_err(crypto_err)?;
                sig.to_bytes().to_vec()
            }
            Self::P384(k) => {
                use p384::ecdsa::signature::Signer;
                let sig: p384::ecdsa::Signature = k.try_sign(data).map_err(crypto_err)?;
                sig.to_bytes().to_vec()
            }
            Self::P521(k) => {
                use p521::ecdsa::signature::Signer;
                let sig: p521::ecdsa::Signature = k.try_sign(data).map_err(crypto_err)?;
                sig.to_bytes().to_vec()
            }
            Self::Rsa(k) => rsa_sign(k, alg, data)?,
        })
    }
}

fn rsa_sign(key: &rsa::RsaPrivateKey, alg: JwsAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    use rsa::sha2::{Sha256, Sha384, Sha512};
    use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
    let key = key.clone();
    let mut rng = rsa::rand_core::OsRng;
    Ok(match alg {
        JwsAlgorithm::RS256 => {
            rsa::pkcs1v15::SigningKey::<Sha256>::new(key).try_sign(data).map_err(crypto_err)?.to_vec()
        }
        JwsAlgorithm::RS384 => {
            rsa::pkcs1v15::SigningKey::<Sha384>::new(key).try_sign(data).map_err(crypto_err)?.to_vec()
        }
        JwsAlgorithm::RS512 => {
            rsa::pkcs1v15::SigningKey::<Sha512>::new(key).try_sign(data).map_err(crypto_err)?.to_vec()
        }
        JwsAlgorithm::PS256 => rsa::pss::BlindedSigningKey::<Sha256>::new(key)
            .try_sign_with_rng(&mut rng, data)
            .map_err(crypto_err)?
            .to_vec(),
        JwsAlgorithm::PS384 => rsa::pss::BlindedSigningKey::<Sha384>::new(key)
            .try_sign_with_rng(&mut rng, data)
            .map_err(crypto_err)?
            .to_vec(),
        JwsAlgorithm::PS512 => rsa::pss::BlindedSigningKey::<Sha512>::new(key)
            .try_sign_with_rng(&mut rng, data)
            .map_err(crypto_err)?
            .to_vec(),
        _ => return Err(Error::Crypto(format!("not an RSA algorithm: {alg}"))),
    })
}

fn rsa_verify(key: &rsa::RsaPublicKey, alg: JwsAlgorithm, data: &[u8], sig: &[u8]) -> bool {
    use rsa::sha2::{Sha256, Sha384, Sha512};
    use rsa::signature::Verifier;
    let key = key.clone();
    match alg {
        JwsAlgorithm::RS256 | JwsAlgorithm::RS384 | JwsAlgorithm::RS512 => {
            let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig) else { return false };
            match alg {
                JwsAlgorithm::RS256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(data, &sig).is_ok(),
                JwsAlgorithm::RS384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key).verify(data, &sig).is_ok(),
                _ => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key).verify(data, &sig).is_ok(),
            }
        }
        JwsAlgorithm::PS256 | JwsAlgorithm::PS384 | JwsAlgorithm::PS512 => {
            let Ok(sig) = rsa::pss::Signature::try_from(sig) else { return false };
            match alg {
                JwsAlgorithm::PS256 => rsa::pss::VerifyingKey::<Sha256>::new(key).verify(data, &sig).is_ok(),
                JwsAlgorithm::PS384 => rsa::pss::VerifyingKey::<Sha384>::new(key).verify(data, &sig).is_ok(),
                _ => rsa::pss::VerifyingKey::<Sha512>::new(key).verify(data, &sig).is_ok(),
            }
        }
        _ => false,
    }
}

impl PublicKey {
    /// Import a public JWK.
    pub fn from_jwk(jwk: &Map<String, Value>) -> Result<Self> {
        let kty = jwk.get("kty").and_then(Value::as_str).unwrap_or_default();
        let crv = jwk.get("crv").and_then(Value::as_str).unwrap_or_default();
        Ok(match (kty, crv) {
            ("OKP", "Ed25519") => {
                let x: [u8; 32] =
                    jwk_field(jwk, "x")?.try_into().map_err(|_| Error::Crypto("invalid Ed25519 key".into()))?;
                Self::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&x).map_err(crypto_err)?)
            }
            ("EC", "P-256") => Self::P256(ec_point_from_jwk!(p256::ecdsa::VerifyingKey, jwk, 32)),
            ("EC", "P-384") => Self::P384(ec_point_from_jwk!(p384::ecdsa::VerifyingKey, jwk, 48)),
            ("EC", "P-521") => Self::P521(ec_point_from_jwk!(p521::ecdsa::VerifyingKey, jwk, 66)),
            ("RSA", _) => {
                let int = |k: &str| jwk_field(jwk, k).map(|b| rsa::BigUint::from_bytes_be(&b));
                Self::Rsa(Box::new(rsa::RsaPublicKey::new(int("n")?, int("e")?).map_err(crypto_err)?))
            }
            _ => return Err(Error::Crypto(format!("unsupported public JWK: kty={kty} crv={crv}"))),
        })
    }

    /// The public JWK (`kty`, `crv`/`x`/`y` or `n`/`e`).
    pub fn to_jwk(&self) -> Map<String, Value> {
        let v = match self {
            Self::Ed25519(k) => json!({ "kty": "OKP", "crv": "Ed25519", "x": b64(&k.to_bytes()) }),
            Self::P256(k) => ec_point_jwk!(k, "P-256", 32),
            Self::P384(k) => ec_point_jwk!(k, "P-384", 48),
            Self::P521(k) => ec_point_jwk!(k, "P-521", 66),
            Self::Rsa(k) => {
                use rsa::traits::PublicKeyParts;
                json!({ "kty": "RSA", "n": b64(&k.n().to_bytes_be()), "e": b64(&k.e().to_bytes_be()) })
            }
        };
        match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    pub fn verify(&self, alg: JwsAlgorithm, data: &[u8], sig: &[u8]) -> bool {
        match self {
            Self::Ed25519(k) => {
                let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else { return false };
                alg == JwsAlgorithm::EdDSA && k.verify_strict(data, &sig).is_ok()
            }
            Self::P256(k) => {
                use p256::ecdsa::signature::Verifier;
                let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else { return false };
                alg == JwsAlgorithm::ES256 && k.verify(data, &sig).is_ok()
            }
            Self::P384(k) => {
                use p384::ecdsa::signature::Verifier;
                let Ok(sig) = p384::ecdsa::Signature::from_slice(sig) else { return false };
                alg == JwsAlgorithm::ES384 && k.verify(data, &sig).is_ok()
            }
            Self::P521(k) => {
                use p521::ecdsa::signature::Verifier;
                let Ok(sig) = p521::ecdsa::Signature::from_slice(sig) else { return false };
                alg == JwsAlgorithm::ES512 && k.verify(data, &sig).is_ok()
            }
            Self::Rsa(k) => rsa_verify(k, alg, data, sig),
        }
    }
}

/// Sign a compact JWS. `header` gets `alg` set; `payload` is serialized as JSON.
pub fn sign_jws(
    key: &PrivateKey,
    alg: JwsAlgorithm,
    mut header: Map<String, Value>,
    payload: &Map<String, Value>,
) -> Result<String> {
    header.insert("alg".into(), alg.as_str().into());
    let signing_input = format!("{}.{}", b64(&serde_json::to_vec(&header)?), b64(&serde_json::to_vec(payload)?));
    let sig = key.sign(alg, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", b64(&sig)))
}

/// Decoded parts of a compact JWS.
#[derive(Debug, Clone)]
pub struct DecodedJws {
    pub header: Map<String, Value>,
    pub payload: Map<String, Value>,
    pub signing_input: String,
    pub signature: Vec<u8>,
}

impl DecodedJws {
    pub fn alg(&self) -> Option<JwsAlgorithm> {
        self.header.get("alg").and_then(Value::as_str).and_then(JwsAlgorithm::parse)
    }

    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(Value::as_str)
    }
}

/// Split and decode a compact JWS without verifying it.
pub fn decode_jws(token: &str) -> Option<DecodedJws> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: Map<String, Value> = serde_json::from_slice(&unb64(h).ok()?).ok()?;
    let payload: Map<String, Value> = serde_json::from_slice(&unb64(p).ok()?).ok()?;
    Some(DecodedJws { header, payload, signing_input: format!("{h}.{p}"), signature: unb64(s).ok()? })
}

/// Verify a compact JWS signature with `key`, accepting only the algorithms in `allowed`
/// (all asymmetric algorithms when empty). Claims are not checked.
pub fn verify_jws(token: &str, key: &PublicKey, allowed: &[JwsAlgorithm]) -> Option<DecodedJws> {
    let decoded = decode_jws(token)?;
    let alg = decoded.alg()?;
    if !allowed.is_empty() && !allowed.contains(&alg) {
        return None;
    }
    key.verify(alg, decoded.signing_input.as_bytes(), &decoded.signature).then_some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_jwk_roundtrip_for_every_algorithm() {
        let rsa = PrivateKey::generate(JwsAlgorithm::RS256, Some(2048)).unwrap();
        for alg in JwsAlgorithm::ALL {
            let key = if alg.is_rsa() { rsa.clone() } else { PrivateKey::generate(alg, None).unwrap() };
            let restored = PrivateKey::from_jwk(&key.to_jwk()).unwrap();
            let public = PublicKey::from_jwk(&restored.public_key().to_jwk()).unwrap();
            let mut payload = Map::new();
            payload.insert("sub".into(), "user".into());
            let token = sign_jws(&restored, alg, Map::new(), &payload).unwrap();
            let decoded = verify_jws(&token, &public, &[alg]).unwrap_or_else(|| panic!("{alg} verifies"));
            assert_eq!(decoded.payload["sub"], "user");
            let other = if alg == JwsAlgorithm::ES256 { JwsAlgorithm::ES384 } else { JwsAlgorithm::ES256 };
            assert!(verify_jws(&token, &public, &[other]).is_none(), "{alg}: disallowed algorithm");
            let parts: Vec<&str> = token.split('.').collect();
            let forged = format!("{}.{}.{}", parts[0], b64(br#"{"sub":"admin"}"#), parts[2]);
            assert!(verify_jws(&forged, &public, &[]).is_none(), "{alg} rejects a modified payload");
        }
    }
}
