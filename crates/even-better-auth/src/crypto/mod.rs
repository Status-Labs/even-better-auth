//! Cryptographic primitives, byte-compatible with the TypeScript implementation.

pub mod jose;
mod jwe;
mod jwt;
pub mod otp;
mod password;
mod random;

pub use jwe::{symmetric_decode_jwt, symmetric_encode_jwt};
pub use jwt::{sign_jwt, verify_jwt};
pub use password::{hash_password, verify_password};
pub use random::{generate_id, generate_random_string, random_bytes, random_string};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// A set of versioned secrets, enabling key rotation (`secrets` option).
#[derive(Debug, Clone)]
pub struct SecretConfig {
    pub keys: BTreeMap<u32, String>,
    pub current_version: u32,
    /// The pre-rotation `secret`, used to decrypt bare (un-enveloped) payloads.
    pub legacy_secret: Option<String>,
    /// Whether ciphertexts are wrapped in a `$ba$<version>$` envelope. False when built
    /// from a single plain `secret`, which keeps output compatible with older deployments.
    pub versioned: bool,
}

impl SecretConfig {
    pub fn single(secret: impl Into<String>) -> Self {
        let secret = secret.into();
        Self {
            keys: BTreeMap::from([(0, secret.clone())]),
            current_version: 0,
            legacy_secret: Some(secret),
            versioned: false,
        }
    }

    pub fn current(&self) -> &str {
        self.keys.get(&self.current_version).map(String::as_str).unwrap_or_default()
    }

    /// All secrets, current first, then the rest, then the legacy secret if distinct.
    pub fn all(&self) -> Vec<&str> {
        let mut out = vec![self.current()];
        for (v, s) in self.keys.iter().rev() {
            if *v != self.current_version {
                out.push(s);
            }
        }
        if let Some(l) = &self.legacy_secret
            && !out.contains(&l.as_str())
        {
            out.push(l);
        }
        out
    }
}

/// HMAC-SHA256 signature encoded as standard base64 (with padding), as used for signed cookies.
pub fn make_signature(value: &str, secret: &str) -> String {
    STANDARD.encode(hmac_sha256(secret.as_bytes(), value.as_bytes()))
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC-SHA256 as unpadded base64url (`createHMAC("SHA-256", "base64urlnopad")`).
pub fn hmac_sign_base64url(secret: &str, data: &str) -> String {
    URL_SAFE_NO_PAD.encode(hmac_sha256(secret.as_bytes(), data.as_bytes()))
}

pub fn hmac_verify_base64url(secret: &str, data: &str, signature: &str) -> bool {
    let Ok(sig) = URL_SAFE_NO_PAD.decode(signature.trim_end_matches('=')) else {
        return false;
    };
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(data.as_bytes());
    mac.verify_slice(&sig).is_ok()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_base64url(data: &str) -> String {
    URL_SAFE_NO_PAD.encode(sha256(data.as_bytes()))
}

const ENVELOPE_PREFIX: &str = "$ba$";

fn raw_encrypt(secret: &str, data: &str) -> Result<String> {
    let key = sha256(secret.as_bytes());
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce: [u8; 24] = random_bytes();
    let ct = cipher.encrypt(&XNonce::from(nonce), data.as_bytes()).map_err(|e| Error::Crypto(e.to_string()))?;
    // @noble/ciphers `managedNonce` prepends the nonce to the ciphertext.
    let mut out = nonce.to_vec();
    out.extend(ct);
    Ok(hex::encode(out))
}

fn raw_decrypt(secret: &str, hex_data: &str) -> Result<String> {
    let bytes = hex::decode(hex_data).map_err(|e| Error::Crypto(e.to_string()))?;
    if bytes.len() < 24 {
        return Err(Error::Crypto("ciphertext too short".into()));
    }
    let key = sha256(secret.as_bytes());
    let cipher = XChaCha20Poly1305::new((&key).into());
    let (nonce, ct) = bytes.split_at(24);
    let pt = cipher
        .decrypt(&XNonce::try_from(nonce).map_err(|_| Error::Crypto("bad nonce".into()))?, ct)
        .map_err(|_| Error::Crypto("decryption failed".into()))?;
    String::from_utf8(pt).map_err(|e| Error::Crypto(e.to_string()))
}

/// XChaCha20-Poly1305 encryption keyed by SHA-256(secret), hex-encoded with a prepended nonce.
/// With versioned secrets the output is wrapped in a `$ba$<version>$` envelope.
pub fn symmetric_encrypt(key: &SecretConfig, data: &str) -> Result<String> {
    let ct = raw_encrypt(key.current(), data)?;
    if key.versioned { Ok(format!("{ENVELOPE_PREFIX}{}${ct}", key.current_version)) } else { Ok(ct) }
}

pub fn symmetric_decrypt(key: &SecretConfig, data: &str) -> Result<String> {
    if let Some(rest) = data.strip_prefix(ENVELOPE_PREFIX)
        && let Some((version, ct)) = rest.split_once('$')
        && let Ok(version) = version.parse::<u32>()
    {
        let secret = key
            .keys
            .get(&version)
            .ok_or_else(|| Error::Crypto(format!("Secret version {version} not found in keys")))?;
        return raw_decrypt(secret, ct);
    }
    let legacy = key
        .legacy_secret
        .as_deref()
        .ok_or_else(|| Error::Crypto("Cannot decrypt legacy bare-hex payload: no legacy secret available".into()))?;
    raw_decrypt(legacy, data)
}

/// Encryption purposes that get an isolated HKDF-derived key.
#[derive(Debug, Clone, Copy)]
pub enum EncryptionPurpose {
    OAuthStateCookie,
    OAuthProxyState,
    OAuthProxyPackage,
    OAuthProxyProfile,
}

impl EncryptionPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::OAuthStateCookie => "oauth-state-cookie",
            Self::OAuthProxyState => "oauth-proxy-state",
            Self::OAuthProxyPackage => "oauth-proxy-package",
            Self::OAuthProxyProfile => "oauth-proxy-profile",
        }
    }
}

fn derive_purpose_secret(secret: &str, purpose: EncryptionPurpose) -> String {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(b"better-auth:oauth-encryption:v1"), secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(format!("better-auth:{}:v1", purpose.as_str()).as_bytes(), &mut okm)
        .expect("32 bytes is a valid hkdf length");
    hex::encode(okm)
}

/// Derive an isolated key for one ciphertext purpose, retaining rotation versions.
pub fn derive_purpose_key(secret: &SecretConfig, purpose: EncryptionPurpose) -> SecretConfig {
    SecretConfig {
        keys: secret.keys.iter().map(|(v, s)| (*v, derive_purpose_secret(s, purpose))).collect(),
        current_version: secret.current_version,
        legacy_secret: secret.legacy_secret.as_deref().map(|s| derive_purpose_secret(s, purpose)),
        versioned: secret.versioned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_44_chars() {
        assert_eq!(make_signature("value", "secret").len(), 44);
    }

    #[test]
    fn symmetric_roundtrip() {
        let key = SecretConfig::single("a-very-secret-key-that-is-long-enough");
        let ct = symmetric_encrypt(&key, "hello").unwrap();
        assert!(!ct.starts_with('$'));
        assert_eq!(symmetric_decrypt(&key, &ct).unwrap(), "hello");
    }

    #[test]
    fn versioned_roundtrip() {
        let key = SecretConfig {
            keys: BTreeMap::from([(1, "one".to_string()), (2, "two".to_string())]),
            current_version: 2,
            legacy_secret: Some("legacy".into()),
            versioned: true,
        };
        let ct = symmetric_encrypt(&key, "hello").unwrap();
        assert!(ct.starts_with("$ba$2$"));
        assert_eq!(symmetric_decrypt(&key, &ct).unwrap(), "hello");
        let legacy = symmetric_encrypt(&SecretConfig::single("legacy"), "old").unwrap();
        assert_eq!(symmetric_decrypt(&key, &legacy).unwrap(), "old");
    }
}
