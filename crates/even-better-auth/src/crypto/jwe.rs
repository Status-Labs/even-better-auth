//! Compact JWE with `alg: "dir"`, `enc: "A256CBC-HS512"` (RFC 7516 / 7518 §5.2.5),
//! matching jose's `EncryptJWT` as used by `symmetricEncodeJWT`.

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::{Sha256, Sha512};

use super::{SecretConfig, constant_time_eq, random_bytes, sha256};
use crate::error::Result;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const INFO: &[u8] = b"BetterAuth.js Generated Encryption Key";
const CLOCK_TOLERANCE: i64 = 15;

fn derive_key(secret: &str, salt: &str) -> [u8; 64] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret.as_bytes());
    let mut okm = [0u8; 64];
    hk.expand(INFO, &mut okm).expect("64 bytes is a valid hkdf length");
    okm
}

/// RFC 7638 thumbprint of the `oct` JWK for `key`.
fn thumbprint(key: &[u8]) -> String {
    let jwk = format!(r#"{{"k":"{}","kty":"oct"}}"#, URL_SAFE_NO_PAD.encode(key));
    URL_SAFE_NO_PAD.encode(sha256(jwk.as_bytes()))
}

fn tag(mac_key: &[u8], aad: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha512>::new_from_slice(mac_key).expect("any key length");
    mac.update(aad);
    mac.update(iv);
    mac.update(ct);
    mac.update(&((aad.len() as u64) * 8).to_be_bytes());
    mac.finalize().into_bytes()[..32].to_vec()
}

pub fn symmetric_encode_jwt(
    payload: &Map<String, Value>,
    secret: &SecretConfig,
    salt: &str,
    expires_in_secs: i64,
) -> Result<String> {
    let key = derive_key(secret.current(), salt);
    let header = json!({ "alg": "dir", "enc": "A256CBC-HS512", "kid": thumbprint(&key) });
    let now = chrono::Utc::now().timestamp();
    let mut claims = payload.clone();
    claims.insert("iat".into(), now.into());
    claims.insert("exp".into(), (now + expires_in_secs).into());
    claims.insert("jti".into(), uuid_v4().into());

    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let iv: [u8; 16] = random_bytes();
    let (mac_key, enc_key) = key.split_at(32);
    let plaintext = serde_json::to_vec(&claims)?;
    let ct = Aes256CbcEnc::new_from_slices(enc_key, &iv)
        .expect("valid key and iv lengths")
        .encrypt_padded_vec::<Pkcs7>(&plaintext);
    let t = tag(mac_key, protected.as_bytes(), &iv, &ct);
    Ok(format!(
        "{protected}..{}.{}.{}",
        URL_SAFE_NO_PAD.encode(iv),
        URL_SAFE_NO_PAD.encode(&ct),
        URL_SAFE_NO_PAD.encode(t)
    ))
}

fn decrypt_with(key: &[u8; 64], parts: &[&str]) -> Option<Map<String, Value>> {
    let iv = URL_SAFE_NO_PAD.decode(parts[2]).ok()?;
    let ct = URL_SAFE_NO_PAD.decode(parts[3]).ok()?;
    let t = URL_SAFE_NO_PAD.decode(parts[4]).ok()?;
    let (mac_key, enc_key) = key.split_at(32);
    if iv.len() != 16 || !constant_time_eq(&tag(mac_key, parts[0].as_bytes(), &iv, &ct), &t) {
        return None;
    }
    let pt = Aes256CbcDec::new_from_slices(enc_key, &iv).ok()?.decrypt_padded_vec::<Pkcs7>(&ct).ok()?;
    let claims: Map<String, Value> = serde_json::from_slice(&pt).ok()?;
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64)
        && exp + CLOCK_TOLERANCE < chrono::Utc::now().timestamp()
    {
        return None;
    }
    Some(claims)
}

pub fn symmetric_decode_jwt(token: &str, secret: &SecretConfig, salt: &str) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 || !parts[1].is_empty() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?).ok()?;
    if header.get("alg")?.as_str()? != "dir" || header.get("enc")?.as_str()? != "A256CBC-HS512" {
        return None;
    }
    let kid = header.get("kid").and_then(Value::as_str);
    for s in secret.all() {
        let key = derive_key(s, salt);
        if let Some(kid) = kid {
            if kid != thumbprint(&key) {
                continue;
            }
            return decrypt_with(&key, &parts);
        }
        if let Some(claims) = decrypt_with(&key, &parts) {
            return Some(claims);
        }
    }
    None
}

fn uuid_v4() -> String {
    let mut b: [u8; 16] = random_bytes();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let secret = SecretConfig::single("secret-secret-secret-secret-secret");
        let mut payload = Map::new();
        payload.insert("hello".into(), "world".into());
        let token = symmetric_encode_jwt(&payload, &secret, "better-auth-session", 60).unwrap();
        let claims = symmetric_decode_jwt(&token, &secret, "better-auth-session").unwrap();
        assert_eq!(claims["hello"], "world");
        assert!(symmetric_decode_jwt(&token, &SecretConfig::single("other"), "better-auth-session").is_none());
    }
}
