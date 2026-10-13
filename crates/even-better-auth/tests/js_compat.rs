//! Byte-level compatibility with the TypeScript implementation. Vectors were produced
//! with node:crypto, @noble/ciphers 2.x and jose 6.x using the same parameters as
//! better-auth (see `crypto/index.ts`, `crypto/jwt.ts`, `crypto/purpose.ts`).

use even_better_auth::crypto::{self, EncryptionPurpose, SecretConfig};

#[tokio::test]
async fn scrypt_password_hash_from_js_verifies() {
    let hash = "00112233445566778899aabbccddeeff:fbc7f6d8cc99b409c5948ba34cd6bf1ff631f99e47f3a328040387393d1253c0f9f36177249745d0bcb123cd0005e43d32206449355159ce72494744f1b4c5ae";
    assert!(crypto::verify_password(hash, "пароль123!").await.unwrap());
    assert!(!crypto::verify_password(hash, "wrong").await.unwrap());
}

#[test]
fn cookie_signature_matches() {
    assert_eq!(crypto::make_signature("token-value", "secret"), "0DpbU2QNiYgO/tfMzHgAHCKT+4IlOx1n9o7c7WOrqJs=");
}

#[test]
fn xchacha_ciphertext_from_js_decrypts() {
    let ct = "13280d80fe4600526262b8c12cffb2545090124f10bcec16b7b023afb7c4277d9ab9845c9e27a12f9197aac66dadc33eb89291";
    assert_eq!(crypto::symmetric_decrypt(&SecretConfig::single("my-secret"), ct).unwrap(), "hello world");
}

#[test]
fn jwe_from_jose_decrypts() {
    let token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoieVhPVEVCX2JzQUhtVXE2WUtHSFFkeWFkY2EtVTREWThmcklPbTh6NVdZOCJ9..qWJdWnTc5_4d6cE95IvzZA.BiQYHpSogzGm9cTWmYnuygWbOaqlVSlIpfmz16telVXZndHkXOhi69S-zjxBGEAWJH53iRKqbMxdKTn3n9953A.TXUuz0Sj18G3T1NGs-z49h0tHdRKJyFbVfRl7A05NoY";
    let claims =
        crypto::symmetric_decode_jwt(token, &SecretConfig::single("jwe-secret"), "better-auth-session").unwrap();
    assert_eq!(claims["hello"], "world");
}

#[test]
fn hmac_base64url_matches() {
    assert_eq!(crypto::hmac_sign_base64url("secret", r#"{"a":1}"#), "qp4uNXX11wmLbKzNeQiIw21f22M0KnO62i1qUXR6hJQ");
}

#[test]
fn purpose_key_matches() {
    let key = crypto::derive_purpose_key(&SecretConfig::single("secret"), EncryptionPurpose::OAuthStateCookie);
    assert_eq!(key.current(), "545cc4e17416b97e8cfbc4f29a76da87cda7a043bd1ce6ab185eab9d84203ca7");
}

/// JWS tokens and private JWKs produced by `jose` 6 (`generateKeyPair` + `exportJWK` + `SignJWT`).
#[test]
fn jose_jws_and_jwks_interoperate() {
    use even_better_auth::crypto::jose::{JwsAlgorithm, PrivateKey, PublicKey, sign_jws, verify_jws};
    let vectors: serde_json::Value = serde_json::from_str(include_str!("fixtures/jose_jws.json")).unwrap();
    for (alg, v) in vectors.as_object().unwrap() {
        let alg = JwsAlgorithm::parse(alg).unwrap();
        let private = PrivateKey::from_jwk(v["jwk"].as_object().unwrap()).unwrap();
        let public = PublicKey::from_jwk(&private.public_key().to_jwk()).unwrap();
        let decoded = verify_jws(v["token"].as_str().unwrap(), &public, &[alg]).unwrap_or_else(|| panic!("{alg}"));
        assert_eq!(decoded.payload["sub"], "user-1");
        assert_eq!(decoded.kid(), Some("k1"));
        // The exported JWK matches jose's member for member (except `alg`/`kid`, which jose omits).
        let mut ours = private.to_jwk();
        ours.retain(|k, _| v["jwk"].get(k).is_some());
        assert_eq!(serde_json::Value::Object(ours), v["jwk"], "{alg} JWK export");
        let token = sign_jws(&private, alg, serde_json::Map::new(), v["jwk"].as_object().unwrap()).unwrap();
        assert!(verify_jws(&token, &public, &[alg]).is_some());
    }
}

/// Writes Rust-signed tokens for checking with `jose` (run with `--ignored`; see
/// `e2e/js-client/verify-jws.mjs`).
#[test]
#[ignore]
fn write_rust_jws_vectors() {
    use even_better_auth::crypto::jose::{JwsAlgorithm, PrivateKey, sign_jws};
    let mut out = serde_json::Map::new();
    for alg in JwsAlgorithm::ALL {
        let key = PrivateKey::generate(alg, None).unwrap();
        let mut payload = serde_json::Map::new();
        payload.insert("sub".into(), "rust".into());
        let token = sign_jws(&key, alg, serde_json::Map::new(), &payload).unwrap();
        out.insert(alg.to_string(), serde_json::json!({ "jwk": key.public_key().to_jwk(), "token": token }));
    }
    std::fs::write(std::env::var("JWS_OUT").unwrap(), serde_json::Value::Object(out).to_string()).unwrap();
}
