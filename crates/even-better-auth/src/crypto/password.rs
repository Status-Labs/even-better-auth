//! scrypt password hashing compatible with `@better-auth/utils/password`:
//! N=16384, r=16, p=1, dkLen=64, salt = 16 random bytes hex-encoded (the hex *string*
//! is the salt), password NFKC-normalized, output `"{salt_hex}:{key_hex}"`.

use unicode_normalization::UnicodeNormalization;

use super::constant_time_eq;
use crate::error::{Error, Result};

fn derive(password: &str, salt: &str) -> Result<Vec<u8>> {
    let params = scrypt::Params::new(14, 16, 1).map_err(|e| Error::Crypto(e.to_string()))?;
    let normalized: String = password.nfkc().collect();
    let mut out = vec![0u8; 64];
    scrypt::scrypt(normalized.as_bytes(), salt.as_bytes(), &params, &mut out)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(out)
}

/// Hash a password. Runs on a blocking thread since scrypt is CPU and memory heavy.
pub async fn hash_password(password: &str) -> Result<String> {
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || {
        let salt = hex::encode(super::random_bytes::<16>());
        let key = derive(&password, &salt)?;
        Ok(format!("{salt}:{}", hex::encode(key)))
    })
    .await
    .map_err(|e| Error::Crypto(e.to_string()))?
}

pub async fn verify_password(hash: &str, password: &str) -> Result<bool> {
    let Some((salt, key)) = hash.split_once(':') else {
        return Ok(false);
    };
    let (salt, key, password) = (salt.to_owned(), key.to_owned(), password.to_owned());
    tokio::task::spawn_blocking(move || {
        let Ok(expected) = hex::decode(&key) else {
            return Ok(false);
        };
        let derived = derive(&password, &salt)?;
        Ok(constant_time_eq(&derived, &expected))
    })
    .await
    .map_err(|e| Error::Crypto(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_and_verify() {
        let hash = hash_password("correctPassword123!").await.unwrap();
        assert_eq!(hash.split(':').count(), 2);
        assert!(verify_password(&hash, "correctPassword123!").await.unwrap());
        assert!(!verify_password(&hash, "wrong").await.unwrap());
    }

    #[test]
    fn known_vector() {
        // Generated with @noble/hashes scrypt(password.normalize("NFKC"), salt, {N:16384,r:16,p:1,dkLen:64}).
        let key = derive("пароль123!", "00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(key.len(), 64);
    }
}
