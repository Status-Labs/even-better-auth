//! HOTP/TOTP (RFC 4226 / RFC 6238) compatible with `@better-auth/utils/otp`: HMAC-SHA1 keyed
//! with the secret's UTF-8 bytes, and `otpauth://` URIs carrying the base32 secret.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use super::constant_time_eq;

pub const DEFAULT_PERIOD: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;

/// The HOTP code for `counter`.
pub fn hotp(secret: &str, counter: u64, digits: u32) -> String {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let offset = (h[h.len() - 1] & 0x0f) as usize;
    let truncated = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
    let digits = digits.clamp(1, 8);
    format!("{:0width$}", truncated % 10u32.pow(digits), width = digits as usize)
}

fn counter_at(unix_ms: i64, period: u64) -> u64 {
    (unix_ms.max(0) as u64) / (period.max(1) * 1000)
}

/// The current TOTP code.
pub fn totp(secret: &str, digits: u32, period: u64) -> String {
    hotp(secret, counter_at(chrono::Utc::now().timestamp_millis(), period), digits)
}

/// Whether `code` matches the TOTP for the current period or one period either side.
pub fn verify_totp(secret: &str, code: &str, digits: u32, period: u64) -> bool {
    let counter = counter_at(chrono::Utc::now().timestamp_millis(), period);
    let mut matched = false;
    for c in [counter.saturating_sub(1), counter, counter + 1] {
        matched |= constant_time_eq(code.as_bytes(), hotp(secret, c, digits).as_bytes());
    }
    matched
}

/// RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `otpauth://totp/{issuer}:{account}?secret=...&issuer=...&digits=...&period=...`.
pub fn totp_uri(secret: &str, issuer: &str, account: &str, digits: u32, period: u64) -> String {
    let enc = crate::utils::url::encode_uri_component;
    let params = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", &base32_encode(secret.as_bytes()))
        .append_pair("issuer", issuer)
        .append_pair("digits", &digits.to_string())
        .append_pair("period", &period.to_string())
        .finish();
    format!("otpauth://totp/{}:{}?{params}", enc(issuer), enc(account))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4226_vectors() {
        // RFC 4226 Appendix D, secret "12345678901234567890".
        let expected =
            ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
        for (i, code) in expected.iter().enumerate() {
            assert_eq!(hotp("12345678901234567890", i as u64, 6), *code);
        }
        // RFC 6238 (SHA-1, 8 digits) at T=59s.
        assert_eq!(hotp("12345678901234567890", 59 / 30, 8), "94287082");
    }

    #[test]
    fn base32_and_uri() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(
            totp_uri("secret", "My App", "a@b.com", 6, 30),
            "otpauth://totp/My%20App:a%40b.com?secret=ONSWG4TFOQ&issuer=My+App&digits=6&period=30"
        );
        let code = totp("s3cret", 6, 30);
        assert!(verify_totp("s3cret", &code, 6, 30));
        assert!(!verify_totp("other", &code, 6, 30) || code == totp("other", 6, 30));
    }
}
