//! WebAuthn relying-party verification, following `@simplewebauthn/server` 13 (which the TS
//! plugin uses): registration (`verifyRegistrationResponse`) and authentication
//! (`verifyAuthenticationResponse`) responses in their JSON form, COSE public keys verified
//! with the crate's JOSE keys, and a minimal CBOR decoder.
//!
//! Attestation: registrations request `attestation: "none"`, so attestation is never used to
//! establish trust. `none` statements must be empty and `packed` self-attestation signatures
//! are verified; certificate-based statements (`packed` with `x5c`, `fido-u2f`, `tpm`,
//! `android-key`, `android-safetynet`, `apple`) are accepted without validating their
//! certificate chains.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::crypto::jose::{JwsAlgorithm, PublicKey};

/// COSE algorithms offered at registration (simplewebauthn's defaults: EdDSA, ES256, RS256).
pub const DEFAULT_ALGORITHMS: [i64; 3] = [-8, -7, -257];
/// COSE algorithms accepted when verifying (simplewebauthn's supported list, minus the
/// deprecated RSASSA-PKCS1-v1_5 with SHA-1).
const SUPPORTED_ALGORITHMS: [i64; 9] = [-8, -7, -35, -36, -37, -38, -39, -257, -258];

type VResult<T> = Result<T, String>;

// ---- encoding helpers ----------------------------------------------------------------------

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Lenient base64url decoding (padding and standard alphabet tolerated).
pub fn from_b64url(s: &str) -> VResult<Vec<u8>> {
    let normalized: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| {
            if c == '+' {
                '-'
            } else if c == '/' {
                '_'
            } else {
                c
            }
        })
        .collect();
    URL_SAFE_NO_PAD.decode(normalized).map_err(|_| format!("invalid base64url: {s}"))
}

/// The stored public key encoding (standard base64, as `@better-auth/utils` writes it).
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn from_b64(s: &str) -> VResult<Vec<u8>> {
    STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')))
        .map_err(|_| "invalid base64 public key".to_owned())
}

// ---- CBOR ----------------------------------------------------------------------------------

/// A decoded CBOR item (the subset WebAuthn uses).
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
    Null,
    Float(f64),
}

impl Cbor {
    pub fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn get_int(&self, key: i128) -> Option<&Cbor> {
        self.get(&Cbor::Int(key))
    }

    fn get_text(&self, key: &str) -> Option<&Cbor> {
        self.get(&Cbor::Text(key.to_owned()))
    }

    fn as_int(&self) -> Option<i128> {
        match self {
            Cbor::Int(i) => Some(*i),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

/// Decode the first CBOR item of `data`, returning it and the number of bytes it used.
pub fn decode_cbor(data: &[u8]) -> VResult<(Cbor, usize)> {
    let mut pos = 0;
    let item = decode_item(data, &mut pos, 0)?;
    Ok((item, pos))
}

fn take<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> VResult<&'a [u8]> {
    let end = pos.checked_add(n).filter(|e| *e <= data.len()).ok_or("truncated CBOR")?;
    let out = &data[*pos..end];
    *pos = end;
    Ok(out)
}

fn decode_item(data: &[u8], pos: &mut usize, depth: usize) -> VResult<Cbor> {
    if depth > 16 {
        return Err("CBOR nested too deeply".into());
    }
    let initial = take(data, pos, 1)?[0];
    let (major, info) = (initial >> 5, initial & 0x1f);
    let arg = |pos: &mut usize| -> VResult<u64> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(take(data, pos, 1)?[0]),
            25 => u64::from(u16::from_be_bytes(take(data, pos, 2)?.try_into().expect("2 bytes"))),
            26 => u64::from(u32::from_be_bytes(take(data, pos, 4)?.try_into().expect("4 bytes"))),
            27 => u64::from_be_bytes(take(data, pos, 8)?.try_into().expect("8 bytes")),
            _ => return Err("unsupported CBOR length (indefinite lengths are not allowed)".into()),
        })
    };
    let len = |pos: &mut usize| -> VResult<usize> { usize::try_from(arg(pos)?).map_err(|_| "CBOR length".into()) };
    Ok(match major {
        0 => Cbor::Int(i128::from(arg(pos)?)),
        1 => Cbor::Int(-1 - i128::from(arg(pos)?)),
        2 => {
            let n = len(pos)?;
            Cbor::Bytes(take(data, pos, n)?.to_vec())
        }
        3 => {
            let n = len(pos)?;
            Cbor::Text(String::from_utf8(take(data, pos, n)?.to_vec()).map_err(|_| "invalid CBOR text")?)
        }
        4 => {
            let n = len(pos)?;
            let mut items = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                items.push(decode_item(data, pos, depth + 1)?);
            }
            Cbor::Array(items)
        }
        5 => {
            let n = len(pos)?;
            let mut entries = Vec::with_capacity(n.min(64));
            for _ in 0..n {
                let k = decode_item(data, pos, depth + 1)?;
                let v = decode_item(data, pos, depth + 1)?;
                entries.push((k, v));
            }
            Cbor::Map(entries)
        }
        6 => {
            arg(pos)?;
            decode_item(data, pos, depth + 1)?
        }
        7 => match info {
            20 => Cbor::Bool(false),
            21 => Cbor::Bool(true),
            22 | 23 => Cbor::Null,
            25 => Cbor::Float(f64::from(half_to_f32(u16::from_be_bytes(take(data, pos, 2)?.try_into().expect("2"))))),
            26 => Cbor::Float(f64::from(f32::from_be_bytes(take(data, pos, 4)?.try_into().expect("4")))),
            27 => Cbor::Float(f64::from_be_bytes(take(data, pos, 8)?.try_into().expect("8"))),
            _ => return Err("unsupported CBOR simple value".into()),
        },
        _ => unreachable!(),
    })
}

fn half_to_f32(h: u16) -> f32 {
    let (sign, exp, frac) = ((h >> 15) & 1, (h >> 10) & 0x1f, h & 0x3ff);
    let magnitude = match exp {
        0 => f32::from(frac) * 2f32.powi(-24),
        31 => {
            if frac == 0 {
                f32::INFINITY
            } else {
                f32::NAN
            }
        }
        e => (1.0 + f32::from(frac) / 1024.0) * 2f32.powi(i32::from(e) - 15),
    };
    if sign == 1 { -magnitude } else { magnitude }
}

// ---- COSE keys -----------------------------------------------------------------------------

/// A credential public key: its COSE algorithm and the key to verify with.
pub struct CoseKey {
    pub alg: i64,
    key: PublicKey,
}

fn jws_alg(alg: i64) -> Option<JwsAlgorithm> {
    Some(match alg {
        -8 => JwsAlgorithm::EdDSA,
        -7 => JwsAlgorithm::ES256,
        -35 => JwsAlgorithm::ES384,
        -36 => JwsAlgorithm::ES512,
        -37 => JwsAlgorithm::PS256,
        -38 => JwsAlgorithm::PS384,
        -39 => JwsAlgorithm::PS512,
        -257 => JwsAlgorithm::RS256,
        -258 => JwsAlgorithm::RS384,
        -259 => JwsAlgorithm::RS512,
        _ => return None,
    })
}

impl CoseKey {
    /// Parse a COSE_Key (`decodeCredentialPublicKey`).
    pub fn parse(bytes: &[u8]) -> VResult<Self> {
        let (cose, _) = decode_cbor(&fix_eddsa_cbor(bytes))?;
        let alg = cose.get_int(3).and_then(Cbor::as_int).ok_or("Credential public key was missing numeric alg")?;
        let alg = i64::try_from(alg).map_err(|_| "invalid alg")?;
        let kty = cose.get_int(1).and_then(Cbor::as_int).ok_or("COSE key missing kty")?;
        let field = |label: i128| -> VResult<String> {
            cose.get_int(label).and_then(Cbor::as_bytes).map(b64url).ok_or_else(|| format!("COSE key missing {label}"))
        };
        let mut jwk = Map::new();
        match kty {
            // OKP
            1 => {
                if cose.get_int(-1).and_then(Cbor::as_int) != Some(6) {
                    return Err("unsupported OKP curve (expected Ed25519)".into());
                }
                jwk.insert("kty".into(), "OKP".into());
                jwk.insert("crv".into(), "Ed25519".into());
                jwk.insert("x".into(), field(-2)?.into());
            }
            // EC2
            2 => {
                let crv = match cose.get_int(-1).and_then(Cbor::as_int) {
                    Some(1) => "P-256",
                    Some(2) => "P-384",
                    Some(3) => "P-521",
                    other => return Err(format!("unsupported EC2 curve {other:?}")),
                };
                jwk.insert("kty".into(), "EC".into());
                jwk.insert("crv".into(), crv.into());
                jwk.insert("x".into(), field(-2)?.into());
                jwk.insert("y".into(), field(-3)?.into());
            }
            // RSA
            3 => {
                jwk.insert("kty".into(), "RSA".into());
                jwk.insert("n".into(), field(-1)?.into());
                jwk.insert("e".into(), field(-2)?.into());
            }
            other => return Err(format!("unsupported COSE key type {other}")),
        }
        let key = PublicKey::from_jwk(&jwk).map_err(|e| e.to_string())?;
        Ok(Self { alg, key })
    }

    /// Verify a WebAuthn signature over `data` (`verifySignature`). ECDSA signatures arrive
    /// DER-encoded.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let Some(alg) = jws_alg(self.alg) else { return false };
        let raw = match alg {
            JwsAlgorithm::ES256 => p256::ecdsa::Signature::from_der(signature).map(|s| s.to_bytes().to_vec()).ok(),
            JwsAlgorithm::ES384 => p384::ecdsa::Signature::from_der(signature).map(|s| s.to_bytes().to_vec()).ok(),
            JwsAlgorithm::ES512 => p521::ecdsa::Signature::from_der(signature).map(|s| s.to_bytes().to_vec()).ok(),
            _ => Some(signature.to_vec()),
        };
        raw.is_some_and(|sig| self.key.verify(alg, data, &sig))
    }
}

/// Some authenticators encode EdDSA keys as a 3-entry map that holds 4 entries; patch the
/// header like simplewebauthn does.
fn fix_eddsa_cbor(bytes: &[u8]) -> Vec<u8> {
    const BAD: [u8; 17] =
        [0xa3, 0x01, 0x63, 0x4f, 0x4b, 0x50, 0x03, 0x27, 0x20, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39];
    let mut out = bytes.to_vec();
    if out.starts_with(&BAD) {
        out[0] = 0xa4;
    }
    out
}

// ---- authenticator data and client data ----------------------------------------------------

pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub user_present: bool,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub counter: u32,
    pub aaguid: Option<[u8; 16]>,
    pub credential_id: Option<Vec<u8>>,
    /// The COSE public key bytes as they appear in the authenticator data.
    pub credential_public_key: Option<Vec<u8>>,
}

/// `parseAuthenticatorData`.
pub fn parse_authenticator_data(data: &[u8]) -> VResult<AuthenticatorData> {
    if data.len() < 37 {
        return Err(format!("Authenticator data was {} bytes, expected at least 37 bytes", data.len()));
    }
    let flags = data[32];
    let mut out = AuthenticatorData {
        rp_id_hash: data[..32].try_into().expect("32 bytes"),
        user_present: flags & 0x01 != 0,
        user_verified: flags & 0x04 != 0,
        backup_eligible: flags & 0x08 != 0,
        backed_up: flags & 0x10 != 0,
        counter: u32::from_be_bytes(data[33..37].try_into().expect("4 bytes")),
        aaguid: None,
        credential_id: None,
        credential_public_key: None,
    };
    let mut pos = 37;
    if flags & 0x40 != 0 {
        out.aaguid = Some(take(data, &mut pos, 16)?.try_into().expect("16 bytes"));
        let id_len = u16::from_be_bytes(take(data, &mut pos, 2)?.try_into().expect("2 bytes"));
        out.credential_id = Some(take(data, &mut pos, usize::from(id_len))?.to_vec());
        let key_bytes = fix_eddsa_cbor(&data[pos..]);
        let (_, used) = decode_cbor(&key_bytes)?;
        out.credential_public_key = Some(key_bytes[..used].to_vec());
        pos += used;
    }
    if flags & 0x80 != 0 {
        let (_, used) = decode_cbor(&data[pos..])?;
        pos += used;
    }
    if data.len() > pos {
        return Err("Leftover bytes detected while parsing authenticator data".into());
    }
    Ok(out)
}

/// The credential's device type and backup state (`parseBackupFlags`).
fn backup_flags(data: &AuthenticatorData) -> VResult<(&'static str, bool)> {
    let device_type = if data.backup_eligible { "multiDevice" } else { "singleDevice" };
    if device_type == "singleDevice" && data.backed_up {
        return Err("Single-device credential indicated that it was backed up, which should be impossible.".into());
    }
    Ok((device_type, data.backed_up))
}

fn format_aaguid(aaguid: &[u8; 16]) -> String {
    let h = hex::encode(aaguid);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

struct ClientData {
    raw: Vec<u8>,
    origin: String,
}

/// Decode `clientDataJSON` and check its type, challenge and origin.
fn check_client_data(
    encoded: Option<&str>,
    expected_type: &str,
    expected_challenge: &str,
    expected_origins: &[String],
) -> VResult<ClientData> {
    let raw = from_b64url(encoded.ok_or("Credential response clientDataJSON was not a string")?)?;
    let json: Value = serde_json::from_slice(&raw).map_err(|_| "clientDataJSON is not JSON")?;
    let field = |k: &str| json.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
    let (kind, challenge, origin) = (field("type"), field("challenge"), field("origin"));
    if kind != expected_type {
        return Err(format!("Unexpected response type: {kind}"));
    }
    if challenge != expected_challenge {
        return Err(format!("Unexpected response challenge \"{challenge}\", expected \"{expected_challenge}\""));
    }
    if !expected_origins.contains(&origin) {
        return Err(format!(
            "Unexpected response origin \"{origin}\", expected one of: {}",
            expected_origins.join(", ")
        ));
    }
    if let Some(binding) = json.get("tokenBinding") {
        let status = binding.get("status").and_then(Value::as_str).unwrap_or_default();
        if !["present", "supported", "not-supported", "notSupported"].contains(&status) {
            return Err(format!("Unexpected tokenBinding status {status}"));
        }
    }
    Ok(ClientData { raw, origin })
}

fn check_credential_ids(response: &Value) -> VResult<()> {
    let id = response.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("Missing credential ID")?;
    if response.get("rawId").and_then(Value::as_str) != Some(id) {
        return Err("Credential ID was not base64url-encoded".into());
    }
    if response.get("type").and_then(Value::as_str) != Some("public-key") {
        return Err("Unexpected credential type, expected \"public-key\"".into());
    }
    Ok(())
}

fn check_rp_id(hash: &[u8; 32], rp_id: &str) -> VResult<()> {
    if Sha256::digest(rp_id.as_bytes()).as_slice() != hash {
        return Err("Unexpected RP ID hash".into());
    }
    Ok(())
}

// ---- ceremonies ----------------------------------------------------------------------------

/// What a verified registration yields (`registrationInfo`).
#[derive(Debug, Clone)]
pub struct VerifiedRegistration {
    pub fmt: String,
    pub aaguid: String,
    /// base64url credential id.
    pub credential_id: String,
    /// COSE public key bytes.
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub transports: Option<Vec<String>>,
    pub user_verified: bool,
    /// `singleDevice` or `multiDevice`.
    pub device_type: String,
    pub backed_up: bool,
    pub origin: String,
}

/// `verifyRegistrationResponse` for a `RegistrationResponseJSON`.
pub fn verify_registration(
    response: &Value,
    expected_challenge: &str,
    expected_origins: &[String],
    rp_id: &str,
    require_user_verification: bool,
) -> VResult<VerifiedRegistration> {
    check_credential_ids(response)?;
    let inner = response.get("response").ok_or("Credential missing response")?;
    let client = check_client_data(
        inner.get("clientDataJSON").and_then(Value::as_str),
        "webauthn.create",
        expected_challenge,
        expected_origins,
    )?;
    let attestation =
        from_b64url(inner.get("attestationObject").and_then(Value::as_str).ok_or("Missing attestationObject")?)?;
    let (object, _) = decode_cbor(&attestation)?;
    let fmt = match object.get_text("fmt") {
        Some(Cbor::Text(f)) => f.clone(),
        _ => return Err("Attestation object is missing fmt".into()),
    };
    let auth_data =
        object.get_text("authData").and_then(Cbor::as_bytes).ok_or("Attestation object is missing authData")?;
    let att_stmt = object.get_text("attStmt").cloned().unwrap_or(Cbor::Map(vec![]));
    let parsed = parse_authenticator_data(auth_data)?;
    check_rp_id(&parsed.rp_id_hash, rp_id)?;
    if !parsed.user_present {
        return Err("User presence was required, but user was not present".into());
    }
    if require_user_verification && !parsed.user_verified {
        return Err("User verification was required, but user could not be verified".into());
    }
    let credential_id = parsed.credential_id.as_ref().ok_or("No credential ID was provided by authenticator")?;
    let public_key = parsed.credential_public_key.as_ref().ok_or("No public key was provided by authenticator")?;
    let aaguid = parsed.aaguid.ok_or("No AAGUID was present during registration")?;
    let key = CoseKey::parse(public_key)?;
    if !SUPPORTED_ALGORITHMS.contains(&key.alg) {
        return Err(format!("Unexpected public key alg \"{}\"", key.alg));
    }
    let client_data_hash = Sha256::digest(&client.raw);
    match fmt.as_str() {
        "none" => {
            if !matches!(&att_stmt, Cbor::Map(m) if m.is_empty()) {
                return Err("None attestation had unexpected attestation statement".into());
            }
        }
        "packed" if att_stmt.get_text("x5c").is_none() => {
            let alg = att_stmt.get_text("alg").and_then(Cbor::as_int).ok_or("Packed attestation missing alg")?;
            if alg != i128::from(key.alg) {
                return Err("Packed self-attestation algorithm does not match the credential key".into());
            }
            let sig = att_stmt.get_text("sig").and_then(Cbor::as_bytes).ok_or("Packed attestation missing sig")?;
            let signed = [auth_data, client_data_hash.as_slice()].concat();
            if !key.verify(&signed, sig) {
                return Err("Packed self-attestation signature is invalid".into());
            }
        }
        "packed" | "fido-u2f" | "android-safetynet" | "android-key" | "tpm" | "apple" => {
            tracing::debug!(fmt, "accepting attestation statement without certificate validation");
        }
        other => return Err(format!("Unsupported Attestation Format: {other}")),
    }
    let (device_type, backed_up) = backup_flags(&parsed)?;
    let transports = inner
        .get("transports")
        .and_then(Value::as_array)
        .map(|t| t.iter().filter_map(Value::as_str).map(str::to_owned).collect());
    Ok(VerifiedRegistration {
        fmt,
        aaguid: format_aaguid(&aaguid),
        credential_id: b64url(credential_id),
        public_key: public_key.clone(),
        counter: parsed.counter,
        transports,
        user_verified: parsed.user_verified,
        device_type: device_type.into(),
        backed_up,
        origin: client.origin,
    })
}

/// What a verified authentication yields (`authenticationInfo`).
#[derive(Debug, Clone)]
pub struct VerifiedAuthentication {
    pub verified: bool,
    pub new_counter: u32,
    pub credential_id: String,
    pub user_verified: bool,
    pub device_type: String,
    pub backed_up: bool,
    pub origin: String,
}

/// `verifyAuthenticationResponse` for an `AuthenticationResponseJSON` against a stored
/// credential. `Ok` with `verified: false` means the signature did not verify.
pub fn verify_authentication(
    response: &Value,
    expected_challenge: &str,
    expected_origins: &[String],
    rp_id: &str,
    credential_public_key: &[u8],
    stored_counter: u32,
    require_user_verification: bool,
) -> VResult<VerifiedAuthentication> {
    check_credential_ids(response)?;
    let inner = response.get("response").ok_or("Credential missing response")?;
    let client = check_client_data(
        inner.get("clientDataJSON").and_then(Value::as_str),
        "webauthn.get",
        expected_challenge,
        expected_origins,
    )?;
    let auth_data = from_b64url(
        inner
            .get("authenticatorData")
            .and_then(Value::as_str)
            .ok_or("Credential response authenticatorData missing")?,
    )?;
    let signature =
        from_b64url(inner.get("signature").and_then(Value::as_str).ok_or("Credential response signature missing")?)?;
    if inner.get("userHandle").is_some_and(|h| !h.is_null() && !h.is_string()) {
        return Err("Credential response userHandle was not a string".into());
    }
    let parsed = parse_authenticator_data(&auth_data)?;
    check_rp_id(&parsed.rp_id_hash, rp_id)?;
    if !parsed.user_present {
        return Err("User not present during authentication".into());
    }
    if require_user_verification && !parsed.user_verified {
        return Err("User verification required, but user could not be verified".into());
    }
    // A counter that did not advance suggests a cloned authenticator.
    if (parsed.counter > 0 || stored_counter > 0) && parsed.counter <= stored_counter {
        return Err(format!("Response counter value {} was lower than expected {stored_counter}", parsed.counter));
    }
    let (device_type, backed_up) = backup_flags(&parsed)?;
    let signed = [auth_data.as_slice(), Sha256::digest(&client.raw).as_slice()].concat();
    let verified = CoseKey::parse(credential_public_key)?.verify(&signed, &signature);
    Ok(VerifiedAuthentication {
        verified,
        new_counter: parsed.counter,
        credential_id: response.get("id").and_then(Value::as_str).unwrap_or_default().to_owned(),
        user_verified: parsed.user_verified,
        device_type: device_type.into(),
        backed_up,
        origin: client.origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_basics() {
        // {1: 2, 3: -7, -1: 1, "a": h'0102', "t": [true, null]}
        let bytes =
            [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x61, 0x61, 0x42, 0x01, 0x02, 0x61, 0x74, 0x82, 0xf5, 0xf6];
        let (item, used) = decode_cbor(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(item.get_int(3), Some(&Cbor::Int(-7)));
        assert_eq!(item.get_int(-1), Some(&Cbor::Int(1)));
        assert_eq!(item.get_text("a"), Some(&Cbor::Bytes(vec![1, 2])));
        assert_eq!(item.get_text("t"), Some(&Cbor::Array(vec![Cbor::Bool(true), Cbor::Null])));
        assert!(decode_cbor(&[0x5f]).is_err(), "indefinite lengths are rejected");
        assert!(decode_cbor(&[0x58, 0x05, 0x01]).is_err(), "truncated");
        assert_eq!(format_aaguid(&[0xab; 16]), "abababab-abab-abab-abab-abababababab");
    }
}
