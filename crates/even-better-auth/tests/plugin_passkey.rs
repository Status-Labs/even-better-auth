mod common;

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{BASE, Client, options};
use even_better_auth::plugins::passkey::{AfterRegistration, PasskeyOptions, PasskeyRegistrationUser, passkey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// ---- a software authenticator ---------------------------------------------------------------

/// Minimal CBOR encoding for the structures authenticators produce.
enum C {
    Int(i64),
    Bytes(Vec<u8>),
    Text(&'static str),
    Map(Vec<(C, C)>),
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    match n {
        0..=23 => out.push(major << 5 | n as u8),
        24..=0xff => out.extend([major << 5 | 24, n as u8]),
        0x100..=0xffff => {
            out.push(major << 5 | 25);
            out.extend((n as u16).to_be_bytes());
        }
        _ => {
            out.push(major << 5 | 26);
            out.extend((n as u32).to_be_bytes());
        }
    }
}

fn cbor(c: &C) -> Vec<u8> {
    let mut out = vec![];
    match c {
        C::Int(i) if *i >= 0 => head(&mut out, 0, *i as u64),
        C::Int(i) => head(&mut out, 1, (-1 - *i) as u64),
        C::Bytes(b) => {
            head(&mut out, 2, b.len() as u64);
            out.extend(b);
        }
        C::Text(t) => {
            head(&mut out, 3, t.len() as u64);
            out.extend(t.as_bytes());
        }
        C::Map(entries) => {
            head(&mut out, 5, entries.len() as u64);
            for (k, v) in entries {
                out.extend(cbor(k));
                out.extend(cbor(v));
            }
        }
    }
    out
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

enum Key {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

struct Authenticator {
    key: Key,
    credential_id: Vec<u8>,
    counter: u32,
    /// Report the backup-eligible and backed-up flags.
    synced: bool,
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const AAGUID: [u8; 16] =
    [0xea, 0x9b, 0x8d, 0x66, 0x4d, 0x01, 0x1d, 0x21, 0x3c, 0xe4, 0xb6, 0xb4, 0x8c, 0xb5, 0x75, 0xd4];

impl Authenticator {
    fn p256(seed: u8) -> Self {
        let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        Self { key: Key::P256(key), credential_id: vec![seed; 16], counter: 0, synced: true }
    }

    fn ed25519(seed: u8) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        Self { key: Key::Ed25519(key), credential_id: vec![seed; 20], counter: 0, synced: false }
    }

    fn id(&self) -> String {
        b64(&self.credential_id)
    }

    fn alg(&self) -> i64 {
        match self.key {
            Key::P256(_) => -7,
            Key::Ed25519(_) => -8,
        }
    }

    fn cose_key(&self) -> Vec<u8> {
        match &self.key {
            Key::P256(k) => {
                let point = k.verifying_key().to_sec1_point(false);
                cbor(&C::Map(vec![
                    (C::Int(1), C::Int(2)),
                    (C::Int(3), C::Int(-7)),
                    (C::Int(-1), C::Int(1)),
                    (C::Int(-2), C::Bytes(point.x().unwrap().to_vec())),
                    (C::Int(-3), C::Bytes(point.y().unwrap().to_vec())),
                ]))
            }
            Key::Ed25519(k) => cbor(&C::Map(vec![
                (C::Int(1), C::Int(1)),
                (C::Int(3), C::Int(-8)),
                (C::Int(-1), C::Int(6)),
                (C::Int(-2), C::Bytes(k.verifying_key().to_bytes().to_vec())),
            ])),
        }
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::P256(k) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = k.sign(data);
                sig.to_der().as_bytes().to_vec()
            }
            Key::Ed25519(k) => {
                use ed25519_dalek::Signer;
                k.sign(data).to_bytes().to_vec()
            }
        }
    }

    fn flags(&self, extra: u8) -> u8 {
        FLAG_UP | FLAG_UV | extra | if self.synced { FLAG_BE | FLAG_BS } else { 0 }
    }

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        json!({ "type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false }).to_string().into_bytes()
    }

    /// `navigator.credentials.create()` for `options`, as `RegistrationResponseJSON`.
    fn register(&self, options: &Value, origin: &str, fmt: &str) -> Value {
        let rp_id = options["rp"]["id"].as_str().unwrap();
        let client_data = Self::client_data("webauthn.create", options["challenge"].as_str().unwrap(), origin);
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags(FLAG_AT));
        auth_data.extend(self.counter.to_be_bytes());
        auth_data.extend(AAGUID);
        auth_data.extend((self.credential_id.len() as u16).to_be_bytes());
        auth_data.extend(&self.credential_id);
        auth_data.extend(self.cose_key());
        let att_stmt = match fmt {
            "packed" | "packed-forged" => {
                let mut signed = [auth_data.as_slice(), Sha256::digest(&client_data).as_slice()].concat();
                if fmt == "packed-forged" {
                    signed.push(0);
                }
                C::Map(vec![(C::Text("alg"), C::Int(self.alg())), (C::Text("sig"), C::Bytes(self.sign(&signed)))])
            }
            _ => C::Map(vec![]),
        };
        let fmt = if fmt.starts_with("packed") { "packed" } else { "none" };
        let attestation = cbor(&C::Map(vec![
            (C::Text("fmt"), C::Text(fmt)),
            (C::Text("attStmt"), att_stmt),
            (C::Text("authData"), C::Bytes(auth_data)),
        ]));
        json!({
            "id": self.id(),
            "rawId": self.id(),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "attestationObject": b64(&attestation),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        })
    }

    /// `navigator.credentials.get()` for `options`, as `AuthenticationResponseJSON`.
    fn authenticate(&mut self, options: &Value, origin: &str) -> Value {
        self.counter += 1;
        let rp_id = options["rpId"].as_str().unwrap();
        let client_data = Self::client_data("webauthn.get", options["challenge"].as_str().unwrap(), origin);
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags(0));
        auth_data.extend(self.counter.to_be_bytes());
        let signed = [auth_data.as_slice(), Sha256::digest(&client_data).as_slice()].concat();
        json!({
            "id": self.id(),
            "rawId": self.id(),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "authenticatorData": b64(&auth_data),
                "signature": b64(&self.sign(&signed)),
                "userHandle": null,
            },
            "clientExtensionResults": {},
        })
    }
}

// ---- tests ----------------------------------------------------------------------------------

async fn setup(configure: impl FnOnce(&mut PasskeyOptions)) -> (Client, Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    let mut opts = PasskeyOptions::default();
    configure(&mut opts);
    o.plugins.push(passkey(opts));
    (Client::build(o).await, db)
}

async fn register(c: &mut Client, authenticator: &Authenticator, fmt: &str, name: Option<&str>) -> common::Res {
    let options = c.get("/passkey/generate-register-options").await;
    assert_eq!(options.status, 200, "{}", options.text);
    let response = authenticator.register(&options.body, BASE, fmt);
    let mut body = json!({ "response": response });
    if let Some(n) = name {
        body["name"] = n.into();
    }
    c.post("/passkey/verify-registration", body).await
}

async fn sign_in(c: &mut Client, authenticator: &mut Authenticator) -> common::Res {
    let options = c.get("/passkey/generate-authenticate-options").await;
    assert_eq!(options.status, 200, "{}", options.text);
    let response = authenticator.authenticate(&options.body, BASE);
    c.post("/passkey/verify-authentication", json!({ "response": response })).await
}

#[tokio::test]
async fn register_and_sign_in() {
    let (mut c, db) = setup(|_| {}).await;
    c.sign_up("u@test.com", "password1234").await;
    let options = c.get("/passkey/generate-register-options?name=Custom").await;
    let o = &options.body;
    assert_eq!(o["rp"], json!({ "name": "Better Auth", "id": "localhost" }));
    assert_eq!(o["user"]["name"], "Custom");
    assert_eq!(o["user"]["displayName"], "u@test.com");
    assert_eq!(o["attestation"], "none");
    assert_eq!(
        o["pubKeyCredParams"],
        json!([{ "alg": -8, "type": "public-key" }, { "alg": -7, "type": "public-key" }, { "alg": -257, "type": "public-key" }])
    );
    assert_eq!(
        o["authenticatorSelection"],
        json!({ "residentKey": "preferred", "userVerification": "preferred", "requireResidentKey": false })
    );
    assert_eq!(o["extensions"], json!({ "credProps": true }));
    assert_eq!(URL_SAFE_NO_PAD.decode(o["challenge"].as_str().unwrap()).unwrap().len(), 32);

    let mut authenticator = Authenticator::p256(7);
    let res = register(&mut c, &authenticator, "none", Some("  Laptop  ")).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["name"], "Laptop");
    assert_eq!(res.body["credentialID"], authenticator.id());
    assert_eq!(res.body["deviceType"], "multiDevice");
    assert_eq!(res.body["backedUp"], true);
    assert_eq!(res.body["transports"], "internal,hybrid");
    assert_eq!(res.body["aaguid"], "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4");
    assert_eq!(res.body["counter"], 0);
    let row = &db.dump("passkey").await[0];
    let cose = base64::engine::general_purpose::STANDARD.decode(row["publicKey"].as_str().unwrap()).unwrap();
    assert_eq!(cose, authenticator.cose_key(), "publicKey is the base64 COSE key");

    // Registered credentials are excluded and allowed afterwards.
    let options = c.get("/passkey/generate-register-options").await;
    assert_eq!(
        options.body["excludeCredentials"],
        json!([{ "id": authenticator.id(), "transports": ["internal", "hybrid"], "type": "public-key" }])
    );
    let options = c.get("/passkey/generate-authenticate-options").await;
    assert_eq!(options.body["allowCredentials"][0]["id"], authenticator.id());
    assert_eq!(c.get("/passkey/list-user-passkeys").await.body.as_array().unwrap().len(), 1);

    // A fresh browser signs in with the passkey.
    let mut fresh = Client::new(c.auth.clone());
    let options = fresh.get("/passkey/generate-authenticate-options").await;
    assert!(options.body.get("allowCredentials").is_none());
    assert_eq!(options.body["rpId"], "localhost");
    let res = sign_in(&mut fresh, &mut authenticator).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["user"]["email"], "u@test.com");
    assert!(fresh.has_session_cookie());
    assert_eq!(fresh.get("/get-session").await.body["user"]["email"], "u@test.com");
    assert_eq!(db.dump("passkey").await[0]["counter"], 1);
}

#[tokio::test]
async fn rejects_bad_responses() {
    let (mut c, _) = setup(|_| {}).await;
    c.sign_up("u@test.com", "password1234").await;
    let mut authenticator = Authenticator::p256(3);
    assert_eq!(register(&mut c, &authenticator, "none", None).await.status, 200);

    // Challenges are single-use.
    let options = c.get("/passkey/generate-authenticate-options").await;
    let response = authenticator.authenticate(&options.body, BASE);
    let ok = c.post("/passkey/verify-authentication", json!({ "response": response.clone() })).await;
    assert_eq!(ok.status, 200, "{}", ok.text);
    let replay = c.post("/passkey/verify-authentication", json!({ "response": response })).await;
    assert_eq!(replay.body["code"], "CHALLENGE_NOT_FOUND");

    // A registration challenge can't complete an authentication.
    c.get("/passkey/generate-register-options").await;
    let options = json!({ "rpId": "localhost", "challenge": "x" });
    let response = authenticator.authenticate(&options, BASE);
    let res = c.post("/passkey/verify-authentication", json!({ "response": response })).await;
    assert_eq!(res.body["code"], "CHALLENGE_NOT_FOUND");

    // Wrong origin, wrong challenge, replayed counter, forged signature.
    let options = c.get("/passkey/generate-authenticate-options").await;
    let response = authenticator.authenticate(&options.body, "https://evil.example");
    let res = c.post("/passkey/verify-authentication", json!({ "response": response })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (400, Some("AUTHENTICATION_FAILED")));

    c.get("/passkey/generate-authenticate-options").await;
    let response = authenticator.authenticate(&json!({ "rpId": "localhost", "challenge": "stale" }), BASE);
    let res = c.post("/passkey/verify-authentication", json!({ "response": response })).await;
    assert_eq!(res.body["code"], "AUTHENTICATION_FAILED");

    let options = c.get("/passkey/generate-authenticate-options").await;
    authenticator.counter = 0;
    let response = authenticator.authenticate(&options.body, BASE);
    let res = c.post("/passkey/verify-authentication", json!({ "response": response })).await;
    assert_eq!(res.body["code"], "AUTHENTICATION_FAILED", "counter must advance");

    let options = c.get("/passkey/generate-authenticate-options").await;
    authenticator.counter = 50;
    let mut response = authenticator.authenticate(&options.body, BASE);
    let impostor = Authenticator::p256(4);
    response["response"]["signature"] = b64(&impostor.sign(b"something else")).into();
    let res = c.post("/passkey/verify-authentication", json!({ "response": response })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("AUTHENTICATION_FAILED")));

    // Unknown credential.
    let options = c.get("/passkey/generate-authenticate-options").await;
    let response = Authenticator::p256(9).authenticate(&options.body, BASE);
    let res = c.post("/passkey/verify-authentication", json!({ "response": response })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("PASSKEY_NOT_FOUND")));

    // Registration with a mismatched RP ID.
    let mut options = c.get("/passkey/generate-register-options").await.body;
    options["rp"]["id"] = "evil.example".into();
    let response = Authenticator::p256(5).register(&options, BASE, "none");
    let res = c.post("/passkey/verify-registration", json!({ "response": response })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (500, Some("FAILED_TO_VERIFY_REGISTRATION")));

    // Registration requires a session.
    let mut anon = Client::new(c.auth.clone());
    assert_eq!(anon.get("/passkey/generate-register-options").await.status, 401);
}

#[tokio::test]
async fn ed25519_packed_attestation_and_management() {
    let (mut c, _) = setup(|_| {}).await;
    c.sign_up("u@test.com", "password1234").await;
    let mut authenticator = Authenticator::ed25519(11);
    let res = register(&mut c, &authenticator, "packed", None).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["deviceType"], "singleDevice");
    assert_eq!(res.body["backedUp"], false);
    assert!(res.body.get("name").is_none_or(Value::is_null));
    let id = res.body["id"].as_str().unwrap().to_owned();

    let mut fresh = Client::new(c.auth.clone());
    assert_eq!(sign_in(&mut fresh, &mut authenticator).await.status, 200);

    let res = c.post("/passkey/update-passkey", json!({ "id": id, "name": " Yubikey " })).await;
    assert_eq!(res.body["passkey"]["name"], "Yubikey", "{}", res.text);
    assert_eq!(c.post("/passkey/update-passkey", json!({ "id": id, "name": "  " })).await.status, 400);

    let mut other = Client::new(c.auth.clone());
    other.sign_up("o@test.com", "password1234").await;
    let res = other.post("/passkey/update-passkey", json!({ "id": id, "name": "Mine" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")));
    assert_eq!(other.post("/passkey/delete-passkey", json!({ "id": id })).await.status, 401);
    assert_eq!(other.post("/passkey/delete-passkey", json!({ "id": "missing" })).await.status, 404);

    let res = c.post("/passkey/delete-passkey", json!({ "id": id })).await;
    assert_eq!(res.body, json!({ "status": true }));
    assert!(c.get("/passkey/list-user-passkeys").await.body.as_array().unwrap().is_empty());

    // A packed self-attestation whose signature doesn't verify is rejected.
    let options = c.get("/passkey/generate-register-options").await;
    let response = Authenticator::ed25519(12).register(&options.body, BASE, "packed-forged");
    let res = c.post("/passkey/verify-registration", json!({ "response": response })).await;
    assert_eq!(res.body["code"], "FAILED_TO_VERIFY_REGISTRATION");
}

#[tokio::test]
async fn registration_without_a_session() {
    let (mut c, db) = setup(|o| {
        o.registration.require_session = false;
        o.registration.resolve_user = Some(Arc::new(|_ctx, context| {
            Box::pin(async move {
                Ok(PasskeyRegistrationUser {
                    id: context.unwrap_or_default(),
                    name: "new@test.com".into(),
                    display_name: None,
                })
            })
        }));
        o.registration.after_verification = Some(Arc::new(|_ctx, verified| {
            Box::pin(async move {
                assert_eq!(verified.context.as_deref(), Some("USER_ID"));
                Ok(Some(AfterRegistration { user_id: None, name: Some(format!("{} key", verified.verification.fmt)) }))
            })
        }));
    })
    .await;
    // No session: `resolve_user` decides who registers (here, from the `context` parameter).
    let options = c.get("/passkey/generate-register-options?context=USER_ID").await;
    assert_eq!(options.status, 200, "{}", options.text);
    assert_eq!(options.body["user"]["name"], "new@test.com");
    let response = Authenticator::p256(21).register(&options.body, BASE, "none");
    let res = c.post("/passkey/verify-registration", json!({ "response": response })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["name"], "none key", "named by after_verification");
    assert_eq!(res.body["userId"], "USER_ID");
    assert!(res.body.get("session").is_none());
    assert_eq!(db.dump("passkey").await.len(), 1);

    let (mut c, _) = setup(|o| o.registration.require_session = false).await;
    let res = c.get("/passkey/generate-register-options").await;
    assert_eq!(res.body["code"], "RESOLVE_USER_REQUIRED");
}

#[tokio::test]
async fn registration_creates_a_session_when_asked() {
    let (mut c, _) = setup(|o| {
        o.registration.require_session = false;
        o.registration.resolve_user = Some(Arc::new(|ctx, _| {
            Box::pin(async move {
                let user = ctx.auth.internal_adapter.find_user_by_email("s@test.com").await?.unwrap();
                Ok(PasskeyRegistrationUser { id: user.id, name: user.email, display_name: None })
            })
        }));
    })
    .await;
    Client::new(c.auth.clone()).sign_up("s@test.com", "password1234").await;
    let options = c.get("/passkey/generate-register-options").await;
    assert_eq!(options.status, 200, "{}", options.text);
    let response = Authenticator::p256(31).register(&options.body, BASE, "none");
    let res = c.post("/passkey/verify-registration", json!({ "response": response, "createSession": true })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["user"]["email"], "s@test.com");
    assert!(res.body["session"]["token"].is_string());
    assert_eq!(c.get("/get-session").await.body["user"]["email"], "s@test.com");
}
