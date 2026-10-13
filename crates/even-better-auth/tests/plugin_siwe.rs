mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::plugins::siwe::{EnsLookupResult, SiweOptions, SiweVerifyMessageArgs, siwe};
use serde_json::json;

const ADDRESS: &str = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
const CHECKSUMMED: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

fn message(domain: &str, nonce: &str, chain_id: u64, extra: &str) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{ADDRESS}\n\nSign in\n\nURI: https://{domain}\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\nIssued At: 2024-01-01T00:00:00Z{extra}"
    )
}

type Seen = Arc<Mutex<Vec<SiweVerifyMessageArgs>>>;

async fn setup(configure: impl FnOnce(&mut SiweOptions)) -> (Client, Seen, Arc<even_better_auth::MemoryAdapter>) {
    let (mut o, db) = options();
    let counter = Arc::new(Mutex::new(0u32));
    let seen: Seen = Arc::default();
    let sink = seen.clone();
    let mut opts = SiweOptions::new(
        "example.com",
        Arc::new(move || {
            let counter = counter.clone();
            Box::pin(async move {
                let mut n = counter.lock().unwrap();
                *n += 1;
                Ok(format!("nonce{:08}", *n))
            })
        }),
        Arc::new(move |args: SiweVerifyMessageArgs| {
            let ok = args.signature == "valid";
            sink.lock().unwrap().push(args);
            Box::pin(async move { Ok(ok) })
        }),
    );
    configure(&mut opts);
    o.plugins.push(siwe(opts));
    (Client::build(o).await, seen, db)
}

async fn nonce(c: &mut Client) -> String {
    let res = c.post("/siwe/nonce", json!({})).await;
    res.body["nonce"].as_str().unwrap_or_else(|| panic!("{}", res.text)).to_owned()
}

#[tokio::test]
async fn sign_in_with_ethereum() {
    let (mut c, seen, db) = setup(|_| {}).await;
    let n = nonce(&mut c).await;
    let res =
        c.post("/siwe/verify", json!({ "message": message("example.com", &n, 1, ""), "signature": "valid" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(res.body["success"], true);
    assert_eq!(res.body["user"]["walletAddress"], CHECKSUMMED);
    assert_eq!(res.body["user"]["chainId"], 1);
    let args = seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(args.address, CHECKSUMMED);
    assert_eq!(args.cacao["p"]["nonce"], n.as_str());
    let session = c.get("/get-session").await;
    assert_eq!(session.body["user"]["name"], CHECKSUMMED);
    assert_eq!(
        session.body["user"]["email"],
        format!("{ADDRESS}@siwe.placeholder.invalid"),
        "emails are stored lowercased"
    );

    // The nonce is single-use.
    let res =
        c.post("/siwe/verify", json!({ "message": message("example.com", &n, 1, ""), "signature": "valid" })).await;
    assert_eq!(res.body["code"], "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");

    // Same wallet on another chain: same user, a second wallet row and account.
    let n = nonce(&mut c).await;
    let res =
        c.post("/siwe/verify", json!({ "message": message("example.com", &n, 137, ""), "signature": "valid" })).await;
    assert_eq!(res.status, 200, "{}", res.text);
    assert_eq!(db.dump("user").await.len(), 1);
    let wallets = db.dump("walletAddress").await;
    assert_eq!(wallets.len(), 2);
    assert!(wallets.iter().any(|w| w["chainId"] == 137 && w["isPrimary"] == false));
    let accounts = db.dump("account").await;
    assert!(accounts.iter().any(|a| a["accountId"] == format!("{CHECKSUMMED}:137").as_str()));
}

#[tokio::test]
async fn rejects_mismatched_messages() {
    let (mut c, _, _) = setup(|_| {}).await;
    let n = nonce(&mut c).await;
    let res = c.post("/siwe/verify", json!({ "message": message("evil.com", &n, 1, ""), "signature": "valid" })).await;
    assert_eq!((res.status, res.body["code"].as_str()), (401, Some("UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")));
    // The failed attempt burned the nonce.
    let res =
        c.post("/siwe/verify", json!({ "message": message("example.com", &n, 1, ""), "signature": "valid" })).await;
    assert_eq!(res.body["code"], "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE");

    let n = nonce(&mut c).await;
    let res = c.post("/siwe/verify", json!({ "message": message("example.com", &n, 1, ""), "signature": "bad" })).await;
    assert_eq!(res.body["message"], "Unauthorized: Invalid SIWE signature");

    let n = nonce(&mut c).await;
    let expired = message("example.com", &n, 1, "\nExpiration Time: 2020-01-01T00:00:00Z");
    let res = c.post("/siwe/verify", json!({ "message": expired, "signature": "valid" })).await;
    assert_eq!(res.body["code"], "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED");

    let n = nonce(&mut c).await;
    let future = message("example.com", &n, 1, "\nNot Before: 2999-01-01T00:00:00Z");
    let res = c.post("/siwe/verify", json!({ "message": future, "signature": "valid" })).await;
    assert_eq!(res.body["code"], "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID");

    let res = c.post("/siwe/verify", json!({ "message": "x", "signature": "valid", "extra": 1 })).await;
    assert_eq!(res.status, 400);
}

#[tokio::test]
async fn email_and_ens() {
    let (mut c, _, db) = setup(|o| {
        o.anonymous = false;
        o.ens_lookup = Some(Arc::new(|_wallet| {
            Box::pin(async {
                Ok(Some(EnsLookupResult { name: "vitalik.eth".into(), avatar: "https://ens/a.png".into() }))
            })
        }));
    })
    .await;
    let n = nonce(&mut c).await;
    let res =
        c.post("/siwe/verify", json!({ "message": message("example.com", &n, 1, ""), "signature": "valid" })).await;
    assert_eq!(res.status, 400, "email required when anonymous is off");

    let n = nonce(&mut c).await;
    let res = c
        .post(
            "/siwe/verify",
            json!({ "message": message("example.com", &n, 1, ""), "signature": "valid", "email": "Me@Example.com" }),
        )
        .await;
    assert_eq!(res.status, 200, "{}", res.text);
    let users = db.dump("user").await;
    assert_eq!(users[0]["email"], "me@example.com");
    assert_eq!(users[0]["name"], "vitalik.eth");
    assert_eq!(users[0]["image"], "https://ens/a.png");
    let claims = db.dump("verification").await;
    assert!(
        claims.iter().all(|v| !v["identifier"].as_str().unwrap().starts_with("siwe-email-claim-")),
        "claim released"
    );

    let res = c.post("/siwe/nonce", json!({ "unexpected": true })).await;
    assert_eq!(res.status, 400);
}

#[tokio::test]
async fn invalid_nonce_from_generator() {
    let (mut c, _, _) = setup(|o| o.get_nonce = Arc::new(|| Box::pin(async { Ok("short".to_owned()) }))).await;
    let res = c.post("/siwe/nonce", json!({})).await;
    assert_eq!((res.status, res.body["code"].as_str()), (500, Some("SIWE_INVALID_NONCE")));
}
