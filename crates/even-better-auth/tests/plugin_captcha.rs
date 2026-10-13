#![cfg(feature = "oauth")]

mod common;

use std::sync::{Arc, Mutex};

use common::{Client, options};
use even_better_auth::api::ApiCall;
use even_better_auth::plugins::captcha::{BotIdVerification, CaptchaOptions, CaptchaProvider, captcha};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A one-route HTTP server answering every request with `reply`; records request bodies.
async fn siteverify(reply: Value) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/siteverify", listener.local_addr().unwrap());
    let bodies = Arc::new(Mutex::new(vec![]));
    let seen = bodies.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut len = 0;
            // Read headers, then Content-Length bytes of body.
            let body = loop {
                len += sock.read(&mut buf[len..]).await.unwrap();
                let text = String::from_utf8_lossy(&buf[..len]).into_owned();
                if let Some(end) = text.find("\r\n\r\n") {
                    let cl = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_owned())
                        })
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    if len >= end + 4 + cl {
                        break text[end + 4..end + 4 + cl].to_owned();
                    }
                }
            };
            seen.lock().unwrap().push(body);
            let payload = reply.to_string();
            let res = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                payload.len()
            );
            sock.write_all(res.as_bytes()).await.unwrap();
        }
    });
    (url, bodies)
}

async fn client(opts: CaptchaOptions) -> Client {
    let (mut o, _) = options();
    o.plugins.push(captcha(opts));
    Client::build(o).await
}

async fn sign_up(c: &mut Client, token: Option<&str>) -> (u16, Value) {
    let mut req = http::Request::builder()
        .method("POST")
        .uri("http://localhost:3000/api/auth/sign-up/email")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "203.0.113.7");
    if let Some(t) = token {
        req = req.header("x-captcha-response", t);
    }
    let body = json!({ "email": "a@test.com", "password": "password1234", "name": "A" }).to_string();
    let res = c.auth.handler(req.body(body.into()).unwrap()).await;
    let status = res.status().as_u16();
    (status, serde_json::from_slice(res.body()).unwrap_or(Value::Null))
}

#[tokio::test]
async fn turnstile() {
    let (url, bodies) = siteverify(json!({ "success": true, "action": "login", "hostname": "example.com" })).await;
    let mut opts = CaptchaOptions::new(CaptchaProvider::cloudflare_turnstile(), "secret");
    opts.site_verify_url_override = Some(url.clone());
    let mut c = client(opts).await;
    let (status, body) = sign_up(&mut c, None).await;
    assert_eq!((status, body["code"].as_str()), (400, Some("MISSING_RESPONSE")));
    let (status, body) = sign_up(&mut c, Some("tok")).await;
    assert_eq!(status, 200, "{body}");
    let sent: Value = serde_json::from_str(&bodies.lock().unwrap()[0]).unwrap();
    assert_eq!(sent, json!({ "secret": "secret", "response": "tok", "remoteip": "203.0.113.7" }));
    // Unprotected paths pass without a token.
    assert_eq!(c.get("/get-session").await.status, 200);

    let mut opts = CaptchaOptions::new(
        CaptchaProvider::CloudflareTurnstile { expected_action: Some("signup".into()), allowed_hostnames: vec![] },
        "secret",
    );
    opts.site_verify_url_override = Some(url.clone());
    let (status, body) = sign_up(&mut client(opts).await, Some("tok")).await;
    assert_eq!((status, body["code"].as_str()), (403, Some("VERIFICATION_FAILED")));

    let mut opts = CaptchaOptions::new(
        CaptchaProvider::CloudflareTurnstile { expected_action: None, allowed_hostnames: vec!["other.com".into()] },
        "secret",
    );
    opts.site_verify_url_override = Some(url);
    let (status, _) = sign_up(&mut client(opts).await, Some("tok")).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn recaptcha_score_and_form_body() {
    let (url, bodies) = siteverify(json!({ "success": true, "score": 0.3, "hostname": "example.com" })).await;
    let mut opts = CaptchaOptions::new(CaptchaProvider::google_recaptcha(), "secret");
    opts.site_verify_url_override = Some(url.clone());
    let (status, _) = sign_up(&mut client(opts).await, Some("tok")).await;
    assert_eq!(status, 403, "score below 0.5");
    assert_eq!(bodies.lock().unwrap()[0], "secret=secret&response=tok&remoteip=203.0.113.7");

    let mut opts = CaptchaOptions::new(
        CaptchaProvider::GoogleRecaptcha { min_score: 0.2, expected_action: None, allowed_hostnames: vec![] },
        "secret",
    );
    opts.site_verify_url_override = Some(url);
    let (status, _) = sign_up(&mut client(opts).await, Some("tok")).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn hcaptcha_and_captchafox() {
    let (url, bodies) = siteverify(json!({ "success": false })).await;
    let mut opts = CaptchaOptions::new(CaptchaProvider::HCaptcha { site_key: Some("site".into()) }, "secret");
    opts.site_verify_url_override = Some(url.clone());
    let (status, _) = sign_up(&mut client(opts).await, Some("tok")).await;
    assert_eq!(status, 403);
    let mut opts = CaptchaOptions::new(CaptchaProvider::CaptchaFox { site_key: None }, "secret");
    opts.site_verify_url_override = Some(url);
    sign_up(&mut client(opts).await, Some("tok")).await;
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies[0], "secret=secret&response=tok&sitekey=site&remoteip=203.0.113.7");
    assert_eq!(bodies[1], "secret=secret&response=tok&remoteIp=203.0.113.7");
}

#[tokio::test]
async fn service_errors_and_custom_endpoints() {
    let mut opts = CaptchaOptions::new(CaptchaProvider::cloudflare_turnstile(), "secret");
    opts.site_verify_url_override = Some("http://127.0.0.1:9/siteverify".into());
    opts.endpoints = vec!["/sign-up/*".into()];
    let mut c = client(opts).await;
    let (status, body) = sign_up(&mut c, Some("tok")).await;
    assert_eq!((status, body["code"].as_str()), (500, Some("UNKNOWN_ERROR")));
    // Not listed any more.
    assert_eq!(c.sign_in("a@test.com", "password1234").await.status, 401);
    // Server-side API calls don't go through on_request.
    let call =
        ApiCall::new("signUpEmail").body(json!({ "email": "b@test.com", "password": "password1234", "name": "B" }));
    assert!(c.auth.api(call).await.is_ok());

    let opts = CaptchaOptions::new(CaptchaProvider::cloudflare_turnstile(), "");
    let (status, _) = sign_up(&mut client(opts).await, Some("tok")).await;
    assert_eq!(status, 500, "missing secret key");
}

#[tokio::test]
async fn bot_id() {
    let opts = CaptchaOptions::new(
        CaptchaProvider::VercelBotId {
            check_bot_id: Arc::new(|headers| {
                Box::pin(async move {
                    Ok(BotIdVerification { is_bot: headers.get("x-bot").is_some(), ..Default::default() })
                })
            }),
            validate_request: None,
        },
        "",
    );
    let mut c = client(opts).await;
    let (status, _) = sign_up(&mut c, None).await;
    assert_eq!(status, 200);
    let req = http::Request::builder()
        .method("POST")
        .uri("http://localhost:3000/api/auth/sign-in/email")
        .header("content-type", "application/json")
        .header("x-bot", "1")
        .body(json!({ "email": "a@test.com", "password": "password1234" }).to_string().into())
        .unwrap();
    assert_eq!(c.auth.handler(req).await.status(), 403);
}
