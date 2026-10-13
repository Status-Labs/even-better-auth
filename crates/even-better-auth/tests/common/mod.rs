//! Test harness: drive a `BetterAuth` instance over HTTP-shaped requests, with a cookie jar.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use even_better_auth::{BetterAuth, BetterAuthOptions, EmailAndPasswordOptions, MemoryAdapter, UserTokenEmail};
use serde_json::Value;

pub const BASE: &str = "http://localhost:3000";

pub fn options() -> (BetterAuthOptions, Arc<MemoryAdapter>) {
    let db = Arc::new(MemoryAdapter::new());
    let mut o = BetterAuthOptions::new(db.clone());
    o.base_url = Some(BASE.into());
    o.secret = Some("better-auth-secret-that-is-long-enough-for-tests".into());
    o.email_and_password = EmailAndPasswordOptions::enabled();
    o.rate_limit.enabled = Some(false);
    (o, db)
}

/// Captures emails sent through `send_verification_email` / `send_reset_password`.
#[derive(Clone, Default)]
pub struct Outbox(pub Arc<Mutex<Vec<UserTokenEmail>>>);

impl Outbox {
    pub fn callback(&self) -> Option<even_better_auth::Callback<UserTokenEmail>> {
        let inner = self.0.clone();
        even_better_auth::callback(move |e: UserTokenEmail| {
            let inner = inner.clone();
            async move {
                inner.lock().unwrap().push(e);
                Ok(())
            }
        })
    }
    pub fn last(&self) -> Option<UserTokenEmail> {
        self.0.lock().unwrap().last().cloned()
    }
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

#[derive(Debug)]
pub struct Res {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Value,
    pub text: String,
}

impl Res {
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_owned()).collect()
    }
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies().into_iter().find(|c| c.starts_with(&format!("{name}=")))
    }
    pub fn location(&self) -> Option<String> {
        self.headers.get("location").map(|v| v.to_str().unwrap().to_owned())
    }
}

/// A client with a cookie jar, like a browser talking to the server.
pub struct Client {
    pub auth: BetterAuth,
    pub jar: BTreeMap<String, String>,
    pub origin: Option<String>,
}

impl Client {
    pub fn new(auth: BetterAuth) -> Self {
        Self { auth, jar: BTreeMap::new(), origin: Some(BASE.into()) }
    }

    pub async fn build(options: BetterAuthOptions) -> Self {
        Self::new(BetterAuth::new(options).await.expect("valid options"))
    }

    pub fn cookie_header(&self) -> String {
        self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    fn store_cookies(&mut self, res: &Res) {
        for c in res.set_cookies() {
            let first = c.split(';').next().unwrap();
            let (name, value) = first.split_once('=').unwrap();
            let expired = c.contains("Max-Age=0");
            if expired || value.is_empty() {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    pub async fn request(&mut self, method: &str, path: &str, body: Option<Value>) -> Res {
        let mut req = http::Request::builder().method(method).uri(format!("{BASE}/api/auth{path}"));
        if !self.jar.is_empty() {
            req = req.header("cookie", self.cookie_header());
        }
        if let Some(o) = &self.origin {
            req = req.header("origin", o);
        }
        let bytes = match &body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Bytes::from(b.to_string())
            }
            None => Bytes::new(),
        };
        let res = self.auth.handler(req.body(bytes).unwrap()).await;
        let status = res.status().as_u16();
        let headers = res.headers().clone();
        let text = String::from_utf8_lossy(res.body()).into_owned();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        let res = Res { status, headers, body, text };
        self.store_cookies(&res);
        res
    }

    pub async fn get(&mut self, path: &str) -> Res {
        self.request("GET", path, None).await
    }

    pub async fn post(&mut self, path: &str, body: Value) -> Res {
        self.request("POST", path, Some(body)).await
    }

    pub async fn sign_up(&mut self, email: &str, password: &str) -> Res {
        self.post("/sign-up/email", serde_json::json!({ "email": email, "password": password, "name": "Test User" }))
            .await
    }

    pub async fn sign_in(&mut self, email: &str, password: &str) -> Res {
        self.post("/sign-in/email", serde_json::json!({ "email": email, "password": password })).await
    }

    pub fn has_session_cookie(&self) -> bool {
        self.jar.contains_key("better-auth.session_token")
    }
}
