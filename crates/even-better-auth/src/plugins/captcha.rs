//! CAPTCHA protection (`plugins/captcha`): requests to the protected endpoints must carry an
//! `x-captcha-response` token, verified with the provider's siteverify API before routing.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};

use crate::api::dispatch::to_response;
use crate::context::AuthContext;
use crate::error::{ApiError, ErrorCode, Result};
use crate::plugin::Plugin;
use crate::utils::url::wildcard_match;

/// Error codes returned by the API.
pub mod error_codes {
    use crate::error::ErrorCode;

    pub const VERIFICATION_FAILED: ErrorCode =
        ErrorCode { code: "VERIFICATION_FAILED", message: "Captcha verification failed" };
    pub const MISSING_RESPONSE: ErrorCode = ErrorCode { code: "MISSING_RESPONSE", message: "Missing CAPTCHA response" };
    pub const UNKNOWN_ERROR: ErrorCode = ErrorCode { code: "UNKNOWN_ERROR", message: "Something went wrong" };
    pub const ALL: &[ErrorCode] = &[VERIFICATION_FAILED, MISSING_RESPONSE, UNKNOWN_ERROR];
}

use error_codes as e;

const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_ENDPOINTS: &[&str] = &["/sign-up/email", "/sign-in/email", "/request-password-reset"];

/// The result of a bot check (`BotIdVerification`).
#[derive(Debug, Clone, Default)]
pub struct BotIdVerification {
    pub is_bot: bool,
    pub is_verified_bot: Option<bool>,
    pub verified_bot_name: Option<String>,
    pub verified_bot_category: Option<String>,
}

pub type CheckBotIdFn = Arc<dyn Fn(HeaderMap) -> BoxFuture<'static, Result<BotIdVerification>> + Send + Sync>;
pub type ValidateRequestFn = Arc<dyn Fn(&HeaderMap, &BotIdVerification) -> bool + Send + Sync>;

#[derive(Clone)]
pub enum CaptchaProvider {
    CloudflareTurnstile {
        expected_action: Option<String>,
        allowed_hostnames: Vec<String>,
    },
    GoogleRecaptcha {
        /// reCAPTCHA v3 score threshold. Default 0.5.
        min_score: f64,
        expected_action: Option<String>,
        allowed_hostnames: Vec<String>,
    },
    HCaptcha {
        site_key: Option<String>,
    },
    CaptchaFox {
        site_key: Option<String>,
    },
    /// A bot check you run yourself (Vercel BotID in TS): `check_bot_id` gets the request
    /// headers; without `validate_request`, anything but `is_bot == false` is rejected.
    VercelBotId {
        check_bot_id: CheckBotIdFn,
        validate_request: Option<ValidateRequestFn>,
    },
}

impl CaptchaProvider {
    pub fn cloudflare_turnstile() -> Self {
        Self::CloudflareTurnstile { expected_action: None, allowed_hostnames: vec![] }
    }

    pub fn google_recaptcha() -> Self {
        Self::GoogleRecaptcha { min_score: 0.5, expected_action: None, allowed_hostnames: vec![] }
    }

    fn site_verify_url(&self) -> &'static str {
        match self {
            Self::CloudflareTurnstile { .. } => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Self::GoogleRecaptcha { .. } => "https://www.google.com/recaptcha/api/siteverify",
            Self::HCaptcha { .. } => "https://api.hcaptcha.com/siteverify",
            Self::CaptchaFox { .. } => "https://api.captchafox.com/siteverify",
            Self::VercelBotId { .. } => "",
        }
    }
}

#[derive(Clone)]
pub struct CaptchaOptions {
    pub provider: CaptchaProvider,
    /// Unused by `VercelBotId`.
    pub secret_key: String,
    /// Protected paths (wildcards allowed). Default: email sign-up/sign-in and password reset.
    pub endpoints: Vec<String>,
    pub site_verify_url_override: Option<String>,
}

impl CaptchaOptions {
    pub fn new(provider: CaptchaProvider, secret_key: impl Into<String>) -> Self {
        Self { provider, secret_key: secret_key.into(), endpoints: vec![], site_verify_url_override: None }
    }
}

/// The request path relative to the base path, with duplicate and trailing slashes removed.
fn normalize_endpoint_path(pathname: &str, base_path: &str) -> String {
    let without_base = pathname.strip_prefix(base_path).unwrap_or(pathname);
    let mut out = String::with_capacity(without_base.len() + 1);
    for c in without_base.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    if !out.starts_with('/') {
        out.insert(0, '/');
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

fn failure(status: StatusCode, code: ErrorCode) -> http::Response<Bytes> {
    to_response(Err(ApiError::from_code(status, code)), None, HeaderMap::new())
}

fn verification_failed() -> Option<http::Response<Bytes>> {
    Some(failure(StatusCode::FORBIDDEN, e::VERIFICATION_FAILED))
}

/// A verification step that could not complete (logged; the client sees `UNKNOWN_ERROR`).
struct Unavailable(String);

async fn site_verify(url: &str, body: SiteVerifyBody) -> std::result::Result<Value, Unavailable> {
    let client = crate::oauth2::http_client();
    let builder = match body {
        SiteVerifyBody::Json(v) => client.post(url).header("content-type", "application/json").body(v.to_string()),
        SiteVerifyBody::Form(pairs) => {
            let encoded = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish();
            client.post(url).header("content-type", "application/x-www-form-urlencoded").body(encoded)
        }
    };
    let unavailable = |detail: String| Unavailable(format!("CAPTCHA service unavailable: {detail}"));
    let res = builder.timeout(VERIFY_TIMEOUT).send().await.map_err(|e| unavailable(e.to_string()))?;
    if !res.status().is_success() {
        return Err(unavailable(res.status().to_string()));
    }
    res.json::<Value>().await.map_err(|e| unavailable(e.to_string()))
}

enum SiteVerifyBody {
    Json(Value),
    Form(Vec<(&'static str, String)>),
}

fn hostname_allowed(allowed: &[String], data: &Value) -> bool {
    allowed.is_empty() || data["hostname"].as_str().is_some_and(|h| allowed.iter().any(|a| a == h))
}

fn action_matches(expected: &Option<String>, data: &Value) -> bool {
    expected.as_ref().is_none_or(|a| data["action"].as_str() == Some(a))
}

pub struct Captcha {
    options: CaptchaOptions,
}

pub fn captcha(options: CaptchaOptions) -> Arc<dyn Plugin> {
    Arc::new(Captcha { options })
}

impl Captcha {
    fn protects(&self, path: &str) -> bool {
        let matches = |p: &str| if p.contains('*') { wildcard_match(p, path) } else { p == path };
        if self.options.endpoints.is_empty() {
            DEFAULT_ENDPOINTS.iter().any(|p| matches(p))
        } else {
            self.options.endpoints.iter().any(|p| matches(p))
        }
    }

    async fn verify(
        &self,
        headers: &HeaderMap,
        ctx: &AuthContext,
    ) -> std::result::Result<Option<http::Response<Bytes>>, Unavailable> {
        let opts = &self.options;
        if let CaptchaProvider::VercelBotId { check_bot_id, validate_request } = &opts.provider {
            let check = tokio::time::timeout(VERIFY_TIMEOUT, check_bot_id(headers.clone())).await;
            let verification = match check {
                Ok(Ok(v)) => v,
                Ok(Err(err)) => return Err(Unavailable(format!("CAPTCHA service unavailable: {err}"))),
                Err(_) => return Err(Unavailable("CAPTCHA service unavailable: Operation timed out".into())),
            };
            let valid = match validate_request {
                Some(f) => f(headers, &verification),
                None => !verification.is_bot,
            };
            return Ok(if valid { None } else { verification_failed() });
        }
        if opts.secret_key.is_empty() {
            return Err(Unavailable("Missing secret key".into()));
        }
        let Some(token) = headers.get("x-captcha-response").and_then(|v| v.to_str().ok()).filter(|v| !v.is_empty())
        else {
            return Ok(Some(failure(StatusCode::BAD_REQUEST, e::MISSING_RESPONSE)));
        };
        let remote_ip = crate::utils::ip::get_ip(headers, &ctx.options.advanced.ip_address);
        let url = opts.site_verify_url_override.as_deref().unwrap_or_else(|| opts.provider.site_verify_url());
        let mut form = vec![("secret", opts.secret_key.clone()), ("response", token.to_owned())];
        match &opts.provider {
            CaptchaProvider::CloudflareTurnstile { expected_action, allowed_hostnames } => {
                let mut body = json!({ "secret": opts.secret_key, "response": token });
                if let Some(ip) = &remote_ip {
                    body["remoteip"] = ip.clone().into();
                }
                let data = site_verify(url, SiteVerifyBody::Json(body)).await?;
                if data["success"] != true {
                    tracing::warn!(provider = "cloudflare-turnstile", reason = "siteverify_rejected", error_codes = %data["error-codes"], "Cloudflare Turnstile verification failed");
                    return Ok(verification_failed());
                }
                if !action_matches(expected_action, &data) {
                    tracing::warn!(
                        provider = "cloudflare-turnstile",
                        reason = "action_mismatch",
                        "Cloudflare Turnstile verification failed"
                    );
                    return Ok(verification_failed());
                }
                if !hostname_allowed(allowed_hostnames, &data) {
                    tracing::warn!(
                        provider = "cloudflare-turnstile",
                        reason = "hostname_mismatch",
                        "Cloudflare Turnstile verification failed"
                    );
                    return Ok(verification_failed());
                }
                Ok(None)
            }
            CaptchaProvider::GoogleRecaptcha { min_score, expected_action, allowed_hostnames } => {
                if let Some(ip) = remote_ip {
                    form.push(("remoteip", ip));
                }
                let data = site_verify(url, SiteVerifyBody::Form(form)).await?;
                let low_score = data["score"].as_f64().is_some_and(|s| s < *min_score);
                if data["success"] != true
                    || low_score
                    || !action_matches(expected_action, &data)
                    || !hostname_allowed(allowed_hostnames, &data)
                {
                    return Ok(verification_failed());
                }
                Ok(None)
            }
            CaptchaProvider::HCaptcha { site_key } | CaptchaProvider::CaptchaFox { site_key } => {
                if let Some(key) = site_key {
                    form.push(("sitekey", key.clone()));
                }
                if let Some(ip) = remote_ip {
                    let field =
                        if matches!(opts.provider, CaptchaProvider::HCaptcha { .. }) { "remoteip" } else { "remoteIp" };
                    form.push((field, ip));
                }
                let data = site_verify(url, SiteVerifyBody::Form(form)).await?;
                Ok(if data["success"] == true { None } else { verification_failed() })
            }
            CaptchaProvider::VercelBotId { .. } => unreachable!("handled above"),
        }
    }
}

#[async_trait]
impl Plugin for Captcha {
    fn id(&self) -> &str {
        "captcha"
    }

    async fn on_request(&self, request: &mut http::Request<Bytes>, ctx: &AuthContext) -> Option<http::Response<Bytes>> {
        let path = normalize_endpoint_path(request.uri().path(), &ctx.options.base_path);
        if !self.protects(&path) {
            return None;
        }
        match self.verify(request.headers(), ctx).await {
            Ok(res) => res,
            Err(Unavailable(message)) => {
                tracing::error!(endpoint = %request.uri(), "{message}");
                Some(failure(StatusCode::INTERNAL_SERVER_ERROR, e::UNKNOWN_ERROR))
            }
        }
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_endpoint_path;

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize_endpoint_path("/api/auth/sign-in/email", "/api/auth"), "/sign-in/email");
        assert_eq!(normalize_endpoint_path("/api/auth//sign-in//email/", "/api/auth"), "/sign-in/email");
        assert_eq!(normalize_endpoint_path("/api/auth", "/api/auth"), "/");
    }
}
