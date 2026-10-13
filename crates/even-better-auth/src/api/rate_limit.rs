//! Request rate limiting (`api/rate-limiter`).

use std::collections::HashMap;
use std::sync::Mutex;

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde_json::{Map, Value, json};

use crate::context::AuthContext;
use crate::db::Where;
use crate::options::{BetterAuthOptions, RateLimitRule, RateLimitStorage};
use crate::utils::ip::get_ip;
use crate::utils::url::wildcard_match;

const MEMORY_MAX_ENTRIES: usize = 100_000;
const NO_TRUSTED_IP_KEY: &str = "no-trusted-ip";

#[derive(Clone, Copy)]
struct Entry {
    count: u64,
    last_request: i64,
    expires_at: i64,
}

pub struct RateLimiter {
    enabled: bool,
    memory: Mutex<HashMap<String, Entry>>,
}

enum Decision {
    Allowed { count: u64, last_request: i64 },
    Denied { retry_after: i64 },
}

fn decide(existing: Option<(u64, i64)>, rule: RateLimitRule, now: i64) -> Decision {
    let window_ms = rule.window as i64 * 1000;
    match existing {
        None => Decision::Allowed { count: 1, last_request: now },
        Some((_, last)) if now - last >= window_ms => Decision::Allowed { count: 1, last_request: now },
        Some((count, last)) if count >= rule.max => {
            Decision::Denied { retry_after: ((last + window_ms - now) as f64 / 1000.0).ceil() as i64 }
        }
        Some((count, _)) => Decision::Allowed { count: count + 1, last_request: now },
    }
}

fn special_rule(path: &str) -> Option<RateLimitRule> {
    if path.starts_with("/sign-in")
        || path.starts_with("/sign-up")
        || path.starts_with("/change-password")
        || path.starts_with("/change-email")
    {
        return Some(RateLimitRule { window: 10, max: 3 });
    }
    if path == "/request-password-reset"
        || path == "/send-verification-email"
        || path.starts_with("/forget-password")
        || path == "/email-otp/send-verification-otp"
        || path == "/email-otp/request-password-reset"
    {
        return Some(RateLimitRule { window: 60, max: 3 });
    }
    None
}

impl RateLimiter {
    pub fn new(options: &BetterAuthOptions) -> Self {
        Self {
            enabled: options.rate_limit.enabled.unwrap_or(!cfg!(debug_assertions)),
            memory: Mutex::new(HashMap::new()),
        }
    }

    fn resolve(&self, ctx: &AuthContext, path: &str, headers: &HeaderMap) -> Option<(String, RateLimitRule)> {
        let opts = &ctx.options.rate_limit;
        let mut ip_config = ctx.options.advanced.ip_address.clone();
        ip_config.localhost_fallback = false;
        let ip = get_ip(headers, &ip_config);
        if ip.is_none() && ip_config.disable_tracking {
            return None;
        }
        let key = format!("{}|{path}", ip.as_deref().unwrap_or(NO_TRUSTED_IP_KEY));
        let mut rule = special_rule(path).unwrap_or(RateLimitRule { window: opts.window, max: opts.max });
        'plugins: for plugin in ctx.plugins() {
            for r in plugin.rate_limit() {
                if (r.path_matcher)(path) {
                    rule = r.rule;
                    break 'plugins;
                }
            }
        }
        let custom =
            opts.custom_rules.iter().find(|(p, _)| if p.contains('*') { wildcard_match(p, path) } else { p == path });
        if let Some((_, custom)) = custom {
            rule = (*custom)?;
        }
        Some((key, rule))
    }

    async fn consume(&self, ctx: &AuthContext, key: &str, rule: RateLimitRule) -> crate::error::Result<Option<i64>> {
        let now = chrono::Utc::now().timestamp_millis();
        match ctx.options.rate_limit_storage() {
            RateLimitStorage::Memory => {
                let mut memory = self.memory.lock().unwrap();
                if memory.len() > MEMORY_MAX_ENTRIES {
                    memory.retain(|_, e| now < e.expires_at);
                }
                let existing = memory.get(key).filter(|e| now < e.expires_at).map(|e| (e.count, e.last_request));
                Ok(match decide(existing, rule, now) {
                    Decision::Allowed { count, last_request } => {
                        memory.insert(
                            key.to_owned(),
                            Entry { count, last_request, expires_at: now + rule.window as i64 * 1000 },
                        );
                        None
                    }
                    Decision::Denied { retry_after } => Some(retry_after),
                })
            }
            RateLimitStorage::SecondaryStorage => {
                let Some(storage) = &ctx.options.secondary_storage else {
                    return Err(crate::error::Error::Config(
                        "secondary-storage rate limiting requires `secondary_storage`".into(),
                    ));
                };
                // The counter opens with a TTL of one window and is never extended.
                let count = storage.increment(key, rule.window).await?;
                Ok(if count <= rule.max { None } else { Some(rule.window as i64) })
            }
            RateLimitStorage::Database => {
                let row = ctx.db.find_one("rateLimit", &[Where::eq("key", key)]).await?;
                let existing = row.as_ref().map(|r| {
                    (
                        r.get("count").and_then(Value::as_u64).unwrap_or(0),
                        r.get("lastRequest").and_then(Value::as_i64).unwrap_or(0),
                    )
                });
                match decide(existing, rule, now) {
                    Decision::Allowed { count, last_request } => {
                        let mut data = Map::new();
                        data.insert("count".into(), count.into());
                        data.insert("lastRequest".into(), last_request.into());
                        if row.is_some() {
                            ctx.db.update_many("rateLimit", &[Where::eq("key", key)], data).await?;
                        } else {
                            data.insert("key".into(), key.into());
                            ctx.db.create("rateLimit", data, false).await?;
                        }
                        Ok(None)
                    }
                    Decision::Denied { retry_after } => Ok(Some(retry_after)),
                }
            }
        }
    }

    /// Returns a 429 response if the request exceeds its limit.
    pub async fn check(&self, ctx: &AuthContext, path: &str, headers: &HeaderMap) -> Option<http::Response<Bytes>> {
        if !self.enabled {
            return None;
        }
        let (key, rule) = self.resolve(ctx, path, headers)?;
        match self.consume(ctx, &key, rule).await {
            Ok(None) => None,
            Ok(Some(retry_after)) => Some(
                http::Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header("content-type", "application/json")
                    .header("x-retry-after", retry_after.to_string())
                    .body(Bytes::from(json!({ "message": "Too many requests. Please try again later." }).to_string()))
                    .expect("valid response"),
            ),
            Err(e) => {
                tracing::error!(error = %e, "rate limit storage error");
                None
            }
        }
    }
}
