//! Bearer token authentication (`plugins/bearer`): accept the session token in an
//! `Authorization: Bearer <token>` header, and expose newly issued tokens in a
//! `set-auth-token` response header.
//!
//! ```no_run
//! # let mut options = even_better_auth::BetterAuthOptions::new(std::sync::Arc::new(even_better_auth::MemoryAdapter::new()));
//! options.plugins.push(even_better_auth::plugins::bearer::bearer(Default::default()));
//! ```

use std::any::Any;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::api::{Ctx, EndpointContext, hook};
use crate::crypto::{constant_time_eq, hmac_sha256, make_signature};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};

#[derive(Debug, Clone, Default)]
pub struct BearerOptions {
    /// Only accept signed tokens (`token.signature`), not bare session tokens.
    pub require_signature: bool,
}

pub struct Bearer {
    options: BearerOptions,
}

pub fn bearer(options: BearerOptions) -> Arc<dyn Plugin> {
    Arc::new(Bearer { options })
}

fn try_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8().map(|c| c.into_owned()).unwrap_or_else(|_| s.to_owned())
}

/// Base64 in either alphabet, padded or not.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed).ok().or_else(|| STANDARD.decode(s).ok()).or_else(|| {
        let normalized = trimmed.replace('+', "-").replace('/', "_");
        URL_SAFE_NO_PAD.decode(normalized).ok()
    })
}

/// The signed session-cookie value carried by the header, if it verifies.
fn signed_token(ctx: &EndpointContext, header: &str, require_signature: bool) -> Option<String> {
    // RFC 7235: the auth scheme is case-insensitive.
    let scheme = header.get(..7)?;
    if !scheme.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = header[7..].trim();
    if token.is_empty() {
        return None;
    }
    let secret = &ctx.auth.secret;
    let signed = if token.contains('.') {
        if token.contains('%') { try_decode(token) } else { token.to_owned() }
    } else {
        if require_signature {
            return None;
        }
        format!("{token}.{}", make_signature(token, secret))
    };
    let (value, signature) = signed.split_once('.')?;
    let expected = hmac_sha256(secret.as_bytes(), value.as_bytes());
    let given = decode_base64(signature)?;
    constant_time_eq(&expected, &given).then_some(signed)
}

async fn before(ctx: Ctx, require_signature: bool) {
    let Some(header) = ctx.header("authorization") else { return };
    if let Some(signed) = signed_token(&ctx, &header, require_signature) {
        ctx.set_request_cookie(&ctx.auth.cookies.session_token.name, &signed);
    }
}

/// Copy a session token set in this response into `set-auth-token`.
fn after(ctx: &EndpointContext) {
    let name = &ctx.auth.cookies.session_token.name;
    let Some(cookie) = ctx.response_cookie(name) else { return };
    let mut parts = cookie.split(';');
    let value = parts.next().and_then(|p| p.split_once('=')).map(|(_, v)| try_decode(v)).unwrap_or_default();
    let expired = parts.any(|p| p.trim().eq_ignore_ascii_case("max-age=0"));
    if value.is_empty() || expired {
        return;
    }
    ctx.set_header("set-auth-token", &value);
    let mut exposed: Vec<String> = ctx
        .response_header("access-control-expose-headers")
        .unwrap_or_default()
        .split(',')
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .collect();
    if !exposed.iter().any(|h| h == "set-auth-token") {
        exposed.push("set-auth-token".into());
    }
    ctx.set_header("access-control-expose-headers", &exposed.join(", "));
}

impl Plugin for Bearer {
    fn id(&self) -> &str {
        "bearer"
    }

    fn hooks(&self) -> PluginHooks {
        let require_signature = self.options.require_signature;
        PluginHooks {
            before: vec![MatchedHook::new(
                |ctx| ctx.has_header("authorization"),
                hook(move |ctx| async move {
                    before(ctx, require_signature).await;
                    Ok(None)
                }),
            )],
            after: vec![MatchedHook::new(
                |_| true,
                hook(|ctx| async move {
                    after(&ctx);
                    Ok(None)
                }),
            )],
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
