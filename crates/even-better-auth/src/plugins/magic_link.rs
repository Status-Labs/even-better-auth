//! Magic link sign-in (`plugins/magic-link`): `POST /sign-in/magic-link` emails a single-use
//! link; `GET /magic-link/verify` consumes it, signing the user in (and up, unless disabled).

use std::any::Any;
use std::sync::Arc;

use http::HeaderMap;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use url::Url;

use crate::api::middleware::{check_callback_urls, form_csrf};
use crate::api::routes::util::is_valid_email;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::crypto;
use crate::error::{ApiError, Error, Result, codes};
use crate::options::Callback;
use crate::options::RateLimitRule;
use crate::plugin::{Plugin, PluginRateLimit};
use crate::types::SessionWithUser;
use crate::utils::validate_user_info::UserSource;

/// Arguments for [`MagicLinkOptions::send_magic_link`].
#[derive(Debug, Clone)]
pub struct MagicLinkEmail {
    pub email: String,
    pub url: String,
    pub token: String,
    pub metadata: Option<Map<String, Value>>,
    pub request_headers: Option<HeaderMap>,
}

pub type TokenFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// How tokens are stored in the verification table (the emailed token is unchanged).
#[derive(Clone, Default)]
pub enum StoreToken {
    #[default]
    Plain,
    /// SHA-256, base64url.
    Hashed,
    Custom(TokenFn),
}

#[derive(Clone)]
pub struct MagicLinkOptions {
    pub send_magic_link: Callback<MagicLinkEmail>,
    /// Seconds until the link expires (default 5 minutes).
    pub expires_in: i64,
    /// Do not create users for unknown emails.
    pub disable_sign_up: bool,
    /// Default: 5 requests per 60 seconds.
    pub rate_limit: RateLimitRule,
    pub generate_token: Option<TokenFn>,
    pub store_token: StoreToken,
}

impl MagicLinkOptions {
    pub fn new(send_magic_link: Callback<MagicLinkEmail>) -> Self {
        Self {
            send_magic_link,
            expires_in: 5 * 60,
            disable_sign_up: false,
            rate_limit: RateLimitRule { window: 60, max: 5 },
            generate_token: None,
            store_token: StoreToken::Plain,
        }
    }
}

fn hash_token(token: &str) -> String {
    crypto::sha256_base64url(token)
}

impl MagicLinkOptions {
    fn stored(&self, token: &str) -> String {
        match &self.store_token {
            StoreToken::Plain => token.to_owned(),
            StoreToken::Hashed => hash_token(token),
            StoreToken::Custom(f) => f(token),
        }
    }
}

fn identifier(stored: &str) -> String {
    format!("magic-link:{stored}")
}

/// The stored `{ type: "magic-link", email, name? }` record, rejecting anything else.
fn parse_record(value: &str) -> Option<(String, Option<String>)> {
    let Value::Object(map) = serde_json::from_str::<Value>(value).ok()? else { return None };
    if map.keys().any(|k| !matches!(k.as_str(), "type" | "email" | "name")) {
        return None;
    }
    if map.get("type")?.as_str()? != "magic-link" {
        return None;
    }
    let email = map.get("email")?.as_str()?.to_owned();
    if !is_valid_email(&email) {
        return None;
    }
    let name = match map.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return None,
    };
    Some((email, name))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInBody {
    email: String,
    name: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
    metadata: Option<Map<String, Value>>,
}

async fn sign_in_magic_link(options: Arc<MagicLinkOptions>, ctx: Ctx) -> EndpointResult {
    form_csrf(&ctx)?;
    let body: SignInBody = ctx.parse_body()?;
    if !is_valid_email(&body.email) {
        return Err(ApiError::bad_request(codes::INVALID_EMAIL));
    }
    let token = match &options.generate_token {
        Some(generate) => generate(&body.email),
        None => crypto::random_string(32, b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    };
    let record = json!({ "type": "magic-link", "email": body.email, "name": body.name });
    let mut record = record.as_object().cloned().unwrap_or_default();
    if body.name.is_none() {
        record.remove("name");
    }
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(options.expires_in);
    ctx.auth
        .internal_adapter
        .create_verification_value(&identifier(&options.stored(&token)), &Value::Object(record).to_string(), expires_at)
        .await?;
    let mut url =
        Url::parse(&format!("{}/magic-link/verify", ctx.base_url)).map_err(|e| Error::Other(e.to_string()))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("token", &token);
        q.append_pair("callbackURL", body.callback_url.as_deref().unwrap_or("/"));
        if let Some(u) = &body.new_user_callback_url {
            q.append_pair("newUserCallbackURL", u);
        }
        if let Some(u) = &body.error_callback_url {
            q.append_pair("errorCallbackURL", u);
        }
    }
    options
        .send_magic_link
        .call(MagicLinkEmail {
            email: body.email,
            url: url.to_string(),
            token,
            metadata: body.metadata,
            request_headers: ctx.is_request.then(|| ctx.headers()),
        })
        .await?;
    ctx.json(json!({ "status": true }))
}

fn decoded_query(ctx: &EndpointContext, key: &str) -> Option<String> {
    ctx.query_str(key)
        .map(|v| percent_encoding::percent_decode_str(&v).decode_utf8().map(|c| c.into_owned()).unwrap_or(v))
}

fn resolve(base: &str, url: &str) -> Result<Url> {
    Url::parse(base).and_then(|b| b.join(url)).map_err(|e| Error::Other(e.to_string()))
}

async fn verify_magic_link(options: Arc<MagicLinkOptions>, ctx: Ctx) -> EndpointResult {
    let callback = decoded_query(&ctx, "callbackURL");
    let new_user = decoded_query(&ctx, "newUserCallbackURL");
    let error_callback = decoded_query(&ctx, "errorCallbackURL");
    check_callback_urls(&ctx, &[callback.clone(), new_user.clone(), error_callback.clone()])?;
    let Some(token) = ctx.query_str("token") else {
        return Err(ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", "token is required"));
    };
    let auth = ctx.auth.clone();
    let callback_url = resolve(&ctx.base_url, callback.as_deref().unwrap_or("/"))?.to_string();
    let error_url = resolve(&ctx.base_url, error_callback.as_deref().unwrap_or(&callback_url))?;
    let new_user_url = resolve(&ctx.base_url, new_user.as_deref().unwrap_or(&callback_url))?.to_string();
    let redirect_error = |error: &str, description: Option<&str>| {
        let mut url = error_url.clone();
        url.query_pairs_mut().append_pair("error", error);
        if let Some(d) = description {
            url.query_pairs_mut().append_pair("error_description", d);
        }
        ctx.redirect(url.to_string())
    };

    let id = identifier(&options.stored(&token));
    // Reject a cross-purpose record without consuming it; issuance requires the atomic consume.
    let pending = auth.internal_adapter.find_verification_value(&id).await?;
    if pending.is_none_or(|v| parse_record(&v.value).is_none()) {
        return redirect_error("INVALID_TOKEN", None);
    }
    let Some(consumed) = auth.internal_adapter.consume_verification_value(&id).await? else {
        return redirect_error("INVALID_TOKEN", None);
    };
    let Some((email, name)) = parse_record(&consumed.value) else {
        return redirect_error("INVALID_TOKEN", None);
    };

    let mut is_new_user = false;
    let mut user = match auth.internal_adapter.find_user_by_email(&email).await? {
        Some(u) => u,
        None if options.disable_sign_up => return redirect_error("new_user_signup_disabled", None),
        None => {
            let mut data = Map::new();
            data.insert("email".into(), email.clone().into());
            data.insert("emailVerified".into(), true.into());
            data.insert("name".into(), name.unwrap_or_default().into());
            match auth.internal_adapter.create_user(data, &UserSource::method("magic-link")).await {
                Ok(u) => {
                    is_new_user = true;
                    u
                }
                Err(Error::Api(e)) if e.code().is_some() => {
                    return redirect_error(e.code().unwrap_or_default(), e.message_str());
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    if !user.email_verified {
        match auth.internal_adapter.revoke_unproven_account_access(&user.id).await? {
            Some(promoted) => user = promoted,
            None => return redirect_error("user_not_found", None),
        }
    }
    let session = match auth.internal_adapter.create_session(&user.id, false, None).await {
        Ok(session) => session,
        Err(Error::Api(e)) if e.code().is_some() => {
            return redirect_error(e.code().unwrap_or_default(), e.message_str());
        }
        Err(_) => return redirect_error("failed_to_create_session", None),
    };
    let data = SessionWithUser { session, user };
    set_session_cookie(&ctx, &data, None, None).await;
    if ctx.query_str("callbackURL").is_none() {
        return ctx.json(json!({
            "token": data.session.token,
            "user": auth.user_output(&data.user),
            "session": auth.session_output(&data.session),
        }));
    }
    ctx.redirect(if is_new_user { new_user_url } else { callback_url })
}

pub struct MagicLink {
    options: Arc<MagicLinkOptions>,
}

pub fn magic_link(options: MagicLinkOptions) -> Arc<dyn Plugin> {
    Arc::new(MagicLink { options: Arc::new(options) })
}

impl Plugin for MagicLink {
    fn id(&self) -> &str {
        "magic-link"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b) = (self.options.clone(), self.options.clone());
        vec![
            Endpoint::post(
                "signInMagicLink",
                "/sign-in/magic-link",
                handler(move |ctx| sign_in_magic_link(a.clone(), ctx)),
            )
            .allow_form(),
            Endpoint::get(
                "magicLinkVerify",
                "/magic-link/verify",
                handler(move |ctx| verify_magic_link(b.clone(), ctx)),
            ),
        ]
    }

    fn rate_limit(&self) -> Vec<PluginRateLimit> {
        vec![PluginRateLimit {
            path_matcher: Arc::new(|p: &str| {
                p.starts_with("/sign-in/magic-link") || p.starts_with("/magic-link/verify")
            }),
            rule: self.options.rate_limit,
        }]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::parse_record;

    #[test]
    fn records_must_match_exactly() {
        assert!(parse_record(r#"{"type":"magic-link","email":"a@b.co"}"#).is_some());
        assert!(parse_record(r#"{"type":"magic-link","email":"a@b.co","name":"N"}"#).is_some());
        assert!(parse_record(r#"{"type":"email-otp","email":"a@b.co"}"#).is_none());
        assert!(parse_record(r#"{"type":"magic-link","email":"a@b.co","extra":1}"#).is_none());
        assert!(parse_record(r#"{"type":"magic-link","email":"nope"}"#).is_none());
        assert!(parse_record("user-id").is_none());
    }
}
