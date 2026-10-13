//! Passkeys (`@better-auth/passkey`): register WebAuthn credentials for a user and sign in
//! with them. Challenges live in verification rows referenced by a signed cookie; responses
//! are verified by [`webauthn`] (a port of the `@simplewebauthn/server` checks the TS plugin
//! relies on). Rows match TS: `credentialID` base64url, `publicKey` the base64 COSE key.

pub mod webauthn;

use std::any::Any;
use std::sync::Arc;

use chrono::{Duration, Utc};
use futures::future::BoxFuture;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::api::middleware::{get_session_from_ctx, require_fresh_session, require_session};
use crate::api::routes::session::GetSessionOptions;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::db::schema::{Field, OnDelete, TableExtension};
use crate::db::{FindManyQuery, Where};
use crate::error::{ApiError, ErrorCode, Result, codes};
use crate::plugin::Plugin;
use crate::types::SessionWithUser;
pub use webauthn::{VerifiedAuthentication, VerifiedRegistration};

/// Error codes (`PASSKEY_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        CHALLENGE_NOT_FOUND => "Challenge not found",
        YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY => "You are not allowed to register this passkey",
        FAILED_TO_VERIFY_REGISTRATION => "Failed to verify registration",
        PASSKEY_NOT_FOUND => "Passkey not found",
        AUTHENTICATION_FAILED => "Authentication failed",
        UNABLE_TO_CREATE_SESSION => "Unable to create session",
        USER_NOT_FOUND => "User not found",
        FAILED_TO_UPDATE_PASSKEY => "Failed to update passkey",
        PREVIOUSLY_REGISTERED => "Previously registered",
        REGISTRATION_CANCELLED => "Registration cancelled",
        AUTH_CANCELLED => "Auth cancelled",
        UNKNOWN_ERROR => "Unknown error",
        SESSION_REQUIRED => "Passkey registration requires an authenticated session",
        RESOLVE_USER_REQUIRED => "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
        RESOLVED_USER_INVALID => "Resolved user is invalid",
    }
}

use error_codes as e;

const MODEL: &str = "passkey";
/// Challenge lifetime.
const MAX_AGE_SECS: i64 = 60 * 5;

/// The user a passkey is registered for.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasskeyRegistrationUser {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none", default)]
    pub display_name: Option<String>,
}

/// Computes extension inputs for a request.
pub type ExtensionsFn =
    Arc<dyn for<'a> Fn(&'a EndpointContext) -> BoxFuture<'a, Result<Option<Map<String, Value>>>> + Send + Sync>;

/// WebAuthn client extension inputs, fixed or computed per request.
#[derive(Clone)]
pub enum ExtensionsResolver {
    Static(Map<String, Value>),
    Dynamic(ExtensionsFn),
}

/// Resolves the user to register for when there is no session (`resolveUser`); receives the
/// `context` query parameter.
pub type ResolveUserFn = Arc<
    dyn for<'a> Fn(&'a EndpointContext, Option<String>) -> BoxFuture<'a, Result<PasskeyRegistrationUser>> + Send + Sync,
>;

/// Input to [`PasskeyRegistrationOptions::after_verification`].
pub struct RegistrationVerified {
    pub verification: VerifiedRegistration,
    pub user: PasskeyRegistrationUser,
    /// The client's `RegistrationResponseJSON`.
    pub client_data: Value,
    pub context: Option<String>,
}

/// Returned from [`PasskeyRegistrationOptions::after_verification`]: attribute the passkey to
/// another user, or label it when the client gave no name.
#[derive(Debug, Clone, Default)]
pub struct AfterRegistration {
    pub user_id: Option<String>,
    pub name: Option<String>,
}

pub type AfterRegistrationFn = Arc<
    dyn for<'a> Fn(&'a EndpointContext, RegistrationVerified) -> BoxFuture<'a, Result<Option<AfterRegistration>>>
        + Send
        + Sync,
>;

pub type AfterAuthenticationFn =
    Arc<dyn for<'a> Fn(&'a EndpointContext, VerifiedAuthentication, Value) -> BoxFuture<'a, Result<()>> + Send + Sync>;

#[derive(Clone)]
pub struct PasskeyRegistrationOptions {
    /// Require a (fresh) session to register. Default `true`.
    pub require_session: bool,
    pub resolve_user: Option<ResolveUserFn>,
    pub after_verification: Option<AfterRegistrationFn>,
    pub extensions: Option<ExtensionsResolver>,
}

impl Default for PasskeyRegistrationOptions {
    fn default() -> Self {
        Self { require_session: true, resolve_user: None, after_verification: None, extensions: None }
    }
}

#[derive(Clone, Default)]
pub struct PasskeyAuthenticationOptions {
    pub extensions: Option<ExtensionsResolver>,
    pub after_verification: Option<AfterAuthenticationFn>,
}

#[derive(Clone)]
pub struct PasskeyOptions {
    /// Default: the base URL's host, else `localhost`.
    pub rp_id: Option<String>,
    /// Default: the app name.
    pub rp_name: Option<String>,
    /// Expected origins. Empty: the request's `Origin` header.
    pub origin: Vec<String>,
    /// Merged into `authenticatorSelection` (e.g. `{"residentKey": "required"}`).
    pub authenticator_selection: Map<String, Value>,
    /// Challenge cookie name (prefixed like other auth cookies).
    pub web_authn_challenge_cookie: String,
    pub registration: PasskeyRegistrationOptions,
    pub authentication: PasskeyAuthenticationOptions,
}

impl Default for PasskeyOptions {
    fn default() -> Self {
        Self {
            rp_id: None,
            rp_name: None,
            origin: vec![],
            authenticator_selection: Map::new(),
            web_authn_challenge_cookie: "better-auth-passkey".into(),
            registration: PasskeyRegistrationOptions::default(),
            authentication: PasskeyAuthenticationOptions::default(),
        }
    }
}

/// Best-effort provider names for common authenticator AAGUIDs (`commonAuthenticatorNames`).
pub const COMMON_AUTHENTICATOR_NAMES: &[(&str, &str)] = &[
    ("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", "Google Password Manager"),
    ("fbfc3007-154e-4ecc-8c0b-6e020557d7bd", "Apple Passwords"),
    ("dd4ec289-e01d-41c9-bb89-70fa845d4bf2", "iCloud Keychain (Managed)"),
    ("08987058-cadc-4b81-b6e1-30de50dcbe96", "Windows Hello"),
    ("9ddd1817-af5a-4672-a2b9-3e3dd95000a9", "Windows Hello"),
    ("6028b017-b1d4-4c02-b4b3-afcdafc96bb2", "Windows Hello"),
    ("bada5566-a7aa-401f-bd96-45619a55120d", "1Password"),
    ("d548826e-79b4-db40-a3d8-11116f7e8349", "Bitwarden"),
    ("531126d6-e717-415c-9320-3d9aa6981239", "Dashlane"),
    ("b78a0a55-6ef8-d246-a042-ba0f6d55050c", "LastPass"),
    ("b84e4048-15dc-4dd0-8640-f4f60813c8af", "NordPass"),
    ("50726f74-6f6e-5061-7373-50726f746f6e", "Proton Pass"),
    ("0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6", "Keeper"),
    ("53414d53-554e-4700-0000-000000000000", "Samsung Pass"),
];

/// A display name for an authenticator AAGUID (`getAuthenticatorName`); `None` for unknown or
/// all-zero (anonymous) AAGUIDs.
pub fn authenticator_name(aaguid: &str) -> Option<&'static str> {
    let normalized = aaguid.trim().to_lowercase();
    COMMON_AUTHENTICATOR_NAMES.iter().find(|(id, _)| *id == normalized).map(|(_, name)| *name)
}

/// The challenge stored between generating options and verifying (`StoredChallengeValue`).
#[derive(Serialize, Deserialize)]
struct StoredChallenge {
    #[serde(rename = "type", default)]
    ceremony: Option<String>,
    #[serde(rename = "expectedChallenge")]
    expected_challenge: String,
    #[serde(rename = "userData")]
    user_data: StoredUser,
    /// `Some(None)` serializes as `null` (registration); `None` omits it (authentication).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<Option<String>>,
}

#[derive(Serialize, Deserialize, Default)]
struct StoredUser {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none", default)]
    display_name: Option<String>,
}

struct Inner {
    options: PasskeyOptions,
}

impl Inner {
    /// `getRpID`.
    fn rp_id(&self, ctx: &EndpointContext) -> String {
        if let Some(id) = self.options.rp_id.as_deref().filter(|s| !s.is_empty()) {
            return id.to_owned();
        }
        ctx.auth
            .base_url
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "localhost".into())
    }

    fn expected_origins(&self, ctx: &EndpointContext) -> Vec<String> {
        if !self.options.origin.is_empty() {
            return self.options.origin.clone();
        }
        ctx.header("origin").filter(|o| !o.is_empty()).into_iter().collect()
    }

    fn challenge_cookie(&self, ctx: &EndpointContext, max_age: Option<i64>) -> crate::cookies::AuthCookie {
        ctx.auth.cookie_factory.create(&self.options.web_authn_challenge_cookie, max_age)
    }

    /// Store a challenge and point the signed cookie at it.
    async fn store_challenge(&self, ctx: &EndpointContext, challenge: &StoredChallenge) -> Result<()> {
        let token = crate::crypto::generate_random_string(32);
        let cookie = self.challenge_cookie(ctx, Some(MAX_AGE_SECS));
        ctx.set_signed_cookie(&cookie.name, &token, &ctx.auth.secret, &cookie.attributes);
        let value = serde_json::to_string(challenge).expect("serializable");
        ctx.auth
            .internal_adapter
            .create_verification_value(&token, &value, Utc::now() + Duration::seconds(MAX_AGE_SECS))
            .await?;
        Ok(())
    }

    /// Consume the challenge the cookie points at, minted by `ceremony`.
    async fn take_challenge(
        &self,
        ctx: &EndpointContext,
        ceremony: &str,
    ) -> std::result::Result<StoredChallenge, ApiError> {
        let cookie = self.challenge_cookie(ctx, None);
        let not_found = || ApiError::bad_request(e::CHALLENGE_NOT_FOUND);
        let token = ctx.get_signed_cookie(&cookie.name, &ctx.auth.secret).ok_or_else(not_found)?;
        let row = ctx.auth.internal_adapter.consume_verification_value(&token).await?.ok_or_else(not_found)?;
        let stored: StoredChallenge = serde_json::from_str(&row.value).map_err(|_| not_found())?;
        // Both ceremonies share the cookie and the row, so a challenge from one must not
        // complete the other.
        if stored.ceremony.as_deref() != Some(ceremony) {
            return Err(not_found());
        }
        Ok(stored)
    }
}

async fn resolve_extensions(
    resolver: Option<&ExtensionsResolver>,
    ctx: &EndpointContext,
) -> Result<Option<Map<String, Value>>> {
    match resolver {
        None => Ok(None),
        Some(ExtensionsResolver::Static(m)) => Ok(Some(m.clone())),
        Some(ExtensionsResolver::Dynamic(f)) => f(ctx).await,
    }
}

fn session_user(s: &SessionWithUser) -> PasskeyRegistrationUser {
    let name = if s.user.email.is_empty() { s.user.id.clone() } else { s.user.email.clone() };
    PasskeyRegistrationUser { id: s.user.id.clone(), name: name.clone(), display_name: Some(name) }
}

/// `resolveRegistrationUser`.
async fn registration_user(
    inner: &Inner,
    ctx: &EndpointContext,
) -> std::result::Result<PasskeyRegistrationUser, ApiError> {
    let reg = &inner.options.registration;
    if reg.require_session {
        let session = ctx.session().ok_or_else(|| ApiError::unauthorized(e::SESSION_REQUIRED))?;
        return Ok(session_user(&session));
    }
    if let Some(session) = get_session_from_ctx(ctx, GetSessionOptions::default()).await? {
        return Ok(session_user(&session));
    }
    let resolve = reg.resolve_user.as_ref().ok_or_else(|| ApiError::bad_request(e::RESOLVE_USER_REQUIRED))?;
    let user = resolve(ctx, ctx.query_str("context")).await?;
    if user.id.is_empty() || user.name.is_empty() {
        return Err(ApiError::bad_request(e::RESOLVED_USER_INVALID));
    }
    Ok(user)
}

async fn user_passkeys(ctx: &EndpointContext, user_id: &str) -> Result<Vec<Map<String, Value>>> {
    ctx.auth
        .db
        .find_many(MODEL, FindManyQuery { where_: vec![Where::eq("userId", user_id)], ..Default::default() })
        .await
}

/// `{ id, transports?, type }` descriptors for allow/exclude lists.
fn credential_descriptors(passkeys: &[Map<String, Value>]) -> Vec<Value> {
    passkeys
        .iter()
        .map(|p| {
            let mut d = Map::new();
            d.insert("id".into(), p.get("credentialID").cloned().unwrap_or(Value::Null));
            if let Some(t) = p.get("transports").and_then(Value::as_str) {
                d.insert("transports".into(), t.split(',').collect::<Vec<_>>().into());
            }
            d.insert("type".into(), "public-key".into());
            Value::Object(d)
        })
        .collect()
}

fn random_challenge() -> String {
    webauthn::b64url(&crate::crypto::random_bytes::<32>())
}

/// `GET /passkey/generate-register-options`
async fn generate_register_options(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    if inner.options.registration.require_session {
        require_fresh_session(&ctx).await?;
    }
    let attachment = ctx.query_str("authenticatorAttachment");
    if let Some(a) = &attachment
        && a != "platform"
        && a != "cross-platform"
    {
        return Err(ApiError::bad_request(codes::VALIDATION_ERROR).with_field(
            "message",
            "[query.authenticatorAttachment] Invalid option: expected one of \"platform\"|\"cross-platform\"",
        ));
    }
    let user = registration_user(&inner, &ctx).await?;
    let passkeys = user_passkeys(&ctx, &user.id).await?;
    let extensions = resolve_extensions(inner.options.registration.extensions.as_ref(), &ctx).await?;
    let user_id = crate::crypto::random_string(32, b"abcdefghijklmnopqrstuvwxyz0123456789");
    let challenge = random_challenge();

    let mut selection = Map::new();
    selection.insert("residentKey".into(), "preferred".into());
    selection.insert("userVerification".into(), "preferred".into());
    selection.extend(inner.options.authenticator_selection.clone());
    if let Some(a) = attachment {
        selection.insert("authenticatorAttachment".into(), a.into());
    }
    match selection.get("residentKey").and_then(Value::as_str) {
        Some(rk) => {
            let required = rk == "required";
            selection.insert("requireResidentKey".into(), required.into());
        }
        None if selection.get("requireResidentKey") == Some(&Value::Bool(true)) => {
            selection.insert("residentKey".into(), "required".into());
        }
        None => {}
    }
    let mut extensions = extensions.unwrap_or_default();
    extensions.insert("credProps".into(), true.into());
    let query_name = ctx.query_str("name").filter(|n| !n.is_empty());
    let options = json!({
        "challenge": challenge,
        "rp": {
            "name": inner.options.rp_name.clone().unwrap_or_else(|| ctx.auth.options.app_name.clone()),
            "id": inner.rp_id(&ctx),
        },
        "user": {
            "id": webauthn::b64url(user_id.as_bytes()),
            "name": query_name.unwrap_or_else(|| if user.name.is_empty() { user.id.clone() } else { user.name.clone() }),
            "displayName": user.display_name.clone().filter(|d| !d.is_empty())
                .unwrap_or_else(|| if user.name.is_empty() { user.id.clone() } else { user.name.clone() }),
        },
        "pubKeyCredParams": webauthn::DEFAULT_ALGORITHMS.iter().map(|alg| json!({ "alg": alg, "type": "public-key" })).collect::<Vec<_>>(),
        "timeout": 60000,
        "attestation": "none",
        "excludeCredentials": credential_descriptors(&passkeys),
        "authenticatorSelection": selection,
        "extensions": extensions,
        "hints": [],
    });
    inner
        .store_challenge(
            &ctx,
            &StoredChallenge {
                ceremony: Some("registration".into()),
                expected_challenge: challenge,
                user_data: StoredUser { id: user.id, name: Some(user.name), display_name: user.display_name },
                context: Some(ctx.query_str("context")),
            },
        )
        .await?;
    ctx.json(options)
}

/// `GET /passkey/generate-authenticate-options`
async fn generate_authenticate_options(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = get_session_from_ctx(&ctx, GetSessionOptions::default()).await?;
    let passkeys = match &session {
        Some(s) => user_passkeys(&ctx, &s.user.id).await?,
        None => vec![],
    };
    let extensions = resolve_extensions(inner.options.authentication.extensions.as_ref(), &ctx).await?;
    let challenge = random_challenge();
    let mut options = Map::new();
    options.insert("rpId".into(), inner.rp_id(&ctx).into());
    options.insert("challenge".into(), challenge.clone().into());
    if !passkeys.is_empty() {
        options.insert("allowCredentials".into(), credential_descriptors(&passkeys).into());
    }
    options.insert("timeout".into(), 60000.into());
    options.insert("userVerification".into(), "preferred".into());
    if let Some(ext) = extensions {
        options.insert("extensions".into(), ext.into());
    }
    inner
        .store_challenge(
            &ctx,
            &StoredChallenge {
                ceremony: Some("authentication".into()),
                expected_challenge: challenge,
                user_data: StoredUser { id: session.map(|s| s.user.id).unwrap_or_default(), ..Default::default() },
                context: None,
            },
        )
        .await?;
    ctx.json(Value::Object(options))
}

#[derive(Deserialize)]
struct VerifyRegistrationBody {
    response: Value,
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "createSession", default)]
    create_session: Option<bool>,
}

/// `POST /passkey/verify-registration`
async fn verify_registration(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let require = inner.options.registration.require_session;
    if require {
        require_fresh_session(&ctx).await?;
    }
    let body: VerifyRegistrationBody = ctx.parse_body()?;
    let origins = inner.expected_origins(&ctx);
    if origins.is_empty() {
        return Err(ApiError::bad_request(e::FAILED_TO_VERIFY_REGISTRATION));
    }
    let stored = inner.take_challenge(&ctx, "registration").await?;
    let session =
        if require { ctx.session() } else { get_session_from_ctx(&ctx, GetSessionOptions::default()).await? };
    let not_allowed = || ApiError::unauthorized(e::YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY);
    if let Some(s) = &session
        && stored.user_data.id != s.user.id
    {
        return Err(not_allowed());
    }

    let verification =
        webauthn::verify_registration(&body.response, &stored.expected_challenge, &origins, &inner.rp_id(&ctx), false)
            .map_err(|err| {
                tracing::error!(error = err, "Failed to verify registration");
                ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_VERIFY_REGISTRATION)
            })?;

    let user = PasskeyRegistrationUser {
        id: stored.user_data.id.clone(),
        name: stored.user_data.name.clone().filter(|n| !n.is_empty()).unwrap_or_else(|| stored.user_data.id.clone()),
        display_name: stored.user_data.display_name.clone(),
    };
    let create_session = body.create_session == Some(true);
    let persist = async {
        let mut target_user_id = user.id.clone();
        let mut name = body.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).map(str::to_owned);
        if let Some(after) = &inner.options.registration.after_verification {
            let result = after(
                &ctx,
                RegistrationVerified {
                    verification: verification.clone(),
                    user: user.clone(),
                    client_data: body.response.clone(),
                    context: stored.context.clone().flatten(),
                },
            )
            .await?;
            if let Some(result) = result {
                if let Some(id) = result.user_id.filter(|id| !id.is_empty()) {
                    if session.as_ref().is_some_and(|s| s.user.id != id) {
                        return Err(not_allowed());
                    }
                    target_user_id = id;
                }
                if name.is_none() {
                    name = result.name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
                }
            }
        }
        if target_user_id.is_empty() {
            return Err(ApiError::bad_request(e::RESOLVED_USER_INVALID));
        }
        let account_user = if create_session {
            Some(
                ctx.auth
                    .internal_adapter
                    .find_user_by_id(&target_user_id)
                    .await?
                    .ok_or_else(|| ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::USER_NOT_FOUND))?,
            )
        } else {
            None
        };
        let transports = verification.transports.as_ref().map(|t| t.join(",")).unwrap_or_default();
        let mut data = Map::new();
        if let Some(n) = name {
            data.insert("name".into(), n.into());
        }
        data.insert("userId".into(), target_user_id.clone().into());
        data.insert("credentialID".into(), verification.credential_id.clone().into());
        data.insert("publicKey".into(), webauthn::b64(&verification.public_key).into());
        data.insert("counter".into(), verification.counter.into());
        data.insert("deviceType".into(), verification.device_type.clone().into());
        data.insert("transports".into(), transports.into());
        data.insert("backedUp".into(), verification.backed_up.into());
        data.insert("createdAt".into(), crate::utils::date::now_value());
        data.insert("aaguid".into(), verification.aaguid.clone().into());
        let passkey = ctx.auth.db.create(MODEL, data, false).await?;
        let Some(user) = account_user else { return Ok((passkey, None)) };
        let session = ctx.auth.internal_adapter.create_session(&target_user_id, false, None).await?;
        Ok((passkey, Some(SessionWithUser { session, user })))
    };
    let (passkey, created) =
        if create_session { ctx.auth.transaction::<_, ApiError>(persist).await? } else { persist.await? };
    let mut out = passkey;
    if let Some(s) = created {
        set_session_cookie(&ctx, &s, None, None).await;
        out.insert("session".into(), Value::Object(ctx.auth.session_output(&s.session)));
        out.insert("user".into(), Value::Object(ctx.auth.user_output(&s.user)));
    }
    ctx.json(Value::Object(out))
}

#[derive(Deserialize)]
struct VerifyAuthenticationBody {
    response: Map<String, Value>,
}

/// `POST /passkey/verify-authentication`
async fn verify_authentication(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: VerifyAuthenticationBody = ctx.parse_body()?;
    let origins = inner.expected_origins(&ctx);
    if origins.is_empty() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "origin missing"));
    }
    let stored = inner.take_challenge(&ctx, "authentication").await?;
    let credential_id = body.response.get("id").and_then(Value::as_str).unwrap_or_default();
    let passkey = ctx
        .auth
        .db
        .find_one(MODEL, &[Where::eq("credentialID", credential_id)])
        .await?
        .ok_or_else(|| ApiError::unauthorized(e::PASSKEY_NOT_FOUND))?;
    let failed = || ApiError::bad_request(e::AUTHENTICATION_FAILED);
    let public_key = webauthn::from_b64(passkey.get("publicKey").and_then(Value::as_str).unwrap_or_default())
        .map_err(|_| failed())?;
    let counter = passkey.get("counter").and_then(Value::as_u64).unwrap_or(0) as u32;
    let response = Value::Object(body.response);
    let verification = webauthn::verify_authentication(
        &response,
        &stored.expected_challenge,
        &origins,
        &inner.rp_id(&ctx),
        &public_key,
        counter,
        false,
    )
    .map_err(|err| {
        tracing::error!(error = err, "Failed to verify authentication");
        failed()
    })?;
    if !verification.verified {
        return Err(ApiError::unauthorized(e::AUTHENTICATION_FAILED));
    }
    if let Some(after) = &inner.options.authentication.after_verification {
        after(&ctx, verification.clone(), response).await?;
    }
    let id = passkey.get("id").and_then(Value::as_str).unwrap_or_default();
    let mut update = Map::new();
    update.insert("counter".into(), verification.new_counter.into());
    ctx.auth.db.update(MODEL, &[Where::eq("id", id)], update).await?;
    let user_id = passkey.get("userId").and_then(Value::as_str).unwrap_or_default();
    let session = ctx.auth.internal_adapter.create_session(user_id, false, None).await?;
    let user = ctx
        .auth
        .internal_adapter
        .find_user_by_id(user_id)
        .await?
        .ok_or_else(|| ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, "User not found"))?;
    let s = SessionWithUser { session, user };
    set_session_cookie(&ctx, &s, None, None).await;
    ctx.json(json!({
        "session": ctx.auth.session_output(&s.session),
        "user": ctx.auth.user_output(&s.user),
    }))
}

/// `GET /passkey/list-user-passkeys`
async fn list_passkeys(ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    ctx.json(user_passkeys(&ctx, &session.user.id).await?.into())
}

/// `requireResourceOwnership`: the passkey `id` must belong to the session user.
async fn owned_passkey(
    ctx: &EndpointContext,
    id: &str,
    forbidden: Option<ErrorCode>,
) -> std::result::Result<Map<String, Value>, ApiError> {
    let session = require_session(ctx).await?;
    let passkey = ctx
        .auth
        .db
        .find_one(MODEL, &[Where::eq("id", id)])
        .await?
        .ok_or_else(|| ApiError::not_found(e::PASSKEY_NOT_FOUND))?;
    if passkey.get("userId").and_then(Value::as_str) != Some(session.user.id.as_str()) {
        return Err(match forbidden {
            Some(code) => ApiError::unauthorized(code),
            None => ApiError::status(StatusCode::UNAUTHORIZED),
        });
    }
    Ok(passkey)
}

#[derive(Deserialize)]
struct IdBody {
    id: String,
}

/// `POST /passkey/delete-passkey`
async fn delete_passkey(ctx: Ctx) -> EndpointResult {
    require_session(&ctx).await?;
    let body: IdBody = ctx.parse_body()?;
    owned_passkey(&ctx, &body.id, None).await?;
    ctx.auth.db.delete(MODEL, &[Where::eq("id", body.id.as_str())]).await?;
    ctx.json(json!({ "status": true }))
}

#[derive(Deserialize)]
struct UpdateBody {
    id: String,
    name: String,
}

/// `POST /passkey/update-passkey`
async fn update_passkey(ctx: Ctx) -> EndpointResult {
    require_session(&ctx).await?;
    let body: UpdateBody = ctx.parse_body()?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request(codes::VALIDATION_ERROR)
            .with_field("message", "[body.name] Too small: expected string to have >=1 characters"));
    }
    owned_passkey(&ctx, &body.id, Some(e::YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY)).await?;
    let mut update = Map::new();
    update.insert("name".into(), name.into());
    let updated = ctx
        .auth
        .db
        .update(MODEL, &[Where::eq("id", body.id.as_str())], update)
        .await?
        .ok_or_else(|| ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_UPDATE_PASSKEY))?;
    ctx.json(json!({ "passkey": updated }))
}

pub struct Passkey {
    inner: Arc<Inner>,
}

pub fn passkey(options: PasskeyOptions) -> Arc<dyn Plugin> {
    Arc::new(Passkey { inner: Arc::new(Inner { options }) })
}

impl Plugin for Passkey {
    fn id(&self) -> &str {
        "passkey"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![TableExtension {
            key: MODEL.into(),
            fields: vec![
                ("name".into(), Field::string().optional()),
                ("publicKey".into(), Field::string()),
                ("userId".into(), Field::string().references("user", "id", OnDelete::Cascade).indexed()),
                ("credentialID".into(), Field::string().indexed()),
                ("counter".into(), Field::number().bigint()),
                ("deviceType".into(), Field::string()),
                ("backedUp".into(), Field::boolean()),
                ("transports".into(), Field::string().optional()),
                ("createdAt".into(), Field::date().optional()),
                ("aaguid".into(), Field::string().optional()),
            ],
            ..Default::default()
        }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b, c, d) = (self.inner.clone(), self.inner.clone(), self.inner.clone(), self.inner.clone());
        vec![
            Endpoint::get(
                "generatePasskeyRegistrationOptions",
                "/passkey/generate-register-options",
                handler(move |ctx| generate_register_options(a.clone(), ctx)),
            ),
            Endpoint::get(
                "generatePasskeyAuthenticationOptions",
                "/passkey/generate-authenticate-options",
                handler(move |ctx| generate_authenticate_options(b.clone(), ctx)),
            ),
            Endpoint::post(
                "verifyPasskeyRegistration",
                "/passkey/verify-registration",
                handler(move |ctx| verify_registration(c.clone(), ctx)),
            ),
            Endpoint::post(
                "verifyPasskeyAuthentication",
                "/passkey/verify-authentication",
                handler(move |ctx| verify_authentication(d.clone(), ctx)),
            ),
            Endpoint::get("listPasskeys", "/passkey/list-user-passkeys", handler(list_passkeys)),
            Endpoint::post("deletePasskey", "/passkey/delete-passkey", handler(delete_passkey)),
            Endpoint::post("updatePasskey", "/passkey/update-passkey", handler(update_passkey)),
        ]
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
    use super::*;

    #[test]
    fn authenticator_names() {
        assert_eq!(authenticator_name(" EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4 "), Some("Google Password Manager"));
        assert_eq!(authenticator_name("00000000-0000-0000-0000-000000000000"), None);
        assert_eq!(authenticator_name(""), None);
    }
}
