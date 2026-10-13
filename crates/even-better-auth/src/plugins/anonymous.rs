//! Anonymous users (`plugins/anonymous`): `POST /sign-in/anonymous` creates a throwaway
//! user; when that user later signs in or up for real, `on_link_account` runs and the
//! anonymous user is deleted. `POST /delete-anonymous-user` removes it on demand.

use std::any::Any;
use std::sync::Arc;

use http::StatusCode;
use serde_json::{Value, json};

use crate::api::middleware::{get_session_from_ctx, require_sensitive_session};
use crate::api::routes::session::GetSessionOptions;
use crate::api::routes::util::is_valid_email;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler, hook};
use crate::cookies::{delete_session_cookie, set_session_cookie};
use crate::db::{Field, Record, TableExtension};
use crate::error::{ApiError, ErrorCode};
#[cfg(feature = "oauth")]
use crate::oauth2::state::{add_oauth_server_context, get_oauth_state};
use crate::options::Callback;
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::types::SessionWithUser;
use crate::utils::validate_user_info::UserSource;

/// Error codes (`ANONYMOUS_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        INVALID_EMAIL_FORMAT => "Email was not generated in a valid format",
        FAILED_TO_CREATE_USER => "Failed to create user",
        COULD_NOT_CREATE_SESSION => "Could not create session",
        ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY => "Anonymous users cannot sign in again anonymously",
        FAILED_TO_DELETE_ANONYMOUS_USER => "Failed to delete anonymous user",
        FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS => "Failed to delete anonymous user sessions",
        USER_IS_NOT_ANONYMOUS => "User is not anonymous",
        DELETE_ANONYMOUS_USER_DISABLED => "Deleting anonymous users is disabled",
    }
}

use error_codes as e;

/// Arguments for [`AnonymousOptions::on_link_account`].
#[derive(Debug, Clone)]
pub struct AnonymousLink {
    pub anonymous_user: SessionWithUser,
    pub new_user: SessionWithUser,
}

pub type StringFn = Arc<dyn Fn() -> String + Send + Sync>;

#[derive(Clone, Default)]
pub struct AnonymousOptions {
    /// Generated emails become `temp-{id}@{domain}` instead of `{id}@anonymous.placeholder.invalid`.
    pub email_domain_name: Option<String>,
    /// Runs when an anonymous user signs in with a real account (e.g. to move their data).
    pub on_link_account: Option<Callback<AnonymousLink>>,
    /// Keep anonymous users after they link a real account, and disable deleting them.
    pub disable_delete_anonymous_user: bool,
    /// Default `"Anonymous"`.
    pub generate_name: Option<StringFn>,
    pub generate_random_email: Option<StringFn>,
}

struct Inner {
    options: AnonymousOptions,
}

fn is_anonymous(user: &crate::types::User) -> bool {
    user.extra.get("isAnonymous").and_then(Value::as_bool).unwrap_or(false)
}

/// A non-routable address for an account without an email (`createPlaceholderEmail`).
pub fn placeholder_email(identifier: &str, namespace: &str) -> String {
    format!("{identifier}@{namespace}.placeholder.invalid")
}

fn no_refresh() -> GetSessionOptions {
    GetSessionOptions { disable_refresh: true, ..Default::default() }
}

async fn sign_in_anonymous(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    if get_session_from_ctx(&ctx, no_refresh()).await?.is_some_and(|s| is_anonymous(&s.user)) {
        return Err(ApiError::bad_request(e::ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY));
    }
    let opts = &inner.options;
    let email = match &opts.generate_random_email {
        Some(f) => {
            let email = f();
            if !is_valid_email(&email) {
                return Err(ApiError::bad_request(e::INVALID_EMAIL_FORMAT));
            }
            email
        }
        None => {
            let id = crate::crypto::generate_id(None);
            match &opts.email_domain_name {
                Some(domain) => format!("temp-{id}@{domain}"),
                None => placeholder_email(&id, "anonymous"),
            }
        }
    };
    let name = opts.generate_name.as_ref().map(|f| f()).filter(|n| !n.is_empty()).unwrap_or_else(|| "Anonymous".into());
    let auth = ctx.auth.clone();
    let mut data = Record::new();
    data.insert("email".into(), email.into());
    data.insert("emailVerified".into(), false.into());
    data.insert("isAnonymous".into(), true.into());
    data.insert("name".into(), name.into());
    let user =
        auth.internal_adapter.create_user(data, &UserSource::method("anonymous")).await.map_err(|err| {
            err.api_or(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_CREATE_USER))
        })?;
    let session = auth
        .internal_adapter
        .create_session(&user.id, false, None)
        .await
        .map_err(|err| err.api_or(ApiError::bad_request(e::COULD_NOT_CREATE_SESSION)))?;
    let token = session.token.clone();
    set_session_cookie(&ctx, &SessionWithUser { session, user: user.clone() }, None, None).await;
    ctx.json(json!({ "token": token, "user": auth.user_output(&user) }))
}

async fn delete_anonymous_user(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_sensitive_session(&ctx).await?;
    if inner.options.disable_delete_anonymous_user {
        return Err(ApiError::bad_request(e::DELETE_ANONYMOUS_USER_DISABLED));
    }
    if !is_anonymous(&session.user) {
        return Err(ApiError::forbidden(e::USER_IS_NOT_ANONYMOUS));
    }
    let ia = &ctx.auth.internal_adapter;
    ia.delete_user_sessions(&session.user.id).await.map_err(|err| {
        tracing::error!(error = %err, "Failed to delete anonymous user sessions");
        ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS)
    })?;
    ia.delete_user(&session.user.id).await.map_err(|err| {
        tracing::error!(error = %err, "Failed to delete anonymous user");
        ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, e::FAILED_TO_DELETE_ANONYMOUS_USER)
    })?;
    delete_session_cookie(&ctx, false);
    ctx.json(json!({ "success": true }))
}

/// The anonymous user behind this request: from the session cookie, or carried through an
/// OAuth redirect in the state's server context.
async fn resolve_anonymous(ctx: &EndpointContext) -> Result<Option<SessionWithUser>, ApiError> {
    if let Some(s) = get_session_from_ctx(ctx, no_refresh()).await?
        && is_anonymous(&s.user)
    {
        return Ok(Some(s));
    }
    #[cfg(feature = "oauth")]
    let id = get_oauth_state(ctx)
        .and_then(|s| s.server_context)
        .and_then(|c| c.get("anonymousUserId").and_then(Value::as_str).map(str::to_owned));
    #[cfg(not(feature = "oauth"))]
    let id: Option<String> = None;
    let Some(id) = id else { return Ok(None) };
    let ia = &ctx.auth.internal_adapter;
    let Some(user) = ia.find_user_by_id(&id).await?.filter(is_anonymous) else { return Ok(None) };
    let now = chrono::Utc::now();
    let session = ia.list_sessions(&user.id).await?.into_iter().find(|s| s.expires_at > now);
    Ok(session.map(|session| SessionWithUser { session, user }))
}

/// Remember the anonymous user across a social sign-in redirect.
async fn before_social(ctx: &EndpointContext) -> Result<(), ApiError> {
    if let Some(s) = get_session_from_ctx(ctx, no_refresh()).await?
        && is_anonymous(&s.user)
    {
        #[cfg(feature = "oauth")]
        {
            let mut values = serde_json::Map::new();
            values.insert("anonymousUserId".into(), s.user.id.into());
            add_oauth_server_context(ctx, values);
        }
    }
    Ok(())
}

/// After a real sign-in, hand over to `on_link_account` and delete the anonymous user.
async fn after_sign_in(inner: Arc<Inner>, ctx: &EndpointContext) -> Result<(), ApiError> {
    let cookie = ctx.response_cookie(&ctx.auth.cookies.session_token.name);
    let has_new_cookie = cookie.is_some_and(|c| {
        let value = c.split(';').next().and_then(|p| p.split_once('=')).map(|(_, v)| v).unwrap_or_default();
        !value.is_empty() && !c.to_ascii_lowercase().contains("max-age=0")
    });
    if !has_new_cookie {
        return Ok(());
    }
    let Some(anonymous) = resolve_anonymous(ctx).await? else { return Ok(()) };
    let new_session = ctx.new_session();
    if ctx.path == "/sign-in/anonymous" && new_session.is_none() {
        return Err(ApiError::bad_request(e::ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY));
    }
    let Some(new_session) = new_session else { return Ok(()) };
    if let Some(cb) = &inner.options.on_link_account {
        cb.call(AnonymousLink { anonymous_user: anonymous.clone(), new_user: new_session.clone() }).await?;
    }
    let same_user = new_session.user.id == anonymous.user.id;
    if inner.options.disable_delete_anonymous_user || same_user || is_anonymous(&new_session.user) {
        return Ok(());
    }
    if let Err(err) = ctx.auth.internal_adapter.delete_user(&anonymous.user.id).await {
        tracing::error!(anonymous_user_id = %anonymous.user.id, error = %err, "Failed to clean up anonymous user during post-link cleanup");
    }
    Ok(())
}

const LINK_PATHS: &[&str] = &[
    "/sign-in",
    "/sign-up",
    "/callback",
    "/magic-link/verify",
    "/email-otp/verify-email",
    "/one-tap/callback",
    "/passkey/verify-authentication",
    "/phone-number/verify",
    "/verify-email",
];

pub struct Anonymous {
    inner: Arc<Inner>,
}

pub fn anonymous(options: AnonymousOptions) -> Arc<dyn Plugin> {
    Arc::new(Anonymous { inner: Arc::new(Inner { options }) })
}

impl Plugin for Anonymous {
    fn id(&self) -> &str {
        "anonymous"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![TableExtension {
            key: "user".into(),
            fields: vec![("isAnonymous".into(), Field::boolean().optional().no_input().default(false))],
            ..Default::default()
        }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b) = (self.inner.clone(), self.inner.clone());
        vec![
            Endpoint::post(
                "signInAnonymous",
                "/sign-in/anonymous",
                handler(move |ctx| sign_in_anonymous(a.clone(), ctx)),
            ),
            Endpoint::post(
                "deleteAnonymousUser",
                "/delete-anonymous-user",
                handler(move |ctx| delete_anonymous_user(b.clone(), ctx)),
            ),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        let inner = self.inner.clone();
        PluginHooks {
            before: vec![MatchedHook::new(
                |ctx| ctx.path == "/sign-in/social",
                hook(|ctx| async move {
                    before_social(&ctx).await?;
                    Ok(None)
                }),
            )],
            after: vec![MatchedHook::new(
                |ctx| LINK_PATHS.iter().any(|p| ctx.path.starts_with(p)),
                hook(move |ctx| {
                    let inner = inner.clone();
                    async move {
                        after_sign_in(inner, &ctx).await?;
                        Ok(None)
                    }
                }),
            )],
        }
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
