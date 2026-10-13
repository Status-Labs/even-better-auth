//! Last login method (`plugins/last-login-method`): remembers how the user last signed in
//! (email, a social provider id, magic-link, ...) in a readable cookie and, optionally, on
//! the user row, so the UI can highlight it.

use std::any::Any;
use std::sync::Arc;

use futures::future::BoxFuture;
use serde_json::{Map, Value};

use crate::api::{EndpointContext, current_request, hook};
use crate::cookies::CookieOptions;
use crate::db::hooks::{BeforeOutcome, DatabaseHooks, Operation};
use crate::db::{Field, Record, TableExtension};
use crate::error::Result;
use crate::plugin::{MatchedHook, Plugin, PluginHooks};

pub type ResolveFn = Arc<dyn Fn(&EndpointContext) -> Option<String> + Send + Sync>;
pub type BeforeStoreCookieFn =
    Arc<dyn Fn(Arc<EndpointContext>, String) -> BoxFuture<'static, Result<bool>> + Send + Sync>;

#[derive(Clone)]
pub struct LastLoginMethodOptions {
    /// Default `better-auth.last_used_login_method`.
    pub cookie_name: String,
    /// Seconds. Default 30 days.
    pub max_age: i64,
    /// Runs before the built-in resolution; `None` falls back to it.
    pub custom_resolve_method: Option<ResolveFn>,
    /// Also store the method in `user.lastLoginMethod`.
    pub store_in_database: bool,
    /// Return `false` (or fail) to skip setting the cookie, e.g. without consent.
    pub before_store_cookie: Option<BeforeStoreCookieFn>,
    /// Column name for `lastLoginMethod`.
    pub field_name: Option<String>,
}

impl Default for LastLoginMethodOptions {
    fn default() -> Self {
        Self {
            cookie_name: "better-auth.last_used_login_method".into(),
            max_age: 60 * 60 * 24 * 30,
            custom_resolve_method: None,
            store_in_database: false,
            before_store_cookie: None,
            field_name: None,
        }
    }
}

const FIELD: &str = "lastLoginMethod";

/// The built-in method names, from the endpoint path.
pub fn default_resolve_method(ctx: &EndpointContext) -> Option<String> {
    let path = ctx.path.as_str();
    if path.is_empty() {
        return None;
    }
    if path.starts_with("/callback/") {
        return ctx.param("id").map(str::to_owned).or_else(|| path.rsplit('/').next().map(str::to_owned));
    }
    let method = match path {
        "/sign-in/email" | "/sign-up/email" => "email",
        p if p.contains("siwe") => "siwe",
        p if p.contains("/passkey/verify-authentication") => "passkey",
        p if p.starts_with("/magic-link/verify") => "magic-link",
        "/sign-in/email-otp" => "email-otp",
        _ => return None,
    };
    Some(method.into())
}

struct Inner {
    options: LastLoginMethodOptions,
}

impl Inner {
    fn resolve(&self, ctx: &EndpointContext) -> Option<String> {
        self.options.custom_resolve_method.as_ref().and_then(|f| f(ctx)).or_else(|| default_resolve_method(ctx))
    }

    async fn after(&self, ctx: Arc<EndpointContext>) {
        let Some(method) = self.resolve(&ctx) else { return };
        let session_cookie = &ctx.auth.cookies.session_token;
        if ctx.response_cookie(&session_cookie.name).is_none() {
            return;
        }
        if let Some(before) = &self.options.before_store_cookie {
            match before(ctx.clone(), method.clone()).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(err) => {
                    tracing::error!(error = %err, "[LastLoginMethod] Error in beforeStoreCookie hook");
                    return;
                }
            }
        }
        let attributes = CookieOptions {
            max_age: Some(self.options.max_age),
            http_only: false,
            ..session_cookie.attributes.clone()
        };
        ctx.set_cookie(&self.options.cookie_name, &method, &attributes);
    }
}

pub struct LastLoginMethod {
    inner: Arc<Inner>,
}

pub fn last_login_method(options: LastLoginMethodOptions) -> Arc<dyn Plugin> {
    Arc::new(LastLoginMethod { inner: Arc::new(Inner { options }) })
}

impl Plugin for LastLoginMethod {
    fn id(&self) -> &str {
        "last-login-method"
    }

    fn schema(&self) -> Vec<TableExtension> {
        if !self.inner.options.store_in_database {
            return vec![];
        }
        let field_name = self.inner.options.field_name.clone().unwrap_or_else(|| FIELD.into());
        vec![TableExtension {
            key: "user".into(),
            fields: vec![(FIELD.into(), Field::string().optional().no_input().field_name(field_name))],
            ..Default::default()
        }]
    }

    fn hooks(&self) -> PluginHooks {
        let inner = self.inner.clone();
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |_| true,
                hook(move |ctx| {
                    let inner = inner.clone();
                    async move {
                        inner.after(ctx).await;
                        Ok(None)
                    }
                }),
            )],
        }
    }

    fn database_hooks(&self) -> DatabaseHooks {
        if !self.inner.options.store_in_database {
            return DatabaseHooks::default();
        }
        let (create, session) = (self.inner.clone(), self.inner.clone());
        DatabaseHooks::new()
            .before("user", Operation::Create, move |_user| {
                let inner = create.clone();
                async move {
                    let method = current_request().and_then(|ctx| inner.resolve(&ctx));
                    Ok(match method {
                        Some(method) => {
                            let mut data = Map::new();
                            data.insert(FIELD.into(), method.into());
                            BeforeOutcome::Merge(data)
                        }
                        None => BeforeOutcome::Continue,
                    })
                }
            })
            .after("session", Operation::Create, move |row| {
                let inner = session.clone();
                async move {
                    let Some(ctx) = current_request() else { return Ok(()) };
                    let Some(method) = inner.resolve(&ctx) else { return Ok(()) };
                    let Some(user_id) = row.get("userId").and_then(Value::as_str) else { return Ok(()) };
                    let mut update = Record::new();
                    update.insert(FIELD.into(), method.into());
                    if let Err(err) = ctx.auth.internal_adapter.update_user(user_id, update).await {
                        tracing::error!(error = %err, "Failed to update lastLoginMethod");
                    }
                    Ok(())
                }
            })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
