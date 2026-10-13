//! Custom session shape (`plugins/custom-session`): replaces `/get-session` so its response is
//! whatever your function builds from the session (e.g. adding roles), and optionally does
//! the same for each entry of `/multi-session/list-device-sessions`.

use std::any::Any;
use std::sync::Arc;

use futures::future::BoxFuture;
use http::Method;
use serde_json::Value;

use crate::api::routes::session::get_session as core_get_session;
use crate::api::{Ctx, Endpoint, EndpointOutput, EndpointResult, handler, hook};
use crate::error::{ApiError, Result};
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::types::SessionWithUser;

/// Builds the session response from the resolved session.
pub type CustomSessionFn = Arc<dyn Fn(SessionWithUser, Ctx) -> BoxFuture<'static, Result<Value>> + Send + Sync>;

/// Wrap an async closure as a [`CustomSessionFn`].
pub fn custom_session_fn<F, Fut>(f: F) -> CustomSessionFn
where
    F: Fn(SessionWithUser, Ctx) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Value>> + Send + 'static,
{
    Arc::new(move |s, ctx| Box::pin(f(s, ctx)))
}

#[derive(Debug, Clone, Default)]
pub struct CustomSessionOptions {
    /// Also apply the function to `/multi-session/list-device-sessions` entries.
    pub should_mutate_list_device_sessions_endpoint: bool,
}

async fn get_session(f: CustomSessionFn, ctx: Ctx) -> EndpointResult {
    // The core handler resolves the session and sets any refreshed cookies on this context.
    let out = core_get_session(ctx.clone()).await?;
    let is_null = matches!(&out, EndpointOutput::Json(Value::Null));
    let session = ctx.session().filter(|_| !is_null);
    match session {
        Some(session) => ctx.json(f(session, ctx.clone()).await?),
        None => ctx.json(Value::Null),
    }
}

async fn mutate_device_sessions(
    f: &CustomSessionFn,
    ctx: Ctx,
) -> std::result::Result<Option<EndpointOutput>, ApiError> {
    let Some(Ok(EndpointOutput::Json(Value::Array(items)))) = ctx.returned() else { return Ok(None) };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let session: SessionWithUser =
            serde_json::from_value(item).map_err(|e| ApiError::internal(format!("invalid device session: {e}")))?;
        out.push(f(session, ctx.clone()).await?);
    }
    Ok(Some(EndpointOutput::Json(Value::Array(out))))
}

pub struct CustomSession {
    f: CustomSessionFn,
    options: CustomSessionOptions,
}

pub fn custom_session(f: CustomSessionFn, options: CustomSessionOptions) -> Arc<dyn Plugin> {
    Arc::new(CustomSession { f, options })
}

impl Plugin for CustomSession {
    fn id(&self) -> &str {
        "custom-session"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let f = self.f.clone();
        vec![
            Endpoint::get("getSession", "/get-session", handler(move |ctx| get_session(f.clone(), ctx)))
                .methods(&[Method::GET, Method::POST]),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        if !self.options.should_mutate_list_device_sessions_endpoint {
            return PluginHooks::default();
        }
        let f = self.f.clone();
        PluginHooks {
            before: vec![],
            after: vec![MatchedHook::new(
                |ctx| ctx.path == "/multi-session/list-device-sessions",
                hook(move |ctx| {
                    let f = f.clone();
                    async move { mutate_device_sessions(&f, ctx).await }
                }),
            )],
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
