//! `POST /sign-out` (`api/routes/sign-out.ts`).

use serde_json::json;

use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::cookies::delete_session_cookie;

async fn sign_out(ctx: Ctx) -> EndpointResult {
    let auth = ctx.auth.clone();
    let token = ctx.get_signed_cookie(&auth.cookies.session_token.name, &auth.secret);
    #[allow(unused_variables)]
    let current = match &token {
        Some(t) => auth.internal_adapter.find_session(t).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "failed to read session from database");
            None
        }),
        None => None,
    };
    if let Some(t) = &token
        && let Err(e) = auth.internal_adapter.delete_session(t).await
    {
        tracing::error!(error = %e, "failed to delete session from database");
    }
    delete_session_cookie(&ctx, false);

    #[cfg(feature = "oauth")]
    if let Some(session) = current
        && let Some(url) = crate::oauth2::provider_logout_url(&ctx, &session).await
    {
        let redirect = !ctx.body().get("disableRedirect").and_then(serde_json::Value::as_bool).unwrap_or(false);
        if redirect {
            ctx.set_header("location", &url);
        }
        return ctx.json(json!({ "success": true, "url": url, "redirect": redirect }));
    }
    ctx.json(json!({ "success": true }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![Endpoint::post("signOut", "/sign-out", handler(sign_out))]
}
