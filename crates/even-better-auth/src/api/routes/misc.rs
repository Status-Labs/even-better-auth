//! `GET /ok` and `GET /error`.

use bytes::Bytes;
use serde_json::json;

use super::util::append_query_params;
use crate::api::{Ctx, Endpoint, EndpointOutput, EndpointResult, handler};

async fn ok(ctx: Ctx) -> EndpointResult {
    ctx.json(json!({ "ok": true }))
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

async fn error_page(ctx: Ctx) -> EndpointResult {
    let code = ctx.query_str("error").unwrap_or_else(|| "UNKNOWN".into());
    let code = if !code.is_empty() && code.chars().all(|c| c.is_ascii_alphanumeric() || "'_-".contains(c)) {
        code
    } else {
        "UNKNOWN".into()
    };
    let description = ctx.query_str("error_description");
    let mut params = vec![("error", code.as_str())];
    if let Some(d) = &description {
        params.push(("error_description", d.as_str()));
    }
    if let Some(url) = &ctx.auth.options.on_api_error_url {
        return ctx.redirect(append_query_params(url, &params));
    }
    let desc_html = description.map(|d| format!("<p>{}</p>", escape_html(&d))).unwrap_or_default();
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Error</title>\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0}}\
         main{{max-width:32rem;padding:1rem}}code{{background:#eee;padding:.2rem .4rem}}</style></head>\
         <body><main><h1>Something went wrong</h1><p>Error code: <code>{}</code></p>{desc_html}</main></body></html>",
        escape_html(&code)
    );
    let res =
        http::Response::builder().header("content-type", "text/html").body(Bytes::from(html)).expect("valid response");
    Ok(EndpointOutput::Response(res))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![Endpoint::get("ok", "/ok", handler(ok)), Endpoint::get("error", "/error", handler(error_page))]
}
