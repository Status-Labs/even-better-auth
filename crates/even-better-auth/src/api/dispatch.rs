//! Routing and the request pipeline: rate limiting, plugin `on_request`, origin checks,
//! before hooks, the endpoint, after hooks and response serialization.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::{Map, Value};

use super::{BeforeHook, Endpoint, EndpointContext, EndpointOutput, MediaType, middleware};
use crate::context::AuthContext;
use crate::error::ApiError;

pub(crate) struct Router {
    endpoints: Vec<Endpoint>,
}

fn match_path(pattern: &str, path: &str) -> Option<HashMap<String, String>> {
    let pat: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    let mut params = HashMap::new();
    for (i, p) in pat.iter().enumerate() {
        if *p == "*" || *p == "**" {
            params.insert("_".into(), segs.get(i..).map(|s| s.join("/")).unwrap_or_default());
            return Some(params);
        }
        let seg = segs.get(i)?;
        if let Some(name) = p.strip_prefix(':') {
            if seg.is_empty() {
                return None;
            }
            let decoded = percent_encoding::percent_decode_str(seg).decode_utf8_lossy().into_owned();
            params.insert(name.into(), decoded);
        } else if p != seg {
            return None;
        }
    }
    (pat.len() == segs.len()).then_some(params)
}

impl Router {
    pub fn new(endpoints: Vec<Endpoint>) -> Self {
        Self { endpoints }
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// Endpoints whose path matches, with extracted params.
    fn matches(&self, path: &str) -> Vec<(&Endpoint, HashMap<String, String>)> {
        self.endpoints.iter().filter_map(|e| match_path(&e.path, path).map(|p| (e, p))).collect()
    }

    pub fn by_key(&self, key: &str) -> Option<&Endpoint> {
        self.endpoints.iter().find(|e| e.key == key)
    }
}

/// A direct server-side call into an endpoint (`auth.api.*`).
#[derive(Debug, Clone, Default)]
pub struct ApiCall {
    /// Endpoint key (e.g. `"getSession"`) or path (e.g. `"/get-session"`).
    pub endpoint: String,
    pub method: Option<Method>,
    pub headers: HeaderMap,
    pub body: Value,
    pub query: Map<String, Value>,
    pub params: HashMap<String, String>,
}

impl ApiCall {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into(), ..Default::default() }
    }
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }
    pub fn body(mut self, body: Value) -> Self {
        self.body = body;
        self
    }
    pub fn query(mut self, query: Map<String, Value>) -> Self {
        self.query = query;
        self
    }
}

/// The result of a direct API call.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub output: EndpointOutput,
}

impl ApiResponse {
    /// The JSON body (`Value::Null` for non-JSON outputs).
    pub fn json(&self) -> Value {
        self.output.as_json().cloned().unwrap_or(Value::Null)
    }
}

fn collect_hooks(auth: &AuthContext, ctx: &EndpointContext, before: bool) -> Vec<BeforeHook> {
    let mut hooks = vec![];
    let user = if before { &auth.options.hooks.before } else { &auth.options.hooks.after };
    if let Some(h) = user {
        hooks.push(h.clone());
    }
    for plugin in auth.plugins() {
        let ph = plugin.hooks();
        let list = if before { ph.before } else { ph.after };
        for h in list {
            if (h.matcher)(ctx) {
                hooks.push(h.handler);
            }
        }
    }
    hooks
}

/// Run an endpoint with origin checks and hooks. Returns the output or error.
pub(crate) async fn run_endpoint(ctx: Arc<EndpointContext>, endpoint: &Endpoint) -> Result<EndpointOutput, ApiError> {
    let auth = ctx.auth.clone();
    let handler = endpoint.handler.clone();
    super::scope(ctx.clone(), async move {
        middleware::origin_check(&ctx)?;
        for hook in collect_hooks(&auth, &ctx, true) {
            if let Some(out) = hook(ctx.clone()).await? {
                return Ok(out);
            }
        }
        let result = handler(ctx.clone()).await;
        if matches!(result, Ok(EndpointOutput::Response(_))) {
            return result;
        }
        ctx.set_returned(result.clone());
        let mut result = result;
        for hook in collect_hooks(&auth, &ctx, false) {
            match hook(ctx.clone()).await {
                Ok(Some(out)) => {
                    ctx.set_returned(Ok(out.clone()));
                    result = Ok(out);
                }
                Ok(None) => {}
                Err(e) => {
                    ctx.set_returned(Err(e.clone()));
                    result = Err(e);
                }
            }
        }
        result
    })
    .await
}

fn json_response(status: StatusCode, body: &Value, headers: HeaderMap) -> http::Response<Bytes> {
    let mut res = http::Response::builder().status(status).body(Bytes::from(body.to_string())).expect("valid response");
    *res.headers_mut() = headers;
    res.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

pub(crate) fn to_response(
    result: Result<EndpointOutput, ApiError>,
    status: Option<StatusCode>,
    mut headers: HeaderMap,
) -> http::Response<Bytes> {
    match result {
        Ok(EndpointOutput::Json(v)) => json_response(status.unwrap_or(StatusCode::OK), &v, headers),
        Ok(EndpointOutput::Redirect(url)) => {
            if let Ok(v) = HeaderValue::from_str(&url) {
                headers.insert(http::header::LOCATION, v);
            }
            let mut res = http::Response::builder().status(StatusCode::FOUND).body(Bytes::new()).expect("valid");
            *res.headers_mut() = headers;
            res
        }
        Ok(EndpointOutput::Response(mut r)) => {
            for (k, v) in headers.iter() {
                if k == http::header::SET_COOKIE {
                    r.headers_mut().append(k, v.clone());
                } else if !r.headers().contains_key(k) {
                    r.headers_mut().insert(k, v.clone());
                }
            }
            r
        }
        Err(e) => {
            for (k, v) in e.headers.iter() {
                headers.insert(k, v.clone());
            }
            if e.status.is_redirection() {
                let mut res = http::Response::builder().status(e.status).body(Bytes::new()).expect("valid");
                *res.headers_mut() = headers;
                return res;
            }
            json_response(e.status, &e.to_json(), headers)
        }
    }
}

fn parse_query(q: Option<&str>) -> Map<String, Value> {
    let pairs: Vec<(String, String)> = q.and_then(|q| serde_urlencoded::from_str(q).ok()).unwrap_or_default();
    pairs.into_iter().map(|(k, v)| (k, Value::String(v))).collect()
}

fn parse_body(headers: &HeaderMap, body: &[u8], allowed: &[MediaType]) -> Result<Value, ApiError> {
    if body.is_empty() || body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let unsupported = || {
        ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            format!("Unsupported media type: {content_type}"),
        )
    };
    match content_type.as_str() {
        "application/json" if allowed.contains(&MediaType::Json) => serde_json::from_slice(body)
            .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "INVALID_JSON", "Invalid JSON body")),
        "application/x-www-form-urlencoded" if allowed.contains(&MediaType::Form) => {
            let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body).map_err(|_| unsupported())?;
            Ok(Value::Object(
                pairs
                    .into_iter()
                    .map(|(k, v)| {
                        let v = match v.as_str() {
                            "true" => Value::Bool(true),
                            "false" => Value::Bool(false),
                            _ => Value::String(v),
                        };
                        (k, v)
                    })
                    .collect(),
            ))
        }
        _ => Err(unsupported()),
    }
}

/// Resolve the base URL (including base path) for a request.
pub(crate) fn request_base_url(auth: &AuthContext, req: &http::Request<Bytes>) -> String {
    if let Some(b) = &auth.base_url {
        return b.clone();
    }
    format!("{}{}", request_origin(auth, req), auth.options.base_path)
}

/// `proto://host` of the request, from (trusted) forwarding headers or the Host header.
pub(crate) fn request_origin(auth: &AuthContext, req: &http::Request<Bytes>) -> String {
    let headers = req.headers();
    let trusted = auth.options.advanced.trusted_proxy_headers;
    let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let host = trusted
        .then(|| header("x-forwarded-host"))
        .flatten()
        .or_else(|| header("host"))
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_else(|| "localhost".into());
    let proto = trusted
        .then(|| header("x-forwarded-proto"))
        .flatten()
        .filter(|p| p == "http" || p == "https")
        .or_else(|| req.uri().scheme_str().map(str::to_owned))
        .unwrap_or_else(|| "http".into());
    format!("{proto}://{host}")
}

fn not_found() -> http::Response<Bytes> {
    http::Response::builder().status(StatusCode::NOT_FOUND).body(Bytes::new()).expect("valid")
}

/// Handle an HTTP request.
pub(crate) async fn handle(
    auth: Arc<AuthContext>,
    router: &Router,
    mut req: http::Request<Bytes>,
) -> http::Response<Bytes> {
    let base_url = request_base_url(&auth, &req);
    let base_path = url::Url::parse(&base_url).map(|u| u.path().trim_end_matches('/').to_owned()).unwrap_or_default();
    let Some(rest) = req.uri().path().strip_prefix(base_path.as_str()) else {
        return not_found();
    };
    let path = match rest.trim_end_matches('/') {
        "" => "/".to_owned(),
        p if p.starts_with('/') => p.to_owned(),
        _ => return not_found(),
    };
    if auth.options.disabled_paths.contains(&path) {
        return not_found();
    }
    if let Some(res) = auth.rate_limiter.check(&auth, &path, req.headers()).await {
        return res;
    }
    for plugin in auth.plugins() {
        if let Some(res) = plugin.on_request(&mut req, &auth).await {
            return res;
        }
    }

    let candidates: Vec<_> = router.matches(&path).into_iter().filter(|(e, _)| !e.server_only).collect();
    if candidates.is_empty() {
        return not_found();
    }
    let method = req.method().clone();
    let Some((endpoint, params)) = candidates.iter().find(|(e, _)| e.methods.contains(&method)).cloned() else {
        if method == Method::OPTIONS {
            return http::Response::builder().status(StatusCode::NO_CONTENT).body(Bytes::new()).expect("valid");
        }
        return to_response(
            Err(ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED", "Method not allowed")),
            None,
            HeaderMap::new(),
        );
    };

    let query = parse_query(req.uri().query());
    let body = match parse_body(req.headers(), req.body(), &endpoint.media_types) {
        Ok(b) => b,
        Err(e) => return to_response(Err(e), None, HeaderMap::new()),
    };
    let ctx = Arc::new(EndpointContext::new(
        auth.clone(),
        base_url,
        method,
        endpoint.path.clone(),
        params,
        req.headers().clone(),
        query,
        body,
        true,
    ));
    ctx.set_raw_body(req.body().clone());
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_default();
    ctx.set_request_url(format!("{}{path_and_query}", request_origin(&auth, &req)));
    let result = run_endpoint(ctx.clone(), endpoint).await;
    if let Err(e) = &result
        && e.status.is_server_error()
    {
        tracing::error!(path = %path, error = %e, "endpoint error");
    }
    let mut res = to_response(result, ctx.status(), ctx.response_headers());
    for plugin in auth.plugins() {
        plugin.on_response(&mut res, &auth).await;
    }
    res
}

/// Invoke an endpoint directly, without HTTP-only checks (origin, rate limiting).
pub(crate) async fn call(auth: Arc<AuthContext>, router: &Router, call: ApiCall) -> Result<ApiResponse, ApiError> {
    let (endpoint, params) = if call.endpoint.starts_with('/') {
        let found = router.matches(&call.endpoint).into_iter().find(|(e, _)| match &call.method {
            Some(m) => e.methods.contains(m),
            None => true,
        });
        found.ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND))?
    } else {
        (router.by_key(&call.endpoint).ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND))?, call.params.clone())
    };
    let method = call.method.unwrap_or_else(|| endpoint.methods[0].clone());
    let base_url = auth.base_url.clone().unwrap_or_else(|| format!("http://localhost{}", auth.options.base_path));
    let ctx = Arc::new(EndpointContext::new(
        auth.clone(),
        base_url,
        method,
        endpoint.path.clone(),
        params,
        call.headers,
        call.query,
        call.body,
        false,
    ));
    let output = run_endpoint(ctx.clone(), endpoint).await?;
    Ok(ApiResponse { status: ctx.status().unwrap_or(StatusCode::OK), headers: ctx.response_headers(), output })
}

#[cfg(test)]
mod tests {
    use super::match_path;

    #[test]
    fn paths() {
        assert!(match_path("/sign-in/email", "/sign-in/email").is_some());
        assert!(match_path("/sign-in/email", "/sign-in").is_none());
        assert_eq!(match_path("/callback/:id", "/callback/github").unwrap()["id"], "github");
        assert!(match_path("/callback/:id", "/callback/").is_none());
    }
}
