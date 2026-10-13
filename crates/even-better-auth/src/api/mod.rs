//! Endpoints, request context and dispatch (the role of better-call plus
//! `createAuthEndpoint` in the TypeScript implementation).

pub(crate) mod dispatch;
pub mod middleware;
pub mod rate_limit;
pub mod routes;

pub(crate) use dispatch::Router;
pub use dispatch::{ApiCall, ApiResponse};

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::future::BoxFuture;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::context::AuthContext;
use crate::cookies::{AuthCookie, CookieOptions, parse_cookies, serialize_cookie};
use crate::crypto::make_signature;
use crate::error::{ApiError, codes};
use crate::types::SessionWithUser;

/// What an endpoint produces on success.
#[derive(Debug, Clone)]
pub enum EndpointOutput {
    /// A JSON body (status 200 unless overridden with [`EndpointContext::set_status`]).
    Json(Value),
    /// A `302 Found` redirect.
    Redirect(String),
    /// A fully-formed response.
    Response(http::Response<Bytes>),
}

impl From<Value> for EndpointOutput {
    fn from(v: Value) -> Self {
        EndpointOutput::Json(v)
    }
}

impl EndpointOutput {
    pub fn as_json(&self) -> Option<&Value> {
        match self {
            EndpointOutput::Json(v) => Some(v),
            _ => None,
        }
    }
}

pub type EndpointResult = Result<EndpointOutput, ApiError>;

/// Shared handle to the per-request context.
pub type Ctx = Arc<EndpointContext>;

pub type HandlerFn = Arc<dyn Fn(Ctx) -> BoxFuture<'static, EndpointResult> + Send + Sync>;

/// Wrap an async function as an endpoint handler.
pub fn handler<F, Fut>(f: F) -> HandlerFn
where
    F: Fn(Ctx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = EndpointResult> + Send + 'static,
{
    Arc::new(move |ctx| Box::pin(f(ctx)))
}

/// A hook that runs before an endpoint. Returning `Some` short-circuits with that output;
/// hooks may also modify the body/query via the context.
pub type BeforeHook = Arc<dyn Fn(Ctx) -> BoxFuture<'static, Result<Option<EndpointOutput>, ApiError>> + Send + Sync>;
/// A hook that runs after an endpoint. [`EndpointContext::returned`] holds the endpoint result;
/// returning `Some` replaces it.
pub type AfterHook = BeforeHook;
pub type Matcher = Arc<dyn Fn(&EndpointContext) -> bool + Send + Sync>;

pub fn hook<F, Fut>(f: F) -> BeforeHook
where
    F: Fn(Ctx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<EndpointOutput>, ApiError>> + Send + 'static,
{
    Arc::new(move |ctx| Box::pin(f(ctx)))
}

/// Accepted request body media types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Json,
    Form,
}

/// An endpoint definition.
#[derive(Clone)]
pub struct Endpoint {
    /// Name of the server API method (e.g. `"signUpEmail"`).
    pub key: String,
    /// Path relative to the base path; `:name` segments are parameters, `*` matches the rest.
    pub path: String,
    pub methods: Vec<Method>,
    pub handler: HandlerFn,
    /// Not reachable over HTTP, only through [`crate::BetterAuth::api`].
    pub server_only: bool,
    pub media_types: Vec<MediaType>,
}

impl Endpoint {
    pub fn new(key: &str, method: Method, path: &str, handler: HandlerFn) -> Self {
        Self {
            key: key.into(),
            path: path.into(),
            methods: vec![method],
            handler,
            server_only: false,
            media_types: vec![MediaType::Json],
        }
    }
    pub fn get(key: &str, path: &str, h: HandlerFn) -> Self {
        Self::new(key, Method::GET, path, h)
    }
    pub fn post(key: &str, path: &str, h: HandlerFn) -> Self {
        Self::new(key, Method::POST, path, h)
    }
    pub fn methods(mut self, methods: &[Method]) -> Self {
        self.methods = methods.to_vec();
        self
    }
    pub fn server_only(mut self) -> Self {
        self.server_only = true;
        self
    }
    pub fn allow_form(mut self) -> Self {
        self.media_types.push(MediaType::Form);
        self
    }
}

#[derive(Default)]
struct ResponseState {
    status: Option<StatusCode>,
    headers: HeaderMap,
    /// `(cookie name, serialized Set-Cookie value)`; later writes for a name replace earlier ones.
    cookies: Vec<(String, String)>,
    session: Option<SessionWithUser>,
    new_session: Option<SessionWithUser>,
    returned: Option<Result<EndpointOutput, ApiError>>,
    /// Request-scoped values shared between hooks and handlers (`defineRequestState`).
    locals: Map<String, Value>,
}

/// Per-request state passed to endpoint handlers and hooks.
pub struct EndpointContext {
    pub auth: Arc<AuthContext>,
    /// Base URL for this request including the base path, e.g. `http://localhost:3000/api/auth`.
    pub base_url: String,
    pub method: Method,
    /// The endpoint path pattern, e.g. `/callback/:id`.
    pub path: String,
    pub params: HashMap<String, String>,
    /// Request headers; hooks may rewrite them (see [`EndpointContext::set_request_cookie`]).
    headers: Mutex<HeaderMap>,
    /// `true` for HTTP requests; `false` for direct server-side API calls.
    pub is_request: bool,
    query: Mutex<Map<String, Value>>,
    body: Mutex<Value>,
    /// The raw request body, for endpoints that must inspect it (e.g. repeated form fields).
    raw_body: Mutex<Option<Bytes>>,
    request_url: Mutex<Option<String>>,
    state: Mutex<ResponseState>,
}

tokio::task_local! {
    static CURRENT: Ctx;
}

/// The context of the endpoint currently executing on this task, if any.
pub fn current_request() -> Option<Ctx> {
    CURRENT.try_with(|c| c.clone()).ok()
}

pub(crate) async fn scope<F: Future>(ctx: Ctx, f: F) -> F::Output {
    CURRENT.scope(ctx, f).await
}

impl EndpointContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        auth: Arc<AuthContext>,
        base_url: String,
        method: Method,
        path: String,
        params: HashMap<String, String>,
        headers: HeaderMap,
        query: Map<String, Value>,
        body: Value,
        is_request: bool,
    ) -> Self {
        Self {
            auth,
            base_url,
            method,
            path,
            params,
            headers: Mutex::new(headers),
            is_request,
            query: Mutex::new(query),
            body: Mutex::new(body),
            raw_body: Mutex::new(None),
            request_url: Mutex::new(None),
            state: Mutex::new(ResponseState::default()),
        }
    }

    // ---- request ---------------------------------------------------------------------

    /// The raw HTTP request body (`None` for server-side API calls).
    pub fn raw_body(&self) -> Option<Bytes> {
        self.raw_body.lock().unwrap().clone()
    }

    pub(crate) fn set_raw_body(&self, body: Bytes) {
        *self.raw_body.lock().unwrap() = Some(body);
    }

    /// The full URL of the HTTP request as the client addressed it (`ctx.request.url`),
    /// independent of a configured base URL. `None` for server-side API calls.
    pub fn request_url(&self) -> Option<String> {
        self.request_url.lock().unwrap().clone()
    }

    pub(crate) fn set_request_url(&self, url: String) {
        *self.request_url.lock().unwrap() = Some(url);
    }

    pub fn body(&self) -> Value {
        self.body.lock().unwrap().clone()
    }

    pub fn set_body(&self, body: Value) {
        *self.body.lock().unwrap() = body;
    }

    pub fn query(&self) -> Map<String, Value> {
        self.query.lock().unwrap().clone()
    }

    pub fn set_query(&self, query: Map<String, Value>) {
        *self.query.lock().unwrap() = query;
    }

    pub fn query_str(&self, key: &str) -> Option<String> {
        self.query.lock().unwrap().get(key).and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
    }

    /// Query flag: `true`/`"true"`.
    pub fn query_flag(&self, key: &str) -> bool {
        matches!(self.query.lock().unwrap().get(key), Some(Value::Bool(true)))
            || self.query_str(key).as_deref() == Some("true")
    }

    pub fn body_str(&self, key: &str) -> Option<String> {
        self.body.lock().unwrap().get(key).and_then(Value::as_str).map(str::to_owned)
    }

    /// Deserialize the body into `T`, mapping failures to a 400 validation error.
    pub fn parse_body<T: DeserializeOwned>(&self) -> Result<T, ApiError> {
        let body = self.body();
        let body = if body.is_null() { Value::Object(Map::new()) } else { body };
        if !body.is_object() {
            return Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT));
        }
        serde_json::from_value(body).map_err(validation_error)
    }

    pub fn parse_query<T: DeserializeOwned>(&self) -> Result<T, ApiError> {
        serde_json::from_value(Value::Object(self.query())).map_err(validation_error)
    }

    /// A request header as a string.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers.lock().unwrap().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
    }

    /// A copy of the request headers.
    pub fn headers(&self) -> HeaderMap {
        self.headers.lock().unwrap().clone()
    }

    pub fn has_header(&self, name: &str) -> bool {
        self.headers.lock().unwrap().contains_key(name)
    }

    /// Replace a request header for the rest of this call (hooks use this to rewrite requests).
    pub fn set_request_header(&self, name: http::HeaderName, value: HeaderValue) {
        self.headers.lock().unwrap().insert(name, value);
    }

    /// Set (or replace) a cookie in the request's `Cookie` header (`setRequestCookie`).
    pub fn set_request_cookie(&self, name: &str, value: &str) {
        let mut cookies: Vec<(String, String)> =
            self.request_cookies().into_iter().filter(|(n, _)| n != name).collect();
        cookies.push((name.to_owned(), crate::utils::url::encode_uri_component(value)));
        let header = cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        if let Ok(v) = HeaderValue::from_str(&header) {
            let mut headers = self.headers.lock().unwrap();
            headers.remove(http::header::COOKIE);
            headers.insert(http::header::COOKIE, v);
        }
    }

    /// The serialized `Set-Cookie` value this response sets for `name`, if any.
    pub fn response_cookie(&self, name: &str) -> Option<String> {
        self.state.lock().unwrap().cookies.iter().find(|(n, _)| n == name).map(|(_, c)| c.clone())
    }

    /// A response header set so far.
    pub fn response_header(&self, name: &str) -> Option<String> {
        self.state.lock().unwrap().headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
    }

    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    // ---- response --------------------------------------------------------------------

    pub fn set_status(&self, status: StatusCode) {
        self.state.lock().unwrap().status = Some(status);
    }

    pub(crate) fn status(&self) -> Option<StatusCode> {
        self.state.lock().unwrap().status
    }

    pub fn set_header(&self, name: &'static str, value: &str) {
        if let Ok(v) = HeaderValue::from_str(value) {
            self.state.lock().unwrap().headers.insert(name, v);
        }
    }

    pub(crate) fn response_headers(&self) -> HeaderMap {
        let state = self.state.lock().unwrap();
        let mut headers = state.headers.clone();
        for (_, c) in &state.cookies {
            if let Ok(v) = HeaderValue::from_str(c) {
                headers.append(http::header::SET_COOKIE, v);
            }
        }
        headers
    }

    pub fn json(&self, value: Value) -> EndpointResult {
        Ok(EndpointOutput::Json(value))
    }

    pub fn redirect(&self, url: impl Into<String>) -> EndpointResult {
        Ok(EndpointOutput::Redirect(url.into()))
    }

    // ---- cookies ---------------------------------------------------------------------

    fn request_cookies(&self) -> Vec<(String, String)> {
        self.headers
            .lock()
            .unwrap()
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(parse_cookies)
            .collect()
    }

    pub fn get_cookie(&self, name: &str) -> Option<String> {
        self.request_cookies().into_iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// All request cookies whose names satisfy `pred`.
    pub fn cookies_matching(&self, pred: impl Fn(&str) -> bool) -> Vec<(String, String)> {
        self.request_cookies().into_iter().filter(|(n, _)| pred(n)).collect()
    }

    /// Read a cookie signed with [`set_signed_cookie`](Self::set_signed_cookie).
    /// Returns `None` if missing or the signature is invalid.
    pub fn get_signed_cookie(&self, name: &str, secret: &str) -> Option<String> {
        let value = self.get_cookie(name)?;
        verify_signed_value(&value, secret)
    }

    fn push_cookie(&self, name: String, serialized: String) {
        let mut state = self.state.lock().unwrap();
        state.cookies.retain(|(n, _)| *n != name);
        state.cookies.push((name, serialized));
    }

    /// Whether this response already sets cookie `name` (or one of its chunks).
    pub fn has_pending_cookie(&self, name: &str) -> bool {
        let chunk = format!("{name}.");
        self.state.lock().unwrap().cookies.iter().any(|(n, _)| n == name || n.starts_with(&chunk))
    }

    pub fn set_cookie(&self, name: &str, value: &str, options: &CookieOptions) {
        self.push_cookie(name.to_owned(), serialize_cookie(name, value, options));
    }

    /// Set `value.base64(HMAC-SHA256(secret, value))`, URL-encoded (better-call's format).
    pub fn set_signed_cookie(&self, name: &str, value: &str, secret: &str, options: &CookieOptions) {
        let signed = format!("{value}.{}", make_signature(value, secret));
        self.set_cookie(name, &crate::utils::url::encode_uri_component(&signed), options);
    }

    /// Expire a cookie (Max-Age=0), replacing any pending write for it.
    pub fn expire_cookie(&self, cookie: &AuthCookie) {
        let options = CookieOptions { max_age: Some(0), ..cookie.attributes.clone() };
        self.set_cookie(&cookie.name, "", &options);
    }

    // ---- session ---------------------------------------------------------------------

    /// The session resolved for this request (set by session middleware).
    pub fn session(&self) -> Option<SessionWithUser> {
        self.state.lock().unwrap().session.clone()
    }

    pub fn set_session(&self, session: Option<SessionWithUser>) {
        self.state.lock().unwrap().session = session;
    }

    /// A session created during this request (sign-in, sign-up, ...).
    pub fn new_session(&self) -> Option<SessionWithUser> {
        self.state.lock().unwrap().new_session.clone()
    }

    pub fn set_new_session(&self, session: SessionWithUser) {
        self.state.lock().unwrap().new_session = Some(session);
    }

    /// A request-scoped value set with [`set_local`](Self::set_local).
    pub fn local(&self, key: &str) -> Option<Value> {
        self.state.lock().unwrap().locals.get(key).cloned()
    }

    /// Store a request-scoped value (`defineRequestState`), visible to later hooks and the handler.
    pub fn set_local(&self, key: &str, value: Value) {
        self.state.lock().unwrap().locals.insert(key.to_owned(), value);
    }

    /// Forget the session created during this request (e.g. when a second factor is required).
    pub fn clear_new_session(&self) {
        self.state.lock().unwrap().new_session = None;
    }

    /// The endpoint's result, available to after-hooks.
    pub fn returned(&self) -> Option<Result<EndpointOutput, ApiError>> {
        self.state.lock().unwrap().returned.clone()
    }

    pub(crate) fn set_returned(&self, r: Result<EndpointOutput, ApiError>) {
        self.state.lock().unwrap().returned = Some(r);
    }
}

/// Verify a `value.signature` string; returns the value if the signature is valid.
pub fn verify_signed_value(signed: &str, secret: &str) -> Option<String> {
    let pos = signed.rfind('.').filter(|p| *p >= 1)?;
    let (value, signature) = (&signed[..pos], &signed[pos + 1..]);
    if signature.len() != 44 || !signature.ends_with('=') {
        return None;
    }
    let expected = make_signature(value, secret);
    crate::crypto::constant_time_eq(expected.as_bytes(), signature.as_bytes()).then(|| value.to_owned())
}

fn validation_error(e: serde_json::Error) -> ApiError {
    let msg = e.to_string();
    ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", format!("[body] {msg}"))
}
