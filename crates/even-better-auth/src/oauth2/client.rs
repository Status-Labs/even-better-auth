//! Authorization URLs, token requests and HTTP helpers (`create-authorization-url.ts`,
//! `validate-authorization-code.ts`, `refresh-access-token.ts`, `token-endpoint-auth.ts`,
//! `utils.ts`).

use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::{Map, Value};
use url::Url;

use super::{
    CLIENT_ASSERTION_TYPE, ClientAssertion, ClientAssertionContext, OAuth2Tokens, ProviderOptions, ValidateCodeParams,
};
use crate::error::{Error, Result};

/// Query parameters set by the framework that `additional_params` may not override.
pub const RESERVED_AUTHORIZATION_PARAMS: &[&str] = &[
    "state",
    "client_id",
    "redirect_uri",
    "response_type",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "scope",
];

/// Parameters for [`create_authorization_url`] (`createAuthorizationURL`).
#[derive(Debug, Clone, Default)]
pub struct AuthorizationRequest {
    pub authorization_endpoint: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub claims: Option<Vec<String>>,
    pub duration: Option<String>,
    pub prompt: Option<String>,
    pub access_type: Option<String>,
    pub response_type: Option<String>,
    pub display: Option<String>,
    pub login_hint: Option<String>,
    pub nonce: Option<String>,
    pub hd: Option<String>,
    pub response_mode: Option<String>,
    pub additional_params: Vec<(String, String)>,
    /// Defaults to a space.
    pub scope_joiner: Option<String>,
}

fn set_param(params: &mut Vec<(String, String)>, key: &str, value: impl Into<String>) {
    let value = value.into();
    if let Some(pos) = params.iter().position(|(k, _)| k == key) {
        params[pos].1 = value;
        let mut i = pos + 1;
        while i < params.len() {
            if params[i].0 == key {
                params.remove(i);
            } else {
                i += 1;
            }
        }
    } else {
        params.push((key.to_owned(), value));
    }
}

fn set_opt(params: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(v) = value.filter(|v| !v.is_empty()) {
        set_param(params, key, v);
    }
}

/// `base64url(sha256(verifier))` without padding (PKCE S256).
pub fn generate_code_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(crate::crypto::sha256(code_verifier.as_bytes()))
}

/// Build a provider authorization URL. `options.authorization_endpoint` and
/// `options.redirect_uri` override the request values.
pub fn create_authorization_url(options: &ProviderOptions, req: AuthorizationRequest) -> Result<Url> {
    let endpoint =
        options.authorization_endpoint.as_deref().filter(|e| !e.is_empty()).unwrap_or(&req.authorization_endpoint);
    let mut url = Url::parse(endpoint).map_err(|e| Error::Config(format!("invalid authorization endpoint: {e}")))?;
    let mut params: Vec<(String, String)> = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
    set_param(&mut params, "response_type", req.response_type.as_deref().filter(|s| !s.is_empty()).unwrap_or("code"));
    if options.client_id.is_empty() {
        return Err(Error::Config("OAuth provider requires clientId".into()));
    }
    set_param(&mut params, "client_id", options.client_id.as_str());
    set_param(&mut params, "state", req.state.as_str());
    if !req.scopes.is_empty() {
        set_param(&mut params, "scope", req.scopes.join(req.scope_joiner.as_deref().unwrap_or(" ")));
    }
    let redirect = options.redirect_uri.as_deref().filter(|r| !r.is_empty()).unwrap_or(&req.redirect_uri);
    set_param(&mut params, "redirect_uri", redirect);
    set_opt(&mut params, "duration", req.duration.as_deref());
    set_opt(&mut params, "display", req.display.as_deref());
    set_opt(&mut params, "login_hint", req.login_hint.as_deref());
    set_opt(&mut params, "nonce", req.nonce.as_deref());
    set_opt(&mut params, "prompt", req.prompt.as_deref());
    set_opt(&mut params, "hd", req.hd.as_deref());
    set_opt(&mut params, "access_type", req.access_type.as_deref());
    set_opt(&mut params, "response_mode", req.response_mode.as_deref());
    if let Some(verifier) = req.code_verifier.as_deref().filter(|v| !v.is_empty()) {
        set_param(&mut params, "code_challenge_method", "S256");
        set_param(&mut params, "code_challenge", generate_code_challenge(verifier));
    }
    if let Some(claims) = &req.claims {
        let mut id_token = Map::new();
        id_token.insert("email".into(), Value::Null);
        id_token.insert("email_verified".into(), Value::Null);
        for c in claims {
            id_token.insert(c.clone(), Value::Null);
        }
        let mut obj = Map::new();
        obj.insert("id_token".into(), Value::Object(id_token));
        set_param(&mut params, "claims", Value::Object(obj).to_string());
    }
    for (k, v) in &req.additional_params {
        if RESERVED_AUTHORIZATION_PARAMS.contains(&k.as_str()) {
            continue;
        }
        set_param(&mut params, k, v.as_str());
    }
    url.set_query(None);
    url.query_pairs_mut().extend_pairs(params.iter());
    Ok(url)
}

/// Parse a `scope` token-response field: a space-delimited string or an array.
pub fn parse_scope_field(scope: Option<&Value>) -> Vec<String> {
    match scope {
        Some(Value::Array(items)) => {
            items.iter().filter_map(|s| s.as_str()).map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect()
        }
        Some(Value::String(s)) => s.split_whitespace().map(str::to_owned).collect(),
        _ => vec![],
    }
}

fn seconds(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64().filter(|n| *n != 0.0),
        Value::String(s) if !s.is_empty() => s.trim().parse().ok(),
        _ => None,
    }
}

fn str_field(data: &Map<String, Value>, key: &str) -> Option<String> {
    data.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Parse a token endpoint response (`getOAuth2Tokens`).
pub fn get_oauth2_tokens(data: &Map<String, Value>) -> OAuth2Tokens {
    let at = |secs: f64| Utc::now() + chrono::Duration::milliseconds((secs * 1000.0) as i64);
    OAuth2Tokens {
        token_type: str_field(data, "token_type"),
        access_token: str_field(data, "access_token"),
        refresh_token: str_field(data, "refresh_token"),
        access_token_expires_at: seconds(data.get("expires_in")).map(at),
        refresh_token_expires_at: seconds(data.get("refresh_token_expires_in")).map(at),
        scopes: parse_scope_field(data.get("scope")),
        id_token: str_field(data, "id_token"),
        raw: data.clone(),
    }
}

/// Union of stored (comma-separated) and incoming scopes, keeping stored order.
pub fn merge_scopes(stored: Option<&str>, incoming: &[String]) -> String {
    let mut out: Vec<String> = vec![];
    let existing = stored.unwrap_or_default().split(',').map(str::trim);
    for s in existing.chain(incoming.iter().map(|s| s.trim())) {
        if !s.is_empty() && !out.iter().any(|o| o == s) {
            out.push(s.to_owned());
        }
    }
    out.join(",")
}

fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// `Authorization: Basic ...` value per RFC 6749 §2.3.1 (form-encoded, then base64).
pub fn encode_basic_credentials(client_id: &str, client_secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{}:{}", form_encode(client_id), form_encode(client_secret))))
}

/// How a client authenticates at the token endpoint (`TokenEndpointAuth`).
#[derive(Debug, Clone)]
pub enum ClientAuthentication {
    /// `client_secret_basic`.
    Basic,
    /// `client_secret_post` (the default when a secret is configured, else `none`).
    Post,
    /// `private_key_jwt` with the given assertion source.
    PrivateKeyJwt(ClientAssertion),
}

/// A form-encoded token endpoint request.
#[derive(Debug, Clone, Default)]
pub struct TokenRequest {
    pub body: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
}

impl TokenRequest {
    fn new() -> Self {
        Self {
            body: vec![],
            headers: vec![
                ("content-type".into(), "application/x-www-form-urlencoded".into()),
                ("accept".into(), "application/json".into()),
            ],
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.body.iter().any(|(k, _)| k == key)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.body.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str())
    }

    pub fn encoded_body(&self) -> String {
        url::form_urlencoded::Serializer::new(String::new()).extend_pairs(self.body.iter()).finish()
    }
}

/// Apply client authentication to a token request (`applyTokenEndpointAuth`). Without an
/// explicit method, a configured [`ProviderOptions::client_assertion`] selects
/// `private_key_jwt`.
pub fn apply_token_endpoint_auth(
    req: &mut TokenRequest,
    options: &ProviderOptions,
    authentication: Option<ClientAuthentication>,
    token_endpoint: &str,
    grant_type: &str,
) -> Result<()> {
    if req.has("client_assertion") != req.has("client_assertion_type") {
        return Err(Error::Config("client_assertion and client_assertion_type must both be provided".into()));
    }
    let client_id = Some(options.client_id.as_str()).filter(|s| !s.is_empty());
    let secret = Some(options.client_secret.as_str()).filter(|s| !s.is_empty());
    let no_secret = |method: &str, req: &TokenRequest| {
        if secret.is_some() || req.has("client_secret") {
            return Err(Error::Config(format!(
                "{method} token endpoint authentication cannot be combined with clientSecret"
            )));
        }
        Ok(())
    };
    if req.has("client_assertion") {
        if matches!(authentication, Some(ClientAuthentication::PrivateKeyJwt(_))) {
            return Err(Error::Config(
                "client_assertion body parameters cannot be combined with tokenEndpointAuth".into(),
            ));
        }
        no_secret("private_key_jwt", req)?;
        if let Some(id) = client_id {
            set_param(&mut req.body, "client_id", id);
        }
        return Ok(());
    }
    let authentication =
        authentication.or_else(|| options.client_assertion.clone().map(ClientAuthentication::PrivateKeyJwt));
    let method = match (&authentication, secret) {
        (Some(ClientAuthentication::PrivateKeyJwt(_)), _) => "private_key_jwt",
        (Some(ClientAuthentication::Basic), _) => "client_secret_basic",
        (_, Some(_)) => "client_secret_post",
        _ => "none",
    };
    let require_id =
        || client_id.ok_or_else(|| Error::Config(format!("{method} token endpoint authentication requires clientId")));
    match authentication {
        Some(ClientAuthentication::PrivateKeyJwt(assertion)) => {
            no_secret("private_key_jwt", req)?;
            let id = require_id()?;
            if token_endpoint.is_empty() {
                return Err(Error::Config(
                    "private_key_jwt token endpoint authentication requires tokenEndpoint".into(),
                ));
            }
            let jwt = assertion.sign(&ClientAssertionContext {
                client_id: id.to_owned(),
                token_endpoint: token_endpoint.to_owned(),
                grant_type: grant_type.to_owned(),
            })?;
            set_param(&mut req.body, "client_id", id);
            set_param(&mut req.body, "client_assertion", jwt.as_str());
            set_param(&mut req.body, "client_assertion_type", CLIENT_ASSERTION_TYPE);
        }
        _ if method == "client_secret_basic" => {
            if req.has("client_secret") {
                return Err(Error::Config(
                    "client_secret_basic token endpoint authentication cannot be combined with client_secret body parameters"
                        .into(),
                ));
            }
            let secret = secret.ok_or_else(|| {
                Error::Config("client_secret_basic token endpoint authentication requires clientSecret".into())
            })?;
            let id = require_id()?;
            set_header(req, "authorization", encode_basic_credentials(id, secret));
        }
        _ if method == "client_secret_post" => {
            let id = require_id()?;
            set_param(&mut req.body, "client_id", id);
            set_param(&mut req.body, "client_secret", secret.unwrap_or_default());
        }
        _ => {
            no_secret("none", req)?;
            if grant_type == "client_credentials" {
                return Err(Error::Config(
                    "none token endpoint authentication cannot be used with client_credentials grant".into(),
                ));
            }
            set_param(&mut req.body, "client_id", require_id()?);
        }
    }
    Ok(())
}

fn set_header(req: &mut TokenRequest, name: &str, value: String) {
    req.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    req.headers.push((name.to_owned(), value));
}

/// Build an `authorization_code` grant request (`authorizationCodeRequest`).
pub fn authorization_code_request(
    options: &ProviderOptions,
    params: &ValidateCodeParams,
    token_endpoint: &str,
    authentication: Option<ClientAuthentication>,
    additional_params: &[(String, String)],
) -> Result<TokenRequest> {
    let mut req = TokenRequest::new();
    set_param(&mut req.body, "grant_type", "authorization_code");
    set_param(&mut req.body, "code", params.code.as_str());
    set_opt(&mut req.body, "code_verifier", params.code_verifier.as_deref());
    set_opt(&mut req.body, "client_key", options.client_key.as_deref());
    set_opt(&mut req.body, "device_id", params.device_id.as_deref());
    let redirect = options.redirect_uri.as_deref().filter(|r| !r.is_empty()).unwrap_or(&params.redirect_uri);
    set_param(&mut req.body, "redirect_uri", redirect);
    for (k, v) in additional_params {
        if !req.has(k) {
            req.body.push((k.clone(), v.clone()));
        }
    }
    apply_token_endpoint_auth(&mut req, options, authentication, token_endpoint, "authorization_code")?;
    Ok(req)
}

/// Exchange an authorization code for tokens (`validateAuthorizationCode`).
pub async fn validate_authorization_code(
    options: &ProviderOptions,
    params: &ValidateCodeParams,
    token_endpoint: &str,
    authentication: Option<ClientAuthentication>,
) -> Result<OAuth2Tokens> {
    let req = authorization_code_request(options, params, token_endpoint, authentication, &[])?;
    let data = post_form(token_endpoint, &req).await?;
    Ok(get_oauth2_tokens(&as_object(data)))
}

const BLOCKED_REFRESH_PARAMS: &[&str] = &["grant_type", "refresh_token", "__proto__", "constructor", "prototype"];

/// Build a `refresh_token` grant request (`refreshAccessTokenRequest`).
pub fn refresh_access_token_request(
    options: &ProviderOptions,
    refresh_token: &str,
    token_endpoint: &str,
    authentication: Option<ClientAuthentication>,
    extra_params: &[(String, String)],
) -> Result<TokenRequest> {
    let mut req = TokenRequest::new();
    set_param(&mut req.body, "grant_type", "refresh_token");
    set_param(&mut req.body, "refresh_token", refresh_token);
    for (k, v) in extra_params {
        if !BLOCKED_REFRESH_PARAMS.contains(&k.as_str()) {
            set_param(&mut req.body, k, v.as_str());
        }
    }
    apply_token_endpoint_auth(&mut req, options, authentication, token_endpoint, "refresh_token")?;
    Ok(req)
}

/// Refresh an access token (`refreshAccessToken`).
pub async fn refresh_access_token(
    options: &ProviderOptions,
    refresh_token: &str,
    token_endpoint: &str,
    authentication: Option<ClientAuthentication>,
    extra_params: &[(String, String)],
) -> Result<OAuth2Tokens> {
    let req = refresh_access_token_request(options, refresh_token, token_endpoint, authentication, extra_params)?;
    let data = as_object(post_form(token_endpoint, &req).await?);
    let mut tokens = get_oauth2_tokens(&data);
    tokens.raw = Map::new();
    Ok(tokens)
}

pub(crate) fn as_object(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

// ---- HTTP ---------------------------------------------------------------------------

/// Shared HTTP client for provider requests. Redirects are never followed, so an
/// attacker-influenced endpoint cannot bounce a server-side request elsewhere.
pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent("better-auth")
            .build()
            .expect("valid http client")
    })
}

async fn send(url: &str, builder: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    let res = builder.send().await.map_err(|e| Error::Http(e.to_string()))?;
    let status = res.status();
    if status.is_redirection() {
        return Err(Error::Http(format!(
            "The OAuth endpoint \"{url}\" returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL."
        )));
    }
    if !status.is_success() {
        let body = res.text().await.unwrap_or_default();
        return Err(Error::Http(format!("{url} responded {status}: {body}")));
    }
    Ok(res)
}

/// POST a form-encoded token request and parse the JSON response.
pub async fn post_form(url: &str, req: &TokenRequest) -> Result<Value> {
    let mut builder = http_client().post(url).body(req.encoded_body());
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    send(url, builder).await?.json().await.map_err(|e| Error::Http(e.to_string()))
}

/// GET a JSON resource with the given headers.
pub async fn get_json(url: &str, headers: &[(&str, String)]) -> Result<Value> {
    let mut builder = http_client().get(url).header("accept", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, v.as_str());
    }
    send(url, builder).await?.json().await.map_err(|e| Error::Http(e.to_string()))
}

/// POST an optional JSON body with the given headers and parse the JSON response
/// (GraphQL and RPC-style user-info endpoints).
pub async fn post_json(url: &str, headers: &[(&str, String)], body: Option<&Value>) -> Result<Value> {
    let mut builder = http_client().post(url).header("accept", "application/json");
    if let Some(body) = body {
        builder = builder.header("content-type", "application/json").body(body.to_string());
    }
    for (k, v) in headers {
        builder = builder.header(*k, v.as_str());
    }
    send(url, builder).await?.json().await.map_err(|e| Error::Http(e.to_string()))
}

/// GET raw bytes with the given headers.
pub async fn get_bytes(url: &str, headers: &[(&str, String)]) -> Result<Vec<u8>> {
    let mut builder = http_client().get(url);
    for (k, v) in headers {
        builder = builder.header(*k, v.as_str());
    }
    let bytes = send(url, builder).await?.bytes().await.map_err(|e| Error::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}

/// `Authorization: Bearer <token>` header pair.
pub fn bearer(token: Option<&str>) -> (&'static str, String) {
    ("authorization", format!("Bearer {}", token.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::PrivateKeyJwtOptions;
    use serde_json::json;

    fn opts() -> ProviderOptions {
        ProviderOptions::new("client-id", "client-secret")
    }

    #[test]
    fn pkce_challenge_matches_rfc7636() {
        // RFC 7636 Appendix B.
        assert_eq!(
            generate_code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn builds_authorization_url() {
        let url = create_authorization_url(
            &opts(),
            AuthorizationRequest {
                authorization_endpoint: "https://idp.example.com/authorize".into(),
                redirect_uri: "http://localhost:3000/api/auth/callback/x".into(),
                state: "st".into(),
                code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into()),
                scopes: vec!["openid".into(), "email".into()],
                prompt: Some("consent".into()),
                login_hint: Some("a@b.com".into()),
                additional_params: vec![("state".into(), "evil".into()), ("foo".into(), "bar".into())],
                ..Default::default()
            },
        )
        .unwrap();
        let q: Vec<(String, String)> = url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect();
        let get = |k: &str| q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(url.origin().ascii_serialization(), "https://idp.example.com");
        assert_eq!(q[0], ("response_type".into(), "code".into()));
        assert_eq!(get("client_id"), Some("client-id"));
        assert_eq!(get("state"), Some("st"));
        assert_eq!(get("scope"), Some("openid email"));
        assert_eq!(get("redirect_uri"), Some("http://localhost:3000/api/auth/callback/x"));
        assert_eq!(get("prompt"), Some("consent"));
        assert_eq!(get("login_hint"), Some("a@b.com"));
        assert_eq!(get("code_challenge_method"), Some("S256"));
        assert_eq!(get("code_challenge"), Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert_eq!(get("foo"), Some("bar"));
        assert_eq!(q.iter().filter(|(k, _)| k == "state").count(), 1);
        assert!(url.as_str().contains("scope=openid+email"));
    }

    #[test]
    fn authorization_url_overrides_and_claims() {
        let mut o = opts();
        o.authorization_endpoint = Some("https://custom.example.com/auth?tenant=1".into());
        o.redirect_uri = Some("https://app.example.com/cb".into());
        let url = create_authorization_url(
            &o,
            AuthorizationRequest {
                authorization_endpoint: "https://ignored.example.com".into(),
                redirect_uri: "http://ignored".into(),
                state: "s".into(),
                claims: Some(vec!["name".into()]),
                ..Default::default()
            },
        )
        .unwrap();
        let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(url.host_str(), Some("custom.example.com"));
        assert_eq!(q["tenant"], "1");
        assert_eq!(q["redirect_uri"], "https://app.example.com/cb");
        assert!(!q.contains_key("code_challenge"));
        assert_eq!(q["claims"], r#"{"id_token":{"email":null,"email_verified":null,"name":null}}"#);
    }

    #[test]
    fn parses_token_response() {
        let data = json!({
            "access_token": "at",
            "refresh_token": "rt",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token_expires_in": "7200",
            "scope": "openid  email profile",
            "id_token": "idt",
            "custom": 1
        });
        let t = get_oauth2_tokens(data.as_object().unwrap());
        assert_eq!(t.access_token.as_deref(), Some("at"));
        assert_eq!(t.refresh_token.as_deref(), Some("rt"));
        assert_eq!(t.token_type.as_deref(), Some("Bearer"));
        assert_eq!(t.id_token.as_deref(), Some("idt"));
        assert_eq!(t.scopes, vec!["openid", "email", "profile"]);
        let secs = (t.access_token_expires_at.unwrap() - Utc::now()).num_seconds();
        assert!((3590..=3600).contains(&secs));
        let secs = (t.refresh_token_expires_at.unwrap() - Utc::now()).num_seconds();
        assert!((7190..=7200).contains(&secs));
        assert_eq!(t.raw["custom"], 1);

        let t = get_oauth2_tokens(
            json!({"access_token": "x", "scope": ["a", " b ", 3, ""], "expires_in": 0}).as_object().unwrap(),
        );
        assert_eq!(t.scopes, vec!["a", "b"]);
        assert!(t.access_token_expires_at.is_none());
        assert!(t.refresh_token.is_none());
    }

    #[test]
    fn merges_scopes() {
        assert_eq!(merge_scopes(Some("a, b"), &["b".into(), "c".into()]), "a,b,c");
        assert_eq!(merge_scopes(None, &[]), "");
    }

    #[test]
    fn token_endpoint_auth() {
        let params = ValidateCodeParams {
            code: "c".into(),
            redirect_uri: "http://r".into(),
            code_verifier: Some("v".into()),
            device_id: None,
        };
        let post = authorization_code_request(&opts(), &params, "https://idp/token", None, &[]).unwrap();
        assert_eq!(post.get("grant_type"), Some("authorization_code"));
        assert_eq!(post.get("code_verifier"), Some("v"));
        assert_eq!(post.get("client_id"), Some("client-id"));
        assert_eq!(post.get("client_secret"), Some("client-secret"));
        assert!(post.header("authorization").is_none());

        let mut o = opts();
        o.client_id = "id with space".into();
        o.client_secret = "s:e/c".into();
        let basic =
            authorization_code_request(&o, &params, "https://idp/token", Some(ClientAuthentication::Basic), &[])
                .unwrap();
        assert!(!basic.has("client_secret"));
        let expected = format!("Basic {}", STANDARD.encode("id+with+space:s%3Ae%2Fc"));
        assert_eq!(basic.header("authorization"), Some(expected.as_str()));

        let public = ProviderOptions::new("pub", "");
        let none = refresh_access_token_request(
            &public,
            "rt",
            "https://idp/token",
            None,
            &[("grant_type".into(), "x".into()), ("scope".into(), "a b".into())],
        )
        .unwrap();
        assert_eq!(none.get("grant_type"), Some("refresh_token"));
        assert_eq!(none.get("client_id"), Some("pub"));
        assert_eq!(none.get("scope"), Some("a b"));
        assert!(!none.has("client_secret"));
        assert!(
            refresh_access_token_request(&public, "rt", "https://idp/token", Some(ClientAuthentication::Basic), &[])
                .is_err()
        );
    }

    #[test]
    fn private_key_jwt_assertions() {
        use crate::crypto::jose::{JwsAlgorithm, PrivateKey, verify_jws};
        let key = PrivateKey::generate(JwsAlgorithm::ES256, None).unwrap();
        let mut jwk = key.to_jwk();
        jwk.insert("kid".into(), "key-1".into());
        let assertion = ClientAssertion::private_key_jwt(PrivateKeyJwtOptions {
            private_key_jwk: Some(jwk.clone()),
            algorithm: Some(JwsAlgorithm::ES256),
            ..Default::default()
        })
        .unwrap();
        let params = ValidateCodeParams { code: "c".into(), redirect_uri: "http://r".into(), ..Default::default() };

        let mut o = ProviderOptions::new("client", "");
        o.client_assertion = Some(assertion.clone());
        let req = authorization_code_request(&o, &params, "https://idp/token", None, &[]).unwrap();
        assert_eq!(req.get("client_id"), Some("client"));
        assert_eq!(req.get("client_assertion_type"), Some(CLIENT_ASSERTION_TYPE));
        assert!(!req.has("client_secret"));
        let jwt = verify_jws(req.get("client_assertion").unwrap(), &key.public_key(), &[JwsAlgorithm::ES256]).unwrap();
        assert_eq!(jwt.kid(), Some("key-1"));
        assert_eq!(jwt.payload["iss"], "client");
        assert_eq!(jwt.payload["sub"], "client");
        assert_eq!(jwt.payload["aud"], "https://idp/token");
        assert!(jwt.payload["exp"].as_i64().unwrap() - jwt.payload["iat"].as_i64().unwrap() == 120);

        // A client secret cannot be combined with private_key_jwt.
        o.client_secret = "secret".into();
        assert!(authorization_code_request(&o, &params, "https://idp/token", None, &[]).is_err());
        // Mismatched or unsupported algorithms are rejected up front.
        let bad = PrivateKeyJwtOptions {
            private_key_jwk: Some(jwk.clone()),
            algorithm: Some(JwsAlgorithm::RS256),
            ..Default::default()
        };
        assert!(ClientAssertion::private_key_jwt(bad).is_err());
        jwk.insert("alg".into(), "HS256".into());
        let hs = PrivateKeyJwtOptions { private_key_jwk: Some(jwk), ..Default::default() };
        assert!(ClientAssertion::private_key_jwt(hs).is_err());
        assert!(ClientAssertion::private_key_jwt(PrivateKeyJwtOptions::default()).is_err());
    }
}
