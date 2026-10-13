//! OpenAPI document and reference page (`plugins/open-api`): `GET /open-api/generate-schema`
//! returns an OpenAPI 3.1 description of every HTTP endpoint and model, and `GET /reference`
//! serves a Scalar API reference for it.
//!
//! Rust endpoints carry no zod schemas or OpenAPI metadata, so operations are described by
//! path, method, operation id (the endpoint key), tags, path parameters and the standard
//! error responses; request bodies list only the client-writable user fields on
//! `/sign-up/email` and `/update-user`, as TS adds them.

use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, StatusCode};
use serde_json::{Map, Value, json};

use crate::api::routes::sign_up::CORE_FIELDS;
use crate::api::{Ctx, Endpoint, EndpointOutput, EndpointResult, handler};
use crate::context::AuthContext;
use crate::db::schema::DefaultValue;
use crate::db::{Field, FieldType};
use crate::error::ApiError;
use crate::plugin::Plugin;

#[derive(Debug, Clone)]
pub struct OpenApiOptions {
    /// Reference page path. Default `/reference`.
    pub path: String,
    /// Answer 404 on the reference page (the schema endpoint stays).
    pub disable_default_reference: bool,
    /// Scalar theme. Default `default`.
    pub theme: String,
    /// CSP nonce for the page's scripts.
    pub nonce: Option<String>,
}

impl Default for OpenApiOptions {
    fn default() -> Self {
        Self { path: "/reference".into(), disable_default_reference: false, theme: "default".into(), nonce: None }
    }
}

fn field_schema(field: &Field) -> Value {
    let mut schema = match field.field_type {
        FieldType::StringArray => json!({ "type": "array", "items": { "type": "string" } }),
        FieldType::NumberArray => json!({ "type": "array", "items": { "type": "number" } }),
        FieldType::Date => json!({ "type": "string", "format": "date-time" }),
        FieldType::String => json!({ "type": "string" }),
        FieldType::Number => json!({ "type": "number" }),
        FieldType::Boolean => json!({ "type": "boolean" }),
        FieldType::Json => json!({ "type": "json" }),
    };
    if let Some(DefaultValue::Value(v)) = &field.default_value {
        schema["default"] = v.clone();
    }
    if !field.input {
        schema["readOnly"] = true.into();
    }
    schema
}

fn input_property(field: &Field) -> Value {
    match field.field_type {
        FieldType::Date => json!({ "type": "string", "format": "date-time" }),
        FieldType::Json => json!({}),
        FieldType::StringArray => json!({ "type": "array", "items": { "type": "string" } }),
        FieldType::NumberArray => json!({ "type": "array", "items": { "type": "number" } }),
        _ => {
            let mut schema = field_schema(field);
            if let Some(obj) = schema.as_object_mut() {
                obj.remove("readOnly");
            }
            schema
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
}

fn to_openapi_path(path: &str) -> String {
    path.split('/')
        .map(|p| p.strip_prefix(':').map_or_else(|| p.to_owned(), |n| format!("{{{n}}}")))
        .collect::<Vec<_>>()
        .join("/")
}

fn path_parameters(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|p| p.strip_prefix(':'))
        .map(|name| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }))
        .collect()
}

fn responses() -> Value {
    let error = |description: &str, required: bool| {
        let mut schema = json!({ "type": "object", "properties": { "message": { "type": "string" } } });
        if required {
            schema["required"] = json!(["message"]);
        }
        json!({ "content": { "application/json": { "schema": schema } }, "description": description })
    };
    json!({
        "400": error("Bad Request. Usually due to missing parameters, or invalid parameters.", true),
        "401": error("Unauthorized. Due to missing or invalid authentication.", true),
        "403": error("Forbidden. You do not have permission to access this resource or to perform this action.", false),
        "404": error("Not Found. The requested resource was not found.", false),
        "429": error("Too Many Requests. You have exceeded the rate limit. Try again later.", false),
        "500": error("Internal Server Error. This is a problem with the server that you cannot fix.", false),
    })
}

fn operation_id(key: &str, method: &Method, used: &mut HashSet<String>) -> String {
    if used.insert(key.to_owned()) {
        return key.to_owned();
    }
    let suffix = capitalize(&method.as_str().to_lowercase());
    let mut candidate = format!("{key}{suffix}");
    let mut n = 2;
    while used.contains(&candidate) {
        candidate = format!("{key}{suffix}{n}");
        n += 1;
    }
    used.insert(candidate.clone());
    candidate
}

/// Client-writable user fields (`getUserInputRequestBodyFields`).
fn user_input_fields(auth: &AuthContext) -> (Map<String, Value>, Vec<String>) {
    let (mut properties, mut required) = (Map::new(), vec![]);
    let Some(user) = auth.schema.table("user") else { return (properties, required) };
    for (name, field) in &user.fields {
        if CORE_FIELDS.contains(&name.as_str()) || !field.input {
            continue;
        }
        properties.insert(name.clone(), input_property(field));
        if field.required && field.default_value.is_none() {
            required.push(name.clone());
        }
    }
    (properties, required)
}

fn request_body(auth: &AuthContext, path: &str) -> Value {
    let mut schema = json!({ "type": "object", "properties": {} });
    if path == "/sign-up/email" || path == "/update-user" {
        let (properties, required) = user_input_fields(auth);
        schema["properties"] = Value::Object(properties);
        if path == "/sign-up/email" && !required.is_empty() {
            schema["required"] = required.into();
        }
    }
    json!({ "content": { "application/json": { "schema": schema } } })
}

/// The OpenAPI document (`generator`).
pub fn generate(auth: &AuthContext) -> Value {
    let mut schemas = Map::new();
    for table in &auth.schema.tables {
        let mut properties = Map::new();
        properties.insert("id".into(), json!({ "type": "string", "readOnly": true }));
        let mut required = vec!["id".to_owned()];
        for (name, field) in &table.fields {
            properties.insert(name.clone(), field_schema(field));
            if field.required && field.returned && !required.contains(name) {
                required.push(name.clone());
            }
        }
        schemas.insert(
            capitalize(&table.key),
            json!({ "type": "object", "properties": properties, "required": required }),
        );
    }

    let mut paths = Map::new();
    let mut used = HashSet::new();
    let mut add = |endpoint: &Endpoint, tags: Vec<String>, paths: &mut Map<String, Value>| {
        if endpoint.server_only || auth.options.disabled_paths.contains(&endpoint.path) {
            return;
        }
        let path = to_openapi_path(&endpoint.path);
        let entry = paths.entry(path).or_insert_with(|| json!({}));
        for method in &endpoint.methods {
            let mut op = json!({
                "tags": tags,
                "operationId": operation_id(&endpoint.key, method, &mut used),
                "security": [{ "bearerAuth": [] }],
                "parameters": path_parameters(&endpoint.path),
                "responses": responses(),
            });
            if matches!(*method, Method::POST | Method::PATCH | Method::PUT) {
                op["requestBody"] = request_body(auth, &endpoint.path);
            } else if !matches!(*method, Method::GET | Method::DELETE) {
                continue;
            }
            entry[method.as_str().to_lowercase()] = op;
        }
    };
    let core = crate::api::routes::core_endpoints();
    let core_keys: HashSet<&str> = core.iter().map(|e| e.key.as_str()).collect();
    for endpoint in &core {
        add(endpoint, vec!["Default".into()], &mut paths);
    }
    for plugin in auth.plugins() {
        if plugin.id() == "open-api" {
            continue;
        }
        for endpoint in plugin.endpoints() {
            if !core_keys.contains(endpoint.key.as_str()) {
                add(&endpoint, vec![capitalize(plugin.id())], &mut paths);
            }
        }
    }

    json!({
        "openapi": "3.1.1",
        "info": {
            "title": "Better Auth",
            "description": "API Reference for your Better Auth Instance",
            "version": "1.1.0",
        },
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "apiKeyCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "apiKeyCookie",
                    "description": "API Key authentication via cookie",
                },
                "bearerAuth": { "type": "http", "scheme": "bearer", "description": "Bearer token authentication" },
            },
        },
        "security": [{ "apiKeyCookie": [], "bearerAuth": [] }],
        "servers": [{ "url": auth.base_url.clone().unwrap_or_else(|| auth.options.base_path.clone()) }],
        "tags": [{
            "name": "Default",
            "description": "Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin.",
        }],
        "paths": paths,
    })
}

fn html_escape_script(json: &str) -> String {
    // Keep the JSON from closing the <script> element it is embedded in.
    json.replace("</", "<\\/")
}

fn reference_html(schema: &Value, theme: &str, nonce: Option<&str>) -> String {
    let nonce_attr = nonce.map(|n| format!("nonce=\"{}\"", n.replace('"', "&quot;"))).unwrap_or_default();
    let configuration = json!({
        "theme": theme,
        "metaData": { "title": "Better Auth API", "description": "API Reference for your Better Auth Instance" },
    });
    format!(
        r#"<!doctype html>
<html>
  <head>
    <title>Scalar API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script id="api-reference" type="application/json">
    {schema}
    </script>
    <script {nonce_attr}>
      document.getElementById('api-reference').dataset.configuration = JSON.stringify({configuration});
    </script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference" {nonce_attr}></script>
  </body>
</html>"#,
        schema = html_escape_script(&schema.to_string()),
        configuration = html_escape_script(&configuration.to_string()),
    )
}

async fn generate_schema(ctx: Ctx) -> EndpointResult {
    ctx.json(generate(&ctx.auth))
}

async fn reference(options: Arc<OpenApiOptions>, ctx: Ctx) -> EndpointResult {
    if options.disable_default_reference {
        return Err(ApiError::message(StatusCode::NOT_FOUND, "Not Found"));
    }
    let html = reference_html(&generate(&ctx.auth), &options.theme, options.nonce.as_deref());
    let response = http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html")
        .body(Bytes::from(html))
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(EndpointOutput::Response(response))
}

pub struct OpenApi {
    options: Arc<OpenApiOptions>,
}

pub fn open_api(options: OpenApiOptions) -> Arc<dyn Plugin> {
    Arc::new(OpenApi { options: Arc::new(options) })
}

impl Plugin for OpenApi {
    fn id(&self) -> &str {
        "open-api"
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let options = self.options.clone();
        vec![
            Endpoint::get("generateOpenAPISchema", "/open-api/generate-schema", handler(generate_schema)),
            Endpoint::get("openAPIReference", &self.options.path, handler(move |ctx| reference(options.clone(), ctx))),
        ]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
