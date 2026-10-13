//! Social sign-in, OAuth callback and account endpoints.

mod account;
mod callback;
mod sign_in;

use http::StatusCode;
use serde_json::{Map, Value};

use super::RESERVED_AUTHORIZATION_PARAMS;
use crate::api::Endpoint;
use crate::error::{ApiError, codes};

pub fn endpoints() -> Vec<Endpoint> {
    let mut endpoints = vec![];
    endpoints.extend(sign_in::endpoints());
    endpoints.extend(callback::endpoints());
    endpoints.extend(account::endpoints());
    endpoints
}

/// Validate `additionalParams` (`additionalAuthorizationParamsSchema`).
pub(crate) fn additional_params(value: Option<&Map<String, Value>>) -> Result<Vec<(String, String)>, ApiError> {
    let Some(map) = value else { return Ok(vec![]) };
    let invalid = |message: String| {
        ApiError::bad_request(codes::VALIDATION_ERROR)
            .with_field("message", format!("[body.additionalParams] {message}"))
    };
    let mut out = vec![];
    for (k, v) in map {
        let Some(v) = v.as_str() else {
            return Err(invalid(format!("expected string for {k}")));
        };
        if RESERVED_AUTHORIZATION_PARAMS.contains(&k.as_str()) {
            return Err(invalid(format!(
                "additionalParams cannot include reserved OAuth parameters: {}",
                RESERVED_AUTHORIZATION_PARAMS.join(", ")
            )));
        }
        out.push((k.clone(), v.to_owned()));
    }
    Ok(out)
}

pub(crate) fn provider_not_found(provider: &str) -> ApiError {
    tracing::error!(provider, "Provider not found. Make sure to add the provider in your auth config");
    ApiError::from_code(StatusCode::NOT_FOUND, codes::PROVIDER_NOT_FOUND)
}
