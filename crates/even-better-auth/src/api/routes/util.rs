//! Helpers shared by route handlers.

use crate::api::EndpointContext;
use crate::error::{ApiError, codes};

/// Email validation equivalent to zod's `z.email()` pattern:
/// `^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`
pub fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else { return false };
    if local.is_empty() || local.starts_with('.') || email.contains("..") {
        return false;
    }
    let local_ok = local.chars().all(|c| c.is_ascii_alphanumeric() || "_'+-.".contains(c))
        && local.chars().last().is_some_and(|c| c.is_ascii_alphanumeric() || "_+-".contains(c));
    if !local_ok {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let (tld, rest) = labels.split_last().expect("len >= 2");
    tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic())
        && rest.iter().all(|l| {
            l.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

pub fn assert_password_length(ctx: &EndpointContext, password: &str) -> Result<(), ApiError> {
    let opts = &ctx.auth.options.email_and_password;
    let len = password.chars().count();
    if len < opts.min_password_length {
        return Err(ApiError::bad_request(codes::PASSWORD_TOO_SHORT));
    }
    if len > opts.max_password_length {
        return Err(ApiError::bad_request(codes::PASSWORD_TOO_LONG));
    }
    Ok(())
}

pub fn assert_password_not_too_long(ctx: &EndpointContext, password: &str) -> Result<(), ApiError> {
    if password.chars().count() > ctx.auth.options.email_and_password.max_password_length {
        return Err(ApiError::bad_request(codes::PASSWORD_TOO_LONG));
    }
    Ok(())
}

/// A body validation failure shaped like better-call's zod errors (`[body.field] message`).
pub fn body_field_error(field: &str, message: &str) -> ApiError {
    ApiError::bad_request(codes::VALIDATION_ERROR).with_field("message", format!("[body.{field}] {message}"))
}

/// Await a side task (e.g. sending an email), logging instead of propagating its failure
/// (`runInBackgroundOrAwait`).
pub async fn run_or_log<F>(task: F)
where
    F: std::future::Future<Output = crate::error::Result<()>>,
{
    if let Err(e) = task.await {
        tracing::error!(error = %e, "failed to run background task");
    }
}

/// Resolve `url` against `base` and set query parameters, like
/// `new URL(url, base)` followed by `searchParams.set(...)`; returns the absolute href.
pub fn resolve_url_with_params(base: &str, url: &str, params: &[(&str, &str)]) -> String {
    let Some(mut resolved) = url::Url::parse(base).ok().and_then(|b| b.join(url).ok()) else {
        return append_query_params(url, params);
    };
    if !params.is_empty() {
        let keep: Vec<(String, String)> = resolved
            .query_pairs()
            .filter(|(k, _)| !params.iter().any(|(p, _)| p == k))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let mut pairs = resolved.query_pairs_mut();
        pairs.clear();
        for (k, v) in keep.iter().map(|(k, v)| (k.as_str(), v.as_str())).chain(params.iter().copied()) {
            pairs.append_pair(k, v);
        }
    }
    resolved.to_string()
}

/// Append query parameters to a (possibly relative) URL, preserving any fragment.
pub fn append_query_params(url: &str, params: &[(&str, &str)]) -> String {
    let (base, fragment) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let encoded = serde_urlencoded::to_string(params).unwrap_or_default();
    let sep = if base.contains('?') { if base.ends_with('?') || base.ends_with('&') { "" } else { "&" } } else { "?" };
    let mut out = format!("{base}{sep}{encoded}");
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails() {
        assert!(is_valid_email("test@test.com"));
        assert!(is_valid_email("a.b+c@sub.example.co"));
        assert!(!is_valid_email("test"));
        assert!(!is_valid_email("test@test"));
        assert!(!is_valid_email(".a@test.com"));
        assert!(!is_valid_email("a..b@test.com"));
    }

    #[test]
    fn query_params() {
        assert_eq!(append_query_params("/cb", &[("error", "X")]), "/cb?error=X");
        assert_eq!(append_query_params("https://a.com/cb?x=1#h", &[("error", "X")]), "https://a.com/cb?x=1&error=X#h");
        let base = "http://localhost:3000/api/auth";
        assert_eq!(resolve_url_with_params(base, "/cb", &[("token", "t")]), "http://localhost:3000/cb?token=t");
        assert_eq!(
            resolve_url_with_params(base, "https://a.com/x?token=old&y=1", &[("token", "t")]),
            "https://a.com/x?y=1&token=t"
        );
    }
}
