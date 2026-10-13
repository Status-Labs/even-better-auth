//! URL helpers and trusted-origin matching (`auth/trusted-origins.ts`, `utils/url.ts`).

use url::Url;

/// The origin of an absolute http(s) URL, or `None` for relative/opaque URLs.
pub fn get_origin(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let origin = parsed.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

pub fn get_host(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_owned(),
    })
}

pub fn get_protocol(url: &str) -> Option<String> {
    Url::parse(url).ok().map(|u| format!("{}:", u.scheme()))
}

fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| matches!(c as u32, 0x00..=0x1f | 0x7f..=0x9f))
}

fn decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn normalize_path(path: &str) -> String {
    let decoded = decode(path);
    let mut segments: Vec<&str> = vec![];
    for seg in decoded.split('/') {
        match seg {
            ".." => {
                segments.pop();
            }
            "." | "" => {}
            s => segments.push(s),
        }
    }
    if segments.is_empty() { String::new() } else { format!("/{}", segments.join("/")) }
}

struct CustomOrigin {
    scheme: String,
    authority: String,
    path: String,
}

fn parse_custom_scheme_origin(value: &str) -> Option<CustomOrigin> {
    if has_control_chars(value) {
        return None;
    }
    let scheme_end = value.find(':').filter(|i| *i > 0)?;
    let scheme = value[..scheme_end].to_lowercase();
    let mut rest = &value[scheme_end + 1..];
    let mut authority = "";
    if let Some(r) = rest.strip_prefix("//") {
        match r.find(['/', '?', '#']) {
            Some(end) => {
                authority = &r[..end];
                rest = &r[end..];
            }
            None => {
                authority = r;
                rest = "";
            }
        }
    }
    let path = match rest.find(['?', '#']) {
        Some(end) => &rest[..end],
        None => rest,
    };
    Some(CustomOrigin { scheme, authority: authority.to_lowercase(), path: normalize_path(path) })
}

/// A relative URL that cannot escape the current origin.
pub fn is_safe_relative_url(value: &str) -> bool {
    if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') || has_control_chars(value) {
        return false;
    }
    let path = match value.find(['?', '#']) {
        Some(end) => &value[..end],
        None => value,
    };
    let lower = path.to_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    let base = Url::parse("https://better-auth.invalid").expect("valid base");
    base.join(value).map(|u| u.origin() == base.origin()).unwrap_or(false)
}

/// Glob match where `*` and `?` do not cross `/`, and `**` matches anything.
pub fn wildcard_match(pattern: &str, sample: &str) -> bool {
    fn go(p: &[char], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('*') if p.get(1) == Some(&'*') => (0..=s.len()).any(|i| go(&p[2..], &s[i..])),
            Some('*') => {
                let mut i = 0;
                loop {
                    if go(&p[1..], &s[i..]) {
                        return true;
                    }
                    if i >= s.len() || s[i] == '/' {
                        return false;
                    }
                    i += 1;
                }
            }
            Some('?') => !s.is_empty() && s[0] != '/' && go(&p[1..], &s[1..]),
            Some(c) => !s.is_empty() && s[0] == *c && go(&p[1..], &s[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = sample.chars().collect();
    go(&p, &s)
}

/// Whether `url` matches a trusted-origin `pattern`.
pub fn matches_origin_pattern(url: &str, pattern: &str, allow_relative_paths: bool) -> bool {
    if url.starts_with('/') {
        return allow_relative_paths && is_safe_relative_url(url);
    }
    if pattern.contains('*') || pattern.contains('?') {
        if pattern.contains("://") {
            return wildcard_match(pattern, &get_origin(url).unwrap_or_else(|| url.to_owned()));
        }
        return get_host(url).is_some_and(|h| wildcard_match(pattern, &h));
    }
    match get_protocol(url).as_deref() {
        Some("http:") | Some("https:") | None => return get_origin(url).as_deref() == Some(pattern),
        _ => {}
    }
    let (Some(parsed), Some(pat)) = (parse_custom_scheme_origin(url), parse_custom_scheme_origin(pattern)) else {
        return false;
    };
    if parsed.scheme != pat.scheme {
        return false;
    }
    if !pat.authority.is_empty() && parsed.authority != pat.authority {
        return false;
    }
    if pat.path.is_empty() {
        return true;
    }
    parsed.path == pat.path || parsed.path.starts_with(&format!("{}/", pat.path))
}

/// Normalize a configured base URL: ensure a path, defaulting to `base_path`.
/// Returns the full base URL including the base path, without a trailing slash.
pub fn with_base_path(base_url: &str, base_path: &str) -> Option<String> {
    let parsed = Url::parse(base_url).ok()?;
    let path = parsed.path().trim_end_matches('/');
    let path = if path.is_empty() { base_path.trim_end_matches('/').to_owned() } else { path.to_owned() };
    Some(format!("{}{}", parsed.origin().ascii_serialization(), path))
}

pub fn encode_uri_component(s: &str) -> String {
    use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
    const SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'!')
        .remove(b'~')
        .remove(b'*')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')');
    utf8_percent_encode(s, SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert!(matches_origin_pattern("http://localhost:3000/foo", "http://localhost:3000", false));
        assert!(!matches_origin_pattern("http://evil.com", "http://localhost:3000", false));
        assert!(matches_origin_pattern("/dashboard", "http://localhost:3000", true));
        assert!(!matches_origin_pattern("//evil.com", "http://localhost:3000", true));
        assert!(!matches_origin_pattern("/\\evil.com", "http://localhost:3000", true));
        assert!(matches_origin_pattern("https://a.example.com", "https://*.example.com", false));
        assert!(!matches_origin_pattern("https://a.evil.com", "https://*.example.com", false));
        assert!(matches_origin_pattern("myapp://callback/x", "myapp://", false));
        assert!(matches_origin_pattern("exp://192.168.1.1:8081/--/path", "exp://192.168.1.1:8081", false));
    }

    #[test]
    fn base_path() {
        assert_eq!(with_base_path("http://localhost:3000", "/api/auth").unwrap(), "http://localhost:3000/api/auth");
        assert_eq!(
            with_base_path("http://localhost:3000/custom/", "/api/auth").unwrap(),
            "http://localhost:3000/custom"
        );
    }
}
