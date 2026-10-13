//! Cookie definitions, (de)serialization and session cookie helpers (`cookies/index.ts`).

mod account;
mod session;

pub use account::{bind_account_cookie_to_session_user, get_account_cookie, merged_account, set_account_cookie};
pub use session::{
    CookieCachePayload, CookieCacheSigner, decode_cookie_cache, delete_session_cookie, get_chunked_cookie,
    set_cookie_cache, set_session_cookie,
};

use crate::options::{BetterAuthOptions, CookieAttributes};

pub const SECURE_COOKIE_PREFIX: &str = "__Secure-";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CookieOptions {
    /// Seconds; `None` makes a session cookie, `Some(0)` expires it.
    pub max_age: Option<i64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
    pub partitioned: bool,
}

impl CookieOptions {
    fn apply(&mut self, attrs: &CookieAttributes) {
        if let Some(d) = &attrs.domain {
            self.domain = Some(d.clone());
        }
        if let Some(p) = &attrs.path {
            self.path = Some(p.clone());
        }
        if let Some(s) = attrs.secure {
            self.secure = s;
        }
        if let Some(h) = attrs.http_only {
            self.http_only = h;
        }
        if let Some(s) = attrs.same_site {
            self.same_site = Some(s);
        }
        if let Some(p) = attrs.partitioned {
            self.partitioned = p;
        }
    }
}

/// Serialize a `Set-Cookie` value. `value` is written as-is (callers encode if needed).
pub fn serialize_cookie(name: &str, value: &str, opts: &CookieOptions) -> String {
    let mut out = format!("{name}={value}");
    if let Some(max_age) = opts.max_age {
        out.push_str(&format!("; Max-Age={}", max_age.max(0)));
        if max_age <= 0 {
            out.push_str("; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        }
    }
    if let Some(domain) = &opts.domain {
        out.push_str(&format!("; Domain={domain}"));
    }
    if let Some(path) = &opts.path {
        out.push_str(&format!("; Path={path}"));
    }
    if opts.http_only {
        out.push_str("; HttpOnly");
    }
    if opts.secure || name.starts_with(SECURE_COOKIE_PREFIX) {
        out.push_str("; Secure");
    }
    if let Some(s) = opts.same_site {
        out.push_str(&format!("; SameSite={}", s.as_str()));
    }
    if opts.partitioned {
        out.push_str("; Partitioned");
    }
    out
}

/// Parse a `Cookie` header into `(name, value)` pairs, percent-decoding values.
pub fn parse_cookies(header: &str) -> Vec<(String, String)> {
    header
        .split(';')
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let mut value = value.trim();
            if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
                value = &value[1..value.len() - 1];
            }
            let decoded = if value.contains('%') {
                percent_encoding::percent_decode_str(value)
                    .decode_utf8()
                    .map(|c| c.into_owned())
                    .unwrap_or_else(|_| value.to_owned())
            } else {
                value.to_owned()
            };
            Some((name.to_owned(), decoded))
        })
        .collect()
}

/// A named cookie with its default attributes.
#[derive(Debug, Clone)]
pub struct AuthCookie {
    pub name: String,
    pub attributes: CookieOptions,
}

/// Builds cookie names/attributes from options (`createCookieGetter`).
#[derive(Debug, Clone)]
pub struct CookieFactory {
    prefix: String,
    secure: bool,
    domain: Option<String>,
    defaults: CookieAttributes,
    overrides: Vec<(String, crate::options::CookieOverride)>,
}

impl CookieFactory {
    pub fn new(options: &BetterAuthOptions) -> Self {
        let secure = options.advanced.use_secure_cookies.unwrap_or_else(|| match &options.base_url {
            Some(url) => url.starts_with("https://"),
            None => !cfg!(debug_assertions),
        });
        let cross = &options.advanced.cross_sub_domain_cookies;
        let domain = if cross.enabled {
            cross.domain.clone().or_else(|| {
                options
                    .base_url
                    .as_deref()
                    .and_then(|u| url::Url::parse(u).ok())
                    .and_then(|u| u.host_str().map(str::to_owned))
            })
        } else {
            None
        };
        Self {
            prefix: options.advanced.cookie_prefix.clone().unwrap_or_else(|| "better-auth".into()),
            secure,
            domain,
            defaults: options.advanced.default_cookie_attributes.clone(),
            overrides: options.advanced.cookies.clone(),
        }
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Create the cookie `"{prefix}.{name}"` with optional `max_age`.
    pub fn create(&self, cookie_name: &str, max_age: Option<i64>) -> AuthCookie {
        let over = self.overrides.iter().find(|(n, _)| n == cookie_name).map(|(_, o)| o);
        let name = over.and_then(|o| o.name.clone()).unwrap_or_else(|| format!("{}.{}", self.prefix, cookie_name));
        let mut attributes = CookieOptions {
            max_age,
            domain: self.domain.clone(),
            path: Some("/".into()),
            secure: self.secure,
            http_only: true,
            same_site: Some(SameSite::Lax),
            partitioned: false,
        };
        attributes.apply(&self.defaults);
        if let Some(o) = over {
            attributes.apply(&o.attributes);
        }
        let secure_prefix = if self.secure { SECURE_COOKIE_PREFIX } else { "" };
        AuthCookie { name: format!("{secure_prefix}{name}"), attributes }
    }
}

/// The built-in auth cookies.
#[derive(Debug, Clone)]
pub struct AuthCookies {
    pub session_token: AuthCookie,
    pub session_data: AuthCookie,
    pub account_data: AuthCookie,
    pub dont_remember: AuthCookie,
}

impl AuthCookies {
    pub fn new(factory: &CookieFactory, options: &BetterAuthOptions) -> Self {
        let cache_age = options.session.cookie_cache.max_age;
        Self {
            session_token: factory.create("session_token", Some(options.session.expires_in)),
            session_data: factory.create("session_data", Some(cache_age)),
            account_data: factory.create("account_data", Some(cache_age)),
            dont_remember: factory.create("dont_remember", None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_parse() {
        let opts = CookieOptions {
            max_age: Some(60),
            path: Some("/".into()),
            http_only: true,
            same_site: Some(SameSite::Lax),
            ..Default::default()
        };
        assert_eq!(serialize_cookie("a", "b", &opts), "a=b; Max-Age=60; Path=/; HttpOnly; SameSite=Lax");
        assert_eq!(
            parse_cookies("a=1; b=x%3Dy; c=\"q\""),
            vec![("a".into(), "1".into()), ("b".into(), "x=y".into()), ("c".into(), "q".into())]
        );
    }
}
