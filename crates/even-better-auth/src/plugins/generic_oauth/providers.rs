//! Preset configurations (`plugins/generic-oauth/providers`).

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::{GenericOAuthConfig, GetUserInfoFn};
use crate::error::{Error, Result};
use crate::oauth2::{self, ClientAuthentication, OAuth2Tokens};
use crate::social_providers::create_placeholder_email;

/// Options shared by the presets (`BaseOAuthProviderOptions`).
#[derive(Clone, Default)]
pub struct BaseProviderOptions {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_endpoint_auth: Option<ClientAuthentication>,
    /// Replaces the preset's default scopes.
    pub scopes: Option<Vec<String>>,
    pub redirect_uri: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub disable_provider_logout: bool,
    pub pkce: Option<bool>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub override_user_info: bool,
}

impl BaseProviderOptions {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self { client_id: client_id.into(), client_secret: Some(client_secret.into()), ..Default::default() }
    }
}

fn base(provider_id: &str, o: BaseProviderOptions, default_scopes: &[&str]) -> GenericOAuthConfig {
    GenericOAuthConfig {
        provider_id: provider_id.into(),
        client_id: o.client_id,
        client_secret: o.client_secret,
        token_endpoint_auth: o.token_endpoint_auth,
        scopes: o.scopes.unwrap_or_else(|| default_scopes.iter().map(|s| s.to_string()).collect()),
        redirect_uri: o.redirect_uri,
        end_session_endpoint: o.end_session_endpoint,
        post_logout_redirect_uri: o.post_logout_redirect_uri,
        disable_provider_logout: o.disable_provider_logout,
        pkce: o.pkce,
        disable_implicit_sign_up: o.disable_implicit_sign_up,
        disable_sign_up: o.disable_sign_up,
        override_user_info: o.override_user_info,
        ..Default::default()
    }
}

const OIDC_SCOPES: &[&str] = &["openid", "profile", "email"];

fn subject(key: &'static str) -> super::AccountSubjectFn {
    Arc::new(move |profile: &Value, _: &OAuth2Tokens| oauth2::subject_from(profile.get(key)))
}

fn user_info(
    f: impl Fn(OAuth2Tokens) -> futures::future::BoxFuture<'static, Result<Option<Value>>> + Send + Sync + 'static,
) -> Option<GetUserInfoFn> {
    Some(Arc::new(f))
}

/// GET JSON, treating any failure as "no profile".
async fn fetch(url: &str, headers: &[(&str, String)]) -> Option<Map<String, Value>> {
    match oauth2::get_json(url, headers).await {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

fn str_of(m: &Map<String, Value>, k: &str) -> Option<String> {
    m.get(k).and_then(Value::as_str).map(str::to_owned)
}

// ---- OIDC discovery presets ---------------------------------------------------------

/// Auth0, discovered from `https://{domain}/.well-known/openid-configuration`.
pub fn auth0(domain: &str, options: BaseProviderOptions) -> Result<GenericOAuthConfig> {
    let with_scheme = if domain.starts_with("http://") || domain.starts_with("https://") {
        domain.to_owned()
    } else {
        format!("https://{domain}")
    };
    let url = url::Url::parse(&with_scheme).map_err(|e| Error::Config(format!("invalid Auth0 domain: {e}")))?;
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    };
    let mut c = base("auth0", options, OIDC_SCOPES);
    c.discovery_url = Some(format!("https://{host}/.well-known/openid-configuration"));
    Ok(c)
}

fn issuer_discovery(id: &str, issuer: &str, options: BaseProviderOptions) -> GenericOAuthConfig {
    let mut c = base(id, options, OIDC_SCOPES);
    c.discovery_url = Some(format!("{}/.well-known/openid-configuration", issuer.strip_suffix('/').unwrap_or(issuer)));
    c
}

/// Okta, discovered from the issuer.
pub fn okta(issuer: &str, options: BaseProviderOptions) -> GenericOAuthConfig {
    issuer_discovery("okta", issuer, options)
}

/// Keycloak, discovered from the realm issuer.
pub fn keycloak(issuer: &str, options: BaseProviderOptions) -> GenericOAuthConfig {
    issuer_discovery("keycloak", issuer, options)
}

// ---- Microsoft Entra ID ---------------------------------------------------------------

fn microsoft_name(p: &Map<String, Value>) -> Option<String> {
    str_of(p, "name").or_else(|| {
        let given = str_of(p, "given_name").or_else(|| str_of(p, "givenname")).unwrap_or_default();
        let family = str_of(p, "family_name").or_else(|| str_of(p, "familyname")).unwrap_or_default();
        Some(format!("{given} {family}").trim().to_owned()).filter(|s| !s.is_empty())
    })
}

async fn microsoft_user_info(tokens: OAuth2Tokens) -> Option<Value> {
    let token_profile = oauth2::decode_jwt_payload(tokens.id_token.as_deref()?)?;
    let oid = str_of(&token_profile, "oid").filter(|o| !o.trim().is_empty())?;
    let token_email = str_of(&token_profile, "email");
    let placeholder = || create_placeholder_email(&oid, "microsoft-entra-id");
    let mut from_token = token_profile.clone();
    from_token.insert("name".into(), microsoft_name(&token_profile).into());
    from_token.insert("email".into(), token_email.clone().unwrap_or_else(placeholder).into());
    from_token.insert("image".into(), token_profile.get("picture").cloned().unwrap_or(Value::Null));
    let verified =
        token_email.is_some() && token_profile.get("email_verified").and_then(Value::as_bool).unwrap_or(false);
    from_token.insert("emailVerified".into(), verified.into());
    let Some(access_token) = tokens.access_token.as_deref() else { return Some(Value::Object(from_token)) };
    let headers = [oauth2::bearer(Some(access_token))];
    let Some(profile) = fetch("https://graph.microsoft.com/oidc/userinfo", &headers).await else {
        return Some(Value::Object(from_token));
    };
    let token_sub = str_of(&token_profile, "sub");
    if token_sub.is_none() || str_of(&profile, "sub") != token_sub {
        return Some(Value::Object(from_token));
    }
    let email = token_email.or_else(|| str_of(&profile, "email"));
    let mut merged = profile.clone();
    merged.extend(token_profile.clone());
    merged.insert("name".into(), microsoft_name(&token_profile).or_else(|| microsoft_name(&profile)).into());
    merged.insert("email".into(), email.clone().unwrap_or_else(placeholder).into());
    merged.insert(
        "image".into(),
        token_profile.get("picture").or_else(|| profile.get("picture")).cloned().unwrap_or(Value::Null),
    );
    let verified = email.is_some()
        && token_profile
            .get("email_verified")
            .or_else(|| profile.get("email_verified"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    merged.insert("emailVerified".into(), verified.into());
    Some(Value::Object(merged))
}

/// Microsoft Entra ID for one tenant (a GUID); ID tokens must verify against the tenant JWKS.
pub fn microsoft_entra_id(tenant_id: &str, options: BaseProviderOptions) -> Result<GenericOAuthConfig> {
    let tenant = tenant_id.to_lowercase();
    let is_guid = tenant.len() == 36
        && tenant
            .char_indices()
            .all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() });
    if !is_guid {
        return Err(Error::Config(
            "The generic microsoftEntraId helper requires a concrete Microsoft Entra tenant GUID. Use the built-in Microsoft provider for common, organizations, or consumers.".into(),
        ));
    }
    let mut c = base("microsoft-entra-id", options, OIDC_SCOPES);
    c.account_subject = Some(subject("oid"));
    c.discovery_url = Some(format!("https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"));
    c.require_id_token_verification = true;
    c.authorization_url = Some(format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"));
    c.token_url = Some(format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"));
    c.user_info_url = Some("https://graph.microsoft.com/oidc/userinfo".into());
    c.get_user_info = user_info(|tokens| Box::pin(async move { Ok(microsoft_user_info(tokens).await) }));
    Ok(c)
}

// ---- endpoint presets -----------------------------------------------------------------

/// Slack (Sign in with Slack, OpenID Connect).
pub fn slack(options: BaseProviderOptions) -> GenericOAuthConfig {
    let mut c = base("slack", options, OIDC_SCOPES);
    c.account_subject = Some(subject("sub"));
    c.authorization_url = Some("https://slack.com/openid/connect/authorize".into());
    c.token_url = Some("https://slack.com/api/openid.connect.token".into());
    c.user_info_url = Some("https://slack.com/api/openid.connect.userInfo".into());
    c.get_user_info = user_info(|tokens| {
        Box::pin(async move {
            let headers = [oauth2::bearer(tokens.access_token.as_deref())];
            let Some(p) = fetch("https://slack.com/api/openid.connect.userInfo", &headers).await else {
                return Ok(None);
            };
            Ok(Some(json!({
                "sub": p.get("sub"),
                "name": p.get("name"),
                "email": p.get("email"),
                "image": p.get("picture").filter(|v| !v.is_null()).or_else(|| p.get("https://slack.com/user_image_512")),
                "emailVerified": p.get("email_verified").and_then(Value::as_bool).unwrap_or(false),
            })))
        })
    });
    c
}

/// LINE Login; `provider_id` defaults to `line` (use another id per region/channel).
pub fn line(provider_id: Option<&str>, options: BaseProviderOptions) -> GenericOAuthConfig {
    const USER_INFO: &str = "https://api.line.me/oauth2/v2.1/userinfo";
    let mut c = base(provider_id.unwrap_or("line"), options, OIDC_SCOPES);
    c.account_subject = Some(subject("sub"));
    c.authorization_url = Some("https://access.line.me/oauth2/v2.1/authorize".into());
    c.token_url = Some("https://api.line.me/oauth2/v2.1/token".into());
    c.user_info_url = Some(USER_INFO.into());
    c.get_user_info = user_info(|tokens| {
        Box::pin(async move {
            let profile = match tokens.id_token.as_deref().and_then(oauth2::decode_jwt_payload) {
                Some(p) => p,
                None => {
                    let headers = [oauth2::bearer(tokens.access_token.as_deref())];
                    let Some(p) = fetch(USER_INFO, &headers).await else { return Ok(None) };
                    p
                }
            };
            Ok(Some(json!({
                "sub": profile.get("sub"),
                "name": profile.get("name"),
                "email": profile.get("email"),
                "image": profile.get("picture"),
                "emailVerified": false,
            })))
        })
    });
    c
}

/// Yandex ID.
pub fn yandex(options: BaseProviderOptions) -> GenericOAuthConfig {
    let mut c = base("yandex", options, &["login:info", "login:email", "login:avatar"]);
    c.account_subject = Some(subject("id"));
    c.authorization_url = Some("https://oauth.yandex.com/authorize".into());
    c.token_url = Some("https://oauth.yandex.com/token".into());
    c.get_user_info = user_info(|tokens| {
        Box::pin(async move {
            let headers = [("authorization", format!("OAuth {}", tokens.access_token.unwrap_or_default()))];
            let Some(p) = fetch("https://login.yandex.ru/info?format=json", &headers).await else { return Ok(None) };
            let email = str_of(&p, "default_email")
                .or_else(|| p.get("emails").and_then(|e| e.get(0)).and_then(Value::as_str).map(str::to_owned));
            let Some(email) = email else { return Ok(None) };
            let name = ["display_name", "real_name", "first_name", "login"].iter().find_map(|k| str_of(&p, k));
            let image = match (p.get("is_avatar_empty").and_then(Value::as_bool), str_of(&p, "default_avatar_id")) {
                (Some(false) | None, Some(avatar)) => {
                    Some(format!("https://avatars.yandex.net/get-yapic/{avatar}/islands-200"))
                }
                _ => None,
            };
            Ok(Some(json!({ "id": p.get("id"), "name": name, "email": email, "emailVerified": false, "image": image })))
        })
    });
    c
}

/// HubSpot (email only: HubSpot exposes no display name or picture).
pub fn hubspot(options: BaseProviderOptions) -> GenericOAuthConfig {
    let mut c = base("hubspot", options, &["oauth"]);
    c.account_subject = Some(subject("id"));
    c.authorization_url = Some("https://app.hubspot.com/oauth/authorize".into());
    c.token_url = Some("https://api.hubapi.com/oauth/v1/token".into());
    c.get_user_info = user_info(|tokens| {
        Box::pin(async move {
            let url =
                format!("https://api.hubapi.com/oauth/v1/access-tokens/{}", tokens.access_token.unwrap_or_default());
            let Some(p) = fetch(&url, &[("content-type", "application/json".into())]).await else { return Ok(None) };
            let id = p
                .get("user_id")
                .filter(|v| !v.is_null())
                .or_else(|| p.get("signed_access_token").and_then(|s| s.get("userId")))
                .and_then(|v| oauth2::subject_from(Some(v)));
            let Some(id) = id else { return Ok(None) };
            Ok(Some(json!({ "id": id, "name": p.get("user"), "email": p.get("user"), "emailVerified": false })))
        })
    });
    c
}

/// Patreon.
pub fn patreon(options: BaseProviderOptions) -> GenericOAuthConfig {
    let mut c = base("patreon", options, &["identity[email]"]);
    c.account_subject = Some(subject("id"));
    c.authorization_url = Some("https://www.patreon.com/oauth2/authorize".into());
    c.token_url = Some("https://www.patreon.com/api/oauth2/token".into());
    c.get_user_info = user_info(|tokens| {
        Box::pin(async move {
            let headers = [oauth2::bearer(tokens.access_token.as_deref())];
            let url = "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified";
            let Some(p) = fetch(url, &headers).await else { return Ok(None) };
            let data = p.get("data").cloned().unwrap_or_default();
            let attrs = data.get("attributes").cloned().unwrap_or_default();
            Ok(Some(json!({
                "id": data.get("id"),
                "name": attrs.get("full_name"),
                "email": attrs.get("email"),
                "image": attrs.get("image_url"),
                "emailVerified": attrs.get("is_email_verified").and_then(Value::as_bool).unwrap_or(false),
            })))
        })
    });
    c
}

/// Gumroad.
pub fn gumroad(options: BaseProviderOptions) -> GenericOAuthConfig {
    let mut c = base("gumroad", options, &["view_profile"]);
    c.account_subject = Some(subject("id"));
    c.authorization_url = Some("https://gumroad.com/oauth/authorize".into());
    c.token_url = Some("https://api.gumroad.com/oauth/token".into());
    c.get_user_info = user_info(|tokens| {
        Box::pin(async move {
            let headers = [oauth2::bearer(tokens.access_token.as_deref())];
            let Some(p) = fetch("https://api.gumroad.com/v2/user", &headers).await else { return Ok(None) };
            let Some(user) = p.get("user").filter(|_| p.get("success") == Some(&Value::Bool(true))) else {
                return Ok(None);
            };
            Ok(Some(json!({
                "id": user.get("user_id"),
                "name": user.get("name"),
                "email": user.get("email"),
                "image": user.get("profile_url"),
                "emailVerified": false,
            })))
        })
    });
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets() {
        let o = || BaseProviderOptions::new("id", "secret");
        assert_eq!(
            auth0("tenant.auth0.com", o()).unwrap().discovery_url.as_deref(),
            Some("https://tenant.auth0.com/.well-known/openid-configuration")
        );
        assert_eq!(
            okta("https://x.okta.com/oauth2/default/", o()).discovery_url.as_deref(),
            Some("https://x.okta.com/oauth2/default/.well-known/openid-configuration")
        );
        assert!(microsoft_entra_id("common", o()).is_err());
        let entra = microsoft_entra_id("0D9B1B0C-1111-2222-3333-444455556666", o()).unwrap();
        assert!(entra.token_url.unwrap().contains("/0d9b1b0c-1111-2222-3333-444455556666/"));
        assert_eq!(line(Some("line-jp"), o()).provider_id, "line-jp");
        let custom = BaseProviderOptions { scopes: Some(vec!["a".into()]), ..o() };
        assert_eq!(slack(custom).scopes, ["a"]);
    }
}
