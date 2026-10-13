//! Sign-In with Ethereum (`plugins/siwe`, ERC-4361): `POST /siwe/nonce` issues a single-use
//! nonce, `POST /siwe/verify` checks the signed message against it and the configured
//! domain, then calls your signature verifier and signs the wallet's user in.

use std::any::Any;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use futures::future::BoxFuture;
use http::StatusCode;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

use crate::api::routes::util::{body_field_error, is_valid_email};
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::db::schema::OnDelete;
use crate::db::{Field, Record, TableExtension, Where};
use crate::error::{ApiError, Result, codes};
use crate::plugin::Plugin;
use crate::plugins::anonymous::placeholder_email as create_placeholder_email;
use crate::types::{SessionWithUser, User};
use crate::utils::validate_user_info::UserSource;

/// Arguments for [`SiweOptions::verify_message`].
#[derive(Debug, Clone)]
pub struct SiweVerifyMessageArgs {
    pub message: String,
    pub signature: String,
    /// EIP-55 checksummed address from the signed message.
    pub address: String,
    pub chain_id: u64,
    /// The CAIP-74 Cacao object TS passes along.
    pub cacao: Value,
}

#[derive(Debug, Clone)]
pub struct EnsLookupResult {
    pub name: String,
    pub avatar: String,
}

pub type NonceFn = Arc<dyn Fn() -> BoxFuture<'static, Result<String>> + Send + Sync>;
pub type VerifyMessageFn = Arc<dyn Fn(SiweVerifyMessageArgs) -> BoxFuture<'static, Result<bool>> + Send + Sync>;
pub type EnsLookupFn = Arc<dyn Fn(String) -> BoxFuture<'static, Result<Option<EnsLookupResult>>> + Send + Sync>;

#[derive(Clone)]
pub struct SiweOptions {
    /// The domain the signed message must name.
    pub domain: String,
    /// New users get `{address}@{domain}` instead of a placeholder address.
    pub email_domain_name: Option<String>,
    /// Allow sign-in without an email (default `true`).
    pub anonymous: bool,
    /// An ERC-4361 nonce: 8–250 alphanumeric characters.
    pub get_nonce: NonceFn,
    /// Verifies the signature (e.g. with an Ethereum library); the plugin checks the message.
    pub verify_message: VerifyMessageFn,
    pub ens_lookup: Option<EnsLookupFn>,
}

impl SiweOptions {
    pub fn new(domain: impl Into<String>, get_nonce: NonceFn, verify_message: VerifyMessageFn) -> Self {
        Self {
            domain: domain.into(),
            email_domain_name: None,
            anonymous: true,
            get_nonce,
            verify_message,
            ens_lookup: None,
        }
    }
}

const NONCE_PREFIX: &str = "siwe:";
/// MySQL schemas cap `verification.identifier` at 255 characters.
const NONCE_MAX_LENGTH: usize = 255 - NONCE_PREFIX.len();

fn is_valid_nonce(nonce: Option<&str>) -> bool {
    nonce.is_some_and(|n| (8..=NONCE_MAX_LENGTH).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn is_hex_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// EIP-55 mixed-case checksum encoding (`toChecksumAddress`).
pub fn to_checksum_address(address: &str) -> String {
    let lower = address.trim_start_matches("0x").to_lowercase();
    let hash = hex::encode(Keccak256::digest(lower.as_bytes()));
    let mut out = String::from("0x");
    for (c, h) in lower.chars().zip(hash.chars()) {
        if c.is_ascii_alphabetic() && h.to_digit(16).unwrap_or(0) >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The fields of an ERC-4361 message (`parseSiweMessage`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParsedSiweMessage {
    pub scheme: Option<String>,
    pub domain: Option<String>,
    pub address: Option<String>,
    pub uri: Option<String>,
    pub version: Option<String>,
    pub chain_id: Option<i64>,
    pub nonce: Option<String>,
    pub issued_at: Option<String>,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
}

pub fn parse_siwe_message(message: &str) -> ParsedSiweMessage {
    let mut out = ParsedSiweMessage::default();
    let lines: Vec<&str> = message.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
    if let Some(rest) = lines.first().and_then(|l| l.strip_suffix(" wants you to sign in with your Ethereum account:"))
    {
        let (scheme, domain) = match rest.split_once("://") {
            Some((s, d))
                if s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                    && s.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)) =>
            {
                (Some(s), d)
            }
            _ => (None, rest),
        };
        if !domain.is_empty() && !domain.chars().any(char::is_whitespace) {
            out.scheme = scheme.map(str::to_owned);
            out.domain = Some(domain.to_owned());
        }
    }
    if let Some(addr) = lines.get(1).map(|l| l.trim()).filter(|a| is_hex_address(a)) {
        out.address = Some(addr.to_owned());
    }
    for line in &lines {
        let Some((key, value)) = line.split_once(": ") else { continue };
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphabetic() || c == ' ') {
            continue;
        }
        let value = value.to_owned();
        match key {
            "URI" => out.uri = Some(value),
            "Version" => out.version = Some(value),
            "Chain ID" => {
                if let Ok(n) = value.parse::<i64>() {
                    out.chain_id = Some(n);
                }
            }
            "Nonce" => out.nonce = Some(value),
            "Issued At" => out.issued_at = Some(value),
            "Expiration Time" => out.expiration_time = Some(value),
            "Not Before" => out.not_before = Some(value),
            "Request ID" => out.request_id = Some(value),
            _ => {}
        }
    }
    out
}

/// Lowercased host (and port) without scheme or path (`normalizeSiweDomain`).
pub fn normalize_siwe_domain(domain: &str) -> String {
    let lower = domain.trim().to_lowercase();
    let without_scheme = match lower.split_once("://") {
        Some((s, rest))
            if s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+.-".contains(c)) =>
        {
            rest.to_owned()
        }
        _ => lower,
    };
    without_scheme.split('/').next().unwrap_or_default().to_owned()
}

fn mismatch() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
        "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID",
    )
}

struct Inner {
    options: SiweOptions,
}

async fn nonce(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    match ctx.body() {
        Value::Null => {}
        Value::Object(m) if m.is_empty() => {}
        _ => return Err(ApiError::bad_request(codes::VALIDATION_ERROR)),
    }
    let nonce = (inner.options.get_nonce)().await?;
    if !is_valid_nonce(Some(&nonce)) {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SIWE_INVALID_NONCE",
            format!("SIWE getNonce must return an ERC-4361 nonce: 8-{NONCE_MAX_LENGTH} alphanumeric characters."),
        ));
    }
    let expires_at = Utc::now() + Duration::minutes(15);
    ctx.auth.internal_adapter.create_verification_value(&format!("{NONCE_PREFIX}{nonce}"), &nonce, expires_at).await?;
    ctx.json(json!({ "nonce": nonce }))
}

struct VerifyBody {
    message: String,
    signature: String,
    email: Option<String>,
}

fn parse_verify_body(ctx: &EndpointContext, anonymous: bool) -> std::result::Result<VerifyBody, ApiError> {
    let Value::Object(body) = ctx.body() else { return Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT)) };
    if let Some(k) = body.keys().find(|k| !matches!(k.as_str(), "message" | "signature" | "email")) {
        return Err(body_field_error(k, "Unrecognized key"));
    }
    let required = |k: &str| match body.get(k).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_owned()),
        _ => Err(body_field_error(k, "Too small: expected string to have >=1 characters")),
    };
    let (message, signature) = (required("message")?, required("signature")?);
    let email = match body.get("email") {
        None | Some(Value::Null) => None,
        Some(Value::String(e)) if is_valid_email(e) => Some(e.clone()),
        Some(_) => return Err(body_field_error("email", "Invalid email address")),
    };
    if !anonymous && email.is_none() {
        return Err(body_field_error("email", "Email is required when the anonymous plugin option is disabled."));
    }
    Ok(VerifyBody { message, signature, email })
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

async fn find_user_for_wallet(ctx: &EndpointContext, wallet: &str, chain_id: i64) -> Result<(Option<User>, bool)> {
    let db = &ctx.auth.db;
    let exact = db.find_one("walletAddress", &[Where::eq("address", wallet), Where::eq("chainId", chain_id)]).await?;
    let row = match &exact {
        Some(row) => Some(row.clone()),
        None => db.find_one("walletAddress", &[Where::eq("address", wallet)]).await?,
    };
    let user = match row.as_ref().and_then(|r| r.get("userId")).and_then(Value::as_str) {
        Some(id) => ctx.auth.internal_adapter.find_user_by_id(id).await?,
        None => None,
    };
    Ok((user, exact.is_some()))
}

async fn add_wallet(ctx: &EndpointContext, user_id: &str, wallet: &str, chain_id: i64, primary: bool) -> Result<()> {
    let mut row = Record::new();
    row.insert("userId".into(), user_id.into());
    row.insert("address".into(), wallet.into());
    row.insert("chainId".into(), chain_id.into());
    row.insert("isPrimary".into(), primary.into());
    row.insert("createdAt".into(), crate::utils::date::now_value());
    ctx.auth.db.create("walletAddress", row, false).await?;
    let mut account = Record::new();
    account.insert("userId".into(), user_id.into());
    account.insert("providerId".into(), "siwe".into());
    account.insert("accountId".into(), format!("{wallet}:{chain_id}").into());
    ctx.auth.internal_adapter.create_account(account).await?;
    Ok(())
}

async fn create_wallet_user(
    inner: &Inner,
    ctx: &EndpointContext,
    wallet: &str,
    email: Option<String>,
) -> std::result::Result<User, ApiError> {
    let opts = &inner.options;
    let ia = &ctx.auth.internal_adapter;
    let normalized = email.map(|e| e.to_lowercase());
    let wallet_email = match &opts.email_domain_name {
        Some(domain) => format!("{wallet}@{domain}"),
        None => create_placeholder_email(wallet, "siwe"),
    };
    // SIWE proves wallet control, not email ownership: use the caller's email only when it
    // is unclaimed and atomically reserved, and fall back silently (no enumeration oracle).
    let mut user_email = wallet_email.clone();
    let mut claim = None;
    if !opts.anonymous
        && let Some(email) = &normalized
    {
        let identifier = format!("siwe-email-claim-{email}");
        let expires = Utc::now() + Duration::seconds(60);
        if ia.reserve_verification_value(&identifier, wallet, expires).await.unwrap_or(false) {
            claim = Some(identifier);
            if ia.find_user_by_email(email).await?.is_none() {
                user_email = email.clone();
            }
        }
    }
    let ens = match &opts.ens_lookup {
        Some(f) => f(wallet.to_owned()).await?,
        None => None,
    };
    let create = |email: String| {
        let mut data = Record::new();
        data.insert("name".into(), ens.as_ref().map_or_else(|| wallet.to_owned(), |e| e.name.clone()).into());
        data.insert("email".into(), email.into());
        data.insert("image".into(), ens.as_ref().map(|e| e.avatar.clone()).unwrap_or_default().into());
        async move { ia.create_user(data, &UserSource::method("siwe")).await }
    };
    let result = match create(user_email.clone()).await {
        Ok(user) => Ok(user),
        Err(err) if normalized.as_deref() == Some(user_email.as_str()) => {
            match ia.find_user_by_email(&user_email).await {
                Ok(Some(_)) => create(wallet_email).await,
                _ => Err(err),
            }
        }
        Err(err) => Err(err),
    };
    if let Some(identifier) = claim {
        let _ = ia.consume_verification_value(&identifier).await;
    }
    Ok(result?)
}

async fn verify(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let opts = &inner.options;
    let body = parse_verify_body(&ctx, opts.anonymous)?;
    match verify_inner(&inner, &ctx, body).await {
        Ok(out) => Ok(out),
        Err(crate::error::Error::Api(api)) => Err(api),
        Err(other) => Err(ApiError::message(StatusCode::UNAUTHORIZED, "Something went wrong. Please try again later.")
            .with_field("error", other.to_string())),
    }
}

async fn verify_inner(inner: &Inner, ctx: &EndpointContext, body: VerifyBody) -> Result<crate::api::EndpointOutput> {
    let opts = &inner.options;
    let parsed = parse_siwe_message(&body.message);
    if !is_valid_nonce(parsed.nonce.as_deref()) {
        return Err(mismatch().into());
    }
    let nonce = parsed.nonce.clone().unwrap_or_default();
    // Consume the single-use nonce before any signature work: the first concurrent request
    // wins, and a failed attempt burns it too.
    let consumed = ctx.auth.internal_adapter.consume_verification_value(&format!("{NONCE_PREFIX}{nonce}")).await?;
    if consumed.is_none() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
            "Unauthorized: Invalid or expired nonce",
        )
        .into());
    }
    // Bind the signed message to server state: signature recovery alone doesn't inspect it.
    let wallet = parsed.address.as_deref().filter(|a| is_hex_address(a)).map(to_checksum_address);
    let domain_matches =
        parsed.domain.as_deref().is_some_and(|d| normalize_siwe_domain(d) == normalize_siwe_domain(&opts.domain));
    let (Some(wallet), Some(chain_id)) = (wallet, parsed.chain_id.filter(|c| *c > 0)) else {
        return Err(mismatch().into());
    };
    if !domain_matches {
        return Err(mismatch().into());
    }
    let now = Utc::now();
    if let Some(expires) = parsed.expiration_time.as_deref().and_then(parse_time)
        && now >= expires
    {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
            "Unauthorized: SIWE message has expired",
        )
        .into());
    }
    if let Some(not_before) = parsed.not_before.as_deref().and_then(parse_time)
        && now < not_before
    {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
            "Unauthorized: SIWE message is not yet valid",
        )
        .into());
    }
    let cacao = json!({
        "h": { "t": "caip122" },
        "p": { "domain": opts.domain, "aud": opts.domain, "nonce": nonce, "iss": opts.domain, "version": "1" },
        "s": { "t": "eip191", "s": body.signature },
    });
    let args = SiweVerifyMessageArgs {
        message: body.message.clone(),
        signature: body.signature.clone(),
        address: wallet.clone(),
        chain_id: chain_id as u64,
        cacao,
    };
    if !(opts.verify_message)(args).await? {
        return Err(ApiError::message(StatusCode::UNAUTHORIZED, "Unauthorized: Invalid SIWE signature").into());
    }

    let (user, exact) = find_user_for_wallet(ctx, &wallet, chain_id).await?;
    let user = match user {
        Some(user) => {
            if !exact {
                add_wallet(ctx, &user.id, &wallet, chain_id, false).await?;
            }
            user
        }
        None => {
            let user = create_wallet_user(inner, ctx, &wallet, body.email).await?;
            add_wallet(ctx, &user.id, &wallet, chain_id, true).await?;
            user
        }
    };
    let session = ctx.auth.internal_adapter.create_session(&user.id, false, None).await?;
    let token = session.token.clone();
    set_session_cookie(ctx, &SessionWithUser { session, user: user.clone() }, None, None).await;
    Ok(crate::api::EndpointOutput::Json(json!({
        "token": token,
        "success": true,
        "user": { "id": user.id, "walletAddress": wallet, "chainId": chain_id },
    })))
}

pub struct Siwe {
    inner: Arc<Inner>,
}

pub fn siwe(options: SiweOptions) -> Arc<dyn Plugin> {
    Arc::new(Siwe { inner: Arc::new(Inner { options }) })
}

impl Plugin for Siwe {
    fn id(&self) -> &str {
        "siwe"
    }

    fn schema(&self) -> Vec<TableExtension> {
        vec![TableExtension {
            key: "walletAddress".into(),
            fields: vec![
                ("userId".into(), Field::string().references("user", "id", OnDelete::Cascade).indexed()),
                ("address".into(), Field::string()),
                ("chainId".into(), Field::number()),
                ("isPrimary".into(), Field::boolean().optional().default(false)),
                ("createdAt".into(), Field::date()),
            ],
            ..Default::default()
        }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b, c) = (self.inner.clone(), self.inner.clone(), self.inner.clone());
        vec![
            Endpoint::post("getSiweNonce", "/siwe/nonce", handler(move |ctx| nonce(a.clone(), ctx))),
            Endpoint::post("getNonce", "/siwe/get-nonce", handler(move |ctx| nonce(b.clone(), ctx))),
            Endpoint::post("verifySiweMessage", "/siwe/verify", handler(move |ctx| verify(c.clone(), ctx))),
        ]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum() {
        for a in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        ] {
            assert_eq!(to_checksum_address(&a.to_lowercase()), a);
        }
    }

    #[test]
    fn parses_messages() {
        let msg = "https://example.com wants you to sign in with your Ethereum account:\r\n0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\n\nI accept: the terms\n\nURI: https://example.com\nVersion: 1\nChain ID: 1\nNonce: abcdefgh12\nIssued At: 2024-01-01T00:00:00Z";
        let p = parse_siwe_message(msg);
        assert_eq!(p.scheme.as_deref(), Some("https"));
        assert_eq!(p.domain.as_deref(), Some("example.com"));
        assert_eq!(p.address.as_deref(), Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
        assert_eq!(p.chain_id, Some(1));
        assert_eq!(p.nonce.as_deref(), Some("abcdefgh12"));
        assert_eq!(normalize_siwe_domain("HTTPS://Example.com:8080/path"), "example.com:8080");
    }
}
