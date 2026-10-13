//! Backup codes (`two-factor/backup-codes`): `POST /two-factor/verify-backup-code`,
//! `POST /two-factor/generate-backup-codes` and the server-only `viewBackupCodes`.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS, Inner, TABLE, assert_not_locked, error_codes as e, find_row, record_failure,
    require_password, reset_failures, two_factor_enabled, verify_two_factor,
};
use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::crypto::{self, SecretConfig};
use crate::db::{Record, Where};
use crate::error::{ApiError, Error, Result};

pub type CodesFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// How backup codes are stored.
#[derive(Clone, Default)]
pub enum StoreBackupCodes {
    Plain,
    /// Encrypted with the auth secret (default).
    #[default]
    Encrypted,
    Custom {
        encrypt: CodesFn,
        decrypt: CodesFn,
    },
}

#[derive(Clone, Default)]
pub struct BackupCodeOptions {
    /// Number of codes (default 10).
    pub amount: Option<usize>,
    /// Characters per code before the dash (default 10).
    pub length: Option<usize>,
    pub custom_generate: Option<Arc<dyn Fn() -> Vec<String> + Send + Sync>>,
    pub store: StoreBackupCodes,
    /// Override the plugin-level `allow_passwordless` for these endpoints.
    pub allow_passwordless: Option<bool>,
}

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Fresh codes like `abcde-fghij`.
pub(super) fn generate(options: &BackupCodeOptions) -> Vec<String> {
    if let Some(custom) = &options.custom_generate {
        return custom();
    }
    (0..options.amount.unwrap_or(10))
        .map(|_| {
            let code = crypto::random_string(options.length.unwrap_or(10), ALPHABET);
            let split = code.len().min(5);
            format!("{}-{}", &code[..split], &code[split..])
        })
        .collect()
}

pub(super) fn encode(codes: &[String], secret: &SecretConfig, options: &BackupCodeOptions) -> Result<String> {
    let json = serde_json::to_string(codes)?;
    Ok(match &options.store {
        StoreBackupCodes::Plain => json,
        StoreBackupCodes::Encrypted => crypto::symmetric_encrypt(secret, &json)?,
        StoreBackupCodes::Custom { encrypt, .. } => encrypt(&json),
    })
}

fn decode(stored: &str, secret: &SecretConfig, options: &BackupCodeOptions) -> Result<Option<Vec<String>>> {
    let json = match &options.store {
        StoreBackupCodes::Plain => stored.to_owned(),
        StoreBackupCodes::Encrypted => crypto::symmetric_decrypt(secret, stored)?,
        StoreBackupCodes::Custom { decrypt, .. } => decrypt(stored),
    };
    Ok(serde_json::from_str(&json).ok())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyBody {
    code: String,
    disable_session: Option<bool>,
}

async fn verify_backup_code(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: VerifyBody = ctx.parse_body()?;
    let verification = verify_two_factor(&ctx).await?;
    let sign_in = verification.is_sign_in();
    let row = find_row(&ctx, &verification.user.id)
        .await?
        .ok_or_else(|| ApiError::bad_request(e::BACKUP_CODES_NOT_ENABLED))?;
    if sign_in {
        assert_not_locked(&ctx, &inner, &row).await?;
    }
    let attempt = verification.begin_attempt(&ctx, DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS).await?;
    let options = &inner.options.backup_codes;
    let codes = match decode(&row.backup_codes, &ctx.auth.secret_config, options) {
        Ok(codes) => codes,
        Err(err) => {
            if let Some(a) = &attempt {
                a.restore(&ctx).await;
            }
            return Err(err.into());
        }
    };
    let Some(codes) = codes.filter(|c| c.contains(&body.code)) else {
        if let Some(a) = &attempt {
            a.record_failure(&ctx).await;
        }
        if sign_in {
            record_failure(&ctx, &inner, &row).await?;
        }
        return Err(ApiError::unauthorized(e::INVALID_BACKUP_CODE));
    };
    let remaining: Vec<String> = codes.into_iter().filter(|c| c != &body.code).collect();
    let mut update = Record::new();
    update.insert("backupCodes".into(), encode(&remaining, &ctx.auth.secret_config, options)?.into());
    // Compare-and-swap on the stored codes so a code can only be spent once.
    let guard = [Where::eq("id", row.id.clone()), Where::eq("backupCodes", row.backup_codes.clone())];
    if ctx.auth.db.update_many(TABLE, &guard, update).await? == 0 {
        return Err(ApiError::message(http::StatusCode::CONFLICT, "Failed to verify backup code. Please try again."));
    }
    if sign_in {
        reset_failures(&ctx, &inner, &row).await?;
    }
    if body.disable_session != Some(true) {
        return verification.valid(&ctx, &inner).await;
    }
    let token = verification.session.as_ref().map(|s| Value::String(s.session.token.clone())).unwrap_or(Value::Null);
    ctx.json(json!({ "token": token, "user": ctx.auth.user_output(&verification.user) }))
}

#[derive(Deserialize)]
struct GenerateBody {
    password: Option<String>,
}

async fn generate_backup_codes(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body: GenerateBody = ctx.parse_body()?;
    let user = &session.user;
    if !two_factor_enabled(user) {
        return Err(ApiError::bad_request(e::TWO_FACTOR_NOT_ENABLED));
    }
    let options = &inner.options.backup_codes;
    require_password(&ctx, &user.id, inner.passwordless(options.allow_passwordless), body.password.as_deref()).await?;
    let row = find_row(&ctx, &user.id).await?.ok_or_else(|| ApiError::bad_request(e::TWO_FACTOR_NOT_ENABLED))?;
    let codes = generate(options);
    let mut update = Record::new();
    update.insert("backupCodes".into(), encode(&codes, &ctx.auth.secret_config, options)?.into());
    ctx.auth.db.update(TABLE, &[Where::eq("id", row.id)], update).await?;
    ctx.json(json!({ "status": true, "backupCodes": codes }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ViewBody {
    user_id: Value,
}

async fn view_backup_codes(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: ViewBody = ctx.parse_body()?;
    let user_id = match body.user_id {
        Value::String(s) => s,
        other => other.to_string(),
    };
    let row = find_row(&ctx, &user_id).await?.ok_or_else(|| ApiError::bad_request(e::BACKUP_CODES_NOT_ENABLED))?;
    let codes = decode(&row.backup_codes, &ctx.auth.secret_config, &inner.options.backup_codes)
        .map_err(|e| Error::Crypto(e.to_string()))?
        .ok_or_else(|| ApiError::bad_request(e::INVALID_BACKUP_CODE))?;
    ctx.json(json!({ "status": true, "backupCodes": codes }))
}

pub(super) fn endpoints(inner: &Arc<Inner>) -> Vec<Endpoint> {
    let (a, b, c) = (inner.clone(), inner.clone(), inner.clone());
    vec![
        Endpoint::post(
            "verifyBackupCode",
            "/two-factor/verify-backup-code",
            handler(move |ctx| verify_backup_code(a.clone(), ctx)),
        ),
        Endpoint::post(
            "generateBackupCodes",
            "/two-factor/generate-backup-codes",
            handler(move |ctx| generate_backup_codes(b.clone(), ctx)),
        ),
        Endpoint::post(
            "viewBackupCodes",
            "/two-factor/view-backup-codes",
            handler(move |ctx| view_backup_codes(c.clone(), ctx)),
        )
        .server_only(),
    ]
}
