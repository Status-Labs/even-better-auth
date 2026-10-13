//! OAuth user provisioning and account linking (`oauth2/link-account.ts`, `oauth2/utils.ts`).

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::state::{LinkData, default_error_url, redirect_on_error};
use super::{OAuth2Tokens, OAuth2UserInfo};
use crate::api::EndpointContext;
use crate::api::routes::email_verification::{create_email_verification_token, verification_url};
use crate::context::AuthContext;
use crate::cookies::{merged_account, set_account_cookie};
use crate::crypto::{symmetric_decrypt, symmetric_encrypt};
use crate::db::{InputAction, Record, parse_input};
use crate::error::{ApiError, Error, Result};
use crate::options::UserTokenEmail;
use crate::types::{Model, SessionWithUser, User};
use crate::utils::date;
use crate::utils::validate_user_info::{UserSource, ValidateUserInfoAction, assert_valid_user_info};

/// Callback error codes (`OAUTH_CALLBACK_ERROR_CODES`).
pub mod error_codes {
    pub const NO_CODE: &str = "no_code";
    pub const PROVIDER_NOT_FOUND: &str = "oauth_provider_not_found";
    pub const ISSUER_MISMATCH: &str = "issuer_mismatch";
    pub const INVALID_CODE: &str = "invalid_code";
    pub const NONCE_BINDING_MISSING: &str = "nonce_binding_missing";
    pub const UNABLE_TO_GET_USER_INFO: &str = "unable_to_get_user_info";
    pub const NO_CALLBACK_URL: &str = "no_callback_url";
    pub const UNABLE_TO_LINK_ACCOUNT: &str = "unable_to_link_account";
    pub const EMAIL_DOES_NOT_MATCH: &str = "email_does_not_match";
    pub const ACCOUNT_ALREADY_LINKED_TO_DIFFERENT_USER: &str = "account_already_linked_to_different_user";
    pub const EMAIL_NOT_FOUND: &str = "email_not_found";
    pub const EMAIL_NOT_VERIFIED: &str = "email_not_verified";
}

fn is_likely_encrypted(token: &str) -> bool {
    token.starts_with("$ba$")
        || (token.len().is_multiple_of(2) && !token.is_empty() && token.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Encrypt an OAuth token for storage when `account.encrypt_oauth_tokens` is on (`setTokenUtil`).
pub fn set_token_util(token: Option<&str>, auth: &AuthContext) -> Result<Option<String>> {
    match token {
        Some(t) if auth.options.account.encrypt_oauth_tokens && !t.is_empty() => {
            Ok(Some(symmetric_encrypt(&auth.secret_config, t)?))
        }
        other => Ok(other.map(str::to_owned)),
    }
}

/// Decrypt a stored OAuth token (`decryptOAuthToken`); plaintext tokens pass through.
pub fn decrypt_oauth_token(token: &str, auth: &AuthContext) -> Result<String> {
    if token.is_empty() || !auth.options.account.encrypt_oauth_tokens || !is_likely_encrypted(token) {
        return Ok(token.to_owned());
    }
    symmetric_decrypt(&auth.secret_config, token)
}

/// Account columns from a provider response.
#[derive(Debug, Clone, Default)]
pub struct OAuthAccountData {
    pub provider_id: String,
    pub account_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub scope: Option<String>,
}

impl OAuthAccountData {
    pub fn from_tokens(provider_id: &str, account_id: &str, tokens: &OAuth2Tokens) -> Self {
        Self {
            provider_id: provider_id.into(),
            account_id: account_id.into(),
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            id_token: tokens.id_token.clone(),
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: Some(tokens.scopes.join(",")),
        }
    }

    /// Token columns (encrypted as configured), omitting absent values.
    fn token_record(&self, auth: &AuthContext) -> Result<Record> {
        let mut r = Record::new();
        r.insert("providerId".into(), self.provider_id.clone().into());
        put_opt(&mut r, "idToken", self.id_token.clone());
        put_opt(&mut r, "accessToken", set_token_util(self.access_token.as_deref(), auth)?);
        put_opt(&mut r, "refreshToken", set_token_util(self.refresh_token.as_deref(), auth)?);
        if let Some(d) = self.access_token_expires_at {
            r.insert("accessTokenExpiresAt".into(), date::to_value(d));
        }
        if let Some(d) = self.refresh_token_expires_at {
            r.insert("refreshTokenExpiresAt".into(), date::to_value(d));
        }
        Ok(r)
    }
}

fn put_opt(r: &mut Record, key: &str, value: Option<String>) {
    if let Some(v) = value {
        r.insert(key.into(), v.into());
    }
}

/// Additional user fields from a mapped provider profile
/// (`parseAdditionalUserInputFromProviderProfile`).
pub fn additional_user_fields(
    auth: &AuthContext,
    user_info: &OAuth2UserInfo,
    action: InputAction,
) -> Result<Record, ApiError> {
    const CORE: &[&str] = &["id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"];
    let Some(table) = auth.schema.table("user") else { return Ok(Record::new()) };
    let allowed: Record = user_info
        .extra
        .iter()
        .filter(|(k, _)| table.fields.iter().find(|(n, _)| n == *k).is_none_or(|(_, f)| f.input))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    parse_input(table, &allowed, action, CORE)
}

/// Result of [`handle_oauth_user_info`].
#[derive(Debug, Clone, Default)]
pub struct OAuthUserInfoOutcome {
    pub data: Option<SessionWithUser>,
    pub error: Option<String>,
    pub is_register: bool,
}

impl OAuthUserInfoOutcome {
    fn error(e: &str, is_register: bool) -> Self {
        Self { data: None, error: Some(e.into()), is_register }
    }
}

/// Inputs for [`handle_oauth_user_info`]. `user_info.email` must be set.
#[derive(Debug, Clone)]
pub struct HandleOAuthUserInfo {
    pub user_info: OAuth2UserInfo,
    pub account: OAuthAccountData,
    pub callback_url: Option<String>,
    pub disable_sign_up: bool,
    pub override_user_info: bool,
    pub is_trusted_provider: bool,
    /// The raw provider profile, passed to `validate_user_info`.
    pub profile: Option<Value>,
}

/// The provider identity as a user record for `validate_user_info`.
fn validation_user(user_info: &OAuth2UserInfo, user_id: Option<&str>) -> Record {
    let mut user = user_info.extra.clone();
    put_opt(&mut user, "name", user_info.name.clone());
    put_opt(&mut user, "email", user_info.email.as_deref().map(str::to_lowercase));
    put_opt(&mut user, "image", user_info.image.clone());
    user.insert("emailVerified".into(), user_info.email_verified.into());
    if let Some(id) = user_id {
        user.insert("id".into(), id.into());
    }
    user
}

fn db_error(ctx: &EndpointContext, e: Error) -> ApiError {
    match e {
        Error::Api(api) => api,
        e => {
            tracing::error!(error = %e, "Better auth was unable to query your database");
            redirect_on_error(&default_error_url(ctx), "internal_server_error", None)
        }
    }
}

/// Find or create the user for a provider identity, link or refresh the account, and
/// create a session (`handleOAuthUserInfo`).
pub async fn handle_oauth_user_info(
    ctx: &EndpointContext,
    opts: HandleOAuthUserInfo,
) -> Result<OAuthUserInfoOutcome, ApiError> {
    let auth = ctx.auth.clone();
    let ia = &auth.internal_adapter;
    let HandleOAuthUserInfo {
        user_info,
        account,
        callback_url,
        disable_sign_up,
        override_user_info,
        is_trusted_provider,
        profile,
    } = opts;
    let source = UserSource::oauth(&account.provider_id, profile);
    let validator = auth.options.user.validate_user_info.as_ref();
    let email = user_info.email.clone().unwrap_or_default().to_lowercase();

    let owned =
        ia.find_account_by_key(&account.provider_id, &account.account_id).await.map_err(|e| db_error(ctx, e))?;
    let db_user = match owned {
        Some(acc) => match ia.find_user_by_id(&acc.user_id).await.map_err(|e| db_error(ctx, e))? {
            Some(user) => Some((user, Some(acc.clone()), vec![acc])),
            None => {
                tracing::error!(
                    "OAuth account references a missing user. Repair the account before retrying authentication."
                );
                return Ok(OAuthUserInfoOutcome::error("unable to link account", false));
            }
        },
        None => ia
            .find_user_by_email_with_accounts(&email)
            .await
            .map_err(|e| db_error(ctx, e))?
            .map(|(user, accounts)| (user, None, accounts)),
    };
    let is_register = db_user.is_none();
    let mut user: Option<User> = db_user.as_ref().map(|(u, _, _)| u.clone());

    if let Some((db, linked, accounts)) = &db_user {
        let linked = linked.clone().or_else(|| {
            accounts
                .iter()
                .find(|a| a.provider_id == account.provider_id && a.account_id == account.account_id)
                .cloned()
        });
        let promote_verified = user_info.email_verified && !db.email_verified && email == db.email;
        match linked {
            None => {
                let linking = &auth.options.account.account_linking;
                let trusted = is_trusted_provider || linking.trusted_providers.contains(&account.provider_id);
                if (!trusted && !user_info.email_verified)
                    || (linking.require_local_email_verified && !db.email_verified)
                    || !linking.enabled
                    || linking.disable_implicit_linking
                {
                    if cfg!(debug_assertions) {
                        tracing::warn!(
                            "User already exist but account isn't linked to {}. To read more about how account linking works in Better Auth see https://www.better-auth.com/docs/concepts/users-accounts#account-linking.",
                            account.provider_id
                        );
                    }
                    return Ok(OAuthUserInfoOutcome::error("account not linked", false));
                }
                let candidate = validation_user(&user_info, Some(&db.id));
                assert_valid_user_info(validator, &candidate, &source, ValidateUserInfoAction::LinkAccount).await?;
                let mut record = account.token_record(&auth)?;
                record.insert("accountId".into(), account.account_id.clone().into());
                record.insert("userId".into(), db.id.clone().into());
                put_opt(&mut record, "scope", account.scope.clone());
                match ia.link_account(record).await {
                    Ok(created) => {
                        if auth.options.account.store_account_cookie {
                            set_account_cookie(ctx, &created.to_record());
                        }
                    }
                    Err(Error::Api(e)) => return Err(e),
                    Err(e) => {
                        tracing::error!(error = %e, "Unable to link account");
                        return Ok(OAuthUserInfoOutcome::error("unable to link account", false));
                    }
                }
                if promote_verified {
                    ia.update_user(&db.id, verified_record()).await?;
                }
                if let Some(updated) = apply_update_user_info_on_link(ctx, &db.id, &user_info).await {
                    user = Some(updated);
                }
            }
            Some(linked) => {
                // Re-validate returning provider users against their fresh profile.
                let candidate = validation_user(&user_info, Some(&db.id));
                assert_valid_user_info(validator, &candidate, &source, ValidateUserInfoAction::SignIn).await?;
                if auth.options.account.store_account_cookie {
                    let fresh = if auth.options.account.update_account_on_sign_in != Some(false) {
                        account.token_record(&auth)?
                    } else {
                        Record::new()
                    };
                    set_account_cookie(ctx, &merged_account(&linked, &fresh));
                }
                if auth.options.account.update_account_on_sign_in != Some(false) {
                    let fresh = account.token_record(&auth)?;
                    if ia.update_account(&linked.id, fresh).await?.is_none() {
                        return Ok(OAuthUserInfoOutcome::error("unable to update account", false));
                    }
                }
                if promote_verified {
                    ia.update_user(&db.id, verified_record()).await?;
                }
            }
        }
        if override_user_info {
            let mut data = additional_user_fields(&auth, &user_info, InputAction::Update)?;
            put_opt(&mut data, "name", user_info.name.clone());
            put_opt(&mut data, "image", user_info.image.clone());
            data.insert("email".into(), email.clone().into());
            let verified = if email == db.email {
                db.email_verified || user_info.email_verified
            } else {
                user_info.email_verified
            };
            data.insert("emailVerified".into(), verified.into());
            match ia.update_user(&db.id, data).await? {
                Some(u) => user = Some(u),
                None => tracing::warn!(
                    "Could not update user info during OAuth sign in; preserving existing user for session."
                ),
            }
        }
    } else {
        if disable_sign_up {
            return Ok(OAuthUserInfoOutcome::error("signup disabled", false));
        }
        let created = async {
            let mut data = additional_user_fields(&auth, &user_info, InputAction::Create).map_err(Error::Api)?;
            data.insert("name".into(), user_info.name.clone().unwrap_or_default().into());
            put_opt(&mut data, "image", user_info.image.clone());
            data.insert("email".into(), email.clone().into());
            data.insert("emailVerified".into(), user_info.email_verified.into());
            let mut acc = account.token_record(&auth)?;
            acc.insert("accountId".into(), account.account_id.clone().into());
            put_opt(&mut acc, "scope", account.scope.clone());
            ia.create_oauth_user(data, acc, &source).await
        }
        .await;
        match created {
            Ok((u, created)) => {
                if auth.options.account.store_account_cookie {
                    set_account_cookie(ctx, &created.to_record());
                }
                user = Some(u);
            }
            Err(Error::Api(e)) => return Err(e),
            Err(e) => {
                tracing::error!(error = %e, "Unable to create OAuth user");
                return Ok(OAuthUserInfoOutcome::error("unable to create user", false));
            }
        }
    }
    let Some(user) = user else {
        return Ok(OAuthUserInfoOutcome::error("unable to create user", false));
    };

    let require_verification = super::find_provider(ctx, &account.provider_id)
        .map(|p| p.options().require_email_verification)
        .unwrap_or(false);
    let ev = &auth.options.email_verification;
    if is_register && !user.email_verified && ev.send_on_sign_up.unwrap_or(require_verification) {
        dispatch_verification_email(ctx, &user, callback_url.as_deref()).await;
    }
    if require_verification && !user.email_verified {
        if !is_register && ev.send_on_sign_in {
            dispatch_verification_email(ctx, &user, callback_url.as_deref()).await;
        }
        return Ok(OAuthUserInfoOutcome::error(error_codes::EMAIL_NOT_VERIFIED, is_register));
    }

    let session = match ia.create_session(&user.id, false, None).await {
        Ok(s) => s,
        Err(Error::Api(e)) if e.code().is_some() => return Err(e),
        Err(e) => {
            tracing::error!(error = %e, "unable to create session");
            return Ok(OAuthUserInfoOutcome::error("unable to create session", false));
        }
    };
    Ok(OAuthUserInfoOutcome { data: Some(SessionWithUser { session, user }), error: None, is_register })
}

fn verified_record() -> Record {
    let mut r = Record::new();
    r.insert("emailVerified".into(), Value::Bool(true));
    r
}

async fn dispatch_verification_email(ctx: &EndpointContext, user: &User, callback_url: Option<&str>) {
    let opts = &ctx.auth.options.email_verification;
    let Some(send) = &opts.send_verification_email else { return };
    let result = async {
        let token = create_email_verification_token(&ctx.auth.secret, &user.email, None, opts.expires_in, None)?;
        let url = verification_url(ctx, &token, callback_url);
        let request_headers = ctx.is_request.then(|| ctx.headers());
        send.call(UserTokenEmail { user: user.clone(), url, token, request_headers }).await.map_err(ApiError::from)
    }
    .await;
    if let Err(e) = result {
        tracing::error!(error = %e, "Failed to send OAuth verification email");
    }
}

/// Copy the linked provider's profile onto the user when
/// `account_linking.update_user_info_on_link` is set (`applyUpdateUserInfoOnLink`).
pub async fn apply_update_user_info_on_link(
    ctx: &EndpointContext,
    user_id: &str,
    user_info: &OAuth2UserInfo,
) -> Option<User> {
    let auth = &ctx.auth;
    if !auth.options.account.account_linking.update_user_info_on_link {
        return None;
    }
    let mut data = match additional_user_fields(auth, user_info, InputAction::Update) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "Could not update user info on account link");
            return None;
        }
    };
    put_opt(&mut data, "name", user_info.name.clone());
    put_opt(&mut data, "image", user_info.image.clone());
    if data.is_empty() {
        return None;
    }
    match auth.internal_adapter.update_user(user_id, data).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "Could not update user info on account link");
            None
        }
    }
}

/// Failure of [`link_oauth_account`]: an error code for the redirect plus an optional message.
#[derive(Debug, Clone)]
pub struct LinkFailure {
    pub code: String,
    pub message: Option<String>,
}

fn link_failure(code: &str) -> LinkFailure {
    LinkFailure { code: code.into(), message: None }
}

/// Link a provider account to the user that started a link-social flow (`linkOAuthAccount`).
pub async fn link_oauth_account(
    ctx: &EndpointContext,
    link: &LinkData,
    user_info: &OAuth2UserInfo,
    account: &OAuthAccountData,
    scopes: &[String],
    profile: Option<Value>,
) -> Result<std::result::Result<(), LinkFailure>, ApiError> {
    let auth = ctx.auth.clone();
    let source = UserSource::oauth(&account.provider_id, profile);
    let candidate = validation_user(user_info, Some(&link.user_id));
    let validator = auth.options.user.validate_user_info.as_ref();
    if let Err(e) = assert_valid_user_info(validator, &candidate, &source, ValidateUserInfoAction::LinkAccount).await {
        let Some(code) = e.code().map(str::to_owned) else { return Err(e) };
        return Ok(Err(LinkFailure { code, message: e.message_str().map(str::to_owned) }));
    }
    let linking = &auth.options.account.account_linking;
    let trusted = linking.trusted_providers.contains(&account.provider_id);
    if (!trusted && !user_info.email_verified) || !linking.enabled {
        tracing::error!("Unable to link account - untrusted provider");
        return Ok(Err(link_failure(error_codes::UNABLE_TO_LINK_ACCOUNT)));
    }
    let email_matches = user_info.email.as_deref().map(str::to_lowercase) == Some(link.email.to_lowercase());
    if !email_matches && !linking.allow_different_emails {
        return Ok(Err(link_failure(error_codes::EMAIL_DOES_NOT_MATCH)));
    }
    let ia = &auth.internal_adapter;
    match ia.find_account_by_key(&account.provider_id, &account.account_id).await? {
        Some(existing) => {
            if existing.user_id != link.user_id {
                return Ok(Err(link_failure(error_codes::ACCOUNT_ALREADY_LINKED_TO_DIFFERENT_USER)));
            }
            let mut data = account.token_record(&auth)?;
            let merged = super::merge_scopes(existing.scope.as_deref(), scopes);
            if !merged.is_empty() {
                data.insert("scope".into(), merged.into());
            }
            ia.update_account(&existing.id, data).await?;
        }
        None => {
            let mut data = account.token_record(&auth)?;
            data.insert("userId".into(), link.user_id.clone().into());
            data.insert("accountId".into(), account.account_id.clone().into());
            data.insert("scope".into(), scopes.join(",").into());
            if let Err(e) = ia.create_account(data).await {
                tracing::error!(error = %e, "unable to link account");
                return Ok(Err(link_failure(error_codes::UNABLE_TO_LINK_ACCOUNT)));
            }
        }
    }
    apply_update_user_info_on_link(ctx, &link.user_id, user_info).await;
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::is_likely_encrypted;

    #[test]
    fn encrypted_detection() {
        assert!(is_likely_encrypted("$ba$1$abcd"));
        assert!(is_likely_encrypted("deadbeef"));
        assert!(!is_likely_encrypted("ya29.a0AfH6"));
        assert!(!is_likely_encrypted("abc"));
    }
}
