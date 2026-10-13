//! The `account_data` cookie (`storeAccountCookie`): the OAuth account, including its
//! (possibly encrypted) tokens, as a chunked JWE.

use super::session::{clean_chunks, get_chunked_cookie, set_chunked};
use crate::api::EndpointContext;
use crate::crypto;
use crate::db::Record;
use crate::types::{Account, Model};

const ACCOUNT_SALT: &str = "better-auth-account";

/// Write `account` to the account cookie.
pub fn set_account_cookie(ctx: &EndpointContext, account: &Record) {
    let auth = &ctx.auth;
    let cookie = &auth.cookies.account_data;
    let max_age = cookie.attributes.max_age.unwrap_or(300);
    match crypto::symmetric_encode_jwt(account, &auth.secret_config, ACCOUNT_SALT, max_age) {
        Ok(data) => set_chunked(ctx, &cookie.name, &data, &cookie.attributes),
        Err(e) => tracing::error!(error = %e, "failed to encode account cookie"),
    }
}

/// The account stored in the request's account cookie, if valid.
pub fn get_account_cookie(ctx: &EndpointContext) -> Option<Account> {
    let auth = &ctx.auth;
    let value = get_chunked_cookie(ctx, &auth.cookies.account_data.name)?;
    let mut claims = crypto::symmetric_decode_jwt(&value, &auth.secret_config, ACCOUNT_SALT)?;
    for k in ["iat", "exp", "jti"] {
        claims.remove(k);
    }
    Account::from_record(claims).ok()
}

/// With a server-side account store, the account cookie must belong to the session user.
pub fn bind_account_cookie_to_session_user(ctx: &EndpointContext) -> bool {
    !ctx.auth.options.stateless
}

/// Keep the account cookie alive alongside a refreshed session: re-issue it when it belongs
/// to `user_id` (or binding is off), otherwise drop it. Skipped when this response already
/// writes a fresh account cookie.
pub(super) fn sync_account_cookie(ctx: &EndpointContext, user_id: &str) {
    let auth = &ctx.auth;
    if !auth.options.account.store_account_cookie || ctx.has_pending_cookie(&auth.cookies.account_data.name) {
        return;
    }
    let Some(account) = get_account_cookie(ctx) else { return };
    if !bind_account_cookie_to_session_user(ctx) || account.user_id == user_id {
        set_account_cookie(ctx, &account.to_record());
    } else {
        let cookie = &auth.cookies.account_data;
        clean_chunks(ctx, &cookie.name, &cookie.attributes);
        ctx.expire_cookie(cookie);
    }
}

/// `account.to_record()` merged with `update`, for re-issuing the cookie after a token change.
pub fn merged_account(account: &Account, update: &Record) -> Record {
    let mut record = account.to_record();
    for (k, v) in update {
        record.insert(k.clone(), v.clone());
    }
    record
}
