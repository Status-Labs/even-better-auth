//! Auth-specific database operations (`createInternalAdapter`), with database hooks applied.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::hooks::{BeforeOutcome, DatabaseHooks, Operation};
use super::{Db, FindManyQuery, Record, SortBy, SortDirection, Where};
use crate::api::current_request;
use crate::crypto;
use crate::error::{ApiError, Result};
use crate::options::StoreIdentifier;
use crate::storage::SecondaryStorage;
use crate::types::{Account, Model, Session, SessionWithUser, User, Verification};
use crate::utils::validate_user_info::{UserSource, ValidateUserInfoAction, assert_valid_user_info};
use crate::utils::{date, ip};

/// Configuration the internal adapter needs from the options.
#[derive(Clone)]
pub(crate) struct InternalConfig {
    pub session_expires_in: i64,
    pub store_identifier: StoreIdentifier,
    pub disable_verification_cleanup: bool,
    pub ip: ip::IpConfig,
    pub storage: Option<Arc<dyn SecondaryStorage>>,
    pub store_session_in_db: bool,
    pub preserve_session_in_db: bool,
    pub verification_in_db: bool,
    pub validate_user_info: Option<crate::utils::validate_user_info::ValidateUserInfoFn>,
}

/// An entry of the `active-sessions-{userId}` list in secondary storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRef {
    token: String,
    /// Milliseconds since the epoch.
    #[serde(rename = "expiresAt")]
    expires_at: i64,
}

/// Whole seconds until `expires_ms`, never negative.
fn ttl_secs(expires_ms: i64, now_ms: i64) -> u64 {
    u64::try_from((expires_ms - now_ms) / 1000).unwrap_or(0)
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn active_sessions_key(user_id: &str) -> String {
    format!("active-sessions-{user_id}")
}

fn verification_key(identifier: &str) -> String {
    format!("verification:{identifier}")
}

/// Log, but otherwise ignore, a failed secondary-storage write that runs after commit.
fn log_after_commit(result: Result<()>, what: &str) -> Result<()> {
    if let Err(e) = result {
        tracing::error!(error = %e, "failed to {what} in secondary storage");
    }
    Ok(())
}

/// Values for [`InternalAdapter::create_session`] beyond the defaults.
#[derive(Default, Clone)]
pub struct SessionOverrides {
    pub data: Record,
    /// Apply `data` after the generated fields, overriding `expiresAt`, `token`, etc.
    pub override_all: bool,
}

#[derive(Clone)]
pub struct InternalAdapter {
    db: Db,
    hooks: Arc<DatabaseHooks>,
    config: InternalConfig,
}

fn record(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Record {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

impl InternalAdapter {
    pub(crate) fn new(db: Db, hooks: Arc<DatabaseHooks>, config: InternalConfig) -> Self {
        Self { db, hooks, config }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    // ---- hook-aware primitives (with-hooks.ts) -------------------------------------

    async fn run_before(&self, model: &str, op: Operation, mut data: Record) -> Result<Option<Record>> {
        if let Some(hooks) = self.hooks.get(model, op) {
            for hook in &hooks.before {
                match hook(data.clone()).await? {
                    BeforeOutcome::Continue => {}
                    BeforeOutcome::Abort => return Ok(None),
                    BeforeOutcome::Merge(extra) => data.extend(extra),
                }
            }
        }
        Ok(Some(data))
    }

    async fn run_after(&self, model: &str, op: Operation, data: &Record) -> Result<()> {
        if let Some(hooks) = self.hooks.get(model, op) {
            // After hooks see committed data: inside a transaction they run once it commits.
            for hook in &hooks.after {
                super::after_commit(hook(data.clone())).await?;
            }
        }
        Ok(())
    }

    /// Create a row, running `before`/`after` create hooks. Returns `None` if a hook aborted.
    pub async fn create_with_hooks(&self, model: &str, data: Record) -> Result<Option<Record>> {
        let Some(data) = self.run_before(model, Operation::Create, data).await? else {
            return Ok(None);
        };
        let created = self.db.create(model, data, false).await?;
        self.run_after(model, Operation::Create, &created).await?;
        Ok(Some(created))
    }

    pub async fn update_with_hooks(&self, model: &str, where_: &[Where], data: Record) -> Result<Option<Record>> {
        let Some(data) = self.run_before(model, Operation::Update, data).await? else {
            return Ok(None);
        };
        let updated = self.db.update(model, where_, data).await?;
        if let Some(row) = &updated {
            self.run_after(model, Operation::Update, row).await?;
        }
        Ok(updated)
    }

    pub async fn update_many_with_hooks(&self, model: &str, where_: &[Where], data: Record) -> Result<u64> {
        let Some(data) = self.run_before(model, Operation::Update, data).await? else {
            return Ok(0);
        };
        self.db.update_many(model, where_, data).await
    }

    pub async fn delete_with_hooks(&self, model: &str, where_: &[Where]) -> Result<()> {
        let has_hooks = self.hooks.get(model, Operation::Delete).is_some();
        if !has_hooks {
            return self.db.delete(model, where_).await;
        }
        let Some(row) = self.db.find_one(model, where_).await? else {
            return Ok(());
        };
        if self.run_before(model, Operation::Delete, row.clone()).await?.is_none() {
            return Ok(());
        }
        self.db.delete(model, where_).await?;
        self.run_after(model, Operation::Delete, &row).await
    }

    pub async fn delete_many_with_hooks(&self, model: &str, where_: &[Where]) -> Result<u64> {
        let has_hooks = self.hooks.get(model, Operation::Delete).is_some();
        if !has_hooks {
            return self.db.delete_many(model, where_).await;
        }
        let rows = self.db.find_many(model, FindManyQuery { where_: where_.to_vec(), ..Default::default() }).await?;
        let mut n = 0;
        for row in rows {
            if self.run_before(model, Operation::Delete, row.clone()).await?.is_none() {
                continue;
            }
            let id = row.get("id").cloned().unwrap_or(Value::Null);
            n += self.db.delete_many(model, &[Where::eq("id", id)]).await?;
            self.run_after(model, Operation::Delete, &row).await?;
        }
        Ok(n)
    }

    // ---- users ---------------------------------------------------------------------

    fn with_timestamps(mut data: Record) -> Record {
        let now = date::now_value();
        data.entry("createdAt").or_insert_with(|| now.clone());
        data.entry("updatedAt").or_insert(now);
        data
    }

    fn lowercase_email(data: &mut Record) {
        if let Some(Value::String(email)) = data.get_mut("email") {
            *email = email.to_lowercase();
        }
    }

    /// Create a user. `source` says how the identity was provisioned, for the
    /// `validate_user_info` gate. Returns a 403 `ApiError` if the gate rejects the user or a
    /// database hook aborted creation.
    pub async fn create_user(&self, mut data: Record, source: &UserSource) -> Result<User> {
        Self::lowercase_email(&mut data);
        data.entry("emailVerified").or_insert(Value::Bool(false));
        assert_valid_user_info(
            self.config.validate_user_info.as_ref(),
            &data,
            source,
            ValidateUserInfoAction::CreateUser,
        )
        .await?;
        let created = self.create_with_hooks("user", Self::with_timestamps(data)).await?.ok_or_else(|| {
            ApiError::new(http::StatusCode::FORBIDDEN, "FAILED_TO_CREATE_USER", "Failed to create user")
        })?;
        User::from_record(created)
    }

    pub async fn create_oauth_user(
        &self,
        user: Record,
        mut account: Record,
        source: &UserSource,
    ) -> Result<(User, Account)> {
        self.db
            .transaction(async {
                let user = self.create_user(user, source).await?;
                account.insert("userId".into(), user.id.clone().into());
                let account = self.create_account(account).await?;
                Ok((user, account))
            })
            .await
    }

    pub async fn find_user_by_id(&self, id: &str) -> Result<Option<User>> {
        self.db.find_one("user", &[Where::eq("id", id)]).await?.map(User::from_record).transpose()
    }

    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>> {
        self.db.find_one("user", &[Where::eq("email", email.to_lowercase())]).await?.map(User::from_record).transpose()
    }

    /// Find a user and all their linked accounts.
    pub async fn find_user_by_email_with_accounts(&self, email: &str) -> Result<Option<(User, Vec<Account>)>> {
        let Some(user) = self.find_user_by_email(email).await? else {
            return Ok(None);
        };
        let accounts = self.find_accounts(&user.id).await?;
        Ok(Some((user, accounts)))
    }

    pub async fn update_user(&self, id: &str, data: Record) -> Result<Option<User>> {
        let user =
            self.update_with_hooks("user", &[Where::eq("id", id)], data).await?.map(User::from_record).transpose()?;
        self.queue_refresh_user_sessions(user.as_ref()).await?;
        Ok(user)
    }

    pub async fn update_user_by_email(&self, email: &str, data: Record) -> Result<Option<User>> {
        let user = self
            .update_with_hooks("user", &[Where::eq("email", email.to_lowercase())], data)
            .await?
            .map(User::from_record)
            .transpose()?;
        self.queue_refresh_user_sessions(user.as_ref()).await?;
        Ok(user)
    }

    pub async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<()> {
        self.update_many_with_hooks(
            "account",
            &[Where::eq("userId", user_id), Where::eq("providerId", "credential")],
            record([("password", password_hash.into())]),
        )
        .await?;
        Ok(())
    }

    pub async fn list_users(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
        sort_by: Option<SortBy>,
        where_: Vec<Where>,
    ) -> Result<Vec<User>> {
        self.db
            .find_many("user", FindManyQuery { where_, limit, offset, sort_by })
            .await?
            .into_iter()
            .map(User::from_record)
            .collect()
    }

    pub async fn count_total_users(&self, where_: &[Where]) -> Result<u64> {
        self.db.count("user", where_).await
    }

    /// Delete a user together with their sessions and accounts.
    pub async fn delete_user(&self, user_id: &str) -> Result<()> {
        let refs = self.active_session_refs(user_id).await?;
        self.db
            .transaction(async {
                if self.sessions_in_db() {
                    self.delete_many_with_hooks("session", &[Where::eq("userId", user_id)]).await?;
                }
                self.delete_many_with_hooks("account", &[Where::eq("userId", user_id)]).await?;
                self.delete_with_hooks("user", &[Where::eq("id", user_id)]).await?;
                self.queue_cached_session_deletion(user_id, refs).await
            })
            .await
    }

    // ---- sessions ------------------------------------------------------------------

    /// Create a session for `user_id`. The IP address and user agent come from the
    /// current request, if any.
    pub async fn create_session(
        &self,
        user_id: &str,
        dont_remember_me: bool,
        overrides: Option<SessionOverrides>,
    ) -> Result<Session> {
        let headers = current_request().map(|r| r.headers());
        let ip_address = headers.as_ref().and_then(|h| ip::get_ip(h, &self.config.ip)).unwrap_or_default();
        let user_agent = headers
            .as_ref()
            .and_then(|h| h.get(http::header::USER_AGENT))
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let overrides = overrides.unwrap_or_default();
        let mut rest = overrides.data.clone();
        rest.remove("id");
        let expires_in = if dont_remember_me { 60 * 60 * 24 } else { self.config.session_expires_in };
        let mut data = record([("ipAddress", ip_address.into()), ("userAgent", user_agent.into())]);
        data.extend(rest.clone());
        let now = date::now_value();
        data.extend(record([
            ("expiresAt", date::to_value(date::in_secs(expires_in))),
            ("userId", user_id.into()),
            ("token", crypto::generate_id(Some(32)).into()),
            ("createdAt", now.clone()),
            ("updatedAt", now),
        ]));
        if overrides.override_all {
            data.extend(rest);
        }
        let failed =
            || ApiError::new(http::StatusCode::FORBIDDEN, "FAILED_TO_CREATE_SESSION", "Failed to create session");
        let data = self.run_before("session", Operation::Create, data).await?.ok_or_else(failed)?;
        let created = if self.sessions_in_db() {
            self.db.create("session", data, false).await?
        } else {
            // Secondary storage is the only session store.
            let mut data = self.db.with_defaults("session", data)?;
            data.insert("id".into(), self.db.generate_id("session").into());
            data
        };
        let session = Session::from_record(created.clone())?;
        if self.config.storage.is_some() {
            if super::in_transaction() && self.db_session_fallback() {
                // The database can serve the session, so cache it only once it commits.
                let this = self.clone();
                let cached = session.clone();
                super::after_commit(Box::pin(async move {
                    log_after_commit(this.cache_session(&cached).await, "cache committed session")
                }))
                .await?;
            } else {
                self.cache_session(&session).await?;
            }
        }
        self.run_after("session", Operation::Create, &created).await?;
        Ok(session)
    }

    pub async fn find_session(&self, token: &str) -> Result<Option<SessionWithUser>> {
        if let Some(storage) = &self.config.storage {
            match storage.get(token).await? {
                Some(raw) => return Ok(serde_json::from_str(&raw).ok()),
                // Preserved rows may be revoked sessions: never restore them from the database.
                None if !self.config.store_session_in_db || self.config.preserve_session_in_db => return Ok(None),
                None => {}
            }
        }
        let Some(row) = self.db.find_one("session", &[Where::eq("token", token)]).await? else {
            return Ok(None);
        };
        let session = Session::from_record(row)?;
        let Some(user) = self.find_user_by_id(&session.user_id).await? else {
            return Ok(None);
        };
        Ok(Some(SessionWithUser { session, user }))
    }

    pub async fn find_sessions(&self, tokens: &[String]) -> Result<Vec<SessionWithUser>> {
        let mut out = vec![];
        if tokens.is_empty() {
            return Ok(out);
        }
        if let Some(storage) = &self.config.storage {
            for token in tokens {
                if let Some(s) = storage.get(token).await?.and_then(|raw| serde_json::from_str(&raw).ok()) {
                    out.push(s);
                }
            }
            return Ok(out);
        }
        let rows = self
            .db
            .find_many(
                "session",
                FindManyQuery {
                    where_: vec![Where::is_in("token", tokens.iter().map(|t| Value::String(t.clone())).collect())],
                    ..Default::default()
                },
            )
            .await?;
        for row in rows {
            let session = Session::from_record(row)?;
            if let Some(user) = self.find_user_by_id(&session.user_id).await? {
                out.push(SessionWithUser { session, user });
            }
        }
        Ok(out)
    }

    pub async fn list_sessions(&self, user_id: &str) -> Result<Vec<Session>> {
        let mut where_ = vec![Where::eq("userId", user_id)];
        if self.db_session_fallback() {
            // The database holds every session, including any whose cached copy failed to write.
            where_.push(Where::gt("expiresAt", date::now_value()));
        } else if let Some(storage) = &self.config.storage {
            let now = now_ms();
            let mut seen = std::collections::HashSet::new();
            let mut sessions = vec![];
            for r in self.active_session_refs(user_id).await? {
                if r.expires_at <= now || !seen.insert(r.token.clone()) {
                    continue;
                }
                let cached =
                    storage.get(&r.token).await?.and_then(|raw| serde_json::from_str::<SessionWithUser>(&raw).ok());
                if let Some(s) = cached {
                    sessions.push(s.session);
                }
            }
            return Ok(sessions);
        }
        self.db
            .find_many("session", FindManyQuery { where_, ..Default::default() })
            .await?
            .into_iter()
            .map(Session::from_record)
            .collect()
    }

    pub async fn update_session(&self, token: &str, data: Record) -> Result<Option<Session>> {
        let Some(data) = self.run_before("session", Operation::Update, data).await? else {
            return Ok(None);
        };
        let mut updated = None;
        if self.sessions_in_db() {
            updated = self.db.update("session", &[Where::eq("token", token)], data.clone()).await?;
        }
        if let Some(cached) = self.update_cached_session(token, &data).await? {
            updated = Some(cached.to_record());
        }
        if let Some(row) = &updated {
            self.run_after("session", Operation::Update, row).await?;
        }
        updated.map(Session::from_record).transpose()
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        if let Some(storage) = &self.config.storage {
            if let Some(raw) = storage.get(token).await? {
                let Ok(cached) = serde_json::from_str::<SessionWithUser>(&raw) else {
                    tracing::error!("Session not found in secondary storage");
                    return Ok(());
                };
                let now = now_ms();
                let mut refs = self.active_session_refs(&cached.session.user_id).await?;
                refs.retain(|r| r.expires_at > now && r.token != token);
                self.write_active_session_refs(&cached.session.user_id, refs).await?;
            }
            storage.delete(token).await?;
            if !self.config.store_session_in_db {
                return Ok(());
            }
            if self.config.preserve_session_in_db {
                self.end_preserved_sessions(vec![Where::eq("token", token)]).await?;
                return Ok(());
            }
        }
        self.delete_with_hooks("session", &[Where::eq("token", token)]).await
    }

    pub async fn delete_sessions(&self, tokens: &[String]) -> Result<()> {
        let values: Vec<Value> = tokens.iter().map(|t| Value::String(t.clone())).collect();
        if let Some(storage) = &self.config.storage {
            for token in tokens {
                storage.delete(token).await?;
            }
            if !self.config.store_session_in_db {
                return Ok(());
            }
            if self.config.preserve_session_in_db {
                self.end_preserved_sessions(vec![Where::is_in("token", values)]).await?;
                return Ok(());
            }
        }
        self.delete_many_with_hooks("session", &[Where::is_in("token", values)]).await?;
        Ok(())
    }

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<()> {
        // Captured before the delete so a replacement session created by a later hook survives.
        let refs = self.active_session_refs(user_id).await?;
        if self.config.storage.is_some() {
            if !self.config.store_session_in_db {
                return self.queue_cached_session_deletion(user_id, refs).await;
            }
            if self.config.preserve_session_in_db {
                self.end_preserved_sessions(vec![Where::eq("userId", user_id)]).await?;
                return self.queue_cached_session_deletion(user_id, refs).await;
            }
        }
        self.delete_many_with_hooks("session", &[Where::eq("userId", user_id)]).await?;
        self.queue_cached_session_deletion(user_id, refs).await
    }

    // ---- accounts ------------------------------------------------------------------

    pub async fn create_account(&self, data: Record) -> Result<Account> {
        let created = self.create_with_hooks("account", Self::with_timestamps(data)).await?.ok_or_else(|| {
            ApiError::new(http::StatusCode::FORBIDDEN, "FAILED_TO_CREATE_ACCOUNT", "Failed to create account")
        })?;
        Account::from_record(created)
    }

    /// Alias of [`create_account`](Self::create_account) (`linkAccount`).
    pub async fn link_account(&self, data: Record) -> Result<Account> {
        self.create_account(data).await
    }

    pub async fn find_accounts(&self, user_id: &str) -> Result<Vec<Account>> {
        self.db
            .find_many("account", FindManyQuery { where_: vec![Where::eq("userId", user_id)], ..Default::default() })
            .await?
            .into_iter()
            .map(Account::from_record)
            .collect()
    }

    pub async fn find_credential_account(&self, user_id: &str) -> Result<Option<Account>> {
        self.db
            .find_one("account", &[Where::eq("userId", user_id), Where::eq("providerId", "credential")])
            .await?
            .map(Account::from_record)
            .transpose()
    }

    pub async fn find_account_by_key(&self, provider_id: &str, account_id: &str) -> Result<Option<Account>> {
        self.db
            .find_one("account", &[Where::eq("accountId", account_id), Where::eq("providerId", provider_id)])
            .await?
            .map(Account::from_record)
            .transpose()
    }

    /// Find the user owning a provider account (`findAccountOwnerByKey`).
    pub async fn find_account_owner_by_key(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<Option<(User, Account)>> {
        let Some(account) = self.find_account_by_key(provider_id, account_id).await? else {
            return Ok(None);
        };
        Ok(self.find_user_by_id(&account.user_id).await?.map(|u| (u, account)))
    }

    pub async fn find_account_by_id(&self, id: &str) -> Result<Option<Account>> {
        self.db.find_one("account", &[Where::eq("id", id)]).await?.map(Account::from_record).transpose()
    }

    pub async fn update_account(&self, id: &str, data: Record) -> Result<Option<Account>> {
        self.update_with_hooks("account", &[Where::eq("id", id)], data).await?.map(Account::from_record).transpose()
    }

    pub async fn delete_account(&self, id: &str) -> Result<()> {
        self.delete_with_hooks("account", &[Where::eq("id", id)]).await
    }

    pub async fn delete_accounts(&self, user_id: &str) -> Result<()> {
        self.delete_many_with_hooks("account", &[Where::eq("userId", user_id)]).await?;
        Ok(())
    }

    // ---- verification --------------------------------------------------------------

    fn stored_identifier(&self, identifier: &str) -> (String, bool) {
        let hashed = self.config.store_identifier.should_hash(identifier);
        if hashed { (crypto::sha256_base64url(identifier), true) } else { (identifier.to_owned(), false) }
    }

    pub async fn create_verification_value(
        &self,
        identifier: &str,
        value: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Verification> {
        let (stored, _) = self.stored_identifier(identifier);
        let data = Self::with_timestamps(record([
            ("identifier", stored.clone().into()),
            ("value", value.into()),
            ("expiresAt", date::to_value(expires_at)),
        ]));
        let data = self.run_before("verification", Operation::Create, data).await?.ok_or_else(|| {
            ApiError::new(http::StatusCode::FORBIDDEN, "FAILED_TO_CREATE_VERIFICATION", "Unable to create verification")
        })?;
        let created = if self.verification_in_db() {
            self.db.create("verification", data, false).await?
        } else {
            let mut data = self.db.with_defaults("verification", data)?;
            data.insert("id".into(), self.db.generate_id("verification").into());
            data
        };
        if let Some(storage) = &self.config.storage {
            let ttl = ttl_secs(expires_at.timestamp_millis(), now_ms());
            if ttl > 0 {
                let json = Value::Object(created.clone()).to_string();
                storage.set(&verification_key(&stored), &json, Some(ttl)).await?;
            }
        }
        self.run_after("verification", Operation::Create, &created).await?;
        Verification::from_record(created)
    }

    async fn latest_verification(&self, identifier: &str) -> Result<Option<Verification>> {
        self.db
            .find_many(
                "verification",
                FindManyQuery {
                    where_: vec![Where::eq("identifier", identifier)],
                    sort_by: Some(SortBy { field: "createdAt".into(), direction: SortDirection::Desc }),
                    limit: Some(1),
                    ..Default::default()
                },
            )
            .await?
            .into_iter()
            .next()
            .map(Verification::from_record)
            .transpose()
    }

    /// The latest verification row for `identifier`. Expired rows are cleaned up unless disabled.
    pub async fn find_verification_value(&self, identifier: &str) -> Result<Option<Verification>> {
        let (stored, hashed) = self.stored_identifier(identifier);
        if let Some(storage) = &self.config.storage {
            let mut keys = vec![verification_key(&stored)];
            if hashed {
                keys.push(verification_key(identifier));
            }
            for key in keys {
                let cached = storage.get(&key).await?.and_then(|raw| serde_json::from_str::<Verification>(&raw).ok());
                if cached.is_some() {
                    return Ok(cached);
                }
            }
            if !self.config.verification_in_db {
                return Ok(None);
            }
        }
        let mut found = self.latest_verification(&stored).await?;
        if found.is_none() && hashed {
            found = self.latest_verification(identifier).await?;
        }
        if !self.config.disable_verification_cleanup {
            self.delete_many_with_hooks("verification", &[Where::lt("expiresAt", date::now_value())]).await?;
        }
        Ok(found)
    }

    pub async fn delete_verification_by_identifier(&self, identifier: &str) -> Result<()> {
        let (stored, _) = self.stored_identifier(identifier);
        if let Some(storage) = &self.config.storage {
            storage.delete(&verification_key(&stored)).await?;
        }
        if self.verification_in_db() {
            self.delete_many_with_hooks("verification", &[Where::eq("identifier", stored)]).await?;
        }
        Ok(())
    }

    pub async fn delete_verification_value(&self, id: &str) -> Result<()> {
        self.delete_with_hooks("verification", &[Where::eq("id", id)]).await
    }

    /// Atomically consume the latest verification row for `identifier`, invalidating all
    /// rows for it. Returns `None` if none exists or it has expired.
    pub async fn consume_verification_value(&self, identifier: &str) -> Result<Option<Verification>> {
        let (stored, hashed) = self.stored_identifier(identifier);
        let mut candidates = vec![stored];
        if hashed {
            candidates.push(identifier.to_owned());
        }
        let mut consumed = None;
        match &self.config.storage {
            Some(storage) if !self.config.verification_in_db => {
                for (i, id) in candidates.iter().enumerate() {
                    let raw = storage.get_and_delete(&verification_key(id)).await?;
                    let Some(v) = raw.and_then(|raw| serde_json::from_str::<Verification>(&raw).ok()) else {
                        continue;
                    };
                    for (j, other) in candidates.iter().enumerate() {
                        if i != j {
                            storage.delete(&verification_key(other)).await?;
                        }
                    }
                    consumed = Some(v);
                    break;
                }
            }
            _ => {
                for id in &candidates {
                    let row = self
                        .db
                        .transaction(async {
                            let Some(latest) = self.latest_verification(id).await? else { return Ok(None) };
                            let consumed =
                                self.db.consume_one("verification", &[Where::eq("id", latest.id.clone())]).await?;
                            // `Some(None)`: lost the race to another consumer.
                            let Some(row) = consumed else { return Ok(Some(None)) };
                            self.run_after("verification", Operation::Delete, &row).await?;
                            self.delete_many_with_hooks("verification", &[Where::eq("identifier", id.clone())]).await?;
                            Ok::<_, crate::error::Error>(Some(Some(row)))
                        })
                        .await?;
                    match row {
                        None => continue,
                        Some(None) => return Ok(None),
                        Some(Some(row)) => {
                            consumed = Some(Verification::from_record(row)?);
                            break;
                        }
                    }
                }
                if consumed.is_some()
                    && let Some(storage) = &self.config.storage
                {
                    for id in &candidates {
                        storage.delete(&verification_key(id)).await?;
                    }
                }
            }
        }
        Ok(consumed.filter(|v| v.expires_at >= Utc::now()))
    }

    /// First-writer-wins marker keyed by a deterministic id derived from `identifier`
    /// (`reserveVerificationValue`). Returns `false` if it already exists. Requires
    /// database-backed verification storage.
    pub async fn reserve_verification_value(
        &self,
        identifier: &str,
        value: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool> {
        if !self.verification_in_db() {
            return Err(crate::error::Error::Config(
                "reserveVerificationValue requires database-backed verification storage. Set verification.storeInDatabase to true for flows that reserve verification values.".into(),
            ));
        }
        let digest = crypto::sha256(format!("reserve:{identifier}").as_bytes());
        let id = match self.db.id_generator() {
            super::IdGenerator::Uuid => {
                let mut b: [u8; 16] = digest[..16].try_into().expect("16 bytes");
                b[6] = (b[6] & 0x0f) | 0x50;
                b[8] = (b[8] & 0x3f) | 0x80;
                let h = hex::encode(b);
                format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
            }
            _ => base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, digest),
        };
        let (stored, _) = self.stored_identifier(identifier);
        let mut data = Self::with_timestamps(record([
            ("identifier", stored.clone().into()),
            ("value", value.into()),
            ("expiresAt", date::to_value(expires_at)),
        ]));
        data.insert("id".into(), id.clone().into());
        if let Err(e) = self.db.create("verification", data, true).await {
            // A create error is ambiguous across adapters: confirm it was a duplicate.
            if self.db.find_one("verification", &[Where::eq("id", id)]).await?.is_some() {
                return Ok(false);
            }
            return Err(e);
        }
        if let Some(storage) = &self.config.storage {
            let ttl = ttl_secs(expires_at.timestamp_millis(), now_ms());
            if ttl > 0 {
                let json = serde_json::json!({ "identifier": stored, "value": value, "expiresAt": date::to_value(expires_at) });
                storage.set(&verification_key(&stored), &json.to_string(), Some(ttl)).await?;
            }
        }
        Ok(true)
    }

    /// Strip the accounts and sessions an unverified user accrued before an email-primary
    /// proof (magic link, email OTP) showed who owns the mailbox, then mark the email
    /// verified (`revokeUnprovenAccountAccess`). Returns the current user.
    pub async fn revoke_unproven_account_access(&self, user_id: &str) -> Result<Option<User>> {
        const LOCK_MS: i64 = 5000;
        let lock = format!("revoke-unproven-account-access:{user_id}");
        let expires = Utc::now() + chrono::Duration::milliseconds(LOCK_MS);
        let acquired = match self.reserve_verification_value(&lock, user_id, expires).await {
            Ok(acquired) => acquired,
            Err(crate::error::Error::Config(_)) => true,
            Err(e) => return Err(e),
        };
        if !acquired {
            // Another request is cleaning up; wait for it (up to 2s), then read the result.
            let deadline = Utc::now() + chrono::Duration::seconds(2);
            while Utc::now() < deadline {
                match self.find_verification_value(&lock).await? {
                    None => break,
                    Some(v) if v.expires_at <= Utc::now() => {
                        self.delete_verification_by_identifier(&lock).await?;
                        break;
                    }
                    Some(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
                }
            }
            return self.find_user_by_id(user_id).await;
        }
        let result = async {
            let Some(user) = self.find_user_by_id(user_id).await? else { return Ok(None) };
            if user.email_verified {
                return Ok(Some(user));
            }
            for account in self.find_accounts(user_id).await? {
                self.delete_account(&account.id).await?;
            }
            self.delete_user_sessions(user_id).await?;
            self.update_user(user_id, record([("emailVerified", true.into())])).await
        }
        .await;
        let _ = self.delete_verification_by_identifier(&lock).await;
        result
    }

    pub async fn update_verification_by_identifier(
        &self,
        identifier: &str,
        data: Record,
    ) -> Result<Option<Verification>> {
        let (stored, _) = self.stored_identifier(identifier);
        if let Some(storage) = &self.config.storage {
            let key = verification_key(&stored);
            let cached = storage.get(&key).await?.and_then(|raw| serde_json::from_str::<Verification>(&raw).ok());
            if let Some(cached) = cached {
                let mut merged = cached.to_record();
                merged.extend(data.clone());
                let updated = Verification::from_record(merged)?;
                let ttl = ttl_secs(updated.expires_at.timestamp_millis(), now_ms());
                if ttl > 0 {
                    let json = serde_json::to_string(&updated)?;
                    storage.set(&key, &json, Some(ttl)).await?;
                }
                if !self.config.verification_in_db {
                    return Ok(Some(updated));
                }
            }
        }
        if !self.verification_in_db() {
            return Ok(None);
        }
        self.update_with_hooks("verification", &[Where::eq("identifier", stored)], data)
            .await?
            .map(Verification::from_record)
            .transpose()
    }
}

// ---- secondary storage -----------------------------------------------------------------

impl InternalAdapter {
    /// Whether sessions are written to the database.
    fn sessions_in_db(&self) -> bool {
        self.config.storage.is_none() || self.config.store_session_in_db
    }

    /// Whether verification values are written to the database.
    fn verification_in_db(&self) -> bool {
        self.config.storage.is_none() || self.config.verification_in_db
    }

    /// With secondary storage, the database is authoritative for sessions only when they are
    /// written to it and revoked rows are deleted.
    fn db_session_fallback(&self) -> bool {
        self.config.storage.is_some() && self.config.store_session_in_db && !self.config.preserve_session_in_db
    }

    async fn active_session_refs(&self, user_id: &str) -> Result<Vec<SessionRef>> {
        let Some(storage) = &self.config.storage else { return Ok(vec![]) };
        let raw = storage.get(&active_sessions_key(user_id)).await?;
        Ok(raw.and_then(|raw| serde_json::from_str(&raw).ok()).unwrap_or_default())
    }

    /// Store the list sorted by expiry, expiring with its last session; delete it when empty.
    async fn write_active_session_refs(&self, user_id: &str, mut refs: Vec<SessionRef>) -> Result<()> {
        let Some(storage) = &self.config.storage else { return Ok(()) };
        let key = active_sessions_key(user_id);
        refs.sort_by_key(|r| r.expires_at);
        let now = now_ms();
        match refs.last().map(|r| ttl_secs(r.expires_at, now)) {
            Some(ttl) if ttl > 0 => storage.set(&key, &serde_json::to_string(&refs)?, Some(ttl)).await,
            _ => storage.delete(&key).await,
        }
    }

    /// Write `{session, user}` under the token and add it to the user's active list.
    async fn cache_session(&self, session: &Session) -> Result<()> {
        let Some(storage) = &self.config.storage else { return Ok(()) };
        let now = now_ms();
        let expires = session.expires_at.timestamp_millis();
        let mut refs = self.active_session_refs(&session.user_id).await?;
        refs.retain(|r| r.expires_at > now && r.token != session.token);
        refs.push(SessionRef { token: session.token.clone(), expires_at: expires });
        self.write_active_session_refs(&session.user_id, refs).await?;
        let Some(user) = self.find_user_by_id(&session.user_id).await? else {
            tracing::warn!("not caching a session whose user does not exist");
            return Ok(());
        };
        let ttl = ttl_secs(expires, now);
        if ttl > 0 {
            let value = serde_json::to_string(&SessionWithUser { session: session.clone(), user })?;
            storage.set(&session.token, &value, Some(ttl)).await?;
        }
        Ok(())
    }

    /// Merge `data` into the cached session, if there is one, returning the result.
    async fn update_cached_session(&self, token: &str, data: &Record) -> Result<Option<Session>> {
        let Some(storage) = &self.config.storage else { return Ok(None) };
        let Some(cached) = storage.get(token).await?.and_then(|raw| serde_json::from_str::<SessionWithUser>(&raw).ok())
        else {
            return Ok(None);
        };
        let mut merged = cached.session.to_record();
        merged.extend(data.clone());
        merged.insert("createdAt".into(), date::to_value(cached.session.created_at));
        let session = Session::from_record(merged)?;
        let now = now_ms();
        let expires = session.expires_at.timestamp_millis();
        let ttl = ttl_secs(expires, now);
        if ttl > 0 {
            let value = serde_json::to_string(&SessionWithUser { session: session.clone(), user: cached.user })?;
            storage.set(token, &value, Some(ttl)).await?;
            let mut refs = self.active_session_refs(&session.user_id).await?;
            refs.retain(|r| r.token != token && r.expires_at > now);
            refs.push(SessionRef { token: token.to_owned(), expires_at: expires });
            self.write_active_session_refs(&session.user_id, refs).await?;
        }
        Ok(Some(session))
    }

    /// Remove the given cached sessions (and their list entries) once the surrounding
    /// transaction commits.
    async fn queue_cached_session_deletion(&self, user_id: &str, refs: Vec<SessionRef>) -> Result<()> {
        if self.config.storage.is_none() {
            return Ok(());
        }
        let this = self.clone();
        let user_id = user_id.to_owned();
        super::after_commit(Box::pin(async move {
            let result = this.delete_cached_sessions(&user_id, &refs).await;
            log_after_commit(result, "delete committed user sessions")
        }))
        .await
    }

    async fn delete_cached_sessions(&self, user_id: &str, refs: &[SessionRef]) -> Result<()> {
        let Some(storage) = &self.config.storage else { return Ok(()) };
        for r in refs {
            storage.delete(&r.token).await?;
        }
        let now = now_ms();
        let mut remaining = self.active_session_refs(user_id).await?;
        remaining.retain(|r| r.expires_at > now && !refs.iter().any(|d| d.token == r.token));
        self.write_active_session_refs(user_id, remaining).await
    }

    /// After a user update commits, rewrite their cached sessions with the new user.
    async fn queue_refresh_user_sessions(&self, user: Option<&User>) -> Result<()> {
        let (Some(_), Some(user)) = (&self.config.storage, user) else { return Ok(()) };
        let this = self.clone();
        let user = user.clone();
        super::after_commit(Box::pin(async move {
            log_after_commit(this.refresh_user_sessions(&user).await, "refresh committed user sessions")
        }))
        .await
    }

    async fn refresh_user_sessions(&self, user: &User) -> Result<()> {
        let Some(storage) = &self.config.storage else { return Ok(()) };
        let now = now_ms();
        for r in self.active_session_refs(&user.id).await? {
            if r.expires_at <= now {
                continue;
            }
            let Some(cached) =
                storage.get(&r.token).await?.and_then(|raw| serde_json::from_str::<SessionWithUser>(&raw).ok())
            else {
                continue;
            };
            let ttl = ttl_secs(cached.session.expires_at.timestamp_millis(), now);
            let value = serde_json::to_string(&SessionWithUser { session: cached.session, user: user.clone() })?;
            storage.set(&r.token, &value, Some(ttl)).await?;
        }
        Ok(())
    }

    /// End live session rows matching `where_` without deleting them
    /// (`preserveSessionInDatabase`): delete hooks still run, and `expiresAt` becomes now.
    async fn end_preserved_sessions(&self, mut where_: Vec<Where>) -> Result<u64> {
        where_.push(Where::gt("expiresAt", date::now_value()));
        let rows = self.db.find_many("session", FindManyQuery { where_, ..Default::default() }).await?;
        let mut n = 0;
        for row in rows {
            if self.run_before("session", Operation::Delete, row.clone()).await?.is_none() {
                continue;
            }
            let id = row.get("id").cloned().unwrap_or(Value::Null);
            n += self
                .db
                .update_many("session", &[Where::eq("id", id)], record([("expiresAt", date::now_value())]))
                .await?;
            self.run_after("session", Operation::Delete, &row).await?;
        }
        Ok(n)
    }
}
