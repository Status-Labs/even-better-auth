//! Key storage across the database, secondary storage, or secondary storage backed by the
//! database (`adapter.ts`). Secondary-storage keys match TS (`api-key:<hash>`,
//! `api-key:by-id:<id>`, `api-key:by-ref:<referenceId>`), so servers can share a store.
//!
//! In memory a key is a record with `metadata` as JSON (an object, or a string for legacy
//! double-encoded rows) and `permissions` as a JSON string, as in TS.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::future::join_all;
use serde_json::{Map, Value};

use super::{API_KEY_TABLE, ApiKeyOptions, ApiKeyStorage, Inner};
use crate::context::AuthContext;
use crate::db::{FindManyQuery, SortBy, SortDirection, Where};
use crate::error::{Error, Result};
use crate::storage::SecondaryStorage;

pub(super) type Record = Map<String, Value>;

pub(super) fn str_field<'a>(r: &'a Record, k: &str) -> Option<&'a str> {
    r.get(k).and_then(Value::as_str)
}

pub(super) fn int_field(r: &Record, k: &str) -> Option<i64> {
    r.get(k).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
}

pub(super) fn date_field(r: &Record, k: &str) -> Option<DateTime<Utc>> {
    r.get(k).and_then(crate::utils::date::parse_value)
}

/// The key's permissions (stored as a JSON string).
pub(super) fn parse_permissions(r: &Record) -> Option<Map<String, Value>> {
    match r.get("permissions")? {
        Value::String(s) => serde_json::from_str::<Value>(s).ok()?.as_object().cloned(),
        Value::Object(o) => Some(o.clone()),
        _ => None,
    }
}

/// A database row as a key: the metadata column decoded once.
pub(super) fn from_db(mut r: Record) -> Record {
    if let Some(Value::String(s)) = r.get("metadata") {
        let parsed = serde_json::from_str(s).unwrap_or(Value::Null);
        r.insert("metadata".into(), parsed);
    }
    r
}

/// A key (or partial update) as database columns: metadata encoded as a JSON string.
pub(super) fn to_db(mut r: Record) -> Record {
    if let Some(meta) = r.get("metadata")
        && !meta.is_null()
    {
        let encoded = meta.to_string();
        r.insert("metadata".into(), encoded.into());
    }
    r
}

/// Legacy rows hold metadata encoded twice; decode the leftover string.
pub(super) fn parse_metadata(meta: Option<&Value>) -> Value {
    match meta {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Null),
        Some(v) => v.clone(),
    }
}

fn needs_metadata_migration(r: &Record) -> bool {
    matches!(r.get("metadata"), Some(Value::String(_)))
}

/// Parse metadata, rewriting legacy double-encoded rows in the database
/// (`migrateDoubleStringifiedMetadata`). Failures are logged.
pub(super) async fn migrate_metadata(auth: &AuthContext, key: &Record, opts: &ApiKeyOptions) -> Value {
    let parsed = parse_metadata(key.get("metadata"));
    if needs_metadata_migration(key) && opts.uses_database() {
        let id = str_field(key, "id").unwrap_or_default();
        let update = to_db(Map::from_iter([("metadata".to_owned(), parsed.clone())]));
        if let Err(e) = auth.db.update(API_KEY_TABLE, &[Where::eq("id", id)], update).await {
            tracing::warn!(error = %e, "Failed to migrate double-stringified metadata for API key {id}");
        }
    }
    parsed
}

/// `batchMigrateLegacyMetadata`.
pub(super) async fn batch_migrate_metadata(auth: &AuthContext, keys: &[Record], opts: &ApiKeyOptions) {
    if !opts.uses_database() {
        return;
    }
    join_all(keys.iter().filter(|k| needs_metadata_migration(k)).map(|k| migrate_metadata(auth, k, opts))).await;
}

fn by_hash(hash: &str) -> String {
    format!("api-key:{hash}")
}

fn by_id(id: &str) -> String {
    format!("api-key:by-id:{id}")
}

fn by_ref(reference_id: &str) -> String {
    format!("api-key:by-ref:{reference_id}")
}

fn storage_of(auth: &AuthContext, opts: &ApiKeyOptions) -> Option<Arc<dyn SecondaryStorage>> {
    opts.custom_storage.clone().or_else(|| auth.options.secondary_storage.clone())
}

fn required_storage(auth: &AuthContext, opts: &ApiKeyOptions) -> Result<Arc<dyn SecondaryStorage>> {
    storage_of(auth, opts)
        .ok_or_else(|| Error::Config("Secondary storage is required when storage mode is 'secondary-storage'".into()))
}

/// Seconds until the key expires, when that is in the future.
fn ttl(key: &Record) -> Option<u64> {
    let secs = (date_field(key, "expiresAt")? - Utc::now()).num_seconds();
    (secs > 0).then_some(secs as u64)
}

async fn read(storage: &dyn SecondaryStorage, key: &str) -> Result<Option<Record>> {
    Ok(storage.get(key).await?.and_then(|s| serde_json::from_str::<Value>(&s).ok()).and_then(|v| match v {
        Value::Object(o) => Some(o),
        _ => None,
    }))
}

async fn read_ref_list(storage: &dyn SecondaryStorage, ref_key: &str) -> Result<Option<Vec<String>>> {
    Ok(storage.get(ref_key).await?.map(|s| serde_json::from_str(&s).unwrap_or_default()))
}

/// Read-modify-write of a reference list that is the source of truth.
async fn modify_ref_list(
    inner: &Inner,
    storage: &dyn SecondaryStorage,
    ref_key: &str,
    modify: impl FnOnce(Vec<String>) -> Vec<String>,
) -> Result<()> {
    let _guard = inner.ref_list_lock.lock().await;
    let ids = modify(read_ref_list(storage, ref_key).await?.unwrap_or_default());
    if ids.is_empty() {
        storage.delete(ref_key).await
    } else {
        storage.set(ref_key, &serde_json::to_string(&ids).expect("serializable"), None).await
    }
}

async fn put(inner: &Inner, storage: &dyn SecondaryStorage, key: &Record, opts: &ApiKeyOptions) -> Result<()> {
    let serialized = Value::Object(key.clone()).to_string();
    let (hash, id) = (str_field(key, "key").unwrap_or_default(), str_field(key, "id").unwrap_or_default());
    let ref_key = by_ref(str_field(key, "referenceId").unwrap_or_default());
    let ttl = ttl(key);
    storage.set(&by_hash(hash), &serialized, ttl).await?;
    storage.set(&by_id(id), &serialized, ttl).await?;
    if opts.fallback_to_database {
        // The list is only a cache of the database: invalidate it.
        return storage.delete(&ref_key).await;
    }
    let id = id.to_owned();
    modify_ref_list(inner, storage, &ref_key, |mut ids| {
        if !ids.contains(&id) {
            ids.push(id);
        }
        ids
    })
    .await
}

async fn remove(inner: &Inner, storage: &dyn SecondaryStorage, key: &Record, opts: &ApiKeyOptions) -> Result<()> {
    let (hash, id) = (str_field(key, "key").unwrap_or_default(), str_field(key, "id").unwrap_or_default());
    let ref_key = by_ref(str_field(key, "referenceId").unwrap_or_default());
    storage.delete(&by_hash(hash)).await?;
    storage.delete(&by_id(id)).await?;
    if opts.fallback_to_database {
        return storage.delete(&ref_key).await;
    }
    modify_ref_list(inner, storage, &ref_key, |ids| ids.into_iter().filter(|k| k != id).collect()).await
}

async fn find_in_db(auth: &AuthContext, field: &str, value: &str) -> Result<Option<Record>> {
    Ok(auth.db.find_one(API_KEY_TABLE, &[Where::eq(field, value)]).await?.map(from_db))
}

/// Look a key up by `field` (`key` hash or `id`) in the configured storage.
async fn get_by(
    auth: &AuthContext,
    inner: &Inner,
    opts: &ApiKeyOptions,
    field: &str,
    value: &str,
) -> Result<Option<Record>> {
    let storage_key = if field == "id" { by_id(value) } else { by_hash(value) };
    match opts.storage {
        ApiKeyStorage::Database => find_in_db(auth, field, value).await,
        ApiKeyStorage::SecondaryStorage => {
            let storage = storage_of(auth, opts);
            if let Some(s) = &storage
                && let Some(cached) = read(s.as_ref(), &storage_key).await?
            {
                return Ok(Some(cached));
            }
            if !opts.fallback_to_database {
                return Ok(None);
            }
            let found = find_in_db(auth, field, value).await?;
            if let (Some(key), Some(s)) = (&found, &storage) {
                put(inner, s.as_ref(), key, opts).await?;
            }
            Ok(found)
        }
    }
}

pub(super) async fn get_by_hash(
    auth: &AuthContext,
    inner: &Inner,
    hash: &str,
    opts: &ApiKeyOptions,
) -> Result<Option<Record>> {
    get_by(auth, inner, opts, "key", hash).await
}

pub(super) async fn get_by_id(
    auth: &AuthContext,
    inner: &Inner,
    id: &str,
    opts: &ApiKeyOptions,
) -> Result<Option<Record>> {
    get_by(auth, inner, opts, "id", id).await
}

/// Write the key to secondary storage (`setApiKey`); a no-op for database storage, where
/// routes write rows directly.
pub(super) async fn set(auth: &AuthContext, inner: &Inner, key: &Record, opts: &ApiKeyOptions) -> Result<()> {
    if opts.storage == ApiKeyStorage::Database {
        return Ok(());
    }
    put(inner, required_storage(auth, opts)?.as_ref(), key, opts).await
}

/// Remove the key from secondary storage (`deleteApiKey`); a no-op for database storage.
pub(super) async fn delete(auth: &AuthContext, inner: &Inner, key: &Record, opts: &ApiKeyOptions) -> Result<()> {
    if opts.storage == ApiKeyStorage::Database {
        return Ok(());
    }
    remove(inner, required_storage(auth, opts)?.as_ref(), key, opts).await
}

/// Remove a key everywhere it is stored.
pub(super) async fn delete_everywhere(
    auth: &AuthContext,
    inner: &Inner,
    key: &Record,
    opts: &ApiKeyOptions,
) -> Result<()> {
    delete(auth, inner, key, opts).await?;
    if opts.uses_database() {
        auth.db.delete(API_KEY_TABLE, &[Where::eq("id", str_field(key, "id").unwrap_or_default())]).await?;
    }
    Ok(())
}

#[derive(Clone, Default)]
pub(super) struct Sort {
    pub by: Option<String>,
    pub descending: bool,
}

async fn list_db(auth: &AuthContext, reference_id: &str, sort: &Sort) -> Result<Vec<Record>> {
    let query = FindManyQuery {
        where_: vec![Where::eq("referenceId", reference_id)],
        sort_by: sort.by.clone().map(|field| SortBy {
            field,
            direction: if sort.descending { SortDirection::Desc } else { SortDirection::Asc },
        }),
        ..Default::default()
    };
    Ok(auth.db.find_many(API_KEY_TABLE, query).await?.into_iter().map(from_db).collect())
}

async fn read_all(storage: &dyn SecondaryStorage, ids: &[String]) -> Result<Vec<Record>> {
    let mut keys = vec![];
    for chunk in ids.chunks(10) {
        for key in join_all(chunk.iter().map(|id| async move { read(storage, &by_id(id)).await })).await {
            keys.extend(key?);
        }
    }
    Ok(keys)
}

/// In-memory sort for secondary storage: nulls first ascending, last descending.
fn sort_in_memory(keys: &mut [Record], sort: &Sort) {
    let Some(field) = &sort.by else { return };
    keys.sort_by(|a, b| {
        let ord = match (a.get(field).filter(|v| !v.is_null()), b.get(field).filter(|v| !v.is_null())) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(x), Some(y)) => match (x.as_f64(), y.as_f64()) {
                (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
                _ => x.to_string().cmp(&y.to_string()),
            },
        };
        if sort.descending { ord.reverse() } else { ord }
    });
}

/// All keys of a reference in the configured storage (`listApiKeys`, without pagination:
/// the route paginates after filtering).
pub(super) async fn list(
    auth: &AuthContext,
    inner: &Inner,
    reference_id: &str,
    opts: &ApiKeyOptions,
    sort: &Sort,
) -> Result<Vec<Record>> {
    if opts.storage == ApiKeyStorage::Database {
        return list_db(auth, reference_id, sort).await;
    }
    let ref_key = by_ref(reference_id);
    let storage = storage_of(auth, opts);
    if let Some(s) = &storage
        && let Some(ids) = read_ref_list(s.as_ref(), &ref_key).await?
        && (!ids.is_empty() || !opts.fallback_to_database)
    {
        let mut keys = read_all(s.as_ref(), &ids).await?;
        sort_in_memory(&mut keys, sort);
        return Ok(keys);
    }
    if !opts.fallback_to_database {
        return Ok(vec![]);
    }
    let keys = list_db(auth, reference_id, sort).await?;
    // Rebuild the cache from the database: entries first, then the full id list.
    if let Some(s) = &storage
        && !keys.is_empty()
    {
        for key in &keys {
            put(inner, s.as_ref(), key, opts).await?;
        }
        let ids: Vec<&str> = keys.iter().filter_map(|k| str_field(k, "id")).collect();
        s.set(&ref_key, &serde_json::to_string(&ids).expect("serializable"), None).await?;
    }
    Ok(keys)
}
