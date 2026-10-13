//! Secondary storage (`secondaryStorage`): a key-value store such as Redis that holds
//! sessions, verification values and rate-limit counters in front of (or instead of)
//! the database.
//!
//! Values use the same layout as the TypeScript implementation, so a Rust and a TS server
//! can share one store:
//!
//! | key | value |
//! |---|---|
//! | `{token}` | `{"session": {...}, "user": {...}}` |
//! | `active-sessions-{userId}` | `[{"token": "...", "expiresAt": <ms>}, ...]` |
//! | `verification:{identifier}` | the verification record |
//! | rate-limit key | counter |

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::Result;

/// A key-value store with per-key expiry. TTLs are in seconds.
#[async_trait]
pub trait SecondaryStorage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>>;
    /// Store `value`, expiring after `ttl` seconds when given.
    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    /// Atomically get a value and delete it.
    async fn get_and_delete(&self, key: &str) -> Result<Option<String>>;
    /// Atomically increment the counter at `key`, returning the new value. An absent key is
    /// created as `1` with the given TTL; later increments never extend the TTL.
    async fn increment(&self, key: &str, ttl: u64) -> Result<u64>;
}

/// An in-process [`SecondaryStorage`], for tests and single-instance deployments.
#[derive(Default)]
pub struct MemoryStorage {
    entries: Mutex<HashMap<String, (String, Option<i64>)>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of live (unexpired) keys.
    pub fn len(&self) -> usize {
        let now = now_ms();
        self.entries.lock().expect("storage lock").values().filter(|(_, exp)| live(*exp, now)).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn live(expires_at: Option<i64>, now: i64) -> bool {
    expires_at.is_none_or(|e| e > now)
}

fn expiry(ttl: Option<u64>, now: i64) -> Option<i64> {
    ttl.filter(|t| *t > 0).map(|t| now + i64::try_from(t).unwrap_or(i64::MAX / 2_000) * 1000)
}

#[async_trait]
impl SecondaryStorage for MemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        let now = now_ms();
        let mut entries = self.entries.lock().expect("storage lock");
        match entries.get(key) {
            Some((v, exp)) if live(*exp, now) => Ok(Some(v.clone())),
            Some(_) => {
                entries.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<()> {
        let now = now_ms();
        self.entries.lock().expect("storage lock").insert(key.to_owned(), (value.to_owned(), expiry(ttl, now)));
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.entries.lock().expect("storage lock").remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>> {
        let now = now_ms();
        let removed = self.entries.lock().expect("storage lock").remove(key);
        Ok(removed.filter(|(_, exp)| live(*exp, now)).map(|(v, _)| v))
    }

    async fn increment(&self, key: &str, ttl: u64) -> Result<u64> {
        let now = now_ms();
        let mut entries = self.entries.lock().expect("storage lock");
        let current = entries.get(key).filter(|(_, exp)| live(*exp, now)).cloned();
        let (count, exp) = match current {
            Some((v, exp)) => (v.parse::<u64>().unwrap_or(0) + 1, exp),
            None => (1, expiry(Some(ttl), now)),
        };
        entries.insert(key.to_owned(), (count.to_string(), exp));
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_storage() {
        let s = MemoryStorage::new();
        s.set("a", "1", None).await.unwrap();
        assert_eq!(s.get("a").await.unwrap().as_deref(), Some("1"));
        assert_eq!(s.get_and_delete("a").await.unwrap().as_deref(), Some("1"));
        assert_eq!(s.get("a").await.unwrap(), None);
        assert_eq!(s.increment("n", 60).await.unwrap(), 1);
        assert_eq!(s.increment("n", 60).await.unwrap(), 2);
        s.entries.lock().unwrap().get_mut("n").unwrap().1 = Some(now_ms() - 1);
        assert_eq!(s.get("n").await.unwrap(), None, "expired keys are gone");
        assert_eq!(s.increment("n", 60).await.unwrap(), 1, "an expired counter restarts");
    }
}
