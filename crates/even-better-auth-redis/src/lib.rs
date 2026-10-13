//! Redis [`SecondaryStorage`] for better-auth, compatible with `@better-auth/redis-storage`
//! (same `better-auth:` key prefix and value layout, so Rust and TS servers can share it).
//!
//! ```no_run
//! # async fn run() -> even_better_auth::Result<()> {
//! use std::sync::Arc;
//! use even_better_auth::{BetterAuthOptions, MemoryAdapter};
//! use even_better_auth_redis::RedisStorage;
//!
//! let mut options = BetterAuthOptions::new(Arc::new(MemoryAdapter::new()));
//! options.secondary_storage = Some(Arc::new(RedisStorage::connect("redis://127.0.0.1/").await?));
//! # Ok(()) }
//! ```

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use even_better_auth::{Error, Result, SecondaryStorage};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;

/// Fallback for servers older than Redis 6.2, which lack `GETDEL`.
const GET_AND_DELETE: &str = r#"
local value = redis.call("GET", KEYS[1])
if value ~= false then
  redis.call("DEL", KEYS[1])
end
return value
"#;

/// `INCR`, setting the TTL only when the counter was just created so the window is fixed.
const INCREMENT: &str = r#"
local value = redis.call("INCR", KEYS[1])
if value == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return value
"#;

/// Secondary storage backed by Redis through a reconnecting [`ConnectionManager`].
#[derive(Clone)]
pub struct RedisStorage {
    conn: ConnectionManager,
    prefix: String,
    supports_getdel: std::sync::Arc<AtomicBool>,
}

fn err(e: redis::RedisError) -> Error {
    Error::Database(format!("redis: {e}"))
}

impl RedisStorage {
    /// Wrap an existing connection manager. Keys are prefixed with `better-auth:`.
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn, prefix: "better-auth:".into(), supports_getdel: std::sync::Arc::new(AtomicBool::new(true)) }
    }

    /// Connect to `url` (e.g. `redis://127.0.0.1/`).
    pub async fn connect(url: &str) -> Result<Self> {
        let client = redis::Client::open(url).map_err(err)?;
        Ok(Self::new(ConnectionManager::new(client).await.map_err(err)?))
    }

    /// Use a different key prefix.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
}

#[async_trait]
impl SecondaryStorage for RedisStorage {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        self.conn.clone().get(self.key(key)).await.map_err(err)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<()> {
        let mut conn = self.conn.clone();
        match ttl.filter(|t| *t > 0) {
            Some(ttl) => conn.set_ex(self.key(key), value, ttl).await.map_err(err),
            None => conn.set(self.key(key), value).await.map_err(err),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.conn.clone().del(self.key(key)).await.map_err(err)
    }

    async fn get_and_delete(&self, key: &str) -> Result<Option<String>> {
        let key = self.key(key);
        let mut conn = self.conn.clone();
        if self.supports_getdel.load(Ordering::Relaxed) {
            match conn.get_del(&key).await {
                Ok(v) => return Ok(v),
                Err(e) if e.to_string().to_lowercase().contains("unknown command") => {
                    self.supports_getdel.store(false, Ordering::Relaxed);
                }
                Err(e) => return Err(err(e)),
            }
        }
        redis::Script::new(GET_AND_DELETE).key(key).invoke_async(&mut conn).await.map_err(err)
    }

    async fn increment(&self, key: &str, ttl: u64) -> Result<u64> {
        if ttl == 0 {
            return Err(Error::Config("redis increment ttl must be positive".into()));
        }
        let mut conn = self.conn.clone();
        redis::Script::new(INCREMENT).key(self.key(key)).arg(ttl).invoke_async(&mut conn).await.map_err(err)
    }
}
