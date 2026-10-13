//! Adapter conformance tests. SQLite always runs (in memory); Postgres and MySQL run when
//! their feature is enabled and `DATABASE_URL_POSTGRES` / `DATABASE_URL_MYSQL` is set.

use std::sync::Arc;

use even_better_auth::MemoryAdapter;
use even_better_auth::db::testing::{random_suffix, run_adapter_suite, suite_schema};
use even_better_auth::db::{Adapter, Db, IdGenerator, Where};
use even_better_auth_sqlx::SqlxAdapter;
use serde_json::{Value, json};

#[cfg(feature = "sqlite")]
async fn sqlite() -> SqlxAdapter {
    SqlxAdapter::connect("sqlite::memory:").await.expect("connect sqlite")
}

#[cfg(any(feature = "postgres", feature = "mysql"))]
async fn from_env(var: &str) -> Option<SqlxAdapter> {
    match std::env::var(var) {
        Ok(url) if !url.is_empty() => Some(SqlxAdapter::connect(&url).await.expect("connect")),
        _ => {
            eprintln!("skipping: {var} is not set");
            None
        }
    }
}

fn rec(v: Value) -> even_better_auth::db::Record {
    v.as_object().cloned().expect("object")
}

/// Checks beyond the shared suite that only hold for real SQL databases.
async fn sql_specific(adapter: SqlxAdapter) {
    let adapter: Arc<dyn Adapter> = Arc::new(adapter);
    let suffix = random_suffix();
    let db = Db::new(adapter.clone(), Arc::new(suite_schema(&suffix, false)), IdGenerator::Random);
    db.migrate().await.expect("migrate");

    let owner = db.create("owner", rec(json!({ "name": "o" })), false).await.expect("owner");
    let item = rec(json!({ "name": "i", "email": "i@example.com", "age": 1, "ownerId": owner["id"] }));
    db.create("item", item, false).await.expect("item");
    let orphan = rec(json!({ "name": "x", "email": "x@example.com", "age": 1, "ownerId": "missing" }));
    assert!(db.create("item", orphan, false).await.is_err(), "foreign key is enforced");
    db.delete("owner", &[Where::eq("id", owner["id"].clone())]).await.expect("delete owner");
    assert_eq!(db.count("item", &[]).await.unwrap(), 0, "ON DELETE CASCADE removes items");

    let missing_required = rec(json!({ "name": "n" }));
    assert!(db.adapter().create(db.table("item").unwrap(), missing_required).await.is_err(), "NOT NULL is enforced");

    let auth = even_better_auth::db::get_auth_tables(&even_better_auth::BetterAuthOptions::new(adapter.clone()));
    adapter.migrate(&auth).await.expect("migrate auth tables");
    adapter.migrate(&auth).await.expect("migrate auth tables again");
}

#[tokio::test]
async fn memory_adapter_conformance() {
    run_adapter_suite(Arc::new(MemoryAdapter::new())).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_conformance() {
    run_adapter_suite(Arc::new(sqlite().await)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_sql_specific() {
    sql_specific(sqlite().await).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_file_database() {
    let dir = std::env::temp_dir().join(format!("even-better-auth-sqlx-{}.db", random_suffix()));
    let url = format!("sqlite://{}", dir.display());
    run_adapter_suite(Arc::new(SqlxAdapter::connect(&url).await.expect("connect"))).await;
    let _ = std::fs::remove_file(&dir);
}

/// SQLite storage matches the TypeScript kysely adapter: ISO date text and 0/1 booleans.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn sqlite_storage_format() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    let adapter: Arc<dyn Adapter> = Arc::new(SqlxAdapter::sqlite(pool.clone()));
    let suffix = random_suffix();
    let db = Db::new(adapter, Arc::new(suite_schema(&suffix, false)), IdGenerator::Random);
    db.migrate().await.unwrap();
    let data = json!({ "name": "s", "email": "s@example.com", "age": 1, "active": true,
                       "expiresAt": "2024-05-06T07:08:09.010Z", "tags": ["a"] });
    db.create("item", rec(data), false).await.unwrap();
    let sql = format!("SELECT active, \"expiresAt\", tags, typeof(active) FROM ba_item_{suffix}");
    let (active, expires, tags, kind): (i64, String, String, String) =
        sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_one(&pool).await.unwrap();
    assert_eq!(
        (active, expires.as_str(), tags.as_str(), kind.as_str()),
        (1, "2024-05-06T07:08:09.010Z", "[\"a\"]", "integer")
    );

    let index = format!("ba_item_{suffix}_ownerId_idx");
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?")
        .bind(&index)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "index on ownerId");
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_conformance() {
    if let Some(a) = from_env("DATABASE_URL_POSTGRES").await {
        run_adapter_suite(Arc::new(a.clone())).await;
        sql_specific(a).await;
    }
}

#[cfg(feature = "mysql")]
#[tokio::test]
async fn mysql_conformance() {
    if let Some(a) = from_env("DATABASE_URL_MYSQL").await {
        run_adapter_suite(Arc::new(a.clone())).await;
        sql_specific(a).await;
    }
}
