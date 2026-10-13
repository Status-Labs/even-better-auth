//! SQL database adapter for better-auth built on [sqlx], supporting SQLite, Postgres and
//! MySQL (cargo features `sqlite` (default), `postgres` and `mysql`).
//!
//! ```no_run
//! # async fn run() -> even_better_auth::Result<()> {
//! use std::sync::Arc;
//! use even_better_auth::{BetterAuth, BetterAuthOptions};
//! use even_better_auth_sqlx::SqlxAdapter;
//!
//! let db = SqlxAdapter::connect("sqlite://auth.db").await?;
//! let auth = BetterAuth::new(BetterAuthOptions::new(Arc::new(db))).await?;
//! auth.migrate().await?;
//! # Ok(()) }
//! ```
//!
//! Storage per field type:
//!
//! | type      | SQLite        | Postgres      | MySQL         |
//! |-----------|---------------|---------------|---------------|
//! | string    | TEXT          | TEXT          | TEXT / VARCHAR(255) when unique, indexed or a reference |
//! | number    | INTEGER/BIGINT| INTEGER/BIGINT| INTEGER/BIGINT|
//! | boolean   | INTEGER 0/1   | BOOLEAN       | BOOLEAN (TINYINT 0/1) |
//! | date      | TEXT (ISO 8601) | TIMESTAMPTZ | DATETIME(3) (UTC) |
//! | json, arrays | TEXT (JSON) | JSONB       | JSON          |

#[cfg(not(any(feature = "sqlite", feature = "postgres", feature = "mysql")))]
compile_error!("even-better-auth-sqlx needs at least one of the `sqlite`, `postgres` or `mysql` features");

mod decode;
mod migrate;
mod query;

use std::sync::Arc;

use async_trait::async_trait;
use even_better_auth::db::{Adapter, FindManyQuery, Record, Schema, SortDirection, Table, Transaction, Where};
use even_better_auth::{Error, Result};
use serde_json::Value;
use sqlx::AssertSqlSafe;

pub use query::Dialect;
use query::{Param, Sql, column_type, finish_row, to_param};

#[derive(Clone)]
enum Pool {
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
    #[cfg(feature = "mysql")]
    MySql(sqlx::MySqlPool),
}

/// An open transaction on one of the pools.
enum TxConn {
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::Transaction<'static, sqlx::Sqlite>),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::Transaction<'static, sqlx::Postgres>),
    #[cfg(feature = "mysql")]
    MySql(sqlx::Transaction<'static, sqlx::MySql>),
}

type SharedTx = Arc<tokio::sync::Mutex<Option<TxConn>>>;

/// A better-auth [`Adapter`] over an sqlx connection pool. Supports transactions.
#[derive(Clone)]
pub struct SqlxAdapter {
    pool: Pool,
    /// Set on the adapter handed out by [`Adapter::begin`]: queries run on this transaction.
    tx: Option<SharedTx>,
}

macro_rules! bind_params {
    ($q:expr, $params:expr) => {{
        let mut q = $q;
        for p in $params {
            q = match p {
                Param::Bool(v) => q.bind(v),
                Param::Int(v) => q.bind(v),
                Param::Float(v) => q.bind(v),
                Param::Text(v) => q.bind(v),
                Param::Json(v) => q.bind(v.map(sqlx::types::Json)),
                Param::Date(v) => q.bind(v),
            };
        }
        q
    }};
}

fn tx_closed() -> Error {
    Error::Database("transaction already finished".into())
}

pub(crate) fn db_err(e: sqlx::Error) -> Error {
    match e.as_database_error() {
        Some(d) if d.is_unique_violation() => Error::Database(format!("unique constraint violated: {d}")),
        _ => Error::Database(e.to_string()),
    }
}

impl SqlxAdapter {
    /// Connect from a URL: `sqlite:...`, `postgres://...` or `mysql://...` (depending on the
    /// enabled features). In-memory SQLite databases use a single, never-recycled connection
    /// so every query sees the same database.
    pub async fn connect(url: &str) -> Result<Self> {
        #[cfg(feature = "sqlite")]
        if url.starts_with("sqlite:") {
            use std::str::FromStr;
            let opts = sqlx::sqlite::SqliteConnectOptions::from_str(url).map_err(db_err)?.create_if_missing(true);
            let mut pool = sqlx::sqlite::SqlitePoolOptions::new();
            if url.contains(":memory:") || url.contains("mode=memory") {
                pool = pool.max_connections(1).min_connections(1).idle_timeout(None).max_lifetime(None);
            }
            return Ok(Self::sqlite(pool.connect_with(opts).await.map_err(db_err)?));
        }
        #[cfg(feature = "postgres")]
        if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            return Ok(Self::postgres(sqlx::PgPool::connect(url).await.map_err(db_err)?));
        }
        #[cfg(feature = "mysql")]
        if url.starts_with("mysql:") || url.starts_with("mariadb:") {
            return Ok(Self::mysql(sqlx::MySqlPool::connect(url).await.map_err(db_err)?));
        }
        Err(Error::Config(format!("unsupported database url (is the cargo feature enabled?): {url}")))
    }

    #[cfg(feature = "sqlite")]
    pub fn sqlite(pool: sqlx::SqlitePool) -> Self {
        Self { pool: Pool::Sqlite(pool), tx: None }
    }

    #[cfg(feature = "postgres")]
    pub fn postgres(pool: sqlx::PgPool) -> Self {
        Self { pool: Pool::Postgres(pool), tx: None }
    }

    #[cfg(feature = "mysql")]
    pub fn mysql(pool: sqlx::MySqlPool) -> Self {
        Self { pool: Pool::MySql(pool), tx: None }
    }

    pub fn dialect(&self) -> Dialect {
        match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(_) => Dialect::Sqlite,
            #[cfg(feature = "postgres")]
            Pool::Postgres(_) => Dialect::Postgres,
            #[cfg(feature = "mysql")]
            Pool::MySql(_) => Dialect::MySql,
        }
    }

    fn sql(&self) -> Sql {
        Sql::new(self.dialect())
    }

    /// Run a query and return its rows as raw (undecoded) records.
    pub(crate) async fn fetch(&self, sql: Sql) -> Result<Vec<Record>> {
        let Sql { text, params, .. } = sql;
        macro_rules! run {
            ($ex:expr, $decode:path) => {
                bind_params!(sqlx::query(AssertSqlSafe(text.as_str())), params)
                    .fetch_all($ex)
                    .await
                    .map_err(db_err)?
                    .iter()
                    .map($decode)
                    .collect()
            };
        }
        if let Some(tx) = &self.tx {
            let mut guard = tx.lock().await;
            return Ok(match guard.as_mut().ok_or_else(tx_closed)? {
                #[cfg(feature = "sqlite")]
                TxConn::Sqlite(t) => run!(&mut **t, decode::sqlite_row),
                #[cfg(feature = "postgres")]
                TxConn::Postgres(t) => run!(&mut **t, decode::pg_row),
                #[cfg(feature = "mysql")]
                TxConn::MySql(t) => run!(&mut **t, decode::mysql_row),
            });
        }
        Ok(match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => run!(p, decode::sqlite_row),
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => run!(p, decode::pg_row),
            #[cfg(feature = "mysql")]
            Pool::MySql(p) => run!(p, decode::mysql_row),
        })
    }

    /// Run a statement, returning the number of affected rows.
    pub(crate) async fn execute(&self, sql: Sql) -> Result<u64> {
        let Sql { text, params, .. } = sql;
        macro_rules! run {
            ($ex:expr) => {
                bind_params!(sqlx::query(AssertSqlSafe(text.as_str())), params)
                    .execute($ex)
                    .await
                    .map_err(db_err)?
                    .rows_affected()
            };
        }
        if let Some(tx) = &self.tx {
            let mut guard = tx.lock().await;
            return Ok(match guard.as_mut().ok_or_else(tx_closed)? {
                #[cfg(feature = "sqlite")]
                TxConn::Sqlite(t) => run!(&mut **t),
                #[cfg(feature = "postgres")]
                TxConn::Postgres(t) => run!(&mut **t),
                #[cfg(feature = "mysql")]
                TxConn::MySql(t) => run!(&mut **t),
            });
        }
        Ok(match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => run!(p),
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => run!(p),
            #[cfg(feature = "mysql")]
            Pool::MySql(p) => run!(p),
        })
    }

    /// Begin a transaction, returning an adapter whose queries run on it.
    async fn begin_tx(&self) -> Result<SqlxAdapter> {
        let conn = match &self.pool {
            #[cfg(feature = "sqlite")]
            Pool::Sqlite(p) => TxConn::Sqlite(p.begin().await.map_err(db_err)?),
            #[cfg(feature = "postgres")]
            Pool::Postgres(p) => TxConn::Postgres(p.begin().await.map_err(db_err)?),
            #[cfg(feature = "mysql")]
            Pool::MySql(p) => TxConn::MySql(p.begin().await.map_err(db_err)?),
        };
        Ok(SqlxAdapter { pool: self.pool.clone(), tx: Some(Arc::new(tokio::sync::Mutex::new(Some(conn)))) })
    }

    /// Commit (or roll back) the transaction this adapter runs on.
    async fn finish_tx(&self, commit: bool) -> Result<()> {
        let Some(conn) = self.tx.as_ref().ok_or_else(tx_closed)?.lock().await.take() else {
            return Err(tx_closed());
        };
        macro_rules! finish {
            ($t:expr) => {
                if commit { $t.commit().await } else { $t.rollback().await }
            };
        }
        match conn {
            #[cfg(feature = "sqlite")]
            TxConn::Sqlite(t) => finish!(t),
            #[cfg(feature = "postgres")]
            TxConn::Postgres(t) => finish!(t),
            #[cfg(feature = "mysql")]
            TxConn::MySql(t) => finish!(t),
        }
        .map_err(db_err)
    }

    async fn fetch_rows(&self, table: &Table, sql: Sql) -> Result<Vec<Record>> {
        Ok(self.fetch(sql).await?.into_iter().map(|r| finish_row(table, r)).collect())
    }

    fn select(&self, table: &Table, where_: &[Where]) -> Sql {
        let mut sql = self.sql();
        sql.push("SELECT ").columns(table).push(" FROM ").ident(&table.model_name).where_clause(table, where_);
        sql
    }

    /// `SET "a" = ?, "b" = ?`
    fn set_clause(sql: &mut Sql, table: &Table, update: &Record) {
        sql.push(" SET ");
        for (i, (col, v)) in update.iter().enumerate() {
            if i > 0 {
                sql.push(", ");
            }
            sql.ident(col).push(" = ");
            let p = to_param(sql.dialect, column_type(table, col), v.clone());
            sql.bind(p);
        }
    }

    /// `WHERE "id" IN (SELECT "id" FROM t WHERE ... LIMIT 1)`
    /// `WHERE id IN (SELECT id ... WHERE <where_> LIMIT 1) AND <where_>`. The repeated
    /// conditions matter on Postgres: when a concurrent transaction changes the row first,
    /// READ COMMITTED re-checks only the outer WHERE against the new row version, so without
    /// them a guarded update (`... WHERE remaining > 0`) would apply to a row that no longer
    /// matches.
    fn first_match(sql: &mut Sql, table: &Table, where_: &[Where]) {
        sql.push(" WHERE ").ident("id").push(" IN (SELECT ").ident("id").push(" FROM ").ident(&table.model_name);
        sql.where_clause(table, where_).push(" LIMIT 1)");
        if !where_.is_empty() {
            sql.push(" AND (");
            sql.conditions(table, where_).push(")");
        }
    }

    fn by_id(&self, table: &Table, id: Value) -> Sql {
        let mut sql = self.select(table, &[]);
        sql.push(" WHERE ").ident("id").push(" = ");
        sql.bind(to_param(sql.dialect, column_type(table, "id"), id));
        sql
    }
}

#[cfg(feature = "mysql")]
impl SqlxAdapter {
    /// Lock the first matching row, then delete or update it in the same transaction
    /// (MySQL has no `RETURNING`). Joins the open transaction, if any.
    async fn mysql_locked(
        &self,
        table: &Table,
        where_: &[Where],
        delete: bool,
        update: Option<&Record>,
    ) -> Result<Option<Record>> {
        if self.tx.is_some() {
            return self.mysql_locked_in_tx(table, where_, delete, update).await;
        }
        let tx = self.begin_tx().await?;
        let result = tx.mysql_locked_in_tx(table, where_, delete, update).await;
        tx.finish_tx(result.is_ok()).await?;
        result
    }

    async fn mysql_locked_in_tx(
        &self,
        table: &Table,
        where_: &[Where],
        delete: bool,
        update: Option<&Record>,
    ) -> Result<Option<Record>> {
        let mut sql = self.select(table, where_);
        sql.push(" LIMIT 1 FOR UPDATE");
        let Some(row) = self.fetch_rows(table, sql).await?.into_iter().next() else {
            return Ok(None);
        };
        let id = row.get("id").cloned().unwrap_or(Value::Null);
        let mut sql = self.sql();
        if delete {
            sql.push("DELETE FROM ").ident(&table.model_name);
        } else {
            sql.push("UPDATE ").ident(&table.model_name);
            Self::set_clause(&mut sql, table, update.expect("update values"));
        }
        sql.push(" WHERE ").ident("id").push(" = ");
        sql.bind(to_param(sql.dialect, column_type(table, "id"), id.clone()));
        self.execute(sql).await?;
        if delete {
            return Ok(Some(row));
        }
        let id = update.and_then(|u| u.get("id")).cloned().unwrap_or(id);
        Ok(self.fetch_rows(table, self.by_id(table, id)).await?.into_iter().next())
    }
}

#[async_trait]
impl Adapter for SqlxAdapter {
    fn id(&self) -> &str {
        match self.dialect() {
            Dialect::Sqlite => "sqlx-sqlite",
            Dialect::Postgres => "sqlx-postgres",
            Dialect::MySql => "sqlx-mysql",
        }
    }

    async fn create(&self, table: &Table, mut data: Record) -> Result<Record> {
        if data.get("id").is_none_or(Value::is_null) {
            data.insert("id".into(), Value::String(even_better_auth::crypto::generate_id(None)));
        }
        let mut sql = self.sql();
        sql.push("INSERT INTO ").ident(&table.model_name).push(" (");
        for (i, col) in data.keys().enumerate() {
            if i > 0 {
                sql.push(", ");
            }
            sql.ident(col);
        }
        sql.push(") VALUES (");
        for (i, (col, v)) in data.iter().enumerate() {
            if i > 0 {
                sql.push(", ");
            }
            let p = to_param(sql.dialect, column_type(table, col), v.clone());
            sql.bind(p);
        }
        sql.push(")");
        if sql.dialect == Dialect::MySql {
            self.execute(sql).await?;
            let id = data.get("id").cloned().unwrap_or(Value::Null);
            let row = self.fetch_rows(table, self.by_id(table, id)).await?.into_iter().next();
            return row.ok_or_else(|| Error::Database("inserted row not found".into()));
        }
        sql.push(" RETURNING ").columns(table);
        let row = self.fetch_rows(table, sql).await?.into_iter().next();
        row.ok_or_else(|| Error::Database("insert returned no row".into()))
    }

    async fn find_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>> {
        let mut sql = self.select(table, where_);
        sql.push(" LIMIT 1");
        Ok(self.fetch_rows(table, sql).await?.into_iter().next())
    }

    async fn find_many(&self, table: &Table, query: &FindManyQuery) -> Result<Vec<Record>> {
        let mut sql = self.select(table, &query.where_);
        if let Some(sort) = &query.sort_by {
            sql.push(" ORDER BY ").ident(&sort.field);
            sql.push(if sort.direction == SortDirection::Desc { " DESC" } else { " ASC" });
            if sql.dialect == Dialect::Postgres {
                sql.push(if sort.direction == SortDirection::Desc { " NULLS LAST" } else { " NULLS FIRST" });
            }
        }
        if query.limit.is_some() || query.offset.is_some() {
            let limit = query.limit.map_or(i64::MAX, |l| i64::try_from(l).unwrap_or(i64::MAX));
            sql.push(" LIMIT ").bind(Param::Int(Some(limit)));
            if let Some(offset) = query.offset {
                sql.push(" OFFSET ").bind(Param::Int(Some(i64::try_from(offset).unwrap_or(i64::MAX))));
            }
        }
        self.fetch_rows(table, sql).await
    }

    async fn count(&self, table: &Table, where_: &[Where]) -> Result<u64> {
        let mut sql = self.sql();
        sql.push("SELECT COUNT(*) AS ")
            .ident("count")
            .push(" FROM ")
            .ident(&table.model_name)
            .where_clause(table, where_);
        let rows = self.fetch(sql).await?;
        let n = rows.first().and_then(|r| r.get("count")).and_then(Value::as_u64);
        Ok(n.unwrap_or(0))
    }

    async fn update(&self, table: &Table, where_: &[Where], update: Record) -> Result<Option<Record>> {
        if update.is_empty() {
            return self.find_one(table, where_).await;
        }
        #[cfg(feature = "mysql")]
        if self.dialect() == Dialect::MySql {
            return self.mysql_locked(table, where_, false, Some(&update)).await;
        }
        let mut sql = self.sql();
        sql.push("UPDATE ").ident(&table.model_name);
        Self::set_clause(&mut sql, table, &update);
        Self::first_match(&mut sql, table, where_);
        sql.push(" RETURNING ").columns(table);
        Ok(self.fetch_rows(table, sql).await?.into_iter().next())
    }

    async fn update_many(&self, table: &Table, where_: &[Where], update: Record) -> Result<u64> {
        if update.is_empty() {
            return self.count(table, where_).await;
        }
        let mut sql = self.sql();
        sql.push("UPDATE ").ident(&table.model_name);
        Self::set_clause(&mut sql, table, &update);
        sql.where_clause(table, where_);
        self.execute(sql).await
    }

    async fn delete(&self, table: &Table, where_: &[Where]) -> Result<()> {
        let mut sql = self.sql();
        sql.push("DELETE FROM ").ident(&table.model_name);
        if sql.dialect == Dialect::MySql {
            sql.where_clause(table, where_).push(" LIMIT 1");
        } else {
            Self::first_match(&mut sql, table, where_);
        }
        self.execute(sql).await?;
        Ok(())
    }

    async fn delete_many(&self, table: &Table, where_: &[Where]) -> Result<u64> {
        let mut sql = self.sql();
        sql.push("DELETE FROM ").ident(&table.model_name).where_clause(table, where_);
        self.execute(sql).await
    }

    async fn consume_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>> {
        #[cfg(feature = "mysql")]
        if self.dialect() == Dialect::MySql {
            return self.mysql_locked(table, where_, true, None).await;
        }
        let mut sql = self.sql();
        sql.push("DELETE FROM ").ident(&table.model_name);
        Self::first_match(&mut sql, table, where_);
        sql.push(" RETURNING ").columns(table);
        Ok(self.fetch_rows(table, sql).await?.into_iter().next())
    }

    async fn migrate(&self, schema: &Schema) -> Result<()> {
        migrate::run(self, schema).await
    }

    async fn begin(&self) -> Result<Option<Arc<dyn Transaction>>> {
        if self.tx.is_some() {
            return Err(Error::Database("nested transactions are not supported".into()));
        }
        Ok(Some(Arc::new(self.begin_tx().await?)))
    }
}

/// Only adapters returned by [`Adapter::begin`] are open transactions; dropping one without
/// committing rolls it back.
#[async_trait]
impl Transaction for SqlxAdapter {
    async fn commit(&self) -> Result<()> {
        self.finish_tx(true).await
    }

    async fn rollback(&self) -> Result<()> {
        self.finish_tx(false).await
    }
}
