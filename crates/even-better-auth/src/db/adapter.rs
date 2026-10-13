//! The database adapter interface.
//!
//! Backends implement [`Adapter`], which receives already-resolved [`Table`]s and
//! records/where-clauses keyed by **column names**. The [`Db`] wrapper used by the
//! rest of the library speaks logical names and takes care of model/field mapping,
//! id generation, default values and `onUpdate` values (the role of
//! `createAdapterFactory` in the TypeScript implementation).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value};

use super::schema::{FieldType, Schema, Table};
use super::transaction::Transaction;
use crate::error::{Error, Result};

/// A database row: column (or logical field) name to JSON value.
/// Dates are RFC 3339 strings with millisecond precision.
pub type Record = Map<String, Value>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Operator {
    #[default]
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Connector {
    #[default]
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Sensitive,
    Insensitive,
}

#[derive(Debug, Clone)]
pub struct Where {
    pub field: String,
    pub value: Value,
    pub operator: Operator,
    pub connector: Connector,
    pub mode: Mode,
}

impl Where {
    pub fn new(field: impl Into<String>, operator: Operator, value: impl Into<Value>) -> Self {
        Self { field: field.into(), value: value.into(), operator, connector: Connector::And, mode: Mode::Sensitive }
    }
    pub fn eq(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Operator::Eq, value)
    }
    pub fn ne(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Operator::Ne, value)
    }
    pub fn gt(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Operator::Gt, value)
    }
    pub fn lt(field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::new(field, Operator::Lt, value)
    }
    pub fn is_in(field: impl Into<String>, values: Vec<Value>) -> Self {
        Self::new(field, Operator::In, Value::Array(values))
    }
    pub fn or(mut self) -> Self {
        self.connector = Connector::Or;
        self
    }
    pub fn insensitive(mut self) -> Self {
        self.mode = Mode::Insensitive;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone)]
pub struct SortBy {
    pub field: String,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Default)]
pub struct FindManyQuery {
    pub where_: Vec<Where>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<SortBy>,
}

/// A storage backend. All names are database (column/model) names.
#[async_trait]
pub trait Adapter: Send + Sync {
    /// Short identifier, e.g. `"memory"` or `"sqlx-postgres"`.
    fn id(&self) -> &str;

    async fn create(&self, table: &Table, data: Record) -> Result<Record>;
    async fn find_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>>;
    async fn find_many(&self, table: &Table, query: &FindManyQuery) -> Result<Vec<Record>>;
    async fn count(&self, table: &Table, where_: &[Where]) -> Result<u64>;
    /// Update the first matching row, returning it after the update.
    async fn update(&self, table: &Table, where_: &[Where], update: Record) -> Result<Option<Record>>;
    async fn update_many(&self, table: &Table, where_: &[Where], update: Record) -> Result<u64>;
    async fn delete(&self, table: &Table, where_: &[Where]) -> Result<()>;
    async fn delete_many(&self, table: &Table, where_: &[Where]) -> Result<u64>;

    /// Atomically find and delete one row. Backends should override this with a
    /// truly atomic implementation; the default is find-then-delete.
    async fn consume_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>> {
        let Some(row) = self.find_one(table, where_).await? else {
            return Ok(None);
        };
        let id = row.get("id").cloned().unwrap_or(Value::Null);
        let n = self.delete_many(table, &[Where::eq("id", id)]).await?;
        Ok(if n > 0 { Some(row) } else { None })
    }

    /// Create missing tables/columns for `schema`. Optional.
    async fn migrate(&self, _schema: &Schema) -> Result<()> {
        Ok(())
    }

    /// Begin a transaction, or `None` when the backend does not support them (the TS
    /// `transaction: false` adapter option). See [`Db::transaction`].
    async fn begin(&self) -> Result<Option<Arc<dyn Transaction>>> {
        Ok(None)
    }
}

/// How record ids are generated.
#[derive(Clone, Default)]
pub enum IdGenerator {
    /// 32 random alphanumeric characters (default).
    #[default]
    Random,
    Uuid,
    /// The database assigns ids.
    Database,
    Custom(Arc<dyn Fn(&str) -> String + Send + Sync>),
}

impl IdGenerator {
    pub fn generate(&self, model: &str) -> Option<String> {
        match self {
            IdGenerator::Random => Some(crate::crypto::generate_id(None)),
            IdGenerator::Uuid => Some(uuid_v4()),
            IdGenerator::Database => None,
            IdGenerator::Custom(f) => Some(f(model)),
        }
    }
}

fn uuid_v4() -> String {
    let mut b: [u8; 16] = crate::crypto::random_bytes();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Schema-aware facade over an [`Adapter`] that speaks logical names.
#[derive(Clone)]
pub struct Db {
    adapter: Arc<dyn Adapter>,
    schema: Arc<Schema>,
    id_generator: IdGenerator,
}

impl Db {
    pub fn new(adapter: Arc<dyn Adapter>, schema: Arc<Schema>, id_generator: IdGenerator) -> Self {
        Self { adapter, schema, id_generator }
    }

    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The base adapter (outside any transaction).
    pub fn adapter(&self) -> &Arc<dyn Adapter> {
        &self.adapter
    }

    /// The adapter to use for the current call: the open transaction, if any (`getCurrentAdapter`).
    fn conn(&self) -> Arc<dyn Adapter> {
        super::transaction::current(&self.adapter).unwrap_or_else(|| self.adapter.clone())
    }

    pub fn table(&self, model: &str) -> Result<&Table> {
        self.schema.resolve(model).ok_or_else(|| Error::Database(format!("model \"{model}\" not found in schema")))
    }

    fn to_columns(table: &Table, data: Record) -> Record {
        data.into_iter()
            .filter(|(k, _)| k == "id" || table.field(k).is_some())
            .map(|(k, v)| {
                let v = normalize_value(table.field_type(&k), v);
                (table.column(&k).to_owned(), v)
            })
            .collect()
    }

    fn from_columns(table: &Table, row: Record) -> Record {
        row.into_iter()
            .map(|(col, v)| match table.field_by_column(&col) {
                Some((name, f)) => (name.to_owned(), denormalize_value(f.field_type, v)),
                None => (col, v),
            })
            .collect()
    }

    fn map_where(table: &Table, where_: &[Where]) -> Vec<Where> {
        where_
            .iter()
            .map(|w| Where {
                field: table.column(&w.field).to_owned(),
                value: normalize_value(table.field_type(&w.field), w.value.clone()),
                ..w.clone()
            })
            .collect()
    }

    /// Fill in default values for missing fields (as [`Db::create`] does).
    pub fn with_defaults(&self, model: &str, mut data: Record) -> Result<Record> {
        let table = self.table(model)?;
        for (name, field) in &table.fields {
            let missing = data.get(name).is_none_or(Value::is_null);
            if missing && let Some(d) = &field.default_value {
                data.insert(name.clone(), d.resolve());
            }
        }
        Ok(data)
    }

    pub fn id_generator(&self) -> &IdGenerator {
        &self.id_generator
    }

    /// A new id for `model` from the configured generator; random when the database
    /// would assign it.
    pub fn generate_id(&self, model: &str) -> String {
        self.id_generator.generate(model).unwrap_or_else(|| crate::crypto::generate_id(None))
    }

    /// Insert a row. Applies default values and generates an id unless `force_id` and an id is given.
    pub async fn create(&self, model: &str, data: Record, force_id: bool) -> Result<Record> {
        let mut data = self.with_defaults(model, data)?;
        let table = self.table(model)?;
        if !(force_id && data.contains_key("id")) {
            match self.id_generator.generate(&table.key) {
                Some(id) => {
                    data.insert("id".into(), Value::String(id));
                }
                None => {
                    data.remove("id");
                }
            }
        }
        let row = self.conn().create(table, Self::to_columns(table, data)).await?;
        Ok(Self::from_columns(table, row))
    }

    pub async fn find_one(&self, model: &str, where_: &[Where]) -> Result<Option<Record>> {
        let table = self.table(model)?;
        let row = self.conn().find_one(table, &Self::map_where(table, where_)).await?;
        Ok(row.map(|r| Self::from_columns(table, r)))
    }

    pub async fn find_many(&self, model: &str, mut query: FindManyQuery) -> Result<Vec<Record>> {
        let table = self.table(model)?;
        query.where_ = Self::map_where(table, &query.where_);
        if let Some(s) = &mut query.sort_by {
            s.field = table.column(&s.field).to_owned();
        }
        let rows = self.conn().find_many(table, &query).await?;
        Ok(rows.into_iter().map(|r| Self::from_columns(table, r)).collect())
    }

    pub async fn count(&self, model: &str, where_: &[Where]) -> Result<u64> {
        let table = self.table(model)?;
        self.conn().count(table, &Self::map_where(table, where_)).await
    }

    fn with_on_update(table: &Table, mut update: Record) -> Record {
        for (name, field) in &table.fields {
            if let Some(on_update) = &field.on_update
                && !update.contains_key(name)
            {
                update.insert(name.clone(), on_update.resolve());
            }
        }
        update
    }

    pub async fn update(&self, model: &str, where_: &[Where], update: Record) -> Result<Option<Record>> {
        let table = self.table(model)?;
        let update = Self::to_columns(table, Self::with_on_update(table, update));
        let row = self.conn().update(table, &Self::map_where(table, where_), update).await?;
        Ok(row.map(|r| Self::from_columns(table, r)))
    }

    pub async fn update_many(&self, model: &str, where_: &[Where], update: Record) -> Result<u64> {
        let table = self.table(model)?;
        let update = Self::to_columns(table, Self::with_on_update(table, update));
        self.conn().update_many(table, &Self::map_where(table, where_), update).await
    }

    pub async fn delete(&self, model: &str, where_: &[Where]) -> Result<()> {
        let table = self.table(model)?;
        self.conn().delete(table, &Self::map_where(table, where_)).await
    }

    pub async fn delete_many(&self, model: &str, where_: &[Where]) -> Result<u64> {
        let table = self.table(model)?;
        self.conn().delete_many(table, &Self::map_where(table, where_)).await
    }

    pub async fn consume_one(&self, model: &str, where_: &[Where]) -> Result<Option<Record>> {
        let table = self.table(model)?;
        let row = self.conn().consume_one(table, &Self::map_where(table, where_)).await?;
        Ok(row.map(|r| Self::from_columns(table, r)))
    }

    /// Atomically update the first row matching `where_` (`incrementOne`): add `increment` to
    /// numeric fields and apply `set`. Implemented as compare-and-swap on the incremented
    /// fields, retried on conflict. Returns the updated row, or `None` if nothing matched.
    pub async fn increment_one(
        &self,
        model: &str,
        where_: &[Where],
        increment: &[(&str, i64)],
        set: Record,
    ) -> Result<Option<Record>> {
        for _ in 0..16 {
            let Some(row) = self.find_one(model, where_).await? else { return Ok(None) };
            let mut update = set.clone();
            let mut guard = where_.to_vec();
            guard.push(Where::eq("id", row.get("id").cloned().unwrap_or(Value::Null)));
            for (field, delta) in increment {
                let current = row.get(*field).and_then(Value::as_i64).unwrap_or(0);
                update.insert((*field).to_owned(), (current + delta).into());
                guard.push(Where::eq(*field, row.get(*field).cloned().unwrap_or(Value::Null)));
            }
            if update.is_empty() {
                return Ok(Some(row));
            }
            if let Some(updated) = self.update(model, &guard, update).await? {
                return Ok(Some(updated));
            }
        }
        Err(Error::Database(format!("increment_one on {model}: too much contention")))
    }

    /// Create or update tables to match the schema (if the adapter supports it).
    pub async fn migrate(&self) -> Result<()> {
        self.adapter.migrate(&self.schema).await
    }
}

/// Normalize values on the way into the database: dates become canonical RFC 3339
/// strings with millisecond precision so string comparison matches time order.
fn normalize_value(ty: Option<FieldType>, v: Value) -> Value {
    match (ty, &v) {
        (Some(FieldType::Date), Value::String(s)) => match chrono::DateTime::parse_from_rfc3339(s) {
            Ok(d) => Value::String(crate::utils::date::format(d.with_timezone(&chrono::Utc))),
            Err(_) => v,
        },
        (Some(FieldType::Date), Value::Number(n)) => n
            .as_i64()
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|d| Value::String(crate::utils::date::format(d)))
            .unwrap_or(v),
        (Some(FieldType::Date), Value::Array(items)) => {
            Value::Array(items.iter().cloned().map(|i| normalize_value(ty, i)).collect())
        }
        _ => v,
    }
}

fn denormalize_value(ty: FieldType, v: Value) -> Value {
    normalize_value(Some(ty), v)
}
