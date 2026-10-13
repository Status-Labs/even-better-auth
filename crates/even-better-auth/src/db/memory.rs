//! In-memory adapter, intended for tests and prototyping.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::RwLock;

use super::adapter::{Adapter, Connector, FindManyQuery, Mode, Operator, Record, SortDirection, Where};
use super::schema::{FieldType, Schema, Table};
use super::transaction::Transaction;
use crate::error::{Error, Result};

type Tables = HashMap<String, Vec<Record>>;

/// Stores rows in process memory. Supports transactions: transactions run one at a time,
/// each on a snapshot that commits with a three-way merge, so concurrent non-transactional
/// writes to other rows are preserved.
#[derive(Default)]
pub struct MemoryAdapter {
    tables: Arc<RwLock<Tables>>,
    tx_lock: Arc<tokio::sync::Mutex<()>>,
}

impl MemoryAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of all rows in a table (by model name), for tests.
    pub async fn dump(&self, model: &str) -> Vec<Record> {
        self.tables.read().await.get(model).cloned().unwrap_or_default()
    }
}

fn column_type(table: &Table, column: &str) -> Option<FieldType> {
    if column == "id" {
        return Some(FieldType::String);
    }
    table.field_by_column(column).map(|(_, f)| f.field_type)
}

fn compare(ty: Option<FieldType>, a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64()?.partial_cmp(&y.as_f64()?),
        (Value::String(x), Value::String(y)) if ty == Some(FieldType::Date) => {
            let x = chrono::DateTime::parse_from_rfc3339(x).ok()?;
            let y = chrono::DateTime::parse_from_rfc3339(y).ok()?;
            Some(x.cmp(&y))
        }
        (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn values_equal(ty: Option<FieldType>, a: &Value, b: &Value, mode: Mode) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) if mode == Mode::Insensitive => x.to_lowercase() == y.to_lowercase(),
        (Value::Number(_), Value::Number(_)) | (Value::String(_), Value::String(_)) => {
            compare(ty, a, b) == Some(Ordering::Equal)
        }
        _ => a == b,
    }
}

fn str_op(a: &Value, b: &Value, mode: Mode, f: impl Fn(&str, &str) -> bool) -> bool {
    match (a.as_str(), b.as_str()) {
        (Some(x), Some(y)) if mode == Mode::Insensitive => f(&x.to_lowercase(), &y.to_lowercase()),
        (Some(x), Some(y)) => f(x, y),
        _ => false,
    }
}

fn matches_one(table: &Table, row: &Record, w: &Where) -> bool {
    let ty = column_type(table, &w.field);
    let null = Value::Null;
    let actual = row.get(&w.field).unwrap_or(&null);
    match w.operator {
        Operator::Eq => values_equal(ty, actual, &w.value, w.mode),
        Operator::Ne => !values_equal(ty, actual, &w.value, w.mode),
        Operator::Lt => compare(ty, actual, &w.value) == Some(Ordering::Less),
        Operator::Lte => matches!(compare(ty, actual, &w.value), Some(Ordering::Less | Ordering::Equal)),
        Operator::Gt => compare(ty, actual, &w.value) == Some(Ordering::Greater),
        Operator::Gte => matches!(compare(ty, actual, &w.value), Some(Ordering::Greater | Ordering::Equal)),
        Operator::In => w.value.as_array().is_some_and(|vs| vs.iter().any(|v| values_equal(ty, actual, v, w.mode))),
        Operator::NotIn => !w.value.as_array().is_some_and(|vs| vs.iter().any(|v| values_equal(ty, actual, v, w.mode))),
        Operator::Contains => match actual {
            Value::Array(items) => items.contains(&w.value),
            _ => str_op(actual, &w.value, w.mode, |a, b| a.contains(b)),
        },
        Operator::StartsWith => str_op(actual, &w.value, w.mode, |a, b| a.starts_with(b)),
        Operator::EndsWith => str_op(actual, &w.value, w.mode, |a, b| a.ends_with(b)),
    }
}

/// Evaluate a where-list the way the SQL adapters do: all AND clauses must hold, and if
/// any OR clauses exist at least one of them must hold.
pub(crate) fn matches(table: &Table, row: &Record, where_: &[Where]) -> bool {
    let (ands, ors): (Vec<_>, Vec<_>) = where_.iter().partition(|w| w.connector == Connector::And);
    ands.iter().all(|w| matches_one(table, row, w))
        && (ors.is_empty() || ors.iter().any(|w| matches_one(table, row, w)))
}

fn check_unique(table: &Table, rows: &[Record], candidate: &Record, skip: Option<usize>) -> Result<()> {
    for (name, field) in &table.fields {
        if !field.unique {
            continue;
        }
        let col = table.column(name);
        let Some(v) = candidate.get(col).filter(|v| !v.is_null()) else { continue };
        if rows.iter().enumerate().any(|(i, r)| Some(i) != skip && r.get(col) == Some(v)) {
            return Err(Error::Database(format!("unique constraint violated on {}.{}", table.model_name, col)));
        }
    }
    Ok(())
}

#[async_trait]
impl Adapter for MemoryAdapter {
    fn id(&self) -> &str {
        "memory"
    }

    async fn create(&self, table: &Table, mut data: Record) -> Result<Record> {
        let mut tables = self.tables.write().await;
        let rows = tables.entry(table.model_name.clone()).or_default();
        if !data.contains_key("id") {
            // Database-assigned ids: the next unused integer.
            let mut n = rows.len() + 1;
            while rows.iter().any(|r| r.get("id").and_then(Value::as_str) == Some(n.to_string().as_str())) {
                n += 1;
            }
            data.insert("id".into(), Value::String(n.to_string()));
        }
        if rows.iter().any(|r| r.get("id") == data.get("id")) {
            return Err(Error::Database(format!("duplicate primary key in {}", table.model_name)));
        }
        check_unique(table, rows, &data, None)?;
        rows.push(data.clone());
        Ok(data)
    }

    async fn find_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>> {
        let tables = self.tables.read().await;
        Ok(tables.get(&table.model_name).and_then(|rows| rows.iter().find(|r| matches(table, r, where_)).cloned()))
    }

    async fn find_many(&self, table: &Table, query: &FindManyQuery) -> Result<Vec<Record>> {
        let tables = self.tables.read().await;
        let mut rows: Vec<Record> = tables
            .get(&table.model_name)
            .map(|rows| rows.iter().filter(|r| matches(table, r, &query.where_)).cloned().collect())
            .unwrap_or_default();
        if let Some(sort) = &query.sort_by {
            let ty = column_type(table, &sort.field);
            rows.sort_by(|a, b| {
                let null = Value::Null;
                let (x, y) = (a.get(&sort.field).unwrap_or(&null), b.get(&sort.field).unwrap_or(&null));
                // NULLs sort first ascending, as in SQLite and MySQL.
                let ord = match (x.is_null(), y.is_null()) {
                    (true, true) => Ordering::Equal,
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    _ => compare(ty, x, y).unwrap_or(Ordering::Equal),
                };
                if sort.direction == SortDirection::Desc { ord.reverse() } else { ord }
            });
        }
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(usize::MAX);
        Ok(rows.into_iter().skip(offset).take(limit).collect())
    }

    async fn count(&self, table: &Table, where_: &[Where]) -> Result<u64> {
        let tables = self.tables.read().await;
        Ok(tables.get(&table.model_name).map_or(0, |rows| rows.iter().filter(|r| matches(table, r, where_)).count())
            as u64)
    }

    async fn update(&self, table: &Table, where_: &[Where], update: Record) -> Result<Option<Record>> {
        let mut tables = self.tables.write().await;
        let Some(rows) = tables.get_mut(&table.model_name) else { return Ok(None) };
        let Some(idx) = rows.iter().position(|r| matches(table, r, where_)) else { return Ok(None) };
        let mut next = rows[idx].clone();
        next.extend(update);
        check_unique(table, rows, &next, Some(idx))?;
        rows[idx] = next.clone();
        Ok(Some(next))
    }

    async fn update_many(&self, table: &Table, where_: &[Where], update: Record) -> Result<u64> {
        let mut tables = self.tables.write().await;
        let Some(rows) = tables.get_mut(&table.model_name) else { return Ok(0) };
        let mut n = 0;
        for row in rows.iter_mut().filter(|r| matches(table, r, where_)) {
            row.extend(update.clone());
            n += 1;
        }
        Ok(n)
    }

    async fn delete(&self, table: &Table, where_: &[Where]) -> Result<()> {
        let mut tables = self.tables.write().await;
        if let Some(rows) = tables.get_mut(&table.model_name)
            && let Some(idx) = rows.iter().position(|r| matches(table, r, where_))
        {
            rows.remove(idx);
        }
        Ok(())
    }

    async fn delete_many(&self, table: &Table, where_: &[Where]) -> Result<u64> {
        let mut tables = self.tables.write().await;
        let Some(rows) = tables.get_mut(&table.model_name) else { return Ok(0) };
        let before = rows.len();
        rows.retain(|r| !matches(table, r, where_));
        Ok((before - rows.len()) as u64)
    }

    async fn consume_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>> {
        let mut tables = self.tables.write().await;
        let Some(rows) = tables.get_mut(&table.model_name) else { return Ok(None) };
        Ok(rows.iter().position(|r| matches(table, r, where_)).map(|idx| rows.remove(idx)))
    }

    async fn begin(&self) -> Result<Option<Arc<dyn Transaction>>> {
        let guard = self.tx_lock.clone().lock_owned().await;
        let base = self.tables.read().await.clone();
        let work = MemoryAdapter { tables: Arc::new(RwLock::new(base.clone())), tx_lock: Default::default() };
        Ok(Some(Arc::new(MemoryTransaction {
            live: self.tables.clone(),
            base,
            work,
            guard: std::sync::Mutex::new(Some(guard)),
        })))
    }
}

/// A transaction over a [`MemoryAdapter`]: reads and writes go to a private copy of the
/// tables, which is merged into the live tables on commit.
struct MemoryTransaction {
    live: Arc<RwLock<Tables>>,
    base: Tables,
    work: MemoryAdapter,
    /// Held until commit or rollback (or drop), serializing transactions.
    guard: std::sync::Mutex<Option<tokio::sync::OwnedMutexGuard<()>>>,
}

impl MemoryTransaction {
    fn release(&self) {
        self.guard.lock().expect("guard lock").take();
    }
}

/// Apply the `base -> work` delta onto `live`: the transaction's creates, updates and deletes,
/// leaving rows the transaction did not touch (including concurrent writes) as they are.
fn merge(live: &mut Tables, base: &Tables, work: &Tables) {
    let id = |r: &Record| r.get("id").cloned();
    for (model, work_rows) in work {
        let empty = Vec::new();
        let base_rows = base.get(model).unwrap_or(&empty);
        let target = live.entry(model.clone()).or_default();
        for before in base_rows {
            let Some(row_id) = id(before) else { continue };
            let after = work_rows.iter().find(|r| id(r).as_ref() == Some(&row_id));
            let pos = target.iter().position(|r| id(r).as_ref() == Some(&row_id));
            match (after, pos) {
                (None, Some(i)) => {
                    target.remove(i);
                }
                (Some(after), Some(i)) if after != before => target[i] = after.clone(),
                (Some(after), None) if after != before => target.push(after.clone()),
                _ => {}
            }
        }
        for row in work_rows {
            let row_id = id(row);
            if !base_rows.iter().any(|b| id(b) == row_id) {
                target.push(row.clone());
            }
        }
    }
}

#[async_trait]
impl Adapter for MemoryTransaction {
    fn id(&self) -> &str {
        "memory"
    }
    async fn create(&self, table: &Table, data: Record) -> Result<Record> {
        self.work.create(table, data).await
    }
    async fn find_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>> {
        self.work.find_one(table, where_).await
    }
    async fn find_many(&self, table: &Table, query: &FindManyQuery) -> Result<Vec<Record>> {
        self.work.find_many(table, query).await
    }
    async fn count(&self, table: &Table, where_: &[Where]) -> Result<u64> {
        self.work.count(table, where_).await
    }
    async fn update(&self, table: &Table, where_: &[Where], update: Record) -> Result<Option<Record>> {
        self.work.update(table, where_, update).await
    }
    async fn update_many(&self, table: &Table, where_: &[Where], update: Record) -> Result<u64> {
        self.work.update_many(table, where_, update).await
    }
    async fn delete(&self, table: &Table, where_: &[Where]) -> Result<()> {
        self.work.delete(table, where_).await
    }
    async fn delete_many(&self, table: &Table, where_: &[Where]) -> Result<u64> {
        self.work.delete_many(table, where_).await
    }
    async fn consume_one(&self, table: &Table, where_: &[Where]) -> Result<Option<Record>> {
        self.work.consume_one(table, where_).await
    }
    async fn migrate(&self, _schema: &Schema) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Transaction for MemoryTransaction {
    async fn commit(&self) -> Result<()> {
        let work = self.work.tables.read().await;
        merge(&mut *self.live.write().await, &self.base, &work);
        self.release();
        Ok(())
    }

    async fn rollback(&self) -> Result<()> {
        self.release();
        Ok(())
    }
}
