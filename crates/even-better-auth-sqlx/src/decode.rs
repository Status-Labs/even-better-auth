//! Per-dialect decoding of result rows into raw JSON values.

#[cfg(feature = "postgres")]
use chrono::{DateTime, Utc};
#[cfg(any(feature = "postgres", feature = "mysql"))]
use chrono::{NaiveDate, NaiveDateTime};
use even_better_auth::db::Record;
#[cfg(any(feature = "postgres", feature = "mysql"))]
use even_better_auth::utils::date;
use serde_json::Value;
use sqlx::{Column, Row, TypeInfo, ValueRef};

fn text_or_bytes<'r, R>(row: &'r R, i: usize) -> Value
where
    R: Row,
    usize: sqlx::ColumnIndex<R>,
    String: sqlx::Decode<'r, R::Database>,
    Vec<u8>: sqlx::Decode<'r, R::Database>,
{
    if let Ok(s) = row.try_get_unchecked::<String, _>(i) {
        return Value::String(s);
    }
    match row.try_get_unchecked::<Vec<u8>, _>(i) {
        Ok(b) => Value::String(String::from_utf8_lossy(&b).into_owned()),
        Err(_) => Value::Null,
    }
}

fn float(f: f64) -> Value {
    serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
}

#[cfg(any(feature = "postgres", feature = "mysql"))]
fn naive(d: NaiveDateTime) -> Value {
    date::to_value(d.and_utc())
}

#[cfg(feature = "sqlite")]
pub(crate) fn sqlite_row(row: &sqlx::sqlite::SqliteRow) -> Record {
    let mut out = Record::new();
    for (i, col) in row.columns().iter().enumerate() {
        let v = match row.try_get_raw(i) {
            Ok(raw) if raw.is_null() => Value::Null,
            Ok(raw) => match raw.type_info().name() {
                "INTEGER" | "BOOLEAN" => row.try_get_unchecked::<i64, _>(i).map(Value::from).unwrap_or(Value::Null),
                "REAL" | "NUMERIC" => row.try_get_unchecked::<f64, _>(i).map(float).unwrap_or(Value::Null),
                _ => text_or_bytes(row, i),
            },
            Err(_) => Value::Null,
        };
        out.insert(col.name().to_owned(), v);
    }
    out
}

#[cfg(feature = "postgres")]
pub(crate) fn pg_row(row: &sqlx::postgres::PgRow) -> Record {
    let mut out = Record::new();
    for (i, col) in row.columns().iter().enumerate() {
        let v = match row.try_get_raw(i) {
            Ok(raw) if raw.is_null() => Value::Null,
            Ok(_) => match col.type_info().name() {
                "BOOL" => row.try_get::<bool, _>(i).map(Value::Bool).unwrap_or(Value::Null),
                "INT2" => row.try_get::<i16, _>(i).map(Value::from).unwrap_or(Value::Null),
                "INT4" => row.try_get::<i32, _>(i).map(Value::from).unwrap_or(Value::Null),
                "INT8" => row.try_get::<i64, _>(i).map(Value::from).unwrap_or(Value::Null),
                "FLOAT4" => row.try_get::<f32, _>(i).map(|f| float(f64::from(f))).unwrap_or(Value::Null),
                "FLOAT8" => row.try_get::<f64, _>(i).map(float).unwrap_or(Value::Null),
                "TIMESTAMPTZ" => row.try_get::<DateTime<Utc>, _>(i).map(date::to_value).unwrap_or(Value::Null),
                "TIMESTAMP" => row.try_get::<NaiveDateTime, _>(i).map(naive).unwrap_or(Value::Null),
                "DATE" => row
                    .try_get::<NaiveDate, _>(i)
                    .map(|d| naive(d.and_hms_opt(0, 0, 0).unwrap_or_default()))
                    .unwrap_or(Value::Null),
                "JSON" | "JSONB" => row.try_get::<sqlx::types::Json<Value>, _>(i).map(|j| j.0).unwrap_or(Value::Null),
                _ => text_or_bytes(row, i),
            },
            Err(_) => Value::Null,
        };
        out.insert(col.name().to_owned(), v);
    }
    out
}

#[cfg(feature = "mysql")]
pub(crate) fn mysql_row(row: &sqlx::mysql::MySqlRow) -> Record {
    let mut out = Record::new();
    for (i, col) in row.columns().iter().enumerate() {
        let v = match row.try_get_raw(i) {
            Ok(raw) if raw.is_null() => Value::Null,
            Ok(_) => match col.type_info().name() {
                "BOOLEAN" | "TINYINT" | "SMALLINT" | "INT" | "MEDIUMINT" | "BIGINT" | "YEAR" | "TINYINT UNSIGNED"
                | "SMALLINT UNSIGNED" | "INT UNSIGNED" | "MEDIUMINT UNSIGNED" => {
                    row.try_get_unchecked::<i64, _>(i).map(Value::from).unwrap_or(Value::Null)
                }
                "BIGINT UNSIGNED" => row.try_get_unchecked::<u64, _>(i).map(Value::from).unwrap_or(Value::Null),
                "FLOAT" => row.try_get_unchecked::<f32, _>(i).map(|f| float(f64::from(f))).unwrap_or(Value::Null),
                "DOUBLE" => row.try_get_unchecked::<f64, _>(i).map(float).unwrap_or(Value::Null),
                "DATETIME" | "TIMESTAMP" => {
                    row.try_get_unchecked::<NaiveDateTime, _>(i).map(naive).unwrap_or(Value::Null)
                }
                "DATE" => row
                    .try_get_unchecked::<NaiveDate, _>(i)
                    .map(|d| naive(d.and_hms_opt(0, 0, 0).unwrap_or_default()))
                    .unwrap_or(Value::Null),
                _ => text_or_bytes(row, i),
            },
            Err(_) => Value::Null,
        };
        out.insert(col.name().to_owned(), v);
    }
    out
}
