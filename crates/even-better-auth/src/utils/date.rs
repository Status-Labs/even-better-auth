//! Dates are exchanged as RFC 3339 strings with millisecond precision, which is what
//! JavaScript's `Date.prototype.toISOString` produces (e.g. `2024-01-01T00:00:00.000Z`).

use chrono::{DateTime, SubsecRound, Utc};
use serde::{Deserialize, Deserializer, Serializer};
use serde_json::Value;

pub fn now() -> DateTime<Utc> {
    Utc::now().trunc_subsecs(3)
}

pub fn format(d: DateTime<Utc>) -> String {
    d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn now_value() -> Value {
    Value::String(format(now()))
}

pub fn to_value(d: DateTime<Utc>) -> Value {
    Value::String(format(d))
}

/// Parse an RFC 3339 string or a millisecond timestamp.
pub fn parse_value(v: &Value) -> Option<DateTime<Utc>> {
    match v {
        Value::String(s) => DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc)),
        Value::Number(n) => n.as_i64().and_then(DateTime::from_timestamp_millis),
        _ => None,
    }
}

/// `now + secs`.
pub fn in_secs(secs: i64) -> DateTime<Utc> {
    now() + chrono::Duration::seconds(secs)
}

pub fn serialize<S: Serializer>(d: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format(*d))
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let v = Value::deserialize(d)?;
    parse_value(&v).ok_or_else(|| serde::de::Error::custom(format!("invalid date: {v}")))
}

pub mod option {
    use super::*;

    pub fn serialize<S: Serializer>(d: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_str(&format(*d)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<DateTime<Utc>>, D::Error> {
        let v = Value::deserialize(d)?;
        if v.is_null() {
            return Ok(None);
        }
        parse_value(&v).map(Some).ok_or_else(|| serde::de::Error::custom(format!("invalid date: {v}")))
    }
}
