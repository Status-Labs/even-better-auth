//! SQL text building, parameter conversion and value decoding shared by all dialects.

use chrono::{DateTime, NaiveDateTime, Utc};
use even_better_auth::db::{Connector, FieldType, Mode, Operator, Record, Table, Where};
use even_better_auth::utils::date;
use serde_json::Value;

/// The SQL dialect an adapter speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
}

/// A bound parameter. `None` is a NULL of the given type, which Postgres needs to
/// infer parameter types.
#[derive(Debug, Clone)]
pub(crate) enum Param {
    Bool(Option<bool>),
    Int(Option<i64>),
    Float(Option<f64>),
    Text(Option<String>),
    Json(Option<Value>),
    Date(Option<DateTime<Utc>>),
}

/// A SQL statement under construction: text with placeholders plus its parameters.
pub(crate) struct Sql {
    pub dialect: Dialect,
    pub text: String,
    pub params: Vec<Param>,
}

impl Sql {
    pub fn new(dialect: Dialect) -> Self {
        Self { dialect, text: String::new(), params: vec![] }
    }

    pub fn push(&mut self, s: &str) -> &mut Self {
        self.text.push_str(s);
        self
    }

    pub fn ident(&mut self, name: &str) -> &mut Self {
        let quoted = quote(self.dialect, name);
        self.text.push_str(&quoted);
        self
    }

    pub fn bind(&mut self, p: Param) -> &mut Self {
        self.params.push(p);
        match self.dialect {
            Dialect::Postgres => {
                let n = self.params.len();
                self.text.push_str(&format!("${n}"));
            }
            _ => self.text.push('?'),
        }
        self
    }

    /// `"a", "b", ...` for the id and every field column of `table`.
    pub fn columns(&mut self, table: &Table) -> &mut Self {
        for (i, col) in select_columns(table).iter().enumerate() {
            if i > 0 {
                self.push(", ");
            }
            self.ident(col);
        }
        self
    }

    /// Append ` WHERE ...` (nothing if `where_` is empty).
    pub fn where_clause(&mut self, table: &Table, where_: &[Where]) -> &mut Self {
        if where_.is_empty() {
            return self;
        }
        self.push(" WHERE ");
        self.conditions(table, where_)
    }

    /// Append the conditions of `where_` (non-empty) without the `WHERE` keyword.
    pub fn conditions(&mut self, table: &Table, where_: &[Where]) -> &mut Self {
        let (ands, ors): (Vec<_>, Vec<_>) = where_.iter().partition(|w| w.connector == Connector::And);
        let mut first = true;
        for w in &ands {
            if !first {
                self.push(" AND ");
            }
            first = false;
            self.condition(table, w);
        }
        if !ors.is_empty() {
            if !first {
                self.push(" AND ");
            }
            self.push("(");
            for (i, w) in ors.iter().enumerate() {
                if i > 0 {
                    self.push(" OR ");
                }
                self.condition(table, w);
            }
            self.push(")");
        }
        self
    }

    fn condition(&mut self, table: &Table, w: &Where) {
        let ty = column_type(table, &w.field);
        let col = quote(self.dialect, &w.field);
        let textual = matches!(ty, None | Some(FieldType::String));
        let insensitive = w.mode == Mode::Insensitive && textual;
        let lhs = if insensitive { format!("LOWER({col})") } else { col.clone() };
        let fold = |v: &Value| match v {
            Value::String(s) if insensitive => Value::String(s.to_lowercase()),
            v => v.clone(),
        };
        self.push("(");
        match w.operator {
            Operator::Eq | Operator::Ne if w.value.is_null() => {
                self.push(&col).push(if w.operator == Operator::Eq { " IS NULL" } else { " IS NOT NULL" });
            }
            Operator::Eq => {
                self.push(&lhs).push(" = ");
                self.value(ty, &fold(&w.value));
            }
            Operator::Ne => {
                self.push(&lhs).push(" <> ");
                self.value(ty, &fold(&w.value));
                self.push(" OR ").push(&col).push(" IS NULL");
            }
            Operator::Lt | Operator::Lte | Operator::Gt | Operator::Gte => {
                let op = match w.operator {
                    Operator::Lt => " < ",
                    Operator::Lte => " <= ",
                    Operator::Gt => " > ",
                    _ => " >= ",
                };
                self.push(&col).push(op);
                self.value(ty, &w.value);
            }
            Operator::In | Operator::NotIn => {
                let items = match &w.value {
                    Value::Array(items) => items.clone(),
                    v => vec![v.clone()],
                };
                let has_null = items.iter().any(Value::is_null);
                let items: Vec<Value> = items.iter().filter(|v| !v.is_null()).map(fold).collect();
                let list = |s: &mut Self, negate: bool| {
                    s.push(&lhs).push(if negate { " NOT IN (" } else { " IN (" });
                    for (i, v) in items.iter().enumerate() {
                        if i > 0 {
                            s.push(", ");
                        }
                        s.value(ty, v);
                    }
                    s.push(")");
                };
                match (w.operator, items.is_empty(), has_null) {
                    (Operator::In, true, false) => {
                        self.push("1 = 0");
                    }
                    (Operator::In, true, true) => {
                        self.push(&col).push(" IS NULL");
                    }
                    (Operator::In, false, has_null) => {
                        list(self, false);
                        if has_null {
                            self.push(" OR ").push(&col).push(" IS NULL");
                        }
                    }
                    (_, true, false) => {
                        self.push("1 = 1");
                    }
                    (_, true, true) => {
                        self.push(&col).push(" IS NOT NULL");
                    }
                    (_, false, true) => {
                        self.push(&col).push(" IS NOT NULL AND ");
                        list(self, true);
                    }
                    (_, false, false) => {
                        list(self, true);
                        self.push(" OR ").push(&col).push(" IS NULL");
                    }
                }
            }
            Operator::Contains if matches!(ty, Some(FieldType::StringArray | FieldType::NumberArray)) => {
                self.array_contains(&col, &w.value);
            }
            Operator::Contains | Operator::StartsWith | Operator::EndsWith => {
                let needle = match &w.value {
                    Value::String(s) => s.clone(),
                    v => v.to_string(),
                };
                let needle = if insensitive { needle.to_lowercase() } else { needle };
                let (pre, post) = match w.operator {
                    Operator::Contains => (true, true),
                    Operator::StartsWith => (false, true),
                    _ => (true, false),
                };
                self.pattern(&lhs, &needle, pre, post);
            }
        }
        self.push(")");
    }

    /// A substring match. SQLite's LIKE ignores ASCII case, so it uses GLOB instead.
    fn pattern(&mut self, lhs: &str, needle: &str, pre: bool, post: bool) {
        let (any, escaped, op) = match self.dialect {
            Dialect::Sqlite => ("*", escape_glob(needle), " GLOB "),
            _ => ("%", escape_like(needle), " LIKE "),
        };
        let pattern = format!("{}{escaped}{}", if pre { any } else { "" }, if post { any } else { "" });
        self.push(lhs).push(op);
        self.bind(Param::Text(Some(pattern)));
        if self.dialect != Dialect::Sqlite {
            self.push(" ESCAPE '!'");
        }
    }

    fn array_contains(&mut self, col: &str, item: &Value) {
        match self.dialect {
            Dialect::Postgres => {
                self.push(col).push(" @> ");
                self.bind(Param::Json(Some(Value::Array(vec![item.clone()]))));
            }
            Dialect::MySql => {
                self.push("JSON_CONTAINS(").push(col).push(", ");
                self.bind(Param::Text(Some(Value::Array(vec![item.clone()]).to_string())));
                self.push(")");
            }
            Dialect::Sqlite => {
                self.push("EXISTS (SELECT 1 FROM json_each(").push(col).push(") WHERE value = ");
                self.bind(to_param(self.dialect, None, item.clone()));
                self.push(")");
            }
        }
    }

    /// Bind a where-clause value for a column of type `ty`.
    fn value(&mut self, ty: Option<FieldType>, v: &Value) {
        let json = matches!(ty, Some(FieldType::Json | FieldType::StringArray | FieldType::NumberArray));
        if json && self.dialect == Dialect::MySql {
            self.push("CAST(");
            self.bind(to_param(self.dialect, ty, v.clone()));
            self.push(" AS JSON)");
        } else {
            self.bind(to_param(self.dialect, ty, v.clone()));
        }
    }
}

pub(crate) fn quote(dialect: Dialect, name: &str) -> String {
    match dialect {
        Dialect::MySql => format!("`{}`", name.replace('`', "``")),
        _ => format!("\"{}\"", name.replace('"', "\"\"")),
    }
}

fn escape_like(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '!' | '%' | '_') {
            out.push('!');
        }
        out.push(c);
    }
    out
}

fn escape_glob(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' | '?' | '[' => {
                out.push('[');
                out.push(c);
                out.push(']');
            }
            c => out.push(c),
        }
    }
    out
}

/// The id column followed by each field's column.
pub(crate) fn select_columns(table: &Table) -> Vec<&str> {
    let mut cols = vec!["id"];
    for (name, _) in &table.fields {
        let col = table.column(name);
        if !cols.contains(&col) {
            cols.push(col);
        }
    }
    cols
}

pub(crate) fn column_type(table: &Table, column: &str) -> Option<FieldType> {
    if column == "id" {
        return Some(FieldType::String);
    }
    table.field_by_column(column).map(|(_, f)| f.field_type)
}

/// Convert a JSON value to a parameter for a column of type `ty`.
pub(crate) fn to_param(dialect: Dialect, ty: Option<FieldType>, v: Value) -> Param {
    let pg = dialect == Dialect::Postgres;
    match ty {
        Some(FieldType::Boolean) => {
            let b = match &v {
                Value::Null => None,
                Value::Bool(b) => Some(*b),
                Value::Number(n) => Some(n.as_f64() != Some(0.0)),
                Value::String(s) => Some(s == "true" || s == "1"),
                _ => Some(true),
            };
            if pg { Param::Bool(b) } else { Param::Int(b.map(i64::from)) }
        }
        Some(FieldType::Date) => {
            if v.is_null() {
                return if dialect == Dialect::Sqlite { Param::Text(None) } else { Param::Date(None) };
            }
            match date::parse_value(&v) {
                Some(d) if dialect == Dialect::Sqlite => Param::Text(Some(date::format(d))),
                Some(d) => Param::Date(Some(d)),
                None => Param::Text(Some(text(v))),
            }
        }
        Some(FieldType::Json | FieldType::StringArray | FieldType::NumberArray) => match (pg, v) {
            (true, Value::Null) => Param::Json(None),
            (true, v) => Param::Json(Some(v)),
            (false, Value::Null) => Param::Text(None),
            (false, v) => Param::Text(Some(v.to_string())),
        },
        Some(FieldType::Number) => match v {
            Value::Number(n) => match n.as_i64() {
                Some(i) => Param::Int(Some(i)),
                None => Param::Float(n.as_f64()),
            },
            Value::Bool(b) => Param::Int(Some(i64::from(b))),
            Value::String(s) => match s.parse::<i64>() {
                Ok(i) => Param::Int(Some(i)),
                Err(_) => Param::Float(s.parse().ok()),
            },
            _ => Param::Int(None),
        },
        Some(FieldType::String) => match v {
            Value::Null => Param::Text(None),
            v => Param::Text(Some(text(v))),
        },
        None => match v {
            Value::Null => Param::Text(None),
            Value::Bool(b) if pg => Param::Bool(Some(b)),
            Value::Bool(b) => Param::Int(Some(i64::from(b))),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Param::Int(Some(i)),
                None => Param::Float(n.as_f64()),
            },
            v => Param::Text(Some(text(v))),
        },
    }
}

fn text(v: Value) -> String {
    match v {
        Value::String(s) => s,
        v => v.to_string(),
    }
}

/// Convert a raw decoded database value to the JSON shape the core expects for `ty`.
pub(crate) fn from_db(ty: Option<FieldType>, v: Value) -> Value {
    match (ty, v) {
        (_, Value::Null) => Value::Null,
        (Some(FieldType::Boolean), Value::Number(n)) => Value::Bool(n.as_f64() != Some(0.0)),
        (Some(FieldType::Boolean), Value::String(s)) => Value::Bool(s == "1" || s == "true"),
        (Some(FieldType::Date), Value::String(s)) => match parse_date(&s) {
            Some(d) => Value::String(date::format(d)),
            None => Value::String(s),
        },
        (Some(FieldType::Date), v @ Value::Number(_)) => date::parse_value(&v).map(date::to_value).unwrap_or(v),
        (Some(FieldType::Json | FieldType::StringArray | FieldType::NumberArray), Value::String(s)) => {
            serde_json::from_str(&s).unwrap_or(Value::String(s))
        }
        (Some(FieldType::Number), Value::String(s)) => {
            s.parse::<i64>().map(Value::from).or_else(|_| s.parse::<f64>().map(Value::from)).unwrap_or(Value::String(s))
        }
        (Some(FieldType::String), v @ (Value::Number(_) | Value::Bool(_))) => Value::String(v.to_string()),
        (_, v) => v,
    }
}

/// Parse RFC 3339, or the `YYYY-MM-DD HH:MM:SS[.fff]` form SQL defaults produce (as UTC).
fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&Utc));
    }
    ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
        .iter()
        .find_map(|f| NaiveDateTime::parse_from_str(s, f).ok())
        .map(|d| d.and_utc())
}

/// Map raw column values of a row to the core's JSON representation.
pub(crate) fn finish_row(table: &Table, raw: Record) -> Record {
    raw.into_iter()
        .map(|(col, v)| {
            let v = from_db(column_type(table, &col), v);
            (col, v)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_patterns() {
        assert_eq!(escape_like("100%_a!"), "100!%!_a!!");
        assert_eq!(escape_glob("a*b?[c]"), "a[*]b[?][[]c]");
    }

    #[test]
    fn parses_sql_dates() {
        assert_eq!(from_db(Some(FieldType::Date), "2024-01-02 03:04:05".into()), "2024-01-02T03:04:05.000Z");
        assert_eq!(from_db(Some(FieldType::Date), "2024-01-02T03:04:05.120+00:00".into()), "2024-01-02T03:04:05.120Z");
    }
}
