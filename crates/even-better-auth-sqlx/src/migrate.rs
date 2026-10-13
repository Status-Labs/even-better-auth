//! Schema migration (`getMigrations`): create missing tables, add missing columns and
//! indexes. Nothing is ever dropped or altered in place.

use even_better_auth::Result;
use even_better_auth::db::schema::DefaultValue;
use even_better_auth::db::{Field, FieldType, OnDelete, Schema, Table};
use serde_json::Value;

use crate::SqlxAdapter;
use crate::query::{Dialect, Param, Sql, quote};

pub(crate) async fn run(adapter: &SqlxAdapter, schema: &Schema) -> Result<()> {
    let dialect = adapter.dialect();
    let mut tables: Vec<&Table> = schema.tables.iter().filter(|t| !t.disable_migration).collect();
    tables.sort_by_key(|t| t.order);
    for table in tables {
        let existing = columns(adapter, &table.model_name).await?;
        let mut indexes = vec![];
        if existing.is_empty() {
            create_table(adapter, schema, table).await?;
        } else {
            for (name, field) in &table.fields {
                let col = table.column(name);
                if existing.iter().any(|c| c == col) {
                    continue;
                }
                add_column(adapter, schema, table, col, field).await?;
                if field.unique {
                    indexes.push((col, true));
                }
            }
        }
        for (name, field) in &table.fields {
            if field.index && !field.unique && indexable(field) {
                indexes.push((table.column(name), false));
            }
        }
        for (col, unique) in indexes {
            ensure_index(adapter, dialect, &table.model_name, col, unique).await?;
        }
    }
    Ok(())
}

async fn columns(adapter: &SqlxAdapter, table: &str) -> Result<Vec<String>> {
    let mut sql = Sql::new(adapter.dialect());
    match sql.dialect {
        Dialect::Sqlite => sql.push("SELECT name FROM pragma_table_info("),
        Dialect::Postgres => sql.push(
            "SELECT column_name::text AS name FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = ",
        ),
        Dialect::MySql => sql.push(
            "SELECT CAST(column_name AS CHAR) AS name FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = ",
        ),
    };
    sql.bind(Param::Text(Some(table.to_owned())));
    if sql.dialect == Dialect::Sqlite {
        sql.push(")");
    }
    let rows = adapter.fetch(sql).await?;
    Ok(rows.into_iter().filter_map(|r| r.get("name").and_then(Value::as_str).map(str::to_owned)).collect())
}

fn indexable(field: &Field) -> bool {
    !matches!(field.field_type, FieldType::Json | FieldType::StringArray | FieldType::NumberArray)
}

fn sql_type(dialect: Dialect, field: &Field) -> &'static str {
    let id_like = field.references.as_ref().is_some_and(|r| r.field == "id");
    match (dialect, field.field_type) {
        (Dialect::MySql, _) if id_like => "VARCHAR(255)",
        (_, _) if id_like => "TEXT",
        (Dialect::MySql, FieldType::String)
            if field.unique || field.index || field.sortable || field.references.is_some() =>
        {
            "VARCHAR(255)"
        }
        (_, FieldType::String) => "TEXT",
        (_, FieldType::Number) if field.bigint => "BIGINT",
        (_, FieldType::Number) => "INTEGER",
        (Dialect::Sqlite, FieldType::Boolean) => "INTEGER",
        (_, FieldType::Boolean) => "BOOLEAN",
        (Dialect::Sqlite, FieldType::Date) => "TEXT",
        (Dialect::Postgres, FieldType::Date) => "TIMESTAMPTZ",
        (Dialect::MySql, FieldType::Date) => "DATETIME(3)",
        (Dialect::Sqlite, _) => "TEXT",
        (Dialect::Postgres, _) => "JSONB",
        (Dialect::MySql, _) => "JSON",
    }
}

fn id_type(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::MySql => "VARCHAR(255)",
        _ => "TEXT",
    }
}

/// A SQL literal for a constant default value, when the column type can carry one.
fn default_literal(dialect: Dialect, field: &Field) -> Option<String> {
    let Some(DefaultValue::Value(v)) = &field.default_value else { return None };
    match (field.field_type, v) {
        (FieldType::Boolean, Value::Bool(b)) => Some(match (dialect, b) {
            (Dialect::Postgres, true) => "TRUE".into(),
            (Dialect::Postgres, false) => "FALSE".into(),
            (_, b) => i32::from(*b).to_string(),
        }),
        (FieldType::Number, Value::Number(n)) => Some(n.to_string()),
        (FieldType::String, Value::String(s)) if dialect != Dialect::MySql || sql_type(dialect, field) != "TEXT" => {
            let s = s.replace('\'', "''");
            let s = if dialect == Dialect::MySql { s.replace('\\', "\\\\") } else { s };
            Some(format!("'{s}'"))
        }
        _ => None,
    }
}

fn on_delete(o: OnDelete) -> &'static str {
    match o {
        OnDelete::Cascade => "CASCADE",
        OnDelete::Restrict => "RESTRICT",
        OnDelete::SetNull => "SET NULL",
        OnDelete::NoAction => "NO ACTION",
        OnDelete::SetDefault => "SET DEFAULT",
    }
}

/// ` REFERENCES "user" ("id") ON DELETE CASCADE`
fn references(dialect: Dialect, schema: &Schema, field: &Field) -> Option<String> {
    let r = field.references.as_ref()?;
    let (model, column) = match schema.resolve(&r.model) {
        Some(t) => (t.model_name.as_str(), t.column(&r.field)),
        None => (r.model.as_str(), r.field.as_str()),
    };
    Some(format!(
        " REFERENCES {} ({}) ON DELETE {}",
        quote(dialect, model),
        quote(dialect, column),
        on_delete(r.on_delete)
    ))
}

async fn create_table(adapter: &SqlxAdapter, schema: &Schema, table: &Table) -> Result<()> {
    let dialect = adapter.dialect();
    let mut defs = vec![format!("{} {} NOT NULL PRIMARY KEY", quote(dialect, "id"), id_type(dialect))];
    let mut foreign = vec![];
    for (name, field) in &table.fields {
        let col = table.column(name);
        if col == "id" {
            continue;
        }
        let mut def = format!("{} {}", quote(dialect, col), sql_type(dialect, field));
        if field.required {
            def.push_str(" NOT NULL");
        }
        if let Some(d) = default_literal(dialect, field) {
            def.push_str(&format!(" DEFAULT {d}"));
        }
        if field.unique {
            def.push_str(" UNIQUE");
        }
        defs.push(def);
        if let Some(r) = references(dialect, schema, field) {
            foreign.push(format!("FOREIGN KEY ({}){r}", quote(dialect, col)));
        }
    }
    defs.extend(foreign);
    let mut sql = Sql::new(dialect);
    sql.push("CREATE TABLE ").ident(&table.model_name).push(" (").push(&defs.join(", ")).push(")");
    if dialect == Dialect::MySql {
        sql.push(" DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin");
    }
    adapter.execute(sql).await?;
    Ok(())
}

/// Added columns are only NOT NULL when a constant default can backfill existing rows.
async fn add_column(adapter: &SqlxAdapter, schema: &Schema, table: &Table, col: &str, field: &Field) -> Result<()> {
    let dialect = adapter.dialect();
    let mut sql = Sql::new(dialect);
    sql.push("ALTER TABLE ").ident(&table.model_name).push(" ADD COLUMN ").ident(col).push(" ");
    sql.push(sql_type(dialect, field));
    let reference = references(dialect, schema, field);
    if reference.is_none()
        && let Some(d) = default_literal(dialect, field)
    {
        if field.required {
            sql.push(" NOT NULL");
        }
        sql.push(" DEFAULT ").push(&d);
    }
    if let Some(r) = reference {
        if dialect == Dialect::MySql {
            sql.push(", ADD FOREIGN KEY (").ident(col).push(")").push(&r);
        } else {
            sql.push(&r);
        }
    }
    adapter.execute(sql).await?;
    Ok(())
}

async fn ensure_index(adapter: &SqlxAdapter, dialect: Dialect, table: &str, col: &str, unique: bool) -> Result<()> {
    let name = index_name(table, col, unique);
    let kind = if unique { "CREATE UNIQUE INDEX " } else { "CREATE INDEX " };
    let mut sql = Sql::new(dialect);
    if dialect == Dialect::MySql {
        let mut check = Sql::new(dialect);
        check.push(
            "SELECT COUNT(*) AS n FROM information_schema.statistics \
             WHERE table_schema = DATABASE() AND table_name = ",
        );
        check.bind(Param::Text(Some(table.to_owned()))).push(" AND index_name = ");
        check.bind(Param::Text(Some(name.clone())));
        let rows = adapter.fetch(check).await?;
        if rows.first().and_then(|r| r.get("n")).and_then(Value::as_u64).unwrap_or(0) > 0 {
            return Ok(());
        }
        sql.push(kind);
    } else {
        sql.push(kind).push("IF NOT EXISTS ");
    }
    sql.ident(&name).push(" ON ").ident(table).push(" (").ident(col).push(")");
    adapter.execute(sql).await?;
    Ok(())
}

const MAX_INDEX_NAME_BYTES: usize = 63;

/// `{table}_{column}_{idx|uidx}`, shortened with a stable hash past 63 bytes (`getDatabaseIndexName`).
pub(crate) fn index_name(table: &str, column: &str, unique: bool) -> String {
    let kind = if unique { "uidx" } else { "idx" };
    let generated = format!("{table}_{column}_{kind}");
    if generated.len() <= MAX_INDEX_NAME_BYTES {
        return generated;
    }
    let mut hash: u32 = 0x811c9dc5;
    for unit in generated.encode_utf16() {
        hash ^= u32::from(unit);
        hash = hash.wrapping_mul(0x01000193);
    }
    let suffix = format!("_{hash:08x}_{kind}");
    let base = &generated[..generated.len() - kind.len() - 1];
    let mut end = MAX_INDEX_NAME_BYTES - suffix.len();
    while !base.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{suffix}", &base[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_names() {
        assert_eq!(index_name("session", "userId", false), "session_userId_idx");
        let long = index_name(&"t".repeat(60), "column", true);
        assert_eq!(long.len(), 63);
        assert!(long.ends_with("_uidx"));
    }
}
