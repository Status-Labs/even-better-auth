//! Database schema description (`getAuthTables`). Tables and fields are keyed by their
//! *logical* names (e.g. `emailVerified`); `model_name` / `field_name` hold the names
//! used in the database.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::options::BetterAuthOptions;
use crate::utils::date::now_value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    String,
    Number,
    Boolean,
    Date,
    Json,
    StringArray,
    NumberArray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnDelete {
    #[default]
    Cascade,
    Restrict,
    SetNull,
    NoAction,
    SetDefault,
}

#[derive(Debug, Clone)]
pub struct Reference {
    pub model: String,
    pub field: String,
    pub on_delete: OnDelete,
}

/// A default value for a field: a constant, or computed when the row is written.
#[derive(Clone)]
pub enum DefaultValue {
    Value(Value),
    Fn(Arc<dyn Fn() -> Value + Send + Sync>),
}

impl DefaultValue {
    pub fn now() -> Self {
        DefaultValue::Fn(Arc::new(now_value))
    }
    pub fn resolve(&self) -> Value {
        match self {
            DefaultValue::Value(v) => v.clone(),
            DefaultValue::Fn(f) => f(),
        }
    }
}

impl std::fmt::Debug for DefaultValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultValue::Value(v) => write!(f, "Value({v})"),
            DefaultValue::Fn(_) => write!(f, "Fn(..)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub field_type: FieldType,
    pub required: bool,
    pub unique: bool,
    /// Whether the field is included in API output.
    pub returned: bool,
    /// Whether the field may be set from user input.
    pub input: bool,
    pub default_value: Option<DefaultValue>,
    pub on_update: Option<DefaultValue>,
    pub references: Option<Reference>,
    /// Column name in the database; defaults to the logical name.
    pub field_name: Option<String>,
    pub bigint: bool,
    pub index: bool,
    pub sortable: bool,
}

impl Field {
    pub fn new(field_type: FieldType) -> Self {
        Self {
            field_type,
            required: true,
            unique: false,
            returned: true,
            input: true,
            default_value: None,
            on_update: None,
            references: None,
            field_name: None,
            bigint: false,
            index: false,
            sortable: false,
        }
    }
    pub fn string() -> Self {
        Self::new(FieldType::String)
    }
    pub fn number() -> Self {
        Self::new(FieldType::Number)
    }
    pub fn boolean() -> Self {
        Self::new(FieldType::Boolean)
    }
    pub fn date() -> Self {
        Self::new(FieldType::Date)
    }
    pub fn json() -> Self {
        Self::new(FieldType::Json)
    }
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }
    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }
    pub fn no_input(mut self) -> Self {
        self.input = false;
        self
    }
    pub fn indexed(mut self) -> Self {
        self.index = true;
        self
    }
    pub fn sortable(mut self) -> Self {
        self.sortable = true;
        self
    }
    pub fn bigint(mut self) -> Self {
        self.bigint = true;
        self
    }
    pub fn default(mut self, v: impl Into<Value>) -> Self {
        self.default_value = Some(DefaultValue::Value(v.into()));
        self
    }
    pub fn default_now(mut self) -> Self {
        self.default_value = Some(DefaultValue::now());
        self
    }
    pub fn on_update_now(mut self) -> Self {
        self.on_update = Some(DefaultValue::now());
        self
    }
    pub fn references(mut self, model: &str, field: &str, on_delete: OnDelete) -> Self {
        self.references = Some(Reference { model: model.into(), field: field.into(), on_delete });
        self
    }
    pub fn field_name(mut self, name: impl Into<String>) -> Self {
        self.field_name = Some(name.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct Table {
    /// Logical key, e.g. `"user"`.
    pub key: String,
    /// Table name in the database.
    pub model_name: String,
    /// Fields in declaration order, keyed by logical name. `id` is implicit.
    pub fields: Vec<(String, Field)>,
    pub order: u32,
    pub disable_migration: bool,
}

impl Table {
    pub fn new(key: &str) -> Self {
        Self { key: key.into(), model_name: key.into(), fields: vec![], order: u32::MAX, disable_migration: false }
    }

    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|(n, _)| n == name).map(|(_, f)| f)
    }

    /// Column name for a logical field name (`id` maps to itself).
    pub fn column<'a>(&'a self, name: &'a str) -> &'a str {
        self.field(name).and_then(|f| f.field_name.as_deref()).unwrap_or(name)
    }

    /// Look up a field by its column name; returns the logical name and the field.
    pub fn field_by_column(&self, column: &str) -> Option<(&str, &Field)> {
        self.fields.iter().find(|(n, f)| f.field_name.as_deref().unwrap_or(n) == column).map(|(n, f)| (n.as_str(), f))
    }

    pub fn field_type(&self, name: &str) -> Option<FieldType> {
        if name == "id" {
            return Some(FieldType::String);
        }
        self.field(name).map(|f| f.field_type)
    }

    /// Insert or replace a field.
    pub fn upsert_field(&mut self, name: impl Into<String>, field: Field) {
        let name = name.into();
        match self.fields.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = field,
            None => self.fields.push((name, field)),
        }
    }
}

/// A plugin's contribution to the schema. Fields on an existing table are merged in.
#[derive(Debug, Clone, Default)]
pub struct TableExtension {
    pub key: String,
    pub model_name: Option<String>,
    pub fields: Vec<(String, Field)>,
    pub disable_migration: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Schema {
    pub tables: Vec<Table>,
}

impl Schema {
    pub fn table(&self, key: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.key == key)
    }

    /// Find a table by logical key or by database model name.
    pub fn resolve(&self, model: &str) -> Option<&Table> {
        self.table(model).or_else(|| self.tables.iter().find(|t| t.model_name == model))
    }
}

/// Field renames and extra fields configured for one of the built-in tables.
#[derive(Debug, Clone, Default)]
pub struct TableOptions {
    pub model_name: Option<String>,
    pub fields: HashMap<String, String>,
    pub additional_fields: Vec<(String, Field)>,
}

fn build(key: &str, opts: &TableOptions, order: u32, fields: Vec<(&str, Field)>) -> Table {
    let mut table = Table::new(key);
    table.model_name = opts.model_name.clone().unwrap_or_else(|| key.into());
    table.order = order;
    for (name, mut field) in fields {
        if let Some(renamed) = opts.fields.get(name) {
            field.field_name = Some(renamed.clone());
        }
        table.fields.push((name.into(), field));
    }
    for (name, field) in &opts.additional_fields {
        table.upsert_field(name.clone(), field.clone());
    }
    table
}

/// Build the full schema from options and plugins.
pub fn get_auth_tables(options: &BetterAuthOptions) -> Schema {
    let mut plugin_tables: Vec<TableExtension> = vec![];
    for plugin in &options.plugins {
        for ext in plugin.schema() {
            match plugin_tables.iter_mut().find(|t| t.key == ext.key) {
                Some(existing) => {
                    for (n, f) in ext.fields {
                        match existing.fields.iter_mut().find(|(en, _)| *en == n) {
                            Some(slot) => slot.1 = f,
                            None => existing.fields.push((n, f)),
                        }
                    }
                    if ext.model_name.is_some() {
                        existing.model_name = ext.model_name;
                    }
                    existing.disable_migration |= ext.disable_migration;
                }
                None => plugin_tables.push(ext),
            }
        }
    }

    let user = build(
        "user",
        &options.user.table,
        1,
        vec![
            ("name", Field::string().sortable()),
            ("email", Field::string().unique().sortable()),
            ("emailVerified", Field::boolean().default(false).no_input()),
            ("image", Field::string().optional()),
            ("createdAt", Field::date().default_now()),
            ("updatedAt", Field::date().default_now().on_update_now()),
        ],
    );
    let session = build(
        "session",
        &options.session.table,
        2,
        vec![
            ("expiresAt", Field::date()),
            ("token", Field::string().unique()),
            ("createdAt", Field::date().default_now()),
            ("updatedAt", Field::date().default_now().on_update_now()),
            ("ipAddress", Field::string().optional()),
            ("userAgent", Field::string().optional()),
            ("userId", Field::string().references("user", "id", OnDelete::Cascade).indexed()),
        ],
    );
    let account = build(
        "account",
        &options.account.table,
        3,
        vec![
            ("accountId", Field::string()),
            ("providerId", Field::string()),
            ("userId", Field::string().references("user", "id", OnDelete::Cascade).indexed()),
            ("accessToken", Field::string().optional().hidden()),
            ("refreshToken", Field::string().optional().hidden()),
            ("idToken", Field::string().optional().hidden()),
            ("accessTokenExpiresAt", Field::date().optional().hidden()),
            ("refreshTokenExpiresAt", Field::date().optional().hidden()),
            ("scope", Field::string().optional()),
            ("password", Field::string().optional().hidden()),
            ("createdAt", Field::date().default_now()),
            ("updatedAt", Field::date().default_now().on_update_now()),
        ],
    );
    let verification = build(
        "verification",
        &options.verification.table,
        4,
        vec![
            ("identifier", Field::string().indexed()),
            ("value", Field::string()),
            ("expiresAt", Field::date()),
            ("createdAt", Field::date().default_now()),
            ("updatedAt", Field::date().default_now().on_update_now()),
        ],
    );

    let mut tables = vec![user, session, account, verification];
    for ext in plugin_tables {
        match tables.iter_mut().find(|t| t.key == ext.key) {
            Some(table) => {
                // Plugin fields on core tables come before user-configured additional fields
                // in TS; additional fields win on conflict, so only add missing ones.
                for (n, f) in ext.fields {
                    if table.field(&n).is_none() {
                        table.fields.push((n, f));
                    }
                }
            }
            None => {
                let mut table = Table::new(&ext.key);
                table.model_name = ext.model_name.unwrap_or(ext.key);
                table.fields = ext.fields;
                table.disable_migration = ext.disable_migration;
                tables.push(table);
            }
        }
    }
    if options.rate_limit_storage() == crate::options::RateLimitStorage::Database {
        let mut table = Table::new("rateLimit");
        table.fields = vec![
            ("key".into(), Field::string().unique()),
            ("count".into(), Field::number()),
            ("lastRequest".into(), Field::number().bigint()),
        ];
        tables.push(table);
    }
    Schema { tables }
}
