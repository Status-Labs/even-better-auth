//! Database layer: schema, adapter interface, the in-memory adapter and the
//! internal adapter that implements auth-specific queries.

mod adapter;
pub mod hooks;
pub(crate) mod internal;
mod memory;
pub mod schema;
#[cfg(feature = "testing")]
pub mod testing;
mod transaction;

pub use adapter::{
    Adapter, Connector, Db, FindManyQuery, IdGenerator, Mode, Operator, Record, SortBy, SortDirection, Where,
};
pub use internal::{InternalAdapter, SessionOverrides};
pub use memory::MemoryAdapter;
pub use schema::{Field, FieldType, OnDelete, Schema, Table, TableExtension, TableOptions, get_auth_tables};
pub use transaction::{Transaction, after_commit, in_transaction};

use serde_json::{Map, Value};

/// Remove fields marked `returned: false` from an output record.
pub fn filter_output(table: &Table, mut record: Map<String, Value>) -> Map<String, Value> {
    for (name, field) in &table.fields {
        if !field.returned {
            record.remove(name);
        }
    }
    record
}

/// Mode for [`parse_input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAction {
    Create,
    Update,
}

/// Validate user-supplied values for additional fields (`parseInputData`): drop unknown keys,
/// reject fields with `input: false`, apply defaults on create, and require required fields.
pub fn parse_input(
    table: &Table,
    data: &Map<String, Value>,
    action: InputAction,
    core_fields: &[&str],
) -> Result<Map<String, Value>, crate::error::ApiError> {
    use crate::error::{ApiError, codes};
    let mut out = Map::new();
    for (name, field) in &table.fields {
        if core_fields.contains(&name.as_str()) {
            continue;
        }
        match data.get(name) {
            Some(v) => {
                if !field.input {
                    return Err(ApiError::bad_request(codes::FIELD_NOT_ALLOWED)
                        .with_field("message", format!("{name} is not allowed to be set")));
                }
                out.insert(name.clone(), v.clone());
            }
            None if action == InputAction::Create => {
                if let Some(d) = &field.default_value {
                    out.insert(name.clone(), d.resolve());
                } else if field.required && field.input {
                    return Err(ApiError::bad_request(codes::MISSING_FIELD)
                        .with_field("message", format!("{name} is required")));
                }
            }
            None => {}
        }
    }
    Ok(out)
}
