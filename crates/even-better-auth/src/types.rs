//! Core models. Each carries an `extra` map holding additional/plugin fields, which are
//! flattened into the JSON representation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::db::Record;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(with = "crate::utils::date")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "crate::utils::date")]
    pub updated_at: DateTime<Utc>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    #[serde(with = "crate::utils::date")]
    pub expires_at: DateTime<Utc>,
    pub token: String,
    #[serde(with = "crate::utils::date")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "crate::utils::date")]
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    pub user_id: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub id: String,
    pub account_id: String,
    pub provider_id: String,
    pub user_id: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default, with = "crate::utils::date::option")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(default, with = "crate::utils::date::option")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(with = "crate::utils::date")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "crate::utils::date")]
    pub updated_at: DateTime<Utc>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[serde(with = "crate::utils::date")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "crate::utils::date")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "crate::utils::date")]
    pub updated_at: DateTime<Utc>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A session together with its user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionWithUser {
    pub session: Session,
    pub user: User,
}

/// Conversion between records and typed models.
pub trait Model: Serialize + serde::de::DeserializeOwned {
    fn from_record(record: Record) -> Result<Self> {
        serde_json::from_value(Value::Object(record)).map_err(|e| Error::Database(format!("invalid row: {e}")))
    }
    fn to_record(&self) -> Record {
        match serde_json::to_value(self) {
            Ok(Value::Object(m)) => m,
            _ => Map::new(),
        }
    }
}

impl Model for User {}
impl Model for Session {}
impl Model for Account {}
impl Model for Verification {}
