//! Role-based access control (`plugins/access`): statements of `resource -> actions`, roles
//! granting a subset, and authorization checks with AND/OR connectors.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// `resource -> allowed actions`.
pub type Statements = BTreeMap<String, Vec<String>>;

/// Build statements from literals: `statements(&[("user", &["create", "list"])])`.
pub fn statements(entries: &[(&str, &[&str])]) -> Statements {
    entries.iter().map(|(r, a)| ((*r).to_owned(), a.iter().map(|s| (*s).to_owned()).collect())).collect()
}

/// How multiple requested actions or resources combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Connector {
    #[default]
    And,
    Or,
}

/// The result of [`Role::authorize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeResponse {
    Success,
    Failure(String),
}

impl AuthorizeResponse {
    pub fn success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// A set of granted permissions.
#[derive(Debug, Clone, Default)]
pub struct Role {
    pub statements: Statements,
}

/// The access-control definition: all statements roles may grant.
#[derive(Debug, Clone, Default)]
pub struct AccessControl {
    pub statements: Statements,
}

impl AccessControl {
    pub fn new(statements: Statements) -> Self {
        Self { statements }
    }

    pub fn new_role(&self, statements: Statements) -> Role {
        Role { statements }
    }
}

fn requested_actions(request: &Value) -> (Vec<&Value>, Connector) {
    match request {
        Value::Array(actions) => (actions.iter().collect(), Connector::And),
        Value::Object(o) => {
            let connector =
                if o.get("connector").and_then(Value::as_str) == Some("OR") { Connector::Or } else { Connector::And };
            let actions = o.get("actions").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
            (actions, connector)
        }
        _ => (vec![], Connector::And),
    }
}

impl Role {
    pub fn new(statements: Statements) -> Self {
        Self { statements }
    }

    /// Check a JSON request of `resource -> [actions]` or `resource -> { actions, connector }`
    /// (the shape the TS API accepts). Resources combine with `connector`.
    pub fn authorize(&self, request: &Map<String, Value>, connector: Connector) -> AuthorizeResponse {
        let mut any_authorized = false;
        for (resource, actions) in request {
            let Some(allowed) = self.statements.get(resource) else {
                if connector == Connector::And {
                    return AuthorizeResponse::Failure(format!("You are not allowed to access resource: {resource}"));
                }
                continue;
            };
            let (requested, action_connector) = requested_actions(actions);
            let has = |a: &&Value| a.as_str().is_some_and(|a| allowed.iter().any(|x| x == a));
            let authorized = !requested.is_empty()
                && match action_connector {
                    Connector::Or => requested.iter().any(has),
                    Connector::And => requested.iter().all(has),
                };
            any_authorized |= authorized;
            match (authorized, connector) {
                (true, Connector::Or) => return AuthorizeResponse::Success,
                (false, Connector::And) => {
                    return AuthorizeResponse::Failure(format!("unauthorized to access resource \"{resource}\""));
                }
                _ => {}
            }
        }
        if any_authorized { AuthorizeResponse::Success } else { AuthorizeResponse::Failure("Not authorized".into()) }
    }

    /// [`authorize`](Self::authorize) for `resource -> actions` pairs (all actions required).
    pub fn allows(&self, permissions: &[(&str, &[&str])]) -> bool {
        let request: Map<String, Value> =
            permissions.iter().map(|(r, a)| ((*r).to_owned(), Value::from(a.to_vec()))).collect();
        self.authorize(&request, Connector::And).success()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn req(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn authorize_matches_ts_semantics() {
        let ac = AccessControl::new(statements(&[
            ("project", &["create", "update", "delete", "delete-many"]),
            ("ui", &["view", "edit", "comment", "hide"]),
        ]));
        let role = ac.new_role(statements(&[
            ("project", &["create", "update", "delete"]),
            ("ui", &["view", "edit", "comment"]),
        ]));
        assert!(role.authorize(&req(json!({ "project": ["create"] })), Connector::And).success());
        assert!(!role.authorize(&req(json!({ "project": ["delete-many"] })), Connector::And).success());
        assert!(
            role.authorize(&req(json!({ "project": ["create", "delete"], "ui": ["view", "edit"] })), Connector::And)
                .success()
        );
        assert!(
            role.authorize(&req(json!({ "project": ["create", "delete-many"], "ui": ["view"] })), Connector::Or)
                .success()
        );
        let or_actions =
            json!({ "project": { "connector": "OR", "actions": ["create", "delete-many"] }, "ui": ["view", "edit"] });
        assert!(role.authorize(&req(or_actions), Connector::And).success());
        assert!(!role.authorize(&req(json!({ "project": [] })), Connector::And).success());
        assert!(!role.authorize(&req(json!({ "project": [] })), Connector::Or).success());
        assert_eq!(
            role.authorize(&req(json!({ "audit": ["read"] })), Connector::And),
            AuthorizeResponse::Failure("You are not allowed to access resource: audit".into())
        );
        assert_eq!(
            role.authorize(&req(json!({ "project": ["delete-many"] })), Connector::And),
            AuthorizeResponse::Failure("unauthorized to access resource \"project\"".into())
        );
        assert!(role.authorize(&req(json!({ "audit": ["read"], "project": ["create"] })), Connector::Or).success());
        assert!(role.allows(&[("ui", &["view"])]));
    }
}
