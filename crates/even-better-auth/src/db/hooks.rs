//! Database lifecycle hooks (`databaseHooks`).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;

use super::Record;
use crate::error::Result;

/// The result of a `before` hook.
pub enum BeforeOutcome {
    /// Proceed unchanged.
    Continue,
    /// Abort the operation (the TS hook returned `false`).
    Abort,
    /// Merge these fields into the data being written.
    Merge(Record),
}

pub type BeforeHook = Arc<dyn Fn(Record) -> BoxFuture<'static, Result<BeforeOutcome>> + Send + Sync>;
pub type AfterHook = Arc<dyn Fn(Record) -> BoxFuture<'static, Result<()>> + Send + Sync>;

#[derive(Clone, Default)]
pub struct OperationHooks {
    pub before: Vec<BeforeHook>,
    pub after: Vec<AfterHook>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Operation {
    Create,
    Update,
    Delete,
}

/// Hooks keyed by (model, operation). Model keys are logical names (`"user"`, `"session"`, ...).
#[derive(Clone, Default)]
pub struct DatabaseHooks {
    hooks: HashMap<(String, Operation), OperationHooks>,
}

impl DatabaseHooks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn before<F, Fut>(mut self, model: &str, op: Operation, f: F) -> Self
    where
        F: Fn(Record) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<BeforeOutcome>> + Send + 'static,
    {
        self.hooks.entry((model.into(), op)).or_default().before.push(Arc::new(move |r| Box::pin(f(r))));
        self
    }

    pub fn after<F, Fut>(mut self, model: &str, op: Operation, f: F) -> Self
    where
        F: Fn(Record) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.hooks.entry((model.into(), op)).or_default().after.push(Arc::new(move |r| Box::pin(f(r))));
        self
    }

    pub fn get(&self, model: &str, op: Operation) -> Option<&OperationHooks> {
        self.hooks.get(&(model.to_owned(), op))
    }

    pub fn extend(&mut self, other: DatabaseHooks) {
        for (k, v) in other.hooks {
            let entry = self.hooks.entry(k).or_default();
            entry.before.extend(v.before);
            entry.after.extend(v.after);
        }
    }
}
