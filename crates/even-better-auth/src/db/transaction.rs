//! Transactions (`runWithTransaction`, `getCurrentAdapter` and `queueAfterTransactionHook`
//! from `@better-auth/core/context`).
//!
//! [`Db::transaction`] begins a transaction on the adapter and runs a future inside an
//! ambient, task-local scope. Every [`Db`] call made from that future (including through the
//! internal adapter and plugins) is routed to the transaction, so multi-step writes commit or
//! roll back together. Nested calls join the outer transaction. Work queued with
//! [`after_commit`] (database `after` hooks, emails) runs only once the transaction commits.
//!
//! Adapters without transaction support return `None` from [`Adapter::begin`]; the future
//! then runs directly and queued work runs immediately.

use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::future::BoxFuture;

use super::adapter::{Adapter, Db};
use crate::error::{Error, Result};

/// An open transaction. Its [`Adapter`] methods run inside the transaction.
///
/// Dropping a transaction without committing must roll it back.
#[async_trait]
pub trait Transaction: Adapter {
    async fn commit(&self) -> Result<()>;
    async fn rollback(&self) -> Result<()>;
}

struct Scope {
    /// Identity of the base adapter the transaction was opened on.
    base: usize,
    tx: Arc<dyn Transaction>,
    pending: Mutex<Vec<BoxFuture<'static, Result<()>>>>,
}

tokio::task_local! {
    static SCOPE: Arc<Scope>;
}

fn key(adapter: &Arc<dyn Adapter>) -> usize {
    Arc::as_ptr(adapter) as *const () as usize
}

/// The transaction adapter for `base`, if the current task is inside one.
pub(crate) fn current(base: &Arc<dyn Adapter>) -> Option<Arc<dyn Adapter>> {
    SCOPE.try_with(|s| (s.base == key(base)).then(|| s.tx.clone() as Arc<dyn Adapter>)).ok().flatten()
}

/// Whether the current task is inside a transaction.
pub fn in_transaction() -> bool {
    SCOPE.try_with(|_| ()).is_ok()
}

/// Run `work` after the current transaction commits, or now when there is none
/// (`queueAfterTransactionHook`). Queued work is dropped if the transaction rolls back.
pub async fn after_commit(work: BoxFuture<'static, Result<()>>) -> Result<()> {
    let mut slot = Some(work);
    let _ = SCOPE.try_with(|s| {
        let work = slot.take().expect("taken once");
        s.pending.lock().expect("pending hooks lock").push(work);
    });
    match slot {
        Some(work) => work.await,
        None => Ok(()),
    }
}

impl Db {
    /// Run `work` in a transaction, joining the current one if already inside it. Commits
    /// when `work` returns `Ok`, rolls back on `Err`, then runs work queued with
    /// [`after_commit`].
    pub async fn transaction<T, E, Fut>(&self, work: Fut) -> std::result::Result<T, E>
    where
        Fut: Future<Output = std::result::Result<T, E>>,
        E: From<Error>,
    {
        let base = self.adapter();
        if current(base).is_some() {
            return work.await;
        }
        let Some(tx) = base.begin().await? else {
            return work.await;
        };
        let scope = Arc::new(Scope { base: key(base), tx: tx.clone(), pending: Mutex::default() });
        let result = SCOPE.scope(scope.clone(), work).await;
        let pending = std::mem::take(&mut *scope.pending.lock().expect("pending hooks lock"));
        match result {
            Ok(value) => {
                tx.commit().await?;
                for work in pending {
                    work.await?;
                }
                Ok(value)
            }
            Err(e) => {
                if let Err(rollback) = tx.rollback().await {
                    tracing::error!(error = %rollback, "failed to roll back transaction");
                }
                Err(e)
            }
        }
    }
}
