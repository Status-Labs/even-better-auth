//! [axum](https://docs.rs/axum) integration for [`even_better_auth`].
//!
//! ```no_run
//! # async fn run(auth: even_better_auth::BetterAuth) {
//! use axum::{routing::get, Router};
//! use even_better_auth_axum::{AuthSession, BetterAuthExt};
//!
//! async fn me(AuthSession(session): AuthSession) -> String {
//!     format!("hello {}", session.user.email)
//! }
//!
//! let app = Router::new()
//!     .route("/me", get(me))
//!     .mount_better_auth(auth);
//! # }
//! ```

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{FromRef, FromRequestParts, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use even_better_auth::{BetterAuth, SessionWithUser};

/// Request bodies larger than this are rejected (1 MiB).
pub const MAX_BODY_SIZE: usize = 1024 * 1024;

/// Forward an axum request to the auth handler.
pub async fn handle(auth: BetterAuth, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, MAX_BODY_SIZE).await {
        Ok(b) => b,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let res = auth.handler(http::Request::from_parts(parts, bytes)).await;
    res.map(Body::from)
}

/// A router serving all auth endpoints under the configured base path.
pub fn auth_router<S: Clone + Send + Sync + 'static>(auth: BetterAuth) -> Router<S> {
    let base = auth.options().base_path.clone();
    let wildcard = format!("{base}/{{*path}}");
    let a = auth.clone();
    Router::new().route(
        &wildcard,
        axum::routing::any(move |req: Request| {
            let auth = a.clone();
            async move { handle(auth, req).await }
        }),
    )
}

pub trait BetterAuthExt<S> {
    /// Mount the auth endpoints (at `options.base_path`) on this router.
    fn mount_better_auth(self, auth: BetterAuth) -> Self;
}

impl<S: Clone + Send + Sync + 'static> BetterAuthExt<S> for Router<S> {
    fn mount_better_auth(self, auth: BetterAuth) -> Self {
        self.merge(auth_router(auth))
    }
}

/// Extractor yielding the current session; rejects with 401 when there is none.
///
/// Requires `BetterAuth` to be obtainable from the router state via [`FromRef`].
pub struct AuthSession(pub SessionWithUser);

/// Extractor yielding the current session, if any.
pub struct MaybeAuthSession(pub Option<SessionWithUser>);

async fn session_from_parts<S>(parts: &Parts, state: &S) -> Result<Option<SessionWithUser>, StatusCode>
where
    BetterAuth: FromRef<S>,
{
    let auth = BetterAuth::from_ref(state);
    auth.get_session(&parts.headers).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

impl<S> FromRequestParts<S> for AuthSession
where
    BetterAuth: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match session_from_parts(parts, state).await? {
            Some(s) => Ok(AuthSession(s)),
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

impl<S> FromRequestParts<S> for MaybeAuthSession
where
    BetterAuth: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(MaybeAuthSession(session_from_parts(parts, state).await?))
    }
}
