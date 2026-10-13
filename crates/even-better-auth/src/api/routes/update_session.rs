//! `POST /update-session` (`api/routes/update-session.ts`).

use http::StatusCode;
use serde_json::{Map, Value, json};

use crate::api::middleware::require_session;
use crate::api::{Ctx, Endpoint, EndpointResult, handler};
use crate::cookies::{delete_session_cookie, set_session_cookie};
use crate::db::{InputAction, Record, parse_input};
use crate::error::{ApiError, codes};
use crate::types::{Model, Session, SessionWithUser};
use crate::utils::date;

const CORE_FIELDS: &[&str] = &["expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId"];

async fn update_session(ctx: Ctx) -> EndpointResult {
    let session = require_session(&ctx).await?;
    let body = match ctx.body() {
        Value::Null => Map::new(),
        Value::Object(m) => m,
        _ => return Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT)),
    };
    let table = ctx.auth.schema.table("session").expect("session table");
    let additional = parse_input(table, &body, InputAction::Update, CORE_FIELDS)?;
    if additional.is_empty() {
        return Err(ApiError::message(StatusCode::BAD_REQUEST, "No fields to update"));
    }
    let mut update: Record = additional;
    update.insert("updatedAt".into(), date::now_value());
    // A missing row in a durable store means the session was revoked or expired server-side:
    // fail closed rather than re-minting cookies from stale cached data. Stateless deployments
    // keep the session in the cookie and legitimately have no row.
    let updated = match ctx.auth.internal_adapter.update_session(&session.session.token, update.clone()).await? {
        Some(updated) => updated,
        None if !ctx.auth.is_stateful() => {
            let mut record = session.session.to_record();
            record.extend(update);
            Session::from_record(record)?
        }
        None => {
            delete_session_cookie(&ctx, false);
            return Err(ApiError::unauthorized(codes::FAILED_TO_GET_SESSION));
        }
    };
    let output = ctx.auth.session_output(&updated);
    set_session_cookie(&ctx, &SessionWithUser { session: updated, user: session.user }, None, None).await;
    ctx.json(json!({ "session": output }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![Endpoint::post("updateSession", "/update-session", handler(update_session))]
}
