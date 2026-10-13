//! Built-in endpoints.

pub mod email_verification;
mod misc;
pub mod password;
pub mod session;
mod sign_in;
mod sign_out;
pub mod sign_up;
mod update_session;
mod update_user;
pub mod util;

use crate::api::Endpoint;

/// All core endpoints (plugin endpoints are added by [`crate::BetterAuth::new`]).
pub fn core_endpoints() -> Vec<Endpoint> {
    let mut endpoints = vec![];
    endpoints.extend(sign_up::endpoints());
    endpoints.extend(sign_in::endpoints());
    endpoints.extend(sign_out::endpoints());
    endpoints.extend(session::endpoints());
    endpoints.extend(email_verification::endpoints());
    endpoints.extend(password::endpoints());
    endpoints.extend(update_user::endpoints());
    endpoints.extend(update_session::endpoints());
    endpoints.extend(misc::endpoints());
    #[cfg(feature = "oauth")]
    endpoints.extend(crate::oauth2::routes::endpoints());
    endpoints
}
