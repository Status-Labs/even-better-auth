//! Built-in plugins (`better-auth/plugins`). Add them to [`BetterAuthOptions::plugins`].
//!
//! [`BetterAuthOptions::plugins`]: crate::BetterAuthOptions::plugins

pub mod access;
pub mod admin;
pub mod anonymous;
pub mod api_key;
pub mod bearer;
#[cfg(feature = "oauth")]
pub mod captcha;
pub mod custom_session;
pub mod device_authorization;
pub mod email_otp;
#[cfg(feature = "oauth")]
pub mod generic_oauth;
#[cfg(feature = "oauth")]
pub mod haveibeenpwned;
pub mod jwt;
pub mod last_login_method;
pub mod magic_link;
pub mod multi_session;
#[cfg(feature = "oauth")]
pub mod oauth_popup;
#[cfg(feature = "oauth")]
pub mod oauth_proxy;
#[cfg(feature = "oauth")]
pub mod one_tap;
pub mod one_time_token;
pub mod open_api;
pub mod organization;
pub mod passkey;
pub mod phone_number;
pub mod siwe;
pub mod two_factor;
pub mod username;
