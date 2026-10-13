//! Error types. [`ApiError`] mirrors better-call's `APIError`: an HTTP status plus a
//! JSON body of the form `{ "code": "...", "message": "..." }`.

use http::StatusCode;
use serde_json::{Map, Value, json};

/// A machine-readable error code paired with its default human-readable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode {
    pub code: &'static str,
    pub message: &'static str,
}

macro_rules! error_codes {
    ($($name:ident => $msg:literal,)*) => {
        /// Built-in error codes (`BASE_ERROR_CODES` in the TypeScript implementation).
        #[allow(non_snake_case)]
        pub mod codes {
            use super::ErrorCode;
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
        }
    };
}

error_codes! {
    USER_NOT_FOUND => "User not found",
    FAILED_TO_CREATE_USER => "Failed to create user",
    FAILED_TO_CREATE_SESSION => "Failed to create session",
    FAILED_TO_UPDATE_USER => "Failed to update user",
    FAILED_TO_GET_SESSION => "Failed to get session",
    INVALID_PASSWORD => "Invalid password",
    INVALID_EMAIL => "Invalid email",
    INVALID_EMAIL_OR_PASSWORD => "Invalid email or password",
    INVALID_USER => "Invalid user",
    SOCIAL_ACCOUNT_ALREADY_LINKED => "Social account already linked",
    PROVIDER_NOT_FOUND => "Provider not found",
    INVALID_TOKEN => "Invalid token",
    TOKEN_EXPIRED => "Token expired",
    ID_TOKEN_NOT_SUPPORTED => "id_token not supported",
    FAILED_TO_GET_USER_INFO => "Failed to get user info",
    USER_EMAIL_NOT_FOUND => "User email not found",
    EMAIL_NOT_VERIFIED => "Email not verified",
    PASSWORD_TOO_SHORT => "Password too short",
    PASSWORD_TOO_LONG => "Password too long",
    USER_ALREADY_EXISTS => "User already exists.",
    USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL => "User already exists. Use another email.",
    EMAIL_CAN_NOT_BE_UPDATED => "Email can not be updated",
    CHANGE_EMAIL_DISABLED => "Change email is disabled",
    CREDENTIAL_ACCOUNT_NOT_FOUND => "Credential account not found",
    SESSION_EXPIRED => "Session expired. Re-authenticate to perform this action.",
    FAILED_TO_UNLINK_LAST_ACCOUNT => "You can't unlink your last account",
    ACCOUNT_NOT_FOUND => "Account not found",
    USER_ALREADY_HAS_PASSWORD => "User already has a password. Provide that to delete the account.",
    CROSS_SITE_NAVIGATION_LOGIN_BLOCKED => "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
    VERIFICATION_EMAIL_NOT_ENABLED => "Verification email isn't enabled",
    EMAIL_ALREADY_VERIFIED => "Email is already verified",
    EMAIL_MISMATCH => "Email mismatch",
    SESSION_NOT_FRESH => "Session is not fresh",
    LINKED_ACCOUNT_ALREADY_EXISTS => "Linked account already exists",
    INVALID_ORIGIN => "Invalid origin",
    INVALID_CALLBACK_URL => "Invalid callbackURL",
    INVALID_REDIRECT_URL => "Invalid redirectURL",
    INVALID_ERROR_CALLBACK_URL => "Invalid errorCallbackURL",
    INVALID_NEW_USER_CALLBACK_URL => "Invalid newUserCallbackURL",
    MISSING_OR_NULL_ORIGIN => "Missing or null Origin",
    CALLBACK_URL_REQUIRED => "callbackURL is required",
    FAILED_TO_CREATE_VERIFICATION => "Unable to create verification",
    FIELD_NOT_ALLOWED => "Field not allowed to be set",
    ASYNC_VALIDATION_NOT_SUPPORTED => "Async validation is not supported",
    VALIDATION_ERROR => "Validation Error",
    MISSING_FIELD => "Field is required",
    METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED => "POST method requires deferSessionRefresh to be enabled in session config",
    BODY_MUST_BE_AN_OBJECT => "Body must be an object",
    PASSWORD_ALREADY_SET => "User already has a password set",
}

/// An error returned from an endpoint. Serialized as a JSON response with `status`.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: Map<String, Value>,
    pub headers: Box<http::HeaderMap>,
}

impl Error {
    /// The `ApiError` this error carries, or `fallback` for internal errors (which are logged).
    pub fn api_or(self, fallback: ApiError) -> ApiError {
        match self {
            Error::Api(e) => e,
            e => {
                tracing::error!(error = %e, "internal error");
                fallback
            }
        }
    }
}

impl ApiError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        let mut body = Map::new();
        body.insert("code".into(), Value::String(code.into()));
        body.insert("message".into(), Value::String(message.into()));
        Self { status, body, headers: Default::default() }
    }

    /// Equivalent of `APIError.from(status, CODE)`.
    pub fn from_code(status: StatusCode, code: ErrorCode) -> Self {
        Self::new(status, code.code, code.message)
    }

    /// An error carrying only a message; the code is derived from the message
    /// (upper-cased, spaces replaced with underscores) like better-call does.
    pub fn message(status: StatusCode, message: impl Into<String>) -> Self {
        let message = message.into();
        let code = message
            .to_uppercase()
            .chars()
            .map(|c| if c == ' ' { '_' } else { c })
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect::<String>();
        Self::new(status, code, message)
    }

    /// An error carrying a bare status, e.g. `ctx.error("INTERNAL_SERVER_ERROR")`.
    pub fn status(status: StatusCode) -> Self {
        let reason = status.canonical_reason().unwrap_or("Error");
        Self::message(status, reason)
    }

    pub fn bad_request(code: ErrorCode) -> Self {
        Self::from_code(StatusCode::BAD_REQUEST, code)
    }
    pub fn unauthorized(code: ErrorCode) -> Self {
        Self::from_code(StatusCode::UNAUTHORIZED, code)
    }
    pub fn forbidden(code: ErrorCode) -> Self {
        Self::from_code(StatusCode::FORBIDDEN, code)
    }
    pub fn not_found(code: ErrorCode) -> Self {
        Self::from_code(StatusCode::NOT_FOUND, code)
    }
    pub fn unprocessable(code: ErrorCode) -> Self {
        Self::from_code(StatusCode::UNPROCESSABLE_ENTITY, code)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", message)
    }

    /// The generic `{ code: "UNAUTHORIZED", message: "Unauthorized" }` error.
    pub fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")
    }

    pub fn with_field(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.body.insert(key.into(), value.into());
        self
    }

    pub fn code(&self) -> Option<&str> {
        self.body.get("code").and_then(Value::as_str)
    }

    pub fn message_str(&self) -> Option<&str> {
        self.body.get("message").and_then(Value::as_str)
    }

    pub fn to_json(&self) -> Value {
        Value::Object(self.body.clone())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status.as_u16(), json!(self.body))
    }
}

impl std::error::Error for ApiError {}

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        match err {
            Error::Api(e) => e,
            other => {
                tracing::error!(error = %other, "internal error");
                ApiError::internal("Internal Server Error")
            }
        }
    }
}

/// Library-level error for non-HTTP failures (configuration, database, crypto).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("http error: {0}")]
    Http(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Api(ApiError),
    #[error("{0}")]
    Other(String),
}

impl From<ApiError> for Error {
    fn from(e: ApiError) -> Self {
        Error::Api(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
