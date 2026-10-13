//! Username authentication (`plugins/username`): `username` / `displayUsername` user fields,
//! `POST /sign-in/username` and `POST /is-username-available`, with validation on sign-up
//! and update-user.

use std::any::Any;
use std::sync::Arc;

use http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::middleware::get_session_from_ctx;
use crate::api::routes::email_verification::{create_email_verification_token, verification_url};
use crate::api::routes::util::assert_password_not_too_long;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, current_request, handler, hook};
use crate::cookies::set_session_cookie;
use crate::db::hooks::{BeforeOutcome, DatabaseHooks, Operation};
use crate::db::{Field, Record, TableExtension, Where};
use crate::error::{ApiError, ErrorCode, codes};
use crate::options::UserTokenEmail;
use crate::plugin::{MatchedHook, Plugin, PluginHooks};
use crate::types::{Model, SessionWithUser, User};

/// Error codes (`USERNAME_ERROR_CODES`).
pub mod error_codes {
    use crate::error::ErrorCode;

    macro_rules! codes {
        ($($name:ident => $msg:literal,)*) => {
            $(pub const $name: ErrorCode = ErrorCode { code: stringify!($name), message: $msg };)*
            pub const ALL: &[ErrorCode] = &[$($name),*];
        };
    }

    codes! {
        INVALID_USERNAME_OR_PASSWORD => "Invalid username or password",
        EMAIL_NOT_VERIFIED => "Email not verified",
        UNEXPECTED_ERROR => "Unexpected error",
        USERNAME_IS_ALREADY_TAKEN => "Username is already taken. Please try another.",
        USERNAME_TOO_SHORT => "Username is too short",
        USERNAME_TOO_LONG => "Username is too long",
        INVALID_USERNAME => "Username is invalid",
        INVALID_DISPLAY_USERNAME => "Display username is invalid",
        USERNAME_IS_IMMUTABLE => "Username cannot be updated",
    }
}

use error_codes as e;

pub type StringValidator = Arc<dyn Fn(&str) -> bool + Send + Sync>;
pub type StringNormalizer = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// When a value is validated relative to normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationOrder {
    #[default]
    PreNormalization,
    PostNormalization,
}

#[derive(Clone)]
pub struct UsernameOptions {
    /// Default 3.
    pub min_username_length: usize,
    /// Default 30.
    pub max_username_length: usize,
    /// Default: only `[a-zA-Z0-9_.]`.
    pub username_validator: Option<StringValidator>,
    /// Default: no validation.
    pub display_username_validator: Option<StringValidator>,
    /// `None` disables normalization; the default lowercases.
    pub username_normalization: Option<StringNormalizer>,
    /// Default: none.
    pub display_username_normalization: Option<StringNormalizer>,
    pub username_validation_order: ValidationOrder,
    pub display_username_validation_order: ValidationOrder,
    /// Users cannot change their username once set.
    pub immutable_username: bool,
    /// Add and maintain the `displayUsername` field (default true).
    pub display_username: bool,
}

impl Default for UsernameOptions {
    fn default() -> Self {
        Self {
            min_username_length: 3,
            max_username_length: 30,
            username_validator: None,
            display_username_validator: None,
            username_normalization: Some(Arc::new(|u: &str| u.to_lowercase())),
            display_username_normalization: None,
            username_validation_order: ValidationOrder::PreNormalization,
            display_username_validation_order: ValidationOrder::PreNormalization,
            immutable_username: false,
            display_username: true,
        }
    }
}

struct Inner {
    options: UsernameOptions,
}

/// Paths whose request hook already validated the username.
const PATHS_WITH_HTTP_VALIDATION: &[&str] = &["/sign-up/email", "/update-user"];

fn default_validator(username: &str) -> bool {
    !username.is_empty() && username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

fn err(code: ErrorCode) -> ApiError {
    ApiError::bad_request(code)
}

impl Inner {
    fn normalize(&self, username: &str) -> String {
        match &self.options.username_normalization {
            Some(f) => f(username),
            None => username.to_owned(),
        }
    }

    fn normalize_display(&self, display: &str) -> String {
        match &self.options.display_username_normalization {
            Some(f) => f(display),
            None => display.to_owned(),
        }
    }

    fn valid_format(&self, username: &str) -> bool {
        match &self.options.username_validator {
            Some(f) => f(username),
            None => default_validator(username),
        }
    }

    /// Length and format checks (`validateUsernameValue`).
    fn check_value(&self, username: &str) -> Option<ErrorCode> {
        let candidate = match self.options.username_validation_order {
            ValidationOrder::PostNormalization => self.normalize(username),
            ValidationOrder::PreNormalization => username.to_owned(),
        };
        let len = candidate.chars().count();
        if len < self.options.min_username_length {
            return Some(e::USERNAME_TOO_SHORT);
        }
        if len > self.options.max_username_length {
            return Some(e::USERNAME_TOO_LONG);
        }
        if !self.valid_format(&candidate) {
            return Some(e::INVALID_USERNAME);
        }
        None
    }

    fn check_display(&self, display: &str) -> Result<(), ApiError> {
        let Some(validator) = &self.options.display_username_validator else { return Ok(()) };
        let candidate = match self.options.display_username_validation_order {
            ValidationOrder::PostNormalization => self.normalize_display(display),
            ValidationOrder::PreNormalization => display.to_owned(),
        };
        if validator(&candidate) { Ok(()) } else { Err(err(e::INVALID_DISPLAY_USERNAME)) }
    }

    async fn find_by_username(&self, ctx: &EndpointContext, username: &str) -> Result<Option<User>, ApiError> {
        let row = ctx.auth.db.find_one("user", &[Where::eq("username", self.normalize(username))]).await?;
        Ok(row.map(User::from_record).transpose()?)
    }

    /// Full validation for writes that did not go through the HTTP hook (`validateUsername`).
    async fn validate(
        &self,
        ctx: &EndpointContext,
        username: &str,
        display: Option<&str>,
        current_user: Option<&str>,
    ) -> Result<(), ApiError> {
        if let Some(code) = self.check_value(username) {
            return Err(err(code));
        }
        if let Some(existing) = self.find_by_username(ctx, username).await?
            && current_user != Some(existing.id.as_str())
        {
            return Err(err(e::USERNAME_IS_ALREADY_TAKEN));
        }
        if let Some(display) = display.filter(|d| !d.is_empty()) {
            self.check_display(display)?;
        }
        Ok(())
    }

    /// Normalize `username` / `displayUsername` in a user record being written.
    async fn before_write(&self, mut user: Record, op: Operation) -> crate::error::Result<BeforeOutcome> {
        let username = user.get("username").and_then(Value::as_str).map(str::to_owned);
        let display = user.get("displayUsername").and_then(Value::as_str).map(str::to_owned);
        let include_display = self.options.display_username;
        if let Some(username) = &username {
            let request = current_request();
            let skip = request.as_ref().is_none_or(|r| PATHS_WITH_HTTP_VALIDATION.contains(&r.path.as_str()));
            if !skip && let Some(ctx) = &request {
                let current_user = match op {
                    Operation::Update => ctx
                        .session()
                        .map(|s| s.user.id)
                        .or_else(|| user.get("id").and_then(Value::as_str).map(str::to_owned)),
                    _ => None,
                };
                self.validate(ctx, username, display.as_deref(), current_user.as_deref()).await?;
            }
            user.insert("username".into(), self.normalize(username).into());
            if include_display {
                match (&display, op) {
                    (Some(d), _) => {
                        user.insert("displayUsername".into(), self.normalize_display(d).into());
                    }
                    (None, Operation::Create) => {
                        user.insert("displayUsername".into(), username.clone().into());
                    }
                    _ => {}
                }
            }
        } else if include_display && let Some(d) = &display {
            user.insert("displayUsername".into(), self.normalize_display(d).into());
        }
        if !include_display {
            user.remove("displayUsername");
        }
        Ok(BeforeOutcome::Merge(user))
    }

    /// Request hook for `/sign-up/email` and `/update-user`.
    async fn validate_request(&self, ctx: &EndpointContext) -> Result<(), ApiError> {
        let mut body = match ctx.body() {
            Value::Object(m) => m,
            _ => return Ok(()),
        };
        let is_sign_up = ctx.path == "/sign-up/email";
        // Use a valid displayUsername as the username when none is given.
        if is_sign_up
            && !body.contains_key("username")
            && let Some(display) = body.get("displayUsername").and_then(Value::as_str)
            && self.check_value(display).is_none()
        {
            body.insert("username".into(), display.into());
        }
        if let Some(username) = body.get("username").and_then(Value::as_str) {
            if let Some(code) = self.check_value(username) {
                return Err(err(code));
            }
            let normalized = self.normalize(username);
            let session = if is_sign_up { None } else { get_session_from_ctx(ctx, Default::default()).await? };
            if !is_sign_up && self.options.immutable_username {
                let current = session.as_ref().and_then(|s| s.user.extra.get("username")).and_then(Value::as_str);
                if current.is_some_and(|c| c != normalized) {
                    return Err(err(e::USERNAME_IS_IMMUTABLE));
                }
            }
            if let Some(existing) = self.find_by_username(ctx, username).await? {
                let own = session.as_ref().is_some_and(|s| s.user.id == existing.id);
                if is_sign_up || !own {
                    return Err(err(e::USERNAME_IS_ALREADY_TAKEN));
                }
            }
        }
        if self.options.display_username {
            if let Some(display) = body.get("displayUsername").and_then(Value::as_str) {
                self.check_display(display)?;
            }
            if is_sign_up
                && !body.contains_key("displayUsername")
                && let Some(username) = body.get("username").cloned()
            {
                body.insert("displayUsername".into(), username);
            }
        }
        ctx.set_body(Value::Object(body));
        Ok(())
    }
}

pub struct Username {
    inner: Arc<Inner>,
}

pub fn username(options: UsernameOptions) -> Arc<dyn Plugin> {
    Arc::new(Username { inner: Arc::new(Inner { options }) })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignInUsernameBody {
    username: String,
    password: String,
    remember_me: Option<bool>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
}

fn invalid_credentials() -> ApiError {
    ApiError::unauthorized(e::INVALID_USERNAME_OR_PASSWORD)
}

async fn sign_in_username(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: SignInUsernameBody = ctx.parse_body()?;
    if body.username.is_empty() || body.password.is_empty() {
        return Err(invalid_credentials());
    }
    let auth = ctx.auth.clone();
    let username = match inner.options.username_validation_order {
        ValidationOrder::PreNormalization => inner.normalize(&body.username),
        ValidationOrder::PostNormalization => body.username.clone(),
    };
    let len = username.chars().count();
    if len < inner.options.min_username_length {
        return Err(ApiError::unprocessable(e::USERNAME_TOO_SHORT));
    }
    if len > inner.options.max_username_length {
        return Err(ApiError::unprocessable(e::USERNAME_TOO_LONG));
    }
    if !inner.valid_format(&username) {
        return Err(ApiError::unprocessable(e::INVALID_USERNAME));
    }
    assert_password_not_too_long(&ctx, &body.password)?;

    let Some(user) = inner.find_by_username(&ctx, &username).await? else {
        // Hash anyway so response timing doesn't reveal whether the username exists.
        auth.hash_password(&body.password).await?;
        return Err(invalid_credentials());
    };
    let account = auth.internal_adapter.find_credential_account(&user.id).await?;
    let Some(hash) = account.and_then(|a| a.password) else {
        return Err(invalid_credentials());
    };
    if !auth.verify_password(&hash, &body.password).await? {
        return Err(invalid_credentials());
    }

    if auth.options.email_and_password.require_email_verification && !user.email_verified {
        let ev = &auth.options.email_verification;
        let Some(send) = &ev.send_verification_email else {
            return Err(ApiError::forbidden(e::EMAIL_NOT_VERIFIED));
        };
        if ev.send_on_sign_in {
            let token = create_email_verification_token(&auth.secret, &user.email, None, ev.expires_in, None)?;
            let callback = body.callback_url.as_deref().unwrap_or("/");
            let url = verification_url(&ctx, &token, Some(callback));
            let request_headers = ctx.is_request.then(|| ctx.headers());
            send.call(UserTokenEmail { user: user.clone(), url, token, request_headers }).await?;
        }
        return Err(ApiError::forbidden(e::EMAIL_NOT_VERIFIED));
    }

    let dont_remember = body.remember_me == Some(false);
    let session = auth.internal_adapter.create_session(&user.id, dont_remember, None).await.map_err(|e| {
        e.api_or(ApiError::from_code(StatusCode::INTERNAL_SERVER_ERROR, codes::FAILED_TO_CREATE_SESSION))
    })?;
    let token = session.token.clone();
    set_session_cookie(&ctx, &SessionWithUser { session, user: user.clone() }, Some(dont_remember), None).await;
    if let Some(cb) = &body.callback_url {
        ctx.set_header("location", cb);
    }
    ctx.json(json!({
        "redirect": body.callback_url.is_some(),
        "token": token,
        "url": body.callback_url,
        "user": auth.user_output(&user),
    }))
}

#[derive(Deserialize)]
struct IsUsernameAvailableBody {
    username: String,
}

async fn is_username_available(inner: Arc<Inner>, ctx: Ctx) -> EndpointResult {
    let body: IsUsernameAvailableBody = ctx.parse_body()?;
    if body.username.is_empty() {
        return Err(ApiError::unprocessable(e::INVALID_USERNAME));
    }
    let len = body.username.chars().count();
    if len < inner.options.min_username_length {
        return Err(ApiError::unprocessable(e::USERNAME_TOO_SHORT));
    }
    if len > inner.options.max_username_length {
        return Err(ApiError::unprocessable(e::USERNAME_TOO_LONG));
    }
    if !inner.valid_format(&body.username) {
        return Err(ApiError::unprocessable(e::INVALID_USERNAME));
    }
    let taken = inner.find_by_username(&ctx, &body.username).await?.is_some();
    ctx.json(json!({ "available": !taken }))
}

impl Plugin for Username {
    fn id(&self) -> &str {
        "username"
    }

    fn schema(&self) -> Vec<TableExtension> {
        let mut fields = vec![("username".into(), Field::string().optional().unique().sortable())];
        if self.inner.options.display_username {
            fields.push(("displayUsername".into(), Field::string().optional()));
        }
        vec![TableExtension { key: "user".into(), fields, ..Default::default() }]
    }

    fn endpoints(&self) -> Vec<Endpoint> {
        let (a, b) = (self.inner.clone(), self.inner.clone());
        vec![
            Endpoint::post("signInUsername", "/sign-in/username", handler(move |ctx| sign_in_username(a.clone(), ctx))),
            Endpoint::post(
                "isUsernameAvailable",
                "/is-username-available",
                handler(move |ctx| is_username_available(b.clone(), ctx)),
            ),
        ]
    }

    fn hooks(&self) -> PluginHooks {
        let inner = self.inner.clone();
        PluginHooks {
            before: vec![MatchedHook::new(
                |ctx| ctx.path == "/sign-up/email" || ctx.path == "/update-user",
                hook(move |ctx| {
                    let inner = inner.clone();
                    async move {
                        inner.validate_request(&ctx).await?;
                        Ok(None)
                    }
                }),
            )],
            after: vec![],
        }
    }

    fn database_hooks(&self) -> DatabaseHooks {
        let (create, update) = (self.inner.clone(), self.inner.clone());
        DatabaseHooks::new()
            .before("user", Operation::Create, move |user| {
                let inner = create.clone();
                async move { inner.before_write(user, Operation::Create).await }
            })
            .before("user", Operation::Update, move |user| {
                let inner = update.clone();
                async move { inner.before_write(user, Operation::Update).await }
            })
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
