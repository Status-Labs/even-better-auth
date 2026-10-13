//! The `user.validateUserInfo` gate (`utils/validate-user-info.ts`): lets the application
//! reject an identity before a user is created, an account is linked, or a provider user
//! signs in again.

use std::future::Future;
use std::sync::Arc;

use futures::future::BoxFuture;
use http::StatusCode;
use serde_json::{Map, Value};

use crate::error::{ApiError, Result};

/// What is about to happen with the incoming identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidateUserInfoAction {
    /// A new user record is about to be created.
    CreateUser,
    /// A provider account is about to be linked to an existing user.
    LinkAccount,
    /// An existing OAuth/SSO user is signing in again; the user data is the fresh profile.
    SignIn,
}

impl ValidateUserInfoAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreateUser => "create-user",
            Self::LinkAccount => "link-account",
            Self::SignIn => "sign-in",
        }
    }
}

/// Provider id and raw (unmapped) profile for OAuth and SSO methods.
#[derive(Debug, Clone, Default)]
pub struct ProviderInfo {
    pub provider_id: String,
    pub profile: Option<Value>,
}

/// Where an identity came from (`UserProvisioningSource`). `method` is one of `"oauth"`,
/// `"sso-oidc"`, `"sso-saml"`, `"email-password"`, `"magic-link"`, `"email-otp"`,
/// `"anonymous"`, `"siwe"`, `"phone-number"`, `"admin"`, or a plugin-defined value.
#[derive(Debug, Clone, Default)]
pub struct UserSource {
    pub method: String,
    /// Present iff `method` is `"oauth"`.
    pub oauth: Option<ProviderInfo>,
    /// Present iff `method` is `"sso-oidc"` or `"sso-saml"`.
    pub sso: Option<ProviderInfo>,
}

impl UserSource {
    pub fn method(method: impl Into<String>) -> Self {
        Self { method: method.into(), ..Default::default() }
    }

    pub fn oauth(provider_id: impl Into<String>, profile: Option<Value>) -> Self {
        Self {
            method: "oauth".into(),
            oauth: Some(ProviderInfo { provider_id: provider_id.into(), profile }),
            sso: None,
        }
    }
}

/// The argument to the `validate_user_info` callback.
#[derive(Debug, Clone)]
pub struct ValidateUserInfo {
    pub user: Map<String, Value>,
    pub source: UserSource,
    pub action: ValidateUserInfoAction,
}

/// A rejection: `error` is a short machine-readable code surfaced to the client.
#[derive(Debug, Clone)]
pub struct UserInfoRejection {
    pub error: String,
    pub error_description: Option<String>,
}

impl UserInfoRejection {
    pub fn new(error: impl Into<String>) -> Self {
        Self { error: error.into(), error_description: None }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }
}

/// `user.validateUserInfo`: return `Ok(None)` to allow, `Ok(Some(rejection))` to reject.
#[derive(Clone)]
pub struct ValidateUserInfoFn(
    Arc<dyn Fn(ValidateUserInfo) -> BoxFuture<'static, Result<Option<UserInfoRejection>>> + Send + Sync>,
);

impl ValidateUserInfoFn {
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(ValidateUserInfo) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<UserInfoRejection>>> + Send + 'static,
    {
        Self(Arc::new(move |v| Box::pin(f(v))))
    }
}

fn forbidden(code: &str, message: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, code, message)
}

fn check_source(source: &UserSource) -> Result<(), ApiError> {
    let missing = |message: &str| Err(forbidden("validation_source_missing", message));
    if source.method.is_empty() {
        return missing("User validation source is required");
    }
    let has_id = |p: &Option<ProviderInfo>| p.as_ref().is_some_and(|p| !p.provider_id.is_empty());
    if source.method == "oauth" && !has_id(&source.oauth) {
        return missing("OAuth user validation source requires oauth.providerId");
    }
    if (source.method == "sso-oidc" || source.method == "sso-saml") && !has_id(&source.sso) {
        return missing("SSO user validation source requires sso.providerId");
    }
    Ok(())
}

/// Run the configured gate, failing closed: a callback error rejects with
/// `validation_failed`. Rejections are `403` errors carrying the callback's code.
pub async fn assert_valid_user_info(
    validator: Option<&ValidateUserInfoFn>,
    user: &Map<String, Value>,
    source: &UserSource,
    action: ValidateUserInfoAction,
) -> Result<(), ApiError> {
    let Some(validate) = validator else { return Ok(()) };
    check_source(source)?;
    let input = ValidateUserInfo { user: user.clone(), source: source.clone(), action };
    match (validate.0)(input).await {
        Ok(None) => Ok(()),
        Ok(Some(rejection)) => {
            let message = rejection.error_description.unwrap_or_else(|| rejection.error.clone());
            Err(forbidden(&rejection.error, &message))
        }
        Err(e) => {
            tracing::error!(error = %e, "validateUserInfo callback threw");
            Err(forbidden("validation_failed", "User validation failed"))
        }
    }
}
