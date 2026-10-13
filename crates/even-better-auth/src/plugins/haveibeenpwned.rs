//! Compromised-password check (`plugins/haveibeenpwned`): passwords hashed on the configured
//! paths (sign-up, change/reset password, ...) are checked against the Have I Been Pwned
//! range API (k-anonymity: only the first 5 hex chars of the SHA-1 leave the server).

use std::any::Any;
use std::sync::Arc;

use futures::future::BoxFuture;
use http::StatusCode;
use sha1::{Digest, Sha1};

use crate::api::current_request;
use crate::error::{ApiError, Error, ErrorCode, Result};
use crate::options::{BetterAuthOptions, PasswordHasher};
use crate::plugin::Plugin;

/// Error codes.
pub mod error_codes {
    use crate::error::ErrorCode;

    pub const PASSWORD_COMPROMISED: ErrorCode = ErrorCode {
        code: "PASSWORD_COMPROMISED",
        message: "The password you entered has been compromised. Please choose a different password.",
    };
    pub const ALL: &[ErrorCode] = &[PASSWORD_COMPROMISED];
}

use error_codes as e;

/// Fetches the range response for a 5-character SHA-1 prefix.
pub type RangeFetcher = Arc<dyn Fn(String) -> BoxFuture<'static, Result<String>> + Send + Sync>;

#[derive(Clone)]
pub struct HaveIBeenPwnedOptions {
    pub custom_password_compromised_message: Option<String>,
    /// Paths whose password hashing is checked.
    pub paths: Vec<String>,
    pub enabled: bool,
    /// Replaces the request to `https://api.pwnedpasswords.com/range/{prefix}`.
    pub range_fetcher: Option<RangeFetcher>,
}

impl Default for HaveIBeenPwnedOptions {
    fn default() -> Self {
        Self {
            custom_password_compromised_message: None,
            paths: [
                "/sign-up/email",
                "/change-password",
                "/reset-password",
                "/email-otp/reset-password",
                "/phone-number/reset-password",
                "/admin/create-user",
                "/admin/set-user-password",
            ]
            .map(String::from)
            .to_vec(),
            enabled: true,
            range_fetcher: None,
        }
    }
}

/// The count for `suffix` in a range response (`getPasswordCompromiseCount`).
fn compromise_count(response: &str, suffix: &str) -> std::result::Result<u64, ()> {
    let prefix = format!("{}:", suffix.to_uppercase());
    for line in response.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(head) = line.get(..prefix.len()) else { continue };
        if !head.eq_ignore_ascii_case(&prefix) {
            continue;
        }
        let text = &line[prefix.len()..];
        return match text.parse::<u64>() {
            Ok(n) if n.to_string() == text && n < (1 << 53) => Ok(n),
            _ => Err(()),
        };
    }
    Ok(0)
}

async fn fetch_range(prefix: String) -> Result<String> {
    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let res = crate::oauth2::http_client()
        .get(&url)
        .header("Add-Padding", "true")
        .header("User-Agent", "BetterAuth Password Checker")
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    if !res.status().is_success() {
        return Err(ApiError::message(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to check password. Status: {}", res.status().as_u16()),
        )
        .into());
    }
    res.text().await.map_err(|e| Error::Http(e.to_string()))
}

/// Whether the password appears in the Have I Been Pwned corpus.
pub async fn is_password_compromised(password: &str, fetcher: Option<&RangeFetcher>) -> Result<bool> {
    let hash = hex::encode_upper(Sha1::digest(password.as_bytes()));
    let (prefix, suffix) = hash.split_at(5);
    let failed =
        || ApiError::message(StatusCode::INTERNAL_SERVER_ERROR, "Failed to check password. Please try again later.");
    let response = match fetcher {
        Some(f) => f(prefix.to_owned()).await,
        None => fetch_range(prefix.to_owned()).await,
    };
    let response = match response {
        Ok(r) => r,
        Err(Error::Api(api)) => return Err(Error::Api(api)),
        Err(_) => return Err(failed().into()),
    };
    let count = compromise_count(&response, suffix).map_err(|_| failed())?;
    Ok(count > 0)
}

pub struct HaveIBeenPwned {
    options: Arc<HaveIBeenPwnedOptions>,
}

pub fn have_i_been_pwned(options: HaveIBeenPwnedOptions) -> Arc<dyn Plugin> {
    Arc::new(HaveIBeenPwned { options: Arc::new(options) })
}

impl Plugin for HaveIBeenPwned {
    fn id(&self) -> &str {
        "have-i-been-pwned"
    }

    /// Wraps the password hasher so hashing on a checked path rejects compromised passwords.
    fn configure(&self, options: &mut BetterAuthOptions) {
        let original = options.email_and_password.password.clone();
        let verify = original.as_ref().map(|h| h.verify.clone());
        let opts = self.options.clone();
        let hash = Arc::new(move |password: String| -> BoxFuture<'static, Result<String>> {
            let opts = opts.clone();
            let original = original.clone();
            Box::pin(async move {
                let checked =
                    opts.enabled && current_request().is_some_and(|ctx| opts.paths.iter().any(|p| *p == ctx.path));
                if checked && is_password_compromised(&password, opts.range_fetcher.as_ref()).await? {
                    let message =
                        opts.custom_password_compromised_message.as_deref().unwrap_or(e::PASSWORD_COMPROMISED.message);
                    return Err(ApiError::message(StatusCode::BAD_REQUEST, message)
                        .with_field("code", e::PASSWORD_COMPROMISED.code)
                        .into());
                }
                match original {
                    Some(h) => (h.hash)(password).await,
                    None => crate::crypto::hash_password(&password).await,
                }
            })
        });
        let verify = verify.unwrap_or_else(|| {
            Arc::new(|hash: String, password: String| -> BoxFuture<'static, Result<bool>> {
                Box::pin(async move { crate::crypto::verify_password(&hash, &password).await })
            })
        });
        options.email_and_password.password = Some(PasswordHasher { hash, verify });
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        e::ALL.to_vec()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::compromise_count;

    #[test]
    fn parses_range_counts() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nABC:0";
        assert_eq!(compromise_count(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"), Ok(42));
        assert_eq!(compromise_count(body, "FFFF"), Ok(0));
        assert_eq!(compromise_count("ABC:01", "abc"), Err(()));
        assert_eq!(compromise_count("ABC:x", "abc"), Err(()));
    }
}
