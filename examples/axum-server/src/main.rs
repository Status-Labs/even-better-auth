//! Minimal axum server using even-better-auth.
//!
//! ```sh
//! BETTER_AUTH_SECRET=change-me-to-a-long-random-string cargo run -p axum-server-example
//! curl -X POST localhost:3000/api/auth/sign-up/email -H 'content-type: application/json' \
//!   -d '{"email":"a@b.com","password":"password1234","name":"A"}' -i
//! ```

use std::sync::{Arc, Mutex};

use axum::extract::FromRef;
use axum::routing::get;
use axum::{Json, Router};
use even_better_auth::oauth2::ProviderOptions;
use even_better_auth::plugins::email_otp::{EmailOtpOptions, OtpEmail, email_otp};
use even_better_auth::plugins::magic_link::{MagicLinkEmail, MagicLinkOptions, magic_link};
use even_better_auth::social_providers::GitHub;
use even_better_auth::{
    BetterAuth, BetterAuthOptions, CookieCacheStrategy, EmailAndPasswordOptions, MemoryAdapter, UserTokenEmail,
};
use even_better_auth_axum::{AuthSession, BetterAuthExt};
use serde_json::{Value, json};

/// Emails "sent" by the server. Exposed at `/api/dev/outbox` when `E2E=1`, for tests.
#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<Value>>>);

impl Outbox {
    fn record(&self, kind: &str, to: &str, url: Option<&str>, token: &str) {
        tracing::info!(kind, to, url, "email");
        self.0.lock().unwrap().push(json!({ "kind": kind, "to": to, "url": url, "token": token }));
    }
}

#[derive(Clone)]
struct AppState {
    auth: BetterAuth,
}

impl FromRef<AppState> for BetterAuth {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

async fn me(AuthSession(session): AuthSession) -> Json<Value> {
    Json(json!({ "user": session.user, "session": session.session }))
}

#[tokio::main]
async fn main() -> even_better_auth::Result<()> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".into());
    let mut options = BetterAuthOptions::new(Arc::new(MemoryAdapter::new()));
    options.base_url = Some(std::env::var("BASE_URL").unwrap_or_else(|_| format!("http://localhost:{port}")));
    options.email_and_password = EmailAndPasswordOptions::enabled();
    if let Ok(strategy) = std::env::var("COOKIE_CACHE") {
        options.session.cookie_cache.enabled = true;
        options.session.cookie_cache.strategy = match strategy.as_str() {
            "jwt" => CookieCacheStrategy::Jwt,
            "jwe" => CookieCacheStrategy::Jwe,
            _ => CookieCacheStrategy::Compact,
        };
    }
    let outbox = Outbox::default();
    let sent = outbox.clone();
    options.email_verification.send_verification_email = even_better_auth::callback(move |email: UserTokenEmail| {
        sent.record("verification", &email.user.email, Some(&email.url), &email.token);
        async { Ok(()) }
    });
    let sent = outbox.clone();
    options.email_and_password.send_reset_password = even_better_auth::callback(move |email: UserTokenEmail| {
        sent.record("reset-password", &email.user.email, Some(&email.url), &email.token);
        async { Ok(()) }
    });
    if let (Ok(id), Ok(secret)) = (std::env::var("GITHUB_CLIENT_ID"), std::env::var("GITHUB_CLIENT_SECRET")) {
        options.social_providers.push(Arc::new(GitHub::new(ProviderOptions::new(id, secret))));
    }
    options.plugins.push(even_better_auth::plugins::bearer::bearer(Default::default()));
    options.plugins.push(even_better_auth::plugins::username::username(Default::default()));
    options.plugins.push(even_better_auth::plugins::jwt::jwt(Default::default())?);
    let sent = outbox.clone();
    options.plugins.push(magic_link(MagicLinkOptions::new(even_better_auth::options::Callback::new(
        move |email: MagicLinkEmail| {
            sent.record("magic-link", &email.email, Some(&email.url), &email.token);
            async { Ok(()) }
        },
    ))));
    let sent = outbox.clone();
    options.plugins.push(email_otp(EmailOtpOptions::new(even_better_auth::options::Callback::new(
        move |email: OtpEmail| {
            sent.record("otp", &email.email, None, &email.otp);
            async { Ok(()) }
        },
    ))));
    options.plugins.push(even_better_auth::plugins::two_factor::two_factor(Default::default()));
    options.plugins.push(even_better_auth::plugins::admin::admin(Default::default())?);
    let sent = outbox.clone();
    options.plugins.push(even_better_auth::plugins::organization::organization(
        even_better_auth::plugins::organization::OrganizationOptions {
            teams: even_better_auth::plugins::organization::TeamOptions { enabled: true, ..Default::default() },
            send_invitation_email: Some(even_better_auth::options::Callback::new(
                move |invite: even_better_auth::plugins::organization::InvitationEmail| {
                    sent.record("invitation", &invite.email, None, &invite.id);
                    async { Ok(()) }
                },
            )),
            ..Default::default()
        },
    ));
    options.plugins.push(even_better_auth::plugins::anonymous::anonymous(Default::default()));
    options.plugins.push(even_better_auth::plugins::multi_session::multi_session(Default::default()));
    let (sent, reset) = (outbox.clone(), outbox.clone());
    let mut phone = even_better_auth::plugins::phone_number::PhoneNumberOptions::new(
        even_better_auth::options::Callback::new(move |otp: even_better_auth::plugins::phone_number::PhoneOtp| {
            sent.record("sms", &otp.phone_number, None, &otp.code);
            async { Ok(()) }
        }),
    );
    phone.send_password_reset_otp = Some(even_better_auth::options::Callback::new(
        move |otp: even_better_auth::plugins::phone_number::PhoneOtp| {
            reset.record("sms-reset", &otp.phone_number, None, &otp.code);
            async { Ok(()) }
        },
    ));
    phone.sign_up_on_verification = Some(even_better_auth::plugins::phone_number::SignUpOnVerification {
        get_temp_email: std::sync::Arc::new(|p| format!("{}@phone.example.com", p.trim_start_matches('+'))),
        get_temp_name: None,
    });
    options.plugins.push(even_better_auth::plugins::phone_number::phone_number(phone));
    options.plugins.push(even_better_auth::plugins::one_time_token::one_time_token(Default::default()));
    options.plugins.push(even_better_auth::plugins::last_login_method::last_login_method(
        even_better_auth::plugins::last_login_method::LastLoginMethodOptions {
            store_in_database: true,
            ..Default::default()
        },
    ));
    options.plugins.push(even_better_auth::plugins::open_api::open_api(Default::default()));
    options.plugins.push(even_better_auth::plugins::device_authorization::device_authorization(Default::default())?);
    options.plugins.push(even_better_auth::plugins::passkey::passkey(Default::default()));
    // Requests with an `x-api-key` header are signed in as the key's owner.
    options.plugins.push(even_better_auth::plugins::api_key::api_key(
        even_better_auth::plugins::api_key::ApiKeyOptions {
            enable_metadata: true,
            enable_session_for_api_keys: true,
            ..Default::default()
        },
    ));
    let auth = BetterAuth::new(options).await?;
    auth.migrate().await?;

    let mut app = Router::new().route("/api/me", get(me)).with_state(AppState { auth: auth.clone() });
    if std::env::var("E2E").is_ok() {
        let sent = outbox.clone();
        app = app
            .route("/api/dev/outbox", get(move || async move { Json(Value::Array(sent.0.lock().unwrap().clone())) }));
        let ctx = auth.context().clone();
        app = app.route(
            "/api/dev/make-admin",
            axum::routing::post(move |Json(body): Json<Value>| async move {
                let email = body["email"].as_str().unwrap_or_default().to_owned();
                let mut update = serde_json::Map::new();
                update.insert("role".into(), "admin".into());
                let user = ctx.internal_adapter.update_user_by_email(&email, update).await.ok().flatten();
                Json(json!({ "ok": user.is_some() }))
            }),
        );
    }
    let app = app.mount_better_auth(auth);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .map_err(|e| even_better_auth::Error::Other(e.to_string()))?;
    tracing::info!("listening on http://localhost:{port}");
    axum::serve(listener, app).await.map_err(|e| even_better_auth::Error::Other(e.to_string()))
}
