//! `POST /sign-up/email` (`api/routes/sign-up.ts`).

use http::StatusCode;
use serde_json::{Map, Value, json};

use super::email_verification::{create_email_verification_token, verification_url};
use super::util::{assert_password_length, is_valid_email};
use crate::api::middleware::form_csrf;
use crate::api::{Ctx, Endpoint, EndpointContext, EndpointResult, handler};
use crate::cookies::set_session_cookie;
use crate::db::{InputAction, Record, parse_input};
use crate::error::{ApiError, Error, codes};
use crate::options::UserTokenEmail;
use crate::types::SessionWithUser;
use crate::utils::date;
use crate::utils::validate_user_info::UserSource;

pub const CORE_FIELDS: &[&str] = &["name", "email", "emailVerified", "image", "createdAt", "updatedAt"];

/// The opaque success returned for duplicate emails when enumeration protection is on.
fn generic_duplicate_response(
    ctx: &EndpointContext,
    name: &str,
    email: &str,
    image: Option<&str>,
    additional: &Map<String, Value>,
) -> EndpointResult {
    let now = date::now_value();
    let id = ctx.auth.options.advanced.generate_id.generate("user").unwrap_or_else(|| crate::crypto::generate_id(None));
    let mut user = Map::new();
    user.insert("id".into(), id.into());
    user.insert("name".into(), name.into());
    user.insert("email".into(), email.into());
    user.insert("emailVerified".into(), false.into());
    user.insert("image".into(), image.map(Value::from).unwrap_or(Value::Null));
    user.insert("createdAt".into(), now.clone());
    user.insert("updatedAt".into(), now);
    user.extend(additional.clone());
    let user = match ctx.auth.schema.table("user") {
        Some(t) => crate::db::filter_output(t, user),
        None => user,
    };
    ctx.json(json!({ "token": null, "user": user }))
}

async fn sign_up_email(ctx: Ctx) -> EndpointResult {
    form_csrf(&ctx)?;
    let auth = ctx.auth.clone();
    let opts = &auth.options.email_and_password;
    if !opts.enabled || opts.disable_sign_up {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_SIGN_UP_DISABLED",
            "Email and password sign up is not enabled",
        ));
    }
    let body = ctx.body();
    let Some(body) = body.as_object() else {
        return Err(ApiError::bad_request(codes::BODY_MUST_BE_AN_OBJECT));
    };
    let str_field = |k: &str| body.get(k).and_then(Value::as_str);
    let (Some(name), Some(email)) = (str_field("name"), str_field("email")) else {
        return Err(ApiError::bad_request(codes::VALIDATION_ERROR));
    };
    if !is_valid_email(email) {
        return Err(ApiError::bad_request(codes::INVALID_EMAIL));
    }
    let Some(password) = str_field("password").filter(|p| !p.is_empty()) else {
        return Err(ApiError::bad_request(codes::INVALID_PASSWORD));
    };
    assert_password_length(&ctx, password)?;
    let image = str_field("image");
    let callback_url = str_field("callbackURL");
    let remember_me = body.get("rememberMe").and_then(Value::as_bool);

    let generic_duplicate = opts.require_email_verification || !opts.auto_sign_in;
    let skip_auto_sign_in = !opts.auto_sign_in || generic_duplicate;

    let mut rest = body.clone();
    for k in ["name", "email", "password", "image", "callbackURL", "rememberMe"] {
        rest.remove(k);
    }
    let user_table = auth.schema.table("user").expect("user table");
    let additional = parse_input(user_table, &rest, InputAction::Create, CORE_FIELDS)?;
    let email = email.to_lowercase();

    if let Some(existing) = auth.internal_adapter.find_user_by_email(&email).await? {
        tracing::info!("sign-up attempt for existing email");
        if generic_duplicate {
            auth.hash_password(password).await?;
            if let Some(cb) = &opts.on_existing_user_sign_up {
                cb.call(existing).await?;
            }
            return generic_duplicate_response(&ctx, name, &email, image, &additional);
        }
        return Err(ApiError::unprocessable(codes::USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL));
    }

    let hash = auth.hash_password(password).await?;
    let mut data: Record = additional.clone();
    data.insert("email".into(), email.clone().into());
    data.insert("name".into(), name.into());
    if let Some(image) = image {
        data.insert("image".into(), image.into());
    }
    data.insert("emailVerified".into(), false.into());
    let dont_remember = remember_me == Some(false);
    // User, credential account and session are created in one transaction.
    let created = auth
        .transaction(async {
            let user = match auth.internal_adapter.create_user(data, &UserSource::method("email-password")).await {
                Ok(u) => u,
                Err(Error::Api(e)) if e.status == StatusCode::FORBIDDEN && generic_duplicate => return Ok(None),
                Err(Error::Api(e)) => return Err(e),
                Err(e) => {
                    tracing::error!(error = %e, "failed to create user");
                    return Err(ApiError::unprocessable(codes::FAILED_TO_CREATE_USER));
                }
            };
            let mut account = Record::new();
            account.insert("userId".into(), user.id.clone().into());
            account.insert("providerId".into(), "credential".into());
            account.insert("accountId".into(), user.id.clone().into());
            account.insert("password".into(), hash.into());
            auth.internal_adapter.link_account(account).await?;
            if skip_auto_sign_in {
                return Ok(Some((user, None)));
            }
            let session = auth
                .internal_adapter
                .create_session(&user.id, dont_remember, None)
                .await
                .map_err(|e| e.api_or(ApiError::bad_request(codes::FAILED_TO_CREATE_SESSION)))?;
            Ok(Some((user, Some(session))))
        })
        .await?;
    let Some((user, session)) = created else {
        return generic_duplicate_response(&ctx, name, &email, image, &additional);
    };

    let ev = &auth.options.email_verification;
    if ev.send_on_sign_up.unwrap_or(opts.require_email_verification) {
        let token = create_email_verification_token(&auth.secret, &user.email, None, ev.expires_in, None)?;
        let url = verification_url(&ctx, &token, callback_url);
        if let Some(send) = &ev.send_verification_email {
            let request_headers = ctx.is_request.then(|| ctx.headers());
            send.call(UserTokenEmail { user: user.clone(), url, token, request_headers }).await?;
        }
    }

    let Some(session) = session else {
        return ctx.json(json!({ "token": null, "user": auth.user_output(&user) }));
    };
    let token = session.token.clone();
    set_session_cookie(&ctx, &SessionWithUser { session, user: user.clone() }, Some(dont_remember), None).await;
    ctx.json(json!({ "token": token, "user": auth.user_output(&user) }))
}

pub fn endpoints() -> Vec<Endpoint> {
    vec![Endpoint::post("signUpEmail", "/sign-up/email", handler(sign_up_email)).allow_form()]
}
