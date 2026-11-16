//! Route handlers. Each one checks the request, counts it, then calls `rusted-auth`.

use super::State;
use super::dto::*;
use super::links;
use crate::failure::AuthFailure;
use crate::rate_limit::Bucket;
use crate::session;
use crate::web::{
    self as cookies, CSRF_COOKIE, Transport, csrf_cookie, new_csrf_token, presented_token,
};
use actix_web::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use actix_web::web::{Bytes, Data, Query};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder};
use rusted_auth::local::Registration;
use rusted_auth::session::{SessionError, SessionKind, SessionStore, UserStore};
use serde::de::DeserializeOwned;

/// A JSON body.
pub(super) fn json<T: DeserializeOwned>(body: &[u8]) -> Result<T, AuthFailure> {
    serde_json::from_slice(body).map_err(AuthFailure::bad_request)
}

/// Whether the body is a submitted HTML form rather than JSON.
pub(super) fn is_form(req: &HttpRequest) -> bool {
    req.headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"))
}

/// A form body.
pub(super) fn form<T: DeserializeOwned>(body: &[u8]) -> Result<T, AuthFailure> {
    let text = std::str::from_utf8(body).map_err(AuthFailure::bad_request)?;
    Query::<T>::from_query(text)
        .map(Query::into_inner)
        .map_err(AuthFailure::bad_request)
}

fn no_store(mut response: HttpResponseBuilder) -> HttpResponseBuilder {
    response.insert_header((CACHE_CONTROL, "no-store"));
    response
}

pub(super) async fn csrf(req: HttpRequest) -> HttpResponse {
    let mut response = no_store(HttpResponse::NoContent());
    if req.cookie(CSRF_COOKIE).is_none() {
        response.cookie(csrf_cookie(new_csrf_token()));
    }
    response.finish()
}

pub(super) async fn register<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let answer = async {
        state.web.check(&req, false, None)?;
        state.limit(Bucket::Register, &req).await?;
        let input: RegisterRequest = json(&body)?;
        state
            .local
            .register(Registration {
                username: input.username,
                email: input.email,
                name: input.name,
                password: input.password,
            })
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        // Created or already registered: the same answer, so the response does not
        // tell whether the address has an account.
        Ok(HttpResponse::Accepted().finish())
    };
    state.answer(answer.await)
}

pub(super) async fn login<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let answer = async {
        // This answer sets the session cookie, so it is always a browser request.
        state.web.check(&req, true, None)?;
        state.limit(Bucket::Login, &req).await?;
        let input: LoginRequest = json(&body)?;
        let context = state.context(&req, SessionKind::Web);
        let login = state
            .local
            .login(&input.identifier, &input.password, context)
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        let mut response = no_store(HttpResponse::Ok());
        cookies::set_session(
            &mut response,
            login.token.expose(),
            login.session.absolute_expires_at,
        );
        Ok(response.json(LoginResponse {
            data: LoginResult {
                user: UserView::from(&login.user),
                mfa_required: login.mfa_required(),
            },
        }))
    };
    state.answer(answer.await)
}

pub(super) async fn mobile_login<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let answer = async {
        state.web.check(&req, false, None)?;
        state.limit(Bucket::Login, &req).await?;
        let input: LoginRequest = json(&body)?;
        let context = state.context(&req, SessionKind::Mobile);
        let login = state
            .local
            .login(&input.identifier, &input.password, context)
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        Ok(no_store(HttpResponse::Ok()).json(MobileLoginResponse {
            data: MobileLoginResult {
                user: UserView::from(&login.user),
                mfa_required: login.mfa_required(),
                token: login.token.expose().to_owned(),
                expires_at: rfc3339(login.session.absolute_expires_at),
            },
        }))
    };
    state.answer(answer.await)
}

pub(super) async fn logout<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
) -> HttpResponse {
    let answer = async {
        state.web.check(&req, false, None)?;
        let sessions = state.local.sessions();
        let presented = presented_token(&req);
        if let Some((token, _)) = &presented {
            // A login that waits for its second factor can be cancelled too.
            let found = match sessions.validate(token).await {
                Err(SessionError::MfaRequired) => sessions.validate_pending_mfa(token).await,
                other => other,
            };
            match found {
                Ok(found) => {
                    sessions.revoke(found.session.id).await?;
                }
                Err(error) if error.is_server_error() => return Err(error.into()),
                Err(_) => {}
            }
        }
        let mut response = HttpResponse::NoContent();
        if !matches!(presented, Some((_, Transport::Bearer))) {
            cookies::clear_session(&mut response);
        }
        Ok(response.finish())
    };
    state.answer(answer.await)
}

pub(super) async fn verify_email<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let submitted_form = is_form(&req);
    let answer = async {
        let (input, csrf): (TokenRequest, Option<String>) = if submitted_form {
            let input: links::TokenForm = form(&body)?;
            (TokenRequest { token: input.token }, input.csrf_token)
        } else {
            (json(&body)?, None)
        };
        state.web.check(&req, false, csrf.as_deref())?;
        state.limit(Bucket::Token, &req).await?;
        let context = state.context(&req, SessionKind::Web);
        state
            .local
            .verify_email(&input.token, context)
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        Ok(HttpResponse::NoContent().finish())
    };
    let answer = answer.await;
    if submitted_form {
        return links::result_page(answer, "Your email address is verified.");
    }
    state.answer(answer)
}

pub(super) async fn resend_verification<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let answer = async {
        state.web.check(&req, false, None)?;
        state.limit(Bucket::Email, &req).await?;
        let input: EmailRequest = json(&body)?;
        let context = state.context(&req, SessionKind::Web);
        state
            .local
            .resend_verification(&input.email, context)
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        Ok(HttpResponse::Accepted().finish())
    };
    state.answer(answer.await)
}

pub(super) async fn forgot_password<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let answer = async {
        state.web.check(&req, false, None)?;
        state.limit(Bucket::Email, &req).await?;
        let input: EmailRequest = json(&body)?;
        let context = state.context(&req, SessionKind::Web);
        state
            .local
            .request_password_reset(&input.email, context)
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        Ok(HttpResponse::Accepted().finish())
    };
    state.answer(answer.await)
}

pub(super) async fn reset_password<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let submitted_form = is_form(&req);
    let answer = async {
        let (input, csrf): (ResetPasswordRequest, Option<String>) = if submitted_form {
            let input: links::ResetForm = form(&body)?;
            (
                ResetPasswordRequest {
                    token: input.token,
                    password: input.password,
                },
                input.csrf_token,
            )
        } else {
            (json(&body)?, None)
        };
        state.web.check(&req, false, csrf.as_deref())?;
        state.limit(Bucket::Token, &req).await?;
        let context = state.context(&req, SessionKind::Web);
        state
            .local
            .reset_password(&input.token, &input.password, context)
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        Ok(HttpResponse::NoContent().finish())
    };
    let answer = answer.await;
    if submitted_form {
        return links::result_page(answer, "Your password is changed. You can sign in now.");
    }
    state.answer(answer)
}

pub(super) async fn change_password<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
    body: Bytes,
) -> HttpResponse {
    let mut signed_out_cookie = false;
    let answer = async {
        state.web.check(&req, false, None)?;
        let current = session::current(state.local.sessions(), &req).await?;
        let input: ChangePasswordRequest = json(&body)?;
        let context = state.context(&req, current.session.kind);
        let result = state
            .local
            .change_password(
                current.authenticated(),
                &input.current_password,
                &input.new_password,
                context,
            )
            .await;
        if let Err(rusted_auth::local::LocalError::TooManyAttempts) = &result {
            // The session was revoked; drop the browser's cookies with it.
            signed_out_cookie = current.transport() == Transport::Cookie;
        }
        result.map_err(AuthFailure::change_password)?;
        Ok(HttpResponse::NoContent().finish())
    };
    let answer = answer.await;
    let mut response = state.answer(answer);
    if signed_out_cookie {
        let mut clear = HttpResponse::NoContent();
        cookies::clear_session(&mut clear);
        for cookie in clear.finish().cookies() {
            let _ = response.add_cookie(&cookie);
        }
    }
    response
}

pub(super) async fn username_available<U: UserStore, S: SessionStore>(
    req: HttpRequest,
    state: Data<State<U, S>>,
) -> HttpResponse {
    let answer = async {
        state.limit(Bucket::Register, &req).await?;
        let query = Query::<UsernameQuery>::from_query(req.query_string())
            .map_err(AuthFailure::bad_request)?;
        let available = state
            .local
            .username_available(&query.username)
            .await
            .map_err(|e| AuthFailure::local(e, "password"))?;
        Ok(HttpResponse::Ok().json(UsernameAvailableResponse {
            data: UsernameAvailableResult { available },
        }))
    };
    state.answer(answer.await)
}

#[cfg(feature = "mfa")]
pub(super) mod mfa {
    use super::*;
    use crate::session::current;
    use rusted_auth::mfa::MfaStatus;

    fn second_factor<U, S>(
        state: &State<U, S>,
    ) -> Result<&dyn super::super::second_factor::DynMfa, AuthFailure> {
        // Routes are only mounted with an `Mfa`.
        state.mfa.as_deref().ok_or_else(AuthFailure::not_found)
    }

    pub(in super::super) async fn verify<U: UserStore, S: SessionStore>(
        req: HttpRequest,
        state: Data<State<U, S>>,
        body: Bytes,
    ) -> HttpResponse {
        let answer = async {
            let Some((token, transport)) = presented_token(&req) else {
                return Err(AuthFailure::unauthenticated());
            };
            // With the cookie, this answer sets a new session cookie.
            state
                .web
                .check(&req, transport == Transport::Cookie, None)?;
            state.limit(Bucket::Login, &req).await?;
            let input: CodeRequest = json(&body)?;
            let done = second_factor(&state)?
                .complete_login(&token, &input.code)
                .await
                .map_err(AuthFailure::mfa_login)?;
            let user = UserView::from(&done.user);
            let method = done.method.name().to_owned();
            let mut response = no_store(HttpResponse::Ok());
            let result = match transport {
                Transport::Cookie => {
                    cookies::set_session(
                        &mut response,
                        done.token.expose(),
                        done.session.absolute_expires_at,
                    );
                    MfaVerifyResult {
                        user,
                        method,
                        token: None,
                        expires_at: None,
                    }
                }
                Transport::Bearer => MfaVerifyResult {
                    user,
                    method,
                    token: Some(done.token.expose().to_owned()),
                    expires_at: Some(rfc3339(done.session.absolute_expires_at)),
                },
            };
            Ok(response.json(MfaVerifyResponse { data: result }))
        };
        state.answer(answer.await)
    }

    pub(in super::super) async fn status<U: UserStore, S: SessionStore>(
        req: HttpRequest,
        state: Data<State<U, S>>,
    ) -> HttpResponse {
        let answer = async {
            let current = current(state.local.sessions(), &req).await?;
            let status = second_factor(&state)?
                .status(current.user.id)
                .await
                .map_err(AuthFailure::mfa_change)?;
            let result = match status {
                MfaStatus::Enabled {
                    since,
                    recovery_codes_left,
                } => MfaStatusResult {
                    status: "enabled".into(),
                    enabled_at: Some(rfc3339(since)),
                    recovery_codes_left: Some(recovery_codes_left),
                },
                MfaStatus::SetupInProgress => MfaStatusResult {
                    status: "setup_in_progress".into(),
                    enabled_at: None,
                    recovery_codes_left: None,
                },
                _ => MfaStatusResult {
                    status: "disabled".into(),
                    enabled_at: None,
                    recovery_codes_left: None,
                },
            };
            Ok(no_store(HttpResponse::Ok()).json(MfaStatusResponse { data: result }))
        };
        state.answer(answer.await)
    }

    pub(in super::super) async fn start_totp<U: UserStore, S: SessionStore>(
        req: HttpRequest,
        state: Data<State<U, S>>,
    ) -> HttpResponse {
        let answer = async {
            state.web.check(&req, false, None)?;
            let current = current(state.local.sessions(), &req).await?;
            let setup = second_factor(&state)?
                .start_totp(current.user.id, &current.user.email)
                .await
                .map_err(AuthFailure::mfa_change)?;
            Ok(no_store(HttpResponse::Ok()).json(TotpSetupResponse {
                data: TotpSetupResult {
                    secret: setup.secret().to_owned(),
                    uri: setup.uri().to_owned(),
                },
            }))
        };
        state.answer(answer.await)
    }

    fn codes_response(codes: &rusted_auth::mfa::RecoveryCodes) -> HttpResponse {
        no_store(HttpResponse::Ok()).json(RecoveryCodesResponse {
            data: RecoveryCodesResult {
                recovery_codes: codes.iter().map(str::to_owned).collect(),
            },
        })
    }

    pub(in super::super) async fn confirm_totp<U: UserStore, S: SessionStore>(
        req: HttpRequest,
        state: Data<State<U, S>>,
        body: Bytes,
    ) -> HttpResponse {
        let answer = async {
            state.web.check(&req, false, None)?;
            let current = current(state.local.sessions(), &req).await?;
            let input: CodeRequest = json(&body)?;
            let codes = second_factor(&state)?
                .confirm_totp(current.user.id, &input.code)
                .await
                .map_err(AuthFailure::mfa_change)?;
            Ok(codes_response(&codes))
        };
        state.answer(answer.await)
    }

    pub(in super::super) async fn regenerate_recovery_codes<U: UserStore, S: SessionStore>(
        req: HttpRequest,
        state: Data<State<U, S>>,
        body: Bytes,
    ) -> HttpResponse {
        let answer = async {
            state.web.check(&req, false, None)?;
            let current = current(state.local.sessions(), &req).await?;
            let input: CodeRequest = json(&body)?;
            let codes = second_factor(&state)?
                .regenerate_recovery_codes(current.user.id, &input.code)
                .await
                .map_err(AuthFailure::mfa_change)?;
            Ok(codes_response(&codes))
        };
        state.answer(answer.await)
    }

    pub(in super::super) async fn disable_totp<U: UserStore, S: SessionStore>(
        req: HttpRequest,
        state: Data<State<U, S>>,
        body: Bytes,
    ) -> HttpResponse {
        let answer = async {
            state.web.check(&req, false, None)?;
            let current = current(state.local.sessions(), &req).await?;
            let input: CodeRequest = json(&body)?;
            second_factor(&state)?
                .disable_totp(current.user.id, &input.code)
                .await
                .map_err(AuthFailure::mfa_change)?;
            Ok(HttpResponse::NoContent().finish())
        };
        state.answer(answer.await)
    }
}
