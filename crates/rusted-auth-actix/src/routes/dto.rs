//! Request and response bodies of [`AuthRoutes`](crate::AuthRoutes).
//!
//! Successful responses are `{ "data": ... }`; names are `snake_case` and times are
//! RFC 3339 in UTC. Each response has its own envelope type, so OpenAPI generators
//! get a concrete type per route.

use rusted_auth::session::{User, Uuid};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

macro_rules! redacted_debug {
    ($name:ident { $($shown:ident),* }) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($shown), &self.$shown))*
                    .finish_non_exhaustive()
            }
        }
    };
}

macro_rules! envelope {
    ($(#[$doc:meta])* $name:ident($inner:ty)) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Serialize)]
        #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
        pub struct $name {
            /// The result.
            pub data: $inner,
        }
    };
}

/// `POST /register`.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct RegisterRequest {
    /// 3 to 32 ASCII letters, digits, `.`, `_` or `-`, starting with a letter or digit.
    #[cfg_attr(feature = "utoipa", schema(min_length = 3, max_length = 32))]
    pub username: String,
    /// Email address.
    #[cfg_attr(feature = "utoipa", schema(max_length = 254, format = Email))]
    pub email: String,
    /// Display name.
    #[cfg_attr(feature = "utoipa", schema(min_length = 1, max_length = 255))]
    pub name: String,
    /// 8 to 128 characters by default.
    #[cfg_attr(feature = "utoipa", schema(min_length = 8, max_length = 128, format = Password))]
    pub password: String,
}
redacted_debug!(RegisterRequest {
    username,
    email,
    name
});

/// `POST /login` and `POST /mobile/login`.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct LoginRequest {
    /// Username or email address; one containing `@` is an email address.
    pub identifier: String,
    /// Password.
    #[cfg_attr(feature = "utoipa", schema(format = Password))]
    pub password: String,
}
redacted_debug!(LoginRequest { identifier });

/// A second-factor code: a TOTP code or a recovery code.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CodeRequest {
    /// The code, digits only.
    pub code: String,
}
redacted_debug!(CodeRequest {});

/// A token from an email link.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TokenRequest {
    /// The token, `rusted_t_...`.
    pub token: String,
}
redacted_debug!(TokenRequest {});

/// An email address, for `POST /password/forgot` and `POST /email/verify/resend`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct EmailRequest {
    /// Email address.
    #[cfg_attr(feature = "utoipa", schema(max_length = 254, format = Email))]
    pub email: String,
}

/// `POST /password/reset`.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ResetPasswordRequest {
    /// The token from the reset link.
    pub token: String,
    /// The new password.
    #[cfg_attr(feature = "utoipa", schema(min_length = 8, max_length = 128, format = Password))]
    pub password: String,
}
redacted_debug!(ResetPasswordRequest {});

/// `POST /password/change`.
#[derive(Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ChangePasswordRequest {
    /// The password now.
    #[cfg_attr(feature = "utoipa", schema(format = Password))]
    pub current_password: String,
    /// The new password.
    #[cfg_attr(feature = "utoipa", schema(min_length = 8, max_length = 128, format = Password))]
    pub new_password: String,
}
redacted_debug!(ChangePasswordRequest {});

/// Query of `GET /username-available`.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::IntoParams))]
pub struct UsernameQuery {
    /// The username to check.
    pub username: String,
}

/// An account as clients see it.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UserView {
    /// Stable identifier.
    pub id: Uuid,
    /// Login name.
    pub username: String,
    /// Email address.
    pub email: String,
    /// Display name.
    pub name: String,
    /// When the email address was verified, if it was.
    #[cfg_attr(feature = "utoipa", schema(format = DateTime))]
    pub email_verified_at: Option<String>,
}

impl From<&User> for UserView {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            name: user.name.clone(),
            email_verified_at: user.email_verified_at.map(rfc3339),
        }
    }
}

/// Result of `POST /login`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct LoginResult {
    /// The account.
    pub user: UserView,
    /// `true` when the session waits for a second factor: continue with
    /// `POST /mfa/verify`. Until then other requests answer 401 `mfa_required`.
    pub mfa_required: bool,
}

/// Result of `POST /mobile/login`.
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MobileLoginResult {
    /// The account.
    pub user: UserView,
    /// `true` when the session waits for a second factor: send this token to
    /// `POST /mfa/verify`, which answers with the token to keep.
    pub mfa_required: bool,
    /// Session token, `rusted_s_...`. Send it as `Authorization: Bearer <token>` and
    /// keep it in secure storage.
    pub token: String,
    /// When the session ends at the latest.
    #[cfg_attr(feature = "utoipa", schema(format = DateTime))]
    pub expires_at: String,
}
redacted_debug!(MobileLoginResult {
    user,
    mfa_required,
    expires_at
});

/// Result of `POST /mfa/verify`.
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MfaVerifyResult {
    /// The account.
    pub user: UserView,
    /// `totp` or `recovery_code`.
    pub method: String,
    /// For bearer clients only: the new session token, which replaces the one sent.
    /// Browsers get it in the session cookie instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// For bearer clients only: when the new session ends at the latest.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(format = DateTime))]
    pub expires_at: Option<String>,
}
redacted_debug!(MfaVerifyResult {
    user,
    method,
    expires_at
});

/// Result of `GET /mfa`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MfaStatusResult {
    /// `disabled`, `setup_in_progress` or `enabled`.
    pub status: String,
    /// When TOTP was switched on; only when `enabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(format = DateTime))]
    pub enabled_at: Option<String>,
    /// Recovery codes not used yet; only when `enabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes_left: Option<usize>,
}

/// Result of `POST /mfa/totp/start`. Shown once.
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TotpSetupResult {
    /// The secret in base32, for typing into an authenticator app.
    pub secret: String,
    /// `otpauth://totp/...` URI, for a QR code.
    pub uri: String,
}
redacted_debug!(TotpSetupResult {});

/// Recovery codes, from `POST /mfa/totp/confirm` and `POST /mfa/recovery-codes`. Shown
/// once.
#[derive(Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct RecoveryCodesResult {
    /// Single-use codes, each usable instead of a TOTP code once.
    pub recovery_codes: Vec<String>,
}
redacted_debug!(RecoveryCodesResult {});

/// Result of `GET /username-available`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UsernameAvailableResult {
    /// Whether no account uses the username.
    pub available: bool,
}

envelope!(
    /// `{ "data": LoginResult }`.
    LoginResponse(LoginResult)
);
envelope!(
    /// `{ "data": MobileLoginResult }`.
    MobileLoginResponse(MobileLoginResult)
);
envelope!(
    /// `{ "data": MfaVerifyResult }`.
    MfaVerifyResponse(MfaVerifyResult)
);
envelope!(
    /// `{ "data": MfaStatusResult }`.
    MfaStatusResponse(MfaStatusResult)
);
envelope!(
    /// `{ "data": TotpSetupResult }`.
    TotpSetupResponse(TotpSetupResult)
);
envelope!(
    /// `{ "data": RecoveryCodesResult }`.
    RecoveryCodesResponse(RecoveryCodesResult)
);
envelope!(
    /// `{ "data": UsernameAvailableResult }`.
    UsernameAvailableResponse(UsernameAvailableResult)
);

/// `time` as RFC 3339 in UTC with second precision, such as `2026-11-16T08:30:00Z`.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    let secs = match time.duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
    };
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn formats_rfc3339() {
        let at = |secs| rfc3339(UNIX_EPOCH + Duration::from_secs(secs));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_794_731_445), "2026-11-15T08:30:45Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH - Duration::from_secs(1)),
            "1969-12-31T23:59:59Z"
        );
    }
}
