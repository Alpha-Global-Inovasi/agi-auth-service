//! `Mfa` behind a trait object, so the routes need no store type parameter for it.

use rusted_auth::mfa::{Mfa, MfaError, MfaLogin, MfaStatus, MfaStore, RecoveryCodes, TotpSetup};
use rusted_auth::session::{SessionStore, Uuid};
use std::future::Future;
use std::pin::Pin;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MfaError>> + Send + 'a>>;

pub(crate) trait DynMfa: Send + Sync + 'static {
    fn status(&self, user_id: Uuid) -> BoxFuture<'_, MfaStatus>;
    fn start_totp<'a>(&'a self, user_id: Uuid, account_name: &'a str) -> BoxFuture<'a, TotpSetup>;
    fn confirm_totp<'a>(&'a self, user_id: Uuid, code: &'a str) -> BoxFuture<'a, RecoveryCodes>;
    fn regenerate_recovery_codes<'a>(
        &'a self,
        user_id: Uuid,
        code: &'a str,
    ) -> BoxFuture<'a, RecoveryCodes>;
    fn disable_totp<'a>(&'a self, user_id: Uuid, code: &'a str) -> BoxFuture<'a, bool>;
    fn complete_login<'a>(&'a self, token: &'a str, code: &'a str) -> BoxFuture<'a, MfaLogin>;
}

impl<M: MfaStore, S: SessionStore> DynMfa for Mfa<M, S> {
    fn status(&self, user_id: Uuid) -> BoxFuture<'_, MfaStatus> {
        Box::pin(Mfa::status(self, user_id))
    }

    fn start_totp<'a>(&'a self, user_id: Uuid, account_name: &'a str) -> BoxFuture<'a, TotpSetup> {
        Box::pin(Mfa::start_totp(self, user_id, account_name))
    }

    fn confirm_totp<'a>(&'a self, user_id: Uuid, code: &'a str) -> BoxFuture<'a, RecoveryCodes> {
        Box::pin(Mfa::confirm_totp(self, user_id, code))
    }

    fn regenerate_recovery_codes<'a>(
        &'a self,
        user_id: Uuid,
        code: &'a str,
    ) -> BoxFuture<'a, RecoveryCodes> {
        Box::pin(Mfa::regenerate_recovery_codes(self, user_id, code))
    }

    fn disable_totp<'a>(&'a self, user_id: Uuid, code: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(Mfa::disable_totp(self, user_id, code))
    }

    fn complete_login<'a>(&'a self, token: &'a str, code: &'a str) -> BoxFuture<'a, MfaLogin> {
        Box::pin(Mfa::complete_login(self, token, code))
    }
}
