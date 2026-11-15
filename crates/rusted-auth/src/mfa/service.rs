//! The second-factor service.

use super::error::MfaError;
use super::recovery::{
    MAX_RECOVERY_CODE_DIGITS, MAX_RECOVERY_CODES, MIN_RECOVERY_CODE_DIGITS, RecoveryCodeHash,
    RecoveryCodes, candidate_hashes,
};
use super::store::{MfaStore, TotpRecord};
use super::totp::{Secret, TotpCheck, TotpConfig, otpauth_uri};
use crate::encryption::Keyring;
use crate::session::attempts::{AttemptScope, AttemptStore, DynAttemptStore, MemoryAttemptStore};
use crate::session::event::{AuthEvent, AuthEventKind, Events, MfaFailure, MfaMethod};
use crate::session::manager::Clock;
use crate::session::{AuthenticatedSession, Session, SessionManager, SessionStore, User};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use zeroize::Zeroizing;

/// How long wrong codes for changes to an account's second factor are counted, from the
/// first one.
const CHANGE_ATTEMPT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// A code that passed the check but is not used up yet.
enum Verified {
    Totp {
        step: u64,
        record: TotpRecord,
        secret: Zeroizing<Vec<u8>>,
    },
    RecoveryCode(RecoveryCodeHash),
}

impl Verified {
    fn method(&self) -> MfaMethod {
        match self {
            Self::Totp { .. } => MfaMethod::Totp,
            Self::RecoveryCode(_) => MfaMethod::RecoveryCode,
        }
    }
}

/// Associated data that ties an encrypted TOTP secret to its account.
fn secret_context(user_id: Uuid) -> Vec<u8> {
    let mut context = b"mfa_totp.secret_enc\0".to_vec();
    context.extend_from_slice(user_id.as_bytes());
    context
}

/// Second-factor settings.
///
/// | | Default |
/// |---|---|
/// | TOTP | see [`TotpConfig`] |
/// | Recovery codes per set | 10 |
/// | Digits per recovery code | 6 |
/// | Wrong codes per login before it is cancelled | 5 |
/// | Wrong codes for changes, per account in 5 minutes | the same number |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MfaConfig {
    /// How TOTP codes are made and checked.
    pub totp: TotpConfig,
    /// Recovery codes per set, 1 to [`MAX_RECOVERY_CODES`].
    pub recovery_codes: usize,
    /// Digits per recovery code, [`MIN_RECOVERY_CODE_DIGITS`] to
    /// [`MAX_RECOVERY_CODE_DIGITS`]. When this equals the TOTP digits, an entered code is
    /// checked as a TOTP code first, then as a recovery code.
    pub recovery_code_digits: u32,
    /// Wrong codes accepted for one login (one session waiting for the second step).
    /// The last allowed one revokes the session, so the user has to log in again. The
    /// same number of wrong codes per account blocks
    /// [`Mfa::disable_totp`] and [`Mfa::regenerate_recovery_codes`] for 5 minutes. At
    /// least 1.
    pub max_attempts: u32,
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            totp: TotpConfig::default(),
            recovery_codes: 10,
            recovery_code_digits: 6,
            max_attempts: 5,
        }
    }
}

impl MfaConfig {
    /// Set [`totp`](Self::totp).
    pub fn totp(mut self, totp: TotpConfig) -> Self {
        self.totp = totp;
        self
    }

    /// Set [`recovery_codes`](Self::recovery_codes).
    pub fn recovery_codes(mut self, count: usize) -> Self {
        self.recovery_codes = count;
        self
    }

    /// Set [`recovery_code_digits`](Self::recovery_code_digits).
    pub fn recovery_code_digits(mut self, digits: u32) -> Self {
        self.recovery_code_digits = digits;
        self
    }

    /// Set [`max_attempts`](Self::max_attempts).
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    fn check(&self) -> Result<(), MfaError> {
        self.totp.check().map_err(MfaError::Config)?;
        if !(1..=MAX_RECOVERY_CODES).contains(&self.recovery_codes) {
            return Err(MfaError::Config(format!(
                "recovery codes per set must be 1 to {MAX_RECOVERY_CODES}, not {}",
                self.recovery_codes
            )));
        }
        if !(MIN_RECOVERY_CODE_DIGITS..=MAX_RECOVERY_CODE_DIGITS)
            .contains(&self.recovery_code_digits)
        {
            return Err(MfaError::Config(format!(
                "recovery codes must have {MIN_RECOVERY_CODE_DIGITS} to \
                 {MAX_RECOVERY_CODE_DIGITS} digits, not {}",
                self.recovery_code_digits
            )));
        }
        if self.max_attempts == 0 {
            return Err(MfaError::Config(
                "at least one attempt must be allowed".into(),
            ));
        }
        Ok(())
    }
}

/// A TOTP setup that has been started but not confirmed: the secret to load into an
/// authenticator app. Returned once by [`Mfa::start_totp`].
///
/// Show the [`uri`](Self::uri) as a QR code (and the [`secret`](Self::secret) as text
/// for typing in by hand), then ask for a code and pass it to [`Mfa::confirm_totp`].
/// The `Debug` output never contains the secret, and the memory is wiped when the value
/// is dropped.
#[non_exhaustive]
pub struct TotpSetup {
    secret: Zeroizing<String>,
    uri: Zeroizing<String>,
}

impl TotpSetup {
    /// The secret in base32 without padding, for typing into an authenticator app.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The `otpauth://totp/...` URI with the secret, issuer, account name, algorithm,
    /// digits and period, for a QR code. Making the QR code is up to the client.
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

impl fmt::Debug for TotpSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TotpSetup(<redacted>)")
    }
}

/// An account's second factor, as reported by [`Mfa::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MfaStatus {
    /// No TOTP authenticator. Login needs only the password.
    Disabled,
    /// A TOTP setup was started but not confirmed. Login still needs only the password.
    SetupInProgress,
    /// A confirmed TOTP authenticator. Login needs a code after the password.
    Enabled {
        /// When the authenticator was confirmed.
        since: SystemTime,
        /// Recovery codes not used yet.
        recovery_codes_left: usize,
    },
}

/// A completed second step: the account and its new, active session.
///
/// This is the only time the new session token is available; it replaces the token of
/// the pending session, which no longer works. The `Debug` output does not contain it.
#[derive(Debug)]
#[non_exhaustive]
pub struct MfaLogin {
    /// The account that logged in.
    pub user: User,
    /// The new, active session.
    pub session: Session,
    /// The token of the new session, to hand to the client in place of the old one.
    pub token: crate::session::SessionToken,
    /// How the step was completed. After a recovery code, consider telling the user how
    /// many are left ([`Mfa::status`]).
    pub method: MfaMethod,
}

/// TOTP authenticators and recovery codes, and the second step of a login.
///
/// Cheap to clone; clones share the store, the keyring and the attempt counters.
///
/// - [`start_totp`](Self::start_totp) creates a secret and returns it with its setup
///   URI, once. Nothing changes for login until the setup is confirmed.
/// - [`confirm_totp`](Self::confirm_totp) checks one code from the authenticator,
///   switches TOTP on and returns the recovery codes, once.
/// - [`complete_login`](Self::complete_login) takes the token of a session waiting for
///   the second step and a TOTP code or a recovery code, and returns a new, active
///   session with a new token.
/// - [`regenerate_recovery_codes`](Self::regenerate_recovery_codes) replaces all
///   recovery codes; [`disable_totp`](Self::disable_totp) deletes the secret and the
///   recovery codes. Both need a current code.
///
/// Pass this to `local::LocalAuthBuilder::mfa` (with the `local` feature) so that password logins of accounts with TOTP produce sessions
/// that wait for the second step.
///
/// Events go to the event sink of the session manager.
pub struct Mfa<M, S> {
    inner: Arc<Inner<M, S>>,
}

struct Inner<M, S> {
    store: M,
    keyring: Keyring,
    sessions: SessionManager<S>,
    config: MfaConfig,
    issuer: Option<String>,
    attempts: Arc<dyn DynAttemptStore>,
    clock: Clock,
}

impl<M, S> Clone for Mfa<M, S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<M, S> fmt::Debug for Mfa<M, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mfa")
            .field("config", &self.inner.config)
            .field("issuer", &self.inner.issuer)
            .field("keyring", &self.inner.keyring)
            .finish_non_exhaustive()
    }
}

/// Configures an [`Mfa`]. Created by [`Mfa::builder`].
pub struct MfaBuilder<M, S> {
    store: M,
    keyring: Keyring,
    sessions: SessionManager<S>,
    config: MfaConfig,
    issuer: Option<String>,
    attempts: Arc<dyn DynAttemptStore>,
    clock: Clock,
}

impl<M: MfaStore, S: SessionStore> MfaBuilder<M, S> {
    /// Where wrong codes are counted. The default, a [`MemoryAttemptStore`], counts in
    /// this process only; with several processes, pass a store they share so that the
    /// limits hold across all of them.
    pub fn attempts(mut self, store: impl AttemptStore) -> Self {
        self.attempts = Arc::new(store);
        self
    }

    /// TOTP, recovery code and attempt settings.
    pub fn config(mut self, config: MfaConfig) -> Self {
        self.config = config;
        self
    }

    /// The name authenticator apps show above the account, usually the application or
    /// company name. Recommended; without it apps show only the account name.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    #[cfg(test)]
    pub(crate) fn clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Build the service. Fails with [`MfaError::Config`] when a setting is out of
    /// range.
    pub fn build(self) -> Result<Mfa<M, S>, MfaError> {
        self.config.check()?;
        Ok(Mfa {
            inner: Arc::new(Inner {
                store: self.store,
                keyring: self.keyring,
                sessions: self.sessions,
                config: self.config,
                issuer: self.issuer,
                attempts: self.attempts,
                clock: self.clock,
            }),
        })
    }
}

impl<M: MfaStore, S: SessionStore> Mfa<M, S> {
    /// Start configuring second factors kept in `store`, with TOTP secrets encrypted by
    /// `keyring`, completing logins of `sessions`.
    ///
    /// `sessions` must be the session manager that the logins use, so that the pending
    /// session's token is revoked in the process that checks tokens.
    pub fn builder(store: M, keyring: Keyring, sessions: SessionManager<S>) -> MfaBuilder<M, S> {
        MfaBuilder {
            store,
            keyring,
            sessions,
            config: MfaConfig::default(),
            issuer: None,
            attempts: Arc::new(MemoryAttemptStore::new()),
            clock: Box::new(SystemTime::now),
        }
    }

    /// The second-factor store.
    pub fn store(&self) -> &M {
        &self.inner.store
    }

    /// The configuration in effect.
    pub fn config(&self) -> MfaConfig {
        self.inner.config
    }

    /// The account's second factor.
    pub async fn status(&self, user_id: Uuid) -> Result<MfaStatus, MfaError> {
        let inner = &self.inner;
        Ok(match inner.store.find_totp(user_id).await? {
            None => MfaStatus::Disabled,
            Some(TotpRecord {
                confirmed_at: None, ..
            }) => MfaStatus::SetupInProgress,
            Some(TotpRecord {
                confirmed_at: Some(since),
                ..
            }) => MfaStatus::Enabled {
                since,
                recovery_codes_left: inner.store.count_unused_recovery_codes(user_id).await?,
            },
        })
    }

    /// `true` when logins of the account need a second step: it has a confirmed TOTP
    /// authenticator.
    pub async fn is_enabled(&self, user_id: Uuid) -> Result<bool, MfaError> {
        Ok(self
            .inner
            .store
            .find_totp(user_id)
            .await?
            .is_some_and(|record| record.is_confirmed()))
    }

    /// Start setting up a TOTP authenticator: create a secret, store it encrypted, and
    /// return it with its setup URI. This is the only time the secret is available.
    ///
    /// `account_name` is shown in the authenticator app next to the issuer, typically
    /// the email address or username. Starting again replaces an unconfirmed setup, so
    /// only the newest secret can be confirmed. Login is not affected until
    /// [`confirm_totp`](Self::confirm_totp) succeeds.
    ///
    /// Call this only for a fully authenticated session of the account. Fails with
    /// [`MfaError::AlreadyEnabled`] when the account already has a confirmed
    /// authenticator.
    pub async fn start_totp(
        &self,
        user_id: Uuid,
        account_name: &str,
    ) -> Result<TotpSetup, MfaError> {
        let inner = &self.inner;
        let config = &inner.config.totp;
        let secret = Secret::generate(config.secret_bytes).map_err(|e| {
            MfaError::Internal(format!("system random number generator failed: {e}"))
        })?;
        let secret_enc = inner
            .keyring
            .encrypt(&secret.0, &secret_context(user_id))
            .map_err(|e| MfaError::Internal(format!("could not encrypt TOTP secret: {e}")))?;
        if !inner
            .store
            .save_unconfirmed_totp(user_id, secret_enc)
            .await?
        {
            return Err(MfaError::AlreadyEnabled);
        }
        tracing::debug!(%user_id, "TOTP setup started");
        Ok(TotpSetup {
            secret: secret.base32(),
            uri: otpauth_uri(config, &secret.0, inner.issuer.as_deref(), account_name),
        })
    }

    /// Finish setting up TOTP with one code from the authenticator, and return the
    /// account's recovery codes. This is the only time the codes are available.
    ///
    /// From now on, password logins of the account wait for the second step. The code
    /// counts as used, so it cannot also complete a login.
    ///
    /// Wrong codes are not counted here: the caller is already authenticated, and
    /// should rate limit this like any other request. Fails with
    /// [`MfaError::InvalidCode`], [`MfaError::NoSetupInProgress`] when
    /// [`start_totp`](Self::start_totp) was not called, or [`MfaError::AlreadyEnabled`].
    pub async fn confirm_totp(&self, user_id: Uuid, code: &str) -> Result<RecoveryCodes, MfaError> {
        let inner = &self.inner;
        let now = (inner.clock)();
        let record = match inner.store.find_totp(user_id).await? {
            None => return Err(MfaError::NoSetupInProgress),
            Some(record) if record.is_confirmed() => return Err(MfaError::AlreadyEnabled),
            Some(record) => record,
        };
        let secret = self.decrypt(&record)?;
        let TotpCheck::Valid { step } = inner.config.totp.verify(&secret, code, now, None) else {
            tracing::debug!(%user_id, "TOTP setup not confirmed: wrong code");
            return Err(MfaError::InvalidCode);
        };
        let codes = self.new_recovery_codes()?;
        let confirmed = inner
            .store
            .confirm_totp(
                user_id,
                &record.secret_enc,
                step,
                now,
                codes.hashes(&inner.keyring, user_id),
            )
            .await?;
        if !confirmed {
            // Setup restarted, or confirmed by a concurrent request.
            tracing::debug!(%user_id, "TOTP setup changed while it was being confirmed");
            return Err(MfaError::InvalidCode);
        }
        tracing::debug!(%user_id, "TOTP enabled");
        self.emit(now, user_id, None, AuthEventKind::TotpEnabled);
        self.emit(
            now,
            user_id,
            None,
            AuthEventKind::RecoveryCodesGenerated { count: codes.len() },
        );
        Ok(codes)
    }

    /// Replace all recovery codes of the account, used or not, with a new set, and
    /// return it. This is the only time the codes are available.
    ///
    /// `code` must be a current TOTP code or an unused recovery code of the account; it
    /// is used up. Wrong codes count against the account: after
    /// [`MfaConfig::max_attempts`] of them, this and [`disable_totp`](Self::disable_totp)
    /// fail with [`MfaError::TooManyAttempts`] for 5 minutes.
    ///
    /// Call this only for a fully authenticated session of the account. Fails with
    /// [`MfaError::NotEnabled`] when the account has no confirmed authenticator, and with
    /// [`MfaError::InvalidCode`] for a wrong, malformed or reused code.
    pub async fn regenerate_recovery_codes(
        &self,
        user_id: Uuid,
        code: &str,
    ) -> Result<RecoveryCodes, MfaError> {
        let inner = &self.inner;
        let now = (inner.clock)();
        if !self.is_enabled(user_id).await? {
            return Err(MfaError::NotEnabled);
        }
        self.authorize_change(user_id, code, now).await?;
        let codes = self.new_recovery_codes()?;
        if !inner
            .store
            .replace_recovery_codes(user_id, codes.hashes(&inner.keyring, user_id))
            .await?
        {
            // Switched off by a concurrent request.
            return Err(MfaError::NotEnabled);
        }
        tracing::debug!(%user_id, "recovery codes replaced");
        self.emit(
            now,
            user_id,
            None,
            AuthEventKind::RecoveryCodesGenerated { count: codes.len() },
        );
        Ok(codes)
    }

    /// Switch TOTP off: delete the secret and all recovery codes. Returns `false` when
    /// there was nothing to delete.
    ///
    /// For a confirmed authenticator, `code` must be a current TOTP code or an unused
    /// recovery code of the account, and wrong codes count as for
    /// [`regenerate_recovery_codes`](Self::regenerate_recovery_codes). An unfinished
    /// setup protects nothing yet and is deleted without checking `code`.
    ///
    /// Call this only for a fully authenticated session of the account. Sessions are not
    /// touched; revoke the others with [`SessionManager::revoke_others`] if that is
    /// wanted. Fails with [`MfaError::InvalidCode`] for a wrong, malformed or reused
    /// code.
    pub async fn disable_totp(&self, user_id: Uuid, code: &str) -> Result<bool, MfaError> {
        let inner = &self.inner;
        let now = (inner.clock)();
        match inner.store.find_totp(user_id).await? {
            None => return Ok(false),
            Some(record) if record.is_confirmed() => {
                self.authorize_change(user_id, code, now).await?;
            }
            Some(_) => {}
        }
        let deleted = inner.store.delete_totp(user_id).await?;
        if deleted {
            tracing::debug!(%user_id, "TOTP disabled");
            self.emit(now, user_id, None, AuthEventKind::TotpDisabled);
        }
        Ok(deleted)
    }

    /// Complete the second step of a login.
    ///
    /// `pending_token` is the token of the session that the password login returned in
    /// state [`PendingMfa`](crate::session::SessionState::PendingMfa); `code` is either a
    /// TOTP code or a recovery code (spaces and hyphens are ignored). Input that has the
    /// shape of both is checked as a TOTP code first. On success the pending session is
    /// revoked and replaced by a new active session with a **new token**, whose absolute
    /// lifetime still counts from the password login ([`SessionManager::activate`]).
    ///
    /// The code is used up only after the new session exists, so a login that fails for
    /// another reason leaves the code valid. Should a concurrent request use the same
    /// code in between, the new session is revoked again and this fails with
    /// [`MfaError::InvalidCode`]; the user then has to log in again.
    ///
    /// # Attempts
    ///
    /// Each wrong code counts against the pending session. After
    /// [`MfaConfig::max_attempts`] wrong codes the session is revoked and this fails with
    /// [`MfaError::TooManyAttempts`]: the user has to log in with the password again.
    /// The counters live in the [`AttemptStore`] given to
    /// [`MfaBuilder::attempts`]; the default keeps them in this process.
    ///
    /// # Errors
    ///
    /// [`MfaError::InvalidCode`] for a wrong, malformed or reused code,
    /// [`MfaError::TooManyAttempts`], [`MfaError::Session`] when the token is not a
    /// session waiting for the second step (unknown, expired after 5 minutes, revoked or
    /// already completed), and storage failures. Failures are reported to the event
    /// sink, never with the code.
    pub async fn complete_login(
        &self,
        pending_token: &str,
        code: &str,
    ) -> Result<MfaLogin, MfaError> {
        let inner = &self.inner;
        let AuthenticatedSession { session, user } =
            inner.sessions.validate_pending_mfa(pending_token).await?;
        let now = (inner.clock)();
        let scope = AttemptScope::Login;
        let attempt = self
            .begin_attempt(scope, session.id, session.absolute_expires_at, now)
            .await?;

        let verified = match self.verify_code(user.id, code, now).await {
            Ok(Ok(verified)) => verified,
            Ok(Err((method, reason))) => {
                return Err(self
                    .login_rejected(now, &session, &user, method, reason, attempt)
                    .await);
            }
            Err(error) => {
                // Not the user's fault: give the attempt back.
                self.end_attempt(scope, session.id, false).await;
                return Err(error);
            }
        };
        let method = verified.method();

        // Activate first: if the session can no longer be activated, the code stays
        // unused.
        let issued = match inner.sessions.activate(&session).await {
            Ok(issued) => issued,
            Err(error) => {
                self.end_attempt(scope, session.id, false).await;
                return Err(error.into());
            }
        };
        self.end_attempt(scope, session.id, true).await;

        let consumed = self.consume(user.id, &verified, now).await;
        if !matches!(consumed, Ok(true)) {
            // A concurrent request used the code first, or the store failed: the new
            // session must not stay usable.
            if let Err(error) = inner.sessions.revoke(issued.session.id).await {
                tracing::error!(session_id = %issued.session.id, %error, "could not revoke session after its code could not be used up");
                return Err(error.into());
            }
            consumed?;
            tracing::debug!(
                session_id = %session.id,
                user_id = %user.id,
                "second authentication step rejected: code used concurrently"
            );
            self.emit(
                now,
                user.id,
                Some(&session),
                AuthEventKind::MfaFailed {
                    session_id: Some(session.id),
                    method: Some(method),
                    reason: MfaFailure::ReusedCode,
                    attempts: attempt,
                },
            );
            return Err(MfaError::InvalidCode);
        }
        if let Verified::Totp { record, secret, .. } = &verified {
            self.reencrypt_if_needed(record, secret).await;
        }

        tracing::debug!(
            session_id = %issued.session.id,
            user_id = %user.id,
            method = method.name(),
            "second authentication step completed"
        );
        self.emit(
            now,
            user.id,
            Some(&issued.session),
            AuthEventKind::MfaSucceeded {
                session_id: issued.session.id,
                method,
            },
        );
        Ok(MfaLogin {
            user,
            session: issued.session,
            token: issued.token,
            method,
        })
    }

    /// Report a rejected login code, and cancel the login when it was the last attempt.
    async fn login_rejected(
        &self,
        now: SystemTime,
        session: &Session,
        user: &User,
        method: Option<MfaMethod>,
        reason: MfaFailure,
        attempt: u32,
    ) -> MfaError {
        let inner = &self.inner;
        tracing::debug!(
            session_id = %session.id,
            user_id = %user.id,
            reason = reason.name(),
            attempt,
            "second authentication step rejected"
        );
        self.emit(
            now,
            user.id,
            Some(session),
            AuthEventKind::MfaFailed {
                session_id: Some(session.id),
                method,
                reason,
                attempts: attempt,
            },
        );
        if attempt < inner.config.max_attempts {
            return MfaError::InvalidCode;
        }
        tracing::warn!(
            session_id = %session.id,
            user_id = %user.id,
            attempts = attempt,
            "too many second-step attempts; login cancelled"
        );
        self.emit(
            now,
            user.id,
            Some(session),
            AuthEventKind::MfaAttemptsExceeded {
                session_id: Some(session.id),
                attempts: attempt,
            },
        );
        // Until the revocation succeeds the counter stays at its maximum, so further
        // codes are refused either way.
        if let Err(error) = inner.sessions.revoke(session.id).await {
            tracing::warn!(session_id = %session.id, %error, "could not revoke session after too many attempts");
            return error.into();
        }
        self.end_attempt(AttemptScope::Login, session.id, true)
            .await;
        MfaError::TooManyAttempts
    }

    /// Check and use up a code that confirms a change to the account's second factor.
    async fn authorize_change(
        &self,
        user_id: Uuid,
        code: &str,
        now: SystemTime,
    ) -> Result<(), MfaError> {
        let scope = AttemptScope::Change;
        let attempt = self
            .begin_attempt(scope, user_id, now + CHANGE_ATTEMPT_WINDOW, now)
            .await?;
        let verified = match self.verify_code(user_id, code, now).await {
            Ok(Ok(verified)) => verified,
            Ok(Err((method, reason))) => {
                return Err(self.change_rejected(now, user_id, method, reason, attempt));
            }
            Err(error) => {
                self.end_attempt(scope, user_id, false).await;
                return Err(error);
            }
        };
        match self.consume(user_id, &verified, now).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(self.change_rejected(
                    now,
                    user_id,
                    Some(verified.method()),
                    MfaFailure::ReusedCode,
                    attempt,
                ));
            }
            Err(error) => {
                self.end_attempt(scope, user_id, false).await;
                return Err(error);
            }
        }
        self.end_attempt(scope, user_id, true).await;
        Ok(())
    }

    /// Report a rejected code for a change. The counter stays until its window ends.
    fn change_rejected(
        &self,
        now: SystemTime,
        user_id: Uuid,
        method: Option<MfaMethod>,
        reason: MfaFailure,
        attempt: u32,
    ) -> MfaError {
        tracing::debug!(
            %user_id,
            reason = reason.name(),
            attempt,
            "second-factor code for a change rejected"
        );
        self.emit(
            now,
            user_id,
            None,
            AuthEventKind::MfaFailed {
                session_id: None,
                method,
                reason,
                attempts: attempt,
            },
        );
        if attempt < self.inner.config.max_attempts {
            return MfaError::InvalidCode;
        }
        tracing::warn!(%user_id, attempts = attempt, "too many second-factor codes for a change");
        self.emit(
            now,
            user_id,
            None,
            AuthEventKind::MfaAttemptsExceeded {
                session_id: None,
                attempts: attempt,
            },
        );
        MfaError::TooManyAttempts
    }

    /// Check a code without using it up. The outer error is a server failure; the inner
    /// one a rejected code, with what kind of code it looked like.
    async fn verify_code(
        &self,
        user_id: Uuid,
        code: &str,
        now: SystemTime,
    ) -> Result<Result<Verified, (Option<MfaMethod>, MfaFailure)>, MfaError> {
        let inner = &self.inner;
        let config = &inner.config;
        let totp_shape = config.totp.looks_like_code(code);
        let candidates =
            candidate_hashes(&inner.keyring, user_id, code, config.recovery_code_digits);
        let shape = match (totp_shape, &candidates) {
            (true, _) => MfaMethod::Totp,
            (false, Some(_)) => MfaMethod::RecoveryCode,
            (false, None) => return Ok(Err((None, MfaFailure::InvalidCode))),
        };
        let Some(record) = inner
            .store
            .find_totp(user_id)
            .await?
            .filter(TotpRecord::is_confirmed)
        else {
            return Ok(Err((Some(shape), MfaFailure::NotEnabled)));
        };

        let mut failure = (Some(MfaMethod::RecoveryCode), MfaFailure::InvalidCode);
        if totp_shape {
            let secret = self.decrypt(&record)?;
            match config
                .totp
                .verify(&secret, code, now, record.last_used_step)
            {
                TotpCheck::Valid { step } => {
                    return Ok(Ok(Verified::Totp {
                        step,
                        record,
                        secret,
                    }));
                }
                TotpCheck::Reused => failure = (Some(MfaMethod::Totp), MfaFailure::ReusedCode),
                TotpCheck::Invalid => failure = (Some(MfaMethod::Totp), MfaFailure::InvalidCode),
            }
        }
        if let Some(candidates) = candidates
            && let Some(hash) = inner
                .store
                .find_unused_recovery_code(user_id, &candidates)
                .await?
        {
            return Ok(Ok(Verified::RecoveryCode(hash)));
        }
        Ok(Err(failure))
    }

    /// Use up a verified code. `false` when a concurrent request used it first.
    async fn consume(
        &self,
        user_id: Uuid,
        verified: &Verified,
        now: SystemTime,
    ) -> Result<bool, MfaError> {
        let store = &self.inner.store;
        Ok(match verified {
            Verified::Totp { step, .. } => store.record_totp_step(user_id, *step).await?,
            Verified::RecoveryCode(hash) => store.use_recovery_code(user_id, hash, now).await?,
        })
    }

    fn decrypt(&self, record: &TotpRecord) -> Result<Zeroizing<Vec<u8>>, MfaError> {
        self.inner
            .keyring
            .decrypt(&record.secret_enc, &secret_context(record.user_id))
            .map_err(|e| {
                tracing::error!(user_id = %record.user_id, error = %e, "could not decrypt TOTP secret");
                MfaError::Internal(format!("could not decrypt TOTP secret: {e}"))
            })
    }

    /// After a key rotation, store the secret encrypted with the active key. Never fails
    /// the login.
    async fn reencrypt_if_needed(&self, record: &TotpRecord, secret: &[u8]) {
        let inner = &self.inner;
        if !inner.keyring.needs_reencryption(&record.secret_enc) {
            return;
        }
        let user_id = record.user_id;
        let result = match inner.keyring.encrypt(secret, &secret_context(user_id)) {
            Ok(new) => inner
                .store
                .replace_totp_secret(user_id, &record.secret_enc, new)
                .await
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match result {
            Ok(_) => tracing::debug!(%user_id, "TOTP secret re-encrypted with the active key"),
            Err(error) => tracing::warn!(%user_id, %error, "could not re-encrypt TOTP secret"),
        }
    }

    fn new_recovery_codes(&self) -> Result<RecoveryCodes, MfaError> {
        let config = &self.inner.config;
        RecoveryCodes::generate(config.recovery_codes, config.recovery_code_digits)
            .map_err(|e| MfaError::Internal(format!("system random number generator failed: {e}")))
    }

    /// Count an attempt before checking it, so that concurrent requests cannot exceed
    /// the limit. Returns the attempt's number. A failing counter store refuses the
    /// request.
    async fn begin_attempt(
        &self,
        scope: AttemptScope,
        key: Uuid,
        expires_at: SystemTime,
        now: SystemTime,
    ) -> Result<u32, MfaError> {
        let max = self.inner.config.max_attempts;
        match self
            .inner
            .attempts
            .dyn_begin(scope, key, max, expires_at, now)
            .await?
        {
            Some(attempt) => Ok(attempt),
            // Earlier requests used the last attempt.
            None => Err(MfaError::TooManyAttempts),
        }
    }

    /// `done`: forget the counter (the code was accepted, or the session revoked);
    /// otherwise give the attempt back. A failure is logged: the counter only errs on
    /// the safe side, and ends with its window.
    async fn end_attempt(&self, scope: AttemptScope, key: Uuid, done: bool) {
        let attempts = &self.inner.attempts;
        let result = if done {
            attempts.dyn_clear(scope, key).await
        } else {
            attempts.dyn_give_back(scope, key).await
        };
        if let Err(error) = result {
            tracing::warn!(scope = scope.as_str(), %key, %error, "could not update attempt counter");
        }
    }

    fn emit(&self, now: SystemTime, user_id: Uuid, session: Option<&Session>, kind: AuthEventKind) {
        self.events().emit(|| AuthEvent {
            at: now,
            user_id: Some(user_id),
            ip: session.and_then(|s| s.ip),
            user_agent: session.and_then(|s| s.user_agent.clone()),
            kind,
        });
    }

    fn events(&self) -> &Events {
        self.inner.sessions.events()
    }
}

#[cfg(feature = "local")]
use crate::session::attempts::BoxFuture;

#[cfg(feature = "local")]
/// What a login needs to know about second factors, without the store's type.
pub(crate) trait SecondFactor: Send + Sync {
    /// `true` when logins of the account must wait for a second step.
    fn required_for(&self, user_id: Uuid) -> BoxFuture<'_, Result<bool, MfaError>>;
}

#[cfg(feature = "local")]
impl<M: MfaStore, S: SessionStore> SecondFactor for Mfa<M, S> {
    fn required_for(&self, user_id: Uuid) -> BoxFuture<'_, Result<bool, MfaError>> {
        Box::pin(self.is_enabled(user_id))
    }
}

#[cfg(test)]
mod tests;
