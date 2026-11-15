//! Email verification, password reset and password change, and the emails that go with
//! registration and lockout.

use super::LocalAuth;
use crate::local::error::LocalError;
use crate::local::mail::{AuthEmail, PasswordChangeVia};
use crate::local::validate;
use crate::session::AuthenticatedSession;
use crate::session::attempts::AttemptScope;
use crate::session::event::{AuthEventKind, EmailKind};
use crate::session::model::{SessionContext, SessionStore};
use crate::session::one_time::{NewOneTimeToken, OneTimeToken, OneTimeTokenHash, TokenPurpose};
use crate::session::user::{User, UserRecord, UserStore};
use std::time::SystemTime;
use uuid::Uuid;

impl<U: UserStore, S: SessionStore> LocalAuth<U, S> {
    /// Send the verification link again, for example from a "resend email" button.
    ///
    /// Always succeeds for a well-formed address, whether or not it has an account, so
    /// the answer does not tell who is registered. A link is sent only to an account
    /// that exists, is not disabled and is not verified yet, and only within the
    /// [`EmailPolicy`](super::EmailPolicy) limit. The new link replaces earlier ones.
    ///
    /// # Errors
    ///
    /// [`LocalError::InvalidEmail`] for a malformed address, and storage failures of the
    /// account lookup.
    pub async fn resend_verification(
        &self,
        email: &str,
        context: SessionContext,
    ) -> Result<(), LocalError> {
        let email = validate::email(email)?;
        let context = context.normalized();
        let Some(record) = self.inner.store.find_by_email(email).await? else {
            return Ok(());
        };
        let user = record.user;
        if user.disabled_at.is_some() || user.email_verified_at.is_some() {
            return Ok(());
        }
        let now = (self.inner.clock)();
        if !self
            .allow_email(now, user.id, EmailKind::VerifyEmail, &context)
            .await
        {
            return Ok(());
        }
        let ttl = self.inner.email_policy.verify_email_ttl;
        if let Some((token, expires_at)) = self
            .issue_token(now, &user, TokenPurpose::VerifyEmail, ttl)
            .await
        {
            let email = AuthEmail::VerifyEmail {
                to: user,
                token,
                expires_at,
            };
            self.send(now, email, &context).await;
        }
        Ok(())
    }

    /// Verify the account's email address with the token from a verification link, and
    /// return the account.
    ///
    /// The token is used up. This does not sign the user in: no session is created.
    ///
    /// # Errors
    ///
    /// [`LocalError::InvalidToken`] when the token is wrong, expired or used, belongs to
    /// a disabled account, or was sent to an address the account no longer has. Also
    /// storage failures.
    pub async fn verify_email(
        &self,
        token: &str,
        context: SessionContext,
    ) -> Result<User, LocalError> {
        let context = context.normalized();
        let now = (self.inner.clock)();
        let record = self.redeem(token, TokenPurpose::VerifyEmail, now).await?;
        let id = record.user.id;
        if self.inner.store.mark_email_verified(id, now).await? {
            tracing::debug!(user_id = %id, "email address verified");
            self.emit(now, Some(id), &context, || AuthEventKind::EmailVerified);
        }
        Ok(self.reload(record).await)
    }

    /// Send a password reset link, for a "forgot password" form.
    ///
    /// Always succeeds for a well-formed address, whether or not it has an account, so
    /// the answer does not tell who is registered. A link is sent only to an account
    /// that exists, has a password and is not disabled, and only within the
    /// [`EmailPolicy`](super::EmailPolicy) limit; nothing is sent to an address without
    /// an account. The new link replaces earlier ones.
    ///
    /// # Errors
    ///
    /// [`LocalError::InvalidEmail`] for a malformed address, and storage failures of the
    /// account lookup.
    pub async fn request_password_reset(
        &self,
        email: &str,
        context: SessionContext,
    ) -> Result<(), LocalError> {
        let email = validate::email(email)?;
        let context = context.normalized();
        let Some(record) = self.inner.store.find_by_email(email).await? else {
            tracing::debug!("password reset requested for an address without an account");
            return Ok(());
        };
        if record.password_hash.is_none() || record.user.disabled_at.is_some() {
            return Ok(());
        }
        let user = record.user;
        let now = (self.inner.clock)();
        if !self
            .allow_email(now, user.id, EmailKind::PasswordReset, &context)
            .await
        {
            return Ok(());
        }
        let ttl = self.inner.email_policy.reset_password_ttl;
        if let Some((token, expires_at)) = self
            .issue_token(now, &user, TokenPurpose::ResetPassword, ttl)
            .await
        {
            self.emit(now, Some(user.id), &context, || {
                AuthEventKind::PasswordResetRequested
            });
            let email = AuthEmail::PasswordReset {
                to: user,
                token,
                expires_at,
            };
            self.send(now, email, &context).await;
        }
        Ok(())
    }

    /// Set a new password with the token from a reset link, and return the account.
    ///
    /// On success the token is used up, the stored hash is replaced and the account's
    /// lockout is cleared in one store update, the email address counts as verified
    /// (its owner just used it), every other reset link of the account stops working,
    /// **every session of the account is revoked**, and the owner is notified. No new
    /// session is created: the user logs in with the new password, including the
    /// second factor when the account has one.
    ///
    /// Revoked sessions stop working at once in this process, and in other processes
    /// sharing the session store within their cache lifetime (30 seconds by default).
    ///
    /// The new password is hashed before the token is used, so a busy hasher does not
    /// waste the link. Using the token and storing the hash are separate store calls:
    /// if storing fails after the token was used, the user has to request a new link.
    ///
    /// # Errors
    ///
    /// [`LocalError::PasswordTooShort`] or [`LocalError::PasswordTooLong`] before the
    /// token is looked at, [`LocalError::InvalidToken`] (see
    /// [`verify_email`](Self::verify_email)), [`LocalError::Busy`], and storage
    /// failures.
    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
        context: SessionContext,
    ) -> Result<User, LocalError> {
        let inner = &self.inner;
        let context = context.normalized();
        inner.password_policy.validate(new_password)?;
        if OneTimeTokenHash::of_presented(token).is_none() {
            return Err(LocalError::InvalidToken);
        }
        let new_hash = inner.hasher.hash(new_password).await?;

        let now = (inner.clock)();
        let record = self.redeem(token, TokenPurpose::ResetPassword, now).await?;
        let id = record.user.id;
        inner.store.reset_password(id, new_hash).await?;
        inner.store.mark_email_verified(id, now).await?;
        self.invalidate_reset_links(now, id).await;
        self.clear_password_change_attempts(id).await;
        let revoked = inner.sessions.revoke_all(id).await?;
        tracing::debug!(user_id = %id, revoked, "password reset");
        self.emit(now, Some(id), &context, || AuthEventKind::PasswordReset);

        let user = self.reload(record).await;
        let email = AuthEmail::PasswordChanged {
            to: user.clone(),
            via: PasswordChangeVia::Reset,
            at: now,
        };
        self.send(now, email, &context).await;
        Ok(user)
    }

    /// Change the password of a signed-in account, given its current password.
    ///
    /// `session` is the caller's validated session. On success the new hash replaces
    /// the old one only if no other change happened meanwhile, every **other** session
    /// of the account is revoked (this one stays signed in), outstanding reset links
    /// stop working, and the owner is notified.
    ///
    /// Wrong current passwords are counted per account
    /// ([`PasswordChangePolicy`](super::PasswordChangePolicy)), separately from failed
    /// logins, so someone holding a stolen session cannot lock the owner out of logging
    /// in. When the limit is reached the calling session is revoked: that many wrong
    /// guesses from a signed-in session suggest it is not the owner's. The owner can
    /// still reset the password by email.
    ///
    /// # Errors
    ///
    /// [`LocalError::PasswordTooShort`] or [`LocalError::PasswordTooLong`] for the new
    /// password, [`LocalError::InvalidCredentials`] for a wrong current password (or a
    /// password changed concurrently), [`LocalError::TooManyAttempts`] when the limit is
    /// reached, [`LocalError::Busy`], and storage failures, including a failing attempt
    /// counter. When revoking the other sessions fails, the password has already been
    /// changed and the storage error is returned.
    pub async fn change_password(
        &self,
        session: &AuthenticatedSession,
        current_password: &str,
        new_password: &str,
        context: SessionContext,
    ) -> Result<(), LocalError> {
        let inner = &self.inner;
        let context = context.normalized();
        inner.password_policy.validate(new_password)?;
        let user_id = session.user.id;
        let session_id = session.session.id;
        let policy = inner.password_change;
        let scope = AttemptScope::PasswordChange;

        let now = (inner.clock)();
        let counted = inner
            .attempts
            .dyn_begin(
                scope,
                user_id,
                policy.max_attempts,
                now + policy.window,
                now,
            )
            .await?;
        let Some(attempts) = counted else {
            self.end_session_after_guesses(session_id).await?;
            return Err(LocalError::TooManyAttempts);
        };

        let hash = self
            .find(&session.user.email)
            .await?
            .filter(|record| record.user.id == user_id)
            .and_then(|record| record.password_hash);
        let verified = match &hash {
            Some(hash) => inner.hasher.verify(current_password, hash).await,
            None => inner.hasher.verify_dummy(current_password).await,
        };
        let matches = match verified {
            Ok(matches) => matches,
            Err(error) => {
                self.give_back_attempt(user_id).await;
                return Err(error);
            }
        };
        let Some(hash) = hash.filter(|_| matches) else {
            tracing::debug!(%user_id, attempts, "password change rejected: wrong password");
            if attempts >= policy.max_attempts {
                tracing::warn!(%user_id, attempts, "too many wrong passwords; session revoked");
                self.end_session_after_guesses(session_id).await?;
                return Err(LocalError::TooManyAttempts);
            }
            return Err(LocalError::InvalidCredentials);
        };

        let new_hash = match inner.hasher.hash(new_password).await {
            Ok(new_hash) => new_hash,
            Err(error) => {
                self.give_back_attempt(user_id).await;
                return Err(error);
            }
        };
        if !inner
            .store
            .replace_password_hash(user_id, &hash, new_hash)
            .await?
        {
            tracing::debug!(%user_id, "password changed concurrently; change rejected");
            return Err(LocalError::InvalidCredentials);
        }
        self.clear_password_change_attempts(user_id).await;
        let now = (inner.clock)();
        self.invalidate_reset_links(now, user_id).await;
        let revoked = inner.sessions.revoke_others(user_id, session_id).await?;
        tracing::debug!(%user_id, revoked, "password changed");
        self.emit(now, Some(user_id), &context, || {
            AuthEventKind::PasswordChanged { session_id }
        });
        let email = AuthEmail::PasswordChanged {
            to: session.user.clone(),
            via: PasswordChangeVia::Change,
            at: now,
        };
        self.send(now, email, &context).await;
        Ok(())
    }

    /// Send the verification link to a new account. Not limited: the account was just
    /// created.
    pub(super) async fn send_verification(&self, user: &User) {
        let context = SessionContext::web();
        let now = (self.inner.clock)();
        let ttl = self.inner.email_policy.verify_email_ttl;
        if let Some((token, expires_at)) = self
            .issue_token(now, user, TokenPurpose::VerifyEmail, ttl)
            .await
        {
            let email = AuthEmail::VerifyEmail {
                to: user.clone(),
                token,
                expires_at,
            };
            self.send(now, email, &context).await;
        }
    }

    /// Tell the owner of `email` that someone tried to register it.
    pub(super) async fn notify_registration_attempt(&self, email: &str) {
        let context = SessionContext::web();
        let record = match self.inner.store.find_by_email(email).await {
            Ok(Some(record)) => record,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "cannot look up the account for a registration notice");
                return;
            }
        };
        let user = record.user;
        let now = (self.inner.clock)();
        if self
            .allow_email(now, user.id, EmailKind::RegistrationAttempt, &context)
            .await
        {
            let email = AuthEmail::RegistrationAttempt { to: user };
            self.send(now, email, &context).await;
        }
    }

    /// Tell the owner that the account was locked.
    pub(super) async fn notify_lockout(
        &self,
        now: SystemTime,
        user: &User,
        until: SystemTime,
        context: &SessionContext,
    ) {
        if self
            .allow_email(now, user.id, EmailKind::AccountLocked, context)
            .await
        {
            let email = AuthEmail::AccountLocked {
                to: user.clone(),
                until,
            };
            self.send(now, email, context).await;
        }
    }

    /// Count one email others caused for `user_id`. `false` when it must not be sent:
    /// the limit is reached, or the counter failed. A failing counter is not an error,
    /// since an error only for registered addresses would reveal them.
    async fn allow_email(
        &self,
        now: SystemTime,
        user_id: Uuid,
        kind: EmailKind,
        context: &SessionContext,
    ) -> bool {
        let policy = self.inner.email_policy;
        let counted = self
            .inner
            .attempts
            .dyn_begin(
                AttemptScope::Email,
                user_id,
                policy.max_emails,
                now + policy.window,
                now,
            )
            .await;
        let allowed = match counted {
            Ok(Some(_)) => return true,
            Ok(None) => {
                tracing::debug!(%user_id, email = kind.name(), "email limit reached; not sent");
                false
            }
            Err(error) => {
                tracing::warn!(%user_id, email = kind.name(), %error, "email counter failed; not sent");
                false
            }
        };
        self.emit(now, Some(user_id), context, || {
            AuthEventKind::EmailThrottled { email: kind }
        });
        allowed
    }

    /// Create and store a token, ending the account's earlier tokens for `purpose`.
    /// `None`, logged, when the token store fails.
    async fn issue_token(
        &self,
        now: SystemTime,
        user: &User,
        purpose: TokenPurpose,
        ttl: std::time::Duration,
    ) -> Option<(OneTimeToken, SystemTime)> {
        let tokens = &self.inner.tokens;
        let issued = async {
            tokens.dyn_invalidate(user.id, purpose, now).await?;
            let token = OneTimeToken::generate().map_err(LocalError::Internal)?;
            let expires_at = now + ttl;
            tokens
                .dyn_insert(NewOneTimeToken {
                    token_hash: token.hash(),
                    user_id: user.id,
                    purpose,
                    email: user.email.clone(),
                    expires_at,
                })
                .await?;
            Ok::<_, LocalError>((token, expires_at))
        }
        .await;
        match issued {
            Ok(issued) => Some(issued),
            Err(error) => {
                tracing::warn!(
                    user_id = %user.id,
                    purpose = purpose.as_str(),
                    %error,
                    "cannot store a one-time token; email not sent"
                );
                None
            }
        }
    }

    /// Hand an email to the mailer. A refusal is logged and reported, never returned.
    async fn send(&self, now: SystemTime, email: AuthEmail, context: &SessionContext) {
        let kind = email.kind();
        let user_id = email.recipient().id;
        if let Err(error) = self.inner.mailer.dyn_send(email).await {
            tracing::warn!(%user_id, email = kind.name(), %error, "mailer refused an email");
            self.emit(now, Some(user_id), context, || {
                AuthEventKind::EmailSendFailed { email: kind }
            });
        }
    }

    /// Use up a token and return its account, checking that the account still has the
    /// address the token was sent to and is not disabled.
    async fn redeem(
        &self,
        token: &str,
        purpose: TokenPurpose,
        now: SystemTime,
    ) -> Result<UserRecord, LocalError> {
        let Some(hash) = OneTimeTokenHash::of_presented(token) else {
            return Err(LocalError::InvalidToken);
        };
        let Some(consumed) = self.inner.tokens.dyn_consume(&hash, purpose, now).await? else {
            tracing::debug!(
                purpose = purpose.as_str(),
                "token rejected: unknown, used or expired"
            );
            return Err(LocalError::InvalidToken);
        };
        // Addresses are unique, so the address the token was sent to finds the account
        // only while the account still has it.
        let record = self
            .inner
            .store
            .find_by_email(&consumed.email)
            .await?
            .filter(|record| record.user.id == consumed.user_id);
        match record {
            Some(record) if record.user.disabled_at.is_none() => Ok(record),
            Some(_) => {
                tracing::debug!(user_id = %consumed.user_id, "token rejected: account is disabled");
                Err(LocalError::InvalidToken)
            }
            None => {
                tracing::debug!(user_id = %consumed.user_id, "token rejected: address changed");
                Err(LocalError::InvalidToken)
            }
        }
    }

    /// The account as stored now, or `record` when it cannot be read again.
    async fn reload(&self, record: UserRecord) -> User {
        match self.inner.store.find_by_email(&record.user.email).await {
            Ok(Some(fresh)) if fresh.user.id == record.user.id => fresh.user,
            _ => record.user,
        }
    }

    async fn invalidate_reset_links(&self, now: SystemTime, user_id: Uuid) {
        let purpose = TokenPurpose::ResetPassword;
        if let Err(error) = self
            .inner
            .tokens
            .dyn_invalidate(user_id, purpose, now)
            .await
        {
            tracing::warn!(%user_id, %error, "cannot end outstanding reset links");
        }
    }

    async fn clear_password_change_attempts(&self, user_id: Uuid) {
        let scope = AttemptScope::PasswordChange;
        if let Err(error) = self.inner.attempts.dyn_clear(scope, user_id).await {
            tracing::warn!(%user_id, %error, "cannot clear the password change counter");
        }
    }

    async fn give_back_attempt(&self, user_id: Uuid) {
        let scope = AttemptScope::PasswordChange;
        if let Err(error) = self.inner.attempts.dyn_give_back(scope, user_id).await {
            tracing::warn!(%user_id, %error, "cannot give back a password change attempt");
        }
    }

    async fn end_session_after_guesses(&self, session_id: Uuid) -> Result<(), LocalError> {
        self.inner.sessions.revoke(session_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
