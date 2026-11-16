//! [`SpawnMailer`]: delivers emails in the background.

use rusted_auth::local::{AuthEmail, Mailer};
use rusted_auth::session::BoxError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;

/// A [`Mailer`] that hands each email to a tokio task and returns at once.
///
/// `Mailer::send` must not wait for delivery: otherwise a password reset request, or a
/// registration with an address that already has an account, answers more slowly for
/// registered addresses. Wrap a mailer that talks to an SMTP server directly (such as
/// `rusted-email`) in this when the application has no job queue. With a queue, queue
/// the email in `send` instead; the queue also retries, which this does not.
///
/// At most `max_concurrent` deliveries run at once (default 16); further emails wait
/// for a slot. Above `max_queued` waiting or running (default 1000), `send` fails at
/// once, which `rusted-auth` logs and reports as `EmailSendFailed`. Failures of the
/// inner mailer happen after `send` returned, so they are only logged here, without
/// the token.
///
/// Must be used inside a tokio runtime, such as Actix's.
pub struct SpawnMailer<M> {
    inner: Arc<M>,
    slots: Arc<Semaphore>,
    queued: Arc<AtomicUsize>,
    max_queued: usize,
}

impl<M> Clone for SpawnMailer<M> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            slots: Arc::clone(&self.slots),
            queued: Arc::clone(&self.queued),
            max_queued: self.max_queued,
        }
    }
}

impl<M> std::fmt::Debug for SpawnMailer<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnMailer")
            .field("queued", &self.queued.load(Ordering::Relaxed))
            .field("max_queued", &self.max_queued)
            .finish_non_exhaustive()
    }
}

impl<M: Mailer> SpawnMailer<M> {
    /// Deliver through `inner` in the background.
    pub fn new(inner: M) -> Self {
        Self {
            inner: Arc::new(inner),
            slots: Arc::new(Semaphore::new(16)),
            queued: Arc::new(AtomicUsize::new(0)),
            max_queued: 1000,
        }
    }

    /// Deliveries running at once. Default: 16.
    #[must_use]
    pub fn max_concurrent(mut self, max: usize) -> Self {
        self.slots = Arc::new(Semaphore::new(max.max(1)));
        self
    }

    /// Emails waiting or being delivered, above which `send` fails. Default: 1000.
    #[must_use]
    pub fn max_queued(mut self, max: usize) -> Self {
        self.max_queued = max.max(1);
        self
    }

    /// Emails waiting or being delivered now.
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }
}

impl<M: Mailer> Mailer for SpawnMailer<M> {
    async fn send(&self, email: AuthEmail) -> Result<(), BoxError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "SpawnMailer needs a tokio runtime")?;
        if self.queued.fetch_add(1, Ordering::AcqRel) >= self.max_queued {
            self.queued.fetch_sub(1, Ordering::AcqRel);
            return Err("mail queue is full".into());
        }
        let inner = Arc::clone(&self.inner);
        let slots = Arc::clone(&self.slots);
        let queued = Arc::clone(&self.queued);
        runtime.spawn(async move {
            let kind = email.kind().name();
            let permit = slots.acquire_owned().await;
            if let Err(error) = inner.send(email).await {
                tracing::error!(email = kind, %error, "sending an account email failed");
            }
            drop(permit);
            queued.fetch_sub(1, Ordering::AcqRel);
        });
        Ok(())
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;
    use rusted_auth::local::RecordingMailer;
    use rusted_auth::session::{User, Uuid};
    use std::future::Future;
    use std::time::Duration;

    struct Slow(RecordingMailer);

    impl Mailer for Slow {
        fn send(&self, email: AuthEmail) -> impl Future<Output = Result<(), BoxError>> + Send {
            let inner = self.0.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                inner.send(email).await
            }
        }
    }

    fn email() -> AuthEmail {
        AuthEmail::RegistrationAttempt {
            to: User {
                id: Uuid::new_v4(),
                username: "budi".into(),
                email: "budi@example.com".into(),
                email_verified_at: None,
                name: "Budi".into(),
                disabled_at: None,
            },
        }
    }

    #[tokio::test]
    async fn send_returns_before_delivery() {
        let recorder = RecordingMailer::new();
        let mailer = SpawnMailer::new(Slow(recorder.clone())).max_queued(1);
        mailer.send(email()).await.unwrap();
        assert!(recorder.is_empty(), "returned before delivery");
        assert!(mailer.send(email()).await.is_err(), "queue of one is full");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(recorder.len(), 1);
        assert_eq!(mailer.queued(), 0);
    }
}
