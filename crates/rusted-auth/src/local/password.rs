//! Password policy and argon2id hashing with bounded concurrency.

use super::error::LocalError;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{self, PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};
use std::collections::VecDeque;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Minimum password length, in Unicode scalar values.
pub const MIN_PASSWORD_CHARS: usize = 8;

/// Maximum password length, in Unicode scalar values.
pub const MAX_PASSWORD_CHARS: usize = 128;

/// argon2id memory cost in KiB (19 MiB), as recommended by OWASP.
const MEMORY_KIB: u32 = 19 * 1024;
/// argon2id iterations.
const ITERATIONS: u32 = 2;
/// argon2id degree of parallelism.
const PARALLELISM: u32 = 1;

/// Check a new password against the length policy.
///
/// The only rule is a length of [`MIN_PASSWORD_CHARS`] to [`MAX_PASSWORD_CHARS`]
/// characters. There are no composition rules (NIST SP 800-63B). Characters are counted
/// as Unicode scalar values, and the password is used exactly as given: it is neither
/// trimmed nor normalized.
pub fn validate_password(password: &str) -> Result<(), LocalError> {
    // Bytes bound the character count from above, which avoids walking a huge input.
    if password.len() > MAX_PASSWORD_CHARS * 4 {
        return Err(LocalError::PasswordTooLong);
    }
    match password.chars().count() {
        n if n < MIN_PASSWORD_CHARS => Err(LocalError::PasswordTooShort),
        n if n > MAX_PASSWORD_CHARS => Err(LocalError::PasswordTooLong),
        _ => Ok(()),
    }
}

/// Limits on concurrent password hashing.
///
/// One argon2id hash holds 19 MiB for its whole duration, so unbounded concurrency lets a
/// burst of logins exhaust memory: 100 at once need about 1.9 GB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HashLimits {
    /// Hashes computed at the same time. Default: 8.
    pub max_concurrent: usize,
    /// How long a request may wait for a free slot before it fails with
    /// [`LocalError::Busy`]. Default: 2 seconds.
    pub max_wait: Duration,
    /// Requests allowed to wait. Beyond this, requests fail with [`LocalError::Busy`]
    /// immediately. Default: 1024.
    pub max_queued: usize,
}

impl Default for HashLimits {
    fn default() -> Self {
        Self {
            max_concurrent: 8,
            max_wait: Duration::from_secs(2),
            max_queued: 1024,
        }
    }
}

impl HashLimits {
    /// Set [`max_concurrent`](Self::max_concurrent). Values below 1 are raised to 1.
    pub fn max_concurrent(mut self, n: usize) -> Self {
        self.max_concurrent = n.max(1);
        self
    }

    /// Set [`max_wait`](Self::max_wait).
    pub fn max_wait(mut self, wait: Duration) -> Self {
        self.max_wait = wait;
        self
    }

    /// Set [`max_queued`](Self::max_queued).
    pub fn max_queued(mut self, n: usize) -> Self {
        self.max_queued = n;
        self
    }
}

/// Hashes and verifies passwords with argon2id (m = 19 MiB, t = 2, p = 1).
///
/// Hashing is CPU and memory heavy, so it never runs on the calling task. Work is handed
/// to a small set of dedicated threads, at most [`HashLimits::max_concurrent`] of them,
/// which are started on demand and exit when idle. The methods are `async` but do not
/// depend on a particular async runtime.
///
/// Clones share the same limits and threads. Create one per application.
#[derive(Clone)]
pub struct PasswordHasher {
    inner: Arc<Inner>,
}

struct Inner {
    params: Params,
    limits: HashLimits,
    /// Hash of a random password, verified against when there is no real hash to check so
    /// that the attempt costs the same.
    dummy_hash: String,
    pool: Mutex<Pool>,
}

struct Pool {
    /// Worker threads currently alive.
    active: usize,
    queue: VecDeque<Job>,
}

struct Job {
    queued_at: Instant,
    /// Runs the work, or reports [`LocalError::Busy`] when called with `true`.
    run: Box<dyn FnOnce(bool) + Send + 'static>,
}

impl fmt::Debug for PasswordHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHasher")
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

impl PasswordHasher {
    /// A hasher with the default [`HashLimits`].
    ///
    /// This computes one hash on the calling thread (tens of milliseconds), so build it
    /// once at startup.
    pub fn new() -> Result<Self, LocalError> {
        Self::with_limits(HashLimits::default())
    }

    /// A hasher with custom limits. See [`PasswordHasher::new`].
    pub fn with_limits(limits: HashLimits) -> Result<Self, LocalError> {
        let params = Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None)
            .map_err(|e| LocalError::Internal(format!("argon2 parameters: {e}")))?;
        Self::with_params(params, limits)
    }

    /// A hasher with cheap parameters so tests do not spend seconds hashing.
    #[cfg(test)]
    pub(crate) fn insecure_for_tests(limits: HashLimits) -> Self {
        let params = Params::new(Params::MIN_M_COST, 1, 1, None).unwrap();
        Self::with_params(params, limits).unwrap()
    }

    /// Occupies one worker until the returned sender is used or dropped. Returns once
    /// the worker has started.
    #[cfg(test)]
    pub(crate) fn occupy_worker(
        &self,
    ) -> (
        std::sync::mpsc::Sender<()>,
        oneshot::Receiver<Result<(), LocalError>>,
    ) {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let blocked = self
            .submit(move || {
                let _ = started_tx.send(());
                let _ = wait.recv();
                Ok(())
            })
            .unwrap();
        started_rx.recv().unwrap();
        (release, blocked)
    }

    /// Queue a job that does nothing, to fill the queue.
    #[cfg(test)]
    pub(crate) fn queue_noop(&self) -> oneshot::Receiver<Result<(), LocalError>> {
        self.submit(|| Ok(())).unwrap()
    }

    fn with_params(params: Params, limits: HashLimits) -> Result<Self, LocalError> {
        let limits = limits.max_concurrent(limits.max_concurrent);
        let dummy_password = Zeroizing::new(uuid::Uuid::new_v4().to_string());
        let dummy_hash = hash_blocking(&params, &dummy_password)?;
        Ok(Self {
            inner: Arc::new(Inner {
                params,
                limits,
                dummy_hash,
                pool: Mutex::new(Pool {
                    active: 0,
                    queue: VecDeque::new(),
                }),
            }),
        })
    }

    /// The limits this hasher was built with.
    pub fn limits(&self) -> HashLimits {
        self.inner.limits
    }

    /// Hash a new password and return it as a PHC string (`$argon2id$v=19$...`) with a
    /// fresh random salt.
    ///
    /// The password must satisfy [`validate_password`].
    pub async fn hash(&self, password: &str) -> Result<String, LocalError> {
        validate_password(password)?;
        let password = Zeroizing::new(password.to_owned());
        let params = self.inner.params.clone();
        self.run(move || hash_blocking(&params, &password)).await
    }

    /// Check `password` against a PHC string produced by [`hash`](Self::hash).
    ///
    /// Returns `Ok(false)` for a wrong password and an error when the hash cannot be
    /// parsed or hashing is at capacity. The parameters stored in the hash are used, so
    /// hashes made with older parameters keep verifying.
    pub async fn verify(&self, password: &str, hash: &str) -> Result<bool, LocalError> {
        // A password over the limit can never have been accepted, so it is rejected
        // without spending a hash on attacker-sized input.
        if matches!(
            validate_password(password),
            Err(LocalError::PasswordTooLong)
        ) {
            return Ok(false);
        }
        let password = Zeroizing::new(password.to_owned());
        let hash = hash.to_owned();
        self.run(move || verify_blocking(&password, &hash)).await
    }

    /// Spend the same effort as [`verify`](Self::verify) without a real hash, for logins
    /// where no account or password exists. Always returns `Ok(false)` unless hashing is
    /// at capacity.
    pub(crate) async fn verify_dummy(&self, password: &str) -> Result<bool, LocalError> {
        self.verify(password, &self.inner.dummy_hash).await?;
        Ok(false)
    }

    async fn run<T, F>(&self, work: F) -> Result<T, LocalError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, LocalError> + Send + 'static,
    {
        self.submit(work)?.await.unwrap_or_else(|_| {
            Err(LocalError::Internal(
                "password hashing worker exited".into(),
            ))
        })
    }

    /// Start `work` on a worker thread, or queue it when all workers are busy.
    fn submit<T, F>(&self, work: F) -> Result<oneshot::Receiver<Result<T, LocalError>>, LocalError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, LocalError> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let job = Job {
            queued_at: Instant::now(),
            run: Box::new(move |waited_too_long| {
                // The caller gave up (for example the client disconnected).
                if tx.is_closed() {
                    return;
                }
                let result = if waited_too_long {
                    Err(LocalError::Busy)
                } else {
                    catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|_| {
                        Err(LocalError::Internal("password hashing panicked".into()))
                    })
                };
                let _ = tx.send(result);
            }),
        };

        let mut pool = self.inner.pool();
        if pool.active >= self.inner.limits.max_concurrent {
            if pool.queue.len() >= self.inner.limits.max_queued {
                drop(pool);
                tracing::warn!("password hashing queue is full");
                return Err(LocalError::Busy);
            }
            pool.queue.push_back(job);
            return Ok(rx);
        }
        pool.active += 1;
        drop(pool);

        let inner = Arc::clone(&self.inner);
        let spawned = std::thread::Builder::new()
            .name("rusted-auth-argon2".into())
            .spawn(move || inner.work(job));
        if let Err(error) = spawned {
            self.inner.pool().active -= 1;
            return Err(LocalError::Internal(format!(
                "cannot start password hashing thread: {error}"
            )));
        }
        Ok(rx)
    }
}

impl Inner {
    fn pool(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Worker thread body: run `first`, then queued jobs until none are left.
    fn work(&self, first: Job) {
        (first.run)(false);
        loop {
            let job = {
                let mut pool = self.pool();
                match pool.queue.pop_front() {
                    Some(job) => job,
                    None => {
                        pool.active -= 1;
                        return;
                    }
                }
            };
            let waited = job.queued_at.elapsed();
            let waited_too_long = waited > self.limits.max_wait;
            if waited_too_long {
                tracing::warn!(
                    waited_ms = waited.as_millis() as u64,
                    "password hashing request waited too long"
                );
            }
            (job.run)(waited_too_long);
        }
    }
}

fn argon2(params: &Params) -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone())
}

fn hash_blocking(params: &Params, password: &str) -> Result<String, LocalError> {
    let hash: PasswordHash = argon2(params)
        .hash_password(password.as_bytes())
        .map_err(|e| LocalError::Internal(format!("password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

fn verify_blocking(password: &str, hash: &str) -> Result<bool, LocalError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| LocalError::Internal(format!("stored password hash is malformed: {e}")))?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(password_hash::Error::PasswordInvalid) => Ok(false),
        Err(e) => Err(LocalError::Internal(format!(
            "password verification failed: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    fn hasher(limits: HashLimits) -> PasswordHasher {
        PasswordHasher::insecure_for_tests(limits)
    }

    #[test]
    fn password_length_is_counted_in_characters() {
        assert!(matches!(
            validate_password("1234567"),
            Err(LocalError::PasswordTooShort)
        ));
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password(&"a".repeat(128)).is_ok());
        assert!(matches!(
            validate_password(&"a".repeat(129)),
            Err(LocalError::PasswordTooLong)
        ));

        // Multi-byte characters count once each.
        assert!(validate_password(&"é".repeat(8)).is_ok());
        assert!(validate_password(&"🔑".repeat(128)).is_ok());
        assert!(matches!(
            validate_password(&"🔑".repeat(129)),
            Err(LocalError::PasswordTooLong)
        ));
        assert!(matches!(
            validate_password(&"a".repeat(1_000_000)),
            Err(LocalError::PasswordTooLong)
        ));
    }

    #[test]
    fn no_composition_rules() {
        assert!(validate_password("aaaaaaaa").is_ok());
        assert!(validate_password("        ").is_ok());
        assert!(validate_password("correct horse battery staple").is_ok());
    }

    #[tokio::test]
    async fn production_parameters_follow_owasp() {
        let hasher = PasswordHasher::new().unwrap();
        let hash = hasher.hash("correct horse").await.unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "unexpected parameters in {hash}"
        );
        assert!(hasher.verify("correct horse", &hash).await.unwrap());
        assert!(!hasher.verify("wrong horse", &hash).await.unwrap());
        assert_eq!(hasher.limits(), HashLimits::default());
        assert_eq!(hasher.limits().max_concurrent, 8);
        assert_eq!(hasher.limits().max_wait, Duration::from_secs(2));
    }

    #[tokio::test]
    async fn hash_and_verify_round_trip() {
        let hasher = hasher(HashLimits::default());
        let first = hasher.hash("correct horse").await.unwrap();
        let second = hasher.hash("correct horse").await.unwrap();
        assert_ne!(first, second, "each hash gets its own salt");
        assert!(hasher.verify("correct horse", &first).await.unwrap());
        assert!(hasher.verify("correct horse", &second).await.unwrap());
        assert!(!hasher.verify("Correct horse", &first).await.unwrap());
        assert!(!hasher.verify("", &first).await.unwrap());
    }

    #[tokio::test]
    async fn hash_enforces_the_policy() {
        let hasher = hasher(HashLimits::default());
        assert!(matches!(
            hasher.hash("short").await,
            Err(LocalError::PasswordTooShort)
        ));
        assert!(matches!(
            hasher.hash(&"a".repeat(129)).await,
            Err(LocalError::PasswordTooLong)
        ));
    }

    #[tokio::test]
    async fn verify_rejects_oversized_passwords_and_malformed_hashes() {
        let hasher = hasher(HashLimits::default());
        let hash = hasher.hash("correct horse").await.unwrap();
        assert!(!hasher.verify(&"a".repeat(10_000), &hash).await.unwrap());

        let error = hasher.verify("correct horse", "not-a-hash").await;
        assert!(matches!(error, Err(LocalError::Internal(_))));
    }

    #[tokio::test]
    async fn dummy_verification_never_succeeds() {
        let hasher = hasher(HashLimits::default());
        assert!(!hasher.verify_dummy("anything at all").await.unwrap());
    }

    #[test]
    fn debug_output_has_no_hash_material() {
        let hasher = hasher(HashLimits::default());
        let debug = format!("{hasher:?}");
        assert!(!debug.contains("argon2id"), "{debug}");
    }

    #[tokio::test]
    async fn never_runs_more_than_the_limit_at_once() {
        let hasher = hasher(HashLimits::default().max_concurrent(3));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut pending = Vec::new();
        for _ in 0..24 {
            let running = Arc::clone(&running);
            let peak = Arc::clone(&peak);
            pending.push(
                hasher
                    .submit(move || {
                        let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(5));
                        running.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .unwrap(),
            );
        }
        for rx in pending {
            rx.await.unwrap().unwrap();
        }

        assert_eq!(peak.load(Ordering::SeqCst), 3);
        assert_eq!(running.load(Ordering::SeqCst), 0);
    }

    fn block_single_worker(
        hasher: &PasswordHasher,
    ) -> (mpsc::Sender<()>, oneshot::Receiver<Result<(), LocalError>>) {
        hasher.occupy_worker()
    }

    #[tokio::test]
    async fn request_that_waited_too_long_is_refused() {
        let limits = HashLimits::default()
            .max_concurrent(1)
            .max_wait(Duration::from_millis(20));
        let hasher = hasher(limits);
        let (release, blocked) = block_single_worker(&hasher);

        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_job = Arc::clone(&ran);
        let queued = hasher
            .submit(move || {
                ran_in_job.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();

        std::thread::sleep(Duration::from_millis(60));
        release.send(()).unwrap();

        blocked.await.unwrap().unwrap();
        assert!(matches!(queued.await.unwrap(), Err(LocalError::Busy)));
        assert_eq!(ran.load(Ordering::SeqCst), 0, "expired work must not run");

        // The hasher recovers once the backlog is gone.
        let hash = hasher.hash("correct horse").await.unwrap();
        assert!(hasher.verify("correct horse", &hash).await.unwrap());
    }

    #[tokio::test]
    async fn request_within_the_wait_limit_is_served() {
        let hasher = hasher(HashLimits::default().max_concurrent(1));
        let (release, blocked) = block_single_worker(&hasher);
        let queued = hasher.submit(|| Ok(7)).unwrap();

        release.send(()).unwrap();
        blocked.await.unwrap().unwrap();
        assert_eq!(queued.await.unwrap().unwrap(), 7);
    }

    #[tokio::test]
    async fn full_queue_is_refused_immediately() {
        let limits = HashLimits::default().max_concurrent(1).max_queued(1);
        let hasher = hasher(limits);
        let (release, blocked) = block_single_worker(&hasher);

        let queued = hasher.submit(|| Ok(())).unwrap();
        let overflow = hasher.submit(|| Ok(()));
        assert!(matches!(overflow, Err(LocalError::Busy)));
        assert!(matches!(
            hasher.verify("correct horse", "irrelevant").await,
            Err(LocalError::Busy)
        ));

        release.send(()).unwrap();
        blocked.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn abandoned_request_is_skipped() {
        let hasher = hasher(HashLimits::default().max_concurrent(1));
        let (release, blocked) = block_single_worker(&hasher);

        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_job = Arc::clone(&ran);
        let abandoned = hasher
            .submit(move || {
                ran_in_job.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        drop(abandoned);
        let last = hasher.submit(|| Ok(())).unwrap();

        release.send(()).unwrap();
        blocked.await.unwrap().unwrap();
        last.await.unwrap().unwrap();
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn panicking_work_is_reported_and_the_worker_survives() {
        let hasher = hasher(HashLimits::default().max_concurrent(1));
        let result: Result<(), LocalError> = hasher.run(|| panic!("boom")).await;
        assert!(matches!(result, Err(LocalError::Internal(_))));

        let hash = hasher.hash("correct horse").await.unwrap();
        assert!(hasher.verify("correct horse", &hash).await.unwrap());
    }
}
