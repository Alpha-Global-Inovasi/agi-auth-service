//! The `auth_events` audit log.

use crate::SeaOrmStore;
use crate::convert::{backend, statement, timestamp};
use chrono::{DateTime, SecondsFormat, Utc};
use rusted_auth::session::{AuthEvent, AuthEventKind, EventSink, StoreError};
use sea_orm::{ConnectionTrait, Value};
use serde_json::{Map, Value as Json, json};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// Most events written by one `INSERT`.
const BATCH: usize = 256;

/// The variant's fields, as the `metadata` column holds them.
///
/// Identifiers are strings, times are RFC 3339 strings in UTC, and enumerations use their
/// snake_case names. A variant added to `rusted-auth` later and not known here is
/// stored with empty metadata; its name is still recorded.
pub fn event_metadata(kind: &AuthEventKind) -> Json {
    let rfc3339 = |time: SystemTime| {
        crate::convert::timestamp(time)
            .map(|t: DateTime<Utc>| t.to_rfc3339_opts(SecondsFormat::Micros, true))
            .ok()
    };
    match kind {
        AuthEventKind::LoginSucceeded {
            session_id,
            mfa_required,
        } => json!({ "session_id": session_id.to_string(), "mfa_required": mfa_required }),
        AuthEventKind::LoginFailed { reason } => json!({ "reason": reason.name() }),
        AuthEventKind::AccountLocked {
            until,
            failed_logins,
        } => json!({ "until": rfc3339(*until), "failed_logins": failed_logins }),
        AuthEventKind::SessionCreated {
            session_id,
            kind,
            state,
        } => json!({
            "session_id": session_id.to_string(),
            "kind": kind.as_str(),
            "state": state.as_str(),
        }),
        AuthEventKind::SessionActivated {
            session_id,
            previous_session_id,
        } => json!({
            "session_id": session_id.to_string(),
            "previous_session_id": previous_session_id.to_string(),
        }),
        AuthEventKind::SessionRevoked { session_id } => {
            json!({ "session_id": session_id.to_string() })
        }
        AuthEventKind::MfaSucceeded { session_id, method } => {
            json!({ "session_id": session_id.to_string(), "method": method.name() })
        }
        AuthEventKind::MfaFailed {
            session_id,
            method,
            reason,
            attempts,
        } => json!({
            "session_id": session_id.map(|id| id.to_string()),
            "method": method.map(|m| m.name()),
            "reason": reason.name(),
            "attempts": attempts,
        }),
        AuthEventKind::MfaAttemptsExceeded {
            session_id,
            attempts,
        } => json!({
            "session_id": session_id.map(|id| id.to_string()),
            "attempts": attempts,
        }),
        AuthEventKind::RecoveryCodesGenerated { count } => json!({ "count": count }),
        AuthEventKind::PasswordChanged { session_id } => {
            json!({ "session_id": session_id.to_string() })
        }
        AuthEventKind::EmailSendFailed { email } | AuthEventKind::EmailThrottled { email } => {
            json!({ "email": email.name() })
        }
        _ => Json::Object(Map::new()),
    }
}

impl SeaOrmStore {
    /// Write events to `auth_events` with one statement.
    ///
    /// [`event_sink`](Self::event_sink) calls this from its writer. Call it directly to
    /// write events from a job queue of your own.
    pub async fn insert_events(&self, events: &[AuthEvent]) -> Result<(), StoreError> {
        for batch in events.chunks(BATCH) {
            let mut rows = Vec::with_capacity(batch.len());
            let mut values: Vec<Value> = Vec::with_capacity(batch.len() * 6);
            for (i, event) in batch.iter().enumerate() {
                let n = i * 6;
                rows.push(format!(
                    "(${}, ${}, ${}::inet, ${}, ${}::jsonb, ${})",
                    n + 1,
                    n + 2,
                    n + 3,
                    n + 4,
                    n + 5,
                    n + 6
                ));
                values.push(event.user_id.into());
                values.push(event.kind.name().into());
                values.push(event.ip.map(|ip| ip.to_string()).into());
                values.push(event.user_agent.clone().into());
                values.push(event_metadata(&event.kind).into());
                values.push(timestamp(event.at)?.into());
            }
            let sql = format!(
                "INSERT INTO auth_events (user_id, event, ip, user_agent, metadata, created_at) \
                 VALUES {}",
                rows.join(", ")
            );
            self.db
                .execute_raw(statement(&sql, values))
                .await
                .map_err(backend)?;
        }
        Ok(())
    }

    /// An [`EventSink`] that records audit events in `auth_events`, and the writer that
    /// does the writing.
    ///
    /// [`EventSink`] methods must not block, so the sink only puts events in a queue of
    /// `capacity` events; spawn [`AuthEventWriter::run`] on the runtime to write them.
    /// When the queue is full, for example because the database is unreachable, further
    /// events are dropped and logged rather than slowing logins down;
    /// [`AuthEventSink::dropped`] counts them.
    ///
    /// ```rust,no_run
    /// # async fn run(db: sea_orm::DatabaseConnection) {
    /// use rusted_auth::session::SessionManager;
    /// use rusted_auth_sea_orm::SeaOrmStore;
    ///
    /// let store = SeaOrmStore::new(db);
    /// let (sink, writer) = store.event_sink(10_000);
    /// tokio::spawn(writer.run());
    /// let sessions = SessionManager::builder(store.clone()).events(sink).build();
    /// # }
    /// ```
    pub fn event_sink(&self, capacity: usize) -> (AuthEventSink, AuthEventWriter) {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        (
            AuthEventSink {
                sender,
                dropped: Arc::clone(&dropped),
            },
            AuthEventWriter {
                store: self.clone(),
                receiver,
            },
        )
    }
}

/// The [`EventSink`] made by [`SeaOrmStore::event_sink`]. Clones share the queue.
#[derive(Clone)]
pub struct AuthEventSink {
    sender: mpsc::Sender<AuthEvent>,
    dropped: Arc<AtomicU64>,
}

impl AuthEventSink {
    /// Events dropped so far because the queue was full or the writer had stopped.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl fmt::Debug for AuthEventSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthEventSink")
            .field(
                "queued",
                &(self.sender.max_capacity() - self.sender.capacity()),
            )
            .field("dropped", &self.dropped())
            .finish()
    }
}

impl EventSink for AuthEventSink {
    fn auth_event(&self, event: &AuthEvent) {
        if self.sender.try_send(event.clone()).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            // Log the first drop and then every thousandth, not each one.
            if dropped == 1 || dropped.is_multiple_of(1000) {
                tracing::warn!(
                    event = event.kind.name(),
                    dropped,
                    "auth event queue is full or closed; dropping audit events"
                );
            }
        }
    }
}

/// Writes the events queued by an [`AuthEventSink`]. See [`SeaOrmStore::event_sink`].
pub struct AuthEventWriter {
    store: SeaOrmStore,
    receiver: mpsc::Receiver<AuthEvent>,
}

impl fmt::Debug for AuthEventWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthEventWriter").finish_non_exhaustive()
    }
}

impl AuthEventWriter {
    /// Write queued events until every [`AuthEventSink`] clone is dropped and the queue
    /// is empty.
    ///
    /// Events are written in batches of what has queued up. A batch the database
    /// refuses is logged and dropped; the writer goes on with the next one.
    pub async fn run(mut self) {
        let mut batch = Vec::with_capacity(BATCH);
        while self.receiver.recv_many(&mut batch, BATCH).await > 0 {
            if let Err(error) = self.store.insert_events(&batch).await {
                tracing::error!(%error, events = batch.len(), "failed to write auth events");
            }
            batch.clear();
        }
    }
}
