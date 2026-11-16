//! Postgres storage for [`rusted-auth`](rusted_auth) with SeaORM.
//!
//! [`SeaOrmStore`] implements every storage trait of `rusted-auth` on one Postgres
//! database:
//!
//! | Trait | Tables |
//! |---|---|
//! | [`UserStore`](rusted_auth::session::UserStore) | `users` |
//! | [`SessionStore`](rusted_auth::session::SessionStore) | `sessions`, joined with `users` |
//! | [`OneTimeTokenStore`](rusted_auth::session::OneTimeTokenStore) | `one_time_tokens` |
//! | [`AttemptStore`](rusted_auth::session::AttemptStore) | `auth_attempts` |
//! | `MfaStore` (`mfa` feature) | `mfa_totp`, `mfa_recovery_codes` |
//! | [`EventSink`](rusted_auth::session::EventSink), through [`SeaOrmStore::event_sink`] | `auth_events` |
//!
//! The [`migration`] module creates the tables. [`SeaOrmStore::cleanup`] deletes what is
//! no longer needed; run it from a periodic job, since the library has no scheduler.
//!
//! ```rust,no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! use rusted_auth::session::SessionManager;
//! use rusted_auth_sea_orm::SeaOrmStore;
//! use rusted_auth_sea_orm::migration::Migrator;
//! use sea_orm_migration::MigratorTrait;
//!
//! let db = sea_orm::Database::connect("postgres://app@localhost/app").await?;
//! Migrator::up(&db, None).await?;
//!
//! let store = SeaOrmStore::new(db);
//! let (events, writer) = store.event_sink(10_000);
//! tokio::spawn(writer.run());
//! let sessions = SessionManager::builder(store.clone()).events(events).build();
//! // LocalAuth::builder(store.clone(), sessions).tokens(store.clone())
//! //     .attempts(store.clone()) ...
//! # let _ = sessions;
//! # Ok(())
//! # }
//! ```
//!
//! # Postgres only
//!
//! The statements use Postgres features (`citext`, `inet`, `ON CONFLICT`, `RETURNING`)
//! and are written by hand, so that each operation the traits require to be atomic is one
//! statement or one transaction. Other databases supported by SeaORM are not.
//!
//! The crate turns on SeaORM's `sqlx-postgres` and `runtime-tokio` features and no TLS
//! backend: enable `runtime-tokio-rustls` (or `-native-tls`) on your own `sea-orm`
//! dependency to connect over TLS.
//!
//! # Times
//!
//! Postgres stores times to the microsecond, so a [`SystemTime`](std::time::SystemTime)
//! read back can be up to a microsecond earlier than the one written. No decision in
//! `rusted-auth` depends on a difference that small.
//!
//! # Errors
//!
//! Database errors are returned as
//! [`StoreError::Backend`](rusted_auth::session::StoreError::Backend), whose message is
//! for logs only. A row for an account that does not exist (a foreign key violation)
//! is [`StoreError::NotFound`](rusted_auth::session::StoreError::NotFound).

#![cfg_attr(test, allow(clippy::unwrap_used))]

mod attempts;
mod cleanup;
mod convert;
mod events;
#[cfg(feature = "mfa")]
mod mfa;
pub mod migration;
mod session;
mod token;
mod user;

pub use cleanup::{CleanupReport, Retention};
pub use events::{AuthEventSink, AuthEventWriter, event_metadata};

use sea_orm::DatabaseConnection;

/// The storage traits of `rusted-auth` on a Postgres database. See the
/// [crate documentation](crate).
///
/// Clones share the connection pool, so give each builder its own clone.
#[derive(Debug, Clone)]
pub struct SeaOrmStore {
    db: DatabaseConnection,
}

impl SeaOrmStore {
    /// A store on `db`, whose tables were created with the [`migration`]s of this crate.
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// The connection, for queries of your own.
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }
}
