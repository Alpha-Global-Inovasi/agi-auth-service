//! Migrations for the tables of `rusted-auth`.
//!
//! Add [`migrations`] to the application's own migrator, so that one `seaql_migrations`
//! table records everything:
//!
//! ```rust
//! use sea_orm_migration::prelude::*;
//!
//! pub struct Migrator;
//!
//! impl MigratorTrait for Migrator {
//!     fn migrations() -> Vec<Box<dyn MigrationTrait>> {
//!         let mut migrations = rusted_auth_sea_orm::migration::migrations();
//!         // migrations.push(Box::new(m20270101_000001_create_posts::Migration));
//!         migrations
//!     }
//! }
//! ```
//!
//! Put them first: the application's tables may refer to `users`. Their names start with
//! `m20261115_` followed by `rusted_auth_`, so they sort before the application's later
//! migrations and do not collide with them. Later versions of `rusted-auth-sea-orm`
//! append migrations to the list; never remove one that has run.
//!
//! An application without migrations of its own can run [`Migrator`] instead, which
//! records its migrations in a separate `rusted_auth_migrations` table.
//!
//! # Requirements
//!
//! - Postgres 13 or newer.
//! - The `citext` extension. The first migration creates it if it is missing, which
//!   needs the `CREATE` privilege on the database (the database owner has it). Where
//!   the migrating role does not, create it once beforehand:
//!   `CREATE EXTENSION IF NOT EXISTS citext;`
//!
//! # Tables
//!
//! | Table | Holds |
//! |---|---|
//! | `users` | Accounts: `username` and `email` are unique ignoring case (`citext`) |
//! | `sessions` | Sessions, with the SHA-256 hash of their token |
//! | `one_time_tokens` | Single-use tokens of email links, with the address they were sent to |
//! | `mfa_totp` | One TOTP authenticator per account, its secret encrypted |
//! | `mfa_recovery_codes` | Keyed hashes (HMAC-SHA-256) of recovery codes |
//! | `auth_attempts` | Counters of failed attempts, keyed by `(scope, key)` |
//! | `auth_events` | The audit log |
//!
//! Rows of the other tables are deleted with their account (`ON DELETE CASCADE`), except
//! `auth_attempts`, which is keyed by more than accounts, and `auth_events`, which keeps
//! the identifier of a deleted account. Delete those rows yourself when an account must
//! leave no trace.

use sea_orm_migration::prelude::*;

mod m20261115_000001_create_auth_tables;

/// The migrations of this crate, oldest first. See the [module documentation](self).
pub fn migrations() -> Vec<Box<dyn MigrationTrait>> {
    vec![Box::new(m20261115_000001_create_auth_tables::Migration)]
}

/// A migrator with only the migrations of this crate, recorded in the
/// `rusted_auth_migrations` table.
///
/// ```rust,no_run
/// # async fn run(db: &sea_orm::DatabaseConnection) -> Result<(), sea_orm::DbErr> {
/// use rusted_auth_sea_orm::migration::Migrator;
/// use sea_orm_migration::MigratorTrait;
///
/// Migrator::up(db, None).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Migrator;

impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        migrations()
    }

    fn migration_table_name() -> DynIden {
        "rusted_auth_migrations".into_iden()
    }
}
