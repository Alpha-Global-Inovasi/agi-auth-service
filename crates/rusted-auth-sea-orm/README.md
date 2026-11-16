# rusted-auth-sea-orm

Postgres storage for [`rusted-auth`](https://crates.io/crates/rusted-auth) with SeaORM:
accounts, sessions, second factors, single-use tokens, attempt counters and the audit log.

`SeaOrmStore` implements `UserStore`, `SessionStore`, `OneTimeTokenStore`, `AttemptStore`
and (with the `mfa` feature) `MfaStore`, and records audit events in `auth_events` through
a non-blocking `EventSink`. The `migration` module creates the tables.

```toml
[dependencies]
rusted-auth = { version = "0.5", features = ["local"] }
rusted-auth-sea-orm = "0.5"
sea-orm = { version = "2.0", features = ["sqlx-postgres", "runtime-tokio-rustls"] }
```

```rust,no_run
use rusted_auth::session::SessionManager;
use rusted_auth_sea_orm::SeaOrmStore;
use rusted_auth_sea_orm::migration::Migrator;
use sea_orm_migration::MigratorTrait;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = sea_orm::Database::connect("postgres://app@localhost/app").await?;
    Migrator::up(&db, None).await?;

    let store = SeaOrmStore::new(db);
    let (events, writer) = store.event_sink(10_000);
    tokio::spawn(writer.run());
    let sessions = SessionManager::builder(store.clone()).events(events).build();
    // LocalAuth::builder(store.clone(), sessions).tokens(store.clone())...
    Ok(())
}
```

An application with migrations of its own adds `rusted_auth_sea_orm::migration::migrations()`
to its migrator instead of running `Migrator`.

## Requirements

- Postgres 13 or newer, with the `citext` extension (the first migration creates it when
  the migrating role may).
- Rust 1.94 or newer (SeaORM 2.0 needs it).

The crate enables no TLS backend for the database connection: choose one on your own
`sea-orm` dependency.

## Cleanup

The library has no scheduler. Run `SeaOrmStore::cleanup` from a periodic job to delete
ended sessions, used and expired tokens, ended attempt counters, and audit events older
than a year (`Retention` changes these periods).

## Tests

The integration tests run against a real database when `RUSTED_AUTH_TEST_DATABASE_URL`
is set, and pass without doing anything otherwise:

```bash
docker run -d --name rusted-auth-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:17
RUSTED_AUTH_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test -p rusted-auth-sea-orm --all-features
```

## License

MIT or Apache-2.0, at your option.
