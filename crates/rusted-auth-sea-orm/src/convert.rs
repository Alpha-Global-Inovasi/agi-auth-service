//! Conversions between the types of `rusted-auth` and the values Postgres stores.

use chrono::{DateTime, Utc};
use rusted_auth::session::StoreError;
use sea_orm::{DbBackend, DbErr, QueryResult, SqlErr, Statement, TryGetable, Value};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// A Postgres statement with `$1`, `$2`, … placeholders.
pub(crate) fn statement<I>(sql: &str, values: I) -> Statement
where
    I: IntoIterator<Item = Value>,
{
    Statement::from_sql_and_values(DbBackend::Postgres, sql, values)
}

/// A database error, for logs only.
pub(crate) fn backend(error: DbErr) -> StoreError {
    StoreError::backend(error)
}

/// `true` for a foreign key violation, such as a row for an account that does not exist.
pub(crate) fn is_foreign_key_violation(error: &DbErr) -> bool {
    matches!(
        error.sql_err(),
        Some(SqlErr::ForeignKeyConstraintViolation(_))
    )
}

/// A time for a `timestamptz` column. Postgres keeps microseconds, so the nanoseconds
/// below that are dropped.
pub(crate) fn timestamp(time: SystemTime) -> Result<DateTime<Utc>, StoreError> {
    let converted = match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_secs())
            .ok()
            .and_then(|secs| DateTime::from_timestamp(secs, after.subsec_nanos())),
        Err(before) => {
            let before = before.duration();
            i64::try_from(before.as_secs()).ok().and_then(|secs| {
                // Round towards the past, keeping the nanoseconds non-negative.
                let (secs, nanos) = match before.subsec_nanos() {
                    0 => (-secs, 0),
                    nanos => (-secs - 1, 1_000_000_000 - nanos),
                };
                DateTime::from_timestamp(secs, nanos)
            })
        }
    };
    converted.ok_or_else(|| StoreError::backend(format!("time {time:?} cannot be stored")))
}

/// The [`SystemTime`] of a stored `timestamptz`.
pub(crate) fn system_time(time: DateTime<Utc>) -> SystemTime {
    let nanos = time.timestamp_subsec_nanos();
    match u64::try_from(time.timestamp()) {
        Ok(secs) => SystemTime::UNIX_EPOCH + Duration::new(secs, nanos),
        Err(_) => {
            let secs = time.timestamp().unsigned_abs();
            SystemTime::UNIX_EPOCH - Duration::from_secs(secs) + Duration::from_nanos(nanos.into())
        }
    }
}

/// Read column `column` of `row`.
pub(crate) fn get<T: TryGetable>(row: &QueryResult, column: &str) -> Result<T, StoreError> {
    row.try_get("", column).map_err(backend)
}

/// Read a `timestamptz` column.
pub(crate) fn get_time(row: &QueryResult, column: &str) -> Result<SystemTime, StoreError> {
    get::<DateTime<Utc>>(row, column).map(system_time)
}

/// Read a nullable `timestamptz` column.
pub(crate) fn get_optional_time(
    row: &QueryResult,
    column: &str,
) -> Result<Option<SystemTime>, StoreError> {
    Ok(get::<Option<DateTime<Utc>>>(row, column)?.map(system_time))
}

/// Read a `bytea` column that holds a 32-byte hash.
pub(crate) fn get_hash(row: &QueryResult, column: &str) -> Result<[u8; 32], StoreError> {
    let bytes: Vec<u8> = get(row, column)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| StoreError::backend(format!("{column} is not 32 bytes long")))
}

/// Read a nullable column with the text of an `inet` value.
pub(crate) fn get_ip(row: &QueryResult, column: &str) -> Result<Option<IpAddr>, StoreError> {
    get::<Option<String>>(row, column)?
        .map(|text| {
            text.parse()
                .map_err(|_| StoreError::backend(format!("{column} is not an address")))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_round_trip_to_the_microsecond() {
        let exact = SystemTime::UNIX_EPOCH + Duration::new(1_800_000_000, 123_456_000);
        assert_eq!(system_time(timestamp(exact).unwrap()), exact);
        let before = SystemTime::UNIX_EPOCH - Duration::new(10, 250_000_000);
        assert_eq!(system_time(timestamp(before).unwrap()), before);
        assert_eq!(
            system_time(timestamp(SystemTime::UNIX_EPOCH).unwrap()),
            SystemTime::UNIX_EPOCH
        );
    }

    #[test]
    fn unrepresentable_times_are_errors() {
        // Beyond chrono's range (about 262 000 years). Some platforms cannot even hold
        // such a `SystemTime`; there is nothing to check then.
        if let Some(far) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(1 << 45)) {
            assert!(timestamp(far).is_err());
        }
    }
}
