//! [`SessionStore`] on the `sessions` table.

use crate::SeaOrmStore;
use crate::convert::{
    backend, get, get_hash, get_ip, get_optional_time, get_time, is_foreign_key_violation,
    statement, timestamp,
};
use crate::user::{user_columns, user_from_row};
use rusted_auth::session::{
    NewSession, Session, SessionKind, SessionRecord, SessionState, SessionStore, SessionTokenHash,
    StoreError, Uuid,
};
use sea_orm::{ConnectionTrait, DbErr, QueryResult, Value};
use std::time::SystemTime;

/// The session columns [`session_from_row`] reads. The address is read as text.
const SESSION_COLUMNS: &str = "sessions.id, sessions.user_id, sessions.kind, sessions.state, \
     sessions.created_at, sessions.last_seen_at, sessions.idle_expires_at, \
     sessions.absolute_expires_at, host(sessions.ip) AS ip, sessions.user_agent, \
     sessions.revoked_at, sessions.idp_sid";

/// Columns and values of an `INSERT INTO sessions`, as `$1` to `$11`.
const INSERT_COLUMNS: &str = "id, token_hash, user_id, kind, state, created_at, last_seen_at, \
     idle_expires_at, absolute_expires_at, ip, user_agent, idp_sid";
const INSERT_VALUES: &str = "$1, $2, $3, $4, $5, $6, $6, $7, $8, $9::inet, $10, $11";

fn insert_values(session: NewSession) -> Result<Vec<Value>, StoreError> {
    Ok(vec![
        Uuid::new_v4().into(),
        session.token_hash.as_bytes().to_vec().into(),
        session.user_id.into(),
        session.kind.as_str().into(),
        session.state.as_str().into(),
        timestamp(session.created_at)?.into(),
        timestamp(session.idle_expires_at)?.into(),
        timestamp(session.absolute_expires_at)?.into(),
        session.ip.map(|ip| ip.to_string()).into(),
        session.user_agent.into(),
        session.idp_sid.into(),
    ])
}

fn session_from_row(row: &QueryResult) -> Result<Session, StoreError> {
    let kind: String = get(row, "kind")?;
    let state: String = get(row, "state")?;
    Ok(Session {
        id: get(row, "id")?,
        user_id: get(row, "user_id")?,
        kind: SessionKind::parse(&kind)
            .ok_or_else(|| StoreError::backend(format!("unknown session kind {kind:?}")))?,
        state: SessionState::parse(&state)
            .ok_or_else(|| StoreError::backend(format!("unknown session state {state:?}")))?,
        created_at: get_time(row, "created_at")?,
        last_seen_at: get_time(row, "last_seen_at")?,
        idle_expires_at: get_time(row, "idle_expires_at")?,
        absolute_expires_at: get_time(row, "absolute_expires_at")?,
        ip: get_ip(row, "ip")?,
        user_agent: get(row, "user_agent")?,
        revoked_at: get_optional_time(row, "revoked_at")?,
        idp_sid: get(row, "idp_sid")?,
    })
}

/// A missing account shows up as a foreign key violation.
fn insert_error(error: DbErr) -> StoreError {
    if is_foreign_key_violation(&error) {
        StoreError::NotFound
    } else {
        backend(error)
    }
}

impl SessionStore for SeaOrmStore {
    async fn insert(&self, session: NewSession) -> Result<Session, StoreError> {
        let sql = format!(
            "INSERT INTO sessions ({INSERT_COLUMNS}) VALUES ({INSERT_VALUES}) \
             RETURNING {SESSION_COLUMNS}"
        );
        let row = self
            .db
            .query_one_raw(statement(&sql, insert_values(session)?))
            .await
            .map_err(insert_error)?
            .ok_or_else(|| StoreError::backend("INSERT returned no row"))?;
        session_from_row(&row)
    }

    async fn find_by_token_hash(
        &self,
        token_hash: &SessionTokenHash,
    ) -> Result<Option<SessionRecord>, StoreError> {
        let sql = format!(
            "SELECT {SESSION_COLUMNS}, sessions.token_hash, {} \
             FROM sessions JOIN users ON users.id = sessions.user_id \
             WHERE sessions.token_hash = $1",
            user_columns("users", "account_")
        );
        let row = self
            .db
            .query_one_raw(statement(&sql, [token_hash.as_bytes().to_vec().into()]))
            .await
            .map_err(backend)?;
        row.map(|row| {
            Ok(SessionRecord {
                session: session_from_row(&row)?,
                token_hash: SessionTokenHash::from_bytes(get_hash(&row, "token_hash")?),
                user: user_from_row(&row, "account_")?,
            })
        })
        .transpose()
    }

    async fn touch(
        &self,
        id: Uuid,
        last_seen_at: SystemTime,
        idle_expires_at: SystemTime,
    ) -> Result<(), StoreError> {
        let result = self
            .db
            .execute_raw(statement(
                "UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id = $1",
                [
                    id.into(),
                    timestamp(last_seen_at)?.into(),
                    timestamp(idle_expires_at)?.into(),
                ],
            ))
            .await
            .map_err(backend)?;
        if result.rows_affected() == 0 {
            Err(StoreError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn activate(
        &self,
        pending_id: Uuid,
        replacement: NewSession,
        now: SystemTime,
    ) -> Result<Option<Session>, StoreError> {
        // One statement: the UPDATE locks the pending row, so of two concurrent calls the
        // second sees it revoked and inserts nothing.
        let sql = format!(
            "WITH pending AS ( \
                 UPDATE sessions SET revoked_at = $12 \
                 WHERE id = $13 AND state = 'pending_mfa' AND revoked_at IS NULL \
                   AND absolute_expires_at > $12 \
                 RETURNING id) \
             INSERT INTO sessions ({INSERT_COLUMNS}) \
             SELECT {INSERT_VALUES} WHERE EXISTS (SELECT 1 FROM pending) \
             RETURNING {SESSION_COLUMNS}"
        );
        let mut values = insert_values(replacement)?;
        values.push(timestamp(now)?.into());
        values.push(pending_id.into());
        let row = self
            .db
            .query_one_raw(statement(&sql, values))
            .await
            .map_err(insert_error)?;
        row.as_ref().map(session_from_row).transpose()
    }

    async fn revoke(
        &self,
        id: Uuid,
        owner: Option<Uuid>,
        at: SystemTime,
    ) -> Result<Option<Session>, StoreError> {
        let sql = format!(
            "UPDATE sessions SET revoked_at = $3 \
             WHERE id = $1 AND ($2::uuid IS NULL OR user_id = $2) AND revoked_at IS NULL \
             RETURNING {SESSION_COLUMNS}"
        );
        let row = self
            .db
            .query_one_raw(statement(
                &sql,
                [id.into(), owner.into(), timestamp(at)?.into()],
            ))
            .await
            .map_err(backend)?;
        row.as_ref().map(session_from_row).transpose()
    }

    async fn revoke_all_for_user(
        &self,
        user_id: Uuid,
        except: Option<Uuid>,
        at: SystemTime,
    ) -> Result<Vec<Uuid>, StoreError> {
        let rows = self
            .db
            .query_all_raw(statement(
                "UPDATE sessions SET revoked_at = $3 \
                 WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2) \
                 RETURNING id",
                [user_id.into(), except.into(), timestamp(at)?.into()],
            ))
            .await
            .map_err(backend)?;
        rows.iter().map(|row| get(row, "id")).collect()
    }

    async fn list_active_for_user(
        &self,
        user_id: Uuid,
        now: SystemTime,
    ) -> Result<Vec<Session>, StoreError> {
        let sql = format!(
            "SELECT {SESSION_COLUMNS} FROM sessions \
             WHERE user_id = $1 AND state = 'active' AND revoked_at IS NULL \
               AND idle_expires_at > $2 AND absolute_expires_at > $2 \
             ORDER BY created_at DESC, id DESC"
        );
        let rows = self
            .db
            .query_all_raw(statement(&sql, [user_id.into(), timestamp(now)?.into()]))
            .await
            .map_err(backend)?;
        rows.iter().map(session_from_row).collect()
    }
}
