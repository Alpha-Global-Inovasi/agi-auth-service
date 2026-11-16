//! The tables of `rusted-auth` 0.5.

use sea_orm_migration::prelude::*;

/// Creates `users`, `sessions`, `one_time_tokens`, `mfa_totp`, `mfa_recovery_codes`,
/// `auth_attempts` and `auth_events`, and the `citext` extension if it is missing.
pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20261115_000001_rusted_auth_create_auth_tables"
    }
}

const UP: &str = r#"
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id uuid PRIMARY KEY,
    username citext NOT NULL,
    email citext NOT NULL,
    email_verified_at timestamptz,
    name text NOT NULL,
    password_hash text,
    failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until timestamptz,
    disabled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_username_key UNIQUE (username),
    CONSTRAINT users_email_key UNIQUE (email)
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('web', 'mobile')),
    state text NOT NULL CHECK (state IN ('pending_mfa', 'active')),
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    ip inet,
    user_agent text,
    revoked_at timestamptz,
    idp_sid text,
    idp_refresh_token_enc bytea,
    CONSTRAINT sessions_token_hash_key UNIQUE (token_hash)
);
CREATE INDEX sessions_user_id_created_at_idx ON sessions (user_id, created_at DESC);
CREATE INDEX sessions_idle_expires_at_idx ON sessions (idle_expires_at);
CREATE INDEX sessions_revoked_at_idx ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;

CREATE TABLE one_time_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose text NOT NULL,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX one_time_tokens_unused_idx ON one_time_tokens (user_id, purpose)
    WHERE used_at IS NULL;
CREATE INDEX one_time_tokens_expires_at_idx ON one_time_tokens (expires_at);

CREATE TABLE mfa_totp (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret_enc bytea NOT NULL,
    confirmed_at timestamptz,
    last_used_step bigint CHECK (last_used_step >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mfa_recovery_codes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mfa_recovery_codes_user_id_code_hash_idx
    ON mfa_recovery_codes (user_id, code_hash);

CREATE TABLE auth_attempts (
    scope text NOT NULL,
    key uuid NOT NULL,
    count integer NOT NULL CHECK (count >= 0),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (scope, key)
);
CREATE INDEX auth_attempts_expires_at_idx ON auth_attempts (expires_at);

CREATE TABLE auth_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id uuid,
    event text NOT NULL,
    ip inet,
    user_agent text,
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL
);
CREATE INDEX auth_events_user_id_created_at_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX auth_events_created_at_idx ON auth_events (created_at);
"#;

// The extension stays: other tables of the application may use it.
const DOWN: &str = r#"
DROP TABLE auth_events;
DROP TABLE auth_attempts;
DROP TABLE mfa_recovery_codes;
DROP TABLE mfa_totp;
DROP TABLE one_time_tokens;
DROP TABLE sessions;
DROP TABLE users;
"#;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(UP).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.get_connection().execute_unprepared(DOWN).await?;
        Ok(())
    }
}
