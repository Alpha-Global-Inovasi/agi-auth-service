//! Tests against a real Postgres database.
//!
//! Set `RUSTED_AUTH_TEST_DATABASE_URL` to a database in which the tests may create
//! schemas, for example `postgres://postgres:postgres@localhost:5432/postgres`. Each test
//! migrates a schema of its own and drops it at the end. Without the variable the tests
//! pass without doing anything, so that `cargo test` works on machines without Postgres;
//! CI also sets `RUSTED_AUTH_REQUIRE_DATABASE=1`, which makes a missing URL fail instead.

#![allow(clippy::unwrap_used)]

use rusted_auth::local::{
    HashLimits, LocalAuth, LocalAuthBuilder, PasswordHasher, RecordingMailer, Registration,
};
use rusted_auth::session::{SessionContext, SessionManager, conformance};
use rusted_auth_sea_orm::migration::Migrator;
use rusted_auth_sea_orm::{CleanupReport, Retention, SeaOrmStore};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement};
use sea_orm_migration::MigratorTrait;
use std::time::{Duration, SystemTime};
use tokio::sync::OnceCell;
use uuid::Uuid;

/// A migrated schema for one test.
struct TestDb {
    url: String,
    schema: String,
    store: SeaOrmStore,
}

static CITEXT: OnceCell<()> = OnceCell::const_new();

fn database_url() -> Option<String> {
    match std::env::var("RUSTED_AUTH_TEST_DATABASE_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            assert!(
                std::env::var_os("RUSTED_AUTH_REQUIRE_DATABASE").is_none(),
                "RUSTED_AUTH_REQUIRE_DATABASE is set but RUSTED_AUTH_TEST_DATABASE_URL is not"
            );
            eprintln!("RUSTED_AUTH_TEST_DATABASE_URL is not set; skipping");
            None
        }
    }
}

async fn execute(db: &DatabaseConnection, sql: &str) {
    db.execute_unprepared(sql).await.unwrap();
}

impl TestDb {
    async fn new() -> Option<Self> {
        let url = database_url()?;
        let admin = Database::connect(&url).await.unwrap();
        // Created once, in `public`, before the tests migrate their schemas side by side:
        // two concurrent `CREATE EXTENSION IF NOT EXISTS` can collide.
        CITEXT
            .get_or_init(|| async {
                execute(
                    &admin,
                    "CREATE EXTENSION IF NOT EXISTS citext SCHEMA public",
                )
                .await;
            })
            .await;
        let schema = format!("rusted_auth_test_{}", Uuid::new_v4().simple());
        execute(&admin, &format!("CREATE SCHEMA {schema}")).await;
        admin.close().await.unwrap();

        let mut options = ConnectOptions::new(&url);
        options
            .max_connections(16)
            .set_schema_search_path(format!("{schema},public"))
            .sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        Some(Self {
            url,
            schema,
            store: SeaOrmStore::new(db),
        })
    }

    fn db(&self) -> &DatabaseConnection {
        self.store.connection()
    }

    async fn execute(&self, sql: &str) {
        execute(self.db(), sql).await;
    }

    async fn texts(&self, sql: &str) -> Vec<String> {
        let rows = self
            .db()
            .query_all_raw(Statement::from_string(
                self.db().get_database_backend(),
                sql,
            ))
            .await
            .unwrap();
        rows.iter()
            .map(|row| row.try_get_by_index(0).unwrap())
            .collect()
    }

    async fn count(&self, table: &str) -> i64 {
        let sql = format!("SELECT count(*) FROM {table}");
        let row = self
            .db()
            .query_one_raw(Statement::from_string(
                self.db().get_database_backend(),
                sql,
            ))
            .await
            .unwrap()
            .unwrap();
        row.try_get_by_index(0).unwrap()
    }

    async fn drop_schema(self) {
        let Self { url, schema, store } = self;
        store.connection().clone().close().await.unwrap();
        let admin = Database::connect(&url).await.unwrap();
        execute(&admin, &format!("DROP SCHEMA {schema} CASCADE")).await;
        admin.close().await.unwrap();
    }
}

/// Run `body` against a fresh schema, or do nothing without a database.
macro_rules! with_db {
    (|$db:ident| $body:expr) => {{
        let Some($db) = TestDb::new().await else {
            return;
        };
        $body;
        $db.drop_schema().await;
    }};
}

#[tokio::test]
async fn user_store_conforms() {
    with_db!(|db| conformance::user_store(&db.store).await);
}

#[tokio::test]
async fn session_store_conforms() {
    with_db!(|db| conformance::session_store(&db.store, &db.store).await);
}

#[tokio::test]
async fn one_time_token_store_conforms() {
    with_db!(|db| conformance::one_time_token_store(&db.store, &db.store).await);
}

#[tokio::test]
async fn attempt_store_conforms() {
    with_db!(|db| conformance::attempt_store(&db.store).await);
}

#[cfg(feature = "mfa")]
#[tokio::test]
async fn mfa_store_conforms() {
    with_db!(|db| rusted_auth::mfa::conformance::mfa_store(&db.store, &db.store).await);
}

#[tokio::test]
async fn migrations_go_down_and_up_again() {
    with_db!(|db| {
        Migrator::down(db.db(), None).await.unwrap();
        let tables = db
            .texts(&format!(
                "SELECT table_name::text FROM information_schema.tables \
                 WHERE table_schema = '{}' ORDER BY table_name",
                db.schema
            ))
            .await;
        assert_eq!(tables, vec!["rusted_auth_migrations"]);
        Migrator::up(db.db(), None).await.unwrap();
        conformance::user_store(&db.store).await;
    });
}

#[tokio::test]
async fn cleanup_deletes_what_ended() {
    with_db!(|db| {
        let user = Uuid::new_v4();
        db.execute(&format!(
            "INSERT INTO users (id, username, email, name) \
             VALUES ('{user}', 'cleanup', 'cleanup@example.com', 'Cleanup')"
        ))
        .await;
        // Times relative to `now()` of the database; the cleanup below runs with the
        // same clock.
        let session = |hash: u8, idle: &str, revoked: &str| {
            format!(
                "INSERT INTO sessions (id, token_hash, user_id, kind, state, created_at, \
                     last_seen_at, idle_expires_at, absolute_expires_at, revoked_at) \
                 VALUES (gen_random_uuid(), decode(repeat('{hash:02x}', 32), 'hex'), '{user}', \
                     'web', 'active', now() - interval '2 days', now() - interval '2 days', \
                     now() + interval '{idle}', now() + interval '30 days', {revoked})"
            )
        };
        db.execute(&session(1, "-1 hour", "NULL")).await; // idle too long
        db.execute(&session(2, "1 hour", "now() - interval '1 hour'"))
            .await; // revoked
        db.execute(&session(3, "1 hour", "NULL")).await; // usable
        let token = |hash: u8, expires: &str, used: &str| {
            format!(
                "INSERT INTO one_time_tokens (token_hash, user_id, purpose, email, expires_at, \
                     used_at) \
                 VALUES (decode(repeat('{hash:02x}', 32), 'hex'), '{user}', 'verify_email', \
                     'cleanup@example.com', now() + interval '{expires}', {used})"
            )
        };
        db.execute(&token(1, "-1 minute", "NULL")).await; // expired
        db.execute(&token(2, "1 hour", "now() - interval '1 minute'"))
            .await; // used
        db.execute(&token(3, "1 hour", "NULL")).await; // usable
        db.execute(&format!(
            "INSERT INTO auth_attempts (scope, key, count, expires_at) VALUES \
             ('email', '{}', 1, now() - interval '1 second'), \
             ('email', '{}', 1, now() + interval '5 minutes')",
            Uuid::new_v4(),
            Uuid::new_v4()
        ))
        .await;
        db.execute(&format!(
            "INSERT INTO auth_events (user_id, event, created_at) VALUES \
             ('{user}', 'login_failed', now() - interval '400 days'), \
             ('{user}', 'login_failed', now() - interval '1 day')"
        ))
        .await;

        let now = SystemTime::now();
        // Ended sessions can be kept for a while.
        let kept = db
            .store
            .cleanup(
                now,
                Retention::default().sessions(Duration::from_secs(86_400)),
            )
            .await
            .unwrap();
        assert_eq!(kept.sessions, 0);
        assert_eq!(kept.one_time_tokens, 2);
        assert_eq!(kept.attempts, 1);
        assert_eq!(kept.events, 1);

        let report = db.store.cleanup(now, Retention::default()).await.unwrap();
        assert_eq!(report.sessions, 2);
        assert_eq!(
            report.one_time_tokens, 0,
            "already deleted by the first run"
        );
        for (table, left) in [
            ("sessions", 1),
            ("one_time_tokens", 1),
            ("auth_attempts", 1),
            ("auth_events", 1),
        ] {
            assert_eq!(db.count(table).await, left, "{table}");
        }
        assert_eq!(
            db.store.cleanup(now, Retention::default()).await.unwrap(),
            CleanupReport::default()
        );
    });
}

fn local_auth(
    store: &SeaOrmStore,
    sessions: SessionManager<SeaOrmStore>,
) -> LocalAuthBuilder<SeaOrmStore, SeaOrmStore> {
    LocalAuth::builder(store.clone(), sessions)
        .tokens(store.clone())
        .attempts(store.clone())
        .hasher(PasswordHasher::insecure_for_tests(HashLimits::default()).unwrap())
}

#[tokio::test]
async fn sign_up_and_login_record_the_audit_log() {
    const PASSWORD: &str = "correct horse battery staple";
    with_db!(|db| {
        let store = db.store.clone();
        let (events, writer) = store.event_sink(1_000);
        let writing = tokio::spawn(writer.run());
        let sessions = SessionManager::builder(store.clone())
            .events(events)
            .build();
        let mailer = RecordingMailer::new();
        let auth = local_auth(&store, sessions)
            .mailer(mailer.clone())
            .build()
            .unwrap();

        auth.register(Registration {
            username: "budi".into(),
            email: "Budi@Example.com".into(),
            name: "Budi Santoso".into(),
            password: PASSWORD.into(),
        })
        .await
        .unwrap();
        let token = mailer
            .take()
            .into_iter()
            .find_map(|email| email.token().map(|t| t.expose().to_owned()))
            .expect("a verification email");
        auth.verify_email(&token, SessionContext::web())
            .await
            .unwrap();

        let client = SessionContext::web()
            .ip("2001:db8::1".parse().unwrap())
            .user_agent("curl/8");
        let wrong = auth.login("budi", "not the password", client.clone()).await;
        assert!(wrong.is_err());
        let login = auth
            .login("BUDI@example.com", PASSWORD, client)
            .await
            .unwrap();
        let validated = auth
            .sessions()
            .validate(login.token.expose())
            .await
            .unwrap();
        assert_eq!(validated.user.username, "budi");
        assert!(validated.user.email_verified_at.is_some());
        assert_eq!(validated.session.ip, Some("2001:db8::1".parse().unwrap()));
        auth.sessions().revoke_all(login.user.id).await.unwrap();
        assert!(
            auth.sessions()
                .validate(login.token.expose())
                .await
                .is_err()
        );

        // The writer stops once every sink is gone.
        drop(auth);
        writing.await.unwrap();
        let events = db.texts("SELECT event FROM auth_events ORDER BY id").await;
        for expected in [
            "email_verified",
            "login_failed",
            "session_created",
            "login_succeeded",
            "session_revoked",
        ] {
            assert!(
                events.iter().any(|e| e == expected),
                "{expected} missing from {events:?}"
            );
        }
        let failed = db
            .texts(
                "SELECT concat_ws(' ', user_id IS NOT NULL, host(ip), user_agent, metadata::text) \
                 FROM auth_events WHERE event = 'login_failed'",
            )
            .await;
        assert_eq!(
            failed,
            vec![r#"t 2001:db8::1 curl/8 {"reason": "wrong_password"}"#]
        );
    });
}

#[tokio::test]
async fn a_lockout_and_a_password_reset_work_across_two_processes() {
    const PASSWORD: &str = "correct horse battery staple";
    with_db!(|db| {
        // Two `LocalAuth`s on one database, as two processes behind a load balancer.
        let mailer = RecordingMailer::new();
        let build = |mailer: &RecordingMailer| {
            let sessions = SessionManager::builder(db.store.clone()).build();
            local_auth(&db.store, sessions)
                .mailer(mailer.clone())
                .require_verified_email(false)
                .build()
                .unwrap()
        };
        let first = build(&mailer);
        let second = build(&mailer);
        first
            .register(Registration {
                username: "siti".into(),
                email: "siti@example.com".into(),
                name: "Siti".into(),
                password: PASSWORD.into(),
            })
            .await
            .unwrap();
        mailer.take();

        // Five failures spread over both lock the account in both.
        for attempt in 0..5 {
            let auth = if attempt % 2 == 0 { &first } else { &second };
            assert!(
                auth.login("siti", "wrong password", SessionContext::web())
                    .await
                    .is_err()
            );
        }
        for auth in [&first, &second] {
            assert!(
                auth.login("siti", PASSWORD, SessionContext::web())
                    .await
                    .is_err()
            );
        }

        // A reset link requested in one process works in the other and lifts the lock.
        first
            .request_password_reset("siti@example.com", SessionContext::web())
            .await
            .unwrap();
        let token = mailer
            .take()
            .into_iter()
            .find_map(|email| email.token().map(|t| t.expose().to_owned()))
            .expect("a reset email");
        let new_password = "an entirely new password";
        second
            .reset_password(&token, new_password, SessionContext::web())
            .await
            .unwrap();
        assert!(
            first
                .reset_password(&token, "yet another password", SessionContext::web())
                .await
                .is_err()
        );
        first
            .login("siti", new_password, SessionContext::web())
            .await
            .unwrap();
    });
}

/// The HTTP routes of `rusted-auth-actix` on Postgres storage, as a mobile client uses
/// them: registration, verification, login with a bearer token, rate limits shared
/// through `auth_attempts`, and logout.
#[actix_web::test]
async fn http_routes_work_on_postgres() {
    use actix_web::http::StatusCode;
    use actix_web::http::header::{AUTHORIZATION, CONTENT_TYPE};
    use actix_web::{App, HttpResponse, test, web};
    use rusted_auth_actix::{
        AuthRoutes, Bucket, CurrentSession, Limit, RateLimiter, RateLimits, SessionAuth, WebConfig,
    };
    use serde_json::{Value, json};

    async fn me(current: CurrentSession) -> HttpResponse {
        HttpResponse::Ok().body(current.user.username.clone())
    }

    fn post(path: &str, body: Value) -> test::TestRequest {
        test::TestRequest::post()
            .uri(path)
            .insert_header((CONTENT_TYPE, "application/json"))
            .peer_addr("198.51.100.7:4000".parse().unwrap())
            .set_payload(body.to_string())
    }

    const PASSWORD: &str = "correct horse battery staple";
    with_db!(|db| {
        let store = db.store.clone();
        let sessions = SessionManager::new(store.clone());
        let mailer = RecordingMailer::new();
        let local = local_auth(&store, sessions.clone())
            .mailer(mailer.clone())
            .build()
            .unwrap();
        let web_config = WebConfig::new(["https://app.example.com"]).unwrap();
        let limits =
            RateLimits::default().set(Bucket::Email, Limit::new(2, Duration::from_secs(60)));
        let routes = AuthRoutes::builder(local, web_config.clone())
            .rate_limiter(RateLimiter::shared(store.clone(), [9; 32]).limits(limits))
            .build()
            .unwrap();
        let app = test::init_service(
            App::new()
                .wrap(SessionAuth::new(sessions.clone(), web_config))
                .service(web::scope("/api/auth").configure(|cfg| routes.configure(cfg)))
                .route("/api/me", web::get().to(me)),
        )
        .await;

        let registration = json!({
            "username": "budi", "email": "budi@example.com", "name": "Budi", "password": PASSWORD,
        });
        let resp =
            test::call_service(&app, post("/api/auth/register", registration).to_request()).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let token = mailer
            .take()
            .into_iter()
            .find_map(|email| email.token().map(|t| t.expose().to_owned()))
            .expect("a verification email");
        let resp = test::call_service(
            &app,
            post("/api/auth/email/verify", json!({ "token": token })).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let login = json!({ "identifier": "budi@example.com", "password": PASSWORD });
        let resp =
            test::call_service(&app, post("/api/auth/mobile/login", login).to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = test::read_body_json(resp).await;
        let bearer = format!("Bearer {}", body["data"]["token"].as_str().unwrap());

        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/me")
                .insert_header((AUTHORIZATION, bearer.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(test::read_body(resp).await, "budi");

        // The email limit is counted in `auth_attempts`, under a hashed key.
        for expected in [
            StatusCode::ACCEPTED,
            StatusCode::ACCEPTED,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let forgot = post(
                "/api/auth/password/forgot",
                json!({ "email": "budi@example.com" }),
            );
            let resp = test::call_service(&app, forgot.to_request()).await;
            assert_eq!(resp.status(), expected);
        }
        let scopes = db
            .texts("SELECT scope || ':' || count FROM auth_attempts WHERE scope = 'client_address' ORDER BY count")
            .await;
        // One row per bucket: register, verification token and login once each, and the
        // email bucket full after two requests.
        assert_eq!(
            scopes,
            [
                "client_address:1",
                "client_address:1",
                "client_address:1",
                "client_address:2"
            ]
        );

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/auth/logout")
                .insert_header((AUTHORIZATION, bearer.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/api/me")
                .insert_header((AUTHORIZATION, bearer.as_str()))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    });
}
