//! End-to-end tests of the remote JWKS path against a local HTTP server.

use crate::jwks::Timings;
use crate::tests::support::{JWKS_JSON, TEST_AUDIENCE, TEST_ISSUER, TEST_KID, sign, valid_claims};
use crate::{AuthError, Issuer, Verifier};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Server {
    url: String,
    hits: Arc<AtomicUsize>,
    failing: Arc<AtomicBool>,
}

#[derive(Clone)]
struct Response {
    body: String,
    cache_control: Option<&'static str>,
    delay: Duration,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            body: JWKS_JSON.to_string(),
            cache_control: None,
            delay: Duration::ZERO,
        }
    }
}

/// Serve `response` to every request; answer 503 while `failing` is set.
async fn serve(response: Response) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/jwks", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let failing = Arc::new(AtomicBool::new(false));

    let (hits_task, failing_task) = (hits.clone(), failing.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let (response, hits, failing) =
                (response.clone(), hits_task.clone(), failing_task.clone());
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(response.delay).await;

                let reply = if failing.load(Ordering::SeqCst) {
                    "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_string()
                } else {
                    let cache = response
                        .cache_control
                        .map(|v| format!("cache-control: {v}\r\n"))
                        .unwrap_or_default();
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{cache}content-length: {}\r\nconnection: close\r\n\r\n{}",
                        response.body.len(),
                        response.body
                    )
                };
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    Server { url, hits, failing }
}

impl Server {
    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn verifier(&self, timings: Timings) -> Verifier {
        Verifier::builder()
            .issuer(
                Issuer::new(TEST_ISSUER)
                    .audience(TEST_AUDIENCE)
                    .jwks_uri(&self.url)
                    .allow_insecure_http(),
            )
            .timings(timings)
            .build()
            .unwrap()
    }
}

fn token() -> String {
    sign(&valid_claims(), Some(TEST_KID))
}

fn unknown_kid_token() -> String {
    sign(&valid_claims(), Some("no-such-kid"))
}

const MS: Duration = Duration::from_millis(1);

#[tokio::test]
async fn keys_are_fetched_once_and_cached() {
    let server = serve(Response::default()).await;
    let verifier = server.verifier(Timings::default());

    for _ in 0..3 {
        verifier.verify(&token()).await.unwrap();
    }
    assert_eq!(server.hits(), 1);
}

#[tokio::test]
async fn concurrent_misses_share_one_fetch() {
    let server = serve(Response {
        delay: 100 * MS,
        ..Response::default()
    })
    .await;
    let verifier = server.verifier(Timings::default());

    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let verifier = verifier.clone();
            tokio::spawn(async move { verifier.verify(&token()).await })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(server.hits(), 1);
}

#[tokio::test]
async fn unknown_kid_cannot_force_refetches() {
    let server = serve(Response::default()).await;
    let verifier = server.verifier(Timings::default());
    verifier.verify(&token()).await.unwrap();

    for _ in 0..5 {
        assert!(matches!(
            verifier.verify(&unknown_kid_token()).await,
            Err(AuthError::KeyNotFound { .. })
        ));
    }
    assert_eq!(server.hits(), 1, "rate limit holds");
}

#[tokio::test]
async fn unknown_kid_refetches_once_the_interval_has_passed() {
    let server = serve(Response::default()).await;
    let verifier = server.verifier(Timings {
        min_fetch_interval: Duration::ZERO,
        ..Timings::default()
    });
    verifier.verify(&token()).await.unwrap();

    // A new kid may mean the issuer rotated keys, so look again
    assert!(matches!(
        verifier.verify(&unknown_kid_token()).await,
        Err(AuthError::KeyNotFound { .. })
    ));
    assert_eq!(server.hits(), 2);
}

#[tokio::test]
async fn max_age_overrides_the_default_ttl() {
    let server = serve(Response {
        cache_control: Some("public, max-age=3600"),
        ..Response::default()
    })
    .await;
    let verifier = server.verifier(Timings {
        default_ttl: 10 * MS,
        min_fetch_interval: Duration::ZERO,
        ..Timings::default()
    });

    verifier.verify(&token()).await.unwrap();
    tokio::time::sleep(40 * MS).await;
    verifier.verify(&token()).await.unwrap();
    assert_eq!(server.hits(), 1);
}

#[tokio::test]
async fn stale_keys_are_served_while_the_issuer_is_down() {
    let server = serve(Response::default()).await;
    let verifier = server.verifier(Timings {
        default_ttl: 20 * MS,
        min_fetch_interval: Duration::ZERO,
        max_stale: Duration::from_secs(3600),
    });

    verifier.verify(&token()).await.unwrap();
    server.failing.store(true, Ordering::SeqCst);
    tokio::time::sleep(60 * MS).await;

    verifier.verify(&token()).await.unwrap();
    assert_eq!(server.hits(), 2, "a refresh was attempted and failed");
}

#[tokio::test]
async fn stale_keys_expire_after_the_grace_period() {
    let server = serve(Response::default()).await;
    let verifier = server.verifier(Timings {
        default_ttl: 20 * MS,
        min_fetch_interval: Duration::ZERO,
        max_stale: Duration::ZERO,
    });

    verifier.verify(&token()).await.unwrap();
    server.failing.store(true, Ordering::SeqCst);
    tokio::time::sleep(60 * MS).await;

    assert!(matches!(
        verifier.verify(&token()).await,
        Err(AuthError::KeysUnavailable(_))
    ));
}

#[tokio::test]
async fn issuer_down_at_startup() {
    let server = serve(Response::default()).await;
    server.failing.store(true, Ordering::SeqCst);
    let verifier = server.verifier(Timings::default());

    assert!(matches!(
        verifier.refresh_keys().await,
        Err(AuthError::KeysUnavailable(_))
    ));
    let hits = server.hits();

    // Within the rate-limit window the failure is reported without another request
    assert!(matches!(
        verifier.verify(&token()).await,
        Err(AuthError::KeysUnavailable(_))
    ));
    assert_eq!(server.hits(), hits);

    // Recovery: an explicit refresh ignores the rate limit
    server.failing.store(false, Ordering::SeqCst);
    verifier.refresh_keys().await.unwrap();
    verifier.verify(&token()).await.unwrap();
}

#[tokio::test]
async fn oversized_response_is_rejected() {
    let padding = "x".repeat(1024 * 1024);
    let server = serve(Response {
        body: format!(r#"{{"keys": [], "padding": "{padding}"}}"#),
        ..Response::default()
    })
    .await;
    let verifier = server.verifier(Timings::default());

    assert!(matches!(
        verifier.verify(&token()).await,
        Err(AuthError::KeysUnavailable(_))
    ));
}

#[tokio::test]
async fn document_without_usable_keys_is_rejected() {
    let server = serve(Response {
        body: r#"{"keys": []}"#.to_string(),
        ..Response::default()
    })
    .await;
    let verifier = server.verifier(Timings::default());

    assert!(matches!(
        verifier.verify(&token()).await,
        Err(AuthError::KeysUnavailable(_))
    ));
}

/// Hits Google's real endpoint. Run with `cargo test -- --ignored`.
#[tokio::test]
#[ignore = "requires network access to Google"]
async fn firebase_preset_keys_are_reachable() {
    let verifier = Verifier::builder()
        .issuer(Issuer::firebase("any-project"))
        .build()
        .unwrap();
    verifier.refresh_keys().await.unwrap();
}
