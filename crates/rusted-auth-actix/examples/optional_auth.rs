//! Public endpoint that personalizes its answer for signed-in callers.
//!
//! ```text
//! FIREBASE_PROJECT_ID=my-project cargo run -p rusted-auth-actix --example optional_auth
//! curl http://127.0.0.1:8080/public
//! curl -H "Authorization: Bearer <firebase id token>" http://127.0.0.1:8080/public
//! ```

use actix_web::{App, HttpServer, web};
use rusted_auth::{Issuer, Verifier};
use rusted_auth_actix::{Authenticate, MaybeAuthenticated};

async fn public_content(user: MaybeAuthenticated) -> String {
    match user.into_inner() {
        Some(principal) => format!("Personalized content for {}", principal.subject),
        None => "Public content for guests".to_string(),
    }
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // The library never reads the environment itself; configuration is the application's job.
    let project_id = std::env::var("FIREBASE_PROJECT_ID")?;
    let verifier = Verifier::builder()
        .issuer(Issuer::firebase(&project_id))
        .build()?;

    // Optional: fail at startup, not on the first request, if Google's keys are unreachable
    verifier.refresh_keys().await?;

    tracing::info!("listening on http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .wrap(Authenticate::optional(verifier.clone()))
            .route("/public", web::get().to(public_content))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;
    Ok(())
}
