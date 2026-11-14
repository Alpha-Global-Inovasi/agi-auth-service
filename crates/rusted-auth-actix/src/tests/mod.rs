use crate::{AuthResponder, Authenticate, Authenticated, MaybeAuthenticated};
use actix_web::http::StatusCode;
use actix_web::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use actix_web::{App, HttpResponse, test, web};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rusted_auth::{AuthError, Issuer, Verifier};
use serde_json::{Value, json};

const ISSUER: &str = "https://issuer.test";
const AUDIENCE: &str = "test-audience";
const KID: &str = "test-kid";
const JWKS_JSON: &str = include_str!("../../../../testdata/jwks.json");
const PRIVATE_KEY: &str = include_str!("../../../../testdata/rsa_private.pem");

fn verifier() -> Verifier {
    Verifier::builder()
        .issuer(Issuer::new(ISSUER).audience(AUDIENCE).jwks_json(JWKS_JSON))
        .build()
        .unwrap()
}

fn token(kid: &str, expires_in: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let claims = json!({
        "iss": ISSUER, "aud": AUDIENCE, "sub": "user-123",
        "iat": now - 60, "exp": now + expires_in,
    });
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap();
    encode(&header, &claims, &key).unwrap()
}

fn valid_token() -> String {
    token(KID, 3600)
}

async fn whoami(user: Authenticated) -> HttpResponse {
    HttpResponse::Ok().body(user.subject.clone())
}

async fn maybe_whoami(user: MaybeAuthenticated) -> HttpResponse {
    let name = user.as_ref().map_or("anonymous", |p| p.subject.as_str());
    HttpResponse::Ok().body(name.to_string())
}

macro_rules! app {
    ($middleware:expr) => {
        test::init_service(
            App::new()
                .wrap($middleware)
                .route("/me", web::get().to(whoami))
                .route("/maybe", web::get().to(maybe_whoami)),
        )
        .await
    };
}

fn get(path: &str, bearer: Option<&str>) -> test::TestRequest {
    let mut req = test::TestRequest::get().uri(path);
    if let Some(token) = bearer {
        req = req.insert_header((AUTHORIZATION, format!("Bearer {token}")));
    }
    req
}

#[actix_web::test]
async fn required_accepts_a_valid_token() {
    let app = app!(Authenticate::required(verifier()));
    let resp = test::call_service(&app, get("/me", Some(&valid_token())).to_request()).await;

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await, "user-123");
}

#[actix_web::test]
async fn required_rejects_a_missing_header() {
    let app = app!(Authenticate::required(verifier()));
    let resp = test::call_service(&app, get("/me", None).to_request()).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body,
        json!({"status": false, "message": "Authentication required", "data": null})
    );
}

#[actix_web::test]
async fn rejections_do_not_leak_details() {
    let app = app!(Authenticate::required(verifier()));

    for bad in [
        "garbage".to_string(),
        token("secret-internal-kid", 3600),
        token(KID, -3600),
    ] {
        let resp = test::call_service(&app, get("/me", Some(&bad)).to_request()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(WWW_AUTHENTICATE).unwrap(),
            "Bearer error=\"invalid_token\""
        );
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(!body.contains("secret-internal-kid"), "{body}");
        assert!(!body.contains(ISSUER), "{body}");
        assert!(
            body.contains("Invalid token") || body.contains("Token expired"),
            "{body}"
        );
    }
}

#[actix_web::test]
async fn non_bearer_scheme_is_rejected() {
    let app = app!(Authenticate::required(verifier()));
    let req = test::TestRequest::get()
        .uri("/me")
        .insert_header((AUTHORIZATION, "Basic dXNlcjpwYXNz"))
        .to_request();

    assert_eq!(
        test::call_service(&app, req).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[actix_web::test]
async fn optional_allows_anonymous_requests() {
    let app = app!(Authenticate::optional(verifier()));

    let resp = test::call_service(&app, get("/maybe", None).to_request()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(test::read_body(resp).await, "anonymous");

    let resp = test::call_service(&app, get("/maybe", Some(&valid_token())).to_request()).await;
    assert_eq!(test::read_body(resp).await, "user-123");
}

#[actix_web::test]
async fn optional_still_rejects_an_invalid_token() {
    let app = app!(Authenticate::optional(verifier()));
    let resp = test::call_service(&app, get("/maybe", Some("garbage")).to_request()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn authenticated_extractor_rejects_anonymous_under_optional() {
    let app = app!(Authenticate::optional(verifier()));
    let resp = test::call_service(&app, get("/me", None).to_request()).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers().get(WWW_AUTHENTICATE).unwrap(), "Bearer");
}

#[actix_web::test]
async fn extractor_without_middleware_is_unauthorized() {
    let app = test::init_service(App::new().route("/me", web::get().to(whoami))).await;
    let resp = test::call_service(&app, get("/me", Some(&valid_token())).to_request()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

struct TeapotResponder;

impl AuthResponder for TeapotResponder {
    fn respond(&self, error: &AuthError) -> HttpResponse {
        HttpResponse::ImATeapot().body(format!("custom: {}", error.public_message()))
    }
}

#[actix_web::test]
async fn custom_responder_is_used_by_middleware_and_extractor() {
    let app = app!(Authenticate::required(verifier()).responder(TeapotResponder));
    let resp = test::call_service(&app, get("/me", None).to_request()).await;
    assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(
        test::read_body(resp).await,
        "custom: Authentication required"
    );

    let app = app!(Authenticate::optional(verifier()).responder(TeapotResponder));
    let resp = test::call_service(&app, get("/me", None).to_request()).await;
    assert_eq!(
        resp.status(),
        StatusCode::IM_A_TEAPOT,
        "extractor uses it too"
    );
}

#[actix_web::test]
async fn unreachable_issuer_is_503() {
    // Nothing listens on port 1, so the key fetch fails
    let verifier = Verifier::builder()
        .issuer(
            Issuer::new(ISSUER)
                .audience(AUDIENCE)
                .jwks_uri("http://127.0.0.1:1/jwks")
                .allow_insecure_http(),
        )
        .build()
        .unwrap();
    let app = app!(Authenticate::required(verifier));
    let resp = test::call_service(&app, get("/me", Some(&valid_token())).to_request()).await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(resp.headers().get(WWW_AUTHENTICATE).is_none());
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["message"], "Authentication service unavailable");
}
