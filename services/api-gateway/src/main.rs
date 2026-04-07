use axum::{extract::{Request, State}, http::StatusCode, middleware::{self, Next}, response::IntoResponse, routing::{any, get}, Router};
use jsonwebtoken::{decode, DecodingKey, Validation};
use phantomgrid_types::{HealthResponse, JwtClaims};
use std::{env, fs};

#[derive(Clone)]
struct AppState { dec: DecodingKey, auth_base: String }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let pub_key = fs::read(env::var("JWT_PUBLIC_KEY_PATH")?)?;
    let state = AppState {
        dec: DecodingKey::from_rsa_pem(&pub_key)?,
        auth_base: env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://auth-service:8081".into()),
    };

    let app = Router::new()
        .route("/health", get(|| async { axum::Json(HealthResponse{ status:"ok", service:"api-gateway", timestamp: chrono::Utc::now() }) }))
        .route("/api/v1/auth/*path", any(proxy_auth))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn auth_mw(State(st): State<AppState>, req: Request, next: Next) -> Result<impl IntoResponse, StatusCode> {
    let path = req.uri().path();
    if path.starts_with("/api/v1/auth/") || path == "/health" { return Ok(next.run(req).await); }
    let header = req.headers().get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
    let token = header.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;
    decode::<JwtClaims>(token, &st.dec, &Validation::new(jsonwebtoken::Algorithm::RS256)).map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(next.run(req).await)
}

async fn proxy_auth(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let path = req.uri().path().replacen("/api/v1", "", 1);
    let url = format!("{}{}", st.auth_base, path);
    let method = req.method().clone();
    let body = axum::body::to_bytes(req.into_body(), usize::MAX).await.unwrap_or_default();

    let resp = client.request(method, url).body(body).send().await;
    match resp {
        Ok(r) => {
            let status = r.status();
            let bytes = r.bytes().await.unwrap_or_default();
            (status, bytes).into_response()
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}
