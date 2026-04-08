use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{any, get, post},
    Json, Router,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use phantomgrid_types::{HealthResponse, JwtClaims};
use std::{env, fs};

#[derive(Clone)]
struct AppState {
    dec: DecodingKey,
    auth_base: String,
    decoy_base: String,
    event_base: String,
    alert_base: String,
    analytics_base: String,
    mitre_base: String,
    tenant_base: String,
    integrations_base: String,
    realtime_base: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let pub_key = fs::read(env::var("JWT_PUBLIC_KEY_PATH")?)?;
    let state = AppState {
        dec: DecodingKey::from_rsa_pem(&pub_key)?,
        auth_base: env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://auth-service:8081".into()),
        decoy_base: env::var("DECOY_MANAGER_URL").unwrap_or_else(|_| "http://decoy-manager:8082".into()),
        event_base: env::var("EVENT_STORE_URL").unwrap_or_else(|_| "http://event-processor:8083".into()),
        alert_base: env::var("ALERT_ENGINE_URL").unwrap_or_else(|_| "http://alert-engine:8083".into()),
        analytics_base: env::var("ANALYTICS_URL").unwrap_or_else(|_| "http://analytics:8086".into()),
        mitre_base: env::var("MITRE_MAPPER_URL").unwrap_or_else(|_| "http://mitre-mapper:8084".into()),
        tenant_base: env::var("TENANT_MANAGER_URL").unwrap_or_else(|_| "http://tenant-manager:8088".into()),
        integrations_base: env::var("INTEGRATIONS_URL").unwrap_or_else(|_| "http://integrations:8089".into()),
        realtime_base: env::var("REALTIME_URL").unwrap_or_else(|_| "http://realtime:8085".into()),
    };

    let app = Router::new()
        .route(
            "/health",
            get(|| async {
                Json(HealthResponse {
                    status: "ok",
                    service: "api-gateway",
                    timestamp: chrono::Utc::now(),
                })
            }),
        )
        .route("/api/v1/sensors/heartbeat", post(sensor_heartbeat))
        .route("/api/v1/auth/*path", any(proxy_auth))
        .route("/api/v1/decoys/*path", any(proxy_decoys))
        .route("/api/v1/networks/*path", any(proxy_decoys))
        .route("/api/v1/events/*path", any(proxy_events))
        .route("/api/v1/alerts/*path", any(proxy_alerts))
        .route("/api/v1/analytics/*path", any(proxy_analytics))
        .route("/api/v1/mitre/*path", any(proxy_mitre))
        .route("/api/v1/tenants/*path", any(proxy_tenants))
        .route("/api/v1/integrations/*path", any(proxy_integrations))
        .route("/ws/*path", any(proxy_realtime))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn auth_mw(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let path = req.uri().path();
    if path.starts_with("/api/v1/auth/") || path == "/health" || path == "/api/v1/sensors/heartbeat" {
        return Ok(next.run(req).await);
    }
    let header = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let token = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    decode::<JwtClaims>(
        token,
        &st.dec,
        &Validation::new(jsonwebtoken::Algorithm::RS256),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(next.run(req).await)
}

async fn sensor_heartbeat() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

async fn proxy_auth(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.auth_base, req, "/api/v1").await
}

async fn proxy_decoys(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.decoy_base, req, "/api/v1").await
}

async fn proxy_events(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.event_base, req, "/api/v1").await
}

async fn proxy_alerts(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.alert_base, req, "/api/v1").await
}

async fn proxy_analytics(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.analytics_base, req, "/api/v1").await
}

async fn proxy_mitre(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.mitre_base, req, "/api/v1").await
}

async fn proxy_tenants(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.tenant_base, req, "/api/v1").await
}

async fn proxy_integrations(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.integrations_base, req, "/api/v1").await
}

async fn proxy_realtime(State(st): State<AppState>, req: Request) -> impl IntoResponse {
    proxy(st.realtime_base, req, "").await
}

async fn proxy(base: String, req: Request, strip_prefix: &str) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let method = match req.method().as_str().parse::<reqwest::Method>() {
        Ok(m) => m,
        Err(_) => reqwest::Method::GET,
    };
    let headers = req.headers().clone();
    let uri = req.uri().clone();
    let body = axum::body::to_bytes(req.into_body(), usize::MAX)
        .await
        .unwrap_or_default();

    let mut path = uri.path().to_string();
    if !strip_prefix.is_empty() {
        path = path.replacen(strip_prefix, "", 1);
    }
    let url = match uri.query() {
        Some(q) => format!("{}{}?{}", base, path, q),
        None => format!("{}{}", base, path),
    };

    let mut outbound = client.request(method, url).body(body);
    outbound = copy_headers(headers, outbound);

    match outbound.send().await {
        Ok(r) => {
            let status = axum::http::StatusCode::from_u16(r.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let bytes = r.bytes().await.unwrap_or_default();
            (status, bytes).into_response()
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

fn copy_headers(headers: HeaderMap, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    for (k, v) in headers.iter() {
        if k.as_str().eq_ignore_ascii_case("host") || k.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            req = req.header(k.as_str(), vs);
        }
    }
    req
}
